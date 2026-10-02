using System.Net;
using System.Data.Common;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises real HTTP and PostgreSQL locks, triggers and durable reactivation receipts.</summary>
public sealed class LicenseReactivationPostgreSqlTests
{
    /// <summary>Synthetic credential used only by the isolated in-process HTTP host.</summary>
    private const string Secret = "tkt939-local-fixture-secret";

    /// <summary>An old owner must not revoke after a committed transfer between its read and POST.</summary>
    [Fact]
    public async Task ConditionalRevoke_TransferBeforePostMustNotRevokeSuccessor()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        using var activated = await fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional", fixture.Request(original));
        Assert.Equal(HttpStatusCode.OK, activated.StatusCode);
        var observed = await fixture.ReadAsync();
        var request = fixture.RevokeRequest(observed);
        await using var db = fixture.Db();
        await using (var transfer = await db.Database.BeginTransactionAsync())
        {
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT \"Id\" FROM \"Licenses\" WHERE \"Id\" = {observed.Id} FOR UPDATE");
            var previous = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(o => o.LicenseId == observed.Id);
            previous.State = "TRANSFERRED";
            previous.EndedAtUtc = DateTime.UtcNow;
            var successor = new RuntimeRecoveryCommercialSubject { Id = Guid.NewGuid(), ProductId = observed.ProductId, CreatedAtUtc = DateTime.UtcNow };
            db.Add(successor);
            await db.SaveChangesAsync();
            db.Add(new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = observed.ProductId,
                LicenseId = observed.Id, OwnerSubjectId = successor.Id, PreviousOwnershipId = previous.Id,
                State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync();
            await transfer.CommitAsync();
        }
        using var result = await fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{observed.LicenseKey}/revoke-conditional", request);
        Assert.True((await fixture.ReadAsync()).IsActive, "Stale owner revoked the transferred license through legacy POST");
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
    }

    /// <summary>A transfer waits for the winning revocation transaction, then invalidates its old receipt.</summary>
    [Fact]
    public async Task ConditionalRevoke_WinsBeforeTransferWithoutDeadlock()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ActivateAsync();
        var request = fixture.RevokeRequest(original);
        Task transfer = Task.CompletedTask;
        fixture.BeforeHttpLicenseUpdate = async () =>
        {
            transfer = fixture.TransferAsync();
            await fixture.WaitForLicenseLockAsync("pg_advisory_xact_lock");
            Assert.False(transfer.IsCompleted);
        };
        var url = $"/api/admin/licenses/{original.LicenseKey}/revoke-conditional";
        using var result = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        await transfer;
        Assert.False((await fixture.ReadAsync()).IsActive);
        using var replay = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
    }

    /// <summary>Legacy lifecycle calls wait behind conditional authority without reversing lock order.</summary>
    [Theory]
    [InlineData("revoke")]
    [InlineData("unrevoke")]
    public async Task ConditionalRevoke_LegacyWriterWaitsWithoutDeadlock(string action)
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ActivateAsync();
        var request = fixture.RevokeRequest(original);
        Task<HttpResponseMessage>? legacy = null;
        fixture.BeforeHttpLicenseUpdate = async () =>
        {
            legacy = fixture.Client.PostAsJsonAsync($"/api/admin/licenses/{original.LicenseKey}/{action}", new { Reason = "security_review" });
            await fixture.WaitForLicenseLockAsync("pg_advisory_xact_lock");
            Assert.False(legacy.IsCompleted);
        };
        var url = $"/api/admin/licenses/{original.LicenseKey}/revoke-conditional";
        using var result = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        using var legacyResult = await legacy!;
        Assert.Equal(HttpStatusCode.OK, legacyResult.StatusCode);
        var final = await fixture.ReadAsync();
        Assert.Equal(action == "unrevoke", final.IsActive);
        Assert.Equal(action == "unrevoke" ? null : "User self-revoke from dashboard", final.RevocationReason);
        using var replay = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(action == "unrevoke" ? HttpStatusCode.Conflict : HttpStatusCode.OK, replay.StatusCode);
    }

    /// <summary>Parallel calls and a discarded response persist exactly one revocation receipt.</summary>
    [Fact]
    public async Task ConditionalRevoke_ReplayAndLostResponsePreserveOneMutation()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ActivateAsync();
        var request = fixture.RevokeRequest(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/revoke-conditional";
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => fixture.Client.PostAsJsonAsync(url, request)));
        foreach (var result in results) { using (result) Assert.Equal(HttpStatusCode.OK, result.StatusCode); }
        var revoked = await fixture.ReadAsync();
        Assert.False(revoked.IsActive);
        Assert.NotEqual(original.AuthorityVersion, revoked.AuthorityVersion);
        Assert.Equal("User self-revoke from dashboard", revoked.RevocationReason);
        Assert.Equal(original.ExpirationDate, revoked.ExpirationDate);
        Assert.Equal(original.MaxSeats, revoked.MaxSeats);
        Assert.Equal(original.LicenseTypeId, revoked.LicenseTypeId);
        using var lostResponseReplay = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.OK, lostResponseReplay.StatusCode);
        Assert.Equal(revoked.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        await using var db = fixture.Db();
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.Action == "REVOKED_CONDITIONAL_V1"));
        using var changedPayload = await fixture.Client.PostAsJsonAsync(url, request with { ExpectedAuthorityVersion = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Conflict, changedPayload.StatusCode);
        using var crossCommand = await fixture.Client.PostAsJsonAsync($"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional",
            fixture.Request(revoked) with { OperationId = request.OperationId });
        Assert.Equal(HttpStatusCode.Conflict, crossCommand.StatusCode);
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"RevocationReason\" = 'security_review' WHERE \"Id\" = {original.Id}");
        using var stale = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal("security_review", (await fixture.ReadAsync()).RevocationReason);
    }

    /// <summary>Prior revocations are verified without attributing their cause to the current user.</summary>
    [Fact]
    public async Task ConditionalRevoke_AlreadyRevokedIsReadOnlyAndRejectsInconsistentEvidence()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var url = $"/api/admin/licenses/{original.LicenseKey}/revoke-conditional";
        using var verified = await fixture.Client.PostAsJsonAsync(url, fixture.RevokeRequest(original));
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        Assert.Contains("AlreadyRevokedVerified", await verified.Content.ReadAsStringAsync());
        var final = await fixture.ReadAsync();
        Assert.Equal(original.AuthorityVersion, final.AuthorityVersion);
        Assert.Equal(original.RevocationReason, final.RevocationReason);
        Assert.Equal(original.RevokedAt, final.RevokedAt);
        await using var db = fixture.Db();
        Assert.Empty(await db.LicenseHistories.ToListAsync());
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"RevocationReason\" = NULL WHERE \"Id\" = {original.Id}");
        using var missing = await fixture.Client.PostAsJsonAsync(url, fixture.RevokeRequest(await fixture.ReadAsync()));
        Assert.Equal(HttpStatusCode.Conflict, missing.StatusCode);
    }

    /// <summary>Receipt failures roll back authority and allow the exact original request to retry.</summary>
    [Fact]
    public async Task ConditionalRevoke_ReceiptFailureRollsBack()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ActivateAsync();
        var request = fixture.RevokeRequest(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/revoke-conditional";
        await using var db = fixture.Db();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION tkt939_fail_revoke_receipt() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN RAISE EXCEPTION 'fixture receipt failure'; END; $body$;
            CREATE TRIGGER tkt939_fail_revoke_receipt BEFORE INSERT ON "LicenseHistories"
            FOR EACH ROW EXECUTE FUNCTION tkt939_fail_revoke_receipt();
            """);
        using var failed = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.True((await fixture.ReadAsync()).IsActive);
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER tkt939_fail_revoke_receipt ON \"LicenseHistories\";");
        using var retry = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
    }

    /// <summary>Missing evidence, duplicate aliases, changed identities and foreign credentials fail closed.</summary>
    [Fact]
    public async Task ConditionalRevoke_AuthenticationAndRequiredEvidence()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ActivateAsync();
        var request = fixture.RevokeRequest(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/revoke-conditional";
        var json = System.Text.Json.JsonSerializer.Serialize(request);
        foreach (var field in new[] { "ExpectedAuthorityIsActive", "ExpectedRevocationReason", "ExpectedRevokedAt", "DesiredRevocationReason", "OperationId" })
        {
            var body = System.Text.Json.Nodes.JsonNode.Parse(json)!.AsObject();
            body.Remove(field);
            using var result = await fixture.Client.PostAsJsonAsync(url, body);
            Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        }
        using var duplicate = await fixture.Client.PostAsync(url, new StringContent(json.Insert(1, "\"operationId\":\"" + Guid.NewGuid() + "\","), System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode);
        foreach (var conflict in new[] { request with { ExpectedOwnershipId = Guid.NewGuid() }, request with { CommercialSubjectId = Guid.NewGuid() },
            request with { ExpectedAuthorityVersion = Guid.NewGuid() }, request with { ExpectedRevocationReason = "security" },
            request with { ExpectedRevokedAt = DateTime.UtcNow } })
        {
            using var result = await fixture.Client.PostAsJsonAsync(url, conflict);
            Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        }
        fixture.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        using var anonymous = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        fixture.Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt939-product-fixture");
        using var foreign = await fixture.Client.PostAsJsonAsync(url, request with { ProductId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Unauthorized, foreign.StatusCode);
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
    }

    /// <summary>Observe PostgreSQL waiting for the global lock before allowing the conditional mutation.</summary>
    [Fact]
    public async Task ConditionalRevoke_GlobalLockWaitRejectsNewerCause()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ActivateAsync();
        await using var db = fixture.Db();
        await using var writer = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevocationReason\" = 'security_review', \"RevokedAt\" = now() WHERE \"Id\" = {original.Id}");
        var pending = fixture.Client.PostAsJsonAsync($"/api/admin/licenses/{original.LicenseKey}/revoke-conditional", fixture.RevokeRequest(original));
        await fixture.WaitForLicenseLockAsync("pg_advisory_xact_lock");
        Assert.False(pending.IsCompleted);
        await writer.CommitAsync();
        using var result = await pending;
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        Assert.Equal("security_review", (await fixture.ReadAsync()).RevocationReason);
    }

    /// <summary>
    /// Concurrent callers and a discarded successful response must produce one state mutation and
    /// receipt; a later revocation, even with identical reason/time, must reject the original retry.
    /// </summary>
    [Fact]
    public async Task ConcurrentRetryAndLostResponse_PreserveOneReceiptAndRejectLaterRevocation()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var request = fixture.Request(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        // Competing initial requests share one operation ID. Bodies are deliberately discarded;
        // a subsequent recovery must use the committed receipt rather than their returned data.
        var retries = await Task.WhenAll(Enumerable.Range(0, 6)
            .Select(_ => fixture.Client.PostAsJsonAsync(url, request)));
        foreach (var response in retries)
        {
            using (response) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        using (var lostResponseRetry = await fixture.Client.PostAsJsonAsync(url, request))
            Assert.Equal(HttpStatusCode.OK, lostResponseRetry.StatusCode);
        var active = await fixture.ReadAsync();
        Assert.True(active.IsActive);
        Assert.NotEqual(original.AuthorityVersion, active.AuthorityVersion);
        Assert.Equal(original.ExpirationDate, active.ExpirationDate);
        Assert.Equal(original.LicenseTypeId, active.LicenseTypeId);
        await using var db = fixture.Db();
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == original.Id));

        // Simulate an independent SQL writer, without the endpoint advisory lock and with an ABA
        // return to the original reason/time. The database version must still distinguish it.
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Licenses" SET "IsActive" = false, "RevocationReason" = {original.RevocationReason},
                "RevokedAt" = {original.RevokedAt} WHERE "Id" = {original.Id}
            """);
        using var stale = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.False((await fixture.ReadAsync()).IsActive);
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == original.Id));
    }

    /// <summary>
    /// The request must not succeed after a competing SQL transaction updates the row while the
    /// HTTP request waits for its lock. Explicit server lock_timeout bounds all waiting paths.
    /// </summary>
    [Fact]
    public async Task ConcurrentForeignRevocation_WinsBeforeConditionalReactivation()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        await using var db = fixture.Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Licenses" SET "RevocationReason" = 'security_review' WHERE "Id" = {original.Id}
            """);
        var waiting = fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional", fixture.Request(original));
        await fixture.WaitForLicenseLockAsync();
        await transaction.CommitAsync();
        using var result = await waiting;
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        var final = await fixture.ReadAsync();
        Assert.False(final.IsActive);
        Assert.Equal("security_review", final.RevocationReason);
        Assert.Empty(await db.LicenseHistories.Where(h => h.LicenseId == original.Id).ToListAsync());
    }

    /// <summary>Receipt insertion failure must roll back activation, allowing a safe identical retry.</summary>
    [Fact]
    public async Task ReceiptPersistenceFailure_RollsBackLicenseAndAllowsRetry()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var request = fixture.Request(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        await using var db = fixture.Db();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION tkt939_fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN RAISE EXCEPTION 'fixture receipt failure'; END; $body$;
            CREATE TRIGGER tkt939_fail_receipt BEFORE INSERT ON "LicenseHistories"
            FOR EACH ROW EXECUTE FUNCTION tkt939_fail_receipt();
            """);
        using var failed = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        Assert.False((await fixture.ReadAsync()).IsActive);
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER tkt939_fail_receipt ON \"LicenseHistories\";");
        using var retry = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == original.Id));
    }

    /// <summary>Authentication and product scoping apply before any conditional state mutation.</summary>
    [Fact]
    public async Task MissingOrForeignProductCredential_CannotReactivate()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        fixture.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        using var anonymous = await fixture.Client.PostAsJsonAsync(url, fixture.Request(original));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        await using var db = fixture.Db();
        db.Products.Add(new Product { Name = "foreign-fixture", ApiSecret = "tkt939-foreign-fixture" });
        await db.SaveChangesAsync();
        fixture.Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt939-foreign-fixture");
        using var foreign = await fixture.Client.PostAsJsonAsync(url, fixture.Request(original));
        Assert.Equal(HttpStatusCode.Unauthorized, foreign.StatusCode);
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
    }

    /// <summary>Rejects wrong ownership, license scope, opaque reason and operation reuse without mutations.</summary>
    [Fact]
    public async Task IdentityReasonAndOperationConflicts_FailClosed()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var request = fixture.Request(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        foreach (var invalid in new[]
        {
            request with { CommercialSubjectId = Guid.NewGuid() },
            request with { ExpectedOwnershipId = Guid.NewGuid() },
            request with { ExpectedAuthorityVersion = Guid.NewGuid() },
            request with { ExpectedRevocationReason = "PROFILE_REQUIRED" },
            request with { ExpectedRevocationReason = " profile_required" }
        })
        {
            using var rejected = await fixture.Client.PostAsJsonAsync(url, invalid);
            Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        }
        using var wrongProduct = await fixture.Client.PostAsJsonAsync(url, request with { ProductId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.NotFound, wrongProduct.StatusCode);
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        using var success = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.OK, success.StatusCode);
        using var changedRetry = await fixture.Client.PostAsJsonAsync(url, request with { ExpectedRevocationReason = null });
        Assert.Equal(HttpStatusCode.Conflict, changedRetry.StatusCode);
    }

    /// <summary>Legacy null-cause revocations retain expiration and expose raw state separately from expiry.</summary>
    [Fact]
    public async Task LegacyNullCauseAndExpiredLicense_PreserveExpiryAndExposeIndependentState()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        await using var db = fixture.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Licenses" SET "RevocationReason" = NULL, "RevokedAt" = NULL,
                "ExpirationDate" = now() - interval '1 day' WHERE "Id" = {original.Id}
            """);
        var observed = await fixture.ReadAsync();
        using var activated = await fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional", fixture.Request(observed));
        Assert.Equal(HttpStatusCode.OK, activated.StatusCode);
        using var read = await fixture.Client.GetAsync($"/api/admin/licenses/{original.LicenseKey}");
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        var json = await read.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.True(json.GetProperty("authorityIsActive").GetBoolean());
        Assert.False(json.GetProperty("isActive").GetBoolean());
        Assert.Equal(observed.ExpirationDate, (await fixture.ReadAsync()).ExpirationDate);
        Assert.NotEqual(observed.AuthorityVersion, json.GetProperty("authorityVersion").GetGuid());
        Assert.NotEqual(Guid.Empty, json.GetProperty("commercialOwnershipId").GetGuid());
        Assert.False(json.TryGetProperty("commercialSubjectId", out _));
    }

    /// <summary>
    /// Active reconciliation verifies owner/state without changing the row or adding a receipt.
    /// A later revocation or an inconsistent active row must never be cleared by this check.
    /// </summary>
    [Fact]
    public async Task ActiveVerification_IsReadOnlyAndRejectsNewRevocationOrInconsistentState()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        using var activation = await fixture.Client.PostAsJsonAsync(url, fixture.Request(original));
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);
        var active = await fixture.ReadAsync();
        var check = fixture.Request(active);
        using var verified = await fixture.Client.PostAsJsonAsync(url, check);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        Assert.Equal(active.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        var verifiedLicense = await fixture.ReadAsync();
        Assert.Equal(active.LicenseKey, verifiedLicense.LicenseKey);
        Assert.Equal(active.ExpirationDate, verifiedLicense.ExpirationDate);
        Assert.Equal(active.LicenseTypeId, verifiedLicense.LicenseTypeId);
        Assert.Equal(active.MaxSeats, verifiedLicense.MaxSeats);
        await using var db = fixture.Db();
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == active.Id));
        using var foreign = await fixture.Client.PostAsJsonAsync(url, check with { CommercialSubjectId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Conflict, foreign.StatusCode);
        using var wrongState = await fixture.Client.PostAsJsonAsync(url, check with { ExpectedAuthorityIsActive = false });
        Assert.Equal(HttpStatusCode.Conflict, wrongState.StatusCode);

        await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Licenses" SET "RevocationReason" = 'security_review' WHERE "Id" = {active.Id}
            """);
        using var inconsistent = await fixture.Client.PostAsJsonAsync(url, fixture.Request(await fixture.ReadAsync()));
        Assert.Equal(HttpStatusCode.Conflict, inconsistent.StatusCode);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Licenses" SET "RevocationReason" = NULL, "RevokedAt" = now() WHERE "Id" = {active.Id}
            """);
        using var residualDate = await fixture.Client.PostAsJsonAsync(url, fixture.Request(await fixture.ReadAsync()));
        Assert.Equal(HttpStatusCode.Conflict, residualDate.StatusCode);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Licenses" SET "IsActive" = false, "RevocationReason" = 'security_review' WHERE "Id" = {active.Id}
            """);
        using var stale = await fixture.Client.PostAsJsonAsync(url, check);
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.False((await fixture.ReadAsync()).IsActive);
        Assert.Equal("security_review", (await fixture.ReadAsync()).RevocationReason);
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == active.Id));
    }

    /// <summary>Missing JSON evidence must never default into an accepted null-cause request.</summary>
    [Fact]
    public async Task OmittedRequiredEvidence_IsRejectedWithoutMutation()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var request = fixture.Request(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        foreach (var field in new[] { "operationId", "licenseId", "productId", "commercialSubjectId",
            "expectedOwnershipId", "expectedAuthorityVersion", "expectedAuthorityIsActive", "expectedRevocationReason" })
        {
            var payload = System.Text.Json.JsonSerializer.SerializeToNode(request,
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!.AsObject();
            Assert.True(payload.Remove(field));
            using var response = await fixture.Client.PostAsJsonAsync(url, payload);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        await using var db = fixture.Db();
        Assert.Empty(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>A committed ownership transfer invalidates both active checks and old successful receipts.</summary>
    [Fact]
    public async Task OwnershipTransferAfterRead_RejectsActiveCheckAndPreviousOperationReplay()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var activationRequest = fixture.Request(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        using var activation = await fixture.Client.PostAsJsonAsync(url, activationRequest);
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);
        var active = await fixture.ReadAsync();
        var check = fixture.Request(active);
        await using var db = fixture.Db();
        await using (var transfer = await db.Database.BeginTransactionAsync())
        {
            var previous = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(o => o.LicenseId == active.Id);
            previous.State = "TRANSFERRED";
            previous.EndedAtUtc = DateTime.UtcNow;
            var successor = new RuntimeRecoveryCommercialSubject
            {
                Id = Guid.NewGuid(), ProductId = active.ProductId, CreatedAtUtc = DateTime.UtcNow
            };
            db.RuntimeRecoveryCommercialSubjects.Add(successor);
            await db.SaveChangesAsync();
            db.RuntimeRecoveryCommercialOwnerships.Add(new RuntimeRecoveryCommercialOwnership
            {
                Id = Guid.NewGuid(), ProductId = active.ProductId, LicenseId = active.Id,
                OwnerSubjectId = successor.Id, PreviousOwnershipId = previous.Id,
                State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            await transfer.CommitAsync();
        }
        using var staleCheck = await fixture.Client.PostAsJsonAsync(url, check);
        Assert.Equal(HttpStatusCode.Conflict, staleCheck.StatusCode);
        using var staleReplay = await fixture.Client.PostAsJsonAsync(url, activationRequest);
        Assert.Equal(HttpStatusCode.Conflict, staleReplay.StatusCode);
        Assert.Equal(active.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == active.Id));
    }

    /// <summary>
    /// Security regression probe: a non-advisory administrative writer commits a revocation after
    /// legacy HTTP read but before its UPDATE. The newer security reason must survive the stale save.
    /// </summary>
    [Fact]
    public async Task LegacySelfRevoke_MustNotOverwriteConcurrentSecurityRevocation()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        using var activation = await fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional", fixture.Request(original));
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);
        Guid securityVersion = Guid.Empty;
        Task concurrentWriter = Task.CompletedTask;
        fixture.BeforeHttpLicenseUpdate = async () =>
        {
            // Mirrors the Razor writer's independent context without taking the HTTP advisory lock.
            concurrentWriter = Task.Run(async () =>
            {
                await using var writer = fixture.Db();
                var row = await writer.Licenses.SingleAsync(l => l.Id == original.Id);
                row.IsActive = false;
                row.RevocationReason = "security_review";
                row.RevokedAt = DateTime.UtcNow;
                await writer.SaveChangesAsync();
                securityVersion = row.AuthorityVersion;
            });
            // A future row lock must be observed, not awaited to completion inside this callback:
            // returning lets HTTP commit and releases that lock so the newer writer can finish.
            await fixture.WaitForWriterCompletionOrLockAsync(concurrentWriter);
        };
        using var revoked = await fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/revoke", new { Reason = "User self-revoke from dashboard" });
        await concurrentWriter.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.NotEqual(Guid.Empty, securityVersion);
        var result = await fixture.ReadAsync();
        Assert.False(result.IsActive);
        Assert.Equal("security_review", result.RevocationReason);
        Assert.Equal(securityVersion, result.AuthorityVersion);
    }

    /// <summary>The conditional endpoint must commit before a queued newer SQL revocation, without a lock cycle.</summary>
    [Fact]
    public async Task ConditionalReactivation_ConcurrentWriterPreservesNewerCauseWithoutDeadlock()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        var request = fixture.Request(original);
        var url = $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional";
        Task concurrentWriter = Task.CompletedTask;
        Guid securityVersion = Guid.Empty;
        fixture.BeforeHttpLicenseUpdate = async () =>
        {
            concurrentWriter = Task.Run(async () =>
            {
                await using var writer = fixture.Db();
                await writer.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE "Licenses" SET "IsActive" = false, "RevocationReason" = 'security_review',
                        "RevokedAt" = now() WHERE "Id" = {original.Id}
                    """);
                securityVersion = (await fixture.ReadAsync()).AuthorityVersion;
            });
            await fixture.WaitForWriterCompletionOrLockAsync(concurrentWriter);
        };
        using var activation = await fixture.Client.PostAsJsonAsync(url, request);
        await concurrentWriter.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);
        var final = await fixture.ReadAsync();
        Assert.False(final.IsActive);
        Assert.Equal("security_review", final.RevocationReason);
        Assert.Equal(securityVersion, final.AuthorityVersion);
        Assert.NotEqual(original.AuthorityVersion, final.AuthorityVersion);
        Assert.Equal(original.ExpirationDate, final.ExpirationDate);
        await using var db = fixture.Db();
        Assert.Equal(request.ExpectedOwnershipId, (await db.RuntimeRecoveryCommercialOwnerships.SingleAsync()).Id);
        Assert.Equal(1, await db.LicenseHistories.CountAsync());
        using var replay = await fixture.Client.PostAsJsonAsync(url, request);
        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
        Assert.Equal(securityVersion, (await fixture.ReadAsync()).AuthorityVersion);
    }

    /// <summary>A held trigger authority lock must delay conditional state changes before any license row lock.</summary>
    [Fact]
    public async Task ConditionalReactivation_WaitsForGlobalAuthorityBeforeMutation()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        await using var holder = fixture.Db();
        await using var transaction = await holder.Database.BeginTransactionAsync();
        await holder.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        var pending = fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional", fixture.Request(original));
        await fixture.WaitForLicenseLockAsync("pg_advisory_xact_lock");
        Assert.False(pending.IsCompleted);
        Assert.Equal(original.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        await transaction.CommitAsync();
        using var completed = await pending;
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
    }

    /// <summary>Legacy sequential retries preserve an existing revocation cause and do not rotate its version.</summary>
    [Fact]
    public async Task LegacyRevoke_AlreadyInactivePreservesCauseDateAndVersion()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        using var response = await fixture.Client.PostAsJsonAsync(
            $"/api/admin/licenses/{original.LicenseKey}/revoke", new { Reason = "User self-revoke from dashboard" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var unchanged = await fixture.ReadAsync();
        Assert.Equal(original.AuthorityVersion, unchanged.AuthorityVersion);
        Assert.Equal(original.RevocationReason, unchanged.RevocationReason);
        Assert.Equal(original.RevokedAt, unchanged.RevokedAt);
        await using var db = fixture.Db();
        Assert.Empty(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>Both legacy actions wait for an external row writer before reading its committed state.</summary>
    [Theory]
    [InlineData("revoke", true)]
    [InlineData("unrevoke", true)]
    [InlineData("revoke", false)]
    [InlineData("unrevoke", false)]
    public async Task LegacyActions_WaitForRowBeforeReadAndReplayWithoutAdditionalMutation(string action, bool writerUpdates)
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = await fixture.ReadAsync();
        await using var db = fixture.Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        if (writerUpdates)
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE "Licenses" SET "IsActive" = false, "RevocationReason" = 'security_review' WHERE "Id" = {original.Id}
                """);
        else
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                SELECT "Id" FROM "Licenses" WHERE "Id" = {original.Id} FOR UPDATE
                """);
        var url = $"/api/admin/licenses/{original.LicenseKey}/{action}";
        var waiting = fixture.Client.PostAsJsonAsync(url, new { Reason = "User self-revoke from dashboard" });
        await fixture.WaitForLicenseLockAsync(writerUpdates ? "pg_advisory_xact_lock" : "FOR UPDATE");
        Assert.False(waiting.IsCompleted);
        await transaction.CommitAsync();
        using var completed = await waiting;
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        var final = await fixture.ReadAsync();
        Assert.Equal(action == "unrevoke", final.IsActive);
        Assert.Equal(action == "unrevoke" ? null : writerUpdates ? "security_review" : original.RevocationReason, final.RevocationReason);
        Assert.Equal(original.ExpirationDate, final.ExpirationDate);
        Assert.Equal(original.MaxSeats, final.MaxSeats);
        Assert.Equal(original.LicenseTypeId, final.LicenseTypeId);
        var histories = await db.LicenseHistories.CountAsync();
        using var replay = await fixture.Client.PostAsJsonAsync(url, new { Reason = "User self-revoke from dashboard" });
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(final.AuthorityVersion, (await fixture.ReadAsync()).AuthorityVersion);
        Assert.Equal(histories, await db.LicenseHistories.CountAsync());
    }

    /// <summary>Injects one deterministic concurrent writer immediately before the HTTP EF update.</summary>
    private sealed class BeforeLicenseUpdateInterceptor : DbCommandInterceptor
    {
        /// <summary>Optional one-shot test callback; production registrations never use this interceptor.</summary>
        public Func<Task>? BeforeUpdate { get; set; }

        /// <summary>Runs the callback before SQL; the callback observes contention without awaiting a blocked writer.</summary>
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (BeforeUpdate is { } callback && command.CommandText.Contains("UPDATE \"Licenses\"", StringComparison.Ordinal))
            {
                BeforeUpdate = null;
                await callback();
            }
            return result;
        }
    }

    /// <summary>
    /// Owns one uniquely named database on an explicitly supplied local test server, a synthetic
    /// commercial owner, and a TestServer host. All owned database state is removed on disposal.
    /// </summary>
    private sealed class Fixture : IAsyncDisposable
    {
        /// <summary>Loopback maintenance connection used only to remove the owned database.</summary>
        private readonly string maintenance;
        /// <summary>Generated ASCII database identifier, safe for quoted fixture DDL.</summary>
        private readonly string database;
        /// <summary>Private fixture connection; never log its ephemeral credential.</summary>
        private readonly string connection;
        /// <summary>Owned in-process HTTP server, disposed before database removal.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Stable license UUID shared by fixture requests and assertions.</summary>
        private readonly Guid licenseId = Guid.NewGuid();
        /// <summary>Random provider subject identity, independent of customer email.</summary>
        private readonly Guid subjectId = Guid.NewGuid();
        /// <summary>Exact initial ownership version used to detect foreign or changed authority.</summary>
        private readonly Guid ownershipId = Guid.NewGuid();
        /// <summary>HTTP-only hook, excluded from independent fixture database contexts.</summary>
        private readonly BeforeLicenseUpdateInterceptor updateInterceptor = new();
        /// <summary>Installs a one-shot local concurrency checkpoint for the next HTTP UPDATE.</summary>
        public Func<Task>? BeforeHttpLicenseUpdate { set => updateInterceptor.BeforeUpdate = value; }

        /// <summary>Creates an isolated host without production credentials or outbound operations.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance;
            this.database = database;
            this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", Secret);
                builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
                // Replace every database registration so HTTP and fixture assertions share only
                // the owned PostgreSQL database; the production connection is never resolved.
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                    services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                    services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                    services.RemoveAll<LicenseDbContext>();
                    services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connection).AddInterceptors(updateInterceptor));
                });
            });
            Client = host.CreateClient();
            Client.DefaultRequestHeaders.Add("X-Admin-Secret", Secret);
        }

        /// <summary>Gets the authenticated local-only TestServer client.</summary>
        public HttpClient Client { get; }

        /// <summary>Creates a fresh context for observing committed state without tracked snapshots.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);

        /// <summary>Observes completion or an actual blocked UPDATE without imposing a circular test wait.</summary>
        public async Task WaitForWriterCompletionOrLockAsync(Task writer)
        {
            await using var observer = new NpgsqlConnection(connection);
            await observer.OpenAsync();
            for (var attempt = 0; attempt < 150; attempt++)
            {
                if (writer.IsCompleted) { await writer; return; }
                await using var command = new NpgsqlCommand("""
                    SELECT count(*) FROM pg_stat_activity
                    WHERE datname = current_database() AND wait_event_type = 'Lock'
                      AND query LIKE '%UPDATE "Licenses"%'
                    """, observer);
                if (Convert.ToInt64(await command.ExecuteScalarAsync()) > 0) return;
                await Task.Delay(20);
            }
            Assert.Fail("The independent writer neither completed nor reached a PostgreSQL UPDATE lock.");
        }

        /// <summary>Returns the exact persisted license version for subsequent conditional requests.</summary>
        public async Task<License> ReadAsync()
        {
            await using var db = Db();
            return await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == licenseId);
        }

        /// <summary>Requires observed PostgreSQL lock waiting, rather than a timing-based race assumption.</summary>
        public async Task WaitForLicenseLockAsync(string statementMarker = "FOR UPDATE")
        {
            await using var observer = new NpgsqlConnection(connection);
            await observer.OpenAsync();
            for (var attempt = 0; attempt < 150; attempt++)
            {
                await using var command = new NpgsqlCommand("""
                    SELECT count(*) FROM pg_stat_activity
                    WHERE datname = current_database() AND wait_event_type = 'Lock'
                      AND query LIKE @statement
                    """, observer);
                command.Parameters.AddWithValue("statement", "%" + statementMarker + "%");
                if (Convert.ToInt64(await command.ExecuteScalarAsync()) > 0) return;
                await Task.Delay(20);
            }
            Assert.Fail("The conditional HTTP request never reached the blocked PostgreSQL row lock.");
        }

        /// <summary>Creates one stable retry payload bound to the seeded subject and ownership version.</summary>
        public AdminController.ConditionalLicenseReactivationRequest Request(License license) => new(
            Guid.NewGuid(), license.Id, license.ProductId, subjectId, ownershipId,
            license.AuthorityVersion, license.IsActive, license.RevocationReason);

        /// <summary>Creates the exact self-revocation snapshot, including nullable UTC cause/date evidence.</summary>
        public AdminController.ConditionalLicenseRevocationRequest RevokeRequest(License license) => new(
            Guid.NewGuid(), license.Id, license.ProductId, subjectId, ownershipId,
            license.AuthorityVersion, license.IsActive, license.RevocationReason, license.RevokedAt,
            "User self-revoke from dashboard");

        /// <summary>Uses the existing conditional route to prepare an active owned fixture license.</summary>
        public async Task<License> ActivateAsync()
        {
            var original = await ReadAsync();
            using var response = await Client.PostAsJsonAsync($"/api/admin/licenses/{original.LicenseKey}/reactivate-conditional", Request(original));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await ReadAsync();
        }

        /// <summary>Performs a real ownership transfer in the established global/license/ownership order.</summary>
        public async Task TransferAsync()
        {
            await using var db = Db();
            await using var transaction = await db.Database.BeginTransactionAsync();
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT \"Id\" FROM \"Licenses\" WHERE \"Id\" = {licenseId} FOR UPDATE");
            var previous = await db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
                SELECT * FROM "RuntimeRecoveryCommercialOwnerships" WHERE "LicenseId" = {licenseId} AND "State" = 'ACTIVE' FOR UPDATE
                """).SingleAsync();
            previous.State = "TRANSFERRED"; previous.EndedAtUtc = DateTime.UtcNow;
            var successor = new RuntimeRecoveryCommercialSubject { Id = Guid.NewGuid(), ProductId = previous.ProductId, CreatedAtUtc = DateTime.UtcNow };
            db.Add(successor); await db.SaveChangesAsync();
            db.Add(new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = previous.ProductId,
                LicenseId = licenseId, OwnerSubjectId = successor.Id, PreviousOwnershipId = previous.Id,
                State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync(); await transaction.CommitAsync();
        }

        /// <summary>Creates and migrates only a generated database on an explicit loopback test server.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES")
                ?? throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES must identify a local test server.");
            var settings = new NpgsqlConnectionStringBuilder(configured);
            if (settings.Host is not ("localhost" or "127.0.0.1" or "::1"))
                throw new InvalidOperationException("TKT939 tests require a loopback PostgreSQL host.");
            var database = "tkt939_" + Guid.NewGuid().ToString("N");
            settings.Database = "postgres";
            var maintenance = settings.ConnectionString;
            await using (var admin = new NpgsqlConnection(maintenance))
            {
                await admin.OpenAsync();
                await using var command = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", admin);
                await command.ExecuteNonQueryAsync();
            }
            settings.Database = database;
            var fixture = new Fixture(maintenance, database, settings.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                await db.Database.MigrateAsync();
                var product = new Product { Name = database, ApiSecret = "tkt939-product-fixture" };
                var type = new LicenseType { Product = product, Name = "Fixture Pro", Slug = "TKT939-PRO" };
                db.AddRange(product, type);
                await db.SaveChangesAsync();
                db.Licenses.Add(new License
                {
                    Id = fixture.licenseId, LicenseKey = Guid.NewGuid().ToString("D"), ProductId = product.Id,
                    LicenseTypeId = type.Id, CustomerEmail = "fixture@example.test", IsActive = false,
                    RevocationReason = "profile_required", RevokedAt = DateTime.UtcNow,
                    ExpirationDate = DateTime.UtcNow.AddDays(20), MaxSeats = 3
                });
                db.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
                {
                    Id = fixture.subjectId, ProductId = product.Id, CreatedAtUtc = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
                db.RuntimeRecoveryCommercialOwnerships.Add(new RuntimeRecoveryCommercialOwnership
                {
                    Id = fixture.ownershipId, LicenseId = fixture.licenseId, ProductId = product.Id,
                    OwnerSubjectId = fixture.subjectId, State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        /// <summary>Closes the HTTP host before dropping only this fixture-generated database.</summary>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await host.DisposeAsync();
            NpgsqlConnection.ClearAllPools();
            await using var admin = new NpgsqlConnection(maintenance);
            await admin.OpenAsync();
            await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", admin);
            await command.ExecuteNonQueryAsync();
        }
    }
}
