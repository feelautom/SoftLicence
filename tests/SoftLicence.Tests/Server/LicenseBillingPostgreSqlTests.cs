using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Real HTTP/PostgreSQL billing authority tests with synthetic identities and an injected UTC clock.</summary>
public sealed class LicenseBillingPostgreSqlTests
{
    /// <summary>First-delivery null expiry is explicit current evidence; repeated reads create no authority, history or ownership mutation.</summary>
    [Fact]
    public async Task AuthorityObservation_FirstDeliveryIsReadOnly()
    {
        await using var f = await Fixture.CreateAsync(); await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = NULL WHERE \"Id\" = {f.LicenseId}");
        var before = await f.ReadAsync();
        var owners = JsonSerializer.Serialize(await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().ToListAsync());
        var request = new AdminController.LicenseBillingAuthorityRequest(before.Id, before.ProductId, f.SubjectId, f.OwnershipId, before.AuthorityVersion);
        for (var i = 0; i < 2; i++)
        {
            using var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!["currentAuthority"]!;
            Assert.Equal(before.Id.ToString(), body["id"]!.GetValue<string>());
            Assert.Equal(f.SubjectId.ToString(), body["commercialSubjectId"]!.GetValue<string>());
            Assert.True(body.AsObject().ContainsKey("expirationDate")); Assert.Null(body["expirationDate"]);
            Assert.True(body["isActive"]!.GetValue<bool>());
            Assert.Equal("true", body["type"]!["params"]![0]!["value"]!.GetValue<string>());
            Assert.True(body.AsObject().ContainsKey("activationDate")); Assert.True(body.AsObject().ContainsKey("hardwareId"));
        }
        Assert.Equal(JsonSerializer.Serialize(before), JsonSerializer.Serialize(await f.ReadAsync()));
        Assert.Equal(owners, JsonSerializer.Serialize(await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().ToListAsync()));
        Assert.Equal(0, await db.LicenseHistories.CountAsync()); Assert.Equal(0, await db.LicenseSeats.CountAsync());
    }

    /// <summary>Every UUID is required, nonempty and immutable in the request shape; aliases and operation-like extras fail before observation.</summary>
    [Fact]
    public async Task AuthorityObservation_StrictShapeAndIdentity()
    {
        await using var f = await Fixture.CreateAsync(); var before = await f.ReadAsync();
        var request = new AdminController.LicenseBillingAuthorityRequest(before.Id, before.ProductId, f.SubjectId, f.OwnershipId, before.AuthorityVersion);
        var body = JsonSerializer.SerializeToNode(request)!.AsObject();
        foreach (var key in body.Select(pair => pair.Key).ToArray())
        {
            var missing = body.DeepClone().AsObject(); missing.Remove(key);
            using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, missing)) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var empty = body.DeepClone().AsObject(); empty[key] = Guid.Empty.ToString();
            using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, empty)) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        var duplicate = body.DeepClone().AsObject(); duplicate["licenseId"] = before.Id.ToString();
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, duplicate)) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var extra = body.DeepClone().AsObject(); extra["OperationId"] = Guid.NewGuid().ToString();
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, extra)) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        foreach (var changed in new[] { request with { LicenseId = Guid.NewGuid() }, request with { ProductId = Guid.NewGuid() } })
        { using var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, changed); Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); }
        foreach (var changed in new[] { request with { CommercialSubjectId = Guid.NewGuid() }, request with { ExpectedOwnershipId = Guid.NewGuid() },
            request with { ExpectedAuthorityVersion = Guid.NewGuid() } })
        { using var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, changed); Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.DoesNotContain(f.SubjectId.ToString(), await response.Content.ReadAsStringAsync()); }
        using (var response = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{Guid.NewGuid():D}/billing-authority", request))
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        await using var db = f.Db(); Assert.Equal(0, await db.LicenseHistories.CountAsync());
    }

    /// <summary>Activation makes the old version stale; transfer cannot be disguised by reobserving only the license version.</summary>
    [Fact]
    public async Task AuthorityObservation_ActivationAndTransferRequireCurrentExactOwner()
    {
        await using var f = await Fixture.CreateAsync(); var before = await f.ReadAsync();
        var request = new AdminController.LicenseBillingAuthorityRequest(before.Id, before.ProductId, f.SubjectId, f.OwnershipId, before.AuthorityVersion);
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ActivationDate\" = {f.Start}, \"HardwareId\" = 'synthetic-hardware' WHERE \"Id\" = {f.LicenseId}");
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request)) Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        request = request with { ExpectedAuthorityVersion = (await f.ReadAsync()).AuthorityVersion };
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request)) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await f.TransferAsync();
        request = request with { ExpectedAuthorityVersion = (await f.ReadAsync()).AuthorityVersion };
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request)) Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(0, await db.LicenseHistories.CountAsync());
    }

    /// <summary>An observation of security-revoked or expired authority never changes it into a paid or active entitlement.</summary>
    [Fact]
    public async Task AuthorityObservation_RevokedStateRemainsExplicit()
    {
        await using var f = await Fixture.CreateAsync(); await f.SecurityRevokeAsync(); var before = await f.ReadAsync();
        using var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl,
            new AdminController.LicenseBillingAuthorityRequest(before.Id, before.ProductId, f.SubjectId, f.OwnershipId, before.AuthorityVersion));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!["currentAuthority"]!;
        Assert.False(body["isActive"]!.GetValue<bool>()); Assert.Equal("security_review", body["revocationReason"]!.GetValue<string>());
        Assert.Equal(JsonSerializer.Serialize(before), JsonSerializer.Serialize(await f.ReadAsync()));
        await using var db = f.Db(); Assert.Equal(0, await db.LicenseHistories.CountAsync());
    }

    /// <summary>Missing authentication and a valid secret scoped to another product cannot disclose current authority.</summary>
    [Fact]
    public async Task AuthorityObservation_ProductScopeIsEnforced()
    {
        await using var f = await Fixture.CreateAsync(); var before = await f.ReadAsync();
        var request = new AdminController.LicenseBillingAuthorityRequest(before.Id, before.ProductId, f.SubjectId, f.OwnershipId, before.AuthorityVersion);
        f.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request)) Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await using var db = f.Db(); db.Products.Add(new Product { Name = "unrelated-748", ApiSecret = "tkt748-other-product" }); await db.SaveChangesAsync();
        f.Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt748-other-product");
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request)) Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        f.Client.DefaultRequestHeaders.Remove("X-Admin-Secret"); f.Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt748-product-fixture");
        using (var response = await f.Client.PostAsJsonAsync(f.AuthorityUrl, request)) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion); Assert.Equal(0, await db.LicenseHistories.CountAsync());
    }

    /// <summary>Configuration DML blocks the observation until commit, proving one coherent snapshot without rotating license authority.</summary>
    [Fact]
    public async Task AuthorityObservation_WaitsForConfigurationWriter()
    {
        await using var f = await Fixture.CreateAsync(); var before = await f.ReadAsync();
        await using var db = f.Db(); await using var writer = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypeCustomParams\" SET \"Value\" = 'false' WHERE \"LicenseTypeId\" = {before.LicenseTypeId}");
        var pending = f.Client.PostAsJsonAsync(f.AuthorityUrl,
            new AdminController.LicenseBillingAuthorityRequest(before.Id, before.ProductId, f.SubjectId, f.OwnershipId, before.AuthorityVersion));
        await f.WaitForLockAsync("LOCK TABLE"); Assert.False(pending.IsCompleted); await writer.CommitAsync();
        using var response = await pending; Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!["currentAuthority"]!;
        Assert.Equal("false", body["type"]!["params"]![0]!["value"]!.GetValue<string>());
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion); Assert.Equal(0, await db.LicenseHistories.CountAsync());
    }

    /// <summary>Exact existing H24 expiry can be adopted before or after cutoff under fresh CAS, then suspended without changing rights.</summary>
    [Theory]
    [InlineData(23)]
    [InlineData(24)]
    [InlineData(168)]
    public async Task GraceExistingH24_AdoptsCurrentAuthorityWithoutExtension(int hours)
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {f.Start.AddHours(24)} WHERE \"Id\" = {f.LicenseId}");
        f.Clock.Now = f.Start.AddHours(hours);
        var stale = await f.RequestAsync("GRACE");
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ActivationDate\" = {f.Start.AddHours(1)} WHERE \"Id\" = {f.LicenseId}");
        await f.StatusAsync(stale, HttpStatusCode.Conflict);
        var request = await f.RequestAsync("GRACE");
        await f.StatusAsync(request with { OperationId = Guid.NewGuid(), DesiredMaxSeats = 4 }, HttpStatusCode.Conflict);
        var before = await f.ReadAsync();
        await f.OkAsync(request);
        var adopted = await f.ReadAsync();
        Assert.Equal(before.ExpirationDate, adopted.ExpirationDate);
        Assert.Equal(before.LicenseKey, adopted.LicenseKey);
        await f.OkAsync(request);
        Assert.Equal(adopted.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(1, await db.LicenseHistories.CountAsync());
        f.Clock.Now = f.Start.AddHours(Math.Max(hours, 24));
        await f.OkAsync(await f.RequestAsync("SUSPEND", request.OperationId));
        Assert.False((await f.ReadAsync()).IsActive);
        Assert.Equal(before.ExpirationDate, (await f.ReadAsync()).ExpirationDate);
        await f.StatusAsync(request, HttpStatusCode.Conflict);
    }

    /// <summary>Even one microsecond away from H24 is not an adoption; unrelated acquired expiry remains untouched.</summary>
    [Theory]
    [InlineData(-10)]
    [InlineData(10)]
    public async Task GraceNearbyExistingExpiry_IsNotAdopted(int ticks)
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {f.Start.AddHours(24).AddTicks(ticks)} WHERE \"Id\" = {f.LicenseId}");
        var before = await f.ReadAsync();
        await f.StatusAsync(await f.RequestAsync("GRACE"), HttpStatusCode.Conflict);
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(before.ExpirationDate, (await f.ReadAsync()).ExpirationDate);
        Assert.Equal(0, await db.LicenseHistories.CountAsync());
    }

    /// <summary>A delayed grace worker still fixes the absolute past H24 expiry before suspension, including never-activated delivery.</summary>
    [Theory]
    [InlineData(1, true)]
    [InlineData(1, false)]
    [InlineData(7, true)]
    [InlineData(7, false)]
    public async Task LateGrace_FixesPastH24WithoutLeavingActivationDuration(int delayDays, bool delivered)
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        DateTime? expiry = delivered ? null : f.Start.AddDays(-1);
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {expiry}, \"ValidityDays\" = 30 WHERE \"Id\" = {f.LicenseId}");
        f.Clock.Now = f.Start.AddDays(delayDays);
        var grace = await f.RequestAsync("GRACE"); await f.OkAsync(grace);
        Assert.Equal(f.Start.AddHours(24), (await f.ReadAsync()).ExpirationDate);
        await f.OkAsync(await f.RequestAsync("SUSPEND", grace.OperationId));
        Assert.False((await f.ReadAsync()).IsActive);
        Assert.Equal(f.Start.AddHours(24), (await f.ReadAsync()).ExpirationDate);
    }

    /// <summary>Delayed grace cannot shorten a recently acquired paid period.</summary>
    [Fact]
    public async Task LateGrace_ProtectsExistingPaidPeriod()
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {f.Start.AddDays(20)} WHERE \"Id\" = {f.LicenseId}");
        f.Clock.Now = f.Start.AddDays(7);
        var before = await f.ReadAsync();
        await f.StatusAsync(await f.RequestAsync("GRACE"), HttpStatusCode.Conflict);
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(before.ExpirationDate, (await f.ReadAsync()).ExpirationDate);
    }

    /// <summary>A new paid order at J8 reuses a terminal suspension without waiting for the voided monthly or annual invoice period.</summary>
    [Theory]
    [InlineData(30)]
    [InlineData(365)]
    public async Task TerminalReturnAtJ8_DoesNotWaitForUnpaidPeriodEnd(int unpaidDays)
    {
        await using var f = await Fixture.CreateAsync();
        var grace = (await f.RequestAsync("GRACE")) with { PeriodEndUtc = f.Start.AddDays(unpaidDays) };
        await f.OkAsync(grace); f.Clock.Now = f.Start.AddHours(24);
        var suspend = (await f.RequestAsync("SUSPEND", grace.OperationId)) with { PeriodEndUtc = grace.PeriodEndUtc };
        await f.OkAsync(suspend); f.Clock.Now = f.Start.AddDays(8);
        var returned = (await f.RequestAsync("PAID", suspend.OperationId)) with {
            CycleId = "cycle-j8-return", SubscriptionId = "sub-j8-return", InvoiceId = "in-j8-return",
            PeriodStartUtc = f.Clock.Now, PeriodEndUtc = f.Clock.Now.AddDays(unpaidDays), GraceStartedAtUtc = null,
            PreviousCycleTerminatedAtUtc = f.Start.AddDays(7) };
        await f.StatusAsync(returned with { PreviousCycleTerminatedAtUtc = null }, HttpStatusCode.Conflict);
        await f.StatusAsync(returned with { PreviousCycleTerminatedAtUtc = f.Start.AddDays(7).AddTicks(-10) }, HttpStatusCode.Conflict);
        await f.StatusAsync(returned with { PreviousCycleTerminatedAtUtc = f.Clock.Now.AddDays(1) }, HttpStatusCode.Conflict);
        await f.StatusAsync(returned with { SubscriptionId = suspend.SubscriptionId }, HttpStatusCode.Conflict);
        await f.StatusAsync(returned with { InvoiceId = suspend.InvoiceId }, HttpStatusCode.Conflict);
        await f.OkAsync(returned);
        Assert.True((await f.ReadAsync()).IsActive);
        Assert.Equal(returned.PeriodEndUtc, (await f.ReadAsync()).ExpirationDate);
        var oldInvoice = (await f.RequestAsync("PAID", suspend.OperationId)) with { PeriodEndUtc = grace.PeriodEndUtc };
        await f.StatusAsync(oldInvoice, HttpStatusCode.Conflict);
    }

    /// <summary>Historical receipt observation survives activation without reapplying an uncertain GRACE or PAID command.</summary>
    [Theory]
    [InlineData("GRACE")]
    [InlineData("PAID")]
    public async Task ReceiptAfterDiscardedResponseAndActivation_IsReadOnly(string command)
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync(command);
        using (var ignored = await f.PostAsync(request)) Assert.Equal(HttpStatusCode.OK, ignored.StatusCode);
        var historical = await f.ReadAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ActivationDate\" = {f.Start.AddHours(1)}, \"HardwareId\" = 'fixture-observation' WHERE \"Id\" = {f.LicenseId}");
        var current = await f.ReadAsync();
        await f.StatusAsync(request, HttpStatusCode.Conflict);
        using var response = await f.ObserveAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("appliedHistorically").GetBoolean());
        Assert.False(body.RootElement.GetProperty("resultVersionMatchesCurrent").GetBoolean());
        Assert.True(body.RootElement.GetProperty("protectedResultMatchesCurrent").GetBoolean());
        Assert.Equal(historical.AuthorityVersion, body.RootElement.GetProperty("historicalResult").GetProperty("authorityVersion").GetGuid());
        Assert.Equal(current.AuthorityVersion, body.RootElement.GetProperty("currentAuthority").GetProperty("authorityVersion").GetGuid());
        Assert.Equal(current.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(1, await db.LicenseHistories.CountAsync());
        using var altered = await f.ObserveAsync(request with { InvoiceId = "in-altered" });
        Assert.Equal(HttpStatusCode.Conflict, altered.StatusCode);
        f.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        using var unauthorized = await f.ObserveAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
    }

    /// <summary>Read-only observation cannot hide transferred authority, foreign causes or changed type configuration.</summary>
    [Theory]
    [InlineData("transfer")]
    [InlineData("cause")]
    [InlineData("configuration")]
    public async Task ReceiptObservation_DivergentAuthorityNeverReapplies(string change)
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID"); await f.OkAsync(request);
        if (change == "transfer") await f.TransferAsync();
        else if (change == "cause") await f.SecurityRevokeAsync();
        else await f.ChangeTypeAsync("parameter");
        var before = await f.ReadAsync();
        using var response = await f.ObserveAsync(request);
        Assert.Equal(change == "configuration" ? HttpStatusCode.OK : HttpStatusCode.Conflict, response.StatusCode);
        if (change == "configuration")
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.True(body.RootElement.GetProperty("appliedHistorically").GetBoolean());
            Assert.False(body.RootElement.GetProperty("protectedResultMatchesCurrent").GetBoolean());
        }
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(before.IsActive, (await f.ReadAsync()).IsActive);
        await using var db = f.Db();
        Assert.Equal(1, await db.LicenseHistories.CountAsync());
    }

    /// <summary>An invoice that entered grace cannot bypass its strict J7 boundary by omitting the receipt link.</summary>
    [Fact]
    public async Task PaidGraceInvoiceWithoutPredecessor_IsRejected()
    {
        await using var f = await Fixture.CreateAsync();
        var grace = await f.RequestAsync("GRACE"); await f.OkAsync(grace);
        f.Clock.Now = f.Start.AddDays(7);
        var before = await f.ReadAsync();
        await f.StatusAsync(await f.RequestAsync("PAID"), HttpStatusCode.Conflict);
        // Changing a known invoice's cycle/period cannot turn it into a later new order.
        f.Clock.Now = f.Start.AddDays(365);
        var relabeled = await f.RequestAsync("PAID", grace.OperationId);
        await f.StatusAsync(relabeled with { CycleId = "cycle-relabel", SubscriptionId = "sub-relabel",
            PeriodStartUtc = f.Clock.Now, PeriodEndUtc = f.Clock.Now.AddDays(30) }, HttpStatusCode.Conflict);
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
    }

    /// <summary>First-activation bookkeeping changes the row version, but must not prevent suspension of unchanged grace authority.</summary>
    [Fact]
    public async Task GraceFirstActivation_PreservesBoundedSuspension()
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = NULL, \"ValidityDays\" = 30 WHERE \"Id\" = {f.LicenseId}");
        var grace = await f.RequestAsync("GRACE"); await f.OkAsync(grace);
        var beforeActivation = await f.ReadAsync();
        var staleSuspend = await f.RequestAsync("SUSPEND", grace.OperationId);
        // Actual persisted fields written by runtime/distribution first activation. This exercises
        // the real authority trigger, not a fabricated in-memory version; activation HTTP is separate.
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ActivationDate\" = {f.Start.AddHours(1)}, \"HardwareId\" = 'fixture-hardware' WHERE \"Id\" = {f.LicenseId}");
        Assert.NotEqual(beforeActivation.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        f.Clock.Now = f.Start.AddHours(24);
        await f.StatusAsync(staleSuspend, HttpStatusCode.Conflict);
        var suspend = await f.RequestAsync("SUSPEND", grace.OperationId);
        await f.OkAsync(suspend);
        Assert.False((await f.ReadAsync()).IsActive);
        await f.StatusAsync(grace, HttpStatusCode.Conflict);
    }

    /// <summary>Payment during active grace replaces its exact expiry after a fresh observation of activation bookkeeping.</summary>
    [Fact]
    public async Task PaidDuringGrace_AfterActivationUsesAbsolutePeriod()
    {
        await using var f = await Fixture.CreateAsync();
        var grace = await f.RequestAsync("GRACE"); await f.OkAsync(grace);
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ActivationDate\" = {f.Start.AddHours(1)}, \"HardwareId\" = 'fixture-paid-hardware' WHERE \"Id\" = {f.LicenseId}");
        f.Clock.Now = f.Start.AddHours(2);
        await f.OkAsync(await f.RequestAsync("PAID", grace.OperationId));
        Assert.Equal(f.Start.AddDays(30), (await f.ReadAsync()).ExpirationDate);
        Assert.True((await f.ReadAsync()).IsActive);
    }

    /// <summary>A suspended result changed and restored by other writers cannot authorize clearing its cause with a fresh CAS.</summary>
    [Fact]
    public async Task SuspensionAba_FreshPaidCannotClearHistoricalCause()
    {
        await using var f = await Fixture.CreateAsync();
        var suspend = await f.SuspendAsync();
        var original = await f.ReadAsync();
        await f.SecurityRevokeAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = FALSE, \"RevocationReason\" = {original.RevocationReason}, \"RevokedAt\" = {original.RevokedAt} WHERE \"Id\" = {f.LicenseId}");
        await f.StatusAsync(await f.RequestAsync("PAID", suspend.OperationId), HttpStatusCode.Conflict);
        var result = await f.ReadAsync();
        Assert.False(result.IsActive);
        Assert.Equal(original.RevocationReason, result.RevocationReason);
        Assert.NotEqual(original.AuthorityVersion, result.AuthorityVersion);
    }

    /// <summary>A completed revoke/restore permits only a fresh current decision; outstanding causes and stale replays fail closed.</summary>
    [Theory]
    [InlineData("SUSPEND")]
    [InlineData("PAID")]
    public async Task GraceAuthorityAba_RequiresFreshDecisionAndNoOutstandingCause(string command)
    {
        await using var f = await Fixture.CreateAsync();
        var grace = await f.RequestAsync("GRACE"); await f.OkAsync(grace);
        var stale = await f.RequestAsync(command, grace.OperationId);
        await f.SecurityRevokeAsync();
        f.Clock.Now = f.Start.AddHours(24);
        await f.StatusAsync(await f.RequestAsync(command, grace.OperationId), HttpStatusCode.Conflict);
        Assert.Equal("security_review", (await f.ReadAsync()).RevocationReason);
        Assert.False((await f.ReadAsync()).IsActive);
        await using var db = f.Db();
        // An independent authority explicitly restores the license. Billing must not infer or
        // perform this restoration; the actual trigger records a new version for both writes.
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = TRUE, \"RevocationReason\" = NULL, \"RevokedAt\" = NULL WHERE \"Id\" = {f.LicenseId}");
        await f.StatusAsync(grace, HttpStatusCode.Conflict);
        await f.StatusAsync(stale, HttpStatusCode.Conflict);
        var fresh = await f.RequestAsync(command, grace.OperationId);
        if (command == "PAID") await f.StatusAsync(fresh with { PaidAtUtc = null }, HttpStatusCode.BadRequest);
        await f.OkAsync(fresh);
        var result = await f.ReadAsync();
        Assert.Equal(command == "PAID", result.IsActive);
        Assert.Equal(command == "PAID" ? f.Start.AddDays(30) : f.Start.AddHours(24), result.ExpirationDate);
    }

    /// <summary>A paid seat reduction cannot silently discard occupied seats or mutate the license on rejection.</summary>
    [Fact]
    public async Task PaidOccupiedSeats_CannotBeShrunk()
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        db.LicenseSeats.AddRange(new LicenseSeat { LicenseId = f.LicenseId, HardwareId = "fixture-one" },
            new LicenseSeat { LicenseId = f.LicenseId, HardwareId = "fixture-two" });
        await db.SaveChangesAsync();
        var before = await f.ReadAsync();
        await f.StatusAsync((await f.RequestAsync("PAID")) with { DesiredMaxSeats = 1 }, HttpStatusCode.Conflict);
        Assert.Equal(before.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(2, await db.LicenseSeats.CountAsync(s => s.IsActive));
    }

    /// <summary>Proves exact H24 suspension, delayed pre-J7 payment recovery and no grace added to the paid period.</summary>
    [Fact]
    public async Task GraceSuspendPaid_UsesExactBoundariesAndSameKey()
    {
        await using var f = await Fixture.CreateAsync();
        var initial = await f.ReadAsync();
        var grace = await f.RequestAsync("GRACE");
        await f.OkAsync(grace);
        var granted = await f.ReadAsync();
        Assert.Equal(f.Start.AddHours(24), granted.ExpirationDate);
        f.Clock.Now = f.Start.AddHours(24).AddTicks(-10);
        var suspend = await f.RequestAsync("SUSPEND", grace.OperationId);
        await f.StatusAsync(suspend, HttpStatusCode.Conflict);
        f.Clock.Now = f.Start.AddHours(24);
        await f.OkAsync(suspend);
        Assert.False((await f.ReadAsync()).IsActive);
        f.Clock.Now = f.Start.AddDays(8); // Delivery is late, but declared payment happened before J7.
        var paid = await f.RequestAsync("PAID", suspend.OperationId);
        paid = paid with { PaidAtUtc = f.Start.AddDays(7).AddTicks(-10) };
        await f.OkAsync(paid);
        var result = await f.ReadAsync();
        Assert.True(result.IsActive);
        Assert.Equal(initial.LicenseKey, result.LicenseKey);
        Assert.Equal(initial.Id, result.Id);
        Assert.Equal(f.Start.AddDays(30), result.ExpirationDate);
        Assert.Null(result.RevocationReason);
        Assert.Equal(initial.MaxSeats, result.MaxSeats);
        await f.StatusAsync(grace, HttpStatusCode.Conflict);
        await using var db = f.Db();
        Assert.Equal(3, await db.LicenseHistories.CountAsync());
    }

    /// <summary>Payment at J7 is outside recovery; a new later paid cycle retains the key and distinct invoice IDs.</summary>
    [Fact]
    public async Task TerminalBoundaryAndLaterReturn_RequireNewPaidPeriod()
    {
        await using var f = await Fixture.CreateAsync();
        var suspended = await f.SuspendAsync();
        f.Clock.Now = f.Start.AddDays(7);
        var late = await f.RequestAsync("PAID", suspended.OperationId);
        await f.StatusAsync(late, HttpStatusCode.Conflict);
        f.Clock.Now = f.Start.AddDays(365);
        var returned = await f.RequestAsync("PAID", suspended.OperationId);
        returned = returned with { CycleId = "cycle-return", SubscriptionId = "sub-return", InvoiceId = "in-return",
            PeriodStartUtc = f.Clock.Now, PeriodEndUtc = f.Clock.Now.AddDays(30), GraceStartedAtUtc = null,
            PreviousCycleTerminatedAtUtc = f.Start.AddDays(7) };
        await f.OkAsync(returned);
        Assert.True((await f.ReadAsync()).IsActive);
        await f.StatusAsync(late, HttpStatusCode.Conflict);
    }

    /// <summary>Concurrent retries and a discarded response produce one receipt; other IDs/payloads/routes cannot reuse payment.</summary>
    [Fact]
    public async Task Paid_ConcurrentReplayAndLostResponseAreIdempotent()
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID");
        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => f.PostAsync(request)));
        foreach (var response in responses) { using (response) Assert.Equal(HttpStatusCode.OK, response.StatusCode); }
        var after = await f.ReadAsync();
        // Deliberately discard all original response bodies, then recover using the same command.
        await f.OkAsync(request);
        Assert.Equal(after.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        await f.StatusAsync(request with { DesiredMaxSeats = 4 }, HttpStatusCode.Conflict);
        await f.StatusAsync((await f.RequestAsync("PAID")) with { OperationId = Guid.NewGuid() }, HttpStatusCode.Conflict);
        using var crossRoute = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{after.LicenseKey}/reactivate-conditional",
            new AdminController.ConditionalLicenseReactivationRequest(request.OperationId, after.Id, after.ProductId,
                f.SubjectId, f.OwnershipId, after.AuthorityVersion, true, null));
        Assert.Equal(HttpStatusCode.Conflict, crossRoute.StatusCode);
        await using var db = f.Db();
        Assert.Equal(1, await db.LicenseHistories.CountAsync());
    }

    /// <summary>A receipt insertion error must leave the pre-command version, expiration and state unchanged.</summary>
    [Theory]
    [InlineData("PAID")]
    [InlineData("GRACE")]
    public async Task ReceiptFailure_RollsBackEntireMutation(string command)
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        if (command == "GRACE")
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {f.Start.AddHours(24)} WHERE \"Id\" = {f.LicenseId}");
        var original = await f.ReadAsync();
        var request = await f.RequestAsync(command);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION tkt748_fail() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN RAISE EXCEPTION 'fixture receipt failure'; END; $body$;
            CREATE TRIGGER tkt748_fail BEFORE INSERT ON "LicenseHistories" FOR EACH ROW EXECUTE FUNCTION tkt748_fail();
            """);
        await f.StatusAsync(request, HttpStatusCode.InternalServerError);
        Assert.Equal(original.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(original.ExpirationDate, (await f.ReadAsync()).ExpirationDate);
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER tkt748_fail ON \"LicenseHistories\"; DROP FUNCTION tkt748_fail();");
        await f.OkAsync(request);
    }

    /// <summary>Current security/refund/dispute/self/profile causes cannot be reclassified as recoverable billing suspension.</summary>
    [Theory]
    [InlineData("security_review")]
    [InlineData("fraud")]
    [InlineData("refund")]
    [InlineData("dispute")]
    [InlineData("profile_required")]
    [InlineData("User self-revoke from dashboard")]
    public async Task ForeignRevocation_IsNeverCleared(string cause)
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevocationReason\" = {cause}, \"RevokedAt\" = {f.Start}, \"ExpirationDate\" = {f.Start.AddHours(24)} WHERE \"Id\" = {f.LicenseId}");
        var original = await f.ReadAsync();
        await f.StatusAsync(await f.RequestAsync("PAID"), HttpStatusCode.Conflict);
        await f.StatusAsync(await f.RequestAsync("GRACE"), HttpStatusCode.Conflict);
        Assert.Equal(original.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Equal(cause, (await f.ReadAsync()).RevocationReason);
    }

    /// <summary>A transferred owner cannot execute a stale request; billing winning first blocks transfer and invalidates replay afterward.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TransferAndPayment_BothOrdersPreserveAuthority(bool transferFirst)
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID");
        if (transferFirst)
        {
            await f.TransferAsync();
            await f.StatusAsync(request, HttpStatusCode.Conflict);
            Assert.Equal(f.Start, (await f.ReadAsync()).ExpirationDate);
        }
        else
        {
            Task? transfer = null;
            // Observe the blocked real SQL writer, then let HTTP release its locks before awaiting it.
            f.BeforeUpdate = async () => { transfer = f.TransferAsync(); await f.WaitForLockAsync("pg_advisory_xact_lock"); Assert.False(transfer.IsCompleted); };
            await f.OkAsync(request);
            await transfer!;
            await f.StatusAsync(request, HttpStatusCode.Conflict);
        }
    }

    /// <summary>A concurrent security writer winning first rejects payment; winning billing never loses the subsequent revocation.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SecurityWriterAndPayment_BothOrdersPreserveNewerCause(bool revokeFirst)
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID");
        if (revokeFirst)
        {
            await f.SecurityRevokeAsync();
            await f.StatusAsync(request, HttpStatusCode.Conflict);
        }
        else
        {
            Task? revoke = null;
            f.BeforeUpdate = async () => { revoke = f.SecurityRevokeAsync(); await f.WaitForLockAsync("UPDATE"); Assert.False(revoke.IsCompleted); };
            await f.OkAsync(request);
            await revoke!;
            await f.StatusAsync(request, HttpStatusCode.Conflict);
        }
        Assert.Equal("security_review", (await f.ReadAsync()).RevocationReason);
        Assert.False((await f.ReadAsync()).IsActive);
    }

    /// <summary>Type/parameter DML and phantom inserts wait during billing, and any later change invalidates its receipt.</summary>
    [Theory]
    [InlineData("parameter")]
    [InlineData("insert")]
    [InlineData("type")]
    public async Task ConfigurationWriter_IsSerializedAndInvalidatesReplay(string mutation)
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID");
        Task? writer = null;
        f.BeforeUpdate = async () => { writer = f.ChangeTypeAsync(mutation); await f.WaitForLockAsync(mutation == "insert" ? "INSERT" : "UPDATE"); Assert.False(writer.IsCompleted); };
        await f.OkAsync(request);
        await writer!;
        await f.StatusAsync(request, HttpStatusCode.Conflict);
    }

    /// <summary>Changes committed after snapshot but before HTTP are rejected even when the license version is unchanged.</summary>
    [Fact]
    public async Task ConfigurationChangedBeforePost_IsRejected()
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID");
        var initial = await f.ReadAsync();
        await f.ChangeTypeAsync("parameter");
        await f.StatusAsync(request, HttpStatusCode.Conflict);
        Assert.Equal(initial.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
    }

    /// <summary>Paid type/seat changes affect only this license; active seats cannot be silently removed to fit a smaller plan.</summary>
    [Fact]
    public async Task PaidConfiguration_ChangesLicenseWithoutMutatingSharedType()
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        var newType = new LicenseType { ProductId = f.ProductId, Name = "Another Pro", Slug = "TKT748-OTHER", IsRecurring = true, DefaultMaxSeats = 5 };
        db.Add(newType); await db.SaveChangesAsync();
        var request = await f.RequestAsync("PAID");
        var desired = await f.TypeAsync(newType.Id);
        await f.OkAsync(request with { DesiredType = desired, DesiredMaxSeats = 5 });
        var result = await f.ReadAsync();
        Assert.Equal(newType.Id, result.LicenseTypeId);
        Assert.Equal(5, result.MaxSeats);
        Assert.Equal(3, (await db.LicenseTypes.FindAsync(request.ExpectedType.Id))!.DefaultMaxSeats);
        Assert.Equal(request.ExpectedType.Params[0].Value, (await db.LicenseTypeCustomParams.SingleAsync()).Value);
    }

    /// <summary>All omitted fields, casing aliases, wrong identity, missing payment and unsupported flags fail without mutations.</summary>
    [Fact]
    public async Task InvalidEvidenceAndPolicy_AreFailClosed()
    {
        await using var f = await Fixture.CreateAsync();
        var request = await f.RequestAsync("PAID");
        var original = await f.ReadAsync();
        var node = JsonSerializer.SerializeToNode(request)!.AsObject();
        foreach (var field in node.Select(p => p.Key).ToArray())
        {
            var missing = node.DeepClone().AsObject(); missing.Remove(field);
            using var result = await f.Client.PostAsJsonAsync(f.Url, missing);
            Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        }
        var duplicate = node.DeepClone().AsObject(); duplicate["operationId"] = Guid.NewGuid();
        using (var result = await f.Client.PostAsJsonAsync(f.Url, duplicate)) Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        await f.StatusAsync(request with { PaidAtUtc = null }, HttpStatusCode.BadRequest);
        await f.StatusAsync(request with { Command = "paid" }, HttpStatusCode.BadRequest);
        await f.StatusAsync(request with { InvoiceId = " in-fixture" }, HttpStatusCode.BadRequest);
        await f.StatusAsync(request with { CommercialSubjectId = Guid.NewGuid() }, HttpStatusCode.Conflict);
        await f.StatusAsync(request with { ExpectedAuthorityVersion = Guid.NewGuid() }, HttpStatusCode.Conflict);
        await f.StatusAsync(request with { ProductId = Guid.NewGuid() }, HttpStatusCode.NotFound);
        f.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        using (var result = await f.PostAsync(request)) Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        f.Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt748-local-fixture-secret");
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"IsFree\" = true WHERE \"Id\" = {original.LicenseTypeId}");
        await f.StatusAsync(await f.RequestAsync("PAID"), HttpStatusCode.Conflict);
        Assert.Equal(original.AuthorityVersion, (await f.ReadAsync()).AuthorityVersion);
        Assert.Empty(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>Mutable deterministic test clock, registered only in the isolated HTTP host.</summary>
    private sealed class Clock : TimeProvider
    {
        /// <summary>Exact UTC instant chosen by each boundary test, without real-time sleeps.</summary>
        public DateTime Now { get; set; } = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        /// <summary>Returns the explicitly controlled test instant.</summary>
        public override DateTimeOffset GetUtcNow() => new(Now);
    }

    /// <summary>HTTP-only hook for observing a concurrent blocked writer immediately before the owned UPDATE.</summary>
    private sealed class UpdateInterceptor : DbCommandInterceptor
    {
        /// <summary>One-shot callback that must observe contention without awaiting the blocked operation.</summary>
        public Func<Task>? Callback { get; set; }
        /// <summary>Runs a single concurrency checkpoint before SQL execution; independent fixture contexts bypass it.</summary>
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (Callback is { } callback && command.CommandText.Contains("UPDATE \"Licenses\"", StringComparison.Ordinal))
            { Callback = null; await callback(); }
            return result;
        }
    }

    /// <summary>Owns one generated local database and HTTP host; always disposes both, including initialization failures.</summary>
    private sealed class Fixture : IAsyncDisposable
    {
        /// <summary>Explicit loopback maintenance endpoint; never read from production configuration.</summary>
        private readonly string maintenance;
        /// <summary>Generated, validated ASCII database name exclusively owned by this fixture.</summary>
        private readonly string database;
        /// <summary>Private ephemeral PostgreSQL connection, never logged by fixture code.</summary>
        private readonly string connection;
        /// <summary>Owned local HTTP host with all database services replaced before startup.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Per-fixture concurrency hook used only by HTTP requests.</summary>
        private readonly UpdateInterceptor interceptor = new();
        /// <summary>Stable synthetic commercial subject, independent from the fixture email.</summary>
        public Guid SubjectId { get; } = Guid.NewGuid();
        /// <summary>Stable synthetic initial ownership ID; transfer creates a different successor.</summary>
        public Guid OwnershipId { get; } = Guid.NewGuid();
        /// <summary>Stable license UUID shared by HTTP and independent SQL assertions.</summary>
        public Guid LicenseId { get; } = Guid.NewGuid();
        /// <summary>Exact product UUID captured during synthetic initialization.</summary>
        public Guid ProductId { get; private set; }
        /// <summary>Exact synthetic key; retained only in test memory and isolated PostgreSQL.</summary>
        private string Key { get; } = Guid.NewGuid().ToString("D");
        /// <summary>Fixed initial period boundary, independent from subsequent injected clock movement.</summary>
        public DateTime Start { get; } = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        /// <summary>Clock used by the conditional billing route, not by unrelated providers.</summary>
        public Clock Clock { get; } = new();
        /// <summary>Authenticated TestServer client; no actual Stripe or external HTTP service is configured.</summary>
        public HttpClient Client { get; }
        /// <summary>Local relative route containing the fixture-owned license key.</summary>
        public string Url => $"/api/admin/licenses/{Key}/billing-conditional";
        /// <summary>Read-only exact-owner authority route, independent of any billing operation receipt.</summary>
        public string AuthorityUrl => $"/api/admin/licenses/{Key}/billing-authority";
        /// <summary>Installs a one-shot test-only checkpoint before the next license UPDATE.</summary>
        public Func<Task>? BeforeUpdate { set => interceptor.Callback = value; }

        /// <summary>Configures isolated HTTP services and explicit synthetic auth before creating the client.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance; this.database = database; this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", "tkt748-local-fixture-secret");
                builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
                // Replace every database registration so no production connection can be resolved.
                builder.ConfigureServices(services => {
                    services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                    services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                    services.RemoveAll<IDbContextFactory<LicenseDbContext>>(); services.RemoveAll<LicenseDbContext>();
                    services.AddDbContextFactory<LicenseDbContext>(o => o.UseNpgsql(connection).AddInterceptors(interceptor));
                    services.AddSingleton<TimeProvider>(Clock);
                });
            });
            Client = host.CreateClient();
            Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt748-local-fixture-secret");
        }

        /// <summary>Creates a fresh observation context without HTTP interception or stale tracking.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);
        /// <summary>Reads committed license state from the actual fixture database.</summary>
        public async Task<License> ReadAsync() { await using var db = Db(); return await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == LicenseId); }
        /// <summary>Posts one exact body over HTTP; callers own and dispose the response.</summary>
        public Task<HttpResponseMessage> PostAsync(AdminController.ConditionalLicenseBillingRequest request) => Client.PostAsJsonAsync(Url, request);
        /// <summary>Reads historical receipt evidence with the exact immutable body; no command is reapplied.</summary>
        public Task<HttpResponseMessage> ObserveAsync(AdminController.ConditionalLicenseBillingRequest request) =>
            Client.PostAsJsonAsync($"/api/admin/licenses/{Key}/billing-receipt", request);
        /// <summary>Checks status and includes only synthetic response diagnostics on failure.</summary>
        public async Task StatusAsync(AdminController.ConditionalLicenseBillingRequest request, HttpStatusCode expected)
        { using var response = await PostAsync(request); Assert.True(response.StatusCode == expected, $"Expected {expected}, got {response.StatusCode}: {await response.Content.ReadAsStringAsync()}"); }
        /// <summary>Requires a real HTTP acknowledgement; its body is intentionally not used as SQL evidence.</summary>
        public Task OkAsync(AdminController.ConditionalLicenseBillingRequest request) => StatusAsync(request, HttpStatusCode.OK);

        /// <summary>Builds an exact complete configuration from PostgreSQL for the requested type.</summary>
        public async Task<AdminController.BillingTypeSnapshot> TypeAsync(Guid id)
        {
            await using var db = Db(); var t = await db.LicenseTypes.Include(x => x.CustomParams).SingleAsync(x => x.Id == id);
            return new(t.Id, t.Slug, t.DefaultDurationDays, t.IsRecurring, t.DefaultAllowedVersions, t.DefaultMaxSeats,
                t.MaxActivationsPerDay, t.AllowAnonymous, t.IsFree, t.EnforceSingleUsePerHardwareId, t.DisableNewActivations,
                t.CustomParams.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new AdminController.BillingParameter(p.Key, p.Value)).ToArray());
        }

        /// <summary>Constructs fresh expected authority while retaining one exact synthetic billing cycle.</summary>
        public async Task<AdminController.ConditionalLicenseBillingRequest> RequestAsync(string command, Guid? previous = null)
        {
            var l = await ReadAsync(); var t = await TypeAsync(l.LicenseTypeId);
            return new(Guid.NewGuid(), command, l.Id, l.ProductId, SubjectId, OwnershipId, l.AuthorityVersion,
                l.IsActive, l.RevocationReason, l.RevokedAt, l.ExpirationDate, l.MaxSeats, t, t, l.MaxSeats,
                "cycle-fixture", "cus-fixture", "sub-fixture", "in-fixture", Start, Start.AddDays(30), Start,
                command == "PAID" ? Clock.Now : null, previous, null);
        }

        /// <summary>Creates actual GRACE and SUSPEND receipts by advancing only the injected HTTP clock.</summary>
        public async Task<AdminController.ConditionalLicenseBillingRequest> SuspendAsync()
        {
            var grace = await RequestAsync("GRACE"); await OkAsync(grace); Clock.Now = Start.AddHours(24);
            var suspend = await RequestAsync("SUSPEND", grace.OperationId); await OkAsync(suspend); return suspend;
        }

        /// <summary>Executes a true ownership transfer in global/license/ownership order without changing the key.</summary>
        public async Task TransferAsync()
        {
            await using var db = Db(); await using var tx = await db.Database.BeginTransactionAsync();
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT \"Id\" FROM \"Licenses\" WHERE \"Id\" = {LicenseId} FOR UPDATE");
            var previous = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(o => o.Id == OwnershipId);
            previous.State = "TRANSFERRED"; previous.EndedAtUtc = Start;
            var next = new RuntimeRecoveryCommercialSubject { ProductId = ProductId, CreatedAtUtc = Start };
            db.Add(next); await db.SaveChangesAsync();
            db.Add(new RuntimeRecoveryCommercialOwnership { LicenseId = LicenseId, ProductId = ProductId,
                OwnerSubjectId = next.Id, PreviousOwnershipId = previous.Id, State = "ACTIVE", CreatedAtUtc = Start });
            await db.SaveChangesAsync(); await tx.CommitAsync();
        }

        /// <summary>Uses an independent SQL writer and actual authority trigger to simulate a newer security revocation.</summary>
        public async Task SecurityRevokeAsync()
        { await using var db = Db(); await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevocationReason\" = 'security_review', \"RevokedAt\" = {Start} WHERE \"Id\" = {LicenseId}"); }

        /// <summary>Mutates shared type configuration using real DML, including an insertion phantom.</summary>
        public async Task ChangeTypeAsync(string mutation)
        {
            var l = await ReadAsync(); await using var db = Db();
            if (mutation == "parameter") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypeCustomParams\" SET \"Value\" = 'false' WHERE \"LicenseTypeId\" = {l.LicenseTypeId}");
            else if (mutation == "type") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"DefaultMaxSeats\" = 7 WHERE \"Id\" = {l.LicenseTypeId}");
            else { db.Add(new LicenseTypeCustomParam { LicenseTypeId = l.LicenseTypeId, Key = "new_parameter", Name = "Fixture", Value = "true" }); await db.SaveChangesAsync(); }
        }

        /// <summary>Requires observed PostgreSQL contention rather than guessing that a delay means a lock.</summary>
        public async Task WaitForLockAsync(string marker)
        {
            await using var observer = new NpgsqlConnection(connection); await observer.OpenAsync();
            for (var i = 0; i < 150; i++)
            {
                await using var cmd = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE @pattern", observer);
                cmd.Parameters.AddWithValue("pattern", "%" + marker + "%");
                if (Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0) return;
                await Task.Delay(20);
            }
            Assert.Fail("No PostgreSQL lock observed for " + marker);
        }

        /// <summary>Creates/migrates a uniquely owned database on an explicitly configured loopback PostgreSQL server.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var settings = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES")
                ?? throw new InvalidOperationException("Local test PostgreSQL connection required"));
            if (settings.Host is not ("localhost" or "127.0.0.1" or "::1")) throw new InvalidOperationException("Loopback test host required");
            settings.Database = "postgres"; var maintenance = settings.ConnectionString;
            var database = "tkt748_" + Guid.NewGuid().ToString("N");
            await using (var admin = new NpgsqlConnection(maintenance)) { await admin.OpenAsync();
                await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", admin); await cmd.ExecuteNonQueryAsync(); }
            settings.Database = database;
            Fixture? f = null;
            try
            {
                f = new Fixture(maintenance, database, settings.ConnectionString);
                await using var db = f.Db(); await db.Database.MigrateAsync();
                var product = new Product { Name = database, ApiSecret = "tkt748-product-fixture" };
                var type = new LicenseType { Product = product, Name = "Fixture Pro", Slug = "TKT748-PRO", IsRecurring = true, DefaultMaxSeats = 3 };
                type.CustomParams.Add(new LicenseTypeCustomParam { Key = "copilot", Name = "Fixture", Value = "true" });
                db.AddRange(product, type); await db.SaveChangesAsync(); f.ProductId = product.Id;
                db.Add(new License { Id = f.LicenseId, LicenseKey = f.Key, ProductId = product.Id, LicenseTypeId = type.Id,
                    CustomerEmail = "fixture@example.test", IsActive = true, ExpirationDate = f.Start, MaxSeats = 3 });
                db.Add(new RuntimeRecoveryCommercialSubject { Id = f.SubjectId, ProductId = product.Id, CreatedAtUtc = f.Start });
                await db.SaveChangesAsync();
                db.Add(new RuntimeRecoveryCommercialOwnership { Id = f.OwnershipId, LicenseId = f.LicenseId,
                    ProductId = product.Id, OwnerSubjectId = f.SubjectId, State = "ACTIVE", CreatedAtUtc = f.Start });
                await db.SaveChangesAsync(); return f;
            }
            catch
            {
                if (f is not null) await f.DisposeAsync();
                else
                {
                    // Host construction may fail before the fixture exists. The database name
                    // is still the locally generated UUID above and must not leak on this path.
                    await using var admin = new NpgsqlConnection(maintenance); await admin.OpenAsync();
                    await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", admin);
                    await cmd.ExecuteNonQueryAsync();
                }
                throw;
            }
        }

        /// <summary>Stops the owned HTTP host before dropping only its generated fixture database.</summary>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose(); await host.DisposeAsync(); NpgsqlConnection.ClearAllPools();
            await using var admin = new NpgsqlConnection(maintenance); await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", admin); await cmd.ExecuteNonQueryAsync();
        }
    }
}
