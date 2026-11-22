using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using Xunit;
using System.Security.Cryptography;
using Npgsql;

namespace SoftLicence.Tests.Server;

/// <summary>Commercial V2 regressions share the existing real HTTP/PostgreSQL fixture, never an in-memory provider.</summary>
public sealed partial class PersonalDayPassPostgreSqlTests
{
    /// <summary>New V1 rights neutralize earlier free restrictions; immutable V2 proof and historical V1 replay remain untouched.</summary>
    [Theory]
    [InlineData("payments", false)]
    [InlineData("renew", false)]
    [InlineData("billing", false)]
    [InlineData("payments", true)]
    [InlineData("renew", true)]
    [InlineData("billing", true)]
    public async Task Tkt1424_V1AcquisitionAndHistoricalReplayHaveDistinctQualification(string producer, bool replayOnly)
    {
        await using var f = await Fixture.CreateAsync();
        var foreign = await f.ReadResponseAsync(f.Request() with { CommercialSubjectId = Guid.NewGuid() });
        var hardware = VmPolicyHardware;
        await ActivatePhysicalCommercialAsync(f, foreign.LicenseKey, hardware);
        var first = Qualified(f.Request());
        Guid licenseId;
        string key;
        Func<Task<HttpResponseMessage>> acquire;
        if (producer == "payments")
        {
            var issued = await f.ReadResponseAsync(first);
            licenseId = issued.LicenseId; key = issued.LicenseKey;
            var request = f.Extend(f.Request(), issued);
            acquire = () => f.PostAsync(request);
        }
        else
        {
            using var created = await f.Client.PostAsJsonAsync("/api/admin/licenses", new AdminController.CreateLicenseRequest {
                ProductName = f.ProductName, TypeSlug = "TIA-CONNECT-PRO", CustomerName = "Synthetic buyer",
                CustomerEmail = "buyer@example.test", CommercialSubjectId = first.CommercialSubjectId,
                Reference = "v1-transition", CommercialEvidence = first.CommercialEvidence });
            Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
            await using var lookup = f.Db();
            var license = await lookup.Licenses.SingleAsync(x => x.Id != foreign.LicenseId);
            licenseId = license.Id; key = license.LicenseKey;
            if (producer == "renew")
            {
                var request = new AdminController.RenewLicenseRequest { TransactionId = "v1-acquisition", DaysToAdd = 30 };
                acquire = () => f.Client.PostAsJsonAsync($"/api/admin/licenses/{key}/renew", request);
            }
            else
            {
                var request = (await BillingAsync(f, licenseId)) with { CommercialEvidence = null };
                acquire = () => f.Client.PostAsJsonAsync($"/api/admin/licenses/{key}/billing-conditional", request);
            }
        }
        await using var db = f.Db();
        var proof = JsonSerializer.Serialize(await db.Set<CommercialOrderEvidence>().AsNoTracking().SingleAsync());
        using (var applied = await acquire()) Assert.True(applied.IsSuccessStatusCode, await applied.Content.ReadAsStringAsync());
        if (replayOnly)
        {
            var acquired = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId));
            using (var exactReplay = await acquire()) Assert.True(exactReplay.IsSuccessStatusCode, await exactReplay.Content.ReadAsStringAsync());
            Assert.Equal(acquired, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId)));
            // Seed a restriction sentinel solely to detect an illicit replay-side qualification write.
            // Production cannot downgrade UNKNOWN to FREE; no acquisition is being simulated here.
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"CommercialNature\"='FREE' WHERE \"Id\"={licenseId}");
            var before = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId));
            using var replay = await acquire();
            // Billing retains its strict historical authority CAS; the sentinel update rotates that CAS.
            if (producer == "billing") Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
            else Assert.True(replay.IsSuccessStatusCode, await replay.Content.ReadAsStringAsync());
            Assert.Equal(before, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId)));
        }
        else
        {
            Assert.Equal("UNKNOWN", (await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId)).CommercialNature);
            using var activation = await f.Client.PostAsJsonAsync("/api/activation", new {
                AppName = f.ProductName, LicenseKey = key, HardwareId = hardware, SystemUuid = VmPolicyUuid, MachineEvidence = VmPolicyEvidence("Dell Inc.", "Precision 7680"), AppVersion = "2.3.924" });
            Assert.Equal(HttpStatusCode.OK, activation.StatusCode);
            Assert.Contains("licenseFile", await activation.Content.ReadAsStringAsync());
            var active = await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId);
            Assert.True(active.IsActive); Assert.Null(active.RevokedAt); Assert.Null(active.RevocationReason);
            Assert.True((await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == foreign.LicenseId)).IsActive);
            Assert.False(await db.LicenseHistories.AnyAsync(x => x.LicenseId == licenseId && x.Action == "FIRST_ORDER_FREE_REVOKED"));
        }
        Assert.Equal(proof, JsonSerializer.Serialize(await db.Set<CommercialOrderEvidence>().AsNoTracking().SingleAsync()));
    }

    /// <summary>Grace and suspension mutate billing authority without acquiring paid rights or lifting commercial restrictions.</summary>
    [Fact]
    public async Task Tkt1424_V1GraceAndSuspendPreserveCommercialRestriction()
    {
        await using var f = await Fixture.CreateAsync();
        var issued = await f.ReadResponseAsync(Qualified(f.Request()));
        var request = await BillingAsync(f, issued.LicenseId);
        var started = request.PeriodStartUtc;
        var grace = request with { Command = "GRACE", CommercialEvidence = null, PaidAtUtc = null,
            GraceStartedAtUtc = started, GraceDurationMinutes = 60 };
        var url = $"/api/admin/licenses/{issued.LicenseKey}/billing-conditional";
        using (var response = await f.Client.PostAsJsonAsync(url, grace))
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        await using var db = f.Db();
        Assert.Equal("FIRST_ORDER_FREE", (await db.Licenses.AsNoTracking().SingleAsync()).CommercialNature);
        var suspend = (await BillingAsync(f, issued.LicenseId)) with { Command = "SUSPEND", CommercialEvidence = null,
            PaidAtUtc = null, GraceStartedAtUtc = started, GraceDurationMinutes = 60,
            PeriodStartUtc = grace.PeriodStartUtc, PeriodEndUtc = grace.PeriodEndUtc, PreviousOperationId = grace.OperationId };
        using (var response = await f.Client.PostAsJsonAsync(url, suspend))
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal("FIRST_ORDER_FREE", license.CommercialNature);
        Assert.False(license.IsActive);
        Assert.Equal("FIRST_ORDER_FREE", (await db.Set<CommercialOrderEvidence>().SingleAsync()).Nature);
    }

    /// <summary>Builds a synthetic explicit commercial assertion; neither the fixture nor production infers the nature.</summary>
    private static AdminController.PersonalDayPassRequest Qualified(AdminController.PersonalDayPassRequest request,
        string nature = "FIRST_ORDER_FREE", int amount = 0, string? order = null) => request with
    {
        CommercialEvidence = new CommercialEvidence(2, request.OperationId, order ?? "order-" + request.OperationId,
            request.CommercialSubjectId, nature, amount, "eur")
    };

    /// <summary>Changes ownership under the production lock order while retaining every immutable historical version.</summary>
    private static async Task<Guid> TransferAsync(Fixture f, Guid licenseId, Guid? subject = null)
    {
        await using var db = f.Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        var previous = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(x => x.LicenseId == licenseId && x.State == "ACTIVE");
        var nextSubject = subject ?? Guid.NewGuid();
        if (!await db.RuntimeRecoveryCommercialSubjects.AnyAsync(x => x.ProductId == previous.ProductId && x.Id == nextSubject))
            db.Add(new RuntimeRecoveryCommercialSubject { ProductId = previous.ProductId, Id = nextSubject, CreatedAtUtc = DateTime.UtcNow });
        previous.State = "TRANSFERRED";
        previous.EndedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        db.Add(new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = previous.ProductId,
            LicenseId = licenseId, OwnerSubjectId = nextSubject, PreviousOwnershipId = previous.Id,
            State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
        await transaction.CommitAsync();
        return nextSubject;
    }

    /// <summary>All paid-equivalent, ordinary gift and trial licenses preserve the pre-existing product auto-unlink behavior.</summary>
    [Theory]
    [InlineData("PAID", 800)]
    [InlineData("PAID_TRIAL", 10000)]
    [InlineData("PAID_TRIAL", 9700)]
    [InlineData("FREE", 0)]
    [InlineData("UNKNOWN", 0)]
    public async Task Tkt1424_LegitimateCommercialNaturesPreserveProductSwitch(string nature, int amount)
    {
        await using var f = await Fixture.CreateAsync();
        var old = await f.ReadResponseAsync(f.Request());
        var hardware = VmPolicyHardware;
        await ActivatePhysicalCommercialAsync(f, old.LicenseKey, hardware);
        var next = f.Request() with { CommercialSubjectId = Guid.NewGuid() };
        var issued = await f.ReadResponseAsync(nature == "UNKNOWN" ? next : Qualified(next, nature, amount));
        await ActivatePhysicalCommercialAsync(f, issued.LicenseKey, hardware);
        await using var db = f.Db();
        Assert.True((await db.Licenses.SingleAsync(x => x.Id == issued.LicenseId)).IsActive);
        Assert.True((await db.LicenseSeats.SingleAsync(x => x.LicenseId == issued.LicenseId)).IsActive);
        Assert.False((await db.LicenseSeats.SingleAsync(x => x.LicenseId == old.LicenseId)).IsActive);
        Assert.True((await db.Licenses.SingleAsync(x => x.Id == old.LicenseId)).IsActive);
    }

    /// <summary>Same-license reactivation and a free gift preserve the original key and first-order origin.</summary>
    [Fact]
    public async Task Tkt1424_SameLicenseGiftAndReactivationRemainValid()
    {
        await using var f = await Fixture.CreateAsync();
        var first = Qualified(f.Request());
        var issued = await f.ReadResponseAsync(first);
        var hardware = VmPolicyHardware;
        await ActivatePhysicalCommercialAsync(f, issued.LicenseKey, hardware);
        var observed = await f.ReadResponseAsync(first);
        var gift = Qualified(f.Extend(f.Request(), observed), "FREE");
        var renewed = await f.ReadResponseAsync(gift);
        Assert.Equal(issued.LicenseId, renewed.LicenseId);
        await using (var db = f.Db())
        {
            var seat = await db.LicenseSeats.SingleAsync();
            seat.IsActive = false; seat.UnlinkedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        await ActivatePhysicalCommercialAsync(f, issued.LicenseKey, hardware);
        await using var after = f.Db();
        Assert.Equal("FIRST_ORDER_FREE", (await after.Licenses.SingleAsync()).CommercialNature);
        Assert.True((await after.LicenseSeats.SingleAsync()).IsActive);
    }

    /// <summary>A transferred subject with no dated machine observation during an unlink gap must not poison later reuse.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt1424_TransferDuringUnlinkGapRequiresActualMachineEvidence(bool intermediateActivation)
    {
        await using var f = await Fixture.CreateAsync();
        var first = f.Request();
        var old = await f.ReadResponseAsync(first);
        var hardware = VmPolicyHardware;
        await ActivatePhysicalCommercialAsync(f, old.LicenseKey, hardware);
        await using (var db = f.Db())
        {
            var seat = await db.LicenseSeats.SingleAsync();
            seat.IsActive = false; seat.UnlinkedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        await TransferAsync(f, old.LicenseId);
        if (intermediateActivation) await ActivatePhysicalCommercialAsync(f, old.LicenseKey, hardware);
        await TransferAsync(f, old.LicenseId, first.CommercialSubjectId);
        await ActivatePhysicalCommercialAsync(f, old.LicenseKey, hardware);
        // Provision a second key for A directly; payments intentionally reuses A's first key.
        var evidence = new CommercialEvidence(2, Guid.NewGuid(), "second-A", first.CommercialSubjectId, "FIRST_ORDER_FREE", 0, "eur");
        using var creation = await f.Client.PostAsJsonAsync("/api/admin/licenses", new AdminController.CreateLicenseRequest {
            ProductName = f.ProductName, TypeSlug = "TIA-CONNECT-PRO", CustomerName = "Synthetic buyer",
            CustomerEmail = "buyer@example.test", Reference = "second-A", CommercialSubjectId = first.CommercialSubjectId,
            CommercialEvidence = evidence });
        Assert.True(creation.IsSuccessStatusCode, await creation.Content.ReadAsStringAsync());
        await using var state = f.Db();
        var second = await state.Licenses.SingleAsync(x => x.Id != old.LicenseId);
        using var activation = await f.Client.PostAsJsonAsync("/api/activation", new { AppName = f.ProductName,
            second.LicenseKey, HardwareId = hardware, SystemUuid = VmPolicyUuid, MachineEvidence = VmPolicyEvidence("Dell Inc.", "Precision 7680"), AppVersion = "2.4.600", CustomerEmail = "buyer@example.test" });
        if (intermediateActivation)
        {
            Assert.Contains("FIRST_ORDER_FREE_HARDWARE_CONFLICT", await activation.Content.ReadAsStringAsync());
            Assert.False((await state.Licenses.AsNoTracking().SingleAsync(x => x.Id == second.Id)).IsActive);
        }
        else Assert.True((await state.LicenseSeats.AsNoTracking().SingleAsync(x => x.LicenseId == second.Id)).IsActive);
    }

    /// <summary>Two transport attempts after a failed CAS acquire only one immutable order and one paid period.</summary>
    [Fact]
    public async Task Tkt1424_CasRetryAndPaymentAliasNeverDoubleRights()
    {
        await using var f = await Fixture.CreateAsync();
        var original = Qualified(f.Request());
        var issued = await f.ReadResponseAsync(original);
        var next = Qualified(f.Extend(f.Request(), issued), "PAID", 700);
        using var stale = await f.PostAsync(next with { ExpectedAuthorityVersion = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        var operationId = Guid.NewGuid();
        next = next with { OperationId = operationId, CommercialEvidence = next.CommercialEvidence! with { OperationId = operationId } };
        var acquired = await f.ReadResponseAsync(next);
        var aliasId = Guid.NewGuid();
        var alias = next with { OperationId = aliasId, CommercialEvidence = next.CommercialEvidence! with { OperationId = aliasId } };
        var replay = await f.ReadResponseAsync(alias);
        Assert.True(replay.Idempotent);
        Assert.Equal(acquired.HistoricalPaidThroughUtc, replay.HistoricalPaidThroughUtc);
        await using var db = f.Db();
        Assert.Equal(2, await db.PersonalDayPassPayments.CountAsync());
        Assert.Equal(2, await db.Set<CommercialOrderEvidence>().CountAsync());
        Assert.Equal(3, await db.Set<CommercialEvidenceOperation>().CountAsync());
        Assert.Equal("PAID", (await db.Licenses.SingleAsync()).CommercialNature);
        using var conflict = await f.PostAsync(alias with { CommercialEvidence = alias.CommercialEvidence! with { PaidAmountMinor = 701 } });
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Contains("commercial_evidence_conflict", await conflict.Content.ReadAsStringAsync());
    }

    /// <summary>Transferred licenses replay their exact historical purchase without qualifying a new grant to the old subject.</summary>
    [Fact]
    public async Task Tkt1424_V2PaymentReplayAfterTransferPreservesAuthority()
    {
        await using var f = await Fixture.CreateAsync();
        var request = Qualified(f.Request());
        var issued = await f.ReadResponseAsync(request);
        await TransferAsync(f, issued.LicenseId);
        await using var db = f.Db();
        var before = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync());
        var replay = await f.ReadResponseAsync(request);
        Assert.True(replay.Idempotent);
        Assert.False(replay.CurrentUsable);
        using var conflict = await f.PostAsync(Qualified(f.Extend(f.Request(), replay)));
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal(before, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync()));
    }

    /// <summary>Malformed explicit facts fail before creating a license, order, receipt or commercial subject.</summary>
    [Theory]
    [InlineData("nature", "\"paid\"")]
    [InlineData("nature", "\"UNKNOWN\"")]
    [InlineData("paidAmountMinor", "0.0")]
    [InlineData("paidAmountMinor", "\"0\"")]
    [InlineData("paidAmountMinor", "-1")]
    [InlineData("version", "3")]
    [InlineData("currency", "\"EUR\"")]
    [InlineData("orderId", "\" padded\"")]
    [InlineData("unexpected", "true")]
    public async Task Tkt1424_InvalidEvidenceIsRejectedBeforeMutation(string field, string json)
    {
        await using var f = await Fixture.CreateAsync();
        var node = JsonSerializer.SerializeToNode(Qualified(f.Request()), new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        node["commercialEvidence"]![field] = JsonNode.Parse(json);
        using var response = await f.Client.PostAsJsonAsync("/api/admin/personal-day-passes/payments", node);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("commercial_evidence_invalid", await response.Content.ReadAsStringAsync());
        await using var db = f.Db();
        Assert.Empty(await db.Licenses.ToListAsync());
        Assert.Empty(await db.Set<CommercialOrderEvidence>().ToListAsync());
    }

    /// <summary>TKT-002098: PAID_TRIAL proof is accepted at 9700 and 10000 only, by the endpoint and by the migrated constraint.</summary>
    [Theory]
    [InlineData(9700, true)]
    [InlineData(10000, true)]
    [InlineData(9600, false)]
    [InlineData(9701, false)]
    [InlineData(0, false)]
    public async Task Tkt2098_PaidTrialAcceptsOnlyIntroductoryAndHistoricalAmounts(int amount, bool accepted)
    {
        await using var f = await Fixture.CreateAsync();
        using (var response = await f.PostAsync(Qualified(f.Request(), "PAID_TRIAL", amount)))
        {
            var body = await response.Content.ReadAsStringAsync();
            if (accepted) Assert.True(response.IsSuccessStatusCode, body);
            else
            {
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                Assert.Contains("commercial_evidence_invalid", body);
            }
        }
        await using var db = f.Db();
        if (accepted)
        {
            var proof = await db.Set<CommercialOrderEvidence>().AsNoTracking().SingleAsync();
            Assert.Equal(("PAID_TRIAL", amount), (proof.Nature, proof.PaidAmountMinor));
        }
        else
        {
            Assert.Empty(await db.Licenses.ToListAsync());
            Assert.Empty(await db.Set<CommercialOrderEvidence>().ToListAsync());
            // A valid historical proof gives the SQL probe below a coherent row to copy.
            await f.ReadResponseAsync(Qualified(f.Request(), "PAID_TRIAL", 10000));
        }
        // The migrated constraint enforces the same rule for any writer that bypasses endpoint validation.
        var orderId = "tkt002098-sql-" + amount;
        var insert = () => db.Database.ExecuteSqlRawAsync("""
            INSERT INTO public."CommercialOrderEvidence" ("Id", "ProductId", "OrderId", "LicenseId", "CommercialSubjectId",
                "Version", "Nature", "PaidAmountMinor", "Currency", "Producer", "ReceiptKey", "AttributionDigest")
            SELECT {0}, "ProductId", {1}, "LicenseId", "CommercialSubjectId",
                "Version", 'PAID_TRIAL', {2}, "Currency", "Producer", {1}, "AttributionDigest"
            FROM public."CommercialOrderEvidence" ORDER BY "OrderId" LIMIT 1;
            """, Guid.NewGuid(), orderId, amount);
        if (accepted) Assert.Equal(1, await insert());
        else
        {
            var refused = await Assert.ThrowsAsync<PostgresException>(insert);
            Assert.Equal(PostgresErrorCodes.CheckViolation, refused.SqlState);
            Assert.Equal("CK_CommercialOrderEvidence_Values", refused.ConstraintName);
            Assert.False(await db.Set<CommercialOrderEvidence>().AnyAsync(x => x.OrderId == orderId));
        }
    }

    /// <summary>Receipt insertion failure rolls back revocation and leaves the original machine authority byte-for-byte intact.</summary>
    [Fact]
    public async Task Tkt1424_RefusalPersistenceFailureRollsBackRevocation()
    {
        await using var f = await Fixture.CreateAsync();
        var old = await f.ReadResponseAsync(f.Request());
        var hardware = VmPolicyHardware;
        await ActivatePhysicalCommercialAsync(f, old.LicenseKey, hardware);
        var issued = await f.ReadResponseAsync(Qualified(f.Request() with { CommercialSubjectId = Guid.NewGuid() }));
        await using var db = f.Db();
        var licenses = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().OrderBy(x => x.Id).ToListAsync());
        var seats = JsonSerializer.Serialize(await db.LicenseSeats.AsNoTracking().ToListAsync());
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION tkt1424_fail_refusal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
              IF NEW."Action" = 'FIRST_ORDER_FREE_REVOKED' THEN RAISE EXCEPTION 'synthetic receipt failure'; END IF;
              RETURN NEW; END $$;
            CREATE TRIGGER tkt1424_fail_refusal BEFORE INSERT ON "LicenseHistories"
              FOR EACH ROW EXECUTE FUNCTION tkt1424_fail_refusal();
            """);
        using var response = await f.Client.PostAsJsonAsync("/api/activation", new {
            AppName = f.ProductName, issued.LicenseKey, HardwareId = hardware, SystemUuid = VmPolicyUuid, MachineEvidence = VmPolicyEvidence("Dell Inc.", "Precision 7680"), AppVersion = "2.4.600",
            CustomerEmail = "buyer@example.test" });
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(licenses, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().OrderBy(x => x.Id).ToListAsync()));
        Assert.Equal(seats, JsonSerializer.Serialize(await db.LicenseSeats.AsNoTracking().ToListAsync()));
        Assert.False(await db.LicenseHistories.AnyAsync(x => x.Action == "FIRST_ORDER_FREE_REVOKED"));
        Assert.False(await db.LicenseHistories.AnyAsync(x => x.LicenseId == issued.LicenseId && x.Action == "ACTIVATION_DECISION_V1"));
    }

    /// <summary>Builds a fully specified billing PAID request from current authority, preserving the existing conditional contract.</summary>
    private static async Task<AdminController.ConditionalLicenseBillingRequest> BillingAsync(Fixture f, Guid licenseId)
    {
        await using var db = f.Db();
        var license = await db.Licenses.SingleAsync(x => x.Id == licenseId);
        var owner = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(x => x.LicenseId == licenseId && x.State == "ACTIVE");
        var t = await db.LicenseTypes.Include(x => x.CustomParams).SingleAsync(x => x.Id == license.LicenseTypeId);
        var type = new AdminController.BillingTypeSnapshot(t.Id, t.Slug, t.DefaultDurationDays, t.IsRecurring,
            t.DefaultAllowedVersions, t.DefaultMaxSeats, t.MaxActivationsPerDay, t.AllowAnonymous, t.IsFree,
            t.EnforceSingleUsePerHardwareId, t.DisableNewActivations,
            t.CustomParams.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new AdminController.BillingParameter(x.Key, x.Value)).ToArray());
        var now = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 1000).UtcDateTime;
        var id = Guid.NewGuid();
        return new(id, "PAID", license.Id, license.ProductId, owner.OwnerSubjectId, owner.Id, license.AuthorityVersion,
            license.IsActive, license.RevocationReason, license.RevokedAt, license.ExpirationDate,
            license.MaxSeats, type, type, license.MaxSeats, "cycle-1424", "customer-1424", "subscription-1424", "invoice-1424",
            now.AddDays(-1), now.AddDays(30), null, now, null, null)
        { CommercialEvidence = new CommercialEvidence(2, id, "billing-order-1424", owner.OwnerSubjectId, "PAID", 14900, "eur") };
    }

    /// <summary>V2 historical billing observations never masquerade old ownership or old revocation as current authority.</summary>
    [Theory]
    [InlineData("transfer")]
    [InlineData("revoke")]
    [InlineData("no-owner")]
    public async Task Tkt1424_BillingHistoricalReceiptReportsActualAuthority(string change)
    {
        await using var f = await Fixture.CreateAsync();
        var initial = Qualified(f.Request(), "PAID_TRIAL", 10000);
        var issued = await f.ReadResponseAsync(initial);
        await ActivatePhysicalCommercialAsync(f, issued.LicenseKey, VmPolicyHardware);
        var request = await BillingAsync(f, issued.LicenseId);
        var url = $"/api/admin/licenses/{issued.LicenseKey}/billing-conditional";
        using (var applied = await f.Client.PostAsJsonAsync(url, request))
            Assert.True(applied.IsSuccessStatusCode, await applied.Content.ReadAsStringAsync());
        using (var replay = await f.Client.PostAsJsonAsync(url, request))
            Assert.True(replay.IsSuccessStatusCode, await replay.Content.ReadAsStringAsync());
        Guid? newSubject = null;
        if (change == "transfer") newSubject = await TransferAsync(f, issued.LicenseId);
        await using var db = f.Db();
        if (change == "revoke")
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\"=false, \"RevokedAt\"=now(), \"RevocationReason\"='security-later' WHERE \"Id\"={issued.LicenseId}");
        if (change == "no-owner")
        {
            var owner = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(x => x.LicenseId == issued.LicenseId && x.State == "ACTIVE");
            owner.State = "REVOKED"; owner.EndedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        var before = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync());
        using var observation = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{issued.LicenseKey}/billing-receipt", request);
        Assert.True(observation.IsSuccessStatusCode, await observation.Content.ReadAsStringAsync());
        var body = JsonNode.Parse(await observation.Content.ReadAsStringAsync())!;
        Assert.True(body["appliedHistorically"]!.GetValue<bool>());
        Assert.False(body["protectedResultMatchesCurrent"]!.GetValue<bool>());
        if (change == "transfer") Assert.Equal(newSubject, body["currentAuthority"]!["commercialSubjectId"]!.GetValue<Guid>());
        if (change == "no-owner") Assert.Null(body["currentAuthority"]);
        if (change == "revoke") Assert.Equal("security-later", body["currentAuthority"]!["revocationReason"]!.GetValue<string>());
        Assert.Equal(before, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync()));
        Assert.Equal("PAID", (await db.Licenses.AsNoTracking().SingleAsync()).CommercialNature);
        using var altered = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{issued.LicenseKey}/billing-receipt",
            request with { CommercialEvidence = request.CommercialEvidence! with { PaidAmountMinor = 14901 } });
        Assert.Equal(HttpStatusCode.Conflict, altered.StatusCode);
    }

    /// <summary>Creation and renewal persist explicit nature while exact historical replays survive transfer and V1/V2 cannot cross.</summary>
    [Fact]
    public async Task Tkt1424_CreateRenewAndCrossRouteIdentities()
    {
        await using var f = await Fixture.CreateAsync();
        var seed = f.Request();
        var evidence = new CommercialEvidence(2, Guid.NewGuid(), "trial-order", seed.CommercialSubjectId, "PAID_TRIAL", 10000, "eur");
        var create = new AdminController.CreateLicenseRequest { ProductName = f.ProductName, CustomerName = "Synthetic buyer",
            CustomerEmail = "buyer@example.test", TypeSlug = "TIA-CONNECT-PRO", CommercialSubjectId = seed.CommercialSubjectId,
            Reference = "trial-reference", CommercialEvidence = evidence };
        using (var response = await f.Client.PostAsJsonAsync("/api/admin/licenses", create))
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        await using var db = f.Db();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal("PAID_TRIAL", license.CommercialNature);
        var renew = new AdminController.RenewLicenseRequest { TransactionId = "renewal1424", DaysToAdd = 30,
            CommercialEvidence = new CommercialEvidence(2, Guid.NewGuid(), "renew-order", seed.CommercialSubjectId, "PAID", 14900, "eur") };
        var url = $"/api/admin/licenses/{license.LicenseKey}/renew";
        using (var response = await f.Client.PostAsJsonAsync(url, renew))
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        Assert.Equal("PAID", (await db.Licenses.AsNoTracking().SingleAsync()).CommercialNature);
        await TransferAsync(f, license.Id);
        var before = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync());
        using (var response = await f.Client.PostAsJsonAsync("/api/admin/licenses", create)) Assert.True(response.IsSuccessStatusCode);
        using (var response = await f.Client.PostAsJsonAsync(url, renew)) Assert.True(response.IsSuccessStatusCode);
        renew.CommercialEvidence = null;
        using (var crossed = await f.Client.PostAsJsonAsync(url, renew)) Assert.Equal(HttpStatusCode.Conflict, crossed.StatusCode);
        var reuse = Qualified(seed) with { OperationId = evidence.OperationId, CommercialEvidence = evidence };
        using (var crossed = await f.PostAsync(reuse)) Assert.Equal(HttpStatusCode.Conflict, crossed.StatusCode);
        Assert.Equal(before, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync()));
    }

    /// <summary>Historical UNKNOWN stays paid-equivalent after a new free gift; no heuristic backfill occurs.</summary>
    [Fact]
    public async Task Tkt1424_HistoricalUnknownCannotBeDowngradedByGift()
    {
        await using var f = await Fixture.CreateAsync();
        var old = await f.ReadResponseAsync(f.Request());
        await f.ReadResponseAsync(Qualified(f.Extend(f.Request(), old)));
        await using var db = f.Db();
        Assert.Equal("UNKNOWN", (await db.Licenses.SingleAsync()).CommercialNature);
        Assert.Equal("FIRST_ORDER_FREE", (await db.Set<CommercialOrderEvidence>().SingleAsync()).Nature);
    }

    /// <summary>Physical PostgreSQL constraints protect order uniqueness and append-only proof from bypassing SQL writers.</summary>
    [Fact]
    public async Task Tkt1424_DatabaseRejectsMutatedOrDuplicateProof()
    {
        await using var f = await Fixture.CreateAsync();
        await f.ReadResponseAsync(Qualified(f.Request()));
        await using var db = f.Db();
        var mutation = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE \"CommercialOrderEvidence\" SET \"Nature\"='FREE'"));
        Assert.Equal("23514", mutation.SqlState);
        var duplicate = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("""
            INSERT INTO "CommercialOrderEvidence" SELECT gen_random_uuid(), "ProductId", "OrderId", "LicenseId",
                "CommercialSubjectId", "Version", "Nature", "PaidAmountMinor", "Currency", "Producer", "ReceiptKey", "AttributionDigest"
                FROM "CommercialOrderEvidence"
            """));
        Assert.Equal("23505", duplicate.SqlState);
        Assert.Equal(1, await db.Set<CommercialOrderEvidence>().CountAsync());
    }

    /// <summary>V1 hashes use their original typed field order, including omitted/null renewals, through real HTTP and PostgreSQL.</summary>
    [Fact]
    public async Task Tkt1424_V1FingerprintBytesAndCrossVersionConflicts()
    {
        await using var f = await Fixture.CreateAsync();
        var r = f.Request();
        var issued = await f.ReadResponseAsync(r);
        await using var db = f.Db();
        var expectedPayment = Fingerprint(new { r.OperationId, r.ProductId, r.CommercialSubjectId,
            r.LicenseTypeId, r.Provider, r.ProviderAccount, r.Environment, r.PaymentId, r.PaidAtUtc,
            r.AmountMinor, r.Currency, r.MaxSeats, r.AllowedVersions, r.CustomerEmail, r.CustomerName,
            r.PrioritySupport, r.ExpectedLicenseId, r.ExpectedOwnershipId, r.ExpectedAuthorityVersion, r.Offer, r.DurationSeconds });
        Assert.Equal(expectedPayment, (await db.PersonalDayPassOperations.SingleAsync()).RequestDigest);
        using (var crossed = await f.PostAsync(Qualified(r))) Assert.Equal(HttpStatusCode.Conflict, crossed.StatusCode);
        // This compatibility fixture renews an activated pass; deferred renewal projection is a separate existing contract.
        await ActivatePhysicalCommercialAsync(f, issued.LicenseKey, VmPolicyHardware);
        foreach (var explicitNull in new[] { false, true })
        {
            var transaction = explicitNull ? "v1-null" : "v1-omitted";
            var payload = new JsonObject { ["transactionId"] = transaction };
            if (explicitNull) { payload["reference"] = null; payload["daysToAdd"] = null; payload["targetExpirationUtc"] = null; }
            var url = $"/api/admin/licenses/{issued.LicenseKey}/renew";
            using var response = await f.Client.PostAsJsonAsync(url, payload);
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
            var expected = Fingerprint(new { ContractVersion = 1, LicenseId = issued.LicenseId, TransactionId = transaction,
                ReferenceSpecified = explicitNull, Reference = (string?)null, DaysToAddSpecified = explicitNull,
                DaysToAdd = (int?)null, TargetExpirationUtcSpecified = explicitNull, TargetExpirationUtc = (DateTime?)null });
            Assert.Equal(expected, (await db.LicenseRenewals.SingleAsync(x => x.TransactionId == transaction)).RequestFingerprint);
            using var retry = await f.Client.PostAsJsonAsync(url, payload);
            Assert.True(retry.IsSuccessStatusCode);
        }
        var subject = Guid.NewGuid();
        var create = new AdminController.CreateLicenseRequest { ProductName = f.ProductName, TypeSlug = "TIA-CONNECT-PRO",
            CustomerName = "Synthetic buyer", CustomerEmail = "buyer@example.test", Reference = "v1-create",
            CommercialSubjectId = subject };
        using var creation = await f.Client.PostAsJsonAsync("/api/admin/licenses", create);
        Assert.True(creation.IsSuccessStatusCode, await creation.Content.ReadAsStringAsync());
        var type = await db.LicenseTypes.SingleAsync();
        var expectedCreation = Fingerprint(new { ProductId = r.ProductId, CommercialSubjectId = subject, LicenseTypeId = type.Id,
            create.CustomerName, create.CustomerEmail, LicenseReference = "v1-create", ValidityDays = (int?)type.DefaultDurationDays,
            MaxSeats = type.DefaultMaxSeats, PartnerCode = (string?)null, Quantity = 1 });
        Assert.Equal(expectedCreation, (await db.LicenseProvisioningRequests.SingleAsync(x => x.Reference == "v1-create")).RequestHash);
        create.CommercialEvidence = new CommercialEvidence(2, Guid.NewGuid(), "crossed-v1-create", subject, "PAID", 1000, "eur");
        using var rejected = await f.Client.PostAsJsonAsync("/api/admin/licenses", create);
        Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        var billing = (await BillingAsync(f, issued.LicenseId)) with { CommercialEvidence = null };
        billing = billing with { PeriodEndUtc = billing.PeriodEndUtc.AddDays(90) };
        var historicalShape = JsonSerializer.SerializeToNode(billing)!.AsObject();
        historicalShape.Remove("CommercialEvidence");
        var expectedBilling = Fingerprint(new { Version = 1, Command = "BILLING_CONDITIONAL_V1", LicenseKey = issued.LicenseKey, Request = historicalShape });
        using var billed = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{issued.LicenseKey}/billing-conditional", billing);
        Assert.True(billed.IsSuccessStatusCode, await billed.Content.ReadAsStringAsync());
        var history = await db.LicenseHistories.AsNoTracking().SingleAsync(x => x.Id == billing.OperationId);
        Assert.Equal(expectedBilling, JsonNode.Parse(history.Details!)!["Digest"]!.GetValue<string>());
    }

    /// <summary>V2 rejects clamped batches and binds immutable proof to the resolved plugin, not the parent authentication product.</summary>
    [Fact]
    public async Task Tkt1424_QuantityBeforeClampAndEffectivePluginProduct()
    {
        await using var f = await Fixture.CreateAsync();
        var seed = f.Request();
        await using var db = f.Db();
        var plugin = new Product { Name = "child-1424", ParentProductId = seed.ProductId };
        var type = new LicenseType { Product = plugin, Name = "Child", Slug = "CHILD", DefaultDurationDays = 10 };
        db.AddRange(plugin, type); await db.SaveChangesAsync();
        var request = new AdminController.CreateLicenseRequest { ProductName = f.ProductName, PluginId = plugin.Id,
            TypeSlug = type.Slug, CustomerName = "Synthetic", Reference = "child-ref", CommercialSubjectId = seed.CommercialSubjectId,
            CommercialEvidence = new CommercialEvidence(2, Guid.NewGuid(), "child-order", seed.CommercialSubjectId, "PAID", 1000, "eur") };
        foreach (var quantity in new[] { 0, 2, 101 })
        {
            request.Quantity = quantity;
            using var rejected = await f.Client.PostAsJsonAsync("/api/admin/licenses", request);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        }
        Assert.Empty(await db.Licenses.ToListAsync());
        request.Quantity = 1;
        using var created = await f.Client.PostAsJsonAsync("/api/admin/licenses", request);
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        Assert.Equal(plugin.Id, (await db.Set<CommercialOrderEvidence>().SingleAsync()).ProductId);
    }

    /// <summary>Simultaneous deliveries serialize on PostgreSQL and yield one acquired license/order/payment.</summary>
    [Fact]
    public async Task Tkt1424_ConcurrentDeliveryAcquiresOnlyOneOrder()
    {
        await using var f = await Fixture.CreateAsync();
        var request = Qualified(f.Request());
        var results = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => f.ReadResponseAsync(request)));
        Assert.Single(results, x => !x.Idempotent);
        Assert.Single(results.Select(x => x.LicenseId).Distinct());
        await using var db = f.Db();
        Assert.Equal(1, await db.Set<CommercialOrderEvidence>().CountAsync());
        Assert.Equal(1, await db.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>Maximum valid provider identities fit the common receipt binding without truncation or a new length restriction.</summary>
    [Fact]
    public async Task Tkt1424_LongProviderTupleKeepsExactReplay()
    {
        await using var f = await Fixture.CreateAsync();
        var request = Qualified(f.Request() with { Provider = new string('p', 200), ProviderAccount = new string('a', 200),
            Environment = new string('e', 200), PaymentId = new string('i', 200) });
        var acquired = await f.ReadResponseAsync(request);
        var replay = await f.ReadResponseAsync(request);
        Assert.True(replay.Idempotent);
        Assert.Equal(acquired.LicenseId, replay.LicenseId);
    }

    /// <summary>Computes the expected legacy digest from an explicitly frozen legacy field list, never the changed DTO.</summary>
    private static string Fingerprint<T>(T value) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));
}

/// <summary>Reuses an actual signed, confirmed Runtime fixture to prove the classic refusal preserves prior authority.</summary>
public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>Captures persisted authority with fresh queries, without navigation cycles or volatile application observations.</summary>
    protected static async Task<string> RuntimeGraphAsync(LicenseDbContext db, Guid licenseId) => JsonSerializer.Serialize(new {
        License = await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == licenseId),
        Seats = await db.LicenseSeats.AsNoTracking().Where(x => x.LicenseId == licenseId).OrderBy(x => x.Id).ToListAsync(),
        Bindings = await db.DistributionInstallationBindings.AsNoTracking().Where(x => x.LicenseId == licenseId).OrderBy(x => x.Id).ToListAsync(),
        Enrollments = await db.RuntimeEnrollments.AsNoTracking().Where(x => x.LicenseId == licenseId).OrderBy(x => x.Id).ToListAsync(),
        Assignments = await db.EnrollmentLicenseAssignments.AsNoTracking().Where(x => x.LicenseId == licenseId).OrderBy(x => x.Id).ToListAsync()
    });
}

/// <summary>Runs the tests from CommercialNaturePostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class CommercialNaturePostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>No old binding, enrollment, seat or assignment changes when a foreign first-order gift is refused.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1424_ClassicRefusalPreservesOldRuntimeGraph")]
    public async Task Tkt1424_ClassicRefusalPreservesOldRuntimeGraph()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: PersonalDayPassPostgreSqlTests.VmPolicyHardware);
        await ActivateCanonicalScenarioAsync(scenario, PersonalDayPassPostgreSqlTests.VmPolicyHardware);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(x => x.Id == scenario.EnrollmentId);
        var old = await db.Licenses.SingleAsync(x => x.Id == enrollment.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(x => x.Id == enrollment.LicenseSeatId);
        if (!await db.RuntimeRecoveryCommercialOwnerships.AnyAsync(x => x.LicenseId == old.Id))
        {
            var subject = new RuntimeRecoveryCommercialSubject
            {
                ProductId = old.ProductId,
                Id = Guid.NewGuid(),
                CreatedAtUtc = seat.FirstActivatedAt.AddDays(-1)
            };
            db.Add(subject);
            db.Add(new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = old.ProductId, LicenseId = old.Id, OwnerSubjectId = subject.Id, CreatedAtUtc = seat.FirstActivatedAt.AddHours(-1) });
        }

        var newcomer = new RuntimeRecoveryCommercialSubject
        {
            ProductId = old.ProductId,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        var gift = new License
        {
            ProductId = old.ProductId,
            LicenseTypeId = old.LicenseTypeId,
            LicenseKey = Guid.NewGuid().ToString("D"),
            CommercialNature = "FIRST_ORDER_FREE",
            CustomerEmail = "buyer@example.test",
            CustomerName = "Synthetic buyer",
            MaxSeats = 1
        };
        db.AddRange(newcomer, gift, new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = old.ProductId, LicenseId = gift.Id, OwnerSubjectId = newcomer.Id, CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
        var before = await RuntimeGraphAsync(db, old.Id);
        var product = await db.Products.SingleAsync(x => x.Id == old.ProductId);
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHostedService>();
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(scenario.AppConnectionString));
            });
        });
        using var client = host.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/activation", new { AppName = product.Name, gift.LicenseKey, HardwareId = PersonalDayPassPostgreSqlTests.VmPolicyHardware, SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid, MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680"), AppVersion = "2.4.600", CustomerEmail = gift.CustomerEmail });
        Assert.Contains("FIRST_ORDER_FREE_HARDWARE_CONFLICT", await response.Content.ReadAsStringAsync());
        Assert.Equal(before, await RuntimeGraphAsync(db, old.Id));
        Assert.False((await db.Licenses.AsNoTracking().SingleAsync(x => x.Id == gift.Id)).IsActive);
    }
}
