using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;
using SoftLicence.Server.Data;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>TKT-001177: end-to-end security lock reports on PostgreSQL with a real enrollment proof.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Frozen signed bytes are reusable only when they remain at least as restrictive.</summary>
    [Theory]
    [InlineData(SecurityLockVerdicts.Release, SecurityLockVerdicts.Maintain, false)]
    [InlineData(SecurityLockVerdicts.Release, SecurityLockVerdicts.Ban, false)]
    [InlineData(SecurityLockVerdicts.Maintain, SecurityLockVerdicts.Ban, false)]
    [InlineData(SecurityLockVerdicts.Maintain, SecurityLockVerdicts.Release, true)]
    [InlineData(SecurityLockVerdicts.Ban, SecurityLockVerdicts.Release, true)]
    [InlineData(SecurityLockVerdicts.Ban, SecurityLockVerdicts.Maintain, true)]
    public void SecurityLockReport_ReplaySeverityOrder(
        string stored, string current, bool expected) =>
        Assert.Equal(expected, SecurityLockVerdictPolicy.ReplayRemainsSafe(stored, current));

    [Fact]
    public async Task SecurityLockReport_SignedVerdictsReplayPolicyAndBanOnPostgreSql()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        string hardwareId;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var binding = await seed.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            var seat = await seed.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
            hardwareId = seat.HardwareId.ToUpperInvariant();
            seat.HardwareId = hardwareId;
            binding.HardwareIdHash = Sha256(hardwareId);
            await seed.SaveChangesAsync();
        }

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        using var ackKey = RSA.Create(2048);
        var options = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory,
            new RuntimeEnrollmentAuthorityService(factory, Options.Create(options)),
            new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options)),
            crypto,
            Options.Create(options),
            new CanaryAckService(factory, configuration, TimeProvider.System));
        // Telemetry of the last 24 hours, stored in another case and an older row outside the window.
        await using (var telemetryDb = await factory.CreateDbContextAsync())
        {
            foreach (var (eventName, age) in new[] { ("Startup_AppStarted", 1), ("Startup_AppStarted", 2), ("Old_Event", 30) })
                telemetryDb.TelemetryRecords.Add(new TelemetryRecord
                {
                    HardwareId = hardwareId.ToLowerInvariant(),
                    ProductId = fixture.ProductId,
                    AppName = "TIAConnect",
                    EventName = eventName,
                    Timestamp = DateTime.UtcNow.AddHours(-age)
                });
            await telemetryDb.SaveChangesAsync();
        }

        var prepared = await service.PrepareAsync("website-step1", Sha256("lock-report-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirmDigest = Sha256("lock-report-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        }, Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
            prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        // Level 1: an authenticated report proves the server is reachable → signed RELEASE.
        var offline = LockRequest(hardwareId, fixture.Version, "HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", 'a');
        var offlineDigest = Sha256("lock-offline");
        var offlineJti = Guid.NewGuid();
        var released = await service.ProcessSecurityLockReportAsync(enrollmentId, offlineDigest, offline,
            LockProof(enrollmentKey, enrollmentId, offline.ReportId!, offlineDigest, options, offlineJti), IPAddress.Loopback);
        Assert.False(released.Idempotent);
        Assert.Equal(SecurityLockVerdicts.Release, released.Response.Verdict);
        Assert.Equal(offline.ReportId, released.Response.ReportId);
        AssertVerdictSignature(released.Response, ackKey);

        // Exact replay returns the stored verdict; the same JTI with another body is a conflict.
        var replay = await service.ProcessSecurityLockReportAsync(enrollmentId, offlineDigest, offline,
            LockProof(enrollmentKey, enrollmentId, offline.ReportId!, offlineDigest, options, offlineJti), IPAddress.Loopback);
        Assert.True(replay.Idempotent);
        Assert.Equal(released.Response, replay.Response);
        var tamperedDigest = Sha256("lock-offline-tampered");
        var conflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessSecurityLockReportAsync(
            enrollmentId, tamperedDigest, offline,
            LockProof(enrollmentKey, enrollmentId, offline.ReportId!, tamperedDigest, options, offlineJti), IPAddress.Loopback));
        Assert.Equal("proof_replay", conflict.ErrorCode);

        // A canary proof can never authenticate a lock report (distinct prefix and path).
        var crossDigest = Sha256("lock-cross");
        var cross = LockRequest(hardwareId, fixture.Version, "LEGACY_MARKER", 3, "NOT_APPLICABLE", 'c');
        var crossError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessSecurityLockReportAsync(
            enrollmentId, crossDigest, cross,
            CanaryProof(enrollmentKey, enrollmentId, cross.ReportId!, crossDigest, options), IPAddress.Loopback));
        Assert.Equal("authentication_failed", crossError.ErrorCode);

        // Non-canonical identifiers are rejected before any persistence.
        var upper = LockRequest(hardwareId, fixture.Version, "LEGACY_MARKER", 3, "NOT_APPLICABLE", 'd');
        upper.LockId = upper.LockId!.ToUpperInvariant();
        var upperDigest = Sha256("lock-upper");
        var upperError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessSecurityLockReportAsync(
            enrollmentId, upperDigest, upper, LockProof(enrollmentKey, enrollmentId, upper.ReportId!, upperDigest, options),
            IPAddress.Loopback));
        Assert.Equal("lock_id_invalid", upperError.ErrorCode);

        // Level 4 without policy: REVIEW → MAINTAIN, OPEN, no ban.
        var tamper = LockRequest(hardwareId, fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", 'e');
        var tamperDigest = Sha256("lock-tamper");
        var maintained = await service.ProcessSecurityLockReportAsync(enrollmentId, tamperDigest, tamper,
            LockProof(enrollmentKey, enrollmentId, tamper.ReportId!, tamperDigest, options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, maintained.Response.Verdict);

        // Admin release: the next report of the same lock receives a signed RELEASE and the row is RELEASED.
        await using (var adminDb = await factory.CreateDbContextAsync())
        {
            var open = await adminDb.SecurityLockReports.SingleAsync(row => row.LockId == tamper.LockId);
            Assert.Equal("OPEN", open.State);
            open.AdminDecision = SecurityLockAdminDecisions.Release;
            open.AdminDecisionAtUtc = DateTime.UtcNow;
            open.AdminDecisionBy = "franck";
            await adminDb.SaveChangesAsync();
        }
        var again = LockRequest(hardwareId, fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", 'e');
        // The same LockId retains its first local detection across later reports.
        again.FirstSeenUtc = tamper.FirstSeenUtc;
        var againDigest = Sha256("lock-tamper-again");
        var adminReleased = await service.ProcessSecurityLockReportAsync(enrollmentId, againDigest, again,
            LockProof(enrollmentKey, enrollmentId, again.ReportId!, againDigest, options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, adminReleased.Response.Verdict);
        AssertVerdictSignature(adminReleased.Response, ackKey);

        // Same lock id with another cause is a conflict (a lock identity never changes meaning).
        var hijack = LockRequest(hardwareId, fixture.Version, "LEGACY_MARKER", 3, "NOT_APPLICABLE", 'e');
        var hijackDigest = Sha256("lock-hijack");
        var hijackError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessSecurityLockReportAsync(
            enrollmentId, hijackDigest, hijack, LockProof(enrollmentKey, enrollmentId, hijack.ReportId!, hijackDigest, options),
            IPAddress.Loopback));
        Assert.Equal("lock_id_conflict", hijackError.ErrorCode);

        // ENFORCE for level 5 → BAN and an automatic permanent hardware ban in the same transaction.
        await using (var policyDb = await factory.CreateDbContextAsync())
        {
            policyDb.SecurityLockEnforcementPolicies.Add(new SecurityLockEnforcementPolicy
            {
                ProductId = fixture.ProductId,
                Cause = "DEBUGGER_ATTACHED_KERNEL",
                Mode = "ENFORCE",
                UpdatedAtUtc = DateTime.UtcNow,
                UpdatedBy = "test"
            });
            await policyDb.SaveChangesAsync();
        }
        var attack = LockRequest(hardwareId, fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", 'f');
        var attackDigest = Sha256("lock-attack");
        var banned = await service.ProcessSecurityLockReportAsync(enrollmentId, attackDigest, attack,
            LockProof(enrollmentKey, enrollmentId, attack.ReportId!, attackDigest, options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Ban, banned.Response.Verdict);
        AssertVerdictSignature(banned.Response, ackKey);

        await using var readback = await factory.CreateDbContextAsync();
        var rows = await readback.SecurityLockReports.AsNoTracking().OrderBy(row => row.Level).ToListAsync();
        Assert.Equal(new[] { "HEARTBEAT_UNREACHABLE", "NATIVE_DLL_REPLACED", "DEBUGGER_ATTACHED_KERNEL" }, rows.Select(row => row.Cause));
        Assert.Equal(new[] { "RELEASED", "RELEASED", "BANNED" }, rows.Select(row => row.State));
        Assert.Equal(new[] { "NOT_APPLICABLE", "REVIEW", "ENFORCE" }, rows.Select(row => row.EffectiveMode));
        Assert.Equal(1, rows[0].ReportCount);
        Assert.Equal(2, rows[1].ReportCount);
        Assert.Equal("franck", rows[1].AdminDecisionBy);
        var ban = await readback.BannedHardwareIds.AsNoTracking().SingleAsync(row => row.HardwareId == hardwareId);
        Assert.Equal("debugger", ban.BanCategory);
        Assert.True(ban.IsActive);
        Assert.Equal(fixture.ProductId, ban.ProductId);
        Assert.StartsWith("security-lock:DEBUGGER_ATTACHED_KERNEL:", ban.Reason, StringComparison.Ordinal);
        // Only accepted reports persist a nonce; rejected and conflicting ones leave nothing behind.
        Assert.Equal(4, await readback.SecurityLockReportNonces.CountAsync());

        // Alert intents are committed with the new level-4 lock and the automatic ban. Level 1 and repeated reports
        // stay silent; provider delivery is covered independently by SecurityLockAlertOutboxTests.
        var deliveries = await readback.SecurityLockAlertDeliveries.AsNoTracking()
            .OrderBy(delivery => delivery.CreatedAtUtc).ToListAsync();
        Assert.Equal(new[] { NotificationService.Triggers.SecurityLockReported, NotificationService.Triggers.SecurityLockBanned },
            deliveries.Select(delivery => delivery.Trigger));
        Assert.All(deliveries, delivery =>
        {
            Assert.Equal("EMAIL", delivery.Channel);
            Assert.Equal(SecurityLockAlertDeliveryStates.Pending, delivery.State);
            Assert.Equal("127.0.0.1", delivery.ClientIp);
            Assert.Null(delivery.Title);
            Assert.Null(delivery.Message);
        });
        Assert.Equal(rows[1].Id, deliveries[0].SecurityLockReportId);
        Assert.Equal(rows[2].Id, deliveries[1].SecurityLockReportId);
    }

    /// <summary>
    /// String-normalization guard: historical hardware bans may be stored in any case, and only live bans count.
    /// A lowercase historical ban must turn a REVIEW report into BAN; an expired ban must not; no duplicate ban
    /// row is ever added for a hardware identifier that is already banned.
    /// </summary>
    [Fact]
    public async Task SecurityLockReport_HistoricalMixedCaseBanAndExpiredBanOnPostgreSql()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        string hardwareId;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var binding = await seed.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            var seat = await seed.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
            hardwareId = seat.HardwareId.ToUpperInvariant();
            seat.HardwareId = hardwareId;
            binding.HardwareIdHash = Sha256(hardwareId);
            // Expired uppercase ban: must be ignored.
            seed.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = fixture.ProductId,
                BannedAt = DateTime.UtcNow.AddDays(-10),
                ExpiresAt = DateTime.UtcNow.AddDays(-1),
                Reason = "historical-expired",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await seed.SaveChangesAsync();
        }

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        using var ackKey = RSA.Create(2048);
        var options = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory,
            new RuntimeEnrollmentAuthorityService(factory, Options.Create(options)),
            new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options)),
            crypto,
            Options.Create(options),
            new CanaryAckService(factory, configuration, TimeProvider.System));
        var prepared = await service.PrepareAsync("website-step1", Sha256("lock-ban-case-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirmDigest = Sha256("lock-ban-case-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        }, Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
            prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        // Only the expired ban exists: REVIEW keeps the lock (MAINTAIN), no new ban.
        var first = LockRequest(hardwareId, fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", '1');
        var firstDigest = Sha256("lock-ban-case-first");
        var maintained = await service.ProcessSecurityLockReportAsync(enrollmentId, firstDigest, first,
            LockProof(enrollmentKey, enrollmentId, first.ReportId!, firstDigest, options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, maintained.Response.Verdict);

        // A live historical ban stored in lower case is still the same hardware: the verdict becomes BAN.
        await using (var banDb = await factory.CreateDbContextAsync())
        {
            banDb.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId.ToLowerInvariant(),
                ProductId = fixture.ProductId,
                BannedAt = DateTime.UtcNow,
                Reason = "historical-lowercase",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await banDb.SaveChangesAsync();
        }
        var second = LockRequest(hardwareId, fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", '1');
        second.FirstSeenUtc = first.FirstSeenUtc;
        var secondDigest = Sha256("lock-ban-case-second");
        var banned = await service.ProcessSecurityLockReportAsync(enrollmentId, secondDigest, second,
            LockProof(enrollmentKey, enrollmentId, second.ReportId!, secondDigest, options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Ban, banned.Response.Verdict);
        AssertVerdictSignature(banned.Response, ackKey);

        await using (var readback = await factory.CreateDbContextAsync())
        {
            var bans = await readback.BannedHardwareIds.AsNoTracking().OrderBy(row => row.BannedAt).ToListAsync();
            Assert.Equal(new[] { "historical-expired", "historical-lowercase" }, bans.Select(row => row.Reason));
            Assert.Equal("BANNED", (await readback.SecurityLockReports.AsNoTracking().SingleAsync()).State);
        }

        // Admin path, same semantics: closed ordinal decisions, product scope, irreversible BAN, no duplicate ban
        // while the lowercase live ban exists, and a new permanent ban once only inactive/expired bans remain.
        var admin = new SecurityLockAdminService(factory);
        Guid rowId;
        await using (var lookup = await factory.CreateDbContextAsync())
            rowId = (await lookup.SecurityLockReports.AsNoTracking().SingleAsync()).Id;
        Assert.Equal(SecurityLockAdminOutcomes.DecisionInvalid,
            (await admin.DecideAsync(rowId, "release", null, "franck", null)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.DecidedByInvalid,
            (await admin.DecideAsync(rowId, SecurityLockAdminDecisions.Ban, null, "   ", null)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.Forbidden,
            (await admin.DecideAsync(rowId, SecurityLockAdminDecisions.Ban, null, "franck", Guid.NewGuid())).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.LockBannedIrreversible,
            (await admin.DecideAsync(rowId, SecurityLockAdminDecisions.Release, null, "franck", null)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.Ok,
            (await admin.DecideAsync(rowId, SecurityLockAdminDecisions.Ban, "confirmed", "franck", fixture.ProductId)).Outcome);
        await using (var readback = await factory.CreateDbContextAsync())
            Assert.Equal(2, await readback.BannedHardwareIds.CountAsync());

        await using (var deactivate = await factory.CreateDbContextAsync())
        {
            var lower = await deactivate.BannedHardwareIds.SingleAsync(row => row.Reason == "historical-lowercase");
            lower.IsActive = false;
            await deactivate.SaveChangesAsync();
        }
        Assert.Equal(SecurityLockAdminOutcomes.Ok,
            (await admin.DecideAsync(rowId, SecurityLockAdminDecisions.Ban, "confirmed", "franck", null)).Outcome);
        await using (var readback = await factory.CreateDbContextAsync())
        {
            var adminBan = await readback.BannedHardwareIds.AsNoTracking()
                .SingleAsync(row => row.Reason.StartsWith("security-lock-admin:"));
            Assert.Equal(hardwareId, adminBan.HardwareId);
            Assert.Equal("piracy", adminBan.BanCategory);
            Assert.True(adminBan.IsActive);
            Assert.Null(adminBan.ExpiresAt);
            // The unique (HardwareId, ProductId) index forbids a second row: the expired exact row was reactivated.
            Assert.Equal(2, await readback.BannedHardwareIds.CountAsync());
            var decided = await readback.SecurityLockReports.AsNoTracking().SingleAsync();
            Assert.Equal("franck", decided.AdminDecisionBy);
            Assert.Equal("confirmed", decided.AdminDecisionReason);
        }

        // Policy changes: only irreversible causes and closed modes, attributed, upserted per product.
        Assert.Equal("cause_invalid", await admin.SetPolicyAsync(fixture.ProductId, "LEGACY_MARKER", "ENFORCE", "franck"));
        Assert.Equal("mode_invalid", await admin.SetPolicyAsync(fixture.ProductId, "NATIVE_DLL_REPLACED", "enforce", "franck"));
        Assert.Equal("updated_by_invalid", await admin.SetPolicyAsync(fixture.ProductId, "NATIVE_DLL_REPLACED", "SHADOW", " "));
        Assert.Equal("not_found", await admin.SetPolicyAsync(Guid.NewGuid(), "NATIVE_DLL_REPLACED", "SHADOW", "franck"));
        Assert.Equal("ok", await admin.SetPolicyAsync(fixture.ProductId, "NATIVE_DLL_REPLACED", "SHADOW", "franck"));
        Assert.Equal("ok", await admin.SetPolicyAsync(fixture.ProductId, "NATIVE_DLL_REPLACED", "ENFORCE", "franck"));
        await using (var readback = await factory.CreateDbContextAsync())
        {
            var policy = await readback.SecurityLockEnforcementPolicies.AsNoTracking().SingleAsync();
            Assert.Equal("ENFORCE", policy.Mode);
            Assert.Equal("franck", policy.UpdatedBy);
        }
    }

    /// <summary>
    /// An authenticated report remains auditable after commercial revocation, but cannot release a
    /// lock or turn an unrelated reported hardware value into a permanent ENFORCE ban.
    /// The old signed RELEASE is immutable and refused when its policy has become stale.
    /// </summary>
    [Fact]
    public async Task SecurityEvidence_CommercialDenialAndUnlinkedHardwareRemainFailClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var service = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));

        var first = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", '7');
        var firstDigest = Sha256("item3b-initial-release-" + Guid.NewGuid().ToString("D"));
        var firstProof = LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
            first.ReportId!, firstDigest, scenario.Options);
        // The lock path must fail as infrastructure when the configured registry version drifts.
        scenario.Options.KeyRegistryVersion += 1;
        var registryFailure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.ProcessSecurityLockReportAsync(
                scenario.EnrollmentId, firstDigest, first, firstProof, IPAddress.Loopback));
        Assert.Equal("Runtime enrollment key registry validation failed.", registryFailure.Message);
        scenario.Options.KeyRegistryVersion -= 1;
        await using (var registryCheck = await scenario.Factory.CreateDbContextAsync())
            Assert.False(await registryCheck.SecurityLockReportNonces.AnyAsync(row =>
                row.EnrollmentId == scenario.EnrollmentId));
        var released = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, firstDigest, first, firstProof, IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, released.Response.Verdict);

        await using (var policy = await scenario.Factory.CreateDbContextAsync())
        {
            policy.SecurityLockEnforcementPolicies.Add(new SecurityLockEnforcementPolicy
            {
                ProductId = scenario.Fixture.ProductId,
                Cause = "DEBUGGER_ATTACHED_KERNEL",
                Mode = "ENFORCE",
                UpdatedAtUtc = DateTime.UtcNow,
                UpdatedBy = "item3b-test"
            });
            await policy.SaveChangesAsync();
        }
        const string unlinkedHardware = "FFFFFFFFFFFFFFFF";
        var unlinked = LockRequest(unlinkedHardware, scenario.Fixture.Version,
            "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", '8');
        var unlinkedDigest = Sha256("item3b-unlinked-" + Guid.NewGuid().ToString("D"));
        var unlinkedVerdict = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, unlinkedDigest, unlinked,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, unlinked.ReportId!, unlinkedDigest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, unlinkedVerdict.Response.Verdict);
        Guid unlinkedRowId;
        await using (var noBan = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.False(await noBan.BannedHardwareIds.AnyAsync(row => row.HardwareId == unlinkedHardware));
            unlinkedRowId = (await noBan.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.LockId == unlinked.LockId)).Id;
        }
        var adminService = new SecurityLockAdminService(scenario.Factory);
        var unlinkedAdmin = await adminService.DecideAsync(
            unlinkedRowId, SecurityLockAdminDecisions.Ban, "reviewed", "admin", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.HardwareUnlinked, unlinkedAdmin.Outcome);
        await using (var rejected = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.False(await rejected.BannedHardwareIds.AnyAsync(row => row.HardwareId == unlinkedHardware));
            var retained = await rejected.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == unlinkedRowId);
            Assert.Null(retained.AdminDecision);
            Assert.Equal(SecurityLockReportStates.Open, retained.State);
        }

        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var assignment = await admin.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.IsActive = false;
            await admin.SaveChangesAsync();
        }
        RuntimeEnrollment afterRevocation;
        await using (var snapshot = await scenario.Factory.CreateDbContextAsync())
            afterRevocation = await snapshot.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);

        var stale = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.ProcessSecurityLockReportAsync(
                scenario.EnrollmentId, firstDigest, first, firstProof, IPAddress.Loopback));
        Assert.Equal("stale_verdict", stale.ErrorCode);

        var current = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", '7');
        current.FirstSeenUtc = first.FirstSeenUtc;
        var currentDigest = Sha256("item3b-current-maintain-" + Guid.NewGuid().ToString("D"));
        var maintained = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, currentDigest, current,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, current.ReportId!, currentDigest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, maintained.Response.Verdict);
        AssertVerdictSignature(maintained.Response, ackKey);

        // A later active historical ban must take precedence, including a lower-case stored value.
        await using (var banDb = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            banDb.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = LegacyHardwareId.ToLowerInvariant(),
                ProductId = scenario.Fixture.ProductId,
                BannedAt = DateTime.UtcNow,
                Reason = "item3b-historical-ban",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await banDb.SaveChangesAsync();
        }
        var bannedReport = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", '7');
        bannedReport.FirstSeenUtc = first.FirstSeenUtc;
        var bannedDigest = Sha256("item3b-current-ban-" + Guid.NewGuid().ToString("D"));
        var bannedVerdict = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, bannedDigest, bannedReport,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, bannedReport.ReportId!, bannedDigest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Ban, bannedVerdict.Response.Verdict);
        AssertVerdictSignature(bannedVerdict.Response, ackKey);
        await using (var banCheck = await scenario.Factory.CreateDbContextAsync())
            Assert.Single(await banCheck.BannedHardwareIds.Where(row =>
                row.HardwareId.ToUpper() == LegacyHardwareId).ToListAsync());

        var canary = new CanaryPingRequest
        {
            Schema = CanaryAckService.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
            HardwareId = LegacyHardwareId,
            AppVersion = scenario.Fixture.Version,
            Trigger = "RuntimeCheck_NativeDllSwapped",
            Severity = 3
        };
        var canaryDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(canary));
        var canaryProof = CanaryProof(scenario.EnrollmentKey, scenario.EnrollmentId,
            canary.EventId!, canaryDigest, scenario.Options);
        var accepted = await service.ProcessCanaryAsync(
            scenario.EnrollmentId, canaryDigest, canary, canaryProof, IPAddress.Loopback);
        var replay = await service.ProcessCanaryAsync(
            scenario.EnrollmentId, canaryDigest, canary, canaryProof, IPAddress.Loopback);
        Assert.False(accepted.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(accepted.ExactResponseBody, replay.ExactResponseBody);
        Assert.Equal("ack", accepted.Response.Decision);
        var encodedSignature = accepted.Response.Signature.Replace('-', '+').Replace('_', '/');
        var signature = Convert.FromBase64String(encodedSignature
            + new string('=', (4 - encodedSignature.Length % 4) % 4));
        Assert.True(ackKey.VerifyData(
            Encoding.UTF8.GetBytes(CanaryAckService.BuildCanonicalPayload(accepted.Response)),
            signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", enrollment.State);
        Assert.Equal(afterRevocation.KeyThumbprint, enrollment.KeyThumbprint);
        Assert.Equal(afterRevocation.SecurityEpoch, enrollment.SecurityEpoch);
        Assert.Equal(afterRevocation.AuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.Null(enrollment.InvalidationReason);
        Assert.False(await check.EnrollmentLicenseAssignments.AnyAsync(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE"));
        Assert.False(await check.RuntimeEnrollmentProofNonces.AnyAsync(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.Operation == "capability"));
        Assert.True(await check.RuntimeCriticalIncidents.AnyAsync(row => row.EventId == canary.EventId));
        Assert.Equal("commercial_denial:assignment_missing", (await check.CanaryAlerts
            .SingleAsync(row => row.HardwareId == LegacyHardwareId)).Details);
        Assert.False(await check.BannedHardwareIds.AnyAsync(row => row.HardwareId == unlinkedHardware));
    }

    /// <summary>
    /// Terminal enrollment state is an identity failure even for a critical report. A fresh fixture
    /// exercises this branch without illegally resurrecting a terminal row in the earlier matrix.
    /// </summary>
    [Fact]
    public async Task CanaryProof_TerminalEnrollmentCannotReplayOrRegainAssignment()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var service = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var request = new CanaryPingRequest
        {
            Schema = CanaryAckService.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
            HardwareId = LegacyHardwareId,
            AppVersion = scenario.Fixture.Version,
            Trigger = "RuntimeCheck_NativeDllSwapped",
            Severity = 3
        };
        var digest = Sha256(System.Text.Json.JsonSerializer.Serialize(request));
        var proof = CanaryProof(scenario.EnrollmentKey, scenario.EnrollmentId,
            request.EventId!, digest, scenario.Options);
        var issued = await service.ProcessCanaryAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(issued.Idempotent);

        await using (var terminal = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var enrollment = await terminal.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "test-independent-enrollment-state";
            await terminal.SaveChangesAsync();
        }
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.ProcessCanaryAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("enrollment_inactive", refused.ErrorCode);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("INVALIDATED", (await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.False(await check.EnrollmentLicenseAssignments.AnyAsync(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE"));
        Assert.Single(await check.RuntimeCanaryProofNonces.Where(row =>
            row.EnrollmentId == scenario.EnrollmentId).ToListAsync());
    }

    /// <summary>
    /// A later assignment ending does not erase frozen first-receipt linkage. Repeated concurrent
    /// admin decisions converge on one ban; PostgreSQL refuses every later report-hardware mutation.
    /// </summary>
    [Fact]
    public async Task SecurityLockAdmin_HistoricalLinkedBanIsAtomicAndIdempotent()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        // The server report stays canonical upper-case while a historical seat uses lower-case.
        await using (var mixedCase = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var assignment = await mixedCase.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var seat = await mixedCase.LicenseSeats.SingleAsync(row => row.Id == assignment.LicenseSeatId);
            seat.HardwareId = LegacyHardwareId.ToLowerInvariant();
            await mixedCase.SaveChangesAsync();
        }
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var service = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var request = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", '9');
        var digest = Sha256("item3b-admin-historical-" + Guid.NewGuid().ToString("D"));
        var accepted = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, request,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, request.ReportId!, digest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, accepted.Response.Verdict);

        Guid reportId;
        await using (var mutate = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var report = await mutate.SecurityLockReports.SingleAsync(row => row.LockId == request.LockId);
            reportId = report.Id;
            var license = await mutate.Licenses.SingleAsync(row => row.ProductId == scenario.Fixture.ProductId);
            license.IsActive = false;
            var seat = await mutate.LicenseSeats.SingleAsync(row => row.LicenseId == license.Id);
            seat.HardwareId = "LATER-DIFFERENT-HARDWARE";
            await mutate.SaveChangesAsync();
            var ended = await mutate.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId);
            Assert.Equal("ENDED", ended.State);
            var capturedAt = Assert.IsType<DateTime>(report.LinkVerifiedAtUtc);
            Assert.True(ended.ActivatedAtUtc <= capturedAt);
            Assert.True(ended.EndedAtUtc >= capturedAt);
        }
        // PostgreSQL, not only the in-memory canonicalizer, rejects lower-case, whitespace,
        // other symbols, oversized and null report hardware values before an admin can review them.
        await using (var postgres = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await postgres.OpenAsync();
            var invalidCases = new string?[]
            {
                string.Empty, LegacyHardwareId.ToLowerInvariant(), " A", "A ", "A@B",
                new string('A', 129), null, "A", new string('A', 128)
            };
            foreach (var value in invalidCases)
            {
                await using var command = postgres.CreateCommand();
                command.CommandText = "UPDATE public.\"SecurityLockReports\" SET \"HardwareId\"=@hardware WHERE \"Id\"=@id";
                command.Parameters.Add(new NpgsqlParameter("hardware", NpgsqlDbType.Varchar)
                {
                    Value = value is null ? DBNull.Value : value
                });
                command.Parameters.AddWithValue("id", reportId);
                var providerError = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
                Assert.Equal(value is { Length: > 128 } ? "22001" : "23514",
                    providerError.SqlState);
            }
        }
        var admin = new SecurityLockAdminService(scenario.Factory);
        await using (var canonical = await scenario.Factory.CreateDbContextAsync())
            Assert.Equal(LegacyHardwareId, (await canonical.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == reportId)).HardwareId);

        // Two independent admin connections wait on a third connection's row lock.
        // Whichever decision reaches the row first, the final state cannot be BANNED+RELEASE.
        await using (var blocker = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await blocker.OpenAsync();
            await using var held = await blocker.BeginTransactionAsync();
            await using (var lockRow = new NpgsqlCommand(
                "SELECT \"Id\" FROM public.\"SecurityLockReports\" WHERE \"Id\"=@id FOR UPDATE", blocker, held))
            {
                lockRow.Parameters.AddWithValue("id", reportId);
                Assert.Equal(reportId, (Guid)(await lockRow.ExecuteScalarAsync())!);
            }
            var banTask = admin.DecideAsync(reportId, SecurityLockAdminDecisions.Ban,
                "race-ban", "admin", scenario.Fixture.ProductId);
            var releaseTask = admin.DecideAsync(reportId, SecurityLockAdminDecisions.Release,
                "race-release", "admin", scenario.Fixture.ProductId);
            await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
            await observer.OpenAsync();
            var waiters = 0L;
            for (var attempt = 0; attempt < 100 && waiters < 2; attempt++)
            {
                await using var observed = new NpgsqlCommand("""
                    SELECT count(*) FROM pg_catalog.pg_stat_activity
                    WHERE datname = current_database() AND wait_event_type = 'Lock'
                      AND query LIKE '%SecurityLockReports%FOR UPDATE%'
                    """, observer);
                waiters = (long)(await observed.ExecuteScalarAsync())!;
                if (waiters < 2) await Task.Delay(20);
            }
            Assert.True(waiters >= 2, "Both admin decisions must overlap on the report row.");
            await held.CommitAsync();
            var race = await Task.WhenAll(banTask, releaseTask).WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(SecurityLockAdminOutcomes.Ok, race[0].Outcome);
            Assert.Contains(race[1].Outcome, new[]
            {
                SecurityLockAdminOutcomes.Ok, SecurityLockAdminOutcomes.LockBannedIrreversible
            });
        }
        await using (var raceCheck = await scenario.Factory.CreateDbContextAsync())
        {
            var result = await raceCheck.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == reportId);
            Assert.Equal(SecurityLockReportStates.Banned, result.State);
            Assert.Equal(SecurityLockAdminDecisions.Ban, result.AdminDecision);
        }
        var decisions = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            admin.DecideAsync(reportId, SecurityLockAdminDecisions.Ban,
                "reviewed", "admin", scenario.Fixture.ProductId)));
        Assert.All(decisions, result => Assert.Equal(SecurityLockAdminOutcomes.Ok, result.Outcome));
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(SecurityLockReportLinkStatuses.VerifiedSeat,
            (await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == reportId)).LinkStatus);
        Assert.Single(await check.BannedHardwareIds.Where(row =>
            row.HardwareId == LegacyHardwareId && row.IsActive).ToListAsync());
        var decided = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == reportId);
        Assert.Equal(SecurityLockAdminDecisions.Ban, decided.AdminDecision);
        Assert.Equal(SecurityLockReportStates.Banned, decided.State);
    }

    /// <summary>
    /// Proves both commit orders between a Runtime report and an administrator BAN. Both writers
    /// queue on the global mutation authority before the hardware and report locks, so neither
    /// order can deadlock or leave the forbidden BANNED-with-RELEASE combination.
    /// </summary>
    /// <param name="adminFirst">Whether the administrator is queued before the Runtime report.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SecurityLockRuntimeAndAdminBan_PostgreSql_GlobalAuthoritySerializesBothCommitOrders(
        bool adminFirst)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var request = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", adminFirst ? '6' : '7');
        var digest = Sha256("item3d2-lock-order-" + Guid.NewGuid().ToString("D"));
        var initial = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, request,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, request.ReportId!, digest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, initial.Response.Verdict);

        Guid reportId;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
            reportId = await read.SecurityLockReports.AsNoTracking()
                .Where(row => row.LockId == request.LockId)
                .Select(row => row.Id)
                .SingleAsync();
        var admin = new SecurityLockAdminService(scenario.Factory);

        await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)", blocker, blockerTransaction))
        {
            await hold.ExecuteNonQueryAsync();
        }

        Task<RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>> StartRuntime() =>
            runtime.ProcessSecurityLockReportAsync(
                scenario.EnrollmentId, digest, request,
                LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, request.ReportId!, digest,
                    scenario.Options), IPAddress.Loopback);
        Task<SecurityLockAdminDecisionResult> StartAdmin() => admin.DecideAsync(
            reportId, SecurityLockAdminDecisions.Ban, "race-ban", "admin",
            scenario.Fixture.ProductId);

        Task<RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>> runtimeTask;
        Task<SecurityLockAdminDecisionResult> adminTask;
        if (adminFirst)
        {
            adminTask = StartAdmin();
            await WaitForGlobalAuthorityWaitersBlockedByAsync(
                scenario.AdminConnectionString, blocker.ProcessID, 1);
            runtimeTask = StartRuntime();
        }
        else
        {
            runtimeTask = StartRuntime();
            await WaitForGlobalAuthorityWaitersBlockedByAsync(
                scenario.AdminConnectionString, blocker.ProcessID, 1);
            adminTask = StartAdmin();
        }
        await WaitForGlobalAuthorityWaitersBlockedByAsync(
            scenario.AdminConnectionString, blocker.ProcessID, 2);
        Assert.False(runtimeTask.IsCompleted);
        Assert.False(adminTask.IsCompleted);

        await blockerTransaction.CommitAsync();
        var runtimeResult = await runtimeTask.WaitAsync(TimeSpan.FromSeconds(15));
        var adminResult = await adminTask.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.Equal(SecurityLockAdminOutcomes.Ok, adminResult.Outcome);
        Assert.Equal(adminFirst ? SecurityLockVerdicts.Ban : SecurityLockVerdicts.Maintain,
            runtimeResult.Response.Verdict);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var stored = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == reportId);
        Assert.Equal(SecurityLockReportStates.Banned, stored.State);
        Assert.Equal(SecurityLockAdminDecisions.Ban, stored.AdminDecision);
        Assert.NotEqual(SecurityLockAdminDecisions.Release, stored.AdminDecision);
        Assert.Single(await check.BannedHardwareIds.AsNoTracking().Where(row =>
            row.HardwareId == LegacyHardwareId && row.IsActive).ToListAsync());
    }

    /// <summary>
    /// A digest-only authenticated alias frozen at first receipt remains proof even if its mutable
    /// row is subsequently disabled; the old observation is never reinterpreted from current state.
    /// </summary>
    [Fact]
    public async Task SecurityLockAdmin_AuthoritativeAliasMustBeEffectiveAtReport()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        Guid aliasId;
        await using (var seed = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var enrollment = await seed.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var assignment = await seed.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var seat = await seed.LicenseSeats.SingleAsync(row => row.Id == assignment.LicenseSeatId);
            seat.HardwareId = StableHardwareId;
            aliasId = Guid.NewGuid();
            seed.HardwareAuthorityAliases.Add(new HardwareAuthorityAlias
            {
                Id = aliasId,
                ProductId = scenario.Fixture.ProductId,
                LicenseId = assignment.LicenseId,
                LicenseSeatId = assignment.LicenseSeatId,
                RuntimeEnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                LegacyHardwareIdSha256 = Sha256(LegacyHardwareId),
                CanonicalHardwareIdSha256 = Sha256(StableHardwareId),
                SecurityEpoch = enrollment.SecurityEpoch,
                AuthorityEpoch = enrollment.AuthorityEpoch,
                IsActive = true,
                CreatedAtUtc = DateTime.UtcNow.AddMinutes(-1)
            });
            await seed.SaveChangesAsync();
        }

        await using (var postgres = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await postgres.OpenAsync();
            foreach (var (digestValue, sqlState) in new[]
            {
                (new string('a', 63), "23514"),
                (new string('a', 65), "22001"),
                (Sha256(LegacyHardwareId).ToUpperInvariant(), "23514"),
                (" " + new string('a', 63), "23514")
            })
            {
                await using var command = postgres.CreateCommand();
                command.CommandText = "UPDATE public.\"HardwareAuthorityAliases\" SET \"LegacyHardwareIdSha256\"=@digest WHERE \"Id\"=@id";
                command.Parameters.AddWithValue("digest", digestValue);
                command.Parameters.AddWithValue("id", aliasId);
                var providerError = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
                Assert.Equal(sqlState, providerError.SqlState);
            }
        }
        await using (var digestCheck = await scenario.Factory.CreateDbContextAsync())
            Assert.Equal(Sha256(LegacyHardwareId), (await digestCheck.HardwareAuthorityAliases
                .AsNoTracking().SingleAsync(row => row.Id == aliasId)).LegacyHardwareIdSha256);

        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var service = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var request = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", 'b');
        var digest = Sha256("item3b-alias-" + Guid.NewGuid().ToString("D"));
        var verdict = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, request,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, request.ReportId!, digest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, verdict.Response.Verdict);
        Guid reportId;
        DateTime firstReported;
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var row = await check.SecurityLockReports.AsNoTracking().SingleAsync(x => x.LockId == request.LockId);
            reportId = row.Id;
            firstReported = row.FirstReportedUtc;
        }

        // The alias can change while a first report is in flight. A held row must
        // cause a bounded retry/refusal, never a positive proof from its old value.
        var racing = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", 'a');
        var racingDigest = Sha256("item3b-alias-race-" + Guid.NewGuid().ToString("D"));
        int nonceCount;
        int banCount;
        int deliveryCount;
        int alertCount;
        await using (var baseline = await scenario.Factory.CreateDbContextAsync())
        {
            nonceCount = await baseline.SecurityLockReportNonces.CountAsync();
            banCount = await baseline.BannedHardwareIds.CountAsync();
            deliveryCount = await baseline.SecurityLockAlertDeliveries.CountAsync();
            alertCount = await baseline.CanaryAlerts.CountAsync();
        }
        await using (var blocker = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await blocker.OpenAsync();
            await using var held = await blocker.BeginTransactionAsync();
            await using (var disable = new NpgsqlCommand("""
                UPDATE public."HardwareAuthorityAliases"
                   SET "IsActive"=false,"DisabledAtUtc"=pg_catalog.clock_timestamp(),
                       "DisabledReason"=@reason
                 WHERE "Id"=@id
                """, blocker, held))
            {
                disable.Parameters.AddWithValue("id", aliasId);
                disable.Parameters.AddWithValue("reason", HardwareAuthorityAlias.OperatorDisabledReason);
                Assert.Equal(1, await disable.ExecuteNonQueryAsync());
            }
            var overlap = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.ProcessSecurityLockReportAsync(
                    scenario.EnrollmentId, racingDigest, racing,
                    LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, racing.ReportId!, racingDigest,
                        scenario.Options), IPAddress.Loopback).WaitAsync(TimeSpan.FromSeconds(15)));
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, overlap.StatusCode);
            Assert.Equal("authority_unavailable", overlap.ErrorCode);
            await using (var check = await scenario.Factory.CreateDbContextAsync())
            {
                Assert.False(await check.SecurityLockReports.AsNoTracking()
                    .AnyAsync(row => row.LockId == racing.LockId));
                Assert.Equal(nonceCount, await check.SecurityLockReportNonces.CountAsync());
                Assert.Equal(banCount, await check.BannedHardwareIds.CountAsync());
                Assert.Equal(deliveryCount, await check.SecurityLockAlertDeliveries.CountAsync());
                Assert.Equal(alertCount, await check.CanaryAlerts.CountAsync());
            }
            await held.RollbackAsync();
        }
        var afterRollback = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, racingDigest, racing,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, racing.ReportId!, racingDigest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, afterRollback.Response.Verdict);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
            Assert.Equal(SecurityLockReportLinkStatuses.VerifiedAlias,
                (await check.SecurityLockReports.AsNoTracking()
                    .SingleAsync(row => row.LockId == racing.LockId)).LinkStatus);

        await using (var blocker = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await blocker.OpenAsync();
            await using var held = await blocker.BeginTransactionAsync();
            await using var disable = new NpgsqlCommand("""
                UPDATE public."HardwareAuthorityAliases"
                   SET "IsActive"=false,"DisabledAtUtc"=pg_catalog.clock_timestamp(),
                       "DisabledReason"=@reason WHERE "Id"=@id
                """, blocker, held);
            disable.Parameters.AddWithValue("id", aliasId);
            disable.Parameters.AddWithValue("reason", HardwareAuthorityAlias.OperatorDisabledReason);
            Assert.Equal(1, await disable.ExecuteNonQueryAsync());
            await held.CommitAsync();
        }
        var afterDisableRequest = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", 'd');
        var afterDisableDigest = Sha256("item3b-alias-disabled-" + Guid.NewGuid().ToString("D"));
        var afterDisable = await service.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, afterDisableDigest, afterDisableRequest,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, afterDisableRequest.ReportId!,
                afterDisableDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, afterDisable.Response.Verdict);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var negative = await check.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.LockId == afterDisableRequest.LockId);
            Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, negative.LinkStatus);
            Assert.Equal("hardware_unlinked", negative.LinkReasonCode);
            Assert.False(await check.BannedHardwareIds.AnyAsync(row =>
                row.HardwareId == LegacyHardwareId && row.IsActive));
        }

        await using (var disable = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var alias = await disable.HardwareAuthorityAliases.SingleAsync(row => row.Id == aliasId);
            alias.IsActive = false;
            alias.DisabledAtUtc = firstReported.AddSeconds(-1);
            alias.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason;
            await disable.SaveChangesAsync();
        }
        var admin = new SecurityLockAdminService(scenario.Factory);
        var accepted = await admin.DecideAsync(
            reportId, SecurityLockAdminDecisions.Ban, "reviewed", "admin", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, accepted.Outcome);
        await using var final = await scenario.Factory.CreateDbContextAsync();
        Assert.True(await final.BannedHardwareIds.AnyAsync(row =>
            row.HardwareId == LegacyHardwareId && row.IsActive));
        Assert.False(await final.BannedHardwareIds.AnyAsync(row => row.HardwareId == StableHardwareId));
    }

    /// <summary>
    /// A first-receipt failure cannot become historical proof after a mutable seat adopts that
    /// hardware; the same LockId remains negative even when current commercial policy changes.
    /// </summary>
    [Fact]
    public async Task SecurityLockProof_UnlinkedAtT0StaysUnlinkedAfterSeatHardwareChanges()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        const string laterHardware = "T0-UNLINKED-T1-SEAT";
        var first = LockRequest(laterHardware, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", 'c');
        var firstDigest = Sha256("frozen-negative-" + Guid.NewGuid().ToString("D"));
        var firstVerdict = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, firstDigest, first,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, first.ReportId!,
                firstDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, firstVerdict.Response.Verdict);
        Guid reportId;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var report = await before.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.LockId == first.LockId);
            reportId = report.Id;
            Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, report.LinkStatus);
            Assert.Equal("hardware_unlinked", report.LinkReasonCode);
            Assert.NotNull(report.LinkVerifiedAtUtc);
            Assert.Null(report.LinkAssignmentId);
        }
        // Caller-forged linked references are ignored before FK/CHECK validation.
        await using (var owner = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await owner.OpenAsync();
            await using var spoof = new NpgsqlCommand("""
                INSERT INTO public."SecurityLockReports"
                    ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                     "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                     "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                     "ReportCount","State","LastVerdict","LinkStatus","LinkAssignmentId",
                     "LinkLicenseSeatId","LinkAliasId","LinkVerifiedAtUtc","LinkReasonCode")
                SELECT @id,e."ProductId",e."Id",e."BindingId",e."InstallationId",@hardware,
                       e."ReleaseVersion",@lockId,'NATIVE_DLL_REPLACED',4,'REVIEW','REVIEW',
                       @evidence,pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
                       pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN',
                       'VERIFIED_ALIAS',@fake,@fake,@fake,pg_catalog.clock_timestamp(),NULL
                FROM public."RuntimeEnrollments" e WHERE e."Id"=@enrollmentId
                """, owner);
            var forgedId = Guid.NewGuid();
            spoof.Parameters.AddWithValue("id", forgedId);
            spoof.Parameters.AddWithValue("hardware", laterHardware);
            spoof.Parameters.AddWithValue("lockId", new string('d', 32));
            spoof.Parameters.AddWithValue("evidence", new string('c', 64));
            spoof.Parameters.AddWithValue("fake", Guid.NewGuid());
            spoof.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            Assert.Equal(1, await spoof.ExecuteNonQueryAsync());
            await using var check = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
            var captured = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == forgedId);
            Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, captured.LinkStatus);
            Assert.Equal("hardware_unlinked", captured.LinkReasonCode);
            Assert.Null(captured.LinkAssignmentId);
            Assert.Null(captured.LinkLicenseSeatId);
            Assert.Null(captured.LinkAliasId);
        }
        // The harness runtime-test role has broad fixture grants. Check the real
        // production-style softlicence_app role established by the migration.
        var productionRoleConnection = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only",
            // The fixture's database cleanup permits only its own app/admin pools. Keep this
            // production-role probe unpooled so an idle foreign-role session cannot outlive it.
            Pooling = false
        }.ConnectionString;
        await using (var app = new NpgsqlConnection(productionRoleConnection))
        {
            await app.OpenAsync();
            await using var privileges = new NpgsqlCommand("""
                SELECT pg_catalog.has_table_privilege(current_user, 'public."SecurityLockReports"', 'SELECT'),
                       pg_catalog.has_table_privilege(current_user, 'public."SecurityLockReports"', 'UPDATE'),
                       pg_catalog.has_table_privilege(current_user, 'public."SecurityLockReports"', 'DELETE'),
                       pg_catalog.has_column_privilege(current_user, 'public."SecurityLockReports"', 'State', 'UPDATE'),
                       pg_catalog.has_column_privilege(current_user, 'public."SecurityLockReports"', 'LinkStatus', 'UPDATE'),
                       pg_catalog.has_function_privilege(current_user,
                           'public.capture_security_lock_report_link()', 'EXECUTE')
                """, app);
            await using var permissions = await privileges.ExecuteReaderAsync();
            Assert.True(await permissions.ReadAsync());
            Assert.True(permissions.GetBoolean(0));
            Assert.False(permissions.GetBoolean(1));
            Assert.False(permissions.GetBoolean(2));
            Assert.True(permissions.GetBoolean(3));
            Assert.False(permissions.GetBoolean(4));
            Assert.False(permissions.GetBoolean(5));
            await permissions.CloseAsync();
            await using var forbidden = new NpgsqlCommand("""
                UPDATE public."SecurityLockReports" SET "LinkStatus"='VERIFIED_SEAT' WHERE "Id"=@id
                """, app);
            forbidden.Parameters.AddWithValue("id", reportId);
            Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(
                () => forbidden.ExecuteNonQueryAsync())).SqlState);
        }
        await using (var owner = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await owner.OpenAsync();
            await using var immutable = new NpgsqlCommand("""
                UPDATE public."SecurityLockReports" SET "LinkReasonCode"='assignment_missing' WHERE "Id"=@id
                """, owner);
            immutable.Parameters.AddWithValue("id", reportId);
            Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(
                () => immutable.ExecuteNonQueryAsync())).SqlState);
        }

        await using (var change = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var assignment = await change.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var seat = await change.LicenseSeats.SingleAsync(row => row.Id == assignment.LicenseSeatId);
            seat.HardwareId = laterHardware;
            await change.SaveChangesAsync();
        }
        var admin = new SecurityLockAdminService(scenario.Factory);
        var denied = await admin.DecideAsync(reportId, SecurityLockAdminDecisions.Ban,
            "reviewed", "admin", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.HardwareUnlinked, denied.Outcome);
        Assert.Equal("hardware_unlinked", denied.DiagnosticCode);
        using (var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "tkt1312-local-synthetic");
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHostedService>();
                services.RemoveAll<IDataProtectionProvider>();
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(
                    options => options.UseNpgsql(scenario.AppConnectionString));
            });
        }))
        using (var client = host.CreateClient())
        {
            client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt1312-local-synthetic");
            var response = await client.PostAsJsonAsync(
                $"/api/admin/security-locks/{reportId:D}/decision",
                new SecurityLockDecisionRequest
                {
                    Decision = SecurityLockAdminDecisions.Ban,
                    DecidedBy = "admin",
                    Reason = "reviewed"
                });
            Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
            var responseText = await response.Content.ReadAsStringAsync();
            Assert.Contains("\"error\":\"hardware_unlinked\"", responseText, StringComparison.Ordinal);
            Assert.DoesNotContain(laterHardware, responseText, StringComparison.Ordinal);
        }
        var repeat = LockRequest(laterHardware, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", 'c');
        repeat.FirstSeenUtc = first.FirstSeenUtc;
        var repeatDigest = Sha256("frozen-negative-repeat-" + Guid.NewGuid().ToString("D"));
        var repeated = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, repeatDigest, repeat,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, repeat.ReportId!,
                repeatDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, repeated.Response.Verdict);
        await using var after = await scenario.Factory.CreateDbContextAsync();
        var frozen = await after.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == reportId);
        Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, frozen.LinkStatus);
        Assert.False(await after.BannedHardwareIds.AnyAsync(row =>
            row.HardwareId == laterHardware && row.IsActive));

        // An old writer may stage its ban and BANNED report in EF savepoints. Neither
        // row is authority until a previous transaction committed the ban.
        await using (var oldWriter = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await using var transaction = await oldWriter.Database.BeginTransactionAsync();
            oldWriter.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = laterHardware,
                ProductId = scenario.Fixture.ProductId,
                BannedAt = DateTime.UtcNow,
                Reason = "old-writer-probe",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            var oldReport = await oldWriter.SecurityLockReports.SingleAsync(row => row.Id == reportId);
            oldReport.State = SecurityLockReportStates.Banned;
            oldReport.LastVerdict = SecurityLockVerdicts.Ban;
            await oldWriter.SaveChangesAsync();
            var refusedCommit = await Assert.ThrowsAsync<PostgresException>(
                () => transaction.CommitAsync());
            Assert.Equal("23514", refusedCommit.SqlState);
        }
        await using (var rollbackCheck = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            Assert.False(await rollbackCheck.BannedHardwareIds.AnyAsync(row =>
                row.HardwareId == laterHardware && row.IsActive));
            Assert.Equal(SecurityLockReportStates.Open,
                (await rollbackCheck.SecurityLockReports.AsNoTracking()
                    .SingleAsync(row => row.Id == reportId)).State);
        }
        await using (var expiredGlobal = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            expiredGlobal.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = laterHardware,
                ProductId = null,
                BannedAt = DateTime.UtcNow.AddDays(-2),
                ExpiresAt = DateTime.UtcNow.AddDays(-1),
                Reason = "expired-global-probe",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await expiredGlobal.SaveChangesAsync();
        }
        await using (var oldWriter = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await using var transaction = await oldWriter.Database.BeginTransactionAsync();
            var oldReport = await oldWriter.SecurityLockReports.SingleAsync(row => row.Id == reportId);
            oldReport.State = SecurityLockReportStates.Banned;
            oldReport.LastVerdict = SecurityLockVerdicts.Ban;
            await oldWriter.SaveChangesAsync();
            Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(
                () => transaction.CommitAsync())).SqlState);
        }
        // A concurrent transaction's uncommitted ban is not an authority snapshot.
        await using (var pendingBan = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await using var pendingTransaction = await pendingBan.Database.BeginTransactionAsync();
            pendingBan.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = laterHardware,
                ProductId = scenario.Fixture.ProductId,
                BannedAt = DateTime.UtcNow,
                Reason = "concurrent-uncommitted-probe",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await pendingBan.SaveChangesAsync();
            await using (var oldWriter = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
            {
                await using var transaction = await oldWriter.Database.BeginTransactionAsync();
                var oldReport = await oldWriter.SecurityLockReports.SingleAsync(row => row.Id == reportId);
                oldReport.State = SecurityLockReportStates.Banned;
                oldReport.LastVerdict = SecurityLockVerdicts.Ban;
                await oldWriter.SaveChangesAsync();
                Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(
                    () => transaction.CommitAsync())).SqlState);
            }
            await pendingTransaction.RollbackAsync();
        }
        await using (var priorBan = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            priorBan.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = laterHardware,
                ProductId = scenario.Fixture.ProductId,
                BannedAt = DateTime.UtcNow,
                Reason = "prior-live-ban",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await priorBan.SaveChangesAsync();
        }
        await using (var oldWriter = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await using var transaction = await oldWriter.Database.BeginTransactionAsync();
            var oldReport = await oldWriter.SecurityLockReports.SingleAsync(row => row.Id == reportId);
            oldReport.State = SecurityLockReportStates.Banned;
            oldReport.LastVerdict = SecurityLockVerdicts.Ban;
            await oldWriter.SaveChangesAsync();
            await transaction.CommitAsync();
        }
        await using (var committed = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
            Assert.Equal(SecurityLockReportStates.Banned,
                (await committed.SecurityLockReports.AsNoTracking()
                    .SingleAsync(row => row.Id == reportId)).State);

        // A previously committed, nonexpired global ban authorizes an old writer's
        // BANNED state even though the report itself has no first-receipt link.
        const string globalHardware = "GLOBAL-LIVE-PROBE";
        var globalReportId = Guid.NewGuid();
        await using (var owner = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await owner.OpenAsync();
            await using var insert = new NpgsqlCommand("""
                INSERT INTO public."SecurityLockReports"
                    ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                     "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                     "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                     "ReportCount","State","LastVerdict")
                SELECT @id,r."ProductId",r."EnrollmentId",r."BindingId",r."InstallationId",
                       @hardware,r."AppVersion",@lockId,r."Cause",r."Level",r."ClientMode",
                       r."EffectiveMode",r."EvidenceDigestSha256",pg_catalog.clock_timestamp(),
                       pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN'
                FROM public."SecurityLockReports" r WHERE r."Id"=@source
                """, owner);
            insert.Parameters.AddWithValue("id", globalReportId);
            insert.Parameters.AddWithValue("source", reportId);
            insert.Parameters.AddWithValue("hardware", globalHardware);
            insert.Parameters.AddWithValue("lockId", new string('e', 32));
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        }
        await using (var globalBan = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            Assert.Equal(SecurityLockReportLinkStatuses.Unlinked,
                (await globalBan.SecurityLockReports.AsNoTracking()
                    .SingleAsync(row => row.Id == globalReportId)).LinkStatus);
            globalBan.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = globalHardware,
                ProductId = null,
                BannedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(1),
                Reason = "prior-live-global-probe",
                BanCategory = BannedHardwareId.Categories.Manual,
                IsActive = true
            });
            await globalBan.SaveChangesAsync();
        }
        await using (var oldWriter = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await using var transaction = await oldWriter.Database.BeginTransactionAsync();
            var globalReport = await oldWriter.SecurityLockReports.SingleAsync(row => row.Id == globalReportId);
            globalReport.State = SecurityLockReportStates.Banned;
            globalReport.LastVerdict = SecurityLockVerdicts.Ban;
            await oldWriter.SaveChangesAsync();
            await transaction.CommitAsync();
        }
        await using (var committed = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
            Assert.Equal(SecurityLockReportStates.Banned,
                (await committed.SecurityLockReports.AsNoTracking()
                    .SingleAsync(row => row.Id == globalReportId)).State);
    }

    /// <summary>
    /// Pre-migration reports remain UNKNOWN after upgrade and cannot justify admin BAN. New reports
    /// get a frozen proof, whose loss is refused by the migration's downgrade guard.
    /// </summary>
    [Fact]
    public async Task SecurityLockProof_LegacyUpgradeAndDowngradeAreFailClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        const string predecessor = "20260922213000_AddEnrollmentAssignmentDualWrite";
        await admin.Database.MigrateAsync(predecessor);
        var legacyId = Guid.NewGuid();
        await using (var connection = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await connection.OpenAsync();
            await using var insert = new NpgsqlCommand("""
                INSERT INTO public."SecurityLockReports"
                    ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                     "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                     "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                     "ReportCount","State","LastVerdict")
                SELECT @id,e."ProductId",e."Id",e."BindingId",e."InstallationId",@hardware,
                       e."ReleaseVersion",@lockId,'NATIVE_DLL_REPLACED',4,'REVIEW','REVIEW',
                       @evidence,pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
                       pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN'
                FROM public."RuntimeEnrollments" e WHERE e."Id"=@enrollmentId
                """, connection);
            insert.Parameters.AddWithValue("id", legacyId);
            insert.Parameters.AddWithValue("hardware", LegacyHardwareId);
            insert.Parameters.AddWithValue("lockId", new string('d', 32));
            insert.Parameters.AddWithValue("evidence", new string('a', 64));
            insert.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        }
        await admin.Database.MigrateAsync();
        await using (var check = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var legacy = await check.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == legacyId);
            Assert.Equal(SecurityLockReportLinkStatuses.UnknownLegacy, legacy.LinkStatus);
            Assert.Equal(SecurityLockReportLinkStatuses.LegacyUnknownReason, legacy.LinkReasonCode);
            Assert.Null(legacy.LinkVerifiedAtUtc);
        }
        var decision = await new SecurityLockAdminService(scenario.Factory).DecideAsync(
            legacyId, SecurityLockAdminDecisions.Ban, "reviewed", "admin",
            scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.HardwareUnlinked, decision.Outcome);
        Assert.Equal("report_link_legacy_unknown", decision.DiagnosticCode);

        await using (var connection = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await connection.OpenAsync();
            foreach (var (lockId, suppliedStatus, suppliedReason) in new[]
            {
                (new string('e', 32), "UNKNOWN_LEGACY", "legacy_unknown"),
                (new string('f', 32), "INVALID", "invalid"),
                (new string('a', 32), (string?)null, (string?)null)
            })
            {
                await using var insert = new NpgsqlCommand("""
                INSERT INTO public."SecurityLockReports"
                    ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                     "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                     "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                     "ReportCount","State","LastVerdict","LinkStatus","LinkAssignmentId",
                     "LinkLicenseSeatId","LinkAliasId","LinkVerifiedAtUtc","LinkReasonCode")
                SELECT pg_catalog.gen_random_uuid(),e."ProductId",e."Id",e."BindingId",
                       e."InstallationId",@hardware,e."ReleaseVersion",@lockId,
                       'NATIVE_DLL_REPLACED',4,'REVIEW','REVIEW',@evidence,
                       pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
                       pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN',
                       @status,@spoof,@spoof,@spoof,pg_catalog.clock_timestamp(),@reason
                FROM public."RuntimeEnrollments" e WHERE e."Id"=@enrollmentId
                """, connection);
                insert.Parameters.AddWithValue("hardware", LegacyHardwareId);
                insert.Parameters.AddWithValue("lockId", lockId);
                insert.Parameters.AddWithValue("evidence", new string('b', 64));
                insert.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
                insert.Parameters.AddWithValue("spoof", Guid.NewGuid());
                insert.Parameters.AddWithValue("status", NpgsqlDbType.Varchar,
                    (object?)suppliedStatus ?? DBNull.Value);
                insert.Parameters.AddWithValue("reason", NpgsqlDbType.Varchar,
                    (object?)suppliedReason ?? DBNull.Value);
                Assert.Equal(1, await insert.ExecuteNonQueryAsync());
            }
        }
        var downgradeFailure = await Assert.ThrowsAnyAsync<Exception>(
            () => admin.Database.MigrateAsync(predecessor));
        Assert.Contains("security-lock proof rollback", downgradeFailure.ToString(),
            StringComparison.Ordinal);
        await using var after = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        foreach (var lockId in new[] { new string('e', 32), new string('f', 32), new string('a', 32) })
        {
            var captured = await after.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.LockId == lockId);
            Assert.Equal(SecurityLockReportLinkStatuses.VerifiedSeat, captured.LinkStatus);
            Assert.NotNull(captured.LinkAssignmentId);
            Assert.NotNull(captured.LinkLicenseSeatId);
            Assert.Null(captured.LinkAliasId);
            Assert.Null(captured.LinkReasonCode);
        }
    }

    /// <summary>
    /// Empty and legacy-only databases can revert the proof migration without losing
    /// evidence. The downgrade removes every proof object and restores the exact
    /// predecessor table ACL, including removal of the upgrade's column grants.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SecurityLockProof_EmptyOrLegacyOnlyDownRestoresPredecessor(bool legacyOnly)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        const string predecessor = "20260922213000_AddEnrollmentAssignmentDualWrite";
        await using var migrator = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        await migrator.Database.MigrateAsync(predecessor);
        if (legacyOnly)
        {
            await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
            await writer.OpenAsync();
            await using var insert = new NpgsqlCommand("""
                INSERT INTO public."SecurityLockReports"
                    ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                     "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                     "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                     "ReportCount","State","LastVerdict")
                SELECT pg_catalog.gen_random_uuid(),e."ProductId",e."Id",e."BindingId",
                       e."InstallationId",@hardware,e."ReleaseVersion",@lockId,
                       'NATIVE_DLL_REPLACED',4,'REVIEW','REVIEW',@evidence,
                       pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
                       pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN'
                FROM public."RuntimeEnrollments" e WHERE e."Id"=@enrollmentId
                """, writer);
            insert.Parameters.AddWithValue("hardware", LegacyHardwareId);
            insert.Parameters.AddWithValue("lockId", new string('a', 32));
            insert.Parameters.AddWithValue("evidence", new string('a', 64));
            insert.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
            await migrator.Database.MigrateAsync();
            await using (var captured = new NpgsqlCommand("""
                SELECT "LinkStatus" FROM public."SecurityLockReports" WHERE "LockId"=@lockId
                """, writer))
            {
                captured.Parameters.AddWithValue("lockId", new string('a', 32));
                Assert.Equal(SecurityLockReportLinkStatuses.UnknownLegacy,
                    (string?)await captured.ExecuteScalarAsync());
            }
            await migrator.Database.MigrateAsync(predecessor);
        }

        await using var check = new NpgsqlConnection(scenario.AdminConnectionString);
        await check.OpenAsync();
        await using var inspect = new NpgsqlCommand("""
            SELECT
                (SELECT count(*) FROM pg_catalog.pg_attribute a
                  WHERE a.attrelid='public."SecurityLockReports"'::regclass
                    AND a.attname IN ('LinkStatus','LinkAssignmentId','LinkLicenseSeatId',
                                      'LinkAliasId','LinkVerifiedAtUtc','LinkReasonCode')
                    AND NOT a.attisdropped),
                (SELECT count(*) FROM pg_catalog.pg_trigger t
                  WHERE t.tgrelid='public."SecurityLockReports"'::regclass
                    AND t.tgname IN ('TR_SecurityLockReports_ImmutableIdentity',
                                     'TR_SecurityLockReports_CaptureLink',
                                     'TR_SecurityLockReports_BanProof')),
                (SELECT count(*) FROM pg_catalog.pg_proc p
                  WHERE p.oid IN (
                      pg_catalog.to_regprocedure('public.guard_security_lock_report_identity()'),
                      pg_catalog.to_regprocedure('public.capture_security_lock_report_link()'),
                      pg_catalog.to_regprocedure('public.guard_security_lock_report_ban()'))),
                (SELECT count(*) FROM pg_catalog.pg_constraint c
                  WHERE c.conrelid='public."SecurityLockReports"'::regclass
                    AND c.conname IN ('CK_SecurityLockReports_LinkProof',
                                      'CK_SecurityLockReports_BanDecision',
                                      'FK_SecurityLockReports_LinkAssignment',
                                      'FK_SecurityLockReports_LinkSeat',
                                      'FK_SecurityLockReports_LinkAlias')),
                (SELECT pg_catalog.string_agg(acl.privilege_type, ',' ORDER BY acl.privilege_type)
                   FROM pg_catalog.pg_class c
                   CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
                  WHERE c.oid='public."SecurityLockReports"'::regclass
                    AND acl.grantee=(SELECT oid FROM pg_catalog.pg_roles
                                      WHERE rolname='softlicence_app')),
                (SELECT count(*) FROM pg_catalog.pg_attribute a
                   CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
                  WHERE a.attrelid='public."SecurityLockReports"'::regclass
                    AND acl.grantee=(SELECT oid FROM pg_catalog.pg_roles
                                      WHERE rolname='softlicence_app')),
                (SELECT count(*) FROM public."SecurityLockReports")
            """, check);
        await using var result = await inspect.ExecuteReaderAsync();
        Assert.True(await result.ReadAsync());
        for (var column = 0; column < 4; column++)
            Assert.Equal(0L, result.GetInt64(column));
        Assert.Equal("DELETE,INSERT,SELECT,UPDATE", result.GetString(4));
        Assert.Equal(0L, result.GetInt64(5));
        Assert.Equal(legacyOnly ? 1L : 0L, result.GetInt64(6));
    }

    /// <summary>
    /// A commercial seat/binding transfer holding the enrollment row cannot overlap a
    /// first report capture into a false historical link. The report transaction
    /// fails atomically, then an old-graph report is frozen UNLINKED after transfer.
    /// </summary>
    [Fact]
    public async Task SecurityLockProof_AssignmentTransferVsFirstInsertIsFailClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var transferDb = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        var original = await transferDb.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var oldEnrollment = await transferDb.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        var newSeatId = Guid.NewGuid();
        var newBindingId = Guid.NewGuid();
        var newInstallationId = Guid.NewGuid().ToString("D");
        var newHandoffDigest = new string('c', 64);
        var lockId = new string('a', 32);
        var baselineNonces = await transferDb.SecurityLockReportNonces.CountAsync();
        var baselineBans = await transferDb.BannedHardwareIds.CountAsync();
        await using var transfer = await transferDb.Database.BeginTransactionAsync();
        await transferDb.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."LicenseSeats"
            SELECT (jsonb_populate_record(NULL::public."LicenseSeats",
                to_jsonb(seat) || jsonb_build_object(
                    'Id', {newSeatId.ToString("D")},
                    'HardwareId', {Guid.NewGuid().ToString("D")}))).*
            FROM public."LicenseSeats" seat WHERE seat."Id" = {original.LicenseSeatId};

            INSERT INTO public."DistributionInstallationBindings"
            SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                to_jsonb(binding) || jsonb_build_object(
                    'Id', {newBindingId.ToString("D")},
                    'LicenseSeatId', {newSeatId.ToString("D")},
                    'InstallationId', {newInstallationId},
                    'GrantRef', {Guid.NewGuid().ToString("D")},
                    'GrantRefDigestSha256', {new string('d', 64)},
                    'HandoffDigestSha256', {newHandoffDigest},
                    'HardwareIdHash', {new string('e', 64)}))).*
            FROM public."DistributionInstallationBindings" binding
            WHERE binding."Id" = {scenario.Fixture.BindingId};

            UPDATE public."RuntimeEnrollments"
            SET "BindingId" = {newBindingId},
                "LicenseSeatId" = {newSeatId},
                "InstallationId" = {newInstallationId},
                "HandoffDigestSha256" = {newHandoffDigest},
                "HardwareIdHash" = {new string('e', 64)}
            WHERE "Id" = {scenario.EnrollmentId};
            """);

        await using var reportConnection = new NpgsqlConnection(scenario.AdminConnectionString);
        await reportConnection.OpenAsync();
        await using (var firstAttempt = await reportConnection.BeginTransactionAsync())
        {
            await using var insert = new NpgsqlCommand("""
                INSERT INTO public."SecurityLockReports"
                    ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                     "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                     "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                     "ReportCount","State","LastVerdict")
                SELECT pg_catalog.gen_random_uuid(),e."ProductId",e."Id",e."BindingId",
                       e."InstallationId",@hardware,e."ReleaseVersion",@lockId,
                       'NATIVE_DLL_REPLACED',4,'REVIEW','REVIEW',@evidence,
                       pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
                       pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN'
                FROM public."RuntimeEnrollments" e WHERE e."Id"=@enrollmentId
                """, reportConnection, firstAttempt);
            insert.Parameters.AddWithValue("hardware", LegacyHardwareId);
            insert.Parameters.AddWithValue("lockId", lockId);
            insert.Parameters.AddWithValue("evidence", new string('a', 64));
            insert.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            Assert.Equal("55P03", (await Assert.ThrowsAsync<PostgresException>(
                () => insert.ExecuteNonQueryAsync())).SqlState);
            await firstAttempt.RollbackAsync();
        }
        await using (var beforeCommit = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            Assert.False(await beforeCommit.SecurityLockReports.AnyAsync(row => row.LockId == lockId));
            Assert.Equal(baselineNonces, await beforeCommit.SecurityLockReportNonces.CountAsync());
            Assert.Equal(baselineBans, await beforeCommit.BannedHardwareIds.CountAsync());
        }
        await transfer.CommitAsync();

        var oldGraphReportId = Guid.NewGuid();
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO public."SecurityLockReports"
                ("Id","ProductId","EnrollmentId","BindingId","InstallationId","HardwareId",
                 "AppVersion","LockId","Cause","Level","ClientMode","EffectiveMode",
                 "EvidenceDigestSha256","FirstSeenUtc","FirstReportedUtc","LastReportedUtc",
                 "ReportCount","State","LastVerdict")
            VALUES (@id,@productId,@enrollmentId,@bindingId,@installationId,@hardware,
                    @version,@lockId,'NATIVE_DLL_REPLACED',4,'REVIEW','REVIEW',@evidence,
                    pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
                    pg_catalog.clock_timestamp(),1,'OPEN','MAINTAIN')
            """, reportConnection))
        {
            insert.Parameters.AddWithValue("id", oldGraphReportId);
            insert.Parameters.AddWithValue("productId", scenario.Fixture.ProductId);
            insert.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            insert.Parameters.AddWithValue("bindingId", oldEnrollment.BindingId);
            insert.Parameters.AddWithValue("installationId", oldEnrollment.InstallationId);
            insert.Parameters.AddWithValue("hardware", LegacyHardwareId);
            insert.Parameters.AddWithValue("version", scenario.Fixture.Version);
            insert.Parameters.AddWithValue("lockId", lockId);
            insert.Parameters.AddWithValue("evidence", new string('a', 64));
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        }
        await using (var after = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var history = await after.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(row => row.EnrollmentId == scenario.EnrollmentId).OrderBy(row => row.Revision).ToListAsync();
            Assert.Equal(2, history.Count);
            Assert.Equal("ENDED", history[0].State);
            Assert.Equal("ACTIVE", history[1].State);
            Assert.Equal(newSeatId, history[1].LicenseSeatId);
            var report = await after.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == oldGraphReportId);
            Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, report.LinkStatus);
            Assert.Equal("enrollment_mismatch", report.LinkReasonCode);
            Assert.Null(report.LinkAssignmentId);
            Assert.Equal(SecurityLockReportStates.Open, report.State);
            Assert.Equal(SecurityLockVerdicts.Maintain, report.LastVerdict);
            Assert.Equal(baselineNonces, await after.SecurityLockReportNonces.CountAsync());
            Assert.Equal(baselineBans, await after.BannedHardwareIds.CountAsync());
        }
        var adminDecision = await new SecurityLockAdminService(scenario.Factory).DecideAsync(
            oldGraphReportId, SecurityLockAdminDecisions.Ban, "reviewed", "admin",
            scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.HardwareUnlinked, adminDecision.Outcome);
    }

    /// <summary>
    /// A fault after the first report flush rolls back its database-captured proof, report,
    /// nonce and any ban as one authority transaction.
    /// </summary>
    [Fact]
    public async Task SecurityLockProof_FirstReportFlushRollsBackWithFinalNonceFailure()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using (var inject = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await inject.OpenAsync();
            await using var fault = new NpgsqlCommand("""
                CREATE FUNCTION public.tkt1312_fail_lock_nonce() RETURNS trigger
                LANGUAGE plpgsql AS $fail$
                BEGIN RAISE EXCEPTION 'injected nonce failure' USING ERRCODE='23514'; END;
                $fail$;
                CREATE TRIGGER "ZZ_TKT1312_FailLockNonce" BEFORE INSERT
                ON public."SecurityLockReportNonces" FOR EACH ROW
                EXECUTE FUNCTION public.tkt1312_fail_lock_nonce();
                """, inject);
            await fault.ExecuteNonQueryAsync();
        }
        try
        {
            using var ackKey = RSA.Create(2048);
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
                }).Build();
            using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
            var runtime = new RuntimeEnrollmentService(
                scenario.Factory,
                new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
                new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
                crypto, Options.Create(scenario.Options),
                new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
            var request = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
                "NATIVE_DLL_REPLACED", 4, "REVIEW", 'f');
            var digest = Sha256("first-flush-rollback-" + Guid.NewGuid().ToString("D"));
            var failure = await Assert.ThrowsAnyAsync<Exception>(() =>
                runtime.ProcessSecurityLockReportAsync(
                    scenario.EnrollmentId, digest, request,
                    LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
                        request.ReportId!, digest, scenario.Options), IPAddress.Loopback));
            Assert.Contains("injected nonce failure", failure.ToString(), StringComparison.Ordinal);
            await using var after = await scenario.Factory.CreateDbContextAsync();
            Assert.False(await after.SecurityLockReports.AnyAsync(row => row.LockId == request.LockId));
            Assert.False(await after.SecurityLockReportNonces.AnyAsync(row =>
                row.EnrollmentId == scenario.EnrollmentId));
            Assert.False(await after.BannedHardwareIds.AnyAsync(row =>
                row.HardwareId == LegacyHardwareId && row.IsActive));
        }
        finally
        {
            await using var remove = new NpgsqlConnection(scenario.AdminConnectionString);
            await remove.OpenAsync();
            await using var cleanup = new NpgsqlCommand("""
                DROP TRIGGER "ZZ_TKT1312_FailLockNonce" ON public."SecurityLockReportNonces";
                DROP FUNCTION public.tkt1312_fail_lock_nonce();
                """, remove);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// Proves both client report time and proof time are decided with PostgreSQL time after the existing report row
    /// wait. The rejected attempt cannot consume quota, add a nonce, update the report, or rewrite enrollment epochs.
    /// </summary>
    /// <param name="expireProof">Whether the proof clock, rather than the report clock, crosses its boundary.</param>
    /// <param name="expectedError">Stable public error after the post-wait time decision.</param>
    /// <param name="expectedStatus">Stable HTTP status after the post-wait time decision.</param>
    [Theory]
    [InlineData(false, "sent_at_outside_window", StatusCodes.Status400BadRequest)]
    [InlineData(true, "authentication_failed", StatusCodes.Status401Unauthorized)]
    public async Task SecurityLockReport_ReportRowWaitUsesFreshDatabaseTime(
        bool expireProof,
        string expectedError,
        int expectedStatus)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        scenario.Options.LockTimeoutMilliseconds = 5000;
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var applicationName = "tkt001312-d2w2-time-" + Guid.NewGuid().ToString("N");
        var taggedConnection = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = applicationName,
            Pooling = false
        }.ConnectionString;
        var taggedFactory = new TestDbFactory(taggedConnection);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            taggedFactory,
            new RuntimeEnrollmentAuthorityService(taggedFactory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(taggedFactory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(taggedFactory, configuration, TimeProvider.System));

        var initial = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", expireProof ? '1' : '2');
        var initialDigest = Sha256("d2w2-time-initial-" + Guid.NewGuid().ToString("D"));
        _ = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, initialDigest, initial,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
                initial.ReportId!, initialDigest, scenario.Options), IPAddress.Loopback);

        Guid reportRowId;
        RuntimeEnrollment beforeEnrollment;
        int beforeNonces;
        int beforeQuotas;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var row = await before.SecurityLockReports.AsNoTracking()
                .SingleAsync(candidate => candidate.LockId == initial.LockId);
            reportRowId = row.Id;
            beforeEnrollment = await before.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            beforeNonces = await before.SecurityLockReportNonces.CountAsync();
            beforeQuotas = await before.RuntimeEnrollmentQuotas.CountAsync();
        }

        await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync();
        await using var held = await blocker.BeginTransactionAsync();
        await using (var lockRow = new NpgsqlCommand(
            "SELECT \"Id\" FROM public.\"SecurityLockReports\" WHERE \"Id\"=@id FOR UPDATE", blocker, held))
        {
            lockRow.Parameters.AddWithValue("id", reportRowId);
            Assert.Equal(reportRowId, (Guid)(await lockRow.ExecuteScalarAsync())!);
        }

        var authorityNow = await ReadSecurityLockDatabaseNowAsync(scenario.AdminConnectionString);
        var expiryBoundary = authorityNow.AddSeconds(3);
        var repeated = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", expireProof ? '1' : '2');
        repeated.FirstSeenUtc = initial.FirstSeenUtc;
        repeated.SentAtUtc = SecurityLockReportValidator.FormatUtc(expireProof
            ? authorityNow
            : expiryBoundary - SecurityLockReportValidator.MaximumClockDistance);
        var repeatedDigest = Sha256("d2w2-time-repeated-" + Guid.NewGuid().ToString("D"));
        var proofTime = expireProof
            ? expiryBoundary.AddSeconds(-scenario.Options.ProofClockSkewSeconds)
            : authorityNow;
        var repeatedProof = LockProofAt(
            scenario.EnrollmentKey, scenario.EnrollmentId, repeated.ReportId!, repeatedDigest,
            scenario.Options, proofTime);
        Task<RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>>? pending = null;
        RuntimeEnrollmentException? rejection = null;
        var blockerCommitted = false;
        try
        {
            pending = runtime.ProcessSecurityLockReportAsync(
                scenario.EnrollmentId, repeatedDigest, repeated, repeatedProof, IPAddress.Loopback);
            await WaitForApplicationBlockedByAsync(
                scenario.AdminConnectionString, applicationName, blocker.ProcessID);
            var observed = await ReadSecurityLockDatabaseNowAsync(scenario.AdminConnectionString);
            Assert.True(observed < expiryBoundary,
                $"The report reached its row wait after the intended expiry boundary ({observed:O}).");
            await Task.Delay(expiryBoundary - observed + TimeSpan.FromMilliseconds(250));
            Assert.False(pending.IsCompleted);
            await held.CommitAsync();
            blockerCommitted = true;
            rejection = await Assert.ThrowsAsync<RuntimeEnrollmentException>(
                () => pending.WaitAsync(TimeSpan.FromSeconds(10)));
        }
        finally
        {
            if (!blockerCommitted && held.Connection is not null)
                await held.RollbackAsync();
            if (pending is { IsCompleted: false })
            {
                try
                {
                    _ = await pending.WaitAsync(TimeSpan.FromSeconds(10));
                }
                catch (Exception)
                {
                    // The assertion below owns the stable public outcome; this drain prevents a leaked backend.
                }
            }
        }
        await blocker.CloseAsync();

        Assert.NotNull(rejection);
        Assert.Equal(expectedError, rejection.ErrorCode);
        Assert.Equal(expectedStatus, rejection.StatusCode);
        await using var after = await scenario.Factory.CreateDbContextAsync();
        var afterEnrollment = await after.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        var afterReport = await after.SecurityLockReports.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == reportRowId);
        Assert.Equal(1, afterReport.ReportCount);
        Assert.Equal(beforeNonces, await after.SecurityLockReportNonces.CountAsync());
        Assert.Equal(beforeQuotas, await after.RuntimeEnrollmentQuotas.CountAsync());
        Assert.Equal(beforeEnrollment.Epoch, afterEnrollment.Epoch);
        Assert.Equal(beforeEnrollment.SecurityEpoch, afterEnrollment.SecurityEpoch);
        Assert.Equal(beforeEnrollment.AuthorityEpoch, afterEnrollment.AuthorityEpoch);
    }

    /// <summary>
    /// A real commercial writer owns global authority, revokes the current licence and completes the deferred
    /// assignment trigger before Runtime can assess B. Runtime then records authenticated evidence as MAINTAIN
    /// without copying the commercial epoch into enrollment lineage.
    /// </summary>
    [Fact]
    public async Task SecurityLockReport_CommercialWriterBeforeBarrierProducesAtomicMaintain()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var applicationName = "tkt001312-d2w2-writer-" + Guid.NewGuid().ToString("N");
        var taggedConnection = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = applicationName,
            Pooling = false
        }.ConnectionString;
        var taggedFactory = new TestDbFactory(taggedConnection);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            taggedFactory,
            new RuntimeEnrollmentAuthorityService(taggedFactory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(taggedFactory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(taggedFactory, configuration, TimeProvider.System));
        RuntimeEnrollment beforeEnrollment;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
            beforeEnrollment = await before.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);

        var writerConnectionString = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Pooling = false
        }.ConnectionString;
        await using var writer = new NpgsqlConnection(writerConnectionString);
        await writer.OpenAsync();
        await using var writerTransaction = await writer.BeginTransactionAsync();
        await using (var revoke = new NpgsqlCommand("""
            UPDATE public."Licenses" AS license
            SET "IsActive" = FALSE, "RevokedAt" = pg_catalog.clock_timestamp()
            FROM public."EnrollmentLicenseAssignments" AS assignment
            WHERE assignment."EnrollmentId" = @enrollmentId
              AND assignment."State" = 'ACTIVE'
              AND license."Id" = assignment."LicenseId"
            """, writer, writerTransaction))
        {
            revoke.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            Assert.Equal(1, await revoke.ExecuteNonQueryAsync());
        }

        var request = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", '3');
        var digest = Sha256("d2w2-commercial-writer-" + Guid.NewGuid().ToString("D"));
        var pending = runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, request,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
                request.ReportId!, digest, scenario.Options), IPAddress.Loopback);
        var writerCommitted = false;
        try
        {
            await WaitForApplicationBlockedByAsync(
                scenario.AdminConnectionString, applicationName, writer.ProcessID);
            Assert.False(pending.IsCompleted);
            await using (var invisible = await scenario.Factory.CreateDbContextAsync())
                Assert.False(await invisible.SecurityLockReports.AnyAsync(row => row.LockId == request.LockId));
            await writerTransaction.CommitAsync();
            writerCommitted = true;
        }
        finally
        {
            if (!writerCommitted && writerTransaction.Connection is not null)
                await writerTransaction.RollbackAsync();
            if (!pending.IsCompleted)
            {
                try
                {
                    _ = await pending.WaitAsync(TimeSpan.FromSeconds(10));
                }
                catch (Exception)
                {
                    // The product assertion below owns the stable outcome; this drain prevents a leaked backend.
                }
            }
        }

        var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        await writer.CloseAsync();
        Assert.Equal(SecurityLockVerdicts.Maintain, result.Response.Verdict);
        AssertVerdictSignature(result.Response, ackKey);
        await using (var after = await scenario.Factory.CreateDbContextAsync())
        {
            var afterEnrollment = await after.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            var report = await after.SecurityLockReports.AsNoTracking()
                .SingleAsync(candidate => candidate.LockId == request.LockId);
            Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, report.LinkStatus);
            Assert.Equal(SecurityLockReportStates.Open, report.State);
            Assert.False(await after.EnrollmentLicenseAssignments.AnyAsync(row =>
                row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE"));
            Assert.Equal(beforeEnrollment.Epoch, afterEnrollment.Epoch);
            Assert.Equal(beforeEnrollment.SecurityEpoch, afterEnrollment.SecurityEpoch);
            Assert.Equal(beforeEnrollment.AuthorityEpoch, afterEnrollment.AuthorityEpoch);
            Assert.False(await after.BannedHardwareIds.AnyAsync(row =>
                row.HardwareId == LegacyHardwareId && row.IsActive));
        }
    }

    /// <summary>
    /// A commercial-only global epoch bump that leaves B eligible cannot rewrite historical enrollment lineage.
    /// The new verdict and its exact replay remain valid while the singleton retains the commercial audit bump.
    /// </summary>
    [Fact]
    public async Task SecurityLockReport_CommercialEpochBumpKeepsEnrollmentLineage()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        RuntimeEnrollment beforeEnrollment;
        long beforeGlobalEpoch;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            beforeEnrollment = await before.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            beforeGlobalEpoch = await before.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(row => row.Id == 1).Select(row => row.Epoch).SingleAsync();
        }
        await using (var commercialBump = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var assignment = await commercialBump.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var license = await commercialBump.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.MaxSeats += 1;
            await commercialBump.SaveChangesAsync();
        }
        long bumpedGlobalEpoch;
        await using (var bumped = await scenario.Factory.CreateDbContextAsync())
            bumpedGlobalEpoch = await bumped.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(row => row.Id == 1).Select(row => row.Epoch).SingleAsync();
        Assert.True(bumpedGlobalEpoch > beforeGlobalEpoch);

        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var request = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", '4');
        var digest = Sha256("d2w2-commercial-epoch-" + Guid.NewGuid().ToString("D"));
        var jti = Guid.NewGuid();
        var proof = LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
            request.ReportId!, digest, scenario.Options, jti);
        var accepted = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var replay = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, accepted.Response.Verdict);
        Assert.True(replay.Idempotent);
        Assert.Equal(accepted.ExactResponseBody, replay.ExactResponseBody);

        await using var after = await scenario.Factory.CreateDbContextAsync();
        var afterEnrollment = await after.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        var afterGlobalEpoch = await after.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(row => row.Id == 1).Select(row => row.Epoch).SingleAsync();
        Assert.Equal(beforeEnrollment.Epoch, afterEnrollment.Epoch);
        Assert.Equal(beforeEnrollment.SecurityEpoch, afterEnrollment.SecurityEpoch);
        Assert.Equal(beforeEnrollment.AuthorityEpoch, afterEnrollment.AuthorityEpoch);
        Assert.Equal(bumpedGlobalEpoch, afterGlobalEpoch);
        Assert.Single(await after.SecurityLockReportNonces.Where(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.Jti == jti.ToString("D")).ToListAsync());
    }

    /// <summary>
    /// Admin RELEASE needs only the report row. It can commit while Runtime waits on global authority; Runtime then
    /// drains and signs RELEASE without a global/report lock cycle.
    /// </summary>
    [Fact]
    public async Task SecurityLockRuntimeAndAdminRelease_DoNotDeadlock()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var ackKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var isolatedConnectionString = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = "tkt001312-d2w2-release-" + Guid.NewGuid().ToString("N"),
            Pooling = false
        }.ConnectionString;
        var isolatedFactory = new TestDbFactory(isolatedConnectionString);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            isolatedFactory,
            new RuntimeEnrollmentAuthorityService(isolatedFactory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(isolatedFactory, Options.Create(scenario.Options)),
            crypto, Options.Create(scenario.Options),
            new CanaryAckService(isolatedFactory, configuration, TimeProvider.System));
        var initial = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", '5');
        var initialDigest = Sha256("d2w2-release-initial-" + Guid.NewGuid().ToString("D"));
        _ = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, initialDigest, initial,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
                initial.ReportId!, initialDigest, scenario.Options), IPAddress.Loopback);
        Guid reportId;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
            reportId = await read.SecurityLockReports.AsNoTracking()
                .Where(row => row.LockId == initial.LockId).Select(row => row.Id).SingleAsync();

        var blockerConnectionString = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Pooling = false
        }.ConnectionString;
        await using var blocker = new NpgsqlConnection(blockerConnectionString);
        await blocker.OpenAsync();
        await using var held = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)", blocker, held))
            await hold.ExecuteNonQueryAsync();

        var repeated = LockRequest(LegacyHardwareId, scenario.Fixture.Version,
            "NATIVE_DLL_REPLACED", 4, "REVIEW", '5');
        repeated.FirstSeenUtc = initial.FirstSeenUtc;
        var repeatedDigest = Sha256("d2w2-release-repeated-" + Guid.NewGuid().ToString("D"));
        var runtimeTask = runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, repeatedDigest, repeated,
            LockProof(scenario.EnrollmentKey, scenario.EnrollmentId,
                repeated.ReportId!, repeatedDigest, scenario.Options), IPAddress.Loopback);
        var blockerCommitted = false;
        try
        {
            await WaitForGlobalAuthorityWaitersBlockedByAsync(
                scenario.AdminConnectionString, blocker.ProcessID, 1);
            var admin = new SecurityLockAdminService(isolatedFactory);
            var released = await admin.DecideAsync(
                reportId, SecurityLockAdminDecisions.Release, "d2w2-release", "admin",
                scenario.Fixture.ProductId).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
            Assert.False(runtimeTask.IsCompleted);
            await held.CommitAsync();
            blockerCommitted = true;
        }
        finally
        {
            if (!blockerCommitted && held.Connection is not null)
                await held.RollbackAsync();
            if (!runtimeTask.IsCompleted)
            {
                try
                {
                    _ = await runtimeTask.WaitAsync(TimeSpan.FromSeconds(10));
                }
                catch (Exception)
                {
                    // The product assertion below owns the stable outcome; this drain prevents a leaked backend.
                }
            }
        }

        var result = await runtimeTask.WaitAsync(TimeSpan.FromSeconds(10));
        await blocker.CloseAsync();
        Assert.Equal(SecurityLockVerdicts.Release, result.Response.Verdict);
        await using (var after = await scenario.Factory.CreateDbContextAsync())
        {
            var row = await after.SecurityLockReports.AsNoTracking().SingleAsync(candidate => candidate.Id == reportId);
            Assert.Equal(SecurityLockAdminDecisions.Release, row.AdminDecision);
            Assert.Equal(SecurityLockReportStates.Released, row.State);
            Assert.False(await after.BannedHardwareIds.AnyAsync(candidate =>
                candidate.HardwareId == LegacyHardwareId && candidate.IsActive));
        }
    }

    private static SecurityLockReportRequest LockRequest(
        string hardwareId, string version, string cause, int level, string mode, char lockChar) => new()
    {
        Schema = SecurityLockReportValidator.RequestSchema,
        ReportId = Guid.NewGuid().ToString("D"),
        SentAtUtc = SecurityLockReportValidator.FormatUtc(DateTimeOffset.UtcNow),
        HardwareId = hardwareId,
        AppVersion = version,
        LockId = new string(lockChar, 32),
        Cause = cause,
        Level = level,
        Mode = mode,
        EvidenceDigestSha256 = Sha256("evidence-" + cause),
        FirstSeenUtc = SecurityLockReportValidator.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(-1))
    };

    private static RuntimeProofHeaders LockProof(
        RSA rsa, Guid enrollmentId, string reportId, string digest, RuntimeEnrollmentOptions options, Guid? jti = null)
        => LockProofAt(rsa, enrollmentId, reportId, digest, options, DateTimeOffset.UtcNow, jti);

    /// <summary>Creates a lock-report proof at one exact timestamp for post-wait clock regressions.</summary>
    private static RuntimeProofHeaders LockProofAt(
        RSA rsa,
        Guid enrollmentId,
        string reportId,
        string digest,
        RuntimeEnrollmentOptions options,
        DateTimeOffset timestamp,
        Guid? jti = null)
    {
        var canonicalTimestamp = FormatUtc(timestamp);
        var canonicalJti = (jti ?? Guid.NewGuid()).ToString("D");
        var payload = RuntimeEnrollmentService.BuildSecurityLockReportProofPayload(
            enrollmentId, 1, options.CanaryAudience, canonicalTimestamp, canonicalJti, reportId, digest);
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return new RuntimeProofHeaders(canonicalTimestamp, canonicalJti, Base64Url(signature));
    }

    /// <summary>Reads PostgreSQL provider time from the exact isolated database.</summary>
    private static async Task<DateTimeOffset> ReadSecurityLockDatabaseNowAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT pg_catalog.clock_timestamp()", connection);
        var value = await command.ExecuteScalarAsync();
        return value is DateTime dateTime
            ? new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc))
            : (DateTimeOffset)value!;
    }

    /// <summary>Waits until one tagged Runtime backend is blocked by the expected PostgreSQL backend.</summary>
    private static async Task WaitForApplicationBlockedByAsync(
        string connectionString,
        string applicationName,
        int blockingProcessId)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 100; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity AS activity
                    WHERE activity.datname = pg_catalog.current_database()
                      AND activity.application_name = @applicationName
                      AND activity.wait_event_type = 'Lock'
                      AND @blocker = ANY(pg_catalog.pg_blocking_pids(activity.pid)))
                """, observer);
            command.Parameters.AddWithValue("applicationName", applicationName);
            command.Parameters.AddWithValue("blocker", blockingProcessId);
            if ((bool)(await command.ExecuteScalarAsync())!)
                return;
            await Task.Delay(25);
        }

        throw new TimeoutException("The tagged Runtime backend did not enter the expected PostgreSQL lock wait.");
    }

    /// <summary>
    /// Waits until the requested number of global authority requests are blocked by one known
    /// backend. The key predicate and <c>pg_blocking_pids</c> jointly prove the intended lock wait.
    /// </summary>
    /// <param name="connectionString">Administrator connection used only for lock observation.</param>
    /// <param name="blockingProcessId">Backend process holding the global authority key.</param>
    /// <param name="minimumWaiters">Minimum matching blocked backends.</param>
    /// <exception cref="TimeoutException">The bounded wait did not observe the expected interleaving.</exception>
    private static async Task WaitForGlobalAuthorityWaitersBlockedByAsync(
        string connectionString,
        int blockingProcessId,
        int minimumWaiters)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 200; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT count(*)
                FROM pg_catalog.pg_locks AS waiting
                WHERE waiting.locktype = 'advisory'
                  AND waiting.database = (
                      SELECT oid FROM pg_catalog.pg_database
                      WHERE datname = pg_catalog.current_database())
                  AND waiting.classid = 999831::oid
                  AND waiting.objid = 1::oid
                  AND waiting.objsubid = 2
                  AND NOT waiting.granted
                  AND @blocker = ANY(pg_catalog.pg_blocking_pids(waiting.pid));
                """, observer);
            command.Parameters.AddWithValue("blocker", blockingProcessId);
            if (Convert.ToInt32(await command.ExecuteScalarAsync()) >= minimumWaiters)
                return;
            await Task.Delay(50);
        }

        throw new TimeoutException(
            $"Expected at least {minimumWaiters} global authority waiter(s) blocked by the known backend.");
    }

    private static void AssertVerdictSignature(SecurityLockVerdictResponse verdict, RSA ackKey)
    {
        var padded = verdict.Signature.Replace('-', '+').Replace('_', '/');
        var signature = Convert.FromBase64String(padded + new string('=', (4 - padded.Length % 4) % 4));
        Assert.True(ackKey.VerifyData(Encoding.UTF8.GetBytes(CanaryAckService.BuildSecurityLockVerdictPayload(verdict)),
            signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
}
