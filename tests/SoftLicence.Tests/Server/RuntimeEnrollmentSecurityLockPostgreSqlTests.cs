using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>TKT-001177: end-to-end security lock reports on PostgreSQL with a real enrollment proof.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
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
    {
        var timestamp = FormatUtc(DateTimeOffset.UtcNow);
        var canonicalJti = (jti ?? Guid.NewGuid()).ToString("D");
        var payload = RuntimeEnrollmentService.BuildSecurityLockReportProofPayload(
            enrollmentId, 1, options.CanaryAudience, timestamp, canonicalJti, reportId, digest);
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return new RuntimeProofHeaders(timestamp, canonicalJti, Base64Url(signature));
    }

    private static void AssertVerdictSignature(SecurityLockVerdictResponse verdict, RSA ackKey)
    {
        var padded = verdict.Signature.Replace('-', '+').Replace('_', '/');
        var signature = Convert.FromBase64String(padded + new string('=', (4 - padded.Length % 4) % 4));
        Assert.True(ackKey.VerifyData(Encoding.UTF8.GetBytes(CanaryAckService.BuildSecurityLockVerdictPayload(verdict)),
            signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
}
