using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves paid auto-unban effects are undone before a durable quota refusal, using only isolated synthetic authority rows.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Preserves the complete paid ban/source binding/enrollment/target graph when the subsequent quota refusal or its writer fails.</summary>
    /// <param name="mode">Normal refusal, SQL insertion failure or client cancellation after the business decision.</param>
    /// <remarks>The seed mirrors the established paid-auto-unban regression without using its default web content root. Every business table is fingerprinted before/after; history is checked independently. Only this task's artifact-root test host and synthetic PostgreSQL are used.</remarks>
    [Theory]
    [InlineData("none")]
    [InlineData("insert")]
    [InlineData("cancel-after")]
    public async Task Tkt976_Legacy_PaidAutoUnban_RefusalRestoresWholeAuthorityGraph(string mode)
    {
        // Each synthetic encryption key belongs to this scenario, never to the shared registry.
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (isolated.Admin, isolated.App);
        const string failure = PaidActivationFailure.SeatLimit;
        var productId = Guid.NewGuid();
        var targetLicenseId = Guid.NewGuid();
        var conflictingLicenseId = Guid.NewGuid();
        var conflictingSeatId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var enrollmentId = Guid.NewGuid();
        var installationId = Guid.NewGuid().ToString("D");
        var eligibleBanId = Guid.NewGuid();
        var hardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        var appName = "Paid activation " + Guid.NewGuid().ToString("N");
        var licenseKey = "PAID-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        var now = DateTime.UtcNow;
        var adminOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connections.Admin)
            .Options;
        await using (var db = new LicenseDbContext(adminOptions))
        {
            var product = new Product
            {
                Id = productId,
                Name = appName,
                ApiSecret = Guid.NewGuid().ToString("N"),
                PrivateKeyXml = string.Empty,
                PublicKeyXml = string.Empty
            };
            var type = new LicenseType
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                Name = "Paid",
                Slug = "PAID-" + Guid.NewGuid().ToString("N"),
                IsFree = false
            };
            var target = new License
            {
                Id = targetLicenseId,
                ProductId = productId,
                LicenseTypeId = type.Id,
                LicenseKey = licenseKey,
                CustomerEmail = "paid@example.test",
                CustomerName = "Paid customer",
                IsActive = true,
                MaxSeats = 2,
                AllowedVersions = "*",
                ExpirationDate = now.AddDays(30)
            };
            var conflicting = new License
            {
                Id = conflictingLicenseId,
                ProductId = productId,
                LicenseTypeId = type.Id,
                LicenseKey = "CONFLICT-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                CustomerEmail = "conflict@example.test",
                CustomerName = "Conflicting customer",
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*",
                ExpirationDate = now.AddDays(30)
            };
            db.AddRange(product, type, target, conflicting);
            db.LicenseSeats.Add(new LicenseSeat
            {
                Id = conflictingSeatId,
                LicenseId = conflictingLicenseId,
                HardwareId = hardwareId,
                IsActive = true,
                FirstActivatedAt = now.AddDays(-2),
                LastCheckInAt = now.AddDays(-1),
                AppVersion = "2.2.999"
            });
            if (failure == PaidActivationFailure.SeatLimit)
            {
                // Two full seats retain the capacity refusal without invoking mono-seat auto-replacement.
                for (var index = 0; index < 2; index++)
                {
                    db.LicenseSeats.Add(new LicenseSeat
                    {
                        Id = Guid.NewGuid(),
                        LicenseId = targetLicenseId,
                        HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                        IsActive = true,
                        FirstActivatedAt = now.AddDays(-3),
                        LastCheckInAt = now.AddDays(-1)
                    });
                }
            }

            var grantRef = Guid.NewGuid().ToString("D");
            var handoffDigest = Sha256("paid-auto-unban-handoff-" + Guid.NewGuid().ToString("N"));
            db.DistributionInstallationBindings.Add(new DistributionInstallationBinding
            {
                Id = bindingId,
                ProductId = productId,
                LicenseId = conflictingLicenseId,
                LicenseSeatId = conflictingSeatId,
                EntitlementId = Guid.NewGuid(),
                SubjectRefDigestSha256 = Sha256("paid-auto-unban-subject"),
                GrantRef = grantRef,
                GrantRefDigestSha256 = Sha256(grantRef),
                HandoffDigestSha256 = handoffDigest,
                InstallationId = installationId,
                HardwareIdHash = Sha256(hardwareId),
                Version = "2.2.999",
                InstallerFilename = "TiaConnect-Setup_v2.2.999.msi",
                InstallerSha256 = new string('f', 64),
                ExecutableSha256 = new string('a', 64),
                NativeDllSha256 = new string('b', 64),
                CoreSha256 = new string('c', 64),
                ApprovedBinariesSource = "release",
                State = "active",
                BoundAtUtc = now.AddDays(-1)
            });
            var encryptionKeyId = "tkt976-paid-" + Guid.NewGuid().ToString("N");
            db.RuntimeEnrollmentKeyRegistries.Add(new RuntimeEnrollmentKeyRegistry
            {
                Purpose = "encryption",
                KeyId = encryptionKeyId,
                MaterialDigestSha256 = Sha256("paid-auto-unban-key-" + productId.ToString("D")),
                State = "active",
                Epoch = 1,
                CreatedAtUtc = now.AddDays(-2)
            });
            var authorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(row => row.Id == 1)
                .Select(row => row.Epoch)
                .SingleAsync();
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = "website-step1",
                BindingId = bindingId,
                ProductId = productId,
                LicenseId = conflictingLicenseId,
                LicenseSeatId = conflictingSeatId,
                InstallationId = installationId,
                HardwareIdHash = Sha256(hardwareId),
                ReleaseVersion = "2.2.999",
                HandoffDigestSha256 = handoffDigest,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = encryptionKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "thumb-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = encryptionKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 1,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1),
                CreatedAtUtc = now.AddDays(-1),
                ActivatedAtUtc = now.AddDays(-1),
                ChallengeConsumedAtUtc = now.AddDays(-1)
            });
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                Id = eligibleBanId,
                HardwareId = hardwareId,
                ProductId = productId,
                Reason = "Auto-ban: outdated version",
                BanCategory = BannedHardwareId.Categories.OutdatedVersion,
                IsActive = true,
                BannedAt = now.AddMinutes(-5)
            });
            await db.SaveChangesAsync();
        }

        var clean = new TestDbFactory(connections.App);
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        using var host = Tkt976_CreateLegacyHost(new Tkt976FaultFactory(connections.App, fault));
        _ = host.Services;
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        using (var scope = host.Services.CreateScope())
        {
            var controller = Tkt976_CreateDirectLegacyController(scope.ServiceProvider);
            controller.HttpContext.RequestAborted = requestCancellation.Token;
            fault.Armed = true;
            var response = Assert.IsAssignableFrom<ObjectResult>(await controller.Activate(new ActivationController.ActivationRequest
            {
                LicenseKey = licenseKey, HardwareId = hardwareId, AppName = appName,
                AppVersion = "2.2.999", CustomerEmail = "paid@example.test"
            }));
            Assert.Equal(mode == "insert" ? 500 : 400, response.StatusCode);
            if (mode == "cancel-after") Assert.True(requestCancellation.IsCancellationRequested);
        }
        Assert.True(fault.ObservedPendingPaidUnban);
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await clean.CreateDbContextAsync();
        var rows = await observed.LicenseHistories.Where(row => row.LicenseId == targetLicenseId
            && row.Action == "ACTIVATION_DECISION_V1").ToListAsync();
        Assert.Equal(mode == "insert" ? 0 : 1, rows.Count);
        if (rows.Count == 1)
        {
            var decision = System.Text.Json.JsonSerializer.Deserialize<LicenseDecisionHistory>(rows[0].Details!,
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!;
            Assert.Equal("SEAT_LIMIT", decision.Code);
            Assert.Equal(2, decision.Snapshot.ActiveSeats);
            Assert.Equal(2, decision.Snapshot.SeatLimit);
        }
        Assert.True((await observed.BannedHardwareIds.SingleAsync(row => row.Id == eligibleBanId)).IsActive);
        Assert.True((await observed.LicenseSeats.SingleAsync(row => row.Id == conflictingSeatId)).IsActive);
        Assert.Equal("active", (await observed.DistributionInstallationBindings.SingleAsync(row => row.Id == bindingId)).State);
        Assert.Equal("ACTIVE", (await observed.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).State);
    }
}
