using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
    public async Task DistributionFinalize_V4CandidatesOnFreshHardware_CreatesInitialBinding()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory, includeSeat: false);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = new DateTimeOffset(2026, 9, 20, 4, 42, 40, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var subjectRef = Convert.ToBase64String(SHA256.HashData("fresh-hardware-target"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var historicalLicenseId = Guid.NewGuid();
        var historicalSeatId = Guid.NewGuid();
        var historicalBindingId = Guid.NewGuid();
        await using (var seedHistoricalAuthority = await factory.CreateDbContextAsync())
        {
            var licenseTypeId = await seedHistoricalAuthority.Licenses.AsNoTracking()
                .Where(candidate => candidate.Id == fixture.LicenseId)
                .Select(candidate => candidate.LicenseTypeId)
                .SingleAsync();
            seedHistoricalAuthority.Licenses.Add(new License
            {
                Id = historicalLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = licenseTypeId,
                LicenseKey = "HIST-" + Guid.NewGuid().ToString("N"),
                IsActive = false,
                MaxSeats = 1,
                AllowedVersions = "2.2.*",
                ExpirationDate = now.AddDays(-1).UtcDateTime
            });
            seedHistoricalAuthority.LicenseSeats.Add(new LicenseSeat
            {
                Id = historicalSeatId,
                LicenseId = historicalLicenseId,
                HardwareId = "UNRELATEDV4HWID1",
                IsActive = false,
                UnlinkedAt = now.AddDays(-1).UtcDateTime
            });
            var historicalGrantRef = Guid.NewGuid().ToString("D");
            seedHistoricalAuthority.DistributionInstallationBindings.Add(new DistributionInstallationBinding
            {
                Id = historicalBindingId,
                ProductId = fixture.ProductId,
                LicenseId = historicalLicenseId,
                LicenseSeatId = historicalSeatId,
                EntitlementId = Guid.NewGuid(),
                SubjectRefDigestSha256 = Sha256(subjectRef),
                GrantRef = historicalGrantRef,
                GrantRefDigestSha256 = Sha256(historicalGrantRef),
                HandoffDigestSha256 = Sha256("unrelated-historical-handoff"),
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareIdHash = Sha256("UNRELATEDV4HWID1"),
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
                InstallerSha256 = Sha256("unrelated-historical-installer"),
                ExecutableSha256 = new string('a', 64),
                NativeDllSha256 = new string('b', 64),
                CoreSha256 = new string('c', 64),
                ApprovedBinariesSource = "release",
                State = "invalidated",
                BoundAtUtc = now.AddDays(-2).UtcDateTime,
                InvalidatedAtUtc = now.AddDays(-1).UtcDateTime,
                InvalidationReason = "installation_superseded"
            });
            await seedHistoricalAuthority.SaveChangesAsync();
        }
        var entitlement = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("fresh-hardware-target-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = subjectRef
            });
        const string freshHardwareId = "FRESHV4HWID0001";
        var request = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV4Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("fresh-hardware-target-handoff"),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-5)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-4)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = freshHardwareId,
            AllowSameAuthorityRecovery = true,
            LicenseReplacementCandidates = new DistributionLicenseReplacementCandidateSet
            {
                Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
                Sources =
                [
                    new DistributionLicenseReplacementProof
                    {
                        Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                        SourceBindingId = historicalBindingId.ToString("D"),
                        SourceLicenseId = historicalLicenseId.ToString("D"),
                        SourceSubjectRef = subjectRef
                    }
                ]
            },
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
                InstallerSha256 = Sha256("fresh-hardware-target-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        await using (var before = await factory.CreateDbContextAsync())
        {
            Assert.Empty(await before.DistributionInstallationBindings
                .Where(candidate => candidate.ProductId == fixture.ProductId
                    && candidate.HardwareIdHash == Sha256(freshHardwareId))
                .ToListAsync());
        }

        var result = await service.FinalizeAsync(
            "website-step1", Sha256("fresh-hardware-target-finalize"), request);

        Assert.False(result.Idempotent);
        Assert.Equal("active", result.Response.State);
        Assert.Equal(Sha256(freshHardwareId), result.Response.HardwareIdHash);
        await using var after = await factory.CreateDbContextAsync();
        var binding = await after.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.ProductId == fixture.ProductId
            && candidate.HardwareIdHash == Sha256(freshHardwareId));
        Assert.Equal(fixture.LicenseId, binding.LicenseId);
        Assert.Null(binding.SupersededBindingId);
    }

    [Fact]
    public async Task DistributionRuntimeSourceResolution_ActiveTargetLicenseBinding_ReturnsNoneForSameAuthorityRecovery()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var subjectRef = Convert.ToBase64String(SHA256.HashData("same-authority-source-resolution"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var grantRef = Guid.NewGuid().ToString("D");
        var authority = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("same-authority-source-resolution-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = subjectRef
            });
        var finalize = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("same-authority-source-resolution-handoff"),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-5)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-4)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = authority.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = fixture.HardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.3.445.exe",
                InstallerSha256 = Sha256("same-authority-source-resolution-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };
        await service.FinalizeAsync(
            "website-step1", Sha256("same-authority-source-resolution-finalize"), finalize);

        var resolution = await service.ResolveRuntimeSourceAsync(
            "website-step1",
            new DistributionRuntimeSourceResolutionRequest
            {
                Schema = DistributionInstallationBindingService.RuntimeSourceResolutionSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                TargetLicenseId = fixture.LicenseId.ToString("D"),
                HardwareId = fixture.HardwareId
            });

        Assert.Equal("none", resolution.Outcome);
        Assert.Null(resolution.SourceLicenseId);
        Assert.Null(resolution.SourceKind);
    }

    [Fact]
    public async Task DistributionFinalize_SameLicenseSeatRelinkAcrossHardware_CreatesRuntimeSuccessor()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var subjectRef = Convert.ToBase64String(SHA256.HashData("same-license-seat-transfer"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        const string targetHardwareId = "F1A2B3C4D5E6A7B8";

        async Task<(string GrantRef, string EntitlementRef)> IssueAsync(
            string label,
            string? requestedSubjectRef = null,
            string requestedClientId = "website-step1")
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var issued = await service.IssueEntitlementAsync(
                requestedClientId,
                Sha256(label + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef),
                    SubjectRef = requestedSubjectRef ?? subjectRef
                });
            return (grantRef, issued.Response.EntitlementRef);
        }

        DistributionInstallationFinalizeRequest FinalizeRequest(
            string label,
            (string GrantRef, string EntitlementRef) authority,
            string hardwareId,
            DateTimeOffset issuedAt) => new()
            {
                Schema = DistributionInstallationBindingService.FinalizeV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                GrantRef = authority.GrantRef,
                HandoffDigestSha256 = Sha256(label + "-handoff-" + authority.GrantRef),
                HandoffIssuedAtUtc = FormatUtc(issuedAt),
                HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
                DownloadCompletedAtUtc = FormatUtc(issuedAt.AddMinutes(1)),
                ProductId = fixture.ProductId.ToString("D"),
                EntitlementRef = authority.EntitlementRef,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareId = hardwareId,
                AllowSameAuthorityRecovery = true,
                Release = new DistributionReleaseEvidence
                {
                    Version = fixture.Version,
                    InstallerFilename = "TiaConnect-Setup_v2.3.195.exe",
                    InstallerSha256 = Sha256(label + "-installer")
                },
                Binaries =
                [
                    new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                    new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                    new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
                ]
            };

        var sourceAuthority = await IssueAsync("same-license-source");
        var sourceRequest = FinalizeRequest(
            "same-license-source", sourceAuthority, fixture.HardwareId, now.AddMinutes(-15));
        var sourceResult = await service.FinalizeAsync(
            "website-step1", Sha256("same-license-source-finalize"), sourceRequest);
        var sourceBindingId = Guid.Parse(sourceResult.Response.BindingId);
        Guid sourceSeatId;
        Guid targetSeatId;
        Guid sourceEnrollmentId;

        await using (var moveSeat = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await moveSeat.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            sourceSeatId = sourceBinding.LicenseSeatId;
            var sourceSeat = await moveSeat.LicenseSeats
                .SingleAsync(candidate => candidate.Id == sourceSeatId);
            sourceSeat.IsActive = false;
            sourceSeat.UnlinkedAt = null;

            targetSeatId = Guid.NewGuid();
            moveSeat.LicenseSeats.Add(new LicenseSeat
            {
                Id = targetSeatId,
                LicenseId = fixture.LicenseId,
                HardwareId = targetHardwareId,
                IsActive = true,
                FirstActivatedAt = now.AddMinutes(-7).UtcDateTime,
                LastCheckInAt = now.AddMinutes(-7).UtcDateTime,
                AppVersion = fixture.Version
            });

            var authorityEpoch = await moveSeat.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            sourceEnrollmentId = Guid.NewGuid();
            moveSeat.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = sourceEnrollmentId,
                ClientId = "website-step1",
                BindingId = sourceBinding.Id,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                InstallationId = sourceBinding.InstallationId,
                HardwareIdHash = sourceBinding.HardwareIdHash,
                ReleaseVersion = sourceBinding.Version,
                HandoffDigestSha256 = sourceBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "sl-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 4,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddHours(-1).UtcDateTime,
                ActivatedAtUtc = now.AddMinutes(-10).UtcDateTime
            });
            await moveSeat.SaveChangesAsync();
        }

        DistributionLicenseReplacementProof UnrelatedCandidate(string label) => new()
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
            SourceBindingId = Guid.NewGuid().ToString("D"),
            SourceLicenseId = Guid.NewGuid().ToString("D"),
            SourceSubjectRef = Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(label)))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_')
        };

        DistributionLicenseReplacementCandidateSet UnrelatedCandidates(string prefix) => new()
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
            Sources =
            [
                UnrelatedCandidate(prefix + "-one"),
                UnrelatedCandidate(prefix + "-two"),
                UnrelatedCandidate(prefix + "-three")
            ]
        };

        // Franck's policy (2026-09-21, TKT-001221): an inconsistent target-licence history no longer
        // blocks a legitimate client. The former "source seat not unlinked" and "divergent subject"
        // refusals are logged divergences now; DistributionFinalize_V4CandidatesOnReleasedTargetHistory
        // covers them. The explicit unlink is kept so the same-license transition below stays exact.
        await using (var markExplicitUnlink = await factory.CreateDbContextAsync())
        {
            var sourceSeat = await markExplicitUnlink.LicenseSeats
                .SingleAsync(candidate => candidate.Id == sourceSeatId);
            sourceSeat.UnlinkedAt = now.AddMinutes(-6).UtcDateTime;
            await markExplicitUnlink.SaveChangesAsync();
        }

        const string differentClientId = "other-authorized-client";
        var differentClientAuthority = await IssueAsync(
            "same-license-different-client", subjectRef, differentClientId);
        var differentClientRequest = FinalizeRequest(
            "same-license-different-client", differentClientAuthority, targetHardwareId, now.AddMinutes(-5));
        differentClientRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        differentClientRequest.LicenseReplacementCandidates = UnrelatedCandidates("different-client-history");
        var differentClient = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            differentClientId, Sha256("same-license-different-client-finalize"), differentClientRequest));
        Assert.Equal("binding_conflict", differentClient.ErrorCode);
        Assert.Equal("same_authority_mismatch", differentClient.ReasonCode);

        await using (var unchanged = await factory.CreateDbContextAsync())
        {
            Assert.Equal("active", (await unchanged.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId)).State);
            Assert.Equal("ACTIVE", (await unchanged.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceEnrollmentId)).State);
        }

        var targetSecurityBindingId = Guid.NewGuid();
        await using (var addTargetSecurityHistory = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await addTargetSecurityHistory.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var targetHistoryGrantRef = Guid.NewGuid().ToString("D");
            addTargetSecurityHistory.DistributionInstallationBindings.Add(new DistributionInstallationBinding
            {
                Id = targetSecurityBindingId,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = targetSeatId,
                EntitlementId = sourceBinding.EntitlementId,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                GrantRef = targetHistoryGrantRef,
                GrantRefDigestSha256 = Sha256(targetHistoryGrantRef),
                HandoffDigestSha256 = Sha256("target-security-history-handoff"),
                HandoffIssuedAtUtc = now.AddHours(-2).UtcDateTime,
                HandoffExpiresAtUtc = now.AddHours(-1).UtcDateTime,
                DownloadCompletedAtUtc = now.AddHours(-2).AddMinutes(1).UtcDateTime,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareIdHash = Sha256(targetHardwareId),
                Version = sourceBinding.Version,
                InstallerFilename = sourceBinding.InstallerFilename,
                InstallerSha256 = sourceBinding.InstallerSha256,
                ExecutableSha256 = sourceBinding.ExecutableSha256,
                NativeDllSha256 = sourceBinding.NativeDllSha256,
                CoreSha256 = sourceBinding.CoreSha256,
                ApprovedBinariesSource = sourceBinding.ApprovedBinariesSource,
                State = "invalidated",
                BoundAtUtc = now.AddHours(-2).UtcDateTime,
                InitialSecurityEpoch = 1,
                InvalidatedAtUtc = now.AddHours(-1).UtcDateTime,
                InvalidationReason = "security_lockdown"
            });
            await addTargetSecurityHistory.SaveChangesAsync();
        }

        var securityHistoryAuthority = await IssueAsync("same-license-target-security-history");
        var securityHistoryRequest = FinalizeRequest(
            "same-license-target-security-history", securityHistoryAuthority, targetHardwareId, now.AddMinutes(-5));
        securityHistoryRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        securityHistoryRequest.LicenseReplacementCandidates = UnrelatedCandidates("security-history");
        var securityHistory = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("same-license-target-security-history-finalize"), securityHistoryRequest));
        Assert.Equal("binding_conflict", securityHistory.ErrorCode);
        Assert.Equal("replacement_candidate_none", securityHistory.ReasonCode);

        await using (var markTargetHistoryBusinessTerminal = await factory.CreateDbContextAsync())
        {
            var targetHistory = await markTargetHistoryBusinessTerminal.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == targetSecurityBindingId);
            targetHistory.InvalidationReason = "installation_superseded";
            await markTargetHistoryBusinessTerminal.SaveChangesAsync();
        }

        var targetAuthority = await IssueAsync("same-license-target");
        var targetRequest = FinalizeRequest(
            "same-license-target", targetAuthority, targetHardwareId, now.AddMinutes(-5));
        targetRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        targetRequest.LicenseReplacementCandidates = UnrelatedCandidates("historical-license");

        var successor = await service.FinalizeAsync(
            "website-step1", Sha256("same-license-target-finalize"), targetRequest);

        Assert.False(successor.Idempotent);
        await using var check = await factory.CreateDbContextAsync();
        var successorBinding = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == Guid.Parse(successor.Response.BindingId));
        Assert.Equal(fixture.LicenseId, successorBinding.LicenseId);
        Assert.Equal(targetSeatId, successorBinding.LicenseSeatId);
        Assert.Equal(Sha256(targetHardwareId), successorBinding.HardwareIdHash);
        Assert.Equal(sourceBindingId, successorBinding.SupersededBindingId);
        Assert.Equal(5, successorBinding.InitialSecurityEpoch);

        var sourceBindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceBindingId);
        Assert.Equal("invalidated", sourceBindingAfter.State);
        Assert.Equal("installation_superseded", sourceBindingAfter.InvalidationReason);
        Assert.False((await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceSeatId)).IsActive);
        Assert.True((await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == targetSeatId)).IsActive);

        var sourceEnrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
        Assert.Equal("INVALIDATED", sourceEnrollmentAfter.State);
        Assert.Equal("binding_superseded", sourceEnrollmentAfter.InvalidationReason);

        var replay = await service.FinalizeAsync(
            "website-step1", Sha256("same-license-target-finalize"), targetRequest);
        Assert.True(replay.Idempotent);
        Assert.Equal(successor.Response, replay.Response);

        var successorBindingId = successorBinding.Id;
        Guid successorEnrollmentId;
        await using (var moveBack = await factory.CreateDbContextAsync())
        {
            var sourceSeat = await moveBack.LicenseSeats.SingleAsync(candidate => candidate.Id == sourceSeatId);
            var targetSeat = await moveBack.LicenseSeats.SingleAsync(candidate => candidate.Id == targetSeatId);
            sourceSeat.IsActive = true;
            sourceSeat.UnlinkedAt = null;
            sourceSeat.LastCheckInAt = now.AddMinutes(-2).UtcDateTime;
            targetSeat.IsActive = false;
            targetSeat.UnlinkedAt = now.AddMinutes(-3).UtcDateTime;

            var currentBinding = await moveBack.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == successorBindingId);
            var authorityEpoch = await moveBack.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            successorEnrollmentId = Guid.NewGuid();
            moveBack.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = successorEnrollmentId,
                ClientId = "website-step1",
                BindingId = currentBinding.Id,
                ProductId = currentBinding.ProductId,
                LicenseId = currentBinding.LicenseId,
                LicenseSeatId = currentBinding.LicenseSeatId,
                InstallationId = currentBinding.InstallationId,
                HardwareIdHash = currentBinding.HardwareIdHash,
                ReleaseVersion = currentBinding.Version,
                HandoffDigestSha256 = currentBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = currentBinding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('f', 64),
                KeyThumbprint = "sl-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('1', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 5,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddMinutes(-4).UtcDateTime,
                ActivatedAtUtc = now.AddMinutes(-3).UtcDateTime
            });
            await moveBack.SaveChangesAsync();
        }

        var returnAuthority = await IssueAsync("same-license-return");
        var returnRequest = FinalizeRequest(
            "same-license-return", returnAuthority, fixture.HardwareId, now.AddMinutes(-1));
        returnRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        returnRequest.LicenseReplacementCandidates = UnrelatedCandidates("return-historical");

        var returned = await service.FinalizeAsync(
            "website-step1", Sha256("same-license-return-finalize"), returnRequest);

        await using var returnCheck = await factory.CreateDbContextAsync();
        var returnedBinding = await returnCheck.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == Guid.Parse(returned.Response.BindingId));
        Assert.Equal(sourceSeatId, returnedBinding.LicenseSeatId);
        Assert.Equal(successorBindingId, returnedBinding.SupersededBindingId);
        Assert.Equal(6, returnedBinding.InitialSecurityEpoch);
        var successorBindingAfterReturn = await returnCheck.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == successorBindingId);
        Assert.Equal("invalidated", successorBindingAfterReturn.State);
        Assert.Equal("installation_superseded", successorBindingAfterReturn.InvalidationReason);
        var successorEnrollmentAfterReturn = await returnCheck.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == successorEnrollmentId);
        Assert.Equal("INVALIDATED", successorEnrollmentAfterReturn.State);
        Assert.Equal("binding_superseded", successorEnrollmentAfterReturn.InvalidationReason);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistributionFinalize_ActiveBindingWithExactEnrollment_ReissuesExactAuthority(
        bool sourceEnrollmentIsActive)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var subjectRef = Convert.ToBase64String(SHA256.HashData("active-binding-authority-recovery"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        async Task<(string GrantRef, string EntitlementRef)> IssueAsync(string label)
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var issued = await service.IssueEntitlementAsync(
                "website-step1",
                Sha256(label + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef),
                    SubjectRef = subjectRef
                });
            return (grantRef, issued.Response.EntitlementRef);
        }

        DistributionInstallationFinalizeRequest FinalizeRequest(
            string label,
            (string GrantRef, string EntitlementRef) authority,
            DateTimeOffset issuedAt) => new()
        {
            Schema = DistributionInstallationBindingService.FinalizeV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = authority.GrantRef,
            HandoffDigestSha256 = Sha256(label + "-handoff-" + authority.GrantRef),
            HandoffIssuedAtUtc = FormatUtc(issuedAt),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(issuedAt.AddMinutes(1)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = authority.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = fixture.HardwareId,
            AllowSameAuthorityRecovery = true,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.3.195.exe",
                InstallerSha256 = Sha256(label + "-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        DistributionLicenseReplacementProof UnrelatedCandidate(string label) => new()
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
            SourceBindingId = Guid.NewGuid().ToString("D"),
            SourceLicenseId = Guid.NewGuid().ToString("D"),
            SourceSubjectRef = Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(label)))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_')
        };

        var sourceAuthority = await IssueAsync("active-binding-source");
        var sourceRequest = FinalizeRequest(
            "active-binding-source", sourceAuthority, now.AddMinutes(-20));
        var source = await service.FinalizeAsync(
            "website-step1", Sha256("active-binding-source-finalize"), sourceRequest);
        var sourceBindingId = Guid.Parse(source.Response.BindingId);
        var sourceEnrollmentId = Guid.NewGuid();

        await using (var seed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await seed.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var authorityEpoch = await seed.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            seed.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = sourceEnrollmentId,
                ClientId = "website-step1",
                BindingId = sourceBinding.Id,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                InstallationId = sourceBinding.InstallationId,
                HardwareIdHash = sourceBinding.HardwareIdHash,
                ReleaseVersion = sourceBinding.Version,
                HandoffDigestSha256 = sourceBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "sl-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "INVALIDATED",
                Epoch = 1,
                SecurityEpoch = 2,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddHours(-2).UtcDateTime,
                ChallengeConsumedAtUtc = now.AddHours(-1).AddMinutes(-5).UtcDateTime,
                ActivatedAtUtc = now.AddHours(-1).UtcDateTime,
                InvalidatedAtUtc = now.AddMinutes(-40).UtcDateTime,
                InvalidationReason = "authority_ineligible"
            });
            seed.LicenseSeats.Add(new LicenseSeat
            {
                Id = Guid.NewGuid(),
                LicenseId = fixture.LicenseId,
                HardwareId = "C6AC7E0660A9BADD",
                IsActive = false,
                FirstActivatedAt = now.AddMinutes(-50).UtcDateTime,
                LastCheckInAt = now.AddMinutes(-45).UtcDateTime,
                UnlinkedAt = now.AddMinutes(-3).UtcDateTime,
                AppVersion = fixture.Version
            });
            await seed.SaveChangesAsync();
        }

        var targetAuthority = await IssueAsync("active-binding-target");
        var targetRequest = FinalizeRequest(
            "active-binding-target", targetAuthority, now.AddMinutes(-2));
        targetRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        targetRequest.LicenseReplacementCandidates = new DistributionLicenseReplacementCandidateSet
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
            Sources =
            [
                UnrelatedCandidate("historical-one"),
                UnrelatedCandidate("historical-two"),
                UnrelatedCandidate("historical-three")
            ]
        };

        foreach (var terminalReason in new[] { "security_lockdown", "unknown_terminal" })
        {
            await using (var mutate = await factory.CreateDbContextAsync())
            {
                var enrollment = await mutate.RuntimeEnrollments
                    .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
                enrollment.InvalidationReason = terminalReason;
                await mutate.SaveChangesAsync();
            }

            var rejected = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                "website-step1", Sha256("active-binding-target-finalize"), targetRequest));
            Assert.Equal("binding_conflict", rejected.ErrorCode);
            Assert.Equal("replacement_enrollment_security_terminal", rejected.ReasonCode);

            await using (var restore = await factory.CreateDbContextAsync())
            {
                var enrollment = await restore.RuntimeEnrollments
                    .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
                enrollment.InvalidationReason = "authority_ineligible";
                await restore.SaveChangesAsync();
            }
        }

        await using (var mutate = await factory.CreateDbContextAsync())
        {
            var enrollment = await mutate.RuntimeEnrollments
                .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
            enrollment.InvalidationReason = "binding_superseded";
            await mutate.SaveChangesAsync();
        }
        var unrelatedBusinessTerminal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1", Sha256("active-binding-target-finalize"), targetRequest));
        Assert.Equal("binding_conflict", unrelatedBusinessTerminal.ErrorCode);
        Assert.Equal("same_authority_active_enrollment_mismatch", unrelatedBusinessTerminal.ReasonCode);
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var enrollment = await restore.RuntimeEnrollments
                .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
            enrollment.State = sourceEnrollmentIsActive ? "ACTIVE" : "INVALIDATED";
            enrollment.InvalidatedAtUtc = sourceEnrollmentIsActive
                ? null
                : now.AddMinutes(-40).UtcDateTime;
            enrollment.InvalidationReason = sourceEnrollmentIsActive
                ? null
                : "authority_ineligible";
            await restore.SaveChangesAsync();
        }

        var recovered = await service.FinalizeAsync(
            "website-step1", Sha256("active-binding-target-finalize"), targetRequest);

        Assert.False(recovered.Idempotent);
        await using var check = await factory.CreateDbContextAsync();
        var sourceBindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceBindingId);
        var sourceEnrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
        var successor = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == Guid.Parse(recovered.Response.BindingId));
        Assert.Equal("invalidated", sourceBindingAfter.State);
        Assert.Equal("installation_superseded", sourceBindingAfter.InvalidationReason);
        Assert.Equal("INVALIDATED", sourceEnrollmentAfter.State);
        Assert.Equal(
            sourceEnrollmentIsActive ? "binding_superseded" : "authority_ineligible",
            sourceEnrollmentAfter.InvalidationReason);
        Assert.Equal(sourceBindingId, successor.SupersededBindingId);
        Assert.Equal(sourceBindingAfter.LicenseSeatId, successor.LicenseSeatId);
        Assert.Equal(sourceBindingAfter.HardwareIdHash, successor.HardwareIdHash);
        Assert.Equal(3, successor.InitialSecurityEpoch);

        var replay = await service.FinalizeAsync(
            "website-step1", Sha256("active-binding-target-finalize"), targetRequest);
        Assert.True(replay.Idempotent);
        Assert.Equal(recovered.Response, replay.Response);
    }

    /// <summary>
    /// Proves that a grantless legacy replacement remains closed until its binding, enrollment,
    /// entitlement, and grant ownership describe the same modern v3 source authority. The test
    /// mutates only its isolated PostgreSQL fixture and verifies the resulting conflict reasons.
    /// </summary>
    [Fact]
    public async Task DistributionFinalize_GrantlessExpiredLegacySource_ReplacesServerDerivedBinding()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);

        var sourceGrantRef = Guid.NewGuid().ToString("D");
        var sourceAuthority = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("grantless-source-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(sourceGrantRef)
            });
        var sourceRequest = CreateFinalizeRequest(
            DistributionInstallationBindingService.FinalizeSchema,
            "grantless-source",
            sourceGrantRef,
            sourceAuthority.Response.EntitlementRef,
            Guid.NewGuid().ToString("D"),
            now.AddMinutes(-20));
        var source = await service.FinalizeAsync(
            "website-step1", Sha256("grantless-source-finalize"), sourceRequest);
        var sourceBindingId = Guid.Parse(source.Response.BindingId);

        long authorityEpoch;
        await using (var authorityReader = await new TestDbFactory(connections.Admin).CreateDbContextAsync())
        {
            authorityEpoch = await authorityReader.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
        }

        Guid targetLicenseId;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await seed.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var sourceLicense = await seed.Licenses.SingleAsync(candidate => candidate.Id == fixture.LicenseId);
            sourceLicense.IsActive = false;
            sourceLicense.RevokedAt = now.AddMinutes(-15).UtcDateTime;
            sourceLicense.ExpirationDate = now.AddMinutes(-15).UtcDateTime;

            targetLicenseId = Guid.NewGuid();
            seed.Licenses.Add(new License
            {
                Id = targetLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = sourceLicense.LicenseTypeId,
                LicenseKey = "GRANTLESS-TARGET-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = sourceLicense.AllowedVersions,
                ExpirationDate = now.AddDays(30).UtcDateTime
            });
            seed.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = Guid.NewGuid(),
                ClientId = "website-step1",
                BindingId = sourceBinding.Id,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                InstallationId = sourceBinding.InstallationId,
                HardwareIdHash = sourceBinding.HardwareIdHash,
                ReleaseVersion = sourceBinding.Version,
                HandoffDigestSha256 = sourceBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = null,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "grantless-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 3,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddHours(-1).UtcDateTime,
                ActivatedAtUtc = now.AddMinutes(-30).UtcDateTime
            });

            await seed.SaveChangesAsync();
        }

        var targetSubjectRef = Convert.ToBase64String(SHA256.HashData("grantless-target-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        DistributionRuntimeSourceResolutionRequest SourceResolutionRequest() => new()
        {
            Schema = DistributionInstallationBindingService.RuntimeSourceResolutionSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            TargetLicenseId = targetLicenseId.ToString("D"),
            HardwareId = fixture.HardwareId
        };
        var inconsistentResolution = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.ResolveRuntimeSourceAsync("website-step1", SourceResolutionRequest()));
        Assert.Equal("replacement_source_authority_mismatch", inconsistentResolution.ReasonCode);
        var targetGrantRef = Guid.NewGuid().ToString("D");
        var targetAuthority = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("grantless-target-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = targetLicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(targetGrantRef),
                SubjectRef = targetSubjectRef
            });
        var targetRequest = CreateFinalizeRequest(
            DistributionInstallationBindingService.FinalizeV5Schema,
            "grantless-target",
            targetGrantRef,
            targetAuthority.Response.EntitlementRef,
            Guid.NewGuid().ToString("D"),
            now.AddMinutes(-5));
        targetRequest.AllowSameAuthorityRecovery = true;
        targetRequest.LegacyLicenseReplacement = new DistributionLegacyLicenseReplacementProof
        {
            Schema = DistributionInstallationBindingService.LegacyLicenseReplacementSchema,
            SourceLicenseId = fixture.LicenseId.ToString("D"),
            TargetLicenseId = targetLicenseId.ToString("D")
        };

        targetRequest.RequestId = Guid.NewGuid().ToString("D");
        targetRequest.LegacyLicenseReplacement.TargetLicenseId = Guid.NewGuid().ToString("D");
        var targetMismatch = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("grantless-target-license-mismatch"), targetRequest));
        Assert.Equal("binding_conflict", targetMismatch.ErrorCode);
        Assert.Equal("legacy_replacement_target_mismatch", targetMismatch.ReasonCode);

        targetRequest.RequestId = Guid.NewGuid().ToString("D");
        targetRequest.LegacyLicenseReplacement.TargetLicenseId = targetLicenseId.ToString("D");
        targetRequest.LegacyLicenseReplacement.SourceLicenseId = Guid.NewGuid().ToString("D");
        var sourceMismatch = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("grantless-source-license-mismatch"), targetRequest));
        Assert.Equal("binding_conflict", sourceMismatch.ErrorCode);
        Assert.Equal("legacy_replacement_source_mismatch", sourceMismatch.ReasonCode);

        targetRequest.RequestId = Guid.NewGuid().ToString("D");
        targetRequest.LegacyLicenseReplacement.SourceLicenseId = fixture.LicenseId.ToString("D");
        var modernOwnership = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("grantless-modern-owner"), targetRequest));
        Assert.Equal("binding_conflict", modernOwnership.ErrorCode);
        Assert.Equal("legacy_replacement_modern_authority_inconsistent", modernOwnership.ReasonCode);

        var sourceSubjectDigest = Sha256("grantless-modern-source-subject");
        await using (var modernSeed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await modernSeed.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var sourceEnrollment = await modernSeed.RuntimeEnrollments
                .SingleAsync(candidate => candidate.BindingId == sourceBindingId);
            sourceBinding.SubjectRefDigestSha256 = sourceSubjectDigest;
            sourceEnrollment.SubjectRefDigestSha256 = sourceSubjectDigest;
            modernSeed.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = sourceBinding.EntitlementId,
                ClientId = "website-step1",
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                GrantRefDigestSha256 = sourceBinding.GrantRefDigestSha256,
                SubjectRefDigestSha256 = sourceSubjectDigest,
                ContractVersion = 3,
                State = "finalized",
                IssuedAtUtc = now.AddHours(-1).UtcDateTime,
                ExpiresAtUtc = now.AddHours(1).UtcDateTime,
                FinalizedAtUtc = now.AddMinutes(-30).UtcDateTime
            });
            var sourceGrantOwnership = await modernSeed.DistributionGrantOwnerships.SingleAsync(candidate =>
                candidate.ProductId == sourceBinding.ProductId
                && candidate.GrantRefDigestSha256 == sourceBinding.GrantRefDigestSha256);
            sourceGrantOwnership.Source = "issue_v3";
            await modernSeed.SaveChangesAsync();
        }

        targetRequest.RequestId = Guid.NewGuid().ToString("D");
        var modernResolution = await service.ResolveRuntimeSourceAsync(
            "website-step1", SourceResolutionRequest());
        Assert.Equal("source", modernResolution.Outcome);
        Assert.Equal("modern", modernResolution.SourceKind);
        Assert.Equal(fixture.LicenseId.ToString("D"), modernResolution.SourceLicenseId);
        var coherentModern = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("grantless-modern-coherent"), targetRequest));
        Assert.Equal("binding_conflict", coherentModern.ErrorCode);
        Assert.Equal("legacy_replacement_modern_authority_required", coherentModern.ReasonCode);

        await using (var inconsistentSeed = await factory.CreateDbContextAsync())
        {
            var sourceEntitlementId = await inconsistentSeed.DistributionInstallationBindings.AsNoTracking()
                .Where(candidate => candidate.Id == sourceBindingId)
                .Select(candidate => candidate.EntitlementId)
                .SingleAsync();
            var sourceEntitlement = await inconsistentSeed.DistributionEntitlements
                .SingleAsync(candidate => candidate.Id == sourceEntitlementId);
            inconsistentSeed.DistributionEntitlements.Remove(sourceEntitlement);
            await inconsistentSeed.SaveChangesAsync();
            inconsistentSeed.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = Guid.NewGuid(),
                ClientId = sourceEntitlement.ClientId,
                ProductId = sourceEntitlement.ProductId,
                LicenseId = sourceEntitlement.LicenseId,
                GrantRefDigestSha256 = sourceEntitlement.GrantRefDigestSha256,
                SubjectRefDigestSha256 = sourceEntitlement.SubjectRefDigestSha256,
                ContractVersion = sourceEntitlement.ContractVersion,
                State = sourceEntitlement.State,
                IssuedAtUtc = sourceEntitlement.IssuedAtUtc,
                ExpiresAtUtc = sourceEntitlement.ExpiresAtUtc,
                FinalizedAtUtc = sourceEntitlement.FinalizedAtUtc
            });
            await inconsistentSeed.SaveChangesAsync();
        }

        targetRequest.RequestId = Guid.NewGuid().ToString("D");
        var inconsistentModern = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("grantless-modern-inconsistent"), targetRequest));
        Assert.Equal("binding_conflict", inconsistentModern.ErrorCode);
        Assert.Equal("legacy_replacement_modern_authority_inconsistent", inconsistentModern.ReasonCode);

        await using (var legacySeed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await legacySeed.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var sourceEnrollment = await legacySeed.RuntimeEnrollments
                .SingleAsync(candidate => candidate.BindingId == sourceBindingId);
            sourceBinding.SubjectRefDigestSha256 = null;
            sourceEnrollment.SubjectRefDigestSha256 = null;
            legacySeed.DistributionEntitlements.Remove(await legacySeed.DistributionEntitlements
                .SingleAsync(candidate => candidate.ProductId == sourceBinding.ProductId
                    && candidate.GrantRefDigestSha256 == sourceBinding.GrantRefDigestSha256));
            legacySeed.DistributionGrantOwnerships.Remove(await legacySeed.DistributionGrantOwnerships
                .SingleAsync(candidate => candidate.ProductId == sourceBinding.ProductId
                    && candidate.GrantRefDigestSha256 == sourceBinding.GrantRefDigestSha256));
            await legacySeed.SaveChangesAsync();
        }

        var legacyResolution = await service.ResolveRuntimeSourceAsync(
            "website-step1", SourceResolutionRequest());
        Assert.Equal("source", legacyResolution.Outcome);
        Assert.Equal("legacy", legacyResolution.SourceKind);
        Assert.Equal(fixture.LicenseId.ToString("D"), legacyResolution.SourceLicenseId);
        var wrongClientResolution = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.ResolveRuntimeSourceAsync("other-client", SourceResolutionRequest()));
        Assert.Equal("cross_generation_finalize_owner_mismatch", wrongClientResolution.ReasonCode);

        string rollbackRequestId;
        long sourceEnrollmentEpoch;
        int sourceEnrollmentSecurityEpoch;
        await using (var disableSeed = await factory.CreateDbContextAsync())
        {
            var license = await disableSeed.Licenses.Include(candidate => candidate.Type)
                .SingleAsync(candidate => candidate.Id == targetLicenseId);
            license.Type!.DisableNewActivations = true;
            var sourceEnrollment = await disableSeed.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.BindingId == sourceBindingId);
            sourceEnrollmentEpoch = sourceEnrollment.Epoch;
            sourceEnrollmentSecurityEpoch = sourceEnrollment.SecurityEpoch;
            await disableSeed.SaveChangesAsync();
        }

        rollbackRequestId = Guid.NewGuid().ToString("D");
        targetRequest.RequestId = rollbackRequestId;
        var postFlushFailure = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("grantless-post-flush-rollback"), targetRequest));
        Assert.Equal("new_activations_disabled", postFlushFailure.ErrorCode);
        Assert.Null(postFlushFailure.ReasonCode);

        await using (var rollbackCheck = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await rollbackCheck.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var sourceSeat = await rollbackCheck.LicenseSeats.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBinding.LicenseSeatId);
            var sourceEnrollment = await rollbackCheck.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.BindingId == sourceBindingId);
            Assert.Equal("active", sourceBinding.State);
            Assert.True(sourceSeat.IsActive);
            Assert.Null(sourceSeat.UnlinkedAt);
            Assert.Equal("ACTIVE", sourceEnrollment.State);
            Assert.Equal(sourceEnrollmentEpoch, sourceEnrollment.Epoch);
            Assert.Equal(sourceEnrollmentSecurityEpoch, sourceEnrollment.SecurityEpoch);
            Assert.Equal(authorityEpoch, sourceEnrollment.AuthorityEpoch);
            Assert.False(await rollbackCheck.LicenseSeats.AsNoTracking()
                .AnyAsync(candidate => candidate.LicenseId == targetLicenseId && candidate.IsActive));
            Assert.False(await rollbackCheck.LicenseHistories.AsNoTracking()
                .AnyAsync(candidate => candidate.Action == "RUNTIME_LEGACY_LICENSE_REPLACED"));
            Assert.False(await rollbackCheck.DistributionBindingRequests.AsNoTracking()
                .AnyAsync(candidate => candidate.RequestId == rollbackRequestId));
            Assert.Equal("issued", await rollbackCheck.DistributionEntitlements.AsNoTracking()
                .Where(candidate => candidate.ProductId == fixture.ProductId
                    && candidate.GrantRefDigestSha256 == Sha256(targetGrantRef))
                .Select(candidate => candidate.State)
                .SingleAsync());
        }

        await using (var enableSeed = await factory.CreateDbContextAsync())
        {
            var license = await enableSeed.Licenses.Include(candidate => candidate.Type)
                .SingleAsync(candidate => candidate.Id == targetLicenseId);
            license.Type!.DisableNewActivations = false;
            await enableSeed.SaveChangesAsync();
        }

        targetRequest.RequestId = Guid.NewGuid().ToString("D");
        var finalizeDigest = Sha256("grantless-target-finalize");
        var concurrent = await Task.WhenAll(
            service.FinalizeAsync("website-step1", finalizeDigest, targetRequest),
            service.FinalizeAsync("website-step1", finalizeDigest, targetRequest));
        var replaced = Assert.Single(concurrent, candidate => !candidate.Idempotent);
        var concurrentReplay = Assert.Single(concurrent, candidate => candidate.Idempotent);
        Assert.Equal(replaced.Response, concurrentReplay.Response);

        var replayed = await service.FinalizeAsync("website-step1", finalizeDigest, targetRequest);
        Assert.True(replayed.Idempotent);
        Assert.Equal(replaced.Response, replayed.Response);

        Assert.False(replaced.Idempotent);
        await using var check = await factory.CreateDbContextAsync();
        var successor = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == Guid.Parse(replaced.Response.BindingId));
        Assert.Equal(targetLicenseId, successor.LicenseId);
        var targetSeat = await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.LicenseId == targetLicenseId && candidate.IsActive);
        Assert.Equal(targetSeat.Id, successor.LicenseSeatId);
        Assert.Equal(sourceBindingId, successor.SupersededBindingId);
        Assert.Equal(4, successor.InitialSecurityEpoch);
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == fixture.ProductId
            && candidate.HardwareIdHash == Sha256(fixture.HardwareId)
            && candidate.State == "active").ToListAsync());

        // Creates one canonical request while allowing each security phase to use an independent request identifier.
        DistributionInstallationFinalizeRequest CreateFinalizeRequest(
            string schema,
            string label,
            string grantRef,
            string entitlementRef,
            string installationId,
            DateTimeOffset issuedAt) => new()
            {
                Schema = schema,
                RequestId = Guid.NewGuid().ToString("D"),
                GrantRef = grantRef,
                HandoffDigestSha256 = Sha256(label + "-handoff-" + grantRef),
                HandoffIssuedAtUtc = FormatUtc(issuedAt),
                HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
                DownloadCompletedAtUtc = FormatUtc(issuedAt.AddMinutes(1)),
                ProductId = fixture.ProductId.ToString("D"),
                EntitlementRef = entitlementRef,
                InstallationId = installationId,
                HardwareId = fixture.HardwareId,
                Release = new DistributionReleaseEvidence
                {
                    Version = fixture.Version,
                    InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
                    InstallerSha256 = Sha256(label + "-installer")
                },
                Binaries =
                [
                    new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                    new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                    new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
                ]
            };
    }

    [Fact]
    public async Task DistributionFinalize_ExpiredSourceAndNewLicense_V4AtomicallySelectsExactWebsiteAuthority()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var sourceSubjectRef = Convert.ToBase64String(SHA256.HashData("cross-license-red-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var targetSubjectRef = Convert.ToBase64String(SHA256.HashData("cross-license-target-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        async Task<(string GrantRef, string EntitlementRef)> IssueAsync(
            Guid licenseId,
            string label,
            string subjectRef)
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var issued = await service.IssueEntitlementAsync(
                "website-step1",
                Sha256(label + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = licenseId.ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef),
                    SubjectRef = subjectRef
                });
            return (grantRef, issued.Response.EntitlementRef);
        }

        DistributionInstallationFinalizeRequest FinalizeRequest(
            string label,
            (string GrantRef, string EntitlementRef) authority,
            DateTimeOffset issuedAt) => new()
            {
                Schema = DistributionInstallationBindingService.FinalizeV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                GrantRef = authority.GrantRef,
                HandoffDigestSha256 = Sha256(label + "-handoff-" + authority.GrantRef),
                HandoffIssuedAtUtc = FormatUtc(issuedAt),
                HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
                DownloadCompletedAtUtc = FormatUtc(issuedAt.AddMinutes(1)),
                ProductId = fixture.ProductId.ToString("D"),
                EntitlementRef = authority.EntitlementRef,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareId = fixture.HardwareId,
                AllowSameAuthorityRecovery = true,
                Release = new DistributionReleaseEvidence
                {
                    Version = fixture.Version,
                    InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
                    InstallerSha256 = Sha256(label + "-installer")
                },
                Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
            };

        var sourceAuthority = await IssueAsync(fixture.LicenseId, "cross-license-source", sourceSubjectRef);
        var sourceRequest = FinalizeRequest("cross-license-source", sourceAuthority, now.AddMinutes(-15));
        var source = await service.FinalizeAsync(
            "website-step1", Sha256("cross-license-source-finalize"), sourceRequest);
        var sourceBindingId = Guid.Parse(source.Response.BindingId);
        Guid targetLicenseId;
        Guid targetSeatId;
        long authorityEpoch;
        await using (var authorityReader = await new TestDbFactory(connections.Admin).CreateDbContextAsync())
        {
            // The application role intentionally cannot read the protected global authority
            // state. Test setup uses the administrative fixture only to seed an exact epoch.
            authorityEpoch = await authorityReader.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
        }

        await using (var seed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await seed.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var sourceLicense = await seed.Licenses.SingleAsync(candidate => candidate.Id == fixture.LicenseId);
            sourceLicense.IsActive = false;
            sourceLicense.RevokedAt = now.AddMinutes(-10).UtcDateTime;
            sourceLicense.ExpirationDate = now.AddMinutes(-10).UtcDateTime;

            targetLicenseId = Guid.NewGuid();
            targetSeatId = Guid.NewGuid();
            seed.Licenses.Add(new License
            {
                Id = targetLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = sourceLicense.LicenseTypeId,
                LicenseKey = "CROSS-LICENSE-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = sourceLicense.AllowedVersions,
                ExpirationDate = now.AddDays(30).UtcDateTime
            });
            seed.LicenseSeats.Add(new LicenseSeat
            {
                Id = targetSeatId,
                LicenseId = targetLicenseId,
                HardwareId = fixture.HardwareId,
                IsActive = true,
                FirstActivatedAt = now.AddMinutes(-8).UtcDateTime,
                LastCheckInAt = now.AddMinutes(-8).UtcDateTime
            });
            seed.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = Guid.NewGuid(),
                ClientId = "website-step1",
                BindingId = sourceBinding.Id,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                InstallationId = sourceBinding.InstallationId,
                HardwareIdHash = sourceBinding.HardwareIdHash,
                ReleaseVersion = sourceBinding.Version,
                HandoffDigestSha256 = sourceBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "xl-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 4,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddHours(-1).UtcDateTime,
                ActivatedAtUtc = now.AddMinutes(-30).UtcDateTime
            });
            await seed.SaveChangesAsync();
        }

        var targetAuthority = await IssueAsync(targetLicenseId, "cross-license-target", targetSubjectRef);
        var targetRequest = FinalizeRequest("cross-license-target", targetAuthority, now.AddMinutes(-5));

        DistributionLicenseReplacementProof ReplacementProof(string sourceSubject) => new()
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
            SourceBindingId = sourceBindingId.ToString("D"),
            SourceLicenseId = fixture.LicenseId.ToString("D"),
            SourceSubjectRef = sourceSubject
        };
        DistributionLicenseReplacementCandidateSet ReplacementCandidates(bool includeMatchingSource) => new()
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
            Sources =
            [
                new()
                {
                    Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                    SourceBindingId = Guid.NewGuid().ToString("D"),
                    SourceLicenseId = Guid.NewGuid().ToString("D"),
                    SourceSubjectRef = Convert.ToBase64String(SHA256.HashData("legacy-candidate-one"u8.ToArray()))
                        .TrimEnd('=').Replace('+', '-').Replace('/', '_')
                },
                includeMatchingSource ? ReplacementProof(sourceSubjectRef) : new()
                {
                    Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                    SourceBindingId = Guid.NewGuid().ToString("D"),
                    SourceLicenseId = Guid.NewGuid().ToString("D"),
                    SourceSubjectRef = Convert.ToBase64String(SHA256.HashData("legacy-candidate-missing"u8.ToArray()))
                        .TrimEnd('=').Replace('+', '-').Replace('/', '_')
                },
                new()
                {
                    Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                    SourceBindingId = Guid.NewGuid().ToString("D"),
                    SourceLicenseId = Guid.NewGuid().ToString("D"),
                    SourceSubjectRef = Convert.ToBase64String(SHA256.HashData("legacy-candidate-three"u8.ToArray()))
                        .TrimEnd('=').Replace('+', '-').Replace('/', '_')
                }
            ]
        };
        targetRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        targetRequest.LicenseReplacementCandidates = ReplacementCandidates(includeMatchingSource: true);

        var legacyProbe = FinalizeRequest("cross-license-legacy-probe", targetAuthority, now.AddMinutes(-4));
        var legacyError = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("cross-license-legacy-probe-finalize"), legacyProbe));
        Assert.Equal("binding_conflict", legacyError.ErrorCode);

        var divergentSubjectProbe = FinalizeRequest(
            "cross-license-divergent-subject-probe", targetAuthority, now.AddMinutes(-4));
        divergentSubjectProbe.Schema = DistributionInstallationBindingService.FinalizeV3Schema;
        divergentSubjectProbe.LicenseReplacement = ReplacementProof(targetSubjectRef);
        var divergentSubjectError = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1",
                Sha256("cross-license-divergent-subject-probe-finalize"),
                divergentSubjectProbe));
        Assert.Equal("binding_conflict", divergentSubjectError.ErrorCode);

        await using (var makeSourceEligible = await factory.CreateDbContextAsync())
        {
            var sourceLicense = await makeSourceEligible.Licenses.SingleAsync(candidate =>
                candidate.Id == fixture.LicenseId);
            sourceLicense.IsActive = true;
            sourceLicense.RevokedAt = null;
            sourceLicense.ExpirationDate = now.AddDays(1).UtcDateTime;
            await makeSourceEligible.SaveChangesAsync();
        }
        var eligibleSourceProbe = FinalizeRequest(
            "cross-license-eligible-source-probe", targetAuthority, now.AddMinutes(-3));
        eligibleSourceProbe.Schema = DistributionInstallationBindingService.FinalizeV3Schema;
        eligibleSourceProbe.LicenseReplacement = ReplacementProof(sourceSubjectRef);
        var eligibleSourceError = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1",
                Sha256("cross-license-eligible-source-probe-finalize"),
                eligibleSourceProbe));
        Assert.Equal("binding_conflict", eligibleSourceError.ErrorCode);
        await using (var restoreSourceIneligible = await factory.CreateDbContextAsync())
        {
            var sourceLicense = await restoreSourceIneligible.Licenses.SingleAsync(candidate =>
                candidate.Id == fixture.LicenseId);
            sourceLicense.IsActive = false;
            sourceLicense.RevokedAt = now.AddMinutes(-10).UtcDateTime;
            sourceLicense.ExpirationDate = now.AddMinutes(-10).UtcDateTime;
            await restoreSourceIneligible.SaveChangesAsync();
        }

        var missingCandidateProbe = FinalizeRequest(
            "cross-license-missing-candidate-probe", targetAuthority, now.AddMinutes(-3));
        missingCandidateProbe.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        missingCandidateProbe.LicenseReplacementCandidates = ReplacementCandidates(includeMatchingSource: false);
        var missingCandidateError = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1",
                Sha256("cross-license-missing-candidate-probe-finalize"),
                missingCandidateProbe));
        Assert.Equal("binding_conflict", missingCandidateError.ErrorCode);
        Assert.Equal("replacement_candidate_none", missingCandidateError.ReasonCode);

        // Reproduce TKT-000295: classic activation has already moved the product seat to the
        // replacement license, leaving the last exact Runtime generation as a business tombstone.
        // Finalize-v4 must resolve that unique leaf from the bounded Website candidate set without
        // reviving or rewriting the forensic rows.
        DateTime sourceInvalidatedAt;
        long businessTerminalAuthorityEpoch;
        await using (var advanceAuthority = await new TestDbFactory(connections.Admin).CreateDbContextAsync())
        {
            var authorityState = await advanceAuthority.RuntimeEnrollmentAuthorityStates
                .SingleAsync(candidate => candidate.Id == 1);
            authorityState.Epoch++;
            businessTerminalAuthorityEpoch = authorityState.Epoch;
            await advanceAuthority.SaveChangesAsync();
        }
        await using (var invalidateSource = await factory.CreateDbContextAsync())
        {
            var invalidatedAt = now.AddMinutes(-2).UtcDateTime;
            sourceInvalidatedAt = new DateTime(
                invalidatedAt.Ticks - invalidatedAt.Ticks % 10,
                DateTimeKind.Utc);
            var sourceBinding = await invalidateSource.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            sourceBinding.State = "invalidated";
            sourceBinding.InvalidatedAtUtc = sourceInvalidatedAt;
            sourceBinding.InvalidationReason = "seat_reassigned_product_scope";
            var sourceEnrollment = await invalidateSource.RuntimeEnrollments
                .SingleAsync(candidate => candidate.BindingId == sourceBindingId);
            sourceEnrollment.State = "INVALIDATED";
            sourceEnrollment.InvalidatedAtUtc = sourceInvalidatedAt;
            sourceEnrollment.InvalidationReason = "seat_reassigned_product_scope";
            sourceEnrollment.AuthorityEpoch = businessTerminalAuthorityEpoch;
            await invalidateSource.SaveChangesAsync();
        }

        // The additive v4 assertion carries bounded Website-owned history. SoftLicence matches the
        // sole hardware binding under its authority lock; list order never grants preference.
        var competingRequest = FinalizeRequest(
            "cross-license-competing-target", targetAuthority, now.AddMinutes(-2));
        competingRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        competingRequest.LicenseReplacementCandidates = targetRequest.LicenseReplacementCandidates;
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstFinalize = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("cross-license-target-finalize"), targetRequest));
        });
        var secondFinalize = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("cross-license-competing-target-finalize"), competingRequest));
        });
        start.SetResult();
        var outcomes = await Task.WhenAll(firstFinalize, secondFinalize);
        var winnerIndex = Array.FindIndex(outcomes, outcome => outcome.Error == null);
        Assert.True(winnerIndex >= 0);
        Assert.Single(outcomes, outcome => outcome.Error == null);
        var losingError = Assert.IsType<DistributionOperationException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error);
        Assert.True(losingError.ErrorCode is "binding_conflict" or "entitlement_ineligible");
        var replaced = outcomes[winnerIndex].Result!;
        var winnerRequest = winnerIndex == 0 ? targetRequest : competingRequest;
        var winnerDigest = winnerIndex == 0
            ? Sha256("cross-license-target-finalize")
            : Sha256("cross-license-competing-target-finalize");

        Assert.False(replaced.Idempotent);
        await using var check = await factory.CreateDbContextAsync();
        var active = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.ProductId == fixture.ProductId
                && candidate.HardwareIdHash == Sha256(fixture.HardwareId)
                && candidate.State == "active");
        Assert.Equal(targetLicenseId, active.LicenseId);
        Assert.Equal(targetSeatId, active.LicenseSeatId);
        Assert.Equal(sourceBindingId, active.SupersededBindingId);
        Assert.Equal(5, active.InitialSecurityEpoch);
        var sourceAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceBindingId);
        Assert.Equal("invalidated", sourceAfter.State);
        Assert.Equal("seat_reassigned_product_scope", sourceAfter.InvalidationReason);
        Assert.Equal(sourceInvalidatedAt, sourceAfter.InvalidatedAtUtc);
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.BindingId == sourceBindingId);
        Assert.Equal("INVALIDATED", enrollmentAfter.State);
        Assert.Equal("seat_reassigned_product_scope", enrollmentAfter.InvalidationReason);
        Assert.Equal(sourceInvalidatedAt, enrollmentAfter.InvalidatedAtUtc);
        var finalAuthorityEpoch = await check.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1)
            .Select(candidate => candidate.Epoch)
            .SingleAsync();
        Assert.True(finalAuthorityEpoch > authorityEpoch);
        Assert.Equal(businessTerminalAuthorityEpoch, enrollmentAfter.AuthorityEpoch);

        var replay = await service.FinalizeAsync(
            "website-step1", winnerDigest, winnerRequest);
        Assert.True(replay.Idempotent);
        Assert.Equal(replaced.Response, replay.Response);
    }

    [Fact]
    public async Task DistributionFinalize_CompletesBeforeClassicActivation_ActivationEndsAssignmentAndPreservesRuntimeIdentity()
    {
        var connections = await ProvisionAsync();
        var directFactory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(directFactory, includeSeat: false);
        var activationLicenseId = Guid.NewGuid();
        var activationSeatId = Guid.NewGuid();
        var activationLicenseKey = "DIST-ACTIVATE-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        string appName;
        await using (var seed = await directFactory.CreateDbContextAsync())
        {
            var finalizeLicense = await seed.Licenses.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == fixture.LicenseId);
            appName = await seed.Products.AsNoTracking()
                .Where(candidate => candidate.Id == fixture.ProductId)
                .Select(candidate => candidate.Name)
                .SingleAsync();
            seed.Licenses.Add(new License
            {
                Id = activationLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = finalizeLicense.LicenseTypeId,
                LicenseKey = activationLicenseKey,
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = finalizeLicense.AllowedVersions,
                ExpirationDate = DateTime.UtcNow.AddDays(1)
            });
            seed.LicenseSeats.Add(new LicenseSeat
            {
                Id = activationSeatId,
                LicenseId = activationLicenseId,
                HardwareId = fixture.HardwareId,
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                IsActive = false,
                UnlinkedAt = DateTime.UtcNow.AddHours(-1)
            });
            await seed.SaveChangesAsync();
        }

        using var webFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connections.App));
            });
        });
        var client = webFactory.CreateClient();
        using (var scope = webFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
            var product = await db.Products.SingleAsync(candidate => candidate.Id == fixture.ProductId);
            var keys = LicenseService.GenerateKeys();
            product.PrivateKeyXml = encryption.Encrypt(keys.PrivateKey);
            product.PublicKeyXml = keys.PublicKey;
            await db.SaveChangesAsync();
        }
        var now = new DateTimeOffset(2026, 7, 27, 15, 0, 0, TimeSpan.Zero);
        var distribution = new DistributionInstallationBindingService(
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await distribution.IssueEntitlementAsync(
            "website-step1",
            Sha256("finalize-wins-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef)
            });
        var finalizeRequest = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("finalize-wins-handoff"),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = fixture.HardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "distribution-finalize-wins.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var finalized = await distribution.FinalizeAsync(
            "website-step1", Sha256("finalize-wins-finalize"), finalizeRequest);
        Assert.False(finalized.Idempotent);

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        Guid bindingId;
        Guid enrollmentId = Guid.NewGuid();
        long enrollmentAuthorityEpoch;
        await using (var seedEnrollment = await directFactory.CreateDbContextAsync())
        {
            var binding = await seedEnrollment.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.ProductId == fixture.ProductId
                    && candidate.LicenseId == fixture.LicenseId
                    && candidate.HardwareIdHash == Sha256(fixture.HardwareId)
                    && candidate.State == "active");
            bindingId = binding.Id;
            enrollmentAuthorityEpoch = await seedEnrollment.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            seedEnrollment.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = "website-step1",
                BindingId = binding.Id,
                ProductId = binding.ProductId,
                LicenseId = binding.LicenseId,
                LicenseSeatId = binding.LicenseSeatId,
                InstallationId = binding.InstallationId,
                HardwareIdHash = binding.HardwareIdHash,
                ReleaseVersion = binding.Version,
                HandoffDigestSha256 = binding.HandoffDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "thumb-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 1,
                AuthorityEpoch = enrollmentAuthorityEpoch,
                ChallengeExpiresAtUtc = DateTime.UtcNow.AddHours(1),
                CreatedAtUtc = DateTime.UtcNow,
                ActivatedAtUtc = DateTime.UtcNow
            });
            await seedEnrollment.SaveChangesAsync();
        }

        var identityBefore = await SnapshotRetainedRuntimeIdentityAsync(directFactory, enrollmentId);
        EnrollmentLicenseAssignment assignmentBefore;
        await using (var original = await directFactory.CreateDbContextAsync())
            assignmentBefore = await original.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE");
        var activationResponse = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = activationLicenseKey,
            HardwareId = fixture.HardwareId,
            AppName = appName,
            AppVersion = fixture.Version
        });
        var activationBody = await activationResponse.Content.ReadAsStringAsync();
        Assert.True(activationResponse.StatusCode == HttpStatusCode.OK,
            $"Expected activation success, got {(int)activationResponse.StatusCode}: {activationBody}");

        using var activationJson = System.Text.Json.JsonDocument.Parse(activationBody);
        Assert.False(string.IsNullOrEmpty(activationJson.RootElement.GetProperty("licenseFile").GetString()));
        DateTime endedAt;
        await using (var check = await directFactory.CreateDbContextAsync())
        {
            var binding = await check.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == bindingId);
            var enrollment = await check.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentId);
            var activeSeats = await check.LicenseSeats.Where(candidate =>
                candidate.IsActive
                && candidate.HardwareId == fixture.HardwareId
                && candidate.License != null
                && candidate.License.ProductId == fixture.ProductId).ToListAsync();
            Assert.Single(activeSeats);
            Assert.Equal(activationLicenseId, activeSeats[0].LicenseId);
            Assert.Equal(activationSeatId, activeSeats[0].Id);
            Assert.Equal("active", binding.State);
            Assert.Equal("ACTIVE", enrollment.State);
            Assert.Equal(enrollmentAuthorityEpoch, enrollment.AuthorityEpoch);
            var assignment = await check.EnrollmentLicenseAssignments.SingleAsync(row => row.Id == assignmentBefore.Id);
            Assert.Equal("ENDED", assignment.State);
            Assert.Equal("seat_released", assignment.EndReason);
            Assert.Equal(assignmentBefore.Revision, assignment.Revision);
            endedAt = Assert.IsType<DateTime>(assignment.EndedAtUtc);
            Assert.Empty(await check.EnrollmentLicenseAssignments.Where(row =>
                row.EnrollmentId == enrollmentId && row.State == "ACTIVE").ToListAsync());
        }
        Assert.Equal(identityBefore, await SnapshotRetainedRuntimeIdentityAsync(directFactory, enrollmentId));
        await AssertEndedAssignmentDeniesRuntimeAsync(directFactory, enrollmentId);

        await using (var standaloneDb = await directFactory.CreateDbContextAsync())
        {
            var cleanup = new SeatCleanupService(standaloneDb, NullLogger<SeatCleanupService>.Instance);
            var replay = await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                fixture.HardwareId, activationLicenseId, fixture.ProductId, redactSensitiveDetails: true);
            Assert.Empty(replay);
        }

        await using var replayCheck = await directFactory.CreateDbContextAsync();
        var replayedAssignment = await replayCheck.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.Id == assignmentBefore.Id);
        Assert.Equal(endedAt, replayedAssignment.EndedAtUtc);
        Assert.Equal("ENDED", replayedAssignment.State);
        Assert.Equal("seat_released", replayedAssignment.EndReason);
        Assert.Equal(assignmentBefore.Revision, replayedAssignment.Revision);
        Assert.Single(await replayCheck.EnrollmentLicenseAssignments.Where(row => row.EnrollmentId == enrollmentId).ToListAsync());
        Assert.Equal(identityBefore, await SnapshotRetainedRuntimeIdentityAsync(directFactory, enrollmentId));
        await AssertEndedAssignmentDeniesRuntimeAsync(directFactory, enrollmentId);
    }

    [Fact]
    public async Task ClassicActivation_CompletesBeforeDistributionFinalize_FinalizeRefuses()
    {
        var connections = await ProvisionAsync();
        var directFactory = new TestDbFactory(connections.App);
        using var webFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connections.App));
            });
        });
        var client = webFactory.CreateClient();
        var now = new DateTimeOffset(2026, 7, 27, 14, 0, 0, TimeSpan.Zero);
        var classicActivationExpirationUtc = CreateFutureClassicActivationExpirationUtc();
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var finalizeLicenseId = Guid.NewGuid();
        var activationLicenseId = Guid.NewGuid();
        var activationSeatId = Guid.NewGuid();
        var hardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        var appName = "Distribution activation race " + productId.ToString("N");
        var activationLicenseKey = "DIST-ACTIVATE-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        const string version = "2.2.844";
        using (var scope = webFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
            var keys = LicenseService.GenerateKeys();
            db.Products.Add(new Product
            {
                Id = productId,
                Name = appName,
                PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
                PublicKeyXml = keys.PublicKey,
                ApiSecret = Guid.NewGuid().ToString("N")
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = typeId,
                ProductId = productId,
                Name = "Distribution activation race",
                Slug = "distribution-activation-" + productId.ToString("N"),
                IsFree = false
            });
            db.Licenses.AddRange(
                new License
                {
                    Id = finalizeLicenseId,
                    ProductId = productId,
                    LicenseTypeId = typeId,
                    LicenseKey = "DIST-FINALIZE-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                    IsActive = true,
                    MaxSeats = 1,
                    AllowedVersions = "2.2.*",
                    ExpirationDate = now.AddDays(1).UtcDateTime
                },
                new License
                {
                    Id = activationLicenseId,
                    ProductId = productId,
                    LicenseTypeId = typeId,
                    LicenseKey = activationLicenseKey,
                    IsActive = true,
                    MaxSeats = 1,
                    AllowedVersions = "2.2.*",
                    ExpirationDate = classicActivationExpirationUtc
                });
            db.LicenseSeats.Add(new LicenseSeat
            {
                Id = activationSeatId,
                LicenseId = activationLicenseId,
                HardwareId = hardwareId,
                FirstActivatedAt = now.AddDays(-1).UtcDateTime,
                LastCheckInAt = now.AddDays(-1).UtcDateTime,
                IsActive = false,
                UnlinkedAt = now.AddHours(-1).UtcDateTime
            });
            db.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_EXE", Hash = new string('a', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_DLL", Hash = new string('b', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_CORE", Hash = new string('c', 64), Source = "release" });
            await db.SaveChangesAsync();
        }

        var distribution = new DistributionInstallationBindingService(
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await distribution.IssueEntitlementAsync(
            "website-step1",
            Sha256("activation-race-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = productId.ToString("D"),
                SoftLicenceLicenseId = finalizeLicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef)
            });
        var finalizeRequest = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("activation-race-handoff"),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
            ProductId = productId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = hardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = version,
                InstallerFilename = "distribution-activation-race.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var activationResponse = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = activationLicenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = version
        });
        Assert.Equal(HttpStatusCode.OK, activationResponse.StatusCode);
        var rejection = await Assert.ThrowsAsync<DistributionOperationException>(() => distribution.FinalizeAsync(
            "website-step1", Sha256("activation-race-finalize"), finalizeRequest));
        Assert.Equal("hardware_already_bound", rejection.ErrorCode);

        await using var check = await directFactory.CreateDbContextAsync();
        var activeSeats = await check.LicenseSeats.Where(candidate =>
            candidate.IsActive
            && candidate.HardwareId == hardwareId
            && candidate.License != null
            && candidate.License.ProductId == productId).ToListAsync();
        Assert.Single(activeSeats);
        Assert.Equal(activationLicenseId, activeSeats[0].LicenseId);
        Assert.Equal(activationSeatId, activeSeats[0].Id);
        Assert.Null(activeSeats[0].UnlinkedAt);
        Assert.Empty(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == productId
            && candidate.HardwareIdHash == Sha256(hardwareId)).ToListAsync());
    }

    [Fact]
    public async Task ClassicActivation_ConcurrentWithDistributionFinalize_WaitsOnSharedExactHardwareLock()
    {
        var connections = await ProvisionAsync();
        var finalizeApplication = "sync-finalize-" + Guid.NewGuid().ToString("N");
        var activationApplication = "sync-activation-" + Guid.NewGuid().ToString("N");
        var finalizeConnection = new NpgsqlConnectionStringBuilder(connections.App)
            { ApplicationName = finalizeApplication, Pooling = false }.ConnectionString;
        var activationConnection = new NpgsqlConnectionStringBuilder(connections.App)
            { ApplicationName = activationApplication, Pooling = false }.ConnectionString;
        var productId = Guid.NewGuid();
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(productId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        var enrollmentSeed = new ConcurrentFinalizeEnrollmentSeed(runtimeOptions.Encryption.ActiveKeyId);
        var directFactory = new ConcurrentFinalizeEnrollmentFactory(finalizeConnection, enrollmentSeed);
        using var webFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(activationConnection));
            });
        });
        var client = webFactory.CreateClient();
        var now = new DateTimeOffset(2026, 7, 27, 16, 0, 0, TimeSpan.Zero);
        var classicActivationExpirationUtc = CreateFutureClassicActivationExpirationUtc();
        var typeId = Guid.NewGuid();
        var finalizeLicenseId = Guid.NewGuid();
        var activationLicenseId = Guid.NewGuid();
        var activationSeatId = Guid.NewGuid();
        var hardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        var appName = "Distribution concurrent lock " + productId.ToString("N");
        var activationLicenseKey = "DIST-CONCURRENT-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        const string version = "2.2.844";
        using (var scope = webFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
            var keys = LicenseService.GenerateKeys();
            db.Products.Add(new Product
            {
                Id = productId,
                Name = appName,
                PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
                PublicKeyXml = keys.PublicKey,
                ApiSecret = Guid.NewGuid().ToString("N")
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = typeId,
                ProductId = productId,
                Name = "Distribution concurrent lock",
                Slug = "distribution-concurrent-" + productId.ToString("N"),
                IsFree = false
            });
            db.Licenses.AddRange(
                new License
                {
                    Id = finalizeLicenseId,
                    ProductId = productId,
                    LicenseTypeId = typeId,
                    LicenseKey = "DIST-CONCURRENT-FINALIZE-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                    IsActive = true,
                    MaxSeats = 1,
                    AllowedVersions = "2.2.*",
                    ExpirationDate = now.AddDays(1).UtcDateTime
                },
                new License
                {
                    Id = activationLicenseId,
                    ProductId = productId,
                    LicenseTypeId = typeId,
                    LicenseKey = activationLicenseKey,
                    IsActive = true,
                    MaxSeats = 1,
                    AllowedVersions = "2.2.*",
                    ExpirationDate = classicActivationExpirationUtc
                });
            db.LicenseSeats.Add(new LicenseSeat
            {
                Id = activationSeatId,
                LicenseId = activationLicenseId,
                HardwareId = hardwareId,
                FirstActivatedAt = now.AddDays(-1).UtcDateTime,
                LastCheckInAt = now.AddDays(-1).UtcDateTime,
                IsActive = false,
                UnlinkedAt = now.AddHours(-1).UtcDateTime
            });
            db.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_EXE", Hash = new string('a', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_DLL", Hash = new string('b', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_CORE", Hash = new string('c', 64), Source = "release" });
            await db.SaveChangesAsync();
        }

        var distribution = new DistributionInstallationBindingService(
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await distribution.IssueEntitlementAsync(
            "website-step1",
            Sha256("concurrent-lock-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = productId.ToString("D"),
                SoftLicenceLicenseId = finalizeLicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef)
            });
        var finalizeRequest = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("concurrent-lock-handoff"),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
            ProductId = productId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = hardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = version,
                InstallerFilename = "distribution-concurrent-lock.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        await using var blocker = new NpgsqlConnection(connections.Admin);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        var productHardwareLockName =
            $"distribution-product-hardware-seat:{productId:D}:{hardwareId}";
        await using (var block = blocker.CreateCommand())
        {
            block.Transaction = blockerTransaction;
            block.CommandText = "SELECT pg_advisory_xact_lock(hashtextextended(@lock_name, 0));";
            block.Parameters.AddWithValue("lock_name", productHardwareLockName);
            await block.ExecuteNonQueryAsync();
        }

        var lockObservation = System.Diagnostics.Stopwatch.StartNew();
        var finalizeTask = CaptureAsync(() => distribution.FinalizeAsync(
            "website-step1", Sha256("concurrent-lock-finalize"), finalizeRequest));
        await WaitForProductHardwareLockChainAsync(
            connections.Admin, productHardwareLockName, blocker.ProcessID,
            finalizeApplication, string.Empty, lockObservation);
        Assert.False(finalizeTask.IsCompleted);
        var activationTask = client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = activationLicenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = version
        });

        await WaitForProductHardwareLockChainAsync(
            connections.Admin, productHardwareLockName, blocker.ProcessID,
            finalizeApplication, activationApplication, lockObservation);
        Assert.False(finalizeTask.IsCompleted);
        Assert.False(activationTask.IsCompleted);
        await blockerTransaction.CommitAsync();

        var finalizeOutcome = await finalizeTask;
        // This ordered scenario must exercise real retained identity, never the rejected-Finalize branch.
        Assert.Null(finalizeOutcome.Error);
        Assert.NotEqual(Guid.Empty, enrollmentSeed.EnrollmentId);
        Assert.NotNull(enrollmentSeed.IdentitySnapshot);
        var activationResponse = await activationTask;
        var activationBody = await activationResponse.Content.ReadAsStringAsync();
        Assert.True(activationResponse.StatusCode == HttpStatusCode.OK,
            $"Expected activation success, got {(int)activationResponse.StatusCode}: {activationBody}");
        if (finalizeOutcome.Error is DistributionOperationException rejection)
            Assert.Equal("hardware_already_bound", rejection.ErrorCode);
        else
            Assert.NotNull(finalizeOutcome.Result);

        await using var check = await directFactory.CreateDbContextAsync();
        var activeSeats = await check.LicenseSeats.Where(candidate =>
            candidate.IsActive
            && candidate.HardwareId == hardwareId
            && candidate.License != null
            && candidate.License.ProductId == productId).ToListAsync();
        Assert.Single(activeSeats);
        Assert.Equal(activationLicenseId, activeSeats[0].LicenseId);
        Assert.Equal(activationSeatId, activeSeats[0].Id);
        var bindings = await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == productId
            && candidate.HardwareIdHash == Sha256(hardwareId)).ToListAsync();
        if (finalizeOutcome.Error != null)
        {
            Assert.Empty(bindings);
        }
        else
        {
            var binding = Assert.Single(bindings);
            Assert.Equal("active", binding.State);
            Assert.Null(binding.InvalidationReason);
            Assert.Null(binding.InvalidatedAtUtc);
            Assert.False((await check.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == binding.LicenseSeatId)).IsActive);
            Assert.NotEqual(Guid.Empty, enrollmentSeed.EnrollmentId);
            Assert.NotNull(enrollmentSeed.IdentitySnapshot);
            Assert.Equal(enrollmentSeed.IdentitySnapshot,
                await SnapshotRetainedRuntimeIdentityAsync(directFactory, enrollmentSeed.EnrollmentId));
            var enrollment = await check.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentSeed.EnrollmentId);
            Assert.Equal(binding.Id, enrollment.BindingId);
            Assert.Equal("ACTIVE", enrollment.State);
            Assert.False(await check.EnrollmentLicenseAssignments.AnyAsync(candidate =>
                candidate.EnrollmentId == enrollment.Id && candidate.State == "ACTIVE"));
            var ended = Assert.Single(await check.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(candidate => candidate.EnrollmentId == enrollment.Id).ToListAsync());
            Assert.Equal("ENDED", ended.State);
            Assert.Equal("seat_released", ended.EndReason);
            Assert.NotNull(ended.EndedAtUtc);
            await AssertEndedAssignmentDeniesRuntimeAsync(directFactory, enrollment.Id);
        }

        // The winning seat remains legitimate; only assignments to inactive seats are forbidden.
        Assert.False(await check.EnrollmentLicenseAssignments.AnyAsync(assignment =>
            assignment.State == "ACTIVE"
            && check.LicenseSeats.Any(seat => seat.Id == assignment.LicenseSeatId && !seat.IsActive
                && seat.License != null && seat.License.ProductId == productId)));
    }

    [Fact]
    public async Task AutoTrial_ConcurrentWithDistributionFinalize_WaitsOnSharedExactHardwareLock()
    {
        var connections = await ProvisionAsync();
        var finalizeApplication = "sync-finalize-" + Guid.NewGuid().ToString("N");
        var activationApplication = "sync-activation-" + Guid.NewGuid().ToString("N");
        var finalizeConnection = new NpgsqlConnectionStringBuilder(connections.App)
            { ApplicationName = finalizeApplication, Pooling = false }.ConnectionString;
        var activationConnection = new NpgsqlConnectionStringBuilder(connections.App)
            { ApplicationName = activationApplication, Pooling = false }.ConnectionString;
        var productId = Guid.NewGuid();
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(productId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        var enrollmentSeed = new ConcurrentFinalizeEnrollmentSeed(runtimeOptions.Encryption.ActiveKeyId);
        var directFactory = new ConcurrentFinalizeEnrollmentFactory(finalizeConnection, enrollmentSeed);
        using var webFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(activationConnection));
            });
        });
        var client = webFactory.CreateClient();
        var now = new DateTimeOffset(2026, 7, 27, 17, 0, 0, TimeSpan.Zero);
        var paidTypeId = Guid.NewGuid();
        var trialTypeId = Guid.NewGuid();
        var finalizeLicenseId = Guid.NewGuid();
        var hardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        var appName = "Distribution auto-trial lock " + productId.ToString("N");
        const string version = "2.2.844";
        using (var scope = webFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
            var keys = LicenseService.GenerateKeys();
            db.Products.Add(new Product
            {
                Id = productId,
                Name = appName,
                PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
                PublicKeyXml = keys.PublicKey,
                ApiSecret = Guid.NewGuid().ToString("N")
            });
            db.LicenseTypes.AddRange(
                new LicenseType
                {
                    Id = paidTypeId,
                    ProductId = productId,
                    Name = "Distribution paid",
                    Slug = "distribution-paid-" + productId.ToString("N"),
                    IsFree = false
                },
                new LicenseType
                {
                    Id = trialTypeId,
                    ProductId = productId,
                    Name = "Trial",
                    Slug = "TRIAL",
                    IsFree = true,
                    AllowAnonymous = true,
                    DefaultDurationDays = 14
                });
            db.Licenses.Add(new License
            {
                Id = finalizeLicenseId,
                ProductId = productId,
                LicenseTypeId = paidTypeId,
                LicenseKey = "DIST-AUTO-TRIAL-FINALIZE-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "2.2.*",
                ExpirationDate = now.AddDays(1).UtcDateTime
            });
            db.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_EXE", Hash = new string('a', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_DLL", Hash = new string('b', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_CORE", Hash = new string('c', 64), Source = "release" });
            await db.SaveChangesAsync();
        }

        var distribution = new DistributionInstallationBindingService(
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await distribution.IssueEntitlementAsync(
            "website-step1",
            Sha256("auto-trial-lock-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = productId.ToString("D"),
                SoftLicenceLicenseId = finalizeLicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef)
            });
        var finalizeRequest = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("auto-trial-lock-handoff"),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
            ProductId = productId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = hardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = version,
                InstallerFilename = "distribution-auto-trial-lock.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var productHardwareLockName =
            $"distribution-product-hardware-seat:{productId:D}:{hardwareId}";
        await using var blocker = new NpgsqlConnection(connections.Admin);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var block = blocker.CreateCommand())
        {
            block.Transaction = blockerTransaction;
            block.CommandText = "SELECT pg_advisory_xact_lock(hashtextextended(@lock_name, 0));";
            block.Parameters.AddWithValue("lock_name", productHardwareLockName);
            await block.ExecuteNonQueryAsync();
        }

        var lockObservation = System.Diagnostics.Stopwatch.StartNew();
        var finalizeTask = CaptureAsync(() => distribution.FinalizeAsync(
            "website-step1", Sha256("auto-trial-lock-finalize"), finalizeRequest));
        await WaitForProductHardwareLockChainAsync(
            connections.Admin, productHardwareLockName, blocker.ProcessID,
            finalizeApplication, string.Empty, lockObservation);
        Assert.False(finalizeTask.IsCompleted);
        var activationTask = client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = "FREE-TRIAL",
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = version,
            CustomerEmail = "trial@example.test",
            CustomerName = "Trial test"
        });

        await WaitForProductHardwareLockChainAsync(
            connections.Admin, productHardwareLockName, blocker.ProcessID,
            finalizeApplication, activationApplication, lockObservation);
        Assert.False(finalizeTask.IsCompleted);
        Assert.False(activationTask.IsCompleted);
        await blockerTransaction.CommitAsync();

        var finalizeOutcome = await finalizeTask;
        // This ordered scenario must exercise real retained identity, never the rejected-Finalize branch.
        Assert.Null(finalizeOutcome.Error);
        Assert.NotEqual(Guid.Empty, enrollmentSeed.EnrollmentId);
        Assert.NotNull(enrollmentSeed.IdentitySnapshot);
        var activationResponse = await activationTask;
        var activationBody = await activationResponse.Content.ReadAsStringAsync();
        Assert.True(activationResponse.StatusCode == HttpStatusCode.OK,
            $"Expected auto-trial success, got {(int)activationResponse.StatusCode}: {activationBody}");
        if (finalizeOutcome.Error is DistributionOperationException rejection)
            Assert.Equal("hardware_already_bound", rejection.ErrorCode);
        else
            Assert.NotNull(finalizeOutcome.Result);

        await using var check = await directFactory.CreateDbContextAsync();
        var trialLicense = await check.Licenses.AsNoTracking()
            .SingleAsync(candidate => candidate.ProductId == productId
                && candidate.LicenseTypeId == trialTypeId
                && candidate.HardwareId == hardwareId);
        var activeSeats = await check.LicenseSeats.Where(candidate =>
            candidate.IsActive
            && candidate.HardwareId == hardwareId
            && candidate.License != null
            && candidate.License.ProductId == productId).ToListAsync();
        Assert.Single(activeSeats);
        Assert.Equal(trialLicense.Id, activeSeats[0].LicenseId);
        var bindings = await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == productId
            && candidate.HardwareIdHash == Sha256(hardwareId)).ToListAsync();
        if (finalizeOutcome.Error != null)
        {
            Assert.Empty(bindings);
        }
        else
        {
            var binding = Assert.Single(bindings);
            Assert.Equal("active", binding.State);
            Assert.Null(binding.InvalidationReason);
            Assert.Null(binding.InvalidatedAtUtc);
            Assert.False((await check.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == binding.LicenseSeatId)).IsActive);
            Assert.NotEqual(Guid.Empty, enrollmentSeed.EnrollmentId);
            Assert.NotNull(enrollmentSeed.IdentitySnapshot);
            Assert.Equal(enrollmentSeed.IdentitySnapshot,
                await SnapshotRetainedRuntimeIdentityAsync(directFactory, enrollmentSeed.EnrollmentId));
            var enrollment = await check.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentSeed.EnrollmentId);
            Assert.Equal(binding.Id, enrollment.BindingId);
            Assert.Equal("ACTIVE", enrollment.State);
            Assert.False(await check.EnrollmentLicenseAssignments.AnyAsync(candidate =>
                candidate.EnrollmentId == enrollment.Id && candidate.State == "ACTIVE"));
            var ended = Assert.Single(await check.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(candidate => candidate.EnrollmentId == enrollment.Id).ToListAsync());
            Assert.Equal("ENDED", ended.State);
            Assert.Equal("seat_released", ended.EndReason);
            Assert.NotNull(ended.EndedAtUtc);
            await AssertEndedAssignmentDeniesRuntimeAsync(directFactory, enrollment.Id);
        }

        // The winning seat remains legitimate; only assignments to inactive seats are forbidden.
        Assert.False(await check.EnrollmentLicenseAssignments.AnyAsync(assignment =>
            assignment.State == "ACTIVE"
            && check.LicenseSeats.Any(seat => seat.Id == assignment.LicenseSeatId && !seat.IsActive
                && seat.License != null && seat.License.ProductId == productId)));
    }

    [Fact]
    public async Task DistributionFinalize_CrossGenerationSameAuthority_IsAtomicIdempotentAndFailClosed()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        const string nextVersion = "2.2.845";
        await using (var seed = await factory.CreateDbContextAsync())
        {
            seed.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = fixture.ProductId, Version = nextVersion, Key = "FP_EXE", Hash = new string('1', 64), Source = "release" },
                new ApprovedBinary { ProductId = fixture.ProductId, Version = nextVersion, Key = "FP_DLL", Hash = new string('2', 64), Source = "release" },
                new ApprovedBinary { ProductId = fixture.ProductId, Version = nextVersion, Key = "FP_CORE", Hash = new string('3', 64), Source = "release" });
            await seed.SaveChangesAsync();
        }

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = new DateTimeOffset(2026, 7, 31, 9, 30, 0, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var installationId = Guid.NewGuid().ToString("D");
        var subjectRef = Convert.ToBase64String(SHA256.HashData("postgres-cross-generation-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        async Task<(string GrantRef, string EntitlementRef)> IssueAsync(string label, string subject)
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var issued = await service.IssueEntitlementAsync(
                "website-step1",
                Sha256(label + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef),
                    SubjectRef = subject
                });
            return (grantRef, issued.Response.EntitlementRef);
        }

        DistributionInstallationFinalizeRequest FinalizeRequest(
            string label,
            string grantRef,
            string entitlementRef,
            DateTimeOffset issuedAt,
            string version,
            char executable,
            char native,
            char core) => new()
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256(label + fixture.ProductId.ToString("D") + "-handoff"),
            HandoffIssuedAtUtc = FormatUtc(issuedAt),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(issuedAt.AddMinutes(1)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = entitlementRef,
            InstallationId = installationId,
            HardwareId = fixture.HardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = version,
                InstallerFilename = $"TiaConnect-Setup_v{version}.exe",
                InstallerSha256 = Sha256(label + "-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string(executable, 64) },
                new() { Key = "FP_DLL", Sha256 = new string(native, 64) },
                new() { Key = "FP_CORE", Sha256 = new string(core, 64) }
            ]
        };

        var originalAuthority = await IssueAsync("postgres-cross-generation-original", subjectRef);
        var originalRequest = FinalizeRequest(
            "postgres-cross-generation-original", originalAuthority.GrantRef,
            originalAuthority.EntitlementRef, now.AddMinutes(-15), fixture.Version, 'a', 'b', 'c');
        var original = await service.FinalizeAsync(
            "website-step1", Sha256("postgres-cross-generation-original-finalize"), originalRequest);
        var bindingId = Guid.Parse(original.Response.BindingId);
        var enrollmentId = Guid.NewGuid();
        long originalAuthorityEpoch;
        await using (var seedEnrollment = await factory.CreateDbContextAsync())
        {
            originalAuthorityEpoch = await seedEnrollment.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            seedEnrollment.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = "website-step1",
                BindingId = bindingId,
                ProductId = fixture.ProductId,
                LicenseId = fixture.LicenseId,
                LicenseSeatId = (await seedEnrollment.DistributionInstallationBindings.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == bindingId)).LicenseSeatId,
                InstallationId = installationId,
                HardwareIdHash = Sha256(fixture.HardwareId),
                ReleaseVersion = fixture.Version,
                HandoffDigestSha256 = originalRequest.HandoffDigestSha256!,
                SubjectRefDigestSha256 = Sha256(subjectRef),
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "cg-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 1,
                AuthorityEpoch = originalAuthorityEpoch,
                ChallengeExpiresAtUtc = DateTime.UtcNow.AddHours(1),
                CreatedAtUtc = DateTime.UtcNow.AddHours(-1),
                ActivatedAtUtc = DateTime.UtcNow.AddMinutes(-30)
            });
            await seedEnrollment.SaveChangesAsync();
        }

        var firstAuthority = await IssueAsync("postgres-cross-generation-first", subjectRef);
        var secondAuthority = await IssueAsync("postgres-cross-generation-second", subjectRef);
        var firstRequest = FinalizeRequest(
            "postgres-cross-generation-first", firstAuthority.GrantRef,
            firstAuthority.EntitlementRef, now.AddMinutes(-5), nextVersion, '1', '2', '3');
        var secondRequest = FinalizeRequest(
            "postgres-cross-generation-second", secondAuthority.GrantRef,
            secondAuthority.EntitlementRef, now.AddMinutes(-5), nextVersion, '1', '2', '3');
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstTask = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("postgres-cross-generation-first-finalize"), firstRequest));
        });
        var secondTask = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("postgres-cross-generation-second-finalize"), secondRequest));
        });
        start.SetResult();
        var outcomes = await Task.WhenAll(firstTask, secondTask);

        var winnerIndex = Array.FindIndex(outcomes, outcome => outcome.Error == null);
        Assert.True(winnerIndex >= 0);
        Assert.Single(outcomes, outcome => outcome.Error == null);
        var losingError = Assert.IsType<DistributionOperationException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error);
        Assert.Equal("binding_conflict", losingError.ErrorCode);
        Assert.Equal("cross_generation_handoff_not_newer", losingError.ReasonCode);
        var winnerRequest = winnerIndex == 0 ? firstRequest : secondRequest;
        var winnerDigest = winnerIndex == 0
            ? Sha256("postgres-cross-generation-first-finalize")
            : Sha256("postgres-cross-generation-second-finalize");
        var replay = await service.FinalizeAsync("website-step1", winnerDigest, winnerRequest);
        Assert.True(replay.Idempotent);
        Assert.Equal(original.Response.BindingId, replay.Response.BindingId);

        long rotationAuthorityEpoch;
        await using (var rotationCheck = await factory.CreateDbContextAsync())
        {
            var rotatedEnrollment = await rotationCheck.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentId);
            rotationAuthorityEpoch = await rotationCheck.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            Assert.Equal("INVALIDATED", rotatedEnrollment.State);
            Assert.Equal("binding_superseded", rotatedEnrollment.InvalidationReason);
            Assert.Equal(rotationAuthorityEpoch, rotatedEnrollment.AuthorityEpoch);
        }

        var divergentAuthority = await IssueAsync(
            "postgres-cross-generation-divergent",
            Convert.ToBase64String(SHA256.HashData("postgres-different-owner"u8.ToArray()))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        var divergentRequest = FinalizeRequest(
            "postgres-cross-generation-divergent", divergentAuthority.GrantRef,
            divergentAuthority.EntitlementRef, now.AddMinutes(-4), nextVersion, '1', '2', '3');
        var divergentError = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1", Sha256("postgres-cross-generation-divergent-finalize"), divergentRequest));
        Assert.Equal("binding_conflict", divergentError.ErrorCode);
        Assert.Equal("cross_generation_subject_mismatch", divergentError.ReasonCode);

        var recoveryAuthority = await IssueAsync("postgres-cross-generation-recovery", subjectRef);
        var recoveryRequest = FinalizeRequest(
            "postgres-cross-generation-recovery", recoveryAuthority.GrantRef,
            recoveryAuthority.EntitlementRef, now.AddMinutes(-3), nextVersion, '1', '2', '3');
        await using (var markSecurityTerminal = await factory.CreateDbContextAsync())
        {
            var binding = await markSecurityTerminal.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == bindingId);
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = now.AddMinutes(-2).UtcDateTime;
            binding.InvalidationReason = "security_lockdown";
            await markSecurityTerminal.SaveChangesAsync();
        }
        var securityTerminalError = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1",
                Sha256("postgres-cross-generation-recovery-finalize"),
                recoveryRequest));
        Assert.Equal("binding_conflict", securityTerminalError.ErrorCode);
        Assert.Equal("cross_generation_binding_inactive", securityTerminalError.ReasonCode);

        await using (var markRecoverableTerminal = await factory.CreateDbContextAsync())
        {
            var binding = await markRecoverableTerminal.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == bindingId);
            binding.InvalidationReason = "installation_superseded";
            await markRecoverableTerminal.SaveChangesAsync();
        }
        var recovered = await service.FinalizeAsync(
            "website-step1",
            Sha256("postgres-cross-generation-recovery-finalize"),
            recoveryRequest);
        Assert.False(recovered.Idempotent);
        Assert.Equal(original.Response.BindingId, recovered.Response.BindingId);

        await using var check = await factory.CreateDbContextAsync();
        var finalBinding = await check.DistributionInstallationBindings.SingleAsync(candidate => candidate.Id == bindingId);
        var supersededEnrollment = await check.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == enrollmentId);
        Assert.Equal("active", finalBinding.State);
        Assert.Null(finalBinding.InvalidatedAtUtc);
        Assert.Null(finalBinding.InvalidationReason);
        Assert.Equal(recoveryRequest.HandoffDigestSha256, finalBinding.HandoffDigestSha256);
        Assert.Equal(nextVersion, finalBinding.Version);
        Assert.Equal("INVALIDATED", supersededEnrollment.State);
        Assert.Equal("binding_superseded", supersededEnrollment.InvalidationReason);
        Assert.True(supersededEnrollment.AuthorityEpoch > originalAuthorityEpoch);
        Assert.Equal(rotationAuthorityEpoch, supersededEnrollment.AuthorityEpoch);
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == fixture.ProductId && candidate.State == "active").ToListAsync());
        Assert.Single(await check.LicenseSeats.Where(candidate =>
            candidate.LicenseId == fixture.LicenseId && candidate.IsActive).ToListAsync());
    }

    /// <summary>
    /// A new installation may recover the same authority only through the explicit V2 path.
    /// On a unique owned database, item-2 forbidden live-enrollment graph mutations must
    /// roll back with 23514, while admissible lineage corruptions reach the service's
    /// binding_conflict guard. The later V1/V2 Refresh sequence retains its exact epoch,
    /// replay and atomic recovery assertions. A divergent copied historical hardware hash
    /// remains observation-only; both variants still require current commercial rights.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistributionFinalize_NewInstallation_V1FailsClosedAndV2AtomicallyRecovers(
        bool divergentHistoricalHardware)
    {
        // This corruption/recovery matrix must not inherit bindings left by older shared-base
        // test runs. The harness owns and drops only its generated database on every exit path.
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (isolated.Admin, isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        // Assignment activation is timestamped by PostgreSQL after fixture setup.
        // Recovery must sample a live clock, never terminalize at the earlier seed instant.
        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var subjectRef = Convert.ToBase64String(SHA256.HashData("new-installation-same-authority"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        async Task<(string GrantRef, string EntitlementRef)> IssueAsync(string label)
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var issued = await service.IssueEntitlementAsync(
                "website-step1",
                Sha256(label + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef),
                    SubjectRef = subjectRef
                });
            return (grantRef, issued.Response.EntitlementRef);
        }

        DistributionInstallationFinalizeRequest FinalizeRequest(
            string label,
            (string GrantRef, string EntitlementRef) authority,
            string installationId,
            DateTimeOffset handoffIssuedAt) => new()
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = authority.GrantRef,
            HandoffDigestSha256 = Sha256(label + "-handoff"),
            HandoffIssuedAtUtc = FormatUtc(handoffIssuedAt),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(handoffIssuedAt.AddMinutes(1)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = authority.EntitlementRef,
            InstallationId = installationId,
            HardwareId = fixture.HardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
                InstallerSha256 = Sha256(label + "-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var sourceInstallationId = Guid.NewGuid().ToString("D");
        var sourceAuthority = await IssueAsync("new-installation-source");
        var sourceRequest = FinalizeRequest(
            "new-installation-source", sourceAuthority, sourceInstallationId, now.AddMinutes(-15));
        var source = await service.FinalizeAsync(
            "website-step1", Sha256("new-installation-source-finalize"), sourceRequest);
        var sourceBindingId = Guid.Parse(source.Response.BindingId);
        var sourceEnrollmentId = Guid.NewGuid();
        var decoyBindingId = Guid.NewGuid();
        var historicalHardwareHash = divergentHistoricalHardware ? new string('1', 64) : Sha256(fixture.HardwareId);
        long sourceAuthorityEpoch;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await seed.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            sourceAuthorityEpoch = await seed.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            var decoyGrant = Guid.NewGuid().ToString("D");
            seed.DistributionInstallationBindings.Add(new DistributionInstallationBinding
            {
                Id = decoyBindingId,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                EntitlementId = sourceBinding.EntitlementId,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                GrantRef = decoyGrant,
                GrantRefDigestSha256 = Sha256(decoyGrant),
                HandoffDigestSha256 = Sha256("new-installation-decoy-handoff"),
                HandoffIssuedAtUtc = now.AddMinutes(-20).UtcDateTime,
                HandoffExpiresAtUtc = now.AddMinutes(-10).UtcDateTime,
                DownloadCompletedAtUtc = now.AddMinutes(-19).UtcDateTime,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareIdHash = Sha256("NEW-INSTALLATION-DECOY-HWID"),
                Version = sourceBinding.Version,
                InstallerFilename = sourceBinding.InstallerFilename,
                InstallerSha256 = sourceBinding.InstallerSha256,
                ExecutableSha256 = sourceBinding.ExecutableSha256,
                NativeDllSha256 = sourceBinding.NativeDllSha256,
                CoreSha256 = sourceBinding.CoreSha256,
                ApprovedBinariesSource = sourceBinding.ApprovedBinariesSource,
                State = "invalidated",
                BoundAtUtc = now.AddMinutes(-20).UtcDateTime,
                InvalidatedAtUtc = now.AddMinutes(-10).UtcDateTime,
                InvalidationReason = "test_fixture"
            });
            seed.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = sourceEnrollmentId,
                ClientId = "website-step1",
                BindingId = sourceBinding.Id,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                InstallationId = sourceBinding.InstallationId,
                HardwareIdHash = historicalHardwareHash,
                ReleaseVersion = sourceBinding.Version,
                HandoffDigestSha256 = sourceBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "ni-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 4,
                AuthorityEpoch = sourceAuthorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddHours(-1).UtcDateTime,
                ActivatedAtUtc = now.AddMinutes(-30).UtcDateTime
            });
            await seed.SaveChangesAsync();
        }

        var targetAuthority = await IssueAsync("new-installation-target");
        var targetRequest = FinalizeRequest(
            "new-installation-target", targetAuthority, Guid.NewGuid().ToString("D"), now.AddMinutes(-5));

        DistributionInstallationBinding sourceBindingBaseline;
        await using (var baseline = await factory.CreateDbContextAsync())
        {
            sourceBindingBaseline = await baseline.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
        }
        Assert.Equal(divergentHistoricalHardware,
            historicalHardwareHash != sourceBindingBaseline.HardwareIdHash);
        // Neither equality nor divergence of the copied hash grants commercial authority.
        // Exercise an actual refusal before restoring the licence through its normal trigger.
        await using (var revoke = await factory.CreateDbContextAsync())
        {
            var license = await revoke.Licenses.SingleAsync(row => row.Id == fixture.LicenseId);
            license.IsActive = false;
            await revoke.SaveChangesAsync();
        }
        var commercialProbe = FinalizeRequest(
            "new-installation-commercial", targetAuthority, targetRequest.InstallationId!, now.AddMinutes(-5));
        commercialProbe.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
        commercialProbe.AllowSameAuthorityRecovery = true;
        var commercialRefusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync("website-step1", Sha256("new-installation-commercial-refusal"), commercialProbe));
        Assert.Equal("entitlement_ineligible", commercialRefusal.ErrorCode);
        await using (var restoreLicense = await factory.CreateDbContextAsync())
        {
            Assert.False(await restoreLicense.DistributionInstallationBindings.AnyAsync(row =>
                row.InstallationId == targetRequest.InstallationId));
            var original = await restoreLicense.RuntimeEnrollments.SingleAsync(row => row.Id == sourceEnrollmentId);
            Assert.Equal("ACTIVE", original.State);
            Assert.Equal(historicalHardwareHash, original.HardwareIdHash);
            var license = await restoreLicense.Licenses.SingleAsync(row => row.Id == fixture.LicenseId);
            license.IsActive = true;
            await restoreLicense.SaveChangesAsync();
        }
        // Item 2 rejects live commercial graph divergence at commit. Only fields outside
        // that trigger's comparison are allowed to reach the service-level lineage guard.
        var corruptions = new (string Field, object CorruptValue, object RestoreValue,
            bool DatabaseRejects)[]
        {
            ("ClientId", "other-website-client", "website-step1", false),
            ("BindingId", decoyBindingId, sourceBindingId, true),
            ("ProductId", Guid.NewGuid(), sourceBindingBaseline.ProductId, true),
            ("LicenseId", Guid.NewGuid(), sourceBindingBaseline.LicenseId, true),
            ("LicenseSeatId", Guid.NewGuid(), sourceBindingBaseline.LicenseSeatId, true),
            ("InstallationId", Guid.NewGuid().ToString("D"), sourceBindingBaseline.InstallationId, true),
            ("SubjectRefDigestSha256", new string('2', 64), sourceBindingBaseline.SubjectRefDigestSha256!, false),
            ("HandoffDigestSha256", new string('3', 64), sourceBindingBaseline.HandoffDigestSha256, true),
            ("ReleaseVersion", "2.2.843", sourceBindingBaseline.Version, true),
            ("ProtocolVersion", "runtime-enrollment-v0", RuntimeEnrollmentService.ProtocolVersion, false)
        };
        foreach (var (field, corruptValue, restoreValue, databaseRejects) in corruptions)
        {
            await using (var corrupt = await factory.CreateDbContextAsync())
            {
                await using var command = corrupt.Database.GetDbConnection().CreateCommand();
                await corrupt.Database.OpenConnectionAsync();
                command.CommandText = $"""
                    UPDATE public."RuntimeEnrollments"
                    SET "{field}" = @value
                    WHERE "Id" = @id
                    """;
                command.Parameters.Add(new NpgsqlParameter("value", corruptValue));
                command.Parameters.Add(new NpgsqlParameter("id", sourceEnrollmentId));
                if (databaseRejects)
                {
                    var rejected = await Assert.ThrowsAsync<PostgresException>(() =>
                        command.ExecuteNonQueryAsync());
                    Assert.Equal("23514", rejected.SqlState);
                    Assert.Equal("unresolved commercial assignment graph: binding_mismatch",
                        rejected.MessageText);
                }
                else
                {
                    Assert.Equal(1, await command.ExecuteNonQueryAsync());
                }
            }

            if (databaseRejects)
            {
                await using var unchanged = new NpgsqlConnection(connections.Admin);
                await unchanged.OpenAsync();
                await using var read = new NpgsqlCommand($"""
                    SELECT "{field}" FROM public."RuntimeEnrollments" WHERE "Id" = @id;
                    """, unchanged);
                read.Parameters.AddWithValue("id", sourceEnrollmentId);
                Assert.Equal(restoreValue, await read.ExecuteScalarAsync());
                continue;
            }

            var probe = FinalizeRequest(
                "new-installation-target", targetAuthority, targetRequest.InstallationId!, now.AddMinutes(-5));
            probe.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
            probe.AllowSameAuthorityRecovery = true;
            DistributionOperationException mismatch;
            try
            {
                mismatch = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                    service.FinalizeAsync(
                        "website-step1", Sha256("new-installation-lineage-" + field), probe));
            }
            catch (Xunit.Sdk.XunitException assertion)
            {
                // Keep the original assertion as the cause while identifying this loop case.
                throw new InvalidOperationException($"Finalize corruption scenario failed: {field}.", assertion);
            }
            Assert.Equal("binding_conflict", mismatch.ErrorCode);

            await using (var verify = await factory.CreateDbContextAsync())
            {
                Assert.Equal("active", (await verify.DistributionInstallationBindings.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == sourceBindingId)).State);
                Assert.False(await verify.DistributionInstallationBindings.AsNoTracking().AnyAsync(
                    candidate => candidate.InstallationId == targetRequest.InstallationId));
                Assert.Equal("ACTIVE", (await verify.RuntimeEnrollments.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == sourceEnrollmentId)).State);
            }

            await using (var restore = await factory.CreateDbContextAsync())
            {
                await using var command = restore.Database.GetDbConnection().CreateCommand();
                await restore.Database.OpenConnectionAsync();
                command.CommandText = $"""
                    UPDATE public."RuntimeEnrollments"
                    SET "{field}" = @value
                    WHERE "Id" = @id
                    """;
                command.Parameters.Add(new NpgsqlParameter("value", restoreValue));
                command.Parameters.Add(new NpgsqlParameter("id", sourceEnrollmentId));
                Assert.Equal(1, await command.ExecuteNonQueryAsync());
            }
        }

        var rejection = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(
                "website-step1", Sha256("new-installation-target-finalize"), targetRequest));

        Assert.Equal("binding_conflict", rejection.ErrorCode);
        await using var check = await factory.CreateDbContextAsync();
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == fixture.ProductId
            && candidate.HardwareIdHash == Sha256(fixture.HardwareId)
            && candidate.State == "active").ToListAsync());
        var sourceBindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceBindingId);
        var sourceEnrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
        Assert.Equal("active", sourceBindingAfter.State);
        Assert.Equal("ACTIVE", sourceEnrollmentAfter.State);
        Assert.Equal(historicalHardwareHash, sourceEnrollmentAfter.HardwareIdHash);
        Assert.Equal(4, sourceEnrollmentAfter.SecurityEpoch);

        targetRequest.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
        targetRequest.AllowSameAuthorityRecovery = true;
        var targetDigest = Sha256("new-installation-target-finalize-v2");
        await using (var admin = new NpgsqlConnection(connections.Admin))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, """
                CREATE OR REPLACE FUNCTION public.test_fail_same_authority_recovery_finalize()
                RETURNS trigger LANGUAGE plpgsql AS $failure$
                BEGIN
                    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'forced recovery finalize failure';
                END
                $failure$;
                """);
            await ExecuteAsync(admin, $"""
                CREATE TRIGGER test_fail_same_authority_recovery_finalize
                BEFORE INSERT ON public."DistributionBindingRequests"
                FOR EACH ROW
                WHEN (NEW."Operation" = 'finalize_binding' AND NEW."RequestId" = '{targetRequest.RequestId}')
                EXECUTE FUNCTION public.test_fail_same_authority_recovery_finalize();
                """);
        }
        try
        {
            var forcedFailure = await Assert.ThrowsAsync<DbUpdateException>(() => service.FinalizeAsync(
                "website-step1", targetDigest, targetRequest));
            Assert.Equal("P0001", Assert.IsType<PostgresException>(forcedFailure.InnerException).SqlState);
        }
        finally
        {
            await using var admin = new NpgsqlConnection(connections.Admin);
            await admin.OpenAsync();
            await ExecuteAsync(admin, """
                DROP TRIGGER IF EXISTS test_fail_same_authority_recovery_finalize
                    ON public."DistributionBindingRequests";
                DROP FUNCTION IF EXISTS public.test_fail_same_authority_recovery_finalize();
                """);
        }
        await using (var rollbackCheck = await factory.CreateDbContextAsync())
        {
            Assert.Equal("active", (await rollbackCheck.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId)).State);
            Assert.Equal("ACTIVE", (await rollbackCheck.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceEnrollmentId)).State);
            Assert.False(await rollbackCheck.DistributionInstallationBindings.AsNoTracking().AnyAsync(
                candidate => candidate.InstallationId == targetRequest.InstallationId));
        }

        var competingAuthority = await IssueAsync("new-installation-competing-target");
        var competingRequest = FinalizeRequest(
            "new-installation-competing-target",
            competingAuthority,
            Guid.NewGuid().ToString("D"),
            now.AddMinutes(-4));
        competingRequest.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
        competingRequest.AllowSameAuthorityRecovery = true;
        var competingDigest = Sha256("new-installation-competing-target-finalize-v2");
        var startRecovery = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstRecovery = Task.Run(async () =>
        {
            await startRecovery.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", targetDigest, targetRequest));
        });
        var secondRecovery = Task.Run(async () =>
        {
            await startRecovery.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", competingDigest, competingRequest));
        });
        startRecovery.SetResult();
        var recoveryOutcomes = await Task.WhenAll(firstRecovery, secondRecovery);
        var winnerIndex = Array.FindIndex(recoveryOutcomes, outcome => outcome.Error == null);
        Assert.True(winnerIndex >= 0, string.Join("; ", recoveryOutcomes.Select(outcome =>
            outcome.Error is DistributionOperationException refusal
                ? $"{refusal.ErrorCode}/{refusal.ReasonCode}"
                : outcome.Error?.GetBaseException() is PostgresException databaseFailure
                    ? $"{databaseFailure.SqlState}/{databaseFailure.MessageText}"
                : outcome.Error?.GetType().Name ?? "accepted")));
        Assert.Single(recoveryOutcomes, outcome => outcome.Error == null);
        Assert.Equal("binding_conflict", Assert.IsType<DistributionOperationException>(
            Assert.Single(recoveryOutcomes, outcome => outcome.Error != null).Error).ErrorCode);
        var recovered = recoveryOutcomes[winnerIndex].Result!;
        var winnerRequest = winnerIndex == 0 ? targetRequest : competingRequest;
        var winnerDigest = winnerIndex == 0 ? targetDigest : competingDigest;
        var replay = await service.FinalizeAsync("website-step1", winnerDigest, winnerRequest);

        Assert.False(recovered.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(recovered.Response, replay.Response);
        await using var recoveredCheck = await factory.CreateDbContextAsync();
        var bindings = await recoveredCheck.DistributionInstallationBindings.AsNoTracking()
            .Where(candidate => candidate.ProductId == fixture.ProductId
                && candidate.HardwareIdHash == Sha256(fixture.HardwareId))
            .OrderBy(candidate => candidate.BoundAtUtc)
            .ToListAsync();
        Assert.Equal(2, bindings.Count);
        var oldBinding = Assert.Single(bindings, candidate => candidate.Id == sourceBindingId);
        var newBinding = Assert.Single(bindings, candidate => candidate.Id != sourceBindingId);
        Assert.Equal("invalidated", oldBinding.State);
        Assert.Equal("installation_superseded", oldBinding.InvalidationReason);
        Assert.Equal("active", newBinding.State);
        Assert.Equal(sourceBindingId, newBinding.SupersededBindingId);
        Assert.Equal(5, newBinding.InitialSecurityEpoch);
        Assert.Equal(winnerRequest.InstallationId, newBinding.InstallationId);
        var invalidatedEnrollment = await recoveredCheck.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
        Assert.Equal("INVALIDATED", invalidatedEnrollment.State);
        Assert.Equal("binding_superseded", invalidatedEnrollment.InvalidationReason);
        Assert.Equal(historicalHardwareHash, invalidatedEnrollment.HardwareIdHash);
        var finalAuthorityEpoch = await recoveredCheck.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1)
            .Select(candidate => candidate.Epoch)
            .SingleAsync();
        Assert.True(finalAuthorityEpoch > sourceAuthorityEpoch);
        Assert.Equal(finalAuthorityEpoch, invalidatedEnrollment.AuthorityEpoch);
        Assert.Single(bindings, candidate => candidate.State == "active");

        using var recoveredKey = RSA.Create(3072);
        var authorityService = new RuntimeEnrollmentAuthorityService(factory, Options.Create(runtimeOptions));
        var registryService = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(runtimeOptions));
        using var cryptoService = new RuntimeEnrollmentCryptoService(Options.Create(runtimeOptions));
        var runtimeService = new RuntimeEnrollmentService(
            factory, authorityService, registryService, cryptoService, Options.Create(runtimeOptions));
        var prepareRequest = PrepareRequest(
            (fixture.ProductId, newBinding.Id, newBinding.HandoffDigestSha256,
                newBinding.InstallationId, newBinding.Version),
            Guid.NewGuid().ToString("D"), recoveredKey);
        var v1Rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => runtimeService.PrepareAsync(
            "website-step1", Sha256("new-installation-recovered-prepare-v1"), prepareRequest));
        Assert.Equal(StatusCodes.Status426UpgradeRequired, v1Rejected.StatusCode);
        Assert.Equal("prepare_v2_required", v1Rejected.ErrorCode);
        await using (var rejectedCheck = await factory.CreateDbContextAsync())
        {
            Assert.False(await rejectedCheck.RuntimeEnrollments.AsNoTracking()
                .AnyAsync(candidate => candidate.BindingId == newBinding.Id));
            Assert.False(await rejectedCheck.RuntimeEnrollmentQuotas.AsNoTracking()
                .AnyAsync(candidate => candidate.Scope == "prepare-binding"
                    && candidate.SubjectPseudonym == newBinding.Id.ToString("D")));
        }

        prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var prepared = await runtimeService.PrepareAsync(
            "website-step1", Sha256("new-installation-recovered-prepare"), prepareRequest);
        Assert.Equal(RuntimeEnrollmentService.PrepareV2ResponseSchema, prepared.Response.Schema);
        Assert.Equal(5, prepared.Response.SecurityEpoch);
        var recoveredEnrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        await using (var preparedCheck = await factory.CreateDbContextAsync())
        {
            var recoveredEnrollment = await preparedCheck.RuntimeEnrollments
                .SingleAsync(candidate => candidate.Id == recoveredEnrollmentId);
            Assert.Equal(5, recoveredEnrollment.SecurityEpoch);
            var recoveredBinding = await preparedCheck.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == newBinding.Id);
            Assert.NotNull(recoveredBinding.HandoffExpiresAtUtc);
            preparedCheck.DistributionLicenseBootstrapAuthorizations.Add(new DistributionLicenseBootstrapAuthorization
            {
                Id = Guid.NewGuid(),
                ProductId = recoveredEnrollment.ProductId,
                LicenseId = recoveredEnrollment.LicenseId,
                LicenseSeatId = recoveredEnrollment.LicenseSeatId,
                EntitlementId = recoveredBinding.EntitlementId,
                BindingId = recoveredEnrollment.BindingId,
                RuntimeEnrollmentId = recoveredEnrollment.Id,
                ClientId = recoveredEnrollment.ClientId,
                GrantRefDigestSha256 = recoveredBinding.GrantRefDigestSha256,
                SubjectRefDigestSha256 = recoveredEnrollment.SubjectRefDigestSha256!,
                HandoffDigestSha256 = recoveredEnrollment.HandoffDigestSha256,
                InstallationId = recoveredEnrollment.InstallationId,
                HardwareIdHash = recoveredEnrollment.HardwareIdHash,
                ReleaseVersion = recoveredBinding.Version,
                ApprovedBinariesDigestSha256 = Sha256(string.Join('\n',
                    recoveredBinding.ExecutableSha256,
                    recoveredBinding.NativeDllSha256,
                    recoveredBinding.CoreSha256)),
                RuntimePublicKeySpkiSha256 = recoveredEnrollment.PublicKeySpkiSha256,
                RuntimeKeyThumbprint = recoveredEnrollment.KeyThumbprint,
                RuntimeEpoch = recoveredEnrollment.Epoch,
                SecurityEpoch = recoveredEnrollment.SecurityEpoch,
                AuthorityEpoch = recoveredEnrollment.AuthorityEpoch,
                Audience = DistributionLicenseBootstrapService.Audience,
                Use = "license-bootstrap",
                State = "CONSUMED",
                IssuedAtUtc = recoveredBinding.BoundAtUtc,
                ExpiresAtUtc = recoveredBinding.HandoffExpiresAtUtc.Value,
                ConsumedAtUtc = recoveredBinding.BoundAtUtc,
                ReplayExpiresAtUtc = recoveredBinding.HandoffExpiresAtUtc.Value
            });
            await preparedCheck.SaveChangesAsync();
        }

        var refreshRequest = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = newBinding.Id.ToString("D"),
            EnrollmentId = recoveredEnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(prepared.Response.Challenge)
        };
        var refreshV1Rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            runtimeService.RefreshPendingAsync(
                "website-step1", Sha256("new-installation-recovered-refresh-v1"), refreshRequest));
        Assert.Equal(StatusCodes.Status426UpgradeRequired, refreshV1Rejected.StatusCode);
        Assert.Equal("refresh_v2_required", refreshV1Rejected.ErrorCode);
        await using (var rejectedRefreshCheck = await factory.CreateDbContextAsync())
        {
            var unchanged = await rejectedRefreshCheck.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == recoveredEnrollmentId);
            Assert.Equal(Sha256(prepared.Response.Challenge), unchanged.ChallengeDigestSha256);
            Assert.False(await rejectedRefreshCheck.RuntimeEnrollmentRequests.AsNoTracking()
                .AnyAsync(candidate => candidate.RequestId == refreshRequest.RequestId));
            Assert.False(await rejectedRefreshCheck.RuntimeEnrollmentQuotas.AsNoTracking()
                .AnyAsync(candidate => candidate.Scope == "refresh-binding"
                    && candidate.SubjectPseudonym == newBinding.Id.ToString("D")));
        }

        refreshRequest.Schema = RuntimeEnrollmentService.RefreshV2Schema;
        refreshRequest.RequestId = Guid.NewGuid().ToString("D");
        refreshRequest.ExpectedSecurityEpoch = 4;
        var staleRefresh = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            runtimeService.RefreshPendingAsync(
                "website-step1", Sha256("new-installation-recovered-refresh-stale"), refreshRequest));
        Assert.Equal(StatusCodes.Status409Conflict, staleRefresh.StatusCode);
        Assert.Equal("security_epoch_mismatch", staleRefresh.ErrorCode);

        refreshRequest.RequestId = Guid.NewGuid().ToString("D");
        refreshRequest.ExpectedSecurityEpoch = 5;
        var refreshDigest = Sha256("new-installation-recovered-refresh-v2");
        var refreshed = await runtimeService.RefreshPendingAsync(
            "website-step1", refreshDigest, refreshRequest);
        var refreshedReplay = await runtimeService.RefreshPendingAsync(
            "website-step1", refreshDigest, refreshRequest);
        Assert.Equal(RuntimeEnrollmentService.RefreshV2ResponseSchema, refreshed.Response.Schema);
        Assert.Equal(5, refreshed.Response.SecurityEpoch);
        Assert.True(refreshedReplay.Idempotent);
        Assert.Equal(refreshed.ExactResponseBody, refreshedReplay.ExactResponseBody);
    }

    /// <summary>
    /// Isolates every negative mutation and the healthy recovery in a fresh database. Quarantine
    /// evidence is never deleted to manufacture a clean authority; all original checks remain.
    /// </summary>
    [Theory]
    [InlineData("healthy")]
    [InlineData("challenge-consumed")]
    [InlineData("formerly-activated")]
    [InlineData("future-expiry")]
    [InlineData("future-invalidation")]
    [InlineData("invalidation-before-expiry")]
    [InlineData("missing-invalidation-time")]
    [InlineData("security-terminal")]
    [InlineData("pending-identity")]
    [InlineData("client-divergence")]
    [InlineData("protocol-divergence")]
    [InlineData("multiple-expired-history")]
    [InlineData("quarantined-history")]
    [InlineData("open-critical-incident")]
    public async Task DistributionFinalize_NewInstallation_SoleExpiredUnactivatedEnrollment_RecoversWithoutRewritingForensicEvidence(
        string scenarioKind)
    {
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (Admin: isolated.Admin, App: isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var subjectRef = Convert.ToBase64String(SHA256.HashData("expired-enrollment-same-authority"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        async Task<(string GrantRef, string EntitlementRef)> IssueAsync(string label)
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var issued = await service.IssueEntitlementAsync(
                "website-step1",
                Sha256(label + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef),
                    SubjectRef = subjectRef
                });
            return (grantRef, issued.Response.EntitlementRef);
        }

        DistributionInstallationFinalizeRequest FinalizeRequest(
            string label,
            (string GrantRef, string EntitlementRef) authority,
            string installationId,
            DateTimeOffset handoffIssuedAt) => new()
        {
            Schema = DistributionInstallationBindingService.FinalizeV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = authority.GrantRef,
            HandoffDigestSha256 = Sha256(label + "-handoff"),
            HandoffIssuedAtUtc = FormatUtc(handoffIssuedAt),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(handoffIssuedAt.AddMinutes(1)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = authority.EntitlementRef,
            InstallationId = installationId,
            HardwareId = fixture.HardwareId,
            AllowSameAuthorityRecovery = true,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
                InstallerSha256 = Sha256(label + "-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var sourceInstallationId = Guid.NewGuid().ToString("D");
        var sourceAuthority = await IssueAsync("expired-enrollment-source");
        var sourceRequest = FinalizeRequest(
            "expired-enrollment-source", sourceAuthority, sourceInstallationId, now.AddMinutes(-15));
        var source = await service.FinalizeAsync(
            "website-step1", Sha256("expired-enrollment-source-finalize"), sourceRequest);
        var sourceBindingId = Guid.Parse(source.Response.BindingId);
        var sourceEnrollmentId = Guid.NewGuid();
        Guid sourceLicenseSeatId;
        var challengeExpiresAtRaw = now.AddMinutes(-5).UtcDateTime;
        var challengeExpiresAtUtc = new DateTime(
            challengeExpiresAtRaw.Ticks - (challengeExpiresAtRaw.Ticks % TimeSpan.TicksPerMicrosecond),
            DateTimeKind.Utc);
        var invalidatedAtRaw = now.AddMinutes(-4).UtcDateTime;
        var invalidatedAtUtc = new DateTime(
            invalidatedAtRaw.Ticks - (invalidatedAtRaw.Ticks % TimeSpan.TicksPerMicrosecond),
            DateTimeKind.Utc);
        long sourceAuthorityEpoch;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await seed.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            // This is historical abandoned authority: its binding predates the enrollment and terminal evidence.
            sourceBinding.BoundAtUtc = now.AddMinutes(-35).UtcDateTime;
            (await seed.LicenseSeats.SingleAsync(row => row.Id == sourceBinding.LicenseSeatId))
                .FirstActivatedAt = now.AddMinutes(-40).UtcDateTime;
            sourceLicenseSeatId = sourceBinding.LicenseSeatId;
            sourceAuthorityEpoch = await seed.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync();
            seed.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = sourceEnrollmentId,
                ClientId = "website-step1",
                BindingId = sourceBinding.Id,
                ProductId = sourceBinding.ProductId,
                LicenseId = sourceBinding.LicenseId,
                LicenseSeatId = sourceBinding.LicenseSeatId,
                InstallationId = sourceBinding.InstallationId,
                HardwareIdHash = sourceBinding.HardwareIdHash,
                ReleaseVersion = sourceBinding.Version,
                HandoffDigestSha256 = sourceBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = sourceBinding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "expired-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                // Seed pending directly: SQL correctly forbids resurrecting a terminal enrollment.
                State = scenarioKind == "pending-identity" ? "PENDING" : "INVALIDATED",
                Epoch = 1,
                SecurityEpoch = 4,
                AuthorityEpoch = sourceAuthorityEpoch,
                ChallengeExpiresAtUtc = challengeExpiresAtUtc,
                CreatedAtUtc = now.AddMinutes(-30).UtcDateTime,
                InvalidatedAtUtc = scenarioKind == "pending-identity" ? null : invalidatedAtUtc,
                InvalidationReason = scenarioKind == "pending-identity" ? null : "challenge_expired"
            });
            await seed.SaveChangesAsync();
            Assert.True(sourceBinding.BoundAtUtc < now.AddMinutes(-30).UtcDateTime);
            Assert.True(invalidatedAtUtc >= sourceBinding.BoundAtUtc);
            Assert.False(await seed.EnrollmentLicenseAssignmentQuarantines.AnyAsync(row =>
                row.EnrollmentId == sourceEnrollmentId));
        }

        var targetAuthority = await IssueAsync("expired-enrollment-target");
        var targetRequest = FinalizeRequest(
            "expired-enrollment-target",
            targetAuthority,
            Guid.NewGuid().ToString("D"),
            now.AddMinutes(-2));

        async Task AssertRecoveryRefusedWithoutMutationAsync(string label)
        {
            long authorityEpochBefore;
            RuntimeEnrollment enrollmentBefore;
            await using (var before = await factory.CreateDbContextAsync())
            {
                authorityEpochBefore = await before.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                    .Where(candidate => candidate.Id == 1)
                    .Select(candidate => candidate.Epoch)
                    .SingleAsync();
                enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
            }
            var probe = FinalizeRequest(
                "expired-enrollment-probe-" + label,
                targetAuthority,
                Guid.NewGuid().ToString("D"),
                now.AddMinutes(-2));
            var error = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                "website-step1", Sha256("expired-enrollment-probe-" + label), probe));
            Assert.Equal("binding_conflict", error.ErrorCode);

            await using var verify = await factory.CreateDbContextAsync();
            var unchangedBinding = await verify.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
            var unchangedEnrollment = await verify.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
            Assert.Equal("active", unchangedBinding.State);
            Assert.Equal(enrollmentBefore.State, unchangedEnrollment.State);
            Assert.Equal(enrollmentBefore.InvalidationReason, unchangedEnrollment.InvalidationReason);
            Assert.Equal(enrollmentBefore.SecurityEpoch, unchangedEnrollment.SecurityEpoch);
            Assert.Equal(enrollmentBefore.ChallengeExpiresAtUtc, unchangedEnrollment.ChallengeExpiresAtUtc);
            Assert.Equal(enrollmentBefore.ChallengeConsumedAtUtc, unchangedEnrollment.ChallengeConsumedAtUtc);
            Assert.Equal(enrollmentBefore.ActivatedAtUtc, unchangedEnrollment.ActivatedAtUtc);
            Assert.Equal(enrollmentBefore.InvalidatedAtUtc, unchangedEnrollment.InvalidatedAtUtc);
            Assert.Equal(enrollmentBefore.ClientId, unchangedEnrollment.ClientId);
            Assert.Equal(enrollmentBefore.BindingId, unchangedEnrollment.BindingId);
            Assert.Equal(enrollmentBefore.ProductId, unchangedEnrollment.ProductId);
            Assert.Equal(enrollmentBefore.LicenseId, unchangedEnrollment.LicenseId);
            Assert.Equal(enrollmentBefore.LicenseSeatId, unchangedEnrollment.LicenseSeatId);
            Assert.Equal(enrollmentBefore.InstallationId, unchangedEnrollment.InstallationId);
            Assert.Equal(enrollmentBefore.HardwareIdHash, unchangedEnrollment.HardwareIdHash);
            Assert.Equal(enrollmentBefore.SubjectRefDigestSha256, unchangedEnrollment.SubjectRefDigestSha256);
            Assert.Equal(enrollmentBefore.HandoffDigestSha256, unchangedEnrollment.HandoffDigestSha256);
            Assert.Equal(enrollmentBefore.ReleaseVersion, unchangedEnrollment.ReleaseVersion);
            Assert.Equal(enrollmentBefore.ProtocolVersion, unchangedEnrollment.ProtocolVersion);
            Assert.Equal(enrollmentBefore.Epoch, unchangedEnrollment.Epoch);
            Assert.False(await verify.DistributionInstallationBindings.AsNoTracking()
                .AnyAsync(candidate => candidate.InstallationId == probe.InstallationId));
            Assert.Equal(authorityEpochBefore, await verify.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync());
        }

        async Task MutateEnrollmentAsync(Action<RuntimeEnrollment> mutation)
        {
            await using var mutate = await factory.CreateDbContextAsync();
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
            mutation(enrollment);
            await mutate.SaveChangesAsync();
        }

        var rejectedMutations = new (string Label, Action<RuntimeEnrollment> Mutate)[]
        {
            ("challenge-consumed", enrollment => enrollment.ChallengeConsumedAtUtc = now.AddMinutes(-6).UtcDateTime),
            ("formerly-activated", enrollment => enrollment.ActivatedAtUtc = now.AddMinutes(-10).UtcDateTime),
            ("future-expiry", enrollment => enrollment.ChallengeExpiresAtUtc = now.AddMinutes(5).UtcDateTime),
            ("future-invalidation", enrollment => enrollment.InvalidatedAtUtc = now.AddMinutes(5).UtcDateTime),
            ("invalidation-before-expiry", enrollment => enrollment.InvalidatedAtUtc = now.AddMinutes(-6).UtcDateTime),
            ("missing-invalidation-time", enrollment => enrollment.InvalidatedAtUtc = null),
            ("security-terminal", enrollment => enrollment.InvalidationReason = "security_lockdown"),
            ("pending-identity", enrollment => enrollment.State = "PENDING"),
            ("client-divergence", enrollment => enrollment.ClientId = "other-website-client"),
            ("protocol-divergence", enrollment => enrollment.ProtocolVersion = "runtime-enrollment-v0")
        };
        var rejected = rejectedMutations.SingleOrDefault(candidate => candidate.Label == scenarioKind);
        if (rejected.Mutate != null)
        {
            await MutateEnrollmentAsync(rejected.Mutate);
            await AssertRecoveryRefusedWithoutMutationAsync(rejected.Label);
            return;
        }
        if (scenarioKind is "multiple-expired-history" or "quarantined-history")
        {
            var secondExpiredEnrollmentId = Guid.NewGuid();
            await using (var addHistory = await factory.CreateDbContextAsync())
            {
                var sourceEnrollment = await addHistory.RuntimeEnrollments.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
                addHistory.RuntimeEnrollments.Add(new RuntimeEnrollment
                {
                    Id = secondExpiredEnrollmentId,
                    ClientId = sourceEnrollment.ClientId,
                    BindingId = sourceEnrollment.BindingId,
                    ProductId = sourceEnrollment.ProductId,
                    LicenseId = sourceEnrollment.LicenseId,
                    LicenseSeatId = sourceEnrollment.LicenseSeatId,
                    InstallationId = sourceEnrollment.InstallationId,
                    HardwareIdHash = sourceEnrollment.HardwareIdHash,
                    ReleaseVersion = sourceEnrollment.ReleaseVersion,
                    HandoffDigestSha256 = sourceEnrollment.HandoffDigestSha256,
                    SubjectRefDigestSha256 = sourceEnrollment.SubjectRefDigestSha256,
                    ProtocolVersion = sourceEnrollment.ProtocolVersion,
                    Algorithm = sourceEnrollment.Algorithm,
                    KeyBackend = sourceEnrollment.KeyBackend,
                    AttestationLevel = sourceEnrollment.AttestationLevel,
                    PublicKeySpkiCiphertext = "test-history",
                    PublicKeySpkiKeyId = sourceEnrollment.PublicKeySpkiKeyId,
                    PublicKeySpkiSha256 = new string('f', 64),
                    KeyThumbprint = "eh-" + Guid.NewGuid().ToString("N"),
                    ChallengeCiphertext = "test-history",
                    ChallengeKeyId = sourceEnrollment.ChallengeKeyId,
                    ChallengeDigestSha256 = new string('a', 64),
                    State = "INVALIDATED",
                    Epoch = 1,
                    SecurityEpoch = 3,
                    AuthorityEpoch = sourceEnrollment.AuthorityEpoch,
                    ChallengeExpiresAtUtc = now.AddMinutes(-8).UtcDateTime,
                    CreatedAtUtc = now.AddMinutes(-40).UtcDateTime,
                    InvalidatedAtUtc = now.AddMinutes(scenarioKind == "quarantined-history" ? -36 : -7).UtcDateTime,
                    InvalidationReason = "challenge_expired"
                });
                await addHistory.SaveChangesAsync();
            }
            await AssertRecoveryRefusedWithoutMutationAsync("multiple-expired-history");
            await using var preserved = await factory.CreateDbContextAsync();
            Assert.True(await preserved.RuntimeEnrollments.AnyAsync(row => row.Id == secondExpiredEnrollmentId));
            Assert.Equal(scenarioKind == "quarantined-history", await preserved.EnrollmentLicenseAssignmentQuarantines.AnyAsync(row =>
                row.EnrollmentId == secondExpiredEnrollmentId));
            return;
        }

        if (scenarioKind == "open-critical-incident")
        {
            var criticalIncidentId = Guid.NewGuid();
            var adminFactory = new TestDbFactory(connections.Admin);
            await using (var addIncident = await adminFactory.CreateDbContextAsync())
            {
                addIncident.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
                {
                    Id = criticalIncidentId,
                    EnrollmentId = sourceEnrollmentId,
                    BindingId = sourceBindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = sourceInstallationId,
                    EventId = "expired-recovery-critical-incident",
                    Trigger = "test_open_critical_incident",
                    State = "OPEN",
                    OpenedSecurityEpoch = 4,
                    OpenedAuthorityEpoch = sourceAuthorityEpoch,
                    OpenedAtUtc = now.AddMinutes(-3).UtcDateTime
                });
                await addIncident.SaveChangesAsync();
            }
            await AssertRecoveryRefusedWithoutMutationAsync("open-critical-incident");
            return;
        }

        var competingAuthority = await IssueAsync("expired-enrollment-competing-target");
        var competingRequest = FinalizeRequest(
            "expired-enrollment-competing-target",
            competingAuthority,
            Guid.NewGuid().ToString("D"),
            now.AddMinutes(-1));
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstRecovery = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("expired-enrollment-target-finalize"), targetRequest));
        });
        var secondRecovery = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("expired-enrollment-competing-finalize"), competingRequest));
        });
        start.SetResult();
        var outcomes = await Task.WhenAll(firstRecovery, secondRecovery);
        var winnerIndex = Array.FindIndex(outcomes, outcome => outcome.Error == null);
        Assert.True(winnerIndex >= 0);
        Assert.Single(outcomes, outcome => outcome.Error == null);
        Assert.Equal("binding_conflict", Assert.IsType<DistributionOperationException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error).ErrorCode);
        var recovered = outcomes[winnerIndex].Result!;
        var winnerRequest = winnerIndex == 0 ? targetRequest : competingRequest;

        Assert.False(recovered.Idempotent);
        await using var check = await factory.CreateDbContextAsync();
        var sourceBindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceBindingId);
        var successor = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == Guid.Parse(recovered.Response.BindingId));
        var expiredEnrollment = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == sourceEnrollmentId);
        Assert.Equal("invalidated", sourceBindingAfter.State);
        Assert.Equal("installation_superseded", sourceBindingAfter.InvalidationReason);
        Assert.Equal("active", successor.State);
        Assert.Equal(sourceBindingId, successor.SupersededBindingId);
        Assert.Equal(5, successor.InitialSecurityEpoch);
        Assert.Equal(winnerRequest.InstallationId, successor.InstallationId);
        Assert.Equal("INVALIDATED", expiredEnrollment.State);
        Assert.Equal("challenge_expired", expiredEnrollment.InvalidationReason);
        Assert.Equal(challengeExpiresAtUtc, expiredEnrollment.ChallengeExpiresAtUtc);
        Assert.Equal(invalidatedAtUtc, expiredEnrollment.InvalidatedAtUtc);
        Assert.Null(expiredEnrollment.ActivatedAtUtc);
        Assert.Null(expiredEnrollment.ChallengeConsumedAtUtc);
        Assert.Equal(sourceAuthorityEpoch, expiredEnrollment.AuthorityEpoch);
    }

    [Fact]
    public async Task DistributionFinalize_ConcurrentSameHardwareAcrossLicenses_AllowsSingleOwner()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory, includeSeat: false);
        var secondLicenseId = Guid.NewGuid();
        await using (var db = await factory.CreateDbContextAsync())
        {
            var firstLicense = await db.Licenses.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == fixture.LicenseId);
            db.Licenses.Add(new License
            {
                Id = secondLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = firstLicense.LicenseTypeId,
                LicenseKey = "DIST-CROSS-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = firstLicense.AllowedVersions,
                ExpirationDate = DateTime.UtcNow.AddDays(1)
            });
            await db.SaveChangesAsync();
        }

        var now = new DateTimeOffset(2026, 7, 27, 13, 0, 0, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var licenseIds = new[] { fixture.LicenseId, secondLicenseId };
        var requests = new List<DistributionInstallationFinalizeRequest>();
        var payloadDigests = new List<string>();
        for (var index = 0; index < licenseIds.Length; index++)
        {
            var grantRef = Guid.NewGuid().ToString("D");
            var entitlement = await service.IssueEntitlementAsync(
                "website-step1",
                Sha256("cross-license-issue-" + index),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV2Schema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = fixture.ProductId.ToString("D"),
                    SoftLicenceLicenseId = licenseIds[index].ToString("D"),
                    GrantRefDigestSha256 = Sha256(grantRef)
                });
            requests.Add(new DistributionInstallationFinalizeRequest
            {
                Schema = DistributionInstallationBindingService.FinalizeSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                GrantRef = grantRef,
                HandoffDigestSha256 = Sha256("cross-license-handoff-" + index),
                HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
                HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
                DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
                ProductId = fixture.ProductId.ToString("D"),
                EntitlementRef = entitlement.Response.EntitlementRef,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareId = fixture.HardwareId,
                Release = new DistributionReleaseEvidence
                {
                    Version = fixture.Version,
                    InstallerFilename = "distribution-cross-license-race.exe",
                    InstallerSha256 = new string('f', 64)
                },
                Binaries =
                [
                    new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                    new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                    new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
                ]
            });
            payloadDigests.Add(Sha256("cross-license-finalize-" + index));
        }

        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = requests.Select((request, index) => Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", payloadDigests[index], request));
        })).ToArray();
        start.SetResult();
        var outcomes = await Task.WhenAll(tasks);

        var successIndex = Array.FindIndex(outcomes, outcome => outcome.Error == null);
        Assert.True(successIndex >= 0);
        Assert.Single(outcomes, outcome => outcome.Error == null);
        var rejection = Assert.IsType<DistributionOperationException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error);
        Assert.Equal("hardware_already_bound", rejection.ErrorCode);

        var replay = await service.FinalizeAsync(
            "website-step1", payloadDigests[successIndex], requests[successIndex]);
        Assert.True(replay.Idempotent);
        Assert.Equal(outcomes[successIndex].Result!.Response, replay.Response);

        await using var check = await factory.CreateDbContextAsync();
        Assert.Single(await check.LicenseSeats.Where(candidate =>
            candidate.IsActive
            && candidate.HardwareId == fixture.HardwareId
            && candidate.License != null
            && candidate.License.ProductId == fixture.ProductId).ToListAsync());
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == fixture.ProductId
            && candidate.HardwareIdHash == Sha256(fixture.HardwareId)
            && candidate.State == "active").ToListAsync());
    }

    /// <summary>Proves cleanup ends only the losing commercial assignment and preserves Runtime identity.</summary>
    [Fact]
    public async Task ProductScopeCleanup_EndsAssignmentAndPreservesRuntimeAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var winner = await SeedProductScopeCleanupWinnerAsync(scenario, LegacyHardwareId);

        RuntimeEnrollment enrollmentBefore;
        DistributionInstallationBinding bindingBefore;
        EnrollmentLicenseAssignment assignmentBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking().SingleAsync();
            bindingBefore = await before.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentBefore.BindingId);
            assignmentBefore = await before.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.EnrollmentId == enrollmentBefore.Id
                    && candidate.State == "ACTIVE");
        }

        await using (var cleanupDb = await scenario.Factory.CreateDbContextAsync())
        {
            var cleanup = new SeatCleanupService(cleanupDb, NullLogger<SeatCleanupService>.Instance);
            await using var transaction = await cleanup.BeginProductScopeCleanupAsync(
                scenario.Fixture.ProductId, LegacyHardwareId);
            var released = await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                LegacyHardwareId, winner.LicenseId, scenario.Fixture.ProductId);
            Assert.Single(released);
            if (transaction != null)
                await transaction.CommitAsync();
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == enrollmentBefore.Id);
        var bindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == bindingBefore.Id);
        var assignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == assignmentBefore.Id);
        var losingSeat = await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == assignmentBefore.LicenseSeatId);
        var winningSeat = await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == winner.SeatId);

        Assert.False(losingSeat.IsActive);
        Assert.NotNull(losingSeat.UnlinkedAt);
        Assert.True(winningSeat.IsActive);
        Assert.Equal("ENDED", assignmentAfter.State);
        Assert.Equal("seat_released", assignmentAfter.EndReason);
        Assert.Equal(assignmentBefore.Revision, assignmentAfter.Revision);
        Assert.Equal(assignmentBefore.EnrollmentId, assignmentAfter.EnrollmentId);
        Assert.Equal(assignmentBefore.LicenseId, assignmentAfter.LicenseId);
        Assert.Equal(assignmentBefore.LicenseSeatId, assignmentAfter.LicenseSeatId);
        Assert.False(await check.EnrollmentLicenseAssignments.AsNoTracking().AnyAsync(candidate =>
            candidate.State == "ACTIVE"
            && (candidate.EnrollmentId == assignmentBefore.EnrollmentId
                || candidate.LicenseSeatId == assignmentBefore.LicenseSeatId)));
        Assert.Equal(bindingBefore.State, bindingAfter.State);
        Assert.Equal(bindingBefore.InvalidatedAtUtc, bindingAfter.InvalidatedAtUtc);
        Assert.Equal(bindingBefore.InvalidationReason, bindingAfter.InvalidationReason);
        Assert.Equal(enrollmentBefore.State, enrollmentAfter.State);
        Assert.Equal(enrollmentBefore.InvalidatedAtUtc, enrollmentAfter.InvalidatedAtUtc);
        Assert.Equal(enrollmentBefore.InvalidationReason, enrollmentAfter.InvalidationReason);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
        Assert.Single(await check.LicenseHistories.AsNoTracking().Where(candidate =>
            candidate.LicenseId == assignmentBefore.LicenseId
            && candidate.Action == HistoryActions.AutoUnlinkedProductScope).ToListAsync());
    }

    /// <summary>Proves a missing item2 assignment returns bounded unavailability and rolls back all cleanup writes.</summary>
    [Fact]
    public async Task ProductScopeCleanup_MissingAssignmentReturns503AndRollsBack()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var winner = await SeedProductScopeCleanupWinnerAsync(scenario, LegacyHardwareId);
        Guid losingSeatId;
        await using (var corrupt = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var enrollmentId = await corrupt.RuntimeEnrollments.AsNoTracking()
                .Select(candidate => candidate.Id).SingleAsync();
            losingSeatId = await corrupt.RuntimeEnrollments.AsNoTracking()
                .Select(candidate => candidate.LicenseSeatId).SingleAsync();
            await corrupt.Database.ExecuteSqlInterpolatedAsync(
                $"DELETE FROM public.\"EnrollmentLicenseAssignments\" WHERE \"EnrollmentId\" = {enrollmentId}");
        }

        await using (var cleanupDb = await scenario.Factory.CreateDbContextAsync())
        {
            var cleanup = new SeatCleanupService(cleanupDb, NullLogger<SeatCleanupService>.Instance);
            await using var transaction = await cleanup.BeginProductScopeCleanupAsync(
                scenario.Fixture.ProductId, LegacyHardwareId);
            var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                    LegacyHardwareId, winner.LicenseId, scenario.Fixture.ProductId));
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);
            Assert.Equal("authority_unavailable", refusal.ErrorCode);
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.True((await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == losingSeatId)).IsActive);
        Assert.True((await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == winner.SeatId)).IsActive);
        Assert.Empty(await check.LicenseHistories.AsNoTracking().Where(candidate =>
            candidate.Action == HistoryActions.AutoUnlinkedProductScope).ToListAsync());
    }

    /// <summary>Proves a caller-owned transaction can roll back seats, history, and forced trigger effects together.</summary>
    [Fact]
    public async Task ProductScopeCleanup_CallerRollbackRestoresSeatsHistoryAndAssignment()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var winner = await SeedProductScopeCleanupWinnerAsync(scenario, LegacyHardwareId);
        Guid losingSeatId;
        Guid assignmentId;
        await using (var snapshot = await scenario.Factory.CreateDbContextAsync())
        {
            var assignment = await snapshot.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.State == "ACTIVE");
            assignmentId = assignment.Id;
            losingSeatId = assignment.LicenseSeatId;
        }

        await using (var cleanupDb = await scenario.Factory.CreateDbContextAsync())
        {
            var cleanup = new SeatCleanupService(cleanupDb, NullLogger<SeatCleanupService>.Instance);
            await using var transaction = await cleanup.BeginProductScopeCleanupAsync(
                scenario.Fixture.ProductId, LegacyHardwareId);
            await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                LegacyHardwareId, winner.LicenseId, scenario.Fixture.ProductId,
                redactSensitiveDetails: true);
            Assert.NotNull(transaction);
            await transaction!.RollbackAsync();
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.True((await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == losingSeatId)).IsActive);
        Assert.Equal("ACTIVE", (await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == assignmentId)).State);
        Assert.Empty(await check.LicenseHistories.AsNoTracking().Where(candidate =>
            candidate.Action == HistoryActions.AutoUnlinkedProductScope).ToListAsync());
    }

    /// <summary>
    /// Proves a scoped cleanup service cannot reuse authority from a committed transaction, while a
    /// newly acquired production lease on the same service remains valid.
    /// </summary>
    [Fact]
    public async Task ProductScopeCleanup_ReusedServiceRejectsUnleasedTransactionThenAcceptsNewLease()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var winner = await SeedProductScopeCleanupWinnerAsync(scenario, LegacyHardwareId);

        RuntimeEnrollment enrollmentBefore;
        DistributionInstallationBinding bindingBefore;
        EnrollmentLicenseAssignment assignmentBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking().SingleAsync();
            bindingBefore = await before.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentBefore.BindingId);
            assignmentBefore = await before.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.EnrollmentId == enrollmentBefore.Id
                    && candidate.State == "ACTIVE");
        }

        await using var cleanupDb = await scenario.Factory.CreateDbContextAsync();
        var cleanup = new SeatCleanupService(cleanupDb, NullLogger<SeatCleanupService>.Instance);
        await using (var completedLease = await cleanup.BeginProductScopeCleanupAsync(
            scenario.Fixture.ProductId, LegacyHardwareId))
        {
            Assert.NotNull(completedLease);
            await completedLease!.CommitAsync();
        }

        await using (var unrelatedTransaction = await cleanupDb.Database.BeginTransactionAsync())
        {
            var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                    LegacyHardwareId, winner.LicenseId, scenario.Fixture.ProductId));
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);
            Assert.Equal("authority_unavailable", refusal.ErrorCode);
            Assert.Equal("product_scope_authority_order_missing", refusal.ReasonCode);
            await unrelatedTransaction.RollbackAsync();
        }

        await using (var afterRefusal = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await afterRefusal.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentBefore.Id);
            var binding = await afterRefusal.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == bindingBefore.Id);
            var assignment = await afterRefusal.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == assignmentBefore.Id);
            Assert.True((await afterRefusal.LicenseSeats.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == assignmentBefore.LicenseSeatId)).IsActive);
            Assert.True((await afterRefusal.LicenseSeats.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == winner.SeatId)).IsActive);
            Assert.Equal("ACTIVE", assignment.State);
            Assert.Equal(assignmentBefore.Revision, assignment.Revision);
            Assert.Equal(bindingBefore.State, binding.State);
            Assert.Equal(bindingBefore.InvalidatedAtUtc, binding.InvalidatedAtUtc);
            Assert.Equal(enrollmentBefore.State, enrollment.State);
            Assert.Equal(enrollmentBefore.SecurityEpoch, enrollment.SecurityEpoch);
            Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollment.AuthorityEpoch);
            Assert.Empty(await afterRefusal.LicenseHistories.AsNoTracking().Where(candidate =>
                candidate.Action == HistoryActions.AutoUnlinkedProductScope).ToListAsync());
        }

        await using (var newLease = await cleanup.BeginProductScopeCleanupAsync(
            scenario.Fixture.ProductId, LegacyHardwareId))
        {
            Assert.NotNull(newLease);
            var released = await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                LegacyHardwareId, winner.LicenseId, scenario.Fixture.ProductId);
            Assert.Single(released);
            await newLease!.CommitAsync();
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var assignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == assignmentBefore.Id);
        Assert.Equal("ENDED", assignmentAfter.State);
        Assert.Equal("seat_released", assignmentAfter.EndReason);
        Assert.False(await check.EnrollmentLicenseAssignments.AsNoTracking().AnyAsync(candidate =>
            candidate.State == "ACTIVE"
            && (candidate.EnrollmentId == assignmentBefore.EnrollmentId
                || candidate.LicenseSeatId == assignmentBefore.LicenseSeatId)));
    }

    /// <summary>
    /// Proves cleanup rechecks the winning licence against PostgreSQL time after waiting for the
    /// global authority lease and rolls back every commercial and Runtime side effect on expiry.
    /// </summary>
    [Fact]
    public async Task ProductScopeCleanup_WinnerExpiresWhileWaitingReturns503WithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var winner = await SeedProductScopeCleanupWinnerAsync(scenario, LegacyHardwareId);

        RuntimeEnrollment enrollmentBefore;
        DistributionInstallationBinding bindingBefore;
        EnrollmentLicenseAssignment assignmentBefore;
        LicenseSeat losingSeatBefore;
        LicenseSeat winningSeatBefore;
        int historyCountBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking().SingleAsync();
            bindingBefore = await before.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentBefore.BindingId);
            assignmentBefore = await before.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.EnrollmentId == enrollmentBefore.Id
                    && candidate.State == "ACTIVE");
            losingSeatBefore = await before.LicenseSeats.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == assignmentBefore.LicenseSeatId);
            winningSeatBefore = await before.LicenseSeats.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == winner.SeatId);
            historyCountBefore = await before.LicenseHistories.AsNoTracking().CountAsync(candidate =>
                candidate.Action == HistoryActions.AutoUnlinkedProductScope);
        }

        var writerApplicationName = "item3b2-expiry-writer-" + Guid.NewGuid().ToString("N");
        var cleanupApplicationName = "item3b2-expiry-cleanup-" + Guid.NewGuid().ToString("N");
        var writerConnection = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = writerApplicationName,
            Pooling = false
        }.ConnectionString;
        var cleanupConnection = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = cleanupApplicationName,
            Pooling = false
        }.ConnectionString;

        await using var writerDb = new TestDbFactory(writerConnection).CreateDbContext();
        var writerAuthority = new SeatCleanupService(
            writerDb, NullLogger<SeatCleanupService>.Instance);
        await using var writerTransaction = await writerAuthority.BeginProductScopeCleanupAsync(
            scenario.Fixture.ProductId, LegacyHardwareId);
        Assert.NotNull(writerTransaction);
        await writerDb.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE public."Licenses"
            SET "ExpirationDate" = pg_catalog.clock_timestamp() + interval '750 milliseconds'
            WHERE "Id" = {winner.LicenseId}
            """);

        var cleanupTask = Task.Run(async () =>
        {
            await using var cleanupDb = new TestDbFactory(cleanupConnection).CreateDbContext();
            var cleanup = new SeatCleanupService(
                cleanupDb, NullLogger<SeatCleanupService>.Instance);
            await using var cleanupTransaction = await cleanup.BeginProductScopeCleanupAsync(
                scenario.Fixture.ProductId, LegacyHardwareId);
            return await Assert.ThrowsAsync<DistributionOperationException>(() =>
                cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                    LegacyHardwareId, winner.LicenseId, scenario.Fixture.ProductId));
        });

        Exception? observationFailure = null;
        try
        {
            await WaitForBlockedBackendAsync(
                scenario.AdminConnectionString, cleanupApplicationName, writerApplicationName);
            Assert.False(cleanupTask.IsCompleted);

            var expired = false;
            for (var attempt = 0; attempt < 100 && !expired; attempt++)
            {
                writerDb.ChangeTracker.Clear();
                var expiration = await writerDb.Licenses.AsNoTracking()
                    .Where(candidate => candidate.Id == winner.LicenseId)
                    .Select(candidate => candidate.ExpirationDate)
                    .SingleAsync();
                var databaseNow = (await RuntimeEnrollmentService.DatabaseNowAsync(
                    writerDb, CancellationToken.None)).UtcDateTime;
                expired = expiration.HasValue && expiration.Value <= databaseNow;
                if (!expired)
                    await Task.Delay(25);
            }

            Assert.True(expired, "The winning licence must expire according to PostgreSQL while cleanup waits.");
            Assert.False(cleanupTask.IsCompleted);
        }
        catch (Exception exception)
        {
            observationFailure = exception;
        }
        finally
        {
            await writerTransaction!.CommitAsync();
        }

        if (observationFailure != null)
        {
            try
            {
                await cleanupTask.WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch
            {
                // Drain the task before surfacing the original lock/clock observation failure.
            }
            throw observationFailure;
        }

        var refusal = await cleanupTask.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);
        Assert.Equal("authority_unavailable", refusal.ErrorCode);
        Assert.Equal("product_scope_winner_expired", refusal.ReasonCode);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == enrollmentBefore.Id);
        var bindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == bindingBefore.Id);
        var assignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == assignmentBefore.Id);
        var losingSeatAfter = await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == losingSeatBefore.Id);
        var winningSeatAfter = await check.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == winningSeatBefore.Id);

        Assert.True(losingSeatAfter.IsActive);
        Assert.Equal(losingSeatBefore.UnlinkedAt, losingSeatAfter.UnlinkedAt);
        Assert.True(winningSeatAfter.IsActive);
        Assert.Equal(winningSeatBefore.UnlinkedAt, winningSeatAfter.UnlinkedAt);
        Assert.Equal("ACTIVE", assignmentAfter.State);
        Assert.Equal(assignmentBefore.Revision, assignmentAfter.Revision);
        Assert.Equal(assignmentBefore.EndedAtUtc, assignmentAfter.EndedAtUtc);
        Assert.Equal(assignmentBefore.EndReason, assignmentAfter.EndReason);
        Assert.Equal(bindingBefore.State, bindingAfter.State);
        Assert.Equal(bindingBefore.InvalidatedAtUtc, bindingAfter.InvalidatedAtUtc);
        Assert.Equal(bindingBefore.InvalidationReason, bindingAfter.InvalidationReason);
        Assert.Equal(enrollmentBefore.State, enrollmentAfter.State);
        Assert.Equal(enrollmentBefore.InvalidatedAtUtc, enrollmentAfter.InvalidatedAtUtc);
        Assert.Equal(enrollmentBefore.InvalidationReason, enrollmentAfter.InvalidationReason);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
        Assert.Equal(historyCountBefore, await check.LicenseHistories.AsNoTracking().CountAsync(candidate =>
            candidate.Action == HistoryActions.AutoUnlinkedProductScope));
    }

    /// <summary>
    /// Proves that two complete product-scope ownership changes serialize at the global lease in
    /// either order, and that the later grant determines the commercial assignment without changing
    /// Runtime cryptographic identity.
    /// </summary>
    /// <param name="newWinnerRunsFirst">Whether cleanup for the newly seeded licence owns the first transaction.</param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ProductScopeCleanup_TwoConnectionCompetingGrantSerializesWithoutPartialRuntime(
        bool newWinnerRunsFirst)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var newWinner = await SeedProductScopeCleanupWinnerAsync(scenario, LegacyHardwareId);
        Guid originalLicenseId;
        Guid originalSeatId;
        RuntimeEnrollment enrollmentBefore;
        DistributionInstallationBinding bindingBefore;
        EnrollmentLicenseAssignment assignmentBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking().SingleAsync();
            bindingBefore = await before.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentBefore.BindingId);
            assignmentBefore = await before.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.EnrollmentId == enrollmentBefore.Id
                    && candidate.State == "ACTIVE");
            originalLicenseId = assignmentBefore.LicenseId;
            originalSeatId = assignmentBefore.LicenseSeatId;
        }

        var firstApplicationName = "item3b2-first-" + Guid.NewGuid().ToString("N");
        var secondApplicationName = "item3b2-second-" + Guid.NewGuid().ToString("N");
        var firstConnection = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = firstApplicationName,
            Pooling = false
        }.ConnectionString;
        var secondConnection = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = secondApplicationName,
            Pooling = false
        }.ConnectionString;
        var firstHeld = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        (Guid LicenseId, Guid SeatId) firstAuthority = newWinnerRunsFirst
            ? (newWinner.LicenseId, newWinner.SeatId)
            : (originalLicenseId, originalSeatId);
        (Guid LicenseId, Guid SeatId) secondAuthority = newWinnerRunsFirst
            ? (originalLicenseId, originalSeatId)
            : (newWinner.LicenseId, newWinner.SeatId);

        // Runs one complete commercial ownership change under the production lock order;
        // the optional pause exposes the first lease for deterministic blocking evidence.
        async Task ChangeOwnerAsync(
            string connectionString,
            (Guid LicenseId, Guid SeatId) authority,
            TaskCompletionSource? acquired,
            Task? pause)
        {
            await using var db = new TestDbFactory(connectionString).CreateDbContext();
            var cleanup = new SeatCleanupService(db, NullLogger<SeatCleanupService>.Instance);
            await using var transaction = await cleanup.BeginProductScopeCleanupAsync(
                scenario.Fixture.ProductId, LegacyHardwareId);
            acquired?.SetResult();
            if (pause != null)
                await pause;
            var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == authority.SeatId);
            seat.IsActive = true;
            seat.UnlinkedAt = null;
            await db.SaveChangesAsync();
            await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                LegacyHardwareId, authority.LicenseId, scenario.Fixture.ProductId);
            if (transaction != null)
                await transaction.CommitAsync();
        }

        var first = Task.Run(() => ChangeOwnerAsync(
            firstConnection, firstAuthority, firstHeld, releaseFirst.Task));
        await firstHeld.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = Task.Run(() => ChangeOwnerAsync(
            secondConnection, secondAuthority, null, null));
        try
        {
            await WaitForBlockedBackendAsync(
                scenario.AdminConnectionString, secondApplicationName, firstApplicationName);
            Assert.False(second.IsCompleted);
        }
        finally
        {
            releaseFirst.TrySetResult();
        }
        await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(20));

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == enrollmentBefore.Id);
        var bindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == bindingBefore.Id);
        var originalAssignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == assignmentBefore.Id);
        var activeSuccessors = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(candidate => candidate.EnrollmentId == assignmentBefore.EnrollmentId
                && candidate.State == "ACTIVE")
            .OrderBy(candidate => candidate.Revision)
            .ThenBy(candidate => candidate.Id)
            .ToListAsync();
        var activeSeats = await check.LicenseSeats.AsNoTracking().Where(candidate =>
            candidate.IsActive
            && candidate.HardwareId == LegacyHardwareId
            && candidate.License != null
            && candidate.License.ProductId == scenario.Fixture.ProductId).ToListAsync();
        var cleanupHistory = await check.LicenseHistories.AsNoTracking().Where(candidate =>
                candidate.Action == HistoryActions.AutoUnlinkedProductScope)
            .OrderBy(candidate => candidate.Timestamp)
            .ThenBy(candidate => candidate.Id)
            .ToListAsync();
        Assert.Single(activeSeats);
        Assert.Equal(2, cleanupHistory.Count);
        Assert.True(cleanupHistory[1].Timestamp >= cleanupHistory[0].Timestamp);
        Assert.Equal(secondAuthority.SeatId, activeSeats[0].Id);
        if (secondAuthority.SeatId == originalSeatId)
        {
            Assert.Equal("ENDED", originalAssignmentAfter.State);
            Assert.Equal("seat_released", originalAssignmentAfter.EndReason);
            var activeSuccessor = Assert.Single(activeSuccessors);
            Assert.Equal(originalLicenseId, activeSuccessor.LicenseId);
            Assert.Equal(originalSeatId, activeSuccessor.LicenseSeatId);
            Assert.True(activeSuccessor.Revision > assignmentBefore.Revision);
        }
        else
        {
            Assert.Equal("ENDED", originalAssignmentAfter.State);
            Assert.Equal("seat_released", originalAssignmentAfter.EndReason);
            Assert.Empty(activeSuccessors);
            Assert.False(await check.EnrollmentLicenseAssignments.AsNoTracking().AnyAsync(candidate =>
                candidate.State == "ACTIVE"
                && candidate.LicenseSeatId == originalSeatId));
        }
        Assert.Equal(bindingBefore.State, bindingAfter.State);
        Assert.Equal(bindingBefore.InvalidatedAtUtc, bindingAfter.InvalidatedAtUtc);
        Assert.Equal(bindingBefore.InvalidationReason, bindingAfter.InvalidationReason);
        Assert.Equal(enrollmentBefore.State, enrollmentAfter.State);
        Assert.Equal(enrollmentBefore.InvalidatedAtUtc, enrollmentAfter.InvalidatedAtUtc);
        Assert.Equal(enrollmentBefore.InvalidationReason, enrollmentAfter.InvalidationReason);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
    }

    /// <summary>Creates the unique winning commercial seat used by product-scope cleanup tests.</summary>
    /// <param name="scenario">The isolated Runtime authority fixture that owns the losing seat.</param>
    /// <param name="hardwareId">The exact canonical hardware shared by the winner and loser.</param>
    /// <returns>The winning licence and seat identifiers.</returns>
    private static async Task<(Guid LicenseId, Guid SeatId)> SeedProductScopeCleanupWinnerAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var sourceLicense = await db.Licenses.AsNoTracking().SingleAsync();
        var licenseId = Guid.NewGuid();
        var seatId = Guid.NewGuid();
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = sourceLicense.ProductId,
            LicenseTypeId = sourceLicense.LicenseTypeId,
            LicenseKey = "PRODUCT-SCOPE-WINNER-" + Guid.NewGuid().ToString("N"),
            IsActive = true,
            MaxSeats = 1,
            AllowedVersions = sourceLicense.AllowedVersions,
            ExpirationDate = DateTime.UtcNow.AddDays(30)
        });
        db.LicenseSeats.Add(new LicenseSeat
        {
            Id = seatId,
            LicenseId = licenseId,
            HardwareId = hardwareId,
            IsActive = true,
            FirstActivatedAt = DateTime.UtcNow,
            LastCheckInAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        return (licenseId, seatId);
    }

    /// <summary>Waits until one tagged PostgreSQL backend is blocked by the other tagged backend.</summary>
    /// <param name="adminConnectionString">Administrator connection used for bounded lock observation.</param>
    /// <param name="blockedApplicationName">Exact application name of the waiting backend.</param>
    /// <param name="blockerApplicationName">Exact application name of the lock owner.</param>
    private static async Task WaitForBlockedBackendAsync(
        string adminConnectionString,
        string blockedApplicationName,
        string blockerApplicationName)
    {
        await using var observer = new NpgsqlConnection(adminConnectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 100; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity AS blocked
                    JOIN pg_catalog.pg_stat_activity AS blocker
                      ON blocker.pid = ANY(pg_catalog.pg_blocking_pids(blocked.pid))
                    WHERE blocked.application_name = @blocked_application
                      AND blocker.application_name = @blocker_application);
                """;
            command.Parameters.AddWithValue("blocked_application", blockedApplicationName);
            command.Parameters.AddWithValue("blocker_application", blockerApplicationName);
            if (Convert.ToBoolean(await command.ExecuteScalarAsync()))
                return;
            await Task.Delay(25);
        }

        throw new TimeoutException("Expected the tagged product-scope authority backend to be blocked.");
    }

    private static DateTime CreateFutureClassicActivationExpirationUtc()
    {
        var expirationUtc = DateTime.UtcNow.AddDays(30);
        Assert.True(
            expirationUtc > DateTime.UtcNow.AddDays(7),
            "ClassicActivation fixtures must remain valid for more than seven days from the wall clock.");
        return expirationUtc;
    }

    /// <summary>Creates contexts that seed a synthetic enrollment inside the successful Finalize transaction.</summary>
    private sealed class ConcurrentFinalizeEnrollmentFactory(
        string connection, ConcurrentFinalizeEnrollmentSeed seed) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Allocates a caller-owned context; only the Finalize commit with a new binding is seeded.</summary>
        public LicenseDbContext CreateDbContext() => new(new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connection).AddInterceptors(seed).Options);
        /// <summary>Honors cancellation before allocating the context.</summary>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CreateDbContext());
        }
    }

    /// <summary>Seeds real persisted Runtime identity before Finalize releases its locks, without altering product SQL.</summary>
    /// <remarks>The cryptographic fields are synthetic placeholders: assertions exercise the real commercial
    /// validator, not signature verification. The database's real deferred triggers create the assignment.</remarks>
    private sealed class ConcurrentFinalizeEnrollmentSeed(string encryptionKeyId)
        : Microsoft.EntityFrameworkCore.Diagnostics.DbTransactionInterceptor
    {
        /// <summary>Exact synthetic enrollment created by the successful Finalize transaction.</summary>
        internal Guid EnrollmentId { get; private set; }
        /// <summary>Hash of all persisted enrollment and binding fields before the competing activation.</summary>
        internal string? IdentitySnapshot { get; private set; }

        /// <summary>Adds identity only when Finalize has saved its first binding; preserves the real transaction commit.</summary>
        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult> TransactionCommittingAsync(
            System.Data.Common.DbTransaction transaction,
            Microsoft.EntityFrameworkCore.Diagnostics.TransactionEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (EnrollmentId != Guid.Empty || eventData.Context is not LicenseDbContext db)
                return result;
            var tracked = db.ChangeTracker.Entries<DistributionInstallationBinding>()
                .Select(entry => entry.Entity).ToArray();
            if (tracked.Length == 0)
                return result;
            var binding = Assert.Single(tracked);
            Assert.Equal("active", binding.State);
            EnrollmentId = Guid.NewGuid();
            var epoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(row => row.Id == 1).Select(row => row.Epoch).SingleAsync(cancellationToken);
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = EnrollmentId, ClientId = "website-step1", BindingId = binding.Id,
                ProductId = binding.ProductId, LicenseId = binding.LicenseId, LicenseSeatId = binding.LicenseSeatId,
                InstallationId = binding.InstallationId, HardwareIdHash = binding.HardwareIdHash,
                ReleaseVersion = binding.Version, HandoffDigestSha256 = binding.HandoffDigestSha256,
                SubjectRefDigestSha256 = binding.SubjectRefDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, Algorithm = "PS256",
                KeyBackend = "software-cng-unattested", AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test", PublicKeySpkiKeyId = encryptionKeyId,
                PublicKeySpkiSha256 = new string('d', 64), KeyThumbprint = "sync-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test", ChallengeKeyId = encryptionKeyId,
                ChallengeDigestSha256 = new string('e', 64), State = "ACTIVE", Epoch = 1,
                SecurityEpoch = 1, AuthorityEpoch = epoch, ChallengeExpiresAtUtc = DateTime.UtcNow.AddHours(1),
                CreatedAtUtc = DateTime.UtcNow, ActivatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(cancellationToken);
            var enrollment = await db.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == EnrollmentId, cancellationToken);
            var storedBinding = await db.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == binding.Id, cancellationToken);
            IdentitySnapshot = Sha256(System.Text.Json.JsonSerializer.Serialize(new { enrollment, binding = storedBinding }));
            return result;
        }
    }

    /// <summary>Proves both tagged operations are pending in the exact global-authority/HWID lock chain.</summary>
    /// <remarks>Finalize must first own the global barrier and wait on the fixture HWID lock. After activation
    /// starts it must wait on Finalize. Both observations share the original five-second budget.</remarks>
    private static async Task WaitForProductHardwareLockChainAsync(
        string connectionString, string exactLockName, int fixturePid,
        string firstApplication, string secondApplication, System.Diagnostics.Stopwatch observation)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        while (observation.Elapsed < TimeSpan.FromSeconds(5))
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                WITH target AS (SELECT pg_catalog.hashtextextended(@lock_name, 0)::bigint AS key)
                SELECT owner.pid, follower.pid
                FROM pg_catalog.pg_stat_activity owner
                LEFT JOIN pg_catalog.pg_stat_activity follower
                  ON owner.pid = ANY(pg_catalog.pg_blocking_pids(follower.pid))
                 AND follower.application_name = @second
                CROSS JOIN target
                WHERE owner.application_name = @first
                  AND @fixture = ANY(pg_catalog.pg_blocking_pids(owner.pid))
                  AND owner.datid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
                  AND (@second = '' OR follower.datid = owner.datid)
                  AND EXISTS (SELECT 1 FROM pg_catalog.pg_locks h
                    WHERE h.pid = owner.pid AND h.locktype = 'advisory' AND NOT h.granted
                      AND h.classid = (((target.key >> 32) & 4294967295)::bigint)::oid
                      AND h.objid = ((target.key & 4294967295)::bigint)::oid AND h.objsubid = 1)
                  AND EXISTS (SELECT 1 FROM pg_catalog.pg_locks g
                    WHERE g.pid = owner.pid AND g.locktype = 'advisory' AND g.granted
                      AND g.classid = 999831 AND g.objid = 1 AND g.objsubid = 2
                      AND g.mode = 'ExclusiveLock')
                  AND (@second = '' OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks g
                    WHERE g.pid = follower.pid AND g.locktype = 'advisory' AND NOT g.granted
                      AND g.classid = 999831 AND g.objid = 1 AND g.objsubid = 2));
                """;
            command.Parameters.AddWithValue("lock_name", exactLockName);
            command.Parameters.AddWithValue("fixture", fixturePid);
            command.Parameters.AddWithValue("first", firstApplication);
            command.Parameters.AddWithValue("second", secondApplication);
            await using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                Assert.NotEqual(fixturePid, reader.GetInt32(0));
                if (secondApplication.Length != 0)
                    Assert.NotEqual(reader.GetInt32(0), reader.GetInt32(1));
                Assert.False(await reader.ReadAsync());
                return;
            }
            await Task.Delay(50);
        }
        throw new TimeoutException("Expected the exact tagged global-authority then HWID PostgreSQL lock chain.");
    }

    private static async Task WaitForAdvisoryWaitersAsync(
        string connectionString,
        string exactLockName,
        int expectedWaiters)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 100; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                WITH target AS (
                    SELECT pg_catalog.hashtextextended(@lock_name, 0)::bigint AS key
                )
                SELECT count(*)
                FROM pg_catalog.pg_locks AS held
                CROSS JOIN target
                WHERE held.locktype = 'advisory'
                  AND held.database = (
                      SELECT oid FROM pg_catalog.pg_database
                      WHERE datname = pg_catalog.current_database())
                  AND held.classid = (((target.key >> 32) & 4294967295)::bigint)::oid
                  AND held.objid = ((target.key & 4294967295)::bigint)::oid
                  AND held.objsubid = 1
                  AND NOT held.granted;
                """;
            command.Parameters.AddWithValue("lock_name", exactLockName);
            var waiters = Convert.ToInt32(await command.ExecuteScalarAsync());
            if (waiters >= expectedWaiters)
                return;
            await Task.Delay(50);
        }

        throw new TimeoutException($"Expected {expectedWaiters} PostgreSQL advisory-lock waiters.");
    }
}
