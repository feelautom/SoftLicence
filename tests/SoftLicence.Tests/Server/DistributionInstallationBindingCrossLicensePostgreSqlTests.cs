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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

        var missingUnlinkAuthority = await IssueAsync("same-license-missing-unlink");
        var missingUnlinkRequest = FinalizeRequest(
            "same-license-missing-unlink", missingUnlinkAuthority, targetHardwareId, now.AddMinutes(-7));
        missingUnlinkRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        missingUnlinkRequest.LicenseReplacementCandidates = UnrelatedCandidates("missing-unlink-history");
        var missingUnlink = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("same-license-missing-unlink-finalize"), missingUnlinkRequest));
        Assert.Equal("binding_conflict", missingUnlink.ErrorCode);
        Assert.Equal("replacement_candidate_none", missingUnlink.ReasonCode);

        await using (var markExplicitUnlink = await factory.CreateDbContextAsync())
        {
            var sourceSeat = await markExplicitUnlink.LicenseSeats
                .SingleAsync(candidate => candidate.Id == sourceSeatId);
            sourceSeat.UnlinkedAt = now.AddMinutes(-6).UtcDateTime;
            await markExplicitUnlink.SaveChangesAsync();
        }

        var divergentSubject = Convert.ToBase64String(SHA256.HashData("different-seat-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var divergentAuthority = await IssueAsync("same-license-divergent-subject", divergentSubject);
        var divergentRequest = FinalizeRequest(
            "same-license-divergent-subject", divergentAuthority, targetHardwareId, now.AddMinutes(-5));
        divergentRequest.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        divergentRequest.LicenseReplacementCandidates = UnrelatedCandidates("divergent-subject-history");
        var divergent = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "website-step1", Sha256("same-license-divergent-subject-finalize"), divergentRequest));
        Assert.Equal("binding_conflict", divergent.ErrorCode);
        Assert.Equal("replacement_candidate_none", divergent.ReasonCode);

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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
    public async Task DistributionFinalize_CompletesBeforeClassicActivation_ActivationAtomicallyInvalidatesRuntimeIdentity()
    {
        const string invalidationReason = "seat_reassigned_product_scope";
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
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

        DateTime bindingInvalidatedAt;
        DateTime enrollmentInvalidatedAt;
        long invalidatedAuthorityEpoch;
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
            Assert.Equal("invalidated", binding.State);
            Assert.Equal(invalidationReason, binding.InvalidationReason);
            Assert.NotNull(binding.InvalidatedAtUtc);
            Assert.Equal("INVALIDATED", enrollment.State);
            Assert.Equal(invalidationReason, enrollment.InvalidationReason);
            Assert.NotNull(enrollment.InvalidatedAtUtc);
            Assert.Equal(binding.InvalidatedAtUtc, enrollment.InvalidatedAtUtc);
            Assert.True(enrollment.AuthorityEpoch > enrollmentAuthorityEpoch);
            Assert.Equal(await check.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => candidate.Epoch)
                .SingleAsync(), enrollment.AuthorityEpoch);
            bindingInvalidatedAt = binding.InvalidatedAtUtc!.Value;
            enrollmentInvalidatedAt = enrollment.InvalidatedAtUtc!.Value;
            invalidatedAuthorityEpoch = enrollment.AuthorityEpoch;
        }

        await using (var standaloneDb = await directFactory.CreateDbContextAsync())
        {
            var cleanup = new SeatCleanupService(standaloneDb, NullLogger<SeatCleanupService>.Instance);
            var replay = await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                fixture.HardwareId, activationLicenseId, fixture.ProductId, redactSensitiveDetails: true);
            Assert.Empty(replay);
        }

        await using var replayCheck = await directFactory.CreateDbContextAsync();
        var replayedBinding = await replayCheck.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == bindingId);
        var replayedEnrollment = await replayCheck.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == enrollmentId);
        Assert.Equal(bindingInvalidatedAt, replayedBinding.InvalidatedAtUtc);
        Assert.Equal(enrollmentInvalidatedAt, replayedEnrollment.InvalidatedAtUtc);
        Assert.Equal(invalidatedAuthorityEpoch, replayedEnrollment.AuthorityEpoch);
        Assert.Equal(invalidationReason, replayedBinding.InvalidationReason);
        Assert.Equal(invalidationReason, replayedEnrollment.InvalidationReason);
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
        var hardwareId = "DIST-ACTIVATE-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
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
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
        var now = new DateTimeOffset(2026, 7, 27, 16, 0, 0, TimeSpan.Zero);
        var classicActivationExpirationUtc = CreateFutureClassicActivationExpirationUtc();
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var finalizeLicenseId = Guid.NewGuid();
        var activationLicenseId = Guid.NewGuid();
        var activationSeatId = Guid.NewGuid();
        var hardwareId = "DIST-CONCURRENT-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
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
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

        var finalizeTask = CaptureAsync(() => distribution.FinalizeAsync(
            "website-step1", Sha256("concurrent-lock-finalize"), finalizeRequest));
        var activationTask = client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = activationLicenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = version
        });

        await WaitForAdvisoryWaitersAsync(
            connections.Admin, productHardwareLockName, expectedWaiters: 2);
        Assert.False(finalizeTask.IsCompleted);
        Assert.False(activationTask.IsCompleted);
        await blockerTransaction.CommitAsync();

        var finalizeOutcome = await finalizeTask;
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
            Assert.Equal("invalidated", binding.State);
            Assert.Equal("seat_reassigned_product_scope", binding.InvalidationReason);
            Assert.False((await check.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == binding.LicenseSeatId)).IsActive);
            Assert.Empty(await check.RuntimeEnrollments.Where(candidate =>
                candidate.BindingId == binding.Id
                && (candidate.State == "PENDING" || candidate.State == "ACTIVE")).ToListAsync());
        }

        Assert.False(await check.DistributionInstallationBindings.AnyAsync(binding =>
            binding.State == "active"
            && check.LicenseSeats.Any(seat => seat.Id == binding.LicenseSeatId && !seat.IsActive)));
    }

    [Fact]
    public async Task AutoTrial_ConcurrentWithDistributionFinalize_WaitsOnSharedExactHardwareLock()
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
        var now = new DateTimeOffset(2026, 7, 27, 17, 0, 0, TimeSpan.Zero);
        var productId = Guid.NewGuid();
        var paidTypeId = Guid.NewGuid();
        var trialTypeId = Guid.NewGuid();
        var finalizeLicenseId = Guid.NewGuid();
        var hardwareId = "DIST-AUTO-TRIAL-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
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
            directFactory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

        var finalizeTask = CaptureAsync(() => distribution.FinalizeAsync(
            "website-step1", Sha256("auto-trial-lock-finalize"), finalizeRequest));
        var activationTask = client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = "FREE-TRIAL",
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = version,
            CustomerEmail = "trial@example.test",
            CustomerName = "Trial test"
        });

        await WaitForAdvisoryWaitersAsync(
            connections.Admin, productHardwareLockName, expectedWaiters: 2);
        Assert.False(finalizeTask.IsCompleted);
        Assert.False(activationTask.IsCompleted);
        await blockerTransaction.CommitAsync();

        var finalizeOutcome = await finalizeTask;
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
            Assert.Equal("invalidated", binding.State);
            Assert.Equal("seat_reassigned_product_scope", binding.InvalidationReason);
            Assert.False((await check.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == binding.LicenseSeatId)).IsActive);
            Assert.Empty(await check.RuntimeEnrollments.Where(candidate =>
                candidate.BindingId == binding.Id
                && (candidate.State == "PENDING" || candidate.State == "ACTIVE")).ToListAsync());
        }

        Assert.False(await check.DistributionInstallationBindings.AnyAsync(binding =>
            binding.State == "active"
            && check.LicenseSeats.Any(seat => seat.Id == binding.LicenseSeatId && !seat.IsActive)));
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

    [Fact]
    public async Task DistributionFinalize_NewInstallation_V1FailsClosedAndV2AtomicallyRecovers()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        // This scenario exercises refresh authority, whose expiry is compared with the
        // PostgreSQL clock. Keep the deterministic provider close to that real clock.
        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
        var corruptions = new (string Field, object CorruptValue, object RestoreValue)[]
        {
            ("ClientId", "other-website-client", "website-step1"),
            ("BindingId", decoyBindingId, sourceBindingId),
            ("ProductId", Guid.NewGuid(), sourceBindingBaseline.ProductId),
            ("LicenseId", Guid.NewGuid(), sourceBindingBaseline.LicenseId),
            ("LicenseSeatId", Guid.NewGuid(), sourceBindingBaseline.LicenseSeatId),
            ("InstallationId", Guid.NewGuid().ToString("D"), sourceBindingBaseline.InstallationId),
            ("HardwareIdHash", new string('1', 64), sourceBindingBaseline.HardwareIdHash),
            ("SubjectRefDigestSha256", new string('2', 64), sourceBindingBaseline.SubjectRefDigestSha256!),
            ("HandoffDigestSha256", new string('3', 64), sourceBindingBaseline.HandoffDigestSha256),
            ("ReleaseVersion", "2.2.843", sourceBindingBaseline.Version),
            ("ProtocolVersion", "runtime-enrollment-v0", RuntimeEnrollmentService.ProtocolVersion)
        };
        foreach (var (field, corruptValue, restoreValue) in corruptions)
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
                Assert.Equal(1, await command.ExecuteNonQueryAsync());
            }

            var probe = FinalizeRequest(
                "new-installation-target", targetAuthority, targetRequest.InstallationId!, now.AddMinutes(-5));
            probe.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
            probe.AllowSameAuthorityRecovery = true;
            var mismatch = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                service.FinalizeAsync(
                    "website-step1", Sha256("new-installation-lineage-" + field), probe));
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
        Assert.True(winnerIndex >= 0);
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

    [Fact]
    public async Task DistributionFinalize_NewInstallation_SoleExpiredUnactivatedEnrollment_RecoversWithoutRewritingForensicEvidence()
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
            var sourceBinding = await seed.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == sourceBindingId);
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
                State = "INVALIDATED",
                Epoch = 1,
                SecurityEpoch = 4,
                AuthorityEpoch = sourceAuthorityEpoch,
                ChallengeExpiresAtUtc = challengeExpiresAtUtc,
                CreatedAtUtc = now.AddMinutes(-30).UtcDateTime,
                InvalidatedAtUtc = invalidatedAtUtc,
                InvalidationReason = "challenge_expired"
            });
            await seed.SaveChangesAsync();
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

        async Task RestoreEnrollmentAsync()
        {
            await MutateEnrollmentAsync(enrollment =>
            {
                enrollment.ClientId = "website-step1";
                enrollment.BindingId = sourceBindingId;
                enrollment.ProductId = fixture.ProductId;
                enrollment.LicenseId = fixture.LicenseId;
                enrollment.LicenseSeatId = sourceLicenseSeatId;
                enrollment.InstallationId = sourceInstallationId;
                enrollment.HardwareIdHash = Sha256(fixture.HardwareId);
                enrollment.ReleaseVersion = fixture.Version;
                enrollment.HandoffDigestSha256 = sourceRequest.HandoffDigestSha256!;
                enrollment.SubjectRefDigestSha256 = Sha256(subjectRef);
                enrollment.ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion;
                enrollment.State = "INVALIDATED";
                enrollment.Epoch = 1;
                enrollment.ChallengeExpiresAtUtc = challengeExpiresAtUtc;
                enrollment.ChallengeConsumedAtUtc = null;
                enrollment.ActivatedAtUtc = null;
                enrollment.InvalidatedAtUtc = invalidatedAtUtc;
                enrollment.InvalidationReason = "challenge_expired";
            });
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
        foreach (var (label, mutation) in rejectedMutations)
        {
            await MutateEnrollmentAsync(mutation);
            await AssertRecoveryRefusedWithoutMutationAsync(label);
            await RestoreEnrollmentAsync();
        }

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
                InvalidatedAtUtc = now.AddMinutes(-7).UtcDateTime,
                InvalidationReason = "challenge_expired"
            });
            await addHistory.SaveChangesAsync();
        }
        await AssertRecoveryRefusedWithoutMutationAsync("multiple-expired-history");
        await using (var removeHistory = await factory.CreateDbContextAsync())
        {
            removeHistory.RuntimeEnrollments.Remove(await removeHistory.RuntimeEnrollments
                .SingleAsync(candidate => candidate.Id == secondExpiredEnrollmentId));
            await removeHistory.SaveChangesAsync();
        }

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
        await using (var removeIncident = await adminFactory.CreateDbContextAsync())
        {
            removeIncident.RuntimeCriticalIncidents.Remove(await removeIncident.RuntimeCriticalIncidents
                .SingleAsync(candidate => candidate.Id == criticalIncidentId));
            await removeIncident.SaveChangesAsync();
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

    private static DateTime CreateFutureClassicActivationExpirationUtc()
    {
        var expirationUtc = DateTime.UtcNow.AddDays(30);
        Assert.True(
            expirationUtc > DateTime.UtcNow.AddDays(7),
            "ClassicActivation fixtures must remain valid for more than seven days from the wall clock.");
        return expirationUtc;
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
