using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.SDK;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    private const string LegacyHardwareId = "A00272B768FFD6AF";
    // TKT-001277 lot 5: the target is the SDK 2.0 identifier derived from TestSystemUuid.
    private const string TestSystemUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";
    private const string StableHardwareId = "6B775195D2F86F36";

    /// <summary>
    /// SUP-000040 (TKT-001262): after Finalize rotated the binding and the Runtime enrollment, the
    /// alias of the same seat and machine still pointed at the superseded authority and every later
    /// migration failed with hardware_authority_migration_conflict ("hardware_authority_rejected" at
    /// Desktop start). The migration now repoints the alias; a disabled alias still conflicts.
    /// </summary>
    /// <param name="aliasDisabled">True to prove a disabled alias keeps refusing.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HardwareAuthorityMigration_StaleAliasOfSameSeat_IsRepointedToCurrentAuthority(bool aliasDisabled)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);

        var staleBindingId = Guid.NewGuid();
        var staleEnrollmentId = Guid.NewGuid();
        int currentSecurityEpoch;
        Guid aliasId;
        Guid? previousMigrationRequestId;
        int previousAliasSecurityEpoch;
        long previousAliasAuthorityEpoch;
        Guid currentLicenseId;
        int activeSeatCount;
        int activeBindingCount;
        await using (var stale = await scenario.Factory.CreateDbContextAsync())
        {
            var current = await stale.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
            var currentEnrollment = await stale.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            currentLicenseId = currentEnrollment.LicenseId;
            currentSecurityEpoch = currentEnrollment.SecurityEpoch;
            var staleGrant = Guid.NewGuid().ToString("D");
            stale.DistributionInstallationBindings.Add(new DistributionInstallationBinding
            {
                Id = staleBindingId,
                ProductId = current.ProductId,
                LicenseId = current.LicenseId,
                LicenseSeatId = current.LicenseSeatId,
                EntitlementId = current.EntitlementId,
                SubjectRefDigestSha256 = current.SubjectRefDigestSha256,
                GrantRef = staleGrant,
                GrantRefDigestSha256 = Sha256(staleGrant),
                HandoffDigestSha256 = Sha256("stale-alias-handoff-" + staleBindingId.ToString("N")),
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareIdHash = current.HardwareIdHash,
                Version = current.Version,
                InstallerFilename = current.InstallerFilename,
                InstallerSha256 = current.InstallerSha256,
                ExecutableSha256 = current.ExecutableSha256,
                NativeDllSha256 = current.NativeDllSha256,
                CoreSha256 = current.CoreSha256,
                ApprovedBinariesSource = current.ApprovedBinariesSource,
                State = "invalidated",
                BoundAtUtc = DateTime.UtcNow.AddDays(-2),
                InitialSecurityEpoch = 1,
                InvalidatedAtUtc = DateTime.UtcNow.AddDays(-1),
                InvalidationReason = "installation_superseded"
            });
            stale.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = staleEnrollmentId,
                ClientId = currentEnrollment.ClientId,
                BindingId = staleBindingId,
                ProductId = currentEnrollment.ProductId,
                LicenseId = currentEnrollment.LicenseId,
                LicenseSeatId = currentEnrollment.LicenseSeatId,
                InstallationId = currentEnrollment.InstallationId,
                HardwareIdHash = currentEnrollment.HardwareIdHash,
                ReleaseVersion = currentEnrollment.ReleaseVersion,
                HandoffDigestSha256 = Sha256("stale-alias-handoff-" + staleBindingId.ToString("N")),
                SubjectRefDigestSha256 = currentEnrollment.SubjectRefDigestSha256,
                ProtocolVersion = currentEnrollment.ProtocolVersion,
                Algorithm = currentEnrollment.Algorithm,
                KeyBackend = currentEnrollment.KeyBackend,
                AttestationLevel = currentEnrollment.AttestationLevel,
                PublicKeySpkiCiphertext = currentEnrollment.PublicKeySpkiCiphertext,
                PublicKeySpkiKeyId = currentEnrollment.PublicKeySpkiKeyId,
                PublicKeySpkiSha256 = new string('5', 64),
                KeyThumbprint = "sl-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = currentEnrollment.ChallengeCiphertext,
                ChallengeKeyId = currentEnrollment.ChallengeKeyId,
                ChallengeDigestSha256 = new string('6', 64),
                State = "INVALIDATED",
                InvalidationReason = "authority_ineligible",
                Epoch = 1,
                SecurityEpoch = currentEnrollment.SecurityEpoch,
                AuthorityEpoch = currentEnrollment.AuthorityEpoch,
                ChallengeExpiresAtUtc = DateTime.UtcNow.AddDays(-2).AddHours(1),
                CreatedAtUtc = DateTime.UtcNow.AddDays(-2),
                InvalidatedAtUtc = DateTime.UtcNow.AddDays(-1)
            });
            await stale.SaveChangesAsync();
            var alias = await stale.HardwareAuthorityAliases.SingleAsync();
            aliasId = alias.Id;
            previousMigrationRequestId = alias.MigrationRequestId;
            previousAliasSecurityEpoch = alias.SecurityEpoch;
            previousAliasAuthorityEpoch = alias.AuthorityEpoch;
            alias.BindingId = staleBindingId;
            alias.RuntimeEnrollmentId = staleEnrollmentId;
            if (aliasDisabled)
            {
                alias.IsActive = false;
                alias.DisabledAtUtc = DateTime.UtcNow;
                alias.DisabledReason = "operator_disabled";
            }
            await stale.SaveChangesAsync();
            activeSeatCount = await stale.LicenseSeats.CountAsync(candidate =>
                candidate.LicenseId == current.LicenseId && candidate.IsActive);
            activeBindingCount = await stale.DistributionInstallationBindings.CountAsync(candidate =>
                candidate.LicenseId == current.LicenseId && candidate.State == "active");
        }

        var historyLogger = new RecordingLogger<RuntimeEnrollmentService>();
        var runtimeOptions = Options.Create(scenario.Options);
        var runtimeAuthority = new RuntimeEnrollmentAuthorityService(scenario.Factory, runtimeOptions);
        var runtimeRegistry = new RuntimeEnrollmentKeyRegistryService(scenario.Factory, runtimeOptions);
        using var runtimeCrypto = new RuntimeEnrollmentCryptoService(runtimeOptions);
        var runtime = new RuntimeEnrollmentService(
            scenario.Factory,
            runtimeAuthority,
            runtimeRegistry,
            runtimeCrypto,
            runtimeOptions,
            signedLicenseFiles: scenario.SignedLicenseFiles,
            historyLogger: historyLogger);
        // The Desktop signs the migration with its current enrollment epoch (5 for SUP-000040).
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        request.SecurityEpoch = currentSecurityEpoch;
        var digest = Sha256("stale-alias-repoint-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        if (aliasDisabled)
        {
            var conflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                runtime.MigrateHardwareAuthorityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
            Assert.Equal("hardware_authority_migration_conflict", conflict.ErrorCode);
            await using var refusedCheck = await scenario.Factory.CreateDbContextAsync();
            var unchanged = await refusedCheck.HardwareAuthorityAliases.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == aliasId);
            Assert.False(unchanged.IsActive);
            Assert.Equal(staleBindingId, unchanged.BindingId);
            Assert.Equal(staleEnrollmentId, unchanged.RuntimeEnrollmentId);
            Assert.Equal(previousMigrationRequestId, unchanged.MigrationRequestId);
            Assert.Equal(previousAliasSecurityEpoch, unchanged.SecurityEpoch);
            Assert.Equal(previousAliasAuthorityEpoch, unchanged.AuthorityEpoch);
            Assert.Equal(activeSeatCount, await refusedCheck.LicenseSeats.CountAsync(candidate =>
                candidate.LicenseId == unchanged.LicenseId && candidate.IsActive));
            Assert.Equal(activeBindingCount, await refusedCheck.DistributionInstallationBindings.CountAsync(candidate =>
                candidate.LicenseId == unchanged.LicenseId && candidate.State == "active"));
            Assert.DoesNotContain(historyLogger.Messages, message =>
                message.Contains("TEMP-FAIL-OPEN(TKT-001262)", StringComparison.Ordinal));
            return;
        }

        await using (var divergentCheck = await scenario.Factory.CreateDbContextAsync())
        {
            var failOpenLogger = new RecordingLogger<HardwareAuthorityAliasResolver>();
            var tolerated = await new HardwareAuthorityAliasResolver(
                divergentCheck,
                Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
                failOpenLogger).ResolveAsync(
                scenario.Fixture.ProductId,
                currentLicenseId,
                LegacyHardwareId,
                HardwareAuthorityResolutionIntent.StatusCheck);
            Assert.True(tolerated.UsedAlias);
            Assert.False(tolerated.Refused);
            Assert.Equal(StableHardwareId, tolerated.EffectiveHardwareId);
            Assert.Null(tolerated.BindingId);
            Assert.Single(failOpenLogger.Messages, message =>
                message.Contains(
                    "TEMP-FAIL-OPEN(TKT-001262) Hardware authority alias",
                    StringComparison.Ordinal));
        }

        var result = await runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.Equal("already_current", result.Response.Decision);
        Assert.False(result.Idempotent);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var repointed = await check.HardwareAuthorityAliases.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == aliasId);
        var activeEnrollment = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        Assert.Equal(scenario.Fixture.BindingId, repointed.BindingId);
        Assert.Equal(scenario.EnrollmentId, repointed.RuntimeEnrollmentId);
        Assert.Equal(Guid.Parse(request.RequestId!), repointed.MigrationRequestId);
        Assert.Equal(activeEnrollment.SecurityEpoch, repointed.SecurityEpoch);
        Assert.Equal(activeEnrollment.AuthorityEpoch, repointed.AuthorityEpoch);
        Assert.Equal(activeSeatCount, await check.LicenseSeats.CountAsync(candidate =>
            candidate.LicenseId == activeEnrollment.LicenseId && candidate.IsActive));
        Assert.Equal(activeBindingCount, await check.DistributionInstallationBindings.CountAsync(candidate =>
            candidate.LicenseId == activeEnrollment.LicenseId && candidate.State == "active"));

        var repairLog = Assert.Single(historyLogger.Messages, message =>
            message.Contains("TEMP-FAIL-OPEN(TKT-001262) ALIAS-REPOINT", StringComparison.Ordinal));
        Assert.Contains(aliasId.ToString(), repairLog, StringComparison.Ordinal);
        Assert.Contains(staleBindingId.ToString(), repairLog, StringComparison.Ordinal);
        Assert.Contains(scenario.Fixture.BindingId.ToString(), repairLog, StringComparison.Ordinal);
        Assert.Contains(staleEnrollmentId.ToString(), repairLog, StringComparison.Ordinal);
        Assert.Contains(scenario.EnrollmentId.ToString(), repairLog, StringComparison.Ordinal);
        Assert.Contains(request.RequestId!, repairLog, StringComparison.Ordinal);
        Assert.DoesNotContain(LegacyHardwareId, repairLog, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(StableHardwareId, repairLog, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha256(LegacyHardwareId), repairLog, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha256(StableHardwareId), repairLog, StringComparison.OrdinalIgnoreCase);

        var aliasLogger = new RecordingLogger<HardwareAuthorityAliasResolver>();
        var aliasResolution = await new HardwareAuthorityAliasResolver(
            check,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
            aliasLogger).ResolveAsync(
            scenario.Fixture.ProductId,
            activeEnrollment.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        Assert.True(aliasResolution.UsedAlias);
        Assert.False(aliasResolution.Refused);
        Assert.Equal(StableHardwareId, aliasResolution.EffectiveHardwareId);
        Assert.Equal(scenario.Fixture.BindingId, aliasResolution.BindingId);
        Assert.Equal(repointed.LicenseSeatId, aliasResolution.LicenseSeatId);
        Assert.DoesNotContain(aliasLogger.Messages, message =>
            message.Contains("tolerated AuthorityGraphDiverged", StringComparison.Ordinal));

        var replay = await runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.True(replay.Idempotent);
        Assert.Equal(result.ExactResponseBody, replay.ExactResponseBody);
        Assert.Equal(result.Response, replay.Response);
        Assert.Single(historyLogger.Messages, message =>
            message.Contains("TEMP-FAIL-OPEN(TKT-001262) ALIAS-REPOINT", StringComparison.Ordinal));
    }

    /// <summary>
    /// Proves the signed compatibility transition updates only licensing state, issues a V2
    /// license, preserves Runtime and assignment lineage, and replays exact response bytes.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_AtomicallyMovesExistingSeatAndReplays()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        Guid initialAssignmentId;
        int initialAssignmentRevision;
        string initialBindingHardwareIdHash;
        string initialEnrollmentHardwareIdHash;
        long initialSecurityEpoch;
        long initialAuthorityEpoch;
        long leaseAuditEpoch;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var initialEnrollment = await before.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            var initialAssignment = await before.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
            initialAssignmentId = initialAssignment.Id;
            initialAssignmentRevision = initialAssignment.Revision;
            initialBindingHardwareIdHash = (await before.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId)).HardwareIdHash;
            initialEnrollmentHardwareIdHash = initialEnrollment.HardwareIdHash;
            initialSecurityEpoch = initialEnrollment.SecurityEpoch;
            initialAuthorityEpoch = initialEnrollment.AuthorityEpoch;
            leaseAuditEpoch = await before.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-atomic-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var migrated = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var replay = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.False(migrated.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(migrated.ExactResponseBody, replay.ExactResponseBody);
        Assert.Equal("migrated", migrated.Response.Decision);
        Assert.Equal(initialSecurityEpoch, migrated.Response.OldSecurityEpoch);
        Assert.Equal(initialSecurityEpoch, migrated.Response.NewSecurityEpoch);
        Assert.Equal(StableHardwareId, migrated.Response.HardwareIdV2);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var binding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await check.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await check.Licenses.Include(candidate => candidate.Product)
            .SingleAsync(candidate => candidate.Id == binding.LicenseId);
        var alias = await check.HardwareAuthorityAliases.SingleAsync();
        var assignment = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
            candidate.EnrollmentId == enrollment.Id && candidate.State == "ACTIVE");
        var nonce = await check.RuntimeEnrollmentProofNonces.AsNoTracking().SingleAsync(candidate =>
            candidate.EnrollmentId == enrollment.Id && candidate.Operation == "hardware-authority-migration");
        Assert.Equal(StableHardwareId, seat.HardwareId);
        Assert.Equal(StableHardwareId, license.HardwareId);
        Assert.Equal(initialBindingHardwareIdHash, binding.HardwareIdHash);
        Assert.Equal(initialEnrollmentHardwareIdHash, enrollment.HardwareIdHash);
        Assert.Equal(initialSecurityEpoch, enrollment.SecurityEpoch);
        Assert.Equal(license.ProductId, alias.ProductId);
        Assert.Equal(license.Id, alias.LicenseId);
        Assert.Equal(seat.Id, alias.LicenseSeatId);
        Assert.Equal(enrollment.Id, alias.RuntimeEnrollmentId);
        Assert.Equal(binding.Id, alias.BindingId);
        Assert.Equal(Sha256(LegacyHardwareId), alias.LegacyHardwareIdSha256);
        Assert.Equal(Sha256(StableHardwareId), alias.CanonicalHardwareIdSha256);
        Assert.Equal(enrollment.SecurityEpoch, alias.SecurityEpoch);
        Assert.Equal(enrollment.AuthorityEpoch, alias.AuthorityEpoch);
        Assert.Equal(initialAuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.Equal(initialAssignmentId, assignment.Id);
        Assert.Equal(initialAssignmentRevision, assignment.Revision);
        Assert.Equal(license.Id, assignment.LicenseId);
        Assert.Equal(seat.Id, assignment.LicenseSeatId);
        Assert.Equal(leaseAuditEpoch, nonce.AuthorityEpoch);
        Assert.Single(await check.LicenseSeats.Where(candidate => candidate.LicenseId == license.Id).ToListAsync());
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.LicenseId == license.Id && candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        var targetConflictSql = check.LicenseSeats.Where(candidate => candidate.Id != seat.Id
            && candidate.IsActive && candidate.License!.ProductId == license.ProductId
            && candidate.HardwareId.ToUpper() == StableHardwareId).ToQueryString();
        Assert.Contains("upper(", targetConflictSql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ProductId", targetConflictSql, StringComparison.Ordinal);
        var validation = LicenseService.ValidateLicense(
            migrated.Response.LicenseFile, license.Product!.PublicKeyXml, StableHardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.False(LicenseService.ValidateLicense(
            migrated.Response.LicenseFile, license.Product.PublicKeyXml, LegacyHardwareId).IsValid);
    }

    /// <summary>
    /// Proves exact replay remains compatible with historical rows that already copied the
    /// canonical digest into the Runtime binding and enrollment. The frozen response is returned
    /// only after current authority revalidation and no commercial history is revised.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_ReplayAcceptsHistoricalCanonicalRuntimeEvidence()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-historical-replay-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var migrated = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            await using var lease = await authority.AcquireMutationAsync(
                mutate, scenario.Fixture.BindingId);
            var binding = await mutate.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            binding.HardwareIdHash = Sha256(StableHardwareId);
            enrollment.HardwareIdHash = binding.HardwareIdHash;
            await mutate.SaveChangesAsync();
            await lease.CommitAsync();
        }

        var replay = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.True(replay.Idempotent);
        Assert.Equal(migrated.ExactResponseBody, replay.ExactResponseBody);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.LicenseHistories.AsNoTracking().Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        Assert.Single(await check.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration").ToListAsync());
        Assert.Single(await check.EnrollmentLicenseAssignments.AsNoTracking().Where(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// Proves copied Runtime and binding HWID compatibility values are inert after the canonical seat
    /// has been migrated. The signed key, installation, current assignment, licence, and seat authorize
    /// exact replay without rewriting either historical value.
    /// </summary>
    /// <param name="evidenceShape">Copied Runtime evidence corruption to install.</param>
    [Theory]
    [InlineData("mixed")]
    [InlineData("third")]
    public async Task HardwareAuthorityMigration_CurrentSeatIgnoresHistoricalRuntimeHardwareEvidence(
        string evidenceShape)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        Guid assignmentId;
        int assignmentRevision;
        int nonceCount;
        int historyCount;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var assignment = await before.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
            assignmentId = assignment.Id;
            assignmentRevision = assignment.Revision;
            nonceCount = await before.RuntimeEnrollmentProofNonces.AsNoTracking().CountAsync(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId
                && candidate.Operation == "hardware-authority-migration");
            historyCount = await before.LicenseHistories.AsNoTracking().CountAsync(candidate =>
                candidate.Action == "HWID_V2_MIGRATED");
        }
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            await using var lease = await authority.AcquireMutationAsync(
                mutate, scenario.Fixture.BindingId);
            var binding = await mutate.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            if (evidenceShape == "mixed")
            {
                binding.HardwareIdHash = Sha256(StableHardwareId);
                enrollment.HardwareIdHash = Sha256(LegacyHardwareId);
            }
            else
            {
                var unknownDigest = Sha256("B6D3EED115BC84AD");
                binding.HardwareIdHash = unknownDigest;
                enrollment.HardwareIdHash = unknownDigest;
            }
            await mutate.SaveChangesAsync();
            await lease.CommitAsync();
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-runtime-evidence-" + evidenceShape + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var replay = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.False(replay.Idempotent);
        Assert.Equal("already_current", replay.Response.Decision);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var assignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
        Assert.Equal(assignmentId, assignmentAfter.Id);
        Assert.Equal(assignmentRevision, assignmentAfter.Revision);
        Assert.Equal(nonceCount + 1, await check.RuntimeEnrollmentProofNonces.AsNoTracking().CountAsync(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration"));
        Assert.Equal(historyCount, await check.LicenseHistories.AsNoTracking().CountAsync(candidate =>
            candidate.Action == "HWID_V2_MIGRATED"));
    }

    /// <summary>
    /// Proves a persistence failure after the licensing rows have been staged rolls back the seat,
    /// legacy licence projection, alias, history, nonce, quota, and assignment as one transaction.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_PersistenceFailureRollsBackLicensingOnlyMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        Guid assignmentId;
        int assignmentRevision;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var assignment = await before.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
            assignmentId = assignment.Id;
            assignmentRevision = assignment.Revision;
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = """
                CREATE FUNCTION public.tkt001312_fail_hardware_migration_history()
                RETURNS trigger LANGUAGE plpgsql AS $function$
                BEGIN
                    RAISE EXCEPTION 'task-owned migration rollback probe' USING ERRCODE = 'P0001';
                END;
                $function$;
                CREATE TRIGGER "TR_Tkt001312_FailHardwareMigrationHistory"
                BEFORE INSERT ON public."LicenseHistories"
                FOR EACH ROW WHEN (NEW."Action" = 'HWID_V2_MIGRATED')
                EXECUTE FUNCTION public.tkt001312_fail_hardware_migration_history();
                """;
            await command.ExecuteNonQueryAsync();
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-rollback-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        await Assert.ThrowsAsync<DbUpdateException>(() => scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        await AssertLegacyAuthorityUnchangedAsync(scenario);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var assignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
        Assert.Equal(assignmentId, assignmentAfter.Id);
        Assert.Equal(assignmentRevision, assignmentAfter.Revision);
        Assert.Empty(await check.HardwareAuthorityAliases.AsNoTracking().ToListAsync());
        Assert.Empty(await check.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration").ToListAsync());
        Assert.Empty(await check.RuntimeEnrollmentQuotas.AsNoTracking().Where(candidate =>
            candidate.Scope.StartsWith("hardware-migration-")).ToListAsync());
    }

    /// <summary>
    /// Proves unrelated commercial global-epoch advances remain nonce audit evidence and do not
    /// replace or increment the migration's historical enrollment lineage.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_CommercialEpochBumpsPreserveLocalLineage()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        long lineageBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            lineageBefore = await before.RuntimeEnrollments.AsNoTracking()
                .Where(candidate => candidate.Id == scenario.EnrollmentId)
                .Select(candidate => candidate.AuthorityEpoch).SingleAsync();
        }
        for (var maxSeats = 2; maxSeats <= 3; maxSeats++)
        {
            var authority = new RuntimeEnrollmentAuthorityService(
                scenario.Factory, Options.Create(scenario.Options));
            await using var mutate = await scenario.Factory.CreateDbContextAsync();
            await using var lease = await authority.AcquireMutationAsync(mutate, scenario.Fixture.BindingId);
            var licenseId = await mutate.DistributionInstallationBindings.AsNoTracking()
                .Where(candidate => candidate.Id == scenario.Fixture.BindingId)
                .Select(candidate => candidate.LicenseId).SingleAsync();
            var license = await mutate.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.MaxSeats = maxSeats;
            await mutate.SaveChangesAsync();
            await lease.CommitAsync();
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-commercial-epoch-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var nonce = await check.RuntimeEnrollmentProofNonces.AsNoTracking().SingleAsync(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration");
        Assert.Equal(lineageBefore, enrollment.AuthorityEpoch);
        Assert.True(nonce.AuthorityEpoch > enrollment.AuthorityEpoch);
        Assert.Equal(enrollment.AuthorityEpoch,
            (await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync()).AuthorityEpoch);
    }

    /// <summary>
    /// Proves the authenticated alias resolves the same V2 seat and never grants a second seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_ValidGraphResolvesCanonicalSeat()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolution = await CreateAliasResolver(db).ResolveAsync(
            binding.ProductId,
            binding.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);

        Assert.True(resolution.UsedAlias);
        Assert.Equal(StableHardwareId, resolution.EffectiveHardwareId);
        Assert.Single(await db.LicenseSeats.Where(candidate => candidate.LicenseId == binding.LicenseId).ToListAsync());
    }

    /// <summary>
    /// Proves distribution Finalize v2 resolves a signed migration alias before seat quota evaluation,
    /// supersedes the authenticated binding, and preserves one active canonical V2 seat at maxSeats one.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DistributionFinalizeV2ResolvesBeforeSeatQuota()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-alias-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);
        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);

        var finalized = await prepared.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-alias-success-" + Guid.NewGuid().ToString("D")),
            prepared.Request);

        Assert.False(finalized.Idempotent);
        Assert.Equal(Sha256(StableHardwareId), finalized.Response.HardwareIdHash);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var license = await check.Licenses.Include(candidate => candidate.Seats)
            .SingleAsync(candidate => candidate.Id == prepared.LicenseId);
        var activeBindings = await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == scenario.Fixture.ProductId && candidate.State == "active").ToListAsync();
        Assert.Equal(1, license.MaxSeats);
        var seat = Assert.Single(license.Seats);
        Assert.True(seat.IsActive);
        Assert.Equal(StableHardwareId, seat.HardwareId);
        Assert.Single(activeBindings);
        Assert.Equal(finalized.Response.BindingId, activeBindings[0].Id.ToString("D"));
        Assert.Equal(Sha256(StableHardwareId), activeBindings[0].HardwareIdHash);
        Assert.Equal(scenario.Fixture.BindingId, activeBindings[0].SupersededBindingId);
        Assert.DoesNotContain(await check.LicenseHistories.Where(candidate =>
            candidate.LicenseId == prepared.LicenseId).ToListAsync(), candidate =>
            candidate.Action is "RUNTIME_INITIAL_SEAT_CREATED" or "RUNTIME_INITIAL_SEAT_REACTIVATED");
    }


    /// <summary>Pre-UUID stable identifier S of the machine, from the retired disk migration (TKT-001277).</summary>
    private const string PreUuidStableHardwareId = "A6D3EED115BC84AD";

    /// <summary>
    /// TKT-001277, production shape measured on 30/09/2026: a seat already moved L to S whose binding and enrollment
    /// carry S. The S to U migration keeps L to S, adds S to U, and a later WebSetup reinstall submitting U finds its
    /// source binding and keeps one seat.
    /// </summary>
    [Fact]
    public async Task UuidMigration_SeatAlreadyStableWithBindingS_AddsTargetAliasAndReinstallKeepsOneSeat()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("uuid-migration-binding-s-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await SeedPreUuidStableSeatAsync(scenario, bindingCarriesLegacy: false);

        var migrated = await MigrateAsync(scenario, PreUuidStableHardwareId);

        Assert.Equal("migrated", migrated.Response.Decision);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var aliases = await check.HardwareAuthorityAliases.AsNoTracking().ToListAsync();
            Assert.Equal(2, aliases.Count);
            Assert.Contains(aliases, alias => alias.LegacyHardwareIdSha256 == Sha256(LegacyHardwareId)
                && alias.CanonicalHardwareIdSha256 == Sha256(PreUuidStableHardwareId));
            Assert.Contains(aliases, alias => alias.LegacyHardwareIdSha256 == Sha256(PreUuidStableHardwareId)
                && alias.CanonicalHardwareIdSha256 == Sha256(StableHardwareId));
            Assert.Equal(StableHardwareId, (await check.LicenseSeats.AsNoTracking().SingleAsync()).HardwareId);
            var licenseId = (await check.Licenses.AsNoTracking().SingleAsync()).Id;
            var resolution = await CreateAliasResolver(check).ResolveAsync(
                scenario.Fixture.ProductId, licenseId, PreUuidStableHardwareId, HardwareAuthorityResolutionIntent.Activation);
            Assert.True(resolution.UsedAlias);
            Assert.Equal(StableHardwareId, resolution.EffectiveHardwareId);
        }

        await AssertUuidReinstallKeepsOneSeatAsync(scenario, subjectRef);
    }

    /// <summary>
    /// TKT-001277 review B1: a seat already moved L to S whose binding still carries L. The migration retargets the
    /// L to S alias to U (one alias per target, source equal to the binding digest) instead of adding S to U, so the
    /// resolver and a WebSetup reinstall submitting U still find the source binding.
    /// </summary>
    [Fact]
    public async Task UuidMigration_SeatAlreadyStableWithBindingL_RetargetsChainedAliasAndReinstallKeepsOneSeat()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("uuid-migration-binding-l-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await SeedPreUuidStableSeatAsync(scenario, bindingCarriesLegacy: true);

        var migrated = await MigrateAsync(scenario, PreUuidStableHardwareId);

        Assert.Equal("migrated", migrated.Response.Decision);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
            Assert.Equal(Sha256(LegacyHardwareId), alias.LegacyHardwareIdSha256);
            Assert.Equal(Sha256(StableHardwareId), alias.CanonicalHardwareIdSha256);
            Assert.True(alias.IsActive);
            var licenseId = (await check.Licenses.AsNoTracking().SingleAsync()).Id;
            var resolution = await CreateAliasResolver(check).ResolveAsync(
                scenario.Fixture.ProductId, licenseId, LegacyHardwareId, HardwareAuthorityResolutionIntent.Activation);
            Assert.True(resolution.UsedAlias);
            Assert.Equal(StableHardwareId, resolution.EffectiveHardwareId);
        }

        await AssertUuidReinstallKeepsOneSeatAsync(scenario, subjectRef);
    }

    /// <summary>
    /// TKT-001277 counter-review B1: after the chained L to U migration, a new S to U request (fresh proof) answers
    /// already_current without adding a second alias to U, and an operator-disabled chained alias stays disabled.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UuidMigration_AlreadyCurrentAfterChainedMigration_KeepsOneTargetAliasAndOperatorDisable(
        bool operatorDisabled)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SeedPreUuidStableSeatAsync(scenario, bindingCarriesLegacy: true);
        await MigrateAsync(scenario, PreUuidStableHardwareId);
        if (operatorDisabled)
        {
            await using var disable = await scenario.Factory.CreateDbContextAsync();
            var alias = await disable.HardwareAuthorityAliases.SingleAsync();
            alias.IsActive = false;
            alias.DisabledAtUtc = DateTime.UtcNow;
            alias.DisabledReason = "operator_disabled";
            await disable.SaveChangesAsync();
        }

        var again = await MigrateAsync(scenario, PreUuidStableHardwareId);

        Assert.Equal("already_current", again.Response.Decision);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var aliases = await check.HardwareAuthorityAliases.AsNoTracking().ToListAsync();
        var target = Assert.Single(aliases);
        Assert.Equal(Sha256(StableHardwareId), target.CanonicalHardwareIdSha256);
        Assert.Equal(!operatorDisabled, target.IsActive);
        Assert.Single(await check.LicenseHistories.AsNoTracking()
            .Where(candidate => candidate.Action == HistoryActions.HardwareIdMigrated).ToListAsync());
    }

    /// <summary>
    /// TKT-001277 review I1: a real migration consumes one customer seat change; an exact replay does not charge it
    /// again.
    /// </summary>
    [Fact]
    public async Task UuidMigration_ConsumesOneSeatChangeOnlyOnce()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioDailySeatChangesAsync(scenario, 3, priorChangesToday: 0);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("uuid-migration-quota-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        await scenario.Runtime.MigrateHardwareAuthorityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var replay = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.True(replay.Idempotent);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var license = await check.Licenses.Include(candidate => candidate.Type).SingleAsync();
        var quota = await SeatChangeQuota.GetStatusAsync(check, license, DateTime.UtcNow);
        Assert.Equal(1, quota.UsedToday);
    }

    /// <summary>
    /// TKT-001277 review I1: when the daily seat changes are exhausted the migration is refused and nothing moves;
    /// the Desktop keeps the licence-file identifier and retries later.
    /// </summary>
    [Fact]
    public async Task UuidMigration_ExhaustedSeatChangeQuota_IsRefusedWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioDailySeatChangesAsync(scenario, 1, priorChangesToday: 1);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => MigrateAsync(scenario, LegacyHardwareId));

        Assert.Equal("max_daily_deactivations_reached", refused.ErrorCode);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(LegacyHardwareId, (await check.LicenseSeats.AsNoTracking().SingleAsync()).HardwareId);
        Assert.Empty(await check.HardwareAuthorityAliases.AsNoTracking().ToListAsync());
        Assert.Empty(await check.LicenseHistories.AsNoTracking()
            .Where(candidate => candidate.Action == HistoryActions.HardwareIdMigrated).ToListAsync());
    }

    /// <summary>
    /// TKT-001277, multi-seat licences: only the migrated seat changes; the other seat and a licence-level identifier
    /// that names another machine are left untouched.
    /// </summary>
    [Fact]
    public async Task UuidMigration_MultiSeatLicence_MovesOnlyTheMigratedSeat()
    {
        const string otherMachine = "0123456789ABCDEF";
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var authority = new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options));
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
            var license = await db.Licenses.SingleAsync();
            license.MaxSeats = 2;
            license.HardwareId = otherMachine;
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = otherMachine,
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            await lease.CommitAsync();
        }

        await MigrateAsync(scenario, LegacyHardwareId);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var seats = await check.LicenseSeats.AsNoTracking().ToListAsync();
        Assert.Equal(2, seats.Count(seat => seat.IsActive));
        Assert.Contains(seats, seat => seat.HardwareId == StableHardwareId);
        Assert.Contains(seats, seat => seat.HardwareId == otherMachine);
        Assert.Equal(otherMachine, (await check.Licenses.AsNoTracking().SingleAsync()).HardwareId);
    }

    /// <summary>
    /// Proves a fresh WebSetup can replace an unengaged successor while the authenticated alias
    /// still points at its predecessor. The second Finalize must advance the unique chain instead
    /// of attempting to create a second child for the predecessor.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_FreshFinalizeBeforeSuccessorEnrollment_AdvancesUniqueChain()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-alias-unengaged-successor"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);

        var firstPrepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        var first = await firstPrepared.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-alias-unengaged-first-" + Guid.NewGuid().ToString("D")),
            firstPrepared.Request);
        var firstSuccessorId = Guid.Parse(first.Response.BindingId);

        var secondPrepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        var second = await secondPrepared.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-alias-unengaged-second-" + Guid.NewGuid().ToString("D")),
            secondPrepared.Request);
        var secondSuccessorId = Guid.Parse(second.Response.BindingId);

        Assert.False(first.Idempotent);
        Assert.False(second.Idempotent);
        Assert.NotEqual(firstSuccessorId, secondSuccessorId);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var source = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
        var firstSuccessor = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == firstSuccessorId);
        var secondSuccessor = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == secondSuccessorId);
        var alias = await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync();

        Assert.Equal("invalidated", source.State);
        Assert.Equal("installation_superseded", source.InvalidationReason);
        Assert.Equal("invalidated", firstSuccessor.State);
        Assert.Equal("installation_superseded", firstSuccessor.InvalidationReason);
        Assert.Equal("active", secondSuccessor.State);
        Assert.Equal(scenario.Fixture.BindingId, firstSuccessor.SupersededBindingId);
        Assert.Equal(firstSuccessorId, secondSuccessor.SupersededBindingId);
        Assert.True(secondSuccessor.InitialSecurityEpoch > firstSuccessor.InitialSecurityEpoch);
        Assert.False(await check.RuntimeEnrollments.AnyAsync(candidate =>
            candidate.BindingId == firstSuccessorId || candidate.BindingId == secondSuccessorId));
        Assert.Equal(scenario.Fixture.BindingId, alias.BindingId);
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == scenario.Fixture.ProductId && candidate.State == "active").ToListAsync());
    }

    /// <summary>
    /// Proves intergeneration Finalize deliberately leaves the alias on its terminal predecessor
    /// until a real Prepare and signed Confirm establish the successor Runtime generation. Confirm
    /// then advances both alias pointers atomically, and exact Finalize and Confirm replays are inert.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DistributionFinalizeDefersRepointUntilSuccessorConfirmAndReplays()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-alias-repoint"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);

        Guid aliasId;
        Guid sourceEnrollmentId;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var sourceAlias = await before.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
            aliasId = sourceAlias.Id;
            sourceEnrollmentId = sourceAlias.RuntimeEnrollmentId;
            Assert.True(sourceAlias.IsActive);
            Assert.Equal(scenario.Fixture.BindingId, sourceAlias.BindingId);
            Assert.Equal(scenario.EnrollmentId, sourceEnrollmentId);
        }

        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        var exactPayloadDigest = Sha256("distribution-finalize-alias-repoint-" + Guid.NewGuid().ToString("D"));
        var finalized = await prepared.Service.FinalizeAsync(
            "website-step1",
            exactPayloadDigest,
            prepared.Request);
        var replay = await prepared.Service.FinalizeAsync(
            "website-step1",
            exactPayloadDigest,
            prepared.Request);

        Assert.False(finalized.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(finalized.Response, replay.Response);
        var successorBindingId = Guid.Parse(finalized.Response.BindingId);
        (Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version)
            successorFixture;
        await using (var deferred = await scenario.Factory.CreateDbContextAsync())
        {
            var successorBinding = await deferred.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == successorBindingId);
            Assert.Equal(scenario.Fixture.BindingId, successorBinding.SupersededBindingId);
            Assert.Equal("active", successorBinding.State);
            var sourceBinding = await deferred.DistributionInstallationBindings.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            Assert.Equal("invalidated", sourceBinding.State);
            Assert.Equal("installation_superseded", sourceBinding.InvalidationReason);
            var sourceEnrollment = await deferred.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == sourceEnrollmentId);
            Assert.Equal("INVALIDATED", sourceEnrollment.State);
            Assert.Equal("binding_superseded", sourceEnrollment.InvalidationReason);
            Assert.False(await deferred.RuntimeEnrollments.AnyAsync(candidate =>
                candidate.BindingId == successorBinding.Id));
            var staleAlias = await deferred.HardwareAuthorityAliases.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == aliasId);
            Assert.True(staleAlias.IsActive);
            Assert.Equal(sourceBinding.Id, staleAlias.BindingId);
            Assert.Equal(sourceEnrollment.Id, staleAlias.RuntimeEnrollmentId);
            successorFixture = (
                successorBinding.ProductId,
                successorBinding.Id,
                successorBinding.HandoffDigestSha256,
                successorBinding.InstallationId,
                successorBinding.Version);
        }

        using var successorKey = RSA.Create(3072);
        var prepareRequest = PrepareRequest(
            successorFixture, Guid.NewGuid().ToString("D"), successorKey);
        prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var preparedEnrollment = await scenario.Runtime.PrepareAsync(
            "website-step1",
            Sha256("distribution-finalize-alias-successor-prepare-" + Guid.NewGuid().ToString("D")),
            prepareRequest);
        var successorEnrollmentId = Guid.Parse(preparedEnrollment.Response.EnrollmentId);
        var confirmRequest = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = successorEnrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256(
            "distribution-finalize-alias-successor-confirm-" + Guid.NewGuid().ToString("D"));
        var confirmProof = Proof(
            successorKey,
            "confirm",
            successorEnrollmentId,
            scenario.Options.ConfirmAudience,
            preparedEnrollment.Response.Challenge,
            confirmDigest);

        var confirmed = await scenario.Runtime.ConfirmAsync(
            successorEnrollmentId,
            confirmDigest,
            confirmRequest,
            confirmProof,
            IPAddress.Loopback);
        var confirmReplay = await scenario.Runtime.ConfirmAsync(
            successorEnrollmentId,
            confirmDigest,
            confirmRequest,
            confirmProof,
            IPAddress.Loopback);

        Assert.False(confirmed.Idempotent);
        Assert.True(confirmReplay.Idempotent);
        Assert.Equal(confirmed.Response, confirmReplay.Response);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var successorEnrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == successorEnrollmentId);
        Assert.Equal("ACTIVE", successorEnrollment.State);
        Assert.Equal(successorBindingId, successorEnrollment.BindingId);
        var repointedAlias = await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == aliasId);
        Assert.True(repointedAlias.IsActive);
        Assert.Equal(successorBindingId, repointedAlias.BindingId);
        Assert.Equal(successorEnrollmentId, repointedAlias.RuntimeEnrollmentId);
        Assert.Equal(successorEnrollment.SecurityEpoch, repointedAlias.SecurityEpoch);
        Assert.Equal(successorEnrollment.AuthorityEpoch, repointedAlias.AuthorityEpoch);
        var strictResolution = await CreateAliasResolver(check).ResolveAsync(
            scenario.Fixture.ProductId,
            prepared.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        Assert.True(strictResolution.UsedAlias);
        Assert.False(strictResolution.Refused);
        Assert.Equal(successorBindingId, strictResolution.BindingId);
    }

    /// <summary>Proves Confirm succeeds without creating or reactivating absent and disabled aliases.</summary>
    /// <param name="removeAlias">True removes the predecessor alias; false disables it explicitly.</param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_MissingOrDisabledAliasIsNoOp(bool removeAlias)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-no-op-" + removeAlias);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await mutate.HardwareAuthorityAliases.SingleAsync(candidate =>
                candidate.Id == successor.AliasId);
            if (removeAlias)
                mutate.HardwareAuthorityAliases.Remove(alias);
            else
            {
                alias.IsActive = false;
                alias.DisabledAtUtc = DateTime.UtcNow;
                alias.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason;
            }
            await mutate.SaveChangesAsync();
        }

        var confirmed = await scenario.Runtime.ConfirmAsync(
            successor.EnrollmentId,
            successor.ConfirmDigest,
            successor.ConfirmRequest,
            successor.ConfirmProof,
            IPAddress.Loopback);

        Assert.False(confirmed.Idempotent);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("ACTIVE", (await check.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == successor.EnrollmentId)).State);
        var retained = await check.HardwareAuthorityAliases.SingleOrDefaultAsync(candidate =>
            candidate.Id == successor.AliasId);
        if (removeAlias)
            Assert.Null(retained);
        else
        {
            Assert.NotNull(retained);
            Assert.False(retained.IsActive);
            Assert.Equal(successor.SourceBindingId, retained.BindingId);
            Assert.Equal(successor.SourceEnrollmentId, retained.RuntimeEnrollmentId);
        }
    }

    /// <summary>
    /// Proves a second active legacy digest already tied to the successor generation does not make
    /// the direct-predecessor alias ambiguous merely because both aliases share one canonical seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_IgnoresUnrelatedActiveSameSeatAlias()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-unrelated-same-seat");
        Guid unrelatedAliasId;
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var sourceAlias = await seed.HardwareAuthorityAliases.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == successor.AliasId);
            var pending = await seed.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == successor.EnrollmentId);
            unrelatedAliasId = Guid.NewGuid();
            seed.HardwareAuthorityAliases.Add(new HardwareAuthorityAlias
            {
                Id = unrelatedAliasId,
                ProductId = sourceAlias.ProductId,
                LicenseId = sourceAlias.LicenseId,
                LicenseSeatId = sourceAlias.LicenseSeatId,
                RuntimeEnrollmentId = pending.Id,
                BindingId = pending.BindingId,
                LegacyHardwareIdSha256 = Sha256("unrelated-legacy-hardware-id"),
                CanonicalHardwareIdSha256 = sourceAlias.CanonicalHardwareIdSha256,
                SecurityEpoch = pending.SecurityEpoch,
                AuthorityEpoch = pending.AuthorityEpoch,
                IsActive = true,
                CreatedAtUtc = DateTime.UtcNow
            });
            await seed.SaveChangesAsync();
        }

        await scenario.Runtime.ConfirmAsync(
            successor.EnrollmentId,
            successor.ConfirmDigest,
            successor.ConfirmRequest,
            successor.ConfirmProof,
            IPAddress.Loopback);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var predecessorAlias = await check.HardwareAuthorityAliases.SingleAsync(candidate =>
            candidate.Id == successor.AliasId);
        var unrelatedAlias = await check.HardwareAuthorityAliases.SingleAsync(candidate =>
            candidate.Id == unrelatedAliasId);
        Assert.Equal(successor.BindingId, predecessorAlias.BindingId);
        Assert.Equal(successor.EnrollmentId, predecessorAlias.RuntimeEnrollmentId);
        Assert.Equal(successor.BindingId, unrelatedAlias.BindingId);
        Assert.Equal(successor.EnrollmentId, unrelatedAlias.RuntimeEnrollmentId);
    }

    /// <summary>Proves multiple active aliases tied to the direct predecessor fail Confirm closed.</summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_AmbiguousPredecessorAliasesFailClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-ambiguous-predecessor");
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var sourceAlias = await seed.HardwareAuthorityAliases.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == successor.AliasId);
            seed.HardwareAuthorityAliases.Add(new HardwareAuthorityAlias
            {
                ProductId = sourceAlias.ProductId,
                LicenseId = sourceAlias.LicenseId,
                LicenseSeatId = sourceAlias.LicenseSeatId,
                RuntimeEnrollmentId = sourceAlias.RuntimeEnrollmentId,
                BindingId = sourceAlias.BindingId,
                LegacyHardwareIdSha256 = Sha256("ambiguous-predecessor-legacy-id"),
                CanonicalHardwareIdSha256 = sourceAlias.CanonicalHardwareIdSha256,
                SecurityEpoch = sourceAlias.SecurityEpoch,
                AuthorityEpoch = sourceAlias.AuthorityEpoch,
                IsActive = true,
                CreatedAtUtc = DateTime.UtcNow
            });
            await seed.SaveChangesAsync();
        }

        var conflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                successor.ConfirmProof,
                IPAddress.Loopback));

        Assert.Equal("enrollment_conflict", conflict.ErrorCode);
        Assert.Equal("confirm_alias_ambiguous", conflict.DiagnosticCode);
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>
    /// Proves direct-predecessor boundary, terminal and epoch violations never repoint an alias;
    /// active evidence tied to the declared predecessor fails closed, while no declared lineage is a no-op.
    /// </summary>
    /// <param name="mutation">Exact authoritative dimension corrupted before Confirm.</param>
    [Theory]
    [InlineData("alias-product")]
    [InlineData("alias-license")]
    [InlineData("alias-seat")]
    [InlineData("alias-canonical-hash")]
    [InlineData("predecessor-not-direct")]
    [InlineData("predecessor-subject")]
    [InlineData("source-client")]
    [InlineData("source-release")]
    [InlineData("successor-initial-security-epoch")]
    [InlineData("alias-authority-epoch")]
    [InlineData("predecessor-binding-state")]
    [InlineData("predecessor-binding-reason")]
    [InlineData("predecessor-enrollment-state")]
    [InlineData("source-authority-epoch")]
    [InlineData("source-terminal-reason")]
    [InlineData("alias-security-epoch")]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_InvalidPredecessorGraphFailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-invalid-" + mutation);
        var expectedAliasSecurityEpoch = successor.AliasSecurityEpoch;
        var expectedAliasAuthorityEpoch = successor.AliasAuthorityEpoch;
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await mutate.HardwareAuthorityAliases.SingleAsync(candidate =>
                candidate.Id == successor.AliasId);
            var sourceEnrollment = await mutate.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == successor.SourceEnrollmentId);
            var sourceBinding = await mutate.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == successor.SourceBindingId);
            var successorBinding = await mutate.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == successor.BindingId);
            switch (mutation)
            {
                case "alias-product":
                    var otherProduct = new Product
                    {
                        Name = "Confirm alias boundary " + Guid.NewGuid().ToString("N"),
                        PrivateKeyXml = "test",
                        PublicKeyXml = "test",
                        ApiSecret = Guid.NewGuid().ToString("N")
                    };
                    mutate.Products.Add(otherProduct);
                    alias.ProductId = otherProduct.Id;
                    break;
                case "alias-license":
                    var sourceLicense = await mutate.Licenses.AsNoTracking().SingleAsync(candidate =>
                        candidate.Id == alias.LicenseId);
                    var otherLicense = new License
                    {
                        LicenseKey = "TKT-001262-" + Guid.NewGuid().ToString("N"),
                        CustomerName = "Confirm alias boundary",
                        CustomerEmail = "confirm-alias-boundary@example.test",
                        LicenseTypeId = sourceLicense.LicenseTypeId,
                        ProductId = sourceLicense.ProductId,
                        AllowedVersions = sourceLicense.AllowedVersions,
                        MaxSeats = 1,
                        IsActive = true
                    };
                    mutate.Licenses.Add(otherLicense);
                    alias.LicenseId = otherLicense.Id;
                    break;
                case "alias-seat":
                    var otherSeat = new LicenseSeat
                    {
                        LicenseId = alias.LicenseId,
                        HardwareId = "0011223344556677",
                        IsActive = false,
                        UnlinkedAt = DateTime.UtcNow
                    };
                    mutate.LicenseSeats.Add(otherSeat);
                    alias.LicenseSeatId = otherSeat.Id;
                    break;
                case "alias-canonical-hash":
                    alias.CanonicalHardwareIdSha256 = Sha256("different-canonical-machine");
                    break;
                case "predecessor-not-direct":
                    successorBinding.SupersededBindingId = null;
                    break;
                case "predecessor-subject":
                    sourceBinding.SubjectRefDigestSha256 = Sha256("different-predecessor-subject");
                    break;
                case "source-client":
                    sourceEnrollment.ClientId = "different-s2s-client";
                    break;
                case "source-release":
                    sourceEnrollment.ReleaseVersion = "99.0.0";
                    break;
                case "successor-initial-security-epoch":
                    successorBinding.InitialSecurityEpoch++;
                    break;
                case "alias-authority-epoch":
                    alias.AuthorityEpoch = long.MaxValue;
                    expectedAliasAuthorityEpoch = alias.AuthorityEpoch;
                    break;
                case "predecessor-binding-state":
                    sourceBinding.State = "corrupt";
                    break;
                case "predecessor-binding-reason":
                    sourceBinding.InvalidationReason = "security_revoked";
                    break;
                case "predecessor-enrollment-state":
                    sourceEnrollment.State = "PENDING";
                    break;
                case "source-authority-epoch":
                    sourceEnrollment.AuthorityEpoch = long.MaxValue;
                    break;
                case "source-terminal-reason":
                    sourceEnrollment.InvalidationReason = "security_revoked";
                    break;
                case "alias-security-epoch":
                    alias.SecurityEpoch = int.MaxValue;
                    expectedAliasSecurityEpoch = alias.SecurityEpoch;
                    break;
                default:
                    throw new InvalidOperationException("Unknown Confirm alias mutation: " + mutation);
            }
            await mutate.SaveChangesAsync();
        }

        if (mutation == "predecessor-not-direct")
        {
            await scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                successor.ConfirmProof,
                IPAddress.Loopback);
            await using var check = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal("ACTIVE", (await check.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == successor.EnrollmentId)).State);
            var alias = await check.HardwareAuthorityAliases.SingleAsync(candidate =>
                candidate.Id == successor.AliasId);
            Assert.Equal(successor.SourceBindingId, alias.BindingId);
            Assert.Equal(successor.SourceEnrollmentId, alias.RuntimeEnrollmentId);
            return;
        }

        var conflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                successor.ConfirmProof,
                IPAddress.Loopback));

        Assert.Equal("enrollment_conflict", conflict.ErrorCode);
        Assert.Equal(ExpectedConfirmAliasDiagnostic(mutation), conflict.DiagnosticCode);
        await AssertPendingSuccessorAndStaleAliasAsync(
            scenario,
            successor,
            expectedAliasSecurityEpoch,
            expectedAliasAuthorityEpoch);
    }

    /// <summary>
    /// Proves representative boundary and ownership failures retain one public conflict while
    /// producing distinct, redacted, allowlisted server diagnostics.
    /// </summary>
    /// <param name="mutation">Exact predecessor evidence corrupted before Confirm.</param>
    /// <param name="expectedDiagnostic">Stable server-only reason expected in the exception and warning.</param>
    [Theory]
    [InlineData("alias-canonical-hash", "confirm_alias_boundary_mismatch")]
    [InlineData("source-client", "confirm_alias_owner_mismatch")]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_DiagnosticsAreDifferentiatedAndRedacted(
        string mutation,
        string expectedDiagnostic)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-diagnostic-" + mutation);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            if (mutation == "alias-canonical-hash")
            {
                var alias = await mutate.HardwareAuthorityAliases.SingleAsync(candidate =>
                    candidate.Id == successor.AliasId);
                alias.CanonicalHardwareIdSha256 = Sha256("diagnostic-different-machine");
            }
            else
            {
                var sourceEnrollment = await mutate.RuntimeEnrollments.SingleAsync(candidate =>
                    candidate.Id == successor.SourceEnrollmentId);
                sourceEnrollment.ClientId = "diagnostic-different-client";
            }
            await mutate.SaveChangesAsync();
        }
        var logger = new RecordingLogger<RuntimeEnrollmentService>();
        var tagged = CreateTaggedRuntime(
            scenario,
            "confirm-diagnostic-" + Guid.NewGuid().ToString("N"),
            logger);
        using var crypto = tagged.Crypto;

        var conflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            tagged.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                successor.ConfirmProof,
                IPAddress.Loopback));

        Assert.Equal("enrollment_conflict", conflict.ErrorCode);
        Assert.Equal(expectedDiagnostic, conflict.DiagnosticCode);
        var warning = Assert.Single(logger.Messages, message =>
            message.Contains("Runtime Confirm alias repoint refused", StringComparison.Ordinal));
        Assert.Contains(expectedDiagnostic, warning, StringComparison.Ordinal);
        Assert.Contains(successor.AliasId.ToString("D"), warning, StringComparison.Ordinal);
        Assert.DoesNotContain(LegacyHardwareId, warning, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(StableHardwareId, warning, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha256(LegacyHardwareId), warning, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha256(StableHardwareId), warning, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(successor.ConfirmDigest, warning, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(successor.Challenge, warning, StringComparison.Ordinal);
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>Proves an invalid Confirm proof cannot advance either alias pointer.</summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_InvalidProofLeavesAliasOnPredecessor()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-invalid-proof");
        using var attackerKey = RSA.Create(3072);
        var invalidProof = Proof(
            attackerKey,
            "confirm",
            successor.EnrollmentId,
            scenario.Options.ConfirmAudience,
            successor.Challenge,
            successor.ConfirmDigest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                invalidProof,
                IPAddress.Loopback));

        Assert.Equal("authentication_failed", rejected.ErrorCode);
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>Proves an expired successor challenge cannot activate the enrollment or repoint the alias.</summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_ExpiredChallengeLeavesAliasOnPredecessor()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-expired-challenge");
        await using (var expire = await scenario.Factory.CreateDbContextAsync())
        {
            await expire.RuntimeEnrollments.Where(candidate => candidate.Id == successor.EnrollmentId)
                .ExecuteUpdateAsync(update => update.SetProperty(
                    candidate => candidate.ChallengeExpiresAtUtc,
                    DateTime.UtcNow.AddMinutes(-1)));
        }

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                successor.ConfirmProof,
                IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status410Gone, rejected.StatusCode);
        Assert.Equal("challenge_expired", rejected.ErrorCode);
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>
    /// Proves a database failure on the alias update rolls back enrollment activation, proof nonce,
    /// both alias pointers and their minimum epochs as one Confirm transaction.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_AliasUpdateFailureRollsBackTransaction()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-alias-update-failure");
        await InstallAliasUpdateFailureTriggerAsync(scenario.AdminConnectionString);
        try
        {
            await Assert.ThrowsAsync<DbUpdateException>(() => scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId,
                successor.ConfirmDigest,
                successor.ConfirmRequest,
                successor.ConfirmProof,
                IPAddress.Loopback));
        }
        finally
        {
            await RemoveAliasUpdateFailureTriggerAsync(scenario.AdminConnectionString);
        }

        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>Proves concurrent exact Confirms serialize to one mutation and one replay.</summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_ConcurrentExactRequestsRepointOnce()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-concurrent");
        var firstApplicationName = "confirm-exact-first-" + Guid.NewGuid().ToString("N");
        var secondApplicationName = "confirm-exact-second-" + Guid.NewGuid().ToString("N");
        var firstRuntime = CreateTaggedRuntime(scenario, firstApplicationName);
        var secondRuntime = CreateTaggedRuntime(scenario, secondApplicationName);
        using var firstCrypto = firstRuntime.Crypto;
        using var secondCrypto = secondRuntime.Crypto;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = timeout.Token;
        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await blockerCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var first = CaptureConfirmAsync(firstRuntime.Runtime.ConfirmAsync(
            successor.EnrollmentId,
            successor.ConfirmDigest,
            successor.ConfirmRequest,
            successor.ConfirmProof,
            IPAddress.Loopback,
            cancellationToken));
        var second = CaptureConfirmAsync(secondRuntime.Runtime.ConfirmAsync(
            successor.EnrollmentId,
            successor.ConfirmDigest,
            successor.ConfirmRequest,
            successor.ConfirmProof,
            IPAddress.Loopback,
            cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [firstApplicationName, secondApplicationName],
            minimumWaiters: 2,
            cancellationToken);
        await blockerTransaction.CommitAsync(cancellationToken);
        var outcomes = await Task.WhenAll(first, second).WaitAsync(cancellationToken);

        Assert.All(outcomes, outcome => Assert.Null(outcome.Error));
        Assert.Single(outcomes, outcome => outcome.Result is { Idempotent: false });
        Assert.Single(outcomes, outcome => outcome.Result is { Idempotent: true });
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var alias = await check.HardwareAuthorityAliases.SingleAsync(candidate =>
            candidate.Id == successor.AliasId);
        Assert.Equal(successor.BindingId, alias.BindingId);
        Assert.Equal(successor.EnrollmentId, alias.RuntimeEnrollmentId);
        Assert.Single(await check.RuntimeEnrollmentProofNonces.Where(candidate =>
            candidate.EnrollmentId == successor.EnrollmentId && candidate.Operation == "confirm").ToListAsync());
    }

    /// <summary>
    /// Proves two different valid proof nonces for one pending successor serialize: one activates
    /// and repoints, while the competing nonce observes the committed enrollment conflict.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SuccessorConfirm_ConcurrentDistinctProofsHaveOneWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(
            scenario, "successor-confirm-competing-proofs");
        var competingProof = Proof(
            successor.Key,
            "confirm",
            successor.EnrollmentId,
            scenario.Options.ConfirmAudience,
            successor.Challenge,
            successor.ConfirmDigest);
        var firstApplicationName = "confirm-distinct-first-" + Guid.NewGuid().ToString("N");
        var secondApplicationName = "confirm-distinct-second-" + Guid.NewGuid().ToString("N");
        var firstRuntime = CreateTaggedRuntime(scenario, firstApplicationName);
        var secondRuntime = CreateTaggedRuntime(scenario, secondApplicationName);
        using var firstCrypto = firstRuntime.Crypto;
        using var secondCrypto = secondRuntime.Crypto;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = timeout.Token;
        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await blockerCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var first = CaptureConfirmAsync(firstRuntime.Runtime.ConfirmAsync(
            successor.EnrollmentId,
            successor.ConfirmDigest,
            successor.ConfirmRequest,
            successor.ConfirmProof,
            IPAddress.Loopback,
            cancellationToken));
        var second = CaptureConfirmAsync(secondRuntime.Runtime.ConfirmAsync(
            successor.EnrollmentId,
            successor.ConfirmDigest,
            successor.ConfirmRequest,
            competingProof,
            IPAddress.Loopback,
            cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [firstApplicationName, secondApplicationName],
            minimumWaiters: 2,
            cancellationToken);
        await blockerTransaction.CommitAsync(cancellationToken);
        var outcomes = await Task.WhenAll(first, second).WaitAsync(cancellationToken);

        var winner = Assert.Single(outcomes, outcome => outcome.Result is { Idempotent: false });
        Assert.Null(winner.Error);
        var loser = Assert.Single(outcomes, outcome => outcome.Error != null);
        var conflict = Assert.IsType<RuntimeEnrollmentException>(loser.Error);
        Assert.Equal("enrollment_conflict", conflict.ErrorCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var alias = await check.HardwareAuthorityAliases.SingleAsync(candidate =>
            candidate.Id == successor.AliasId);
        Assert.Equal(successor.BindingId, alias.BindingId);
        Assert.Equal(successor.EnrollmentId, alias.RuntimeEnrollmentId);
        Assert.Single(await check.RuntimeEnrollmentProofNonces.Where(candidate =>
            candidate.EnrollmentId == successor.EnrollmentId && candidate.Operation == "confirm").ToListAsync());
    }

    /// <summary>
    /// Reproduces the production forced-update graph where the obsolete Runtime generation was
    /// terminalized for execution while its server-authenticated alias, binding and seat remain
    /// coherent. A supported installer must rotate that exact authority to the current version
    /// without allocating a second seat or accepting a client-declared source identity.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_ForcedUpdateAfterVersionTerminalization_RotatesOneSeat()
    {
        const string obsoleteVersion = "2.3.591";
        const string currentVersion = "2.4.402";
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var migrationCrypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var subjectRef = Base64Url(SHA256.HashData("forced-update-version-authority"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);

        await using (var terminalize = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await terminalize.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var enrollment = await terminalize.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            var seat = await terminalize.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == binding.LicenseSeatId);
            var product = await terminalize.Products.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.ProductId);
            var license = await terminalize.Licenses.SingleAsync(candidate =>
                candidate.Id == binding.LicenseId);
            var currentBinaries = await terminalize.ApprovedBinaries.AsNoTracking()
                .Where(candidate => candidate.ProductId == scenario.Fixture.ProductId
                    && candidate.Version == scenario.Fixture.Version)
                .ToListAsync();

            product.MinimumAllowedVersion = "2.4.300";
            license.AllowedVersions = "*";
            binding.Version = obsoleteVersion;
            enrollment.ReleaseVersion = obsoleteVersion;
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "authority_ineligible";
            seat.AppVersion = obsoleteVersion;
            terminalize.ApprovedBinaries.AddRange(
                new[] { obsoleteVersion, currentVersion }.SelectMany(version =>
                    currentBinaries.Select(candidate => new ApprovedBinary
                    {
                        ProductId = candidate.ProductId,
                        Version = version,
                        Key = candidate.Key,
                        Hash = candidate.Hash,
                        Source = candidate.Source
                    })));
            await terminalize.SaveChangesAsync();
        }

        await using var resolverDb = await scenario.Factory.CreateDbContextAsync();
        var sourceBinding = await resolverDb.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        Assert.Equal(
            RuntimeBindingEligibility.VersionIneligible,
            await RuntimeBindingEligibilityEvaluator.EvaluateAsync(
                resolverDb,
                sourceBinding,
                DateTimeOffset.UtcNow,
                allowIneligibleSourceLicense: false,
                CancellationToken.None, migrationCrypto));
        var sourceResolution = await CreateAliasResolver(resolverDb, migrationCrypto).ResolveAsync(
            scenario.Fixture.ProductId,
            sourceBinding.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Finalize);
        Assert.True(sourceResolution.UsedAlias);

        await SetHardwareBanAsync(scenario, StableHardwareId, active: true);
        var bannedResolution = await CreateAliasResolver(resolverDb, migrationCrypto).ResolveAsync(
            scenario.Fixture.ProductId,
            sourceBinding.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Finalize);
        Assert.True(bannedResolution.Refused);
        Assert.Equal(HardwareAuthorityRefusalReason.AuthorityGraphDiverged, bannedResolution.RefusalReason);
        await SetHardwareBanAsync(scenario, StableHardwareId, active: false);

        await using (var tamper = await scenario.Factory.CreateDbContextAsync())
        {
            var baseline = await tamper.ApprovedBinaries.SingleAsync(candidate =>
                candidate.ProductId == scenario.Fixture.ProductId
                && candidate.Version == obsoleteVersion
                && candidate.Key == "FP_EXE");
            var approvedHash = baseline.Hash;
            baseline.Hash = new string('0', 64);
            await tamper.SaveChangesAsync();

            var tamperedResolution = await CreateAliasResolver(tamper, migrationCrypto).ResolveAsync(
                scenario.Fixture.ProductId,
                sourceBinding.LicenseId,
                LegacyHardwareId,
                HardwareAuthorityResolutionIntent.Finalize);
            // TEMP-FAIL-OPEN(TKT-001262): a divergent source baseline no longer blocks the authenticated
            // alias; the target release still passes Finalize's own ApprovedBinaries check.
            Assert.False(tamperedResolution.Refused);
            Assert.True(tamperedResolution.UsedAlias);

            baseline.Hash = approvedHash;
            await tamper.SaveChangesAsync();
        }

        await using (var securityTerminal = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await securityTerminal.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            enrollment.InvalidationReason = "security_revoked";
            await securityTerminal.SaveChangesAsync();

            var securityResolution = await CreateAliasResolver(securityTerminal, migrationCrypto).ResolveAsync(
                scenario.Fixture.ProductId,
                sourceBinding.LicenseId,
                LegacyHardwareId,
                HardwareAuthorityResolutionIntent.Finalize);
            // TEMP-FAIL-OPEN(TKT-001262): Franck's directive keeps only certain business refusals
            // (ineligible licence, active explicit ban, real quota). A historical security terminal
            // on the alias enrollment is logged and tolerated; an active ban still refuses above.
            Assert.False(securityResolution.Refused);
            Assert.True(securityResolution.UsedAlias);

            enrollment.InvalidationReason = "authority_ineligible";
            await securityTerminal.SaveChangesAsync();
        }

        var prepared = await PrepareDistributionFinalizeAsync(
            scenario,
            subjectRef,
            LegacyHardwareId,
            hardwareAuthorityAliases: CreateAliasResolver(resolverDb, migrationCrypto));
        Assert.NotNull(prepared.Request.Release);
        prepared.Request.Release.Version = currentVersion;

        var finalized = await prepared.Service.FinalizeAsync(
            "website-step1",
            Sha256("forced-update-version-authority-finalize-" + Guid.NewGuid().ToString("D")),
            prepared.Request);

        Assert.False(finalized.Idempotent);
        Assert.Equal(Sha256(StableHardwareId), finalized.Response.HardwareIdHash);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var seats = await check.LicenseSeats
            .Where(candidate => candidate.LicenseId == prepared.LicenseId)
            .ToListAsync();
        Assert.Single(seats);
        Assert.True(seats[0].IsActive);
        Assert.Equal(StableHardwareId, seats[0].HardwareId);
        var activeBinding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.LicenseId == prepared.LicenseId && candidate.State == "active");
        Assert.Equal(currentVersion, activeBinding.Version);
        Assert.Equal(scenario.Fixture.BindingId, activeBinding.SupersededBindingId);

        // SUP-000040 (TKT-001262): Finalize rotated the binding but the alias still points at the
        // superseded one. The next Desktop start resolves the Runtime source with the legacy
        // identifier; it must no longer fail with replacement_source_authority_mismatch, and every
        // later alias resolution must reach the canonical seat and the new active binding.
        await using var afterRotation = await scenario.Factory.CreateDbContextAsync();
        var failOpenLogger = new RecordingLogger<HardwareAuthorityAliasResolver>();
        var statusResolution = await new HardwareAuthorityAliasResolver(
            afterRotation,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
            failOpenLogger).ResolveAsync(
            scenario.Fixture.ProductId,
            prepared.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        Assert.True(statusResolution.UsedAlias);
        Assert.Equal(StableHardwareId, statusResolution.EffectiveHardwareId);
        Assert.Equal(activeBinding.Id, statusResolution.BindingId);
        // TEMP-FAIL-OPEN(TKT-001262): the tolerance is observable with every repair fact and no
        // hardware identifier or digest.
        var failOpen = Assert.Single(failOpenLogger.Messages, message =>
            message.Contains("TEMP-FAIL-OPEN(TKT-001262)", StringComparison.Ordinal));
        Assert.Contains("intent StatusCheck", failOpen, StringComparison.Ordinal);
        Assert.Contains(prepared.LicenseId.ToString(), failOpen, StringComparison.Ordinal);
        Assert.Contains(scenario.Fixture.BindingId.ToString(), failOpen, StringComparison.Ordinal);
        Assert.Contains("successor binding " + activeBinding.Id, failOpen, StringComparison.Ordinal);
        Assert.Contains("supersedes " + scenario.Fixture.BindingId, failOpen, StringComparison.Ordinal);
        Assert.Contains("active binding candidates 1 (exact)", failOpen, StringComparison.Ordinal);
        Assert.Contains("correlation ", failOpen, StringComparison.Ordinal);
        Assert.Contains("truncated False", failOpen, StringComparison.Ordinal);
        Assert.DoesNotContain(LegacyHardwareId, failOpen, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(StableHardwareId, failOpen, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha256(LegacyHardwareId), failOpen, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha256(StableHardwareId), failOpen, StringComparison.OrdinalIgnoreCase);
        // R7: inside the TEMP-FAIL-OPEN branch an active explicit ban on either identifier keeps
        // the refusal; the ban is lifted again afterwards.
        foreach (var bannedHardwareId in new[] { LegacyHardwareId, StableHardwareId })
        {
            await SetHardwareBanAsync(scenario, bannedHardwareId, active: true);
            await using (var bannedDb = await scenario.Factory.CreateDbContextAsync())
            {
                var banned = await CreateAliasResolver(bannedDb, migrationCrypto).ResolveAsync(
                    scenario.Fixture.ProductId,
                    prepared.LicenseId,
                    LegacyHardwareId,
                    HardwareAuthorityResolutionIntent.StatusCheck);
                Assert.True(banned.Refused);
                Assert.Equal(HardwareAuthorityRefusalReason.AuthorityGraphDiverged, banned.RefusalReason);
            }
            await SetHardwareBanAsync(scenario, bannedHardwareId, active: false);
        }
        var runtimeSource = await prepared.Service.ResolveRuntimeSourceAsync(
            "website-step1",
            new DistributionRuntimeSourceResolutionRequest
            {
                Schema = DistributionInstallationBindingService.RuntimeSourceResolutionSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                TargetLicenseId = prepared.LicenseId.ToString("D"),
                HardwareId = LegacyHardwareId
            });
        Assert.Equal("none", runtimeSource.Outcome);

        // C1, exact SUP-000040 graph: the rotated successor never completed its enrollment
        // (INVALIDATED/challenge_expired) and a new WebSetup run finalizes again with the legacy
        // identifier, a fresh grant and a fresh handoff. It must be accepted without a 409 and
        // without duplicating the seat or leaving two active bindings.
        await using (var expire = await scenario.Factory.CreateDbContextAsync())
        {
            // Production shape: the Runtime prepared an enrollment for the successor, then its
            // challenge expired because the Desktop could not bootstrap (enrollment 9b5233f2…).
            Assert.False(await expire.RuntimeEnrollments.AnyAsync(candidate => candidate.BindingId == activeBinding.Id));
            var predecessor = await expire.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            var expiredAt = DateTime.UtcNow.AddMinutes(-3);
            expire.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = Guid.NewGuid(),
                ClientId = predecessor.ClientId,
                BindingId = activeBinding.Id,
                ProductId = activeBinding.ProductId,
                LicenseId = activeBinding.LicenseId,
                LicenseSeatId = activeBinding.LicenseSeatId,
                InstallationId = activeBinding.InstallationId,
                HardwareIdHash = activeBinding.HardwareIdHash,
                ReleaseVersion = activeBinding.Version,
                HandoffDigestSha256 = activeBinding.HandoffDigestSha256,
                SubjectRefDigestSha256 = activeBinding.SubjectRefDigestSha256,
                ProtocolVersion = predecessor.ProtocolVersion,
                Algorithm = predecessor.Algorithm,
                KeyBackend = predecessor.KeyBackend,
                AttestationLevel = predecessor.AttestationLevel,
                PublicKeySpkiCiphertext = predecessor.PublicKeySpkiCiphertext,
                PublicKeySpkiKeyId = predecessor.PublicKeySpkiKeyId,
                PublicKeySpkiSha256 = new string('7', 64),
                KeyThumbprint = "sl-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = predecessor.ChallengeCiphertext,
                ChallengeKeyId = predecessor.ChallengeKeyId,
                ChallengeDigestSha256 = new string('8', 64),
                State = RuntimeAuthorityTransitionResolver.InvalidatedState,
                InvalidationReason = "challenge_expired",
                Epoch = 1,
                SecurityEpoch = predecessor.SecurityEpoch,
                AuthorityEpoch = predecessor.AuthorityEpoch,
                ChallengeExpiresAtUtc = expiredAt,
                CreatedAtUtc = expiredAt.AddMinutes(-5),
                InvalidatedAtUtc = expiredAt
            });
            await expire.SaveChangesAsync();
        }
        await using var retryDb = await scenario.Factory.CreateDbContextAsync();
        var retry = await PrepareDistributionFinalizeAsync(
            scenario,
            subjectRef,
            LegacyHardwareId,
            hardwareAuthorityAliases: CreateAliasResolver(retryDb, migrationCrypto));
        Assert.NotNull(retry.Request.Release);
        retry.Request.Release.Version = currentVersion;
        Assert.NotEqual(prepared.Request.GrantRef, retry.Request.GrantRef);
        Assert.NotEqual(prepared.Request.HandoffDigestSha256, retry.Request.HandoffDigestSha256);
        var retried = await retry.Service.FinalizeAsync(
            "website-step1",
            Sha256("sup-000040-retry-finalize-" + Guid.NewGuid().ToString("D")),
            retry.Request);
        Assert.False(retried.Idempotent);
        Assert.Equal(Sha256(StableHardwareId), retried.Response.HardwareIdHash);
        await using (var afterRetry = await scenario.Factory.CreateDbContextAsync())
        {
            var retrySeats = await afterRetry.LicenseSeats
                .Where(candidate => candidate.LicenseId == prepared.LicenseId)
                .ToListAsync();
            Assert.Single(retrySeats);
            Assert.True(retrySeats[0].IsActive);
            var activeAfterRetry = await afterRetry.DistributionInstallationBindings
                .Where(candidate => candidate.LicenseId == prepared.LicenseId && candidate.State == "active")
                .ToListAsync();
            var retryBinding = Assert.Single(activeAfterRetry);
            Assert.Equal(Guid.Parse(retried.Response.BindingId), retryBinding.Id);
        }

        // R3, exact SUP-000040 update-check topology over HTTP: the alias still points at a superseded
        // binding and enrollment, one successor is active on the canonical seat, and a stale inactive
        // seat carries the legacy identifier. /api/admin/licenses/resolve with the legacy identifier
        // must report the active licence, and the AdminController TEMP-FAIL-OPEN log must carry no
        // hardware identifier or digest.
        var staleLegacySeatId = Guid.NewGuid();
        string resolverAdminSecret;
        await using (var addStale = await scenario.Factory.CreateDbContextAsync())
        {
            resolverAdminSecret = (await addStale.Products.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.ProductId)).ApiSecret;
            // The alias is still pinned to the binding superseded by the rotations above.
            Assert.Equal(scenario.Fixture.BindingId, await addStale.HardwareAuthorityAliases.AsNoTracking()
                .Where(alias => alias.LicenseId == prepared.LicenseId)
                .Select(alias => alias.BindingId)
                .SingleAsync());
            addStale.LicenseSeats.Add(new LicenseSeat
            {
                Id = staleLegacySeatId,
                LicenseId = prepared.LicenseId,
                HardwareId = LegacyHardwareId,
                IsActive = false,
                FirstActivatedAt = DateTime.UtcNow.AddDays(-90),
                UnlinkedAt = DateTime.UtcNow.AddDays(-60)
            });
            await addStale.SaveChangesAsync();
        }
        var resolveAliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        var resolveAdminLogs = new RecordingLogger<AdminController>();
        using (var resolveFactory = CreateAliasWebFactory(scenario, resolveAliasLogs, adminLogger: resolveAdminLogs))
        using (var resolveClient = resolveFactory.CreateClient())
        {
            resolveClient.DefaultRequestHeaders.Add("X-Admin-Secret", resolverAdminSecret);
            var staleAliasResolution = await resolveClient.PostAsJsonAsync("/api/admin/licenses/resolve", new
            {
                Schema = "targeted-license-resolution-v1",
                ProductId = scenario.Fixture.ProductId,
                HardwareId = LegacyHardwareId
            });
            var staleAliasBody = await staleAliasResolution.Content.ReadAsStringAsync();
            Assert.True(staleAliasResolution.IsSuccessStatusCode, staleAliasBody);
            using (var staleAliasJson = JsonDocument.Parse(staleAliasBody))
            {
                Assert.Equal("Active", staleAliasJson.RootElement.GetProperty("status").GetString());
                Assert.Equal("active_license_found", staleAliasJson.RootElement.GetProperty("reasonCode").GetString());
                Assert.Equal(prepared.LicenseId, staleAliasJson.RootElement.GetProperty("licenseId").GetGuid());
                Assert.True(staleAliasJson.RootElement.GetProperty("seatActive").GetBoolean());
            }
        }
        var aliasTolerance = Assert.Single(resolveAliasLogs.Messages, message =>
            message.Contains("TEMP-FAIL-OPEN(TKT-001262)", StringComparison.Ordinal)
            && message.Contains("tolerated AuthorityGraphDiverged", StringComparison.Ordinal));
        var adminTolerance = Assert.Single(resolveAdminLogs.Messages, message =>
            message.Contains("TEMP-FAIL-OPEN(TKT-001262) Targeted licence resolution used alias", StringComparison.Ordinal));
        Assert.Contains(prepared.LicenseId.ToString(), adminTolerance, StringComparison.Ordinal);
        foreach (var message in new[] { aliasTolerance, adminTolerance })
        {
            Assert.DoesNotContain(LegacyHardwareId, message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(StableHardwareId, message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Sha256(LegacyHardwareId), message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Sha256(StableHardwareId), message, StringComparison.OrdinalIgnoreCase);
        }
        await using (var removeStale = await scenario.Factory.CreateDbContextAsync())
        {
            removeStale.LicenseSeats.Remove(await removeStale.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == staleLegacySeatId));
            await removeStale.SaveChangesAsync();
        }

        // C2: the resolver reports a binding as current only when exactly one active candidate
        // exists; with none it keeps the seat mapping but claims no binding.
        Guid currentActiveId;
        await using (var zero = await scenario.Factory.CreateDbContextAsync())
        {
            var current = await zero.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.LicenseId == prepared.LicenseId && candidate.State == "active");
            currentActiveId = current.Id;
            current.State = "invalidated";
            current.InvalidatedAtUtc = DateTime.UtcNow;
            current.InvalidationReason = "installation_superseded";
            await zero.SaveChangesAsync();
            var none = await CreateAliasResolver(zero, migrationCrypto).ResolveAsync(
                scenario.Fixture.ProductId, prepared.LicenseId, LegacyHardwareId,
                HardwareAuthorityResolutionIntent.StatusCheck);
            Assert.True(none.UsedAlias);
            Assert.Equal(StableHardwareId, none.EffectiveHardwareId);
            Assert.Null(none.BindingId);
            current.State = "active";
            current.InvalidatedAtUtc = null;
            current.InvalidationReason = null;
            await zero.SaveChangesAsync();
        }
        // Two active bindings for one (product, hardware digest) are unrepresentable: the unique
        // index IX_DistributionInstallationBindings_ProductId_HardwareIdHash rejects them, so the
        // defensive "several candidates" branch claims no binding and is not seeded here.
    }

    /// <summary>
    /// Reproduces the authenticated legacy-to-V2 migration followed by an explicit V2 unlink,
    /// a legacy-seat reactivation, and a Finalize v4 carrying three bounded historical candidates.
    /// The exact alias binding must remain authoritative while unrelated candidates are ignored,
    /// retiring the transitional legacy seat and restoring one canonical V2 Runtime authority.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_FinalizeAfterV2UnlinkAndLegacyReactivation_ReconcilesOneSeat()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("hardware-alias-reconciliation-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);

        Guid sourceSeatId;
        Guid legacySeatId;
        Guid licenseId;
        await using (var diverge = await scenario.Factory.CreateDbContextAsync())
        {
            var sourceBinding = await diverge.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var sourceEnrollment = await diverge.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            licenseId = sourceBinding.LicenseId;
            var sourceSeat = await diverge.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == sourceBinding.LicenseSeatId);
            sourceSeatId = sourceSeat.Id;
            sourceSeat.IsActive = false;
            sourceSeat.UnlinkedAt = DateTime.UtcNow.AddMinutes(-5);
            sourceBinding.State = "invalidated";
            sourceBinding.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
            sourceBinding.InvalidationReason = "seat_ineligible";
            sourceEnrollment.State = "INVALIDATED";
            sourceEnrollment.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
            sourceEnrollment.InvalidationReason = "seat_ineligible";

            legacySeatId = Guid.NewGuid();
            diverge.LicenseSeats.Add(new LicenseSeat
            {
                Id = legacySeatId,
                LicenseId = sourceBinding.LicenseId,
                HardwareId = LegacyHardwareId,
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow.AddMinutes(-3),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-3),
                AppVersion = scenario.Fixture.Version
            });
            await diverge.SaveChangesAsync();
        }

        await using (var authorityCheck = await scenario.Factory.CreateDbContextAsync())
        {
            var resolver = CreateAliasResolver(authorityCheck);
            var activation = await resolver.ResolveAsync(
                scenario.Fixture.ProductId,
                licenseId,
                LegacyHardwareId,
                HardwareAuthorityResolutionIntent.Activation);
            var finalize = await resolver.ResolveAsync(
                scenario.Fixture.ProductId,
                licenseId,
                LegacyHardwareId,
                HardwareAuthorityResolutionIntent.Finalize);

            Assert.True(activation.Refused);
            Assert.Equal(HardwareAuthorityRefusalReason.AuthorityGraphDiverged, activation.RefusalReason);
            Assert.True(finalize.Refused);
            Assert.Equal(
                HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired,
                finalize.RefusalReason);
            Assert.Equal(StableHardwareId, finalize.EffectiveHardwareId);
        }

        await using (var securityDivergence = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await securityDivergence.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            binding.InvalidationReason = "security_lockdown";
            await securityDivergence.SaveChangesAsync();

            var refused = await CreateAliasResolver(securityDivergence).ResolveAsync(
                scenario.Fixture.ProductId,
                licenseId,
                LegacyHardwareId,
                HardwareAuthorityResolutionIntent.Finalize);
            Assert.True(refused.Refused);
            Assert.Equal(HardwareAuthorityRefusalReason.AuthorityGraphDiverged, refused.RefusalReason);

            binding.InvalidationReason = "seat_ineligible";
            await securityDivergence.SaveChangesAsync();
        }

        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        var sourceResolution = await prepared.Service.ResolveRuntimeSourceAsync(
            "website-step1",
            new DistributionRuntimeSourceResolutionRequest
            {
                Schema = DistributionInstallationBindingService.RuntimeSourceResolutionSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                TargetLicenseId = prepared.LicenseId.ToString("D"),
                HardwareId = LegacyHardwareId
            });
        Assert.Equal("none", sourceResolution.Outcome);
        Assert.Null(sourceResolution.SourceLicenseId);
        Assert.Null(sourceResolution.SourceKind);

        ConfigureFinalizeV4WithUnrelatedCandidates(prepared.Request);
        var finalizeDigest = Sha256(
            "hardware-alias-reconciliation-finalize-" + Guid.NewGuid().ToString("D"));
        var finalized = await prepared.Service.FinalizeAsync(
            "website-step1",
            finalizeDigest,
            prepared.Request);

        Assert.False(finalized.Idempotent);
        Assert.Equal(Sha256(StableHardwareId), finalized.Response.HardwareIdHash);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var seats = await check.LicenseSeats
            .Where(candidate => candidate.LicenseId == prepared.LicenseId)
            .OrderBy(candidate => candidate.Id)
            .ToListAsync();
        Assert.Equal(2, seats.Count);
        Assert.Single(seats, candidate => candidate.IsActive
            && candidate.Id == sourceSeatId
            && candidate.HardwareId == StableHardwareId);
        Assert.Contains(seats, candidate => !candidate.IsActive
            && candidate.Id == legacySeatId
            && candidate.HardwareId == LegacyHardwareId);
        var activeBinding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.ProductId == scenario.Fixture.ProductId && candidate.State == "active");
        Assert.Equal(sourceSeatId, activeBinding.LicenseSeatId);
        Assert.Equal(Sha256(StableHardwareId), activeBinding.HardwareIdHash);
        Assert.Equal(StableHardwareId, (await check.Licenses.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == licenseId)).HardwareId);
        Assert.Equal(scenario.Fixture.BindingId, activeBinding.SupersededBindingId);

        var replay = await prepared.Service.FinalizeAsync(
            "website-step1",
            finalizeDigest,
            prepared.Request);
        Assert.True(replay.Idempotent);
        Assert.Equal(finalized.Response, replay.Response);
    }

    /// <summary>
    /// Forces two identical Finalize v4 requests with unrelated history candidates to queue behind
    /// the Runtime global lock while the authenticated alias graph is divergent. The serialized loser
    /// must replay the committed V2 response instead of re-evaluating candidates or creating authority.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_ConcurrentDivergentFinalize_ReplaysOneCanonicalV2Result()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("hardware-alias-concurrent-reconciliation"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);

        Guid sourceSeatId;
        Guid legacySeatId;
        Guid licenseId;
        await using (var diverge = await scenario.Factory.CreateDbContextAsync())
        {
            var sourceBinding = await diverge.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var sourceEnrollment = await diverge.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            var sourceSeat = await diverge.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == sourceBinding.LicenseSeatId);
            sourceSeatId = sourceSeat.Id;
            licenseId = sourceBinding.LicenseId;
            sourceSeat.IsActive = false;
            sourceSeat.UnlinkedAt = DateTime.UtcNow.AddMinutes(-5);
            sourceBinding.State = "invalidated";
            sourceBinding.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
            sourceBinding.InvalidationReason = "seat_ineligible";
            sourceEnrollment.State = "INVALIDATED";
            sourceEnrollment.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
            sourceEnrollment.InvalidationReason = "seat_ineligible";

            legacySeatId = Guid.NewGuid();
            diverge.LicenseSeats.Add(new LicenseSeat
            {
                Id = legacySeatId,
                LicenseId = licenseId,
                HardwareId = LegacyHardwareId,
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow.AddMinutes(-3),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-3),
                AppVersion = scenario.Fixture.Version
            });
            await diverge.SaveChangesAsync();
        }

        var applicationName = "finalize-divergent-" + Guid.NewGuid().ToString("N");
        var prepared = await PrepareDistributionFinalizeAsync(
            scenario, subjectRef, LegacyHardwareId, applicationName);
        ConfigureFinalizeV4WithUnrelatedCandidates(prepared.Request);
        var finalizeDigest = Sha256(
            "hardware-alias-concurrent-finalize-" + Guid.NewGuid().ToString("D"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = timeout.Token;

        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await blockerCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var first = CaptureDistributionFinalizeAsync(prepared.Service.FinalizeAsync(
            "website-step1", finalizeDigest, prepared.Request, cancellationToken));
        var second = CaptureDistributionFinalizeAsync(prepared.Service.FinalizeAsync(
            "website-step1", finalizeDigest, prepared.Request, cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [applicationName],
            minimumWaiters: 2,
            cancellationToken);
        await blockerTransaction.CommitAsync(cancellationToken);

        await Task.WhenAll((Task)first, second).WaitAsync(cancellationToken);
        var outcomes = new[] { await first, await second };
        Assert.All(outcomes, outcome => Assert.Null(outcome.Error));
        var results = outcomes.Select(outcome => Assert.IsType<
                DistributionOperationResult<DistributionInstallationBindingResponse>>(outcome.Result))
            .ToList();
        Assert.Single(results, result => !result.Idempotent);
        Assert.Single(results, result => result.Idempotent);
        Assert.Equal(results[0].Response, results[1].Response);
        Assert.All(results, result =>
            Assert.Equal(Sha256(StableHardwareId), result.Response.HardwareIdHash));

        var replay = await prepared.Service.FinalizeAsync(
            "website-step1", finalizeDigest, prepared.Request, cancellationToken);
        Assert.True(replay.Idempotent);
        Assert.Equal(results[0].Response, replay.Response);

        await using var check = await scenario.Factory.CreateDbContextAsync(cancellationToken);
        var license = await check.Licenses.Include(candidate => candidate.Seats)
            .SingleAsync(candidate => candidate.Id == licenseId, cancellationToken);
        Assert.Equal(1, license.MaxSeats);
        Assert.Equal(2, license.Seats.Count);
        Assert.Single(license.Seats, candidate => candidate.IsActive
            && candidate.Id == sourceSeatId
            && candidate.HardwareId == StableHardwareId);
        Assert.Contains(license.Seats, candidate => !candidate.IsActive
            && candidate.Id == legacySeatId
            && candidate.HardwareId == LegacyHardwareId);
        var bindings = await check.DistributionInstallationBindings.Where(candidate =>
                candidate.ProductId == scenario.Fixture.ProductId)
            .ToListAsync(cancellationToken);
        var activeBinding = Assert.Single(bindings, candidate => candidate.State == "active");
        Assert.Equal(2, bindings.Count);
        Assert.Equal(sourceSeatId, activeBinding.LicenseSeatId);
        Assert.Equal(scenario.Fixture.BindingId, activeBinding.SupersededBindingId);
        Assert.Equal(Sha256(StableHardwareId), activeBinding.HardwareIdHash);
    }

    /// <summary>
    /// Proves noncanonical transition identifiers, disabled authenticated aliases, and unrelated
    /// canonical identities all fail without creating a second seat or successor binding.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DistributionFinalizeRejectsInvalidOrUnprovenAuthorityWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-refusal-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);
        var refusalLogs = new RecordingLogger<DistributionInstallationBindingService>();
        var prepared = await PrepareDistributionFinalizeAsync(
            scenario, subjectRef, LegacyHardwareId, logger: refusalLogs);
        // Keep the capacity diagnostics distinct from alias proof checks under the mono-seat replacement contract.
        var capacityHardware = await Tkt976_FillMultiSeatCapacityAsync(scenario.Factory, prepared.LicenseId);

        foreach (var invalidHardwareId in new[]
                 {
                     LegacyHardwareId.ToLowerInvariant(),
                     LegacyHardwareId + " "
                 })
        {
            prepared.Request.HardwareId = invalidHardwareId;
            var invalid = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                prepared.Service.FinalizeAsync(
                    "website-step1",
                    Sha256("distribution-finalize-invalid-" + invalidHardwareId),
                    prepared.Request));
            Assert.Equal("invalid_request", invalid.ErrorCode);
        }

        prepared.Request.HardwareId = "G00272B768FFD6AF";
        var genericIdentity = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            prepared.Service.FinalizeAsync(
                "website-step1",
                Sha256("distribution-finalize-generic-identity-" + Guid.NewGuid().ToString("D")),
                prepared.Request));
        Assert.Equal("seat_limit_reached", genericIdentity.ErrorCode);

        await using (var disable = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await disable.HardwareAuthorityAliases.SingleAsync();
            alias.IsActive = false;
            alias.DisabledAtUtc = DateTime.UtcNow;
            alias.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason;
            await disable.SaveChangesAsync();
        }
        prepared.Request.HardwareId = LegacyHardwareId;
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            prepared.Service.FinalizeAsync(
                "website-step1",
                Sha256("distribution-finalize-refused-" + Guid.NewGuid().ToString("D")),
                prepared.Request));
        Assert.Equal("hardware_authority_refused", refused.ErrorCode);
        Assert.Equal("alias_resolution_unavailable", refused.ReasonCode);
        Assert.NotNull(refused.HardwareAuthorityRefusal);
        Assert.Equal(prepared.Request.RequestId, refused.HardwareAuthorityRefusal.RequestId);
        Assert.True(refused.HardwareAuthorityRefusal.Decision.AliasResolutionRefused);
        var refusalLog = Assert.Single(refusalLogs.Messages, message =>
            message.StartsWith("HardwareAuthorityRefused ", StringComparison.Ordinal));
        Assert.Contains("ReasonCode=alias_resolution_unavailable", refusalLog, StringComparison.Ordinal);
        Assert.Contains($"RequestId={prepared.Request.RequestId}", refusalLog, StringComparison.Ordinal);
        Assert.DoesNotContain(LegacyHardwareId, refusalLog, StringComparison.Ordinal);
        Assert.DoesNotContain(StableHardwareId, refusalLog, StringComparison.Ordinal);
        Assert.DoesNotContain(scenario.Fixture.BindingId.ToString("D"), refusalLog, StringComparison.Ordinal);

        prepared.Request.HardwareId = "B00272B768FFD6AF";
        var unrelated = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            prepared.Service.FinalizeAsync(
                "website-step1",
                Sha256("distribution-finalize-unrelated-" + Guid.NewGuid().ToString("D")),
                prepared.Request));
        Assert.Equal("seat_limit_reached", unrelated.ErrorCode);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var binding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var seats = await check.LicenseSeats.Where(candidate => candidate.LicenseId == prepared.LicenseId).ToListAsync();
        Assert.Equal("active", binding.State);
        Assert.Equal(2, seats.Count);
        Assert.All(seats, seat => Assert.True(seat.IsActive));
        Assert.Contains(seats, seat => seat.HardwareId == StableHardwareId);
        Assert.Contains(seats, seat => seat.HardwareId == capacityHardware);
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == scenario.Fixture.ProductId).ToListAsync());
    }

    /// <summary>
    /// Exercises every closed TKT-000579 refusal through the production Finalize transaction on PostgreSQL 17.
    /// The fixed resolver isolates the selected guard while all entitlement, seat, binding, and rollback work
    /// remains backed by the migrated relational schema.
    /// </summary>
    [Theory]
    [InlineData("alias-ambiguous", "alias_resolution_ambiguous")]
    [InlineData("alias-unavailable", "alias_resolution_unavailable")]
    [InlineData("graph-missing", "authority_graph_missing")]
    [InlineData("graph-diverged", "authority_graph_diverged")]
    [InlineData("identity-missing", "alias_reconciliation_identity_missing")]
    [InlineData("cardinality", "canonical_seat_cardinality_mismatch")]
    [InlineData("source-missing", "recovery_source_missing")]
    [InlineData("binding-mismatch", "recovery_source_binding_mismatch")]
    public async Task HardwareAuthorityRefusal_EachGuardIsDistinctOnPostgreSql17(
        string guardScenario,
        string expectedReasonCode)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData(
            Encoding.UTF8.GetBytes("hardware-refusal-pg-" + guardScenario)));
        var submittedHardwareId = LegacyHardwareId;
        Guid? reconciliationSeatId = null;
        HardwareAuthorityResolution resolution;
        if (guardScenario is "alias-ambiguous" or "alias-unavailable" or "graph-missing" or "graph-diverged")
        {
            var refusalReason = guardScenario switch
            {
                "alias-ambiguous" => HardwareAuthorityRefusalReason.AmbiguousAlias,
                "alias-unavailable" => HardwareAuthorityRefusalReason.AliasUnavailable,
                "graph-missing" => HardwareAuthorityRefusalReason.AuthorityGraphMissing,
                _ => HardwareAuthorityRefusalReason.AuthorityGraphDiverged
            };
            resolution = new HardwareAuthorityResolution(
                submittedHardwareId,
                submittedHardwareId,
                null,
                HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: refusalReason);
        }
        else if (guardScenario == "identity-missing")
        {
            resolution = new HardwareAuthorityResolution(
                submittedHardwareId,
                StableHardwareId,
                null,
                HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired);
        }
        else
        {
            await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
            await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
            await MigrateScenarioAsync(scenario);
            await using (var mutate = await scenario.Factory.CreateDbContextAsync())
            {
                var binding = await mutate.DistributionInstallationBindings.SingleAsync(candidate =>
                    candidate.Id == scenario.Fixture.BindingId);
                var canonicalSeat = await mutate.LicenseSeats.SingleAsync(candidate =>
                    candidate.Id == binding.LicenseSeatId);
                reconciliationSeatId = canonicalSeat.Id;
                canonicalSeat.IsActive = false;
                canonicalSeat.UnlinkedAt = DateTime.UtcNow.AddMinutes(-5);
                if (guardScenario != "cardinality")
                {
                    mutate.LicenseSeats.Add(new LicenseSeat
                    {
                        Id = Guid.NewGuid(),
                        LicenseId = binding.LicenseId,
                        HardwareId = LegacyHardwareId,
                        IsActive = true,
                        FirstActivatedAt = DateTime.UtcNow.AddMinutes(-4),
                        LastCheckInAt = DateTime.UtcNow.AddMinutes(-4),
                        AppVersion = scenario.Fixture.Version
                    });
                }
                if (guardScenario == "source-missing")
                {
                    binding.State = "invalidated";
                    binding.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
                    binding.InvalidationReason = "security_lockdown";
                }
                if (guardScenario == "binding-mismatch")
                {
                    // Signed migration preserves the original binding's historical digest.
                    // A distinct canonical source must exist to reach the mismatch guard;
                    // an absent source correctly stops at recovery_source_missing instead.
                    var distinctSource = (DistributionInstallationBinding)mutate.Entry(binding).CurrentValues.ToObject();
                    distinctSource.Id = Guid.NewGuid();
                    distinctSource.InstallationId = Guid.NewGuid().ToString("D");
                    distinctSource.GrantRef = Guid.NewGuid().ToString("D");
                    distinctSource.GrantRefDigestSha256 = Sha256(distinctSource.GrantRef);
                    distinctSource.HandoffDigestSha256 = Sha256("binding-mismatch-source-" + distinctSource.Id);
                    distinctSource.HardwareIdHash = Sha256(StableHardwareId);
                    mutate.DistributionInstallationBindings.Add(distinctSource);
                    Assert.NotEqual(binding.Id, distinctSource.Id);
                    Assert.NotEqual(binding.HardwareIdHash, distinctSource.HardwareIdHash);
                }
                await mutate.SaveChangesAsync();
            }
            resolution = new HardwareAuthorityResolution(
                submittedHardwareId,
                StableHardwareId,
                null,
                HardwareAuthorityResolutionStatus.Refused,
                Guid.NewGuid(),
                reconciliationSeatId,
                HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired);
        }

        var logger = new RecordingLogger<DistributionInstallationBindingService>();
        var prepared = await PrepareDistributionFinalizeAsync(
            scenario,
            subjectRef,
            submittedHardwareId,
            logger: logger,
            hardwareAuthorityAliases: new FixedHardwareAuthorityAliasResolver(resolution));

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            prepared.Service.FinalizeAsync(
                "website-step1",
                Sha256("hardware-refusal-pg-finalize-" + guardScenario),
                prepared.Request));

        Assert.Equal("hardware_authority_refused", exception.ErrorCode);
        Assert.Equal(expectedReasonCode, exception.ReasonCode);
        Assert.Equal(prepared.Request.RequestId, exception.HardwareAuthorityRefusal?.RequestId);
        var refusalLog = Assert.Single(logger.Messages, message =>
            message.StartsWith("HardwareAuthorityRefused ", StringComparison.Ordinal));
        Assert.Contains($"ReasonCode={expectedReasonCode}", refusalLog, StringComparison.Ordinal);
        Assert.DoesNotContain(LegacyHardwareId, refusalLog, StringComparison.Ordinal);
        Assert.DoesNotContain(StableHardwareId, refusalLog, StringComparison.Ordinal);
    }

    /// <summary>
    /// Proves an exact signed migration replay queued first on the Runtime global lock completes
    /// idempotently before a transitional alias Finalize creates one successor authority. The test
    /// observes both PostgreSQL waiters before releasing the blocker and bounds completion to 30 seconds.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_SignedMigrationReplayQueuedBeforeDistributionFinalizeCompletesFirst()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-concurrency-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        var migrationRequest = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var migrationDigest = Sha256("distribution-finalize-concurrent-migration-" + Guid.NewGuid().ToString("D"));
        var migrationProof = Proof(
            scenario.EnrollmentKey,
            "hardware-authority-migration",
            scenario.EnrollmentId,
            scenario.Options.ConfirmAudience,
            "-",
            migrationDigest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId,
            migrationDigest,
            migrationRequest,
            migrationProof,
            IPAddress.Loopback);
        var replayApplicationName = "migration-replay-first-" + Guid.NewGuid().ToString("N");
        var finalizeApplicationName = "finalize-second-" + Guid.NewGuid().ToString("N");
        var alias = await PrepareDistributionFinalizeAsync(
            scenario, subjectRef, LegacyHardwareId, finalizeApplicationName);
        var replayRuntime = CreateTaggedRuntime(scenario, replayApplicationName);
        using var replayCrypto = replayRuntime.Crypto;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = timeout.Token;

        // Holding the production global lock lets the observer prove the first waiter before the
        // second contender starts, instead of inferring order from task creation timing.
        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await blockerCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var replayTask = CaptureHardwareMigrationAsync(replayRuntime.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId,
            migrationDigest,
            migrationRequest,
            migrationProof,
            IPAddress.Loopback,
            cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [replayApplicationName],
            minimumWaiters: 1,
            cancellationToken);
        var finalizeTask = CaptureDistributionFinalizeAsync(alias.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-concurrent-alias-" + Guid.NewGuid().ToString("D")),
            alias.Request,
            cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [replayApplicationName, finalizeApplicationName],
            minimumWaiters: 2,
            cancellationToken);
        await blockerTransaction.CommitAsync(cancellationToken);

        await Task.WhenAll((Task)replayTask, finalizeTask).WaitAsync(cancellationToken);

        var finalize = await finalizeTask;
        var replay = await replayTask;
        Assert.Null(finalize.Error);
        Assert.NotNull(finalize.Result);
        Assert.Null(replay.Error);
        Assert.True(replay.Result?.Idempotent);
        Assert.Equal("migrated", replay.Result?.Response.Decision);
        await AssertFinalizedMigrationAuthorityAsync(scenario, alias.LicenseId, cancellationToken);
    }

    /// <summary>
    /// Proves a transitional alias Finalize queued first on the Runtime global lock creates one
    /// successor authority before the historical signed replay fails closed as ineligible. The test
    /// observes both PostgreSQL waiters before releasing the blocker and bounds completion to 30 seconds.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DistributionFinalizeQueuedBeforeSignedMigrationReplayRejectsHistoricalAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-first-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        var migrationRequest = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var migrationDigest = Sha256("distribution-finalize-first-migration-" + Guid.NewGuid().ToString("D"));
        var migrationProof = Proof(
            scenario.EnrollmentKey,
            "hardware-authority-migration",
            scenario.EnrollmentId,
            scenario.Options.ConfirmAudience,
            "-",
            migrationDigest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId,
            migrationDigest,
            migrationRequest,
            migrationProof,
            IPAddress.Loopback);
        var finalizeApplicationName = "finalize-first-" + Guid.NewGuid().ToString("N");
        var replayApplicationName = "migration-replay-second-" + Guid.NewGuid().ToString("N");
        var alias = await PrepareDistributionFinalizeAsync(
            scenario, subjectRef, LegacyHardwareId, finalizeApplicationName);
        var replayRuntime = CreateTaggedRuntime(scenario, replayApplicationName);
        using var replayCrypto = replayRuntime.Crypto;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = timeout.Token;

        // Holding the production global lock lets the observer prove the first waiter before the
        // second contender starts, instead of inferring order from task creation timing.
        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await blockerCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var finalizeTask = CaptureDistributionFinalizeAsync(alias.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-first-alias-" + Guid.NewGuid().ToString("D")),
            alias.Request,
            cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [finalizeApplicationName],
            minimumWaiters: 1,
            cancellationToken);
        var replayTask = CaptureHardwareMigrationAsync(replayRuntime.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId,
            migrationDigest,
            migrationRequest,
            migrationProof,
            IPAddress.Loopback,
            cancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [finalizeApplicationName, replayApplicationName],
            minimumWaiters: 2,
            cancellationToken);
        await blockerTransaction.CommitAsync(cancellationToken);

        await Task.WhenAll((Task)finalizeTask, replayTask).WaitAsync(cancellationToken);

        var finalize = await finalizeTask;
        var replay = await replayTask;
        Assert.Null(finalize.Error);
        Assert.NotNull(finalize.Result);
        // Finalize deliberately terminalizes the source authority, so the historical replay must
        // preserve the unchanged fail-closed product contract after it acquires the global lock.
        var replayError = Assert.IsType<RuntimeEnrollmentException>(replay.Error);
        Assert.Equal("binding_ineligible", replayError.ErrorCode);
        Assert.Null(replay.Result);
        await AssertFinalizedMigrationAuthorityAsync(scenario, alias.LicenseId, cancellationToken);
    }

    /// <summary>
    /// Proves a direct V2 Finalize cannot hold the canonical hardware lock while an alias Finalize
    /// holds the Runtime global lock, even when both are forced to overlap before licence recovery.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DistributionFinalizeAliasAndDirectV2UseGlobalFirstOrder()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("distribution-finalize-direct-v2-race-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);
        var directApplicationName = "finalize-direct-" + Guid.NewGuid().ToString("N");
        var aliasApplicationName = "finalize-alias-" + Guid.NewGuid().ToString("N");
        var alias = await PrepareDistributionFinalizeAsync(
            scenario, subjectRef, LegacyHardwareId, aliasApplicationName);
        var direct = await PrepareDistributionFinalizeAsync(
            scenario, subjectRef, StableHardwareId, directApplicationName);
        using var raceTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var raceCancellationToken = raceTimeout.Token;

        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(raceCancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(raceCancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText =
                "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(@lockName, 0));";
            blockerCommand.Parameters.AddWithValue(
                "lockName",
                $"distribution-license-seat:{direct.LicenseId:D}");
            await blockerCommand.ExecuteNonQueryAsync(raceCancellationToken);
        }

        var directTask = CaptureDistributionFinalizeAsync(direct.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-direct-v2-race-" + Guid.NewGuid().ToString("D")),
            direct.Request,
            raceCancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [directApplicationName],
            minimumWaiters: 1,
            raceCancellationToken);

        var aliasTask = CaptureDistributionFinalizeAsync(alias.Service.FinalizeAsync(
            "website-step1",
            Sha256("distribution-finalize-alias-race-" + Guid.NewGuid().ToString("D")),
            alias.Request,
            raceCancellationToken));
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [directApplicationName, aliasApplicationName],
            minimumWaiters: 2,
            raceCancellationToken);
        await blockerTransaction.CommitAsync(raceCancellationToken);

        await Task.WhenAll((Task)directTask, aliasTask).WaitAsync(raceCancellationToken);
        var outcomes = new[] { await directTask, await aliasTask };
        Assert.Contains(outcomes, outcome => outcome.Result != null);
        Assert.All(outcomes.Where(outcome => outcome.Error != null), outcome =>
        {
            var error = Assert.IsType<DistributionOperationException>(outcome.Error);
            Assert.Contains(error.ErrorCode, new[] { "hardware_authority_refused", "binding_conflict" });
        });

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var seats = await check.LicenseSeats.Where(candidate => candidate.LicenseId == direct.LicenseId).ToListAsync();
        var activeBindings = await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == scenario.Fixture.ProductId && candidate.State == "active").ToListAsync();
        var seat = Assert.Single(seats);
        Assert.True(seat.IsActive);
        Assert.Equal(StableHardwareId, seat.HardwareId);
        Assert.Single(activeBindings);
        Assert.Equal(Sha256(StableHardwareId), activeBindings[0].HardwareIdHash);
    }

    /// <summary>
    /// Proves an inactive V2 seat remains locatable for activation and status but cannot be targeted by deactivation.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_InactiveSeatPreservesReactivationIdentityOnly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await MutateAliasGraphAsync(scenario, "seat-inactive");

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolver = CreateAliasResolver(db);
        var activation = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);
        var status = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, LegacyHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        var deactivation = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Deactivation);

        Assert.True(activation.UsedAlias);
        Assert.True(status.UsedAlias);
        Assert.Equal(StableHardwareId, activation.EffectiveHardwareId);
        Assert.True(deactivation.Refused);
    }

    /// <summary>
    /// Proves legitimate monotonic Runtime generations preserve a matching alias while rollback and identity divergence fail closed.
    /// </summary>
    // TEMP-FAIL-OPEN(TKT-001262): Runtime-graph drift behind an authenticated, active, same-licence
    // alias whose canonical seat still matches is logged and resolved. A changed canonical seat
    // digest and a disabled alias stay refused.
    [Theory]
    [InlineData("generation-forward", true)]
    [InlineData("security-rollback", true)]
    [InlineData("authority-rollback", true)]
    [InlineData("enrollment-hash", true)]
    [InlineData("binding-hash", true)]
    [InlineData("canonical-hash", false)]
    [InlineData("enrollment-inactive", true)]
    [InlineData("binding-inactive", true)]
    [InlineData("alias-disabled", false)]
    public async Task HardwareAuthorityAlias_RevalidatesLiveAuthorityGraph(string mutation, bool shouldResolve)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await MutateAliasGraphAsync(scenario, mutation);

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolution = await CreateAliasResolver(db).ResolveAsync(
            binding.ProductId,
            binding.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);

        Assert.Equal(shouldResolve, resolution.UsedAlias);
        Assert.Equal(!shouldResolve, resolution.Refused);
        Assert.Single(await db.LicenseSeats.Where(candidate => candidate.LicenseId == binding.LicenseId).ToListAsync());
    }

    /// <summary>
    /// Proves the one-time migration backfill materializes a divergent historical migration as disabled so legacy input is refused instead of becoming a new seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_BackfillDivergenceCreatesDisabledRefusalMarker()
    {
        using var scenario = await CreateHistoricalAliasScenarioAsync();

        var adminFactory = new TestDbFactory(scenario.AdminConnectionString);
        await using (var diverge = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await diverge.OpenAsync();
            await using var command = new Npgsql.NpgsqlCommand(
                "UPDATE \"DistributionInstallationBindings\" SET \"HardwareIdHash\" = @digest WHERE \"Id\" = @binding;", diverge);
            command.Parameters.AddWithValue("digest", Sha256("backfill-divergence"));
            command.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await using (var upgrade = await adminFactory.CreateDbContextAsync())
        {
            await upgrade.GetService<IMigrator>().MigrateAsync();
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            Assert.True(await ScalarAsync<bool>(admin, """
                SELECT has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'SELECT')
                   AND has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'INSERT')
                   AND has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'UPDATE')
                   AND has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'DELETE');
                """));
            await GrantApplicationRuntimePrivilegesAsync(admin);
        }

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var alias = await db.HardwareAuthorityAliases.SingleAsync();
        var bindingAfter = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var seatCount = await db.LicenseSeats.CountAsync(candidate =>
            candidate.LicenseId == bindingAfter.LicenseId);
        var resolution = await CreateAliasResolver(db).ResolveAsync(
            bindingAfter.ProductId,
            bindingAfter.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);

        Assert.False(alias.IsActive);
        Assert.NotNull(alias.DisabledAtUtc);
        Assert.True(resolution.Refused);
        Assert.Equal(1, seatCount);
    }

    /// <summary>
    /// Reproduces the production graph whose authenticated migration history was backfilled as
    /// an inactive alias after the canonical V2 seat was unlinked while its binding remained
    /// active and its enrollment became business-terminal. The test simulates the separately
    /// authorized operator promotion after upgrade; Finalize v4 must then use only that exact
    /// server-owned history to retire the legacy transition seat and restore one V2 authority.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_BackfilledInactiveBusinessGraph_FinalizeV4ReconcilesCanonicalV2()
    {
        var subjectRef = Base64Url(SHA256.HashData("hardware-alias-backfill-reconciliation"u8.ToArray()));
        using var scenario = await CreateHistoricalAliasScenarioAsync(subjectRef);

        var adminFactory = new TestDbFactory(scenario.AdminConnectionString);

        var historicalGraph = await ReleaseHistoricalAliasSeatAsync(scenario);
        var licenseId = historicalGraph.LicenseId;
        var sourceSeatId = historicalGraph.SourceSeatId;
        var legacySeatId = historicalGraph.LegacySeatId;

        await using (var upgrade = await adminFactory.CreateDbContextAsync())
        {
            await upgrade.GetService<IMigrator>().MigrateAsync();
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(admin);
        }

        await using (var backfillCheck = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await backfillCheck.HardwareAuthorityAliases.SingleAsync();
            var history = await backfillCheck.LicenseHistories.SingleAsync(candidate =>
                candidate.Action == "HWID_V2_MIGRATED" && candidate.LicenseId == licenseId);
            var sourceBinding = await backfillCheck.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var sourceEnrollment = await backfillCheck.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);

            Assert.False(alias.IsActive);
            Assert.NotNull(alias.DisabledAtUtc);
            Assert.Equal(HardwareAuthorityAlias.LegacyDisabledUnknownReason, alias.DisabledReason);
            Assert.Null(alias.MigrationRequestId);
            Assert.Equal(history.Id, alias.Id);
            Assert.Equal("active", sourceBinding.State);
            Assert.Equal("INVALIDATED", sourceEnrollment.State);
            Assert.Equal("authority_ineligible", sourceEnrollment.InvalidationReason);
            alias.DisabledReason = HardwareAuthorityAlias.BackfillAuthorityInvalidReason;
            await backfillCheck.SaveChangesAsync();
        }

        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        ConfigureFinalizeV4WithUnrelatedCandidates(prepared.Request);
        var finalizeDigest = Sha256(
            "hardware-alias-backfill-finalize-" + Guid.NewGuid().ToString("D"));
        var finalized = await prepared.Service.FinalizeAsync(
            "website-step1",
            finalizeDigest,
            prepared.Request);

        Assert.False(finalized.Idempotent);
        Assert.Equal(Sha256(StableHardwareId), finalized.Response.HardwareIdHash);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var license = await check.Licenses.Include(candidate => candidate.Seats)
            .SingleAsync(candidate => candidate.Id == licenseId);
        Assert.Equal(1, license.MaxSeats);
        Assert.Equal(2, license.Seats.Count);
        Assert.Single(license.Seats, candidate => candidate.IsActive
            && candidate.Id == sourceSeatId
            && candidate.HardwareId == StableHardwareId);
        Assert.Contains(license.Seats, candidate => !candidate.IsActive
            && candidate.Id == legacySeatId
            && candidate.HardwareId == LegacyHardwareId);
        var activeBinding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.ProductId == scenario.Fixture.ProductId && candidate.State == "active");
        Assert.Equal(sourceSeatId, activeBinding.LicenseSeatId);
        Assert.Equal(Sha256(StableHardwareId), activeBinding.HardwareIdHash);
        Assert.Equal(scenario.Fixture.BindingId, activeBinding.SupersededBindingId);

        var replay = await prepared.Service.FinalizeAsync(
            "website-step1",
            finalizeDigest,
            prepared.Request);
        Assert.True(replay.Idempotent);
        Assert.Equal(finalized.Response, replay.Response);
    }

    /// <summary>
    /// Proves an alias backfilled as active and disabled later under the pre-reason schema is not
    /// indistinguishable from an originally invalid backfill. The upgrade must preserve ambiguity
    /// as fail-closed instead of granting Finalize compatibility authority.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_PreReasonOperatorDisable_UpgradeRemainsUnavailable()
    {
        using var scenario = await CreateHistoricalAliasScenarioAsync();

        var adminFactory = new TestDbFactory(scenario.AdminConnectionString);
        await using (var historicalUpgrade = await adminFactory.CreateDbContextAsync())
        {
            await historicalUpgrade.GetService<IMigrator>().MigrateAsync(
                "20260821191047_AddRecoveryTelemetryV1");
        }
        await using (var disable = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await disable.OpenAsync();
            await using var command = new Npgsql.NpgsqlCommand("""
                UPDATE "HardwareAuthorityAliases"
                SET "IsActive" = FALSE, "DisabledAtUtc" = CURRENT_TIMESTAMP
                WHERE "IsActive" AND "MigrationRequestId" IS NULL;
                """, disable);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await using (var upgrade = await adminFactory.CreateDbContextAsync())
        {
            await upgrade.GetService<IMigrator>().MigrateAsync();
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(admin);
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var aliasAfterUpgrade = await check.HardwareAuthorityAliases.SingleAsync();
        Assert.Equal(HardwareAuthorityAlias.LegacyDisabledUnknownReason, aliasAfterUpgrade.DisabledReason);
        var resolution = await CreateAliasResolver(check).ResolveAsync(
            scenario.Fixture.ProductId,
            aliasAfterUpgrade.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Finalize);

        Assert.True(resolution.Refused);
        Assert.Equal(HardwareAuthorityRefusalReason.AliasUnavailable, resolution.RefusalReason);
    }

    /// <summary>
    /// Proves the inactive-backfill continuation remains fail-closed when its durable state reason,
    /// exact migration history, or business-terminal enrollment proof is not eligible.
    /// The graph is populated on a fresh historical schema and upgraded through the actual migrations.
    /// </summary>
    /// <param name="mutation">Exact provenance or terminal-state mutation to reject after upgrade.</param>
    /// <param name="expectedReason">Required unchanged resolver refusal for that mutation.</param>
    [Theory]
    [InlineData("operator-disabled", HardwareAuthorityRefusalReason.AliasUnavailable)]
    [InlineData("history-tampered", HardwareAuthorityRefusalReason.AliasUnavailable)]
    [InlineData("history-duplicate", HardwareAuthorityRefusalReason.AliasUnavailable)]
    [InlineData("security-terminal", HardwareAuthorityRefusalReason.AuthorityGraphDiverged)]
    public async Task HardwareAuthorityAlias_InactiveBackfillWithoutExactProof_RemainsRefused(
        string mutation,
        HardwareAuthorityRefusalReason expectedReason)
    {
        using var scenario = await CreateHistoricalAliasScenarioAsync();

        var adminFactory = new TestDbFactory(scenario.AdminConnectionString);

        var historicalGraph = await ReleaseHistoricalAliasSeatAsync(scenario);
        var licenseId = historicalGraph.LicenseId;
        var sourceSeatId = historicalGraph.SourceSeatId;

        await using (var upgrade = await adminFactory.CreateDbContextAsync())
        {
            await upgrade.GetService<IMigrator>().MigrateAsync();
        }
        await using (var mutate = await adminFactory.CreateDbContextAsync())
        {
            var alias = await mutate.HardwareAuthorityAliases.SingleAsync();
            Assert.Equal(HardwareAuthorityAlias.LegacyDisabledUnknownReason, alias.DisabledReason);
            alias.DisabledReason = HardwareAuthorityAlias.BackfillAuthorityInvalidReason;
            switch (mutation)
            {
                case "operator-disabled":
                    alias.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason;
                    break;
                case "history-tampered":
                    (await mutate.LicenseHistories.SingleAsync(candidate =>
                        candidate.Action == "HWID_V2_MIGRATED" && candidate.LicenseId == licenseId)).Details = "{}";
                    break;
                case "history-duplicate":
                    var history = await mutate.LicenseHistories.SingleAsync(candidate =>
                        candidate.Action == "HWID_V2_MIGRATED" && candidate.LicenseId == licenseId);
                    history.Details = "{\"schema\":\"tampered\"," + history.Details![1..];
                    break;
                case "security-terminal":
                    (await mutate.RuntimeEnrollments.SingleAsync(candidate =>
                        candidate.Id == scenario.EnrollmentId)).InvalidationReason = "security_revoked";
                    break;
                default:
                    throw new InvalidOperationException("Unknown inactive backfill proof mutation.");
            }
            await mutate.SaveChangesAsync();
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(admin);
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var resolution = await CreateAliasResolver(check).ResolveAsync(
            scenario.Fixture.ProductId,
            licenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Finalize);

        Assert.True(resolution.Refused);
        Assert.Equal(expectedReason, resolution.RefusalReason);
        var seats = await check.LicenseSeats.Where(candidate => candidate.LicenseId == licenseId).ToListAsync();
        Assert.Equal(2, seats.Count);
        Assert.Single(seats, candidate => candidate.Id == sourceSeatId && !candidate.IsActive);
        Assert.Single(seats, candidate => candidate.HardwareId == LegacyHardwareId && candidate.IsActive);
    }

    /// <summary>
    /// Proves the complete legacy compatibility cycle uses one V2 seat through real HTTP serialization and successful activation bodies, rejects non-canonical primary identities before reactivation, checks both ban identities, and fails closed on later alias divergence.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_HttpCyclePreservesOneCanonicalSeatAndFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await PrepareLegacyHttpActivationAsync(scenario);
        var aliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        var activationLogs = new RecordingLogger<ActivationController>();
        using var webFactory = CreateAliasWebFactory(scenario, aliasLogs, activationLogger: activationLogs);
        using var client = webFactory.CreateClient();

        Guid licenseId;
        Guid seatId;
        DateTime firstActivatedAt;
        string licenseKey;
        string appName;
        string publicKey;
        string adminSecret;
        await using (var initial = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await initial.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var license = await initial.Licenses.Include(candidate => candidate.Product)
                .SingleAsync(candidate => candidate.Id == binding.LicenseId);
            var seat = await initial.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
            licenseId = license.Id;
            seatId = seat.Id;
            firstActivatedAt = seat.FirstActivatedAt;
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
            publicKey = license.Product.PublicKeyXml;
            adminSecret = license.Product.ApiSecret;
        }

        var initialActivation = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.True(
            initialActivation.IsSuccessStatusCode,
            $"Legacy HTTP activation failed with {(int)initialActivation.StatusCode}: {await initialActivation.Content.ReadAsStringAsync()}");
        await MigrateScenarioAsync(scenario);

        var legacyCheck = await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.Equal(HttpStatusCode.OK, legacyCheck.StatusCode);
        using (var checkJson = JsonDocument.Parse(await legacyCheck.Content.ReadAsStringAsync()))
        {
            Assert.Equal("VALID", checkJson.RootElement.GetProperty("status").GetString());
            var signed = checkJson.RootElement.GetProperty("licenseFile").GetString();
            Assert.NotNull(signed);
            Assert.True(LicenseService.ValidateLicense(signed!, publicKey, LegacyHardwareId).IsValid);
            Assert.False(LicenseService.ValidateLicense(signed!, publicKey, StableHardwareId).IsValid);
        }

        client.DefaultRequestHeaders.Add("X-Admin-Secret", adminSecret);
        var aliasCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = LegacyHardwareId });
        Assert.Equal(HttpStatusCode.OK, aliasCoverage.StatusCode);
        using (var coverageJson = JsonDocument.Parse(await aliasCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());

        var canonicalCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = StableHardwareId });
        Assert.Equal(HttpStatusCode.OK, canonicalCoverage.StatusCode);
        using (var coverageJson = JsonDocument.Parse(await canonicalCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());

        // SUP-000040 (TKT-001262): the Website update check resolves the licence by the legacy
        // identifier. A stale inactive seat of that identifier must not hide the active canonical
        // seat reached through the authenticated alias.
        var staleLegacySeatId = Guid.NewGuid();
        await using (var addStale = await scenario.Factory.CreateDbContextAsync())
        {
            addStale.LicenseSeats.Add(new LicenseSeat
            {
                Id = staleLegacySeatId,
                LicenseId = licenseId,
                HardwareId = LegacyHardwareId,
                IsActive = false,
                FirstActivatedAt = firstActivatedAt.AddDays(-30),
                UnlinkedAt = firstActivatedAt.AddDays(-1)
            });
            await addStale.SaveChangesAsync();
        }
        var legacyResolution = await client.PostAsJsonAsync("/api/admin/licenses/resolve", new
        {
            Schema = "targeted-license-resolution-v1",
            ProductId = scenario.Fixture.ProductId,
            HardwareId = LegacyHardwareId
        });
        var legacyResolutionBody = await legacyResolution.Content.ReadAsStringAsync();
        Assert.True(legacyResolution.IsSuccessStatusCode, legacyResolutionBody);
        using (var resolutionJson = JsonDocument.Parse(legacyResolutionBody))
        {
            Assert.Equal("Active", resolutionJson.RootElement.GetProperty("status").GetString());
            Assert.Equal("active_license_found", resolutionJson.RootElement.GetProperty("reasonCode").GetString());
            Assert.Equal(licenseId, resolutionJson.RootElement.GetProperty("licenseId").GetGuid());
            Assert.True(resolutionJson.RootElement.GetProperty("seatActive").GetBoolean());
        }
        // A disabled alias is not a resolution: the stale legacy seat stays the only candidate.
        await using (var disableAlias = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await disableAlias.HardwareAuthorityAliases.SingleAsync(candidate =>
                candidate.LicenseId == licenseId && candidate.LegacyHardwareIdSha256 == Sha256(LegacyHardwareId));
            alias.IsActive = false;
            alias.DisabledAtUtc = DateTime.UtcNow;
            alias.DisabledReason = "operator_disabled";
            await disableAlias.SaveChangesAsync();
            var disabledResolution = await client.PostAsJsonAsync("/api/admin/licenses/resolve", new
            {
                Schema = "targeted-license-resolution-v1",
                ProductId = scenario.Fixture.ProductId,
                HardwareId = LegacyHardwareId
            });
            using (var disabledJson = JsonDocument.Parse(await disabledResolution.Content.ReadAsStringAsync()))
            {
                Assert.Equal("Inactive", disabledJson.RootElement.GetProperty("status").GetString());
                Assert.Equal("seat_inactive", disabledJson.RootElement.GetProperty("reasonCode").GetString());
            }
            alias.IsActive = true;
            alias.DisabledAtUtc = null;
            alias.DisabledReason = null;
            await disableAlias.SaveChangesAsync();
        }
        await using (var removeStale = await scenario.Factory.CreateDbContextAsync())
        {
            removeStale.LicenseSeats.Remove(await removeStale.LicenseSeats.SingleAsync(candidate =>
                candidate.Id == staleLegacySeatId));
            await removeStale.SaveChangesAsync();
        }

        var deactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = LegacyHardwareId,
            AppName = appName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, deactivation.StatusCode);

        var reactivation = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.True(
            reactivation.IsSuccessStatusCode,
            $"Canonical legacy reactivation failed with {(int)reactivation.StatusCode}: {await reactivation.Content.ReadAsStringAsync()}");

        // HTTP 200 also carries a structured activation refusal; require business success before checking the canonical seat.
        using (var reactivationJson = JsonDocument.Parse(await reactivation.Content.ReadAsStringAsync()))
        {
            var body = reactivationJson.RootElement;
            var code = body.TryGetProperty("errorCode", out var error) ? error.GetString() : "none";
            var businessRefused = body.TryGetProperty("isSuccess", out var success) && !success.GetBoolean();
            Assert.False(businessRefused, $"Legacy reactivation returned a business refusal: code={code}.");
            Assert.True(body.TryGetProperty("licenseFile", out var signedFile)
                && signedFile.ValueKind == JsonValueKind.String
                && !string.IsNullOrEmpty(signedFile.GetString()), "Legacy reactivation did not return a signed license file.");
        }

        var directV2Check = await PostCheckAsync(client, licenseKey, appName, StableHardwareId);
        var directV2Body = await directV2Check.Content.ReadAsStringAsync();
        Assert.True(
            directV2Check.IsSuccessStatusCode,
            $"Direct V2 check failed with {(int)directV2Check.StatusCode}: {directV2Body}");
        using (var directJson = JsonDocument.Parse(directV2Body))
        {
            Assert.Equal("VALID", directJson.RootElement.GetProperty("status").GetString());
            var signed = directJson.RootElement.GetProperty("licenseFile").GetString();
            Assert.NotNull(signed);
            Assert.True(LicenseService.ValidateLicense(signed!, publicKey, StableHardwareId).IsValid);
            Assert.False(LicenseService.ValidateLicense(signed!, publicKey, LegacyHardwareId).IsValid);
        }

        await SetHardwareBanAsync(scenario, StableHardwareId, active: true);
        using (var canonicalBanJson = JsonDocument.Parse(
            await (await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId)).Content.ReadAsStringAsync()))
            Assert.Equal("REVOKED", canonicalBanJson.RootElement.GetProperty("status").GetString());
        var canonicalBanCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = LegacyHardwareId });
        using (var coverageJson = JsonDocument.Parse(await canonicalBanCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());

        await SetHardwareBanAsync(scenario, StableHardwareId, active: false);
        await SetHardwareBanAsync(scenario, LegacyHardwareId, active: true);
        using (var legacyBanJson = JsonDocument.Parse(
            await (await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId)).Content.ReadAsStringAsync()))
            Assert.Equal("REVOKED", legacyBanJson.RootElement.GetProperty("status").GetString());
        var legacyBanCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = LegacyHardwareId });
        using (var coverageJson = JsonDocument.Parse(await legacyBanCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());

        await SetHardwareBanAsync(scenario, LegacyHardwareId, active: false);
        await SetHardwareBanAsync(
            scenario,
            LegacyHardwareId,
            active: true,
            category: BannedHardwareId.Categories.OutdatedVersion);
        using (var outdatedJson = JsonDocument.Parse(
            await (await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId)).Content.ReadAsStringAsync()))
            Assert.Equal("UPDATE_REQUIRED", outdatedJson.RootElement.GetProperty("status").GetString());
        var outdatedCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = LegacyHardwareId });
        using (var coverageJson = JsonDocument.Parse(await outdatedCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());
        await SetHardwareBanAsync(scenario, LegacyHardwareId, active: false);

        await using (var diverge = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await diverge.HardwareAuthorityAliases.SingleAsync();
            alias.CanonicalHardwareIdSha256 = Sha256("endpoint-divergence");
            await diverge.SaveChangesAsync();
        }
        var tolerated = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        var toleratedBody = await tolerated.Content.ReadAsStringAsync();
        Assert.True(tolerated.IsSuccessStatusCode,
            $"Compatibility activation failed with {(int)tolerated.StatusCode}: {toleratedBody}");
        using (var toleratedJson = JsonDocument.Parse(toleratedBody))
        {
            Assert.True(toleratedJson.RootElement.TryGetProperty("licenseFile", out var licenseFile), toleratedBody);
            var signed = licenseFile.GetString();
            Assert.NotNull(signed);
            Assert.True(LicenseService.ValidateLicense(signed!, publicKey, LegacyHardwareId).IsValid);
        }
        var divergentCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = LegacyHardwareId });
        using (var coverageJson = JsonDocument.Parse(await divergentCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());
        var compatibilityLog = Assert.Single(activationLogs.Messages, message =>
            message.Contains("compatibility fail-open", StringComparison.Ordinal)
            && message.Contains(nameof(HardwareAuthorityRefusalReason.AuthorityGraphDiverged), StringComparison.Ordinal));
        Assert.Contains("binding state", compatibilityLog, StringComparison.Ordinal);
        Assert.Contains("enrollment count", compatibilityLog, StringComparison.Ordinal);
        Assert.Contains("enrollment invalidations", compatibilityLog, StringComparison.Ordinal);
        Assert.Contains("coherent seat release", compatibilityLog, StringComparison.Ordinal);
        Assert.Contains("enrollment decision", compatibilityLog, StringComparison.Ordinal);
        Assert.DoesNotContain(LegacyHardwareId, compatibilityLog, StringComparison.Ordinal);
        Assert.DoesNotContain(StableHardwareId, compatibilityLog, StringComparison.Ordinal);
        Assert.DoesNotContain(Sha256(LegacyHardwareId), compatibilityLog, StringComparison.Ordinal);
        Assert.DoesNotContain(Sha256(StableHardwareId), compatibilityLog, StringComparison.Ordinal);

        await using (var secure = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await secure.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            enrollment.State = RuntimeAuthorityTransitionResolver.InvalidatedState;
            enrollment.InvalidationReason = "security_revoked";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            await secure.SaveChangesAsync();
        }
        var securityTerminal = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        var securityTerminalBody = await securityTerminal.Content.ReadAsStringAsync();
        Assert.True(securityTerminal.IsSuccessStatusCode,
            $"Historical security terminal compatibility failed with {(int)securityTerminal.StatusCode}: {securityTerminalBody}");
        using (var securityJson = JsonDocument.Parse(securityTerminalBody))
        {
            Assert.True(securityJson.RootElement.TryGetProperty("licenseFile", out var licenseFile), securityTerminalBody);
            Assert.True(LicenseService.ValidateLicense(
                licenseFile.GetString()!, publicKey, LegacyHardwareId).IsValid);
        }
        var securityTerminalCoverage = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/hardware-authority",
            new { HardwareId = LegacyHardwareId });
        using (var coverageJson = JsonDocument.Parse(await securityTerminalCoverage.Content.ReadAsStringAsync()))
            Assert.True(coverageJson.RootElement.GetProperty("coveredByActiveSeat").GetBoolean());

        await using var final = await scenario.Factory.CreateDbContextAsync();
        var seats = await final.LicenseSeats.Where(candidate => candidate.LicenseId == licenseId).ToListAsync();
        Assert.Single(seats);
        Assert.Equal(seatId, seats[0].Id);
        Assert.Equal(firstActivatedAt, seats[0].FirstActivatedAt);
        Assert.Equal(StableHardwareId, seats[0].HardwareId);
        Assert.True(seats[0].IsActive);
        // TKT-001294: the deliberate HWID_DIAGNOSIS lines carry identifiers on purpose; every other alias log stays digest-free.
        Assert.Contains(aliasLogs.Messages, message =>
            message.StartsWith("HWID_DIAGNOSIS alias-resolution", StringComparison.Ordinal)
            && message.Contains(LegacyHardwareId, StringComparison.Ordinal));
        Assert.DoesNotContain(aliasLogs.Messages.Where(message => !message.StartsWith("HWID_DIAGNOSIS", StringComparison.Ordinal)), message =>
            message.Contains(LegacyHardwareId, StringComparison.Ordinal)
            || message.Contains(StableHardwareId, StringComparison.Ordinal)
            || message.Contains(Sha256(LegacyHardwareId), StringComparison.Ordinal)
            || message.Contains(Sha256(StableHardwareId), StringComparison.Ordinal));
    }

    /// <summary>
    /// Proves a lowercase spelling of a known migrated legacy identity is rejected by all public seat endpoints
    /// before it can create, reactivate, check, or deactivate the single canonical V2 seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_LowercaseKnownLegacyIsRejectedWithoutSeatMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        var aliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        using var webFactory = CreateAliasWebFactory(scenario, aliasLogs);
        using var client = webFactory.CreateClient();

        Guid licenseId;
        string licenseKey;
        string appName;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var license = await db.Licenses.Include(candidate => candidate.Product)
                .SingleAsync(candidate => candidate.Id == binding.LicenseId);
            licenseId = license.Id;
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
        }

        var canonicalDeactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = LegacyHardwareId,
            AppName = appName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, canonicalDeactivation.StatusCode);

        var lowercaseLegacy = LegacyHardwareId.ToLowerInvariant();
        var invalidActivation = await PostActivationAsync(client, licenseKey, appName, lowercaseLegacy);
        Assert.Equal(HttpStatusCode.BadRequest, invalidActivation.StatusCode);
        Assert.Equal("INVALID_HARDWARE_ID", invalidActivation.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        var invalidCheck = await PostCheckAsync(client, licenseKey, appName, lowercaseLegacy);
        Assert.Equal(HttpStatusCode.BadRequest, invalidCheck.StatusCode);
        Assert.Equal("INVALID_HARDWARE_ID", invalidCheck.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        var invalidDeactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = lowercaseLegacy,
            AppName = appName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.BadRequest, invalidDeactivation.StatusCode);
        Assert.Equal("INVALID_HARDWARE_ID", invalidDeactivation.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var seats = await verify.LicenseSeats
            .Where(candidate => candidate.LicenseId == licenseId)
            .ToListAsync();
        Assert.Single(seats);
        Assert.False(seats[0].IsActive);
        Assert.Equal(StableHardwareId, seats[0].HardwareId);
    }

    /// <summary>
    /// Proves through resolver and HTTP paths that direct canonical V2 remains operational while legacy alias compatibility is disabled.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DisabledPolicyDoesNotBlockDirectV2OrAuthorizeArbitraryLegacy()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, StableHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolver = new HardwareAuthorityAliasResolver(
            db,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "off" }),
            NullLogger<HardwareAuthorityAliasResolver>.Instance);

        var direct = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, StableHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        var arbitrary = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, "B00272B768FFD6AF",
            HardwareAuthorityResolutionIntent.Activation);

        Assert.Equal(HardwareAuthorityResolutionStatus.NoAlias, direct.Status);
        Assert.Equal(HardwareAuthorityResolutionStatus.NoAlias, arbitrary.Status);
        Assert.Empty(await db.HardwareAuthorityAliases.ToListAsync());

        var aliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        using var webFactory = CreateAliasWebFactory(scenario, aliasLogs, aliasMode: "off");
        using var client = webFactory.CreateClient();
        var license = await db.Licenses.Include(candidate => candidate.Product)
            .SingleAsync(candidate => candidate.Id == binding.LicenseId);
        var directV2Check = await PostCheckAsync(
            client,
            license.LicenseKey,
            license.Product!.Name,
            StableHardwareId);
        Assert.Equal(HttpStatusCode.OK, directV2Check.StatusCode);
        using var directV2Json = JsonDocument.Parse(await directV2Check.Content.ReadAsStringAsync());
        Assert.Equal("VALID", directV2Json.RootElement.GetProperty("status").GetString());
        Assert.False(string.IsNullOrWhiteSpace(directV2Json.RootElement.GetProperty("licenseFile").GetString()));
    }

    /// <summary>
    /// Proves identical legacy and V2 identities return a signed current license without
    /// changing the seat, security generation, or audit history.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_IdenticalAuthorityIsNoOp()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, StableHardwareId);
        long initialAuthorityEpoch;
        int initialAssignmentRevision;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            initialAuthorityEpoch = await before.RuntimeEnrollments.AsNoTracking()
                .Where(candidate => candidate.Id == scenario.EnrollmentId)
                .Select(candidate => candidate.AuthorityEpoch).SingleAsync();
            initialAssignmentRevision = await before.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(candidate => candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE")
                .Select(candidate => candidate.Revision).SingleAsync();
        }
        var request = MigrationRequest(scenario, StableHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-current-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var result = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.Equal("already_current", result.Response.Decision);
        Assert.Equal(result.Response.OldSecurityEpoch, result.Response.NewSecurityEpoch);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(initialAuthorityEpoch, await check.RuntimeEnrollments.AsNoTracking()
            .Where(candidate => candidate.Id == scenario.EnrollmentId)
            .Select(candidate => candidate.AuthorityEpoch).SingleAsync());
        Assert.Equal(initialAssignmentRevision, await check.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(candidate => candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE")
            .Select(candidate => candidate.Revision).SingleAsync());
        Assert.Empty(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        Assert.Empty(await check.HardwareAuthorityAliases.ToListAsync());
    }

    /// <summary>
    /// Proves a fluctuating legacy disk observation can converge locally when the requested V2
    /// identity already owns the exact seat, binding, and enrollment without mutating authority.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_TargetAlreadyAuthoritativeIsNoOp()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, StableHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-target-current-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var result = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.False(result.Idempotent);
        Assert.Equal("already_current", result.Response.Decision);
        Assert.Equal(1, result.Response.OldSecurityEpoch);
        Assert.Equal(1, result.Response.NewSecurityEpoch);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(StableHardwareId, (await check.LicenseSeats.SingleAsync()).HardwareId);
        Assert.Empty(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// Proves a different WMI enumeration result cannot claim the current installation even
    /// when it proposes the same deterministic V2 target.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_DifferentLegacyDiskFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, "B00272B768FFD6AF", StableHardwareId);
        var digest = Sha256("hardware-migration-wmi-order-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        Assert.Equal("hardware_authority_migration_ineligible", rejected.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
    }

    /// <summary>
    /// Proves a V2 identity already owned by another active seat in the same product cannot be
    /// merged, transferred, or consumed by the current Runtime installation.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_CompetingTargetSeatFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await AddCompetingTargetSeatAsync(scenario);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-conflict-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status409Conflict, rejected.StatusCode);
        Assert.Equal("hardware_authority_migration_conflict", rejected.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
    }

    /// <summary>
    /// Proves concurrent migration attempts serialize on authority: one changes the licensing
    /// seat and the follower observes the same current authority as an idempotent-safe no-op.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_ConcurrentRequestsHaveSingleWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        Guid assignmentId;
        int assignmentRevision;
        long securityEpoch;
        long authorityEpoch;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var assignment = await before.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
            var enrollment = await before.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            assignmentId = assignment.Id;
            assignmentRevision = assignment.Revision;
            securityEpoch = enrollment.SecurityEpoch;
            authorityEpoch = enrollment.AuthorityEpoch;
        }
        var firstRequest = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var secondRequest = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var firstDigest = Sha256("hardware-migration-race-a-" + Guid.NewGuid().ToString("D"));
        var secondDigest = Sha256("hardware-migration-race-b-" + Guid.NewGuid().ToString("D"));
        var firstProof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", firstDigest);
        var secondProof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", secondDigest);

        var outcomes = await Task.WhenAll(
            CaptureHardwareMigrationAsync(scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, firstDigest, firstRequest, firstProof, IPAddress.Loopback)),
            CaptureHardwareMigrationAsync(scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, secondDigest, secondRequest, secondProof, IPAddress.Loopback)));

        Assert.Single(outcomes, outcome => outcome.Result?.Response.Decision == "migrated");
        Assert.Single(outcomes, outcome => outcome.Result?.Response.Decision == "already_current");
        Assert.All(outcomes, outcome =>
        {
            Assert.Null(outcome.Error);
            Assert.NotNull(outcome.Result);
            Assert.False(outcome.Result.Idempotent);
            Assert.Equal(StableHardwareId, outcome.Result.Response.HardwareIdV2);
            Assert.Equal(securityEpoch, outcome.Result.Response.OldSecurityEpoch);
            Assert.Equal(securityEpoch, outcome.Result.Response.NewSecurityEpoch);
        });
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        Assert.Equal(2, await check.RuntimeEnrollmentProofNonces.AsNoTracking().CountAsync(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration"));
        var assignmentAfter = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        Assert.Equal(assignmentId, assignmentAfter.Id);
        Assert.Equal(assignmentRevision, assignmentAfter.Revision);
        Assert.Equal(securityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(authorityEpoch, enrollmentAfter.AuthorityEpoch);
    }

    /// <summary>
    /// Proves a real commercial expiry writer and a fresh signed migration serialize on the
    /// production global lease. A migration queued first commits one coherent HWID-only generation
    /// before the expiry; an expiry queued first makes the migration deny while item 2 correctly
    /// leaves the historical ACTIVE assignment revision unchanged and no migration fragment remains.
    /// </summary>
    /// <param name="migrationQueuedFirst">Selects the observed PostgreSQL advisory wait order.</param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HardwareAuthorityMigration_CommercialExpiryRaceIsAtomic(bool migrationQueuedFirst)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        Guid licenseId;
        Guid assignmentId;
        int assignmentRevision;
        string bindingHardwareIdHash;
        string enrollmentHardwareIdHash;
        long enrollmentSecurityEpoch;
        long enrollmentAuthorityEpoch;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await before.DistributionInstallationBindings.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var enrollment = await before.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            var assignment = await before.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId && candidate.State == "ACTIVE");
            licenseId = binding.LicenseId;
            assignmentId = assignment.Id;
            assignmentRevision = assignment.Revision;
            bindingHardwareIdHash = binding.HardwareIdHash;
            enrollmentHardwareIdHash = enrollment.HardwareIdHash;
            enrollmentSecurityEpoch = enrollment.SecurityEpoch;
            enrollmentAuthorityEpoch = enrollment.AuthorityEpoch;
        }
        var migrationApplicationName = "hardware-migration-writer-race-" + Guid.NewGuid().ToString("N");
        var writerApplicationName = "hardware-expiry-writer-race-" + Guid.NewGuid().ToString("N");
        var taggedRuntime = CreateTaggedRuntime(scenario, migrationApplicationName);
        using var taggedCrypto = taggedRuntime.Crypto;
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-writer-race-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = timeout.Token;

        await using var blocker = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var blockerTransaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using (var blockerCommand = blocker.CreateCommand())
        {
            blockerCommand.Transaction = blockerTransaction;
            blockerCommand.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await blockerCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var writerConnectionString = new Npgsql.NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = writerApplicationName,
            Pooling = false
        }.ConnectionString;
        await using var writer = new Npgsql.NpgsqlConnection(writerConnectionString);
        await writer.OpenAsync(cancellationToken);
        await using var writerTransaction = await writer.BeginTransactionAsync(cancellationToken);
        await using var writerCommand = writer.CreateCommand();
        writerCommand.Transaction = writerTransaction;
        writerCommand.CommandText = """
            UPDATE public."Licenses"
            SET "ExpirationDate" = clock_timestamp() - interval '1 minute'
            WHERE "Id" = @licenseId;
            """;
        writerCommand.Parameters.AddWithValue("licenseId", licenseId);

        Task<(RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>? Result, Exception? Error)> migrationTask;
        Task<int> writerTask;
        if (migrationQueuedFirst)
        {
            migrationTask = CaptureHardwareMigrationAsync(taggedRuntime.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback, cancellationToken));
            await WaitForAdvisoryWaitersAsync(
                scenario.AdminConnectionString, [migrationApplicationName], 1, cancellationToken);
            writerTask = writerCommand.ExecuteNonQueryAsync(cancellationToken);
        }
        else
        {
            writerTask = writerCommand.ExecuteNonQueryAsync(cancellationToken);
            await WaitForAdvisoryWaitersAsync(
                scenario.AdminConnectionString, [writerApplicationName], 1, cancellationToken);
            migrationTask = CaptureHardwareMigrationAsync(taggedRuntime.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback, cancellationToken));
        }
        await WaitForAdvisoryWaitersAsync(
            scenario.AdminConnectionString,
            [migrationApplicationName, writerApplicationName],
            2,
            cancellationToken);
        Assert.False(migrationTask.IsCompleted);
        Assert.False(writerTask.IsCompleted);
        await blockerTransaction.CommitAsync(cancellationToken);

        if (migrationQueuedFirst)
        {
            var migrated = await migrationTask.WaitAsync(cancellationToken);
            Assert.Null(migrated.Error);
            Assert.Equal("migrated", migrated.Result?.Response.Decision);
            Assert.Equal(1, await writerTask.WaitAsync(cancellationToken));
            await using (var visibleBeforeWriterCommit = await scenario.Factory.CreateDbContextAsync(cancellationToken))
            {
                var active = await visibleBeforeWriterCommit.EnrollmentLicenseAssignments.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == assignmentId && candidate.State == "ACTIVE",
                        cancellationToken);
                Assert.Equal(assignmentRevision, active.Revision);
                Assert.Equal(StableHardwareId, await visibleBeforeWriterCommit.LicenseSeats.AsNoTracking()
                    .Where(candidate => candidate.Id == active.LicenseSeatId)
                    .Select(candidate => candidate.HardwareId).SingleAsync(cancellationToken));
            }
            await writerTransaction.CommitAsync(cancellationToken);
            await using var ended = await scenario.Factory.CreateDbContextAsync(cancellationToken);
            var terminal = await ended.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.EnrollmentId == scenario.EnrollmentId, cancellationToken);
            Assert.Equal("ACTIVE", terminal.State);
            Assert.Equal(assignmentRevision, terminal.Revision);
            var stableBinding = await ended.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId, cancellationToken);
            var stableEnrollment = await ended.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId, cancellationToken);
            Assert.Equal(bindingHardwareIdHash, stableBinding.HardwareIdHash);
            Assert.Equal(enrollmentHardwareIdHash, stableEnrollment.HardwareIdHash);
            Assert.Equal(enrollmentSecurityEpoch, stableEnrollment.SecurityEpoch);
            Assert.Equal(enrollmentAuthorityEpoch, stableEnrollment.AuthorityEpoch);
            Assert.Single(await ended.HardwareAuthorityAliases.AsNoTracking().ToListAsync(cancellationToken));
            Assert.Single(await ended.LicenseHistories.AsNoTracking().Where(candidate =>
                candidate.Action == "HWID_V2_MIGRATED").ToListAsync(cancellationToken));
            Assert.Single(await ended.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId
                && candidate.Operation == "hardware-authority-migration").ToListAsync(cancellationToken));
        }
        else
        {
            Assert.Equal(1, await writerTask.WaitAsync(cancellationToken));
            await writerTransaction.CommitAsync(cancellationToken);
            var denied = await migrationTask.WaitAsync(cancellationToken);
            var error = Assert.IsType<RuntimeEnrollmentException>(denied.Error);
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, error.StatusCode);
            Assert.Null(denied.Result);
            await AssertLegacyAuthorityUnchangedAsync(scenario);
            await using var unchanged = await scenario.Factory.CreateDbContextAsync(cancellationToken);
            var active = await unchanged.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == assignmentId, cancellationToken);
            Assert.Equal("ACTIVE", active.State);
            Assert.Equal(assignmentRevision, active.Revision);
            Assert.Empty(await unchanged.HardwareAuthorityAliases.AsNoTracking().ToListAsync(cancellationToken));
            Assert.Empty(await unchanged.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId
                && candidate.Operation == "hardware-authority-migration").ToListAsync(cancellationToken));
        }
    }

    /// <summary>
    /// Proves an exact encrypted replay cannot bypass a licence revocation committed after the
    /// original V2 transition.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_ReplayRevalidatesCurrentAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-replay-revocation-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await MutateScenarioAuthorityAsync(scenario, "license-revoked");

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// Proves an unauthenticated migration is rejected before a missing or quarantined commercial
    /// assignment can disclose its current state, and leaves every Runtime authority row unchanged.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_InvalidProofPrecedesQuarantinedAssignment()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = """
                DELETE FROM public."EnrollmentLicenseAssignments"
                WHERE "EnrollmentId" = @enrollmentId;
                INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                    ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId", "Reason", "ObservedAtUtc")
                SELECT "Id", "BindingId", "LicenseId", "LicenseSeatId", 'live_state_mismatch', clock_timestamp()
                FROM public."RuntimeEnrollments" WHERE "Id" = @enrollmentId;
                """;
            command.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            await command.ExecuteNonQueryAsync();
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-invalid-proof-quarantine-" + Guid.NewGuid().ToString("D"));
        using var attackerKey = RSA.Create(3072);
        var proof = Proof(attackerKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status401Unauthorized, rejected.StatusCode);
        Assert.Equal("authentication_failed", rejected.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await check.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration").ToListAsync());
    }

    /// <summary>
    /// Proves the migration endpoint itself rejects absent or quarantined commercial authority as
    /// 422 and treats duplicate or broken assignment relations as 503, without any partial write.
    /// Each case owns an isolated database because the ambiguity fixtures remove local constraints.
    /// </summary>
    /// <param name="assignmentState">Exact malformed assignment graph to install.</param>
    /// <param name="expectedStatusCode">Stable public status for the graph classification.</param>
    /// <param name="expectedDiagnostic">Bounded internal assignment diagnostic.</param>
    [Theory]
    [InlineData("missing", StatusCodes.Status422UnprocessableEntity, "assignment_missing")]
    [InlineData("quarantined", StatusCodes.Status422UnprocessableEntity, "assignment_quarantined")]
    [InlineData("duplicate", StatusCodes.Status503ServiceUnavailable, "assignment_duplicate_active")]
    [InlineData("relation-missing", StatusCodes.Status503ServiceUnavailable, "assignment_relation_missing")]
    public async Task HardwareAuthorityMigration_AssignmentGraphFailsClosedWithoutMutation(
        string assignmentState,
        int expectedStatusCode,
        string expectedDiagnostic)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        RuntimeEnrollment enrollmentBefore;
        LicenseSeat seatBefore;
        int quotaCountBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            seatBefore = await before.LicenseSeats.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == enrollmentBefore.LicenseSeatId);
            quotaCountBefore = await before.RuntimeEnrollmentQuotas.AsNoTracking().CountAsync();
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            switch (assignmentState)
            {
                case "missing":
                    command.CommandText = """
                        DELETE FROM public."EnrollmentLicenseAssignments"
                        WHERE "EnrollmentId" = @enrollmentId;
                        """;
                    break;
                case "quarantined":
                    command.CommandText = """
                        DELETE FROM public."EnrollmentLicenseAssignments"
                        WHERE "EnrollmentId" = @enrollmentId;
                        INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                            ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId", "Reason", "ObservedAtUtc")
                        SELECT "Id", "BindingId", "LicenseId", "LicenseSeatId",
                               'live_state_mismatch', clock_timestamp()
                        FROM public."RuntimeEnrollments" WHERE "Id" = @enrollmentId;
                        """;
                    break;
                case "duplicate":
                    command.Parameters.AddWithValue("duplicateId", Guid.NewGuid());
                    command.CommandText = """
                        DROP INDEX public."IX_EnrollmentLicenseAssignments_EnrollmentId";
                        DROP INDEX public."IX_EnrollmentLicenseAssignments_LicenseSeatId";
                        INSERT INTO public."EnrollmentLicenseAssignments"
                            ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                             "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
                        SELECT @duplicateId, "EnrollmentId", "LicenseId", "LicenseSeatId", 'ACTIVE',
                               clock_timestamp(), NULL, "Revision" + 1, NULL
                        FROM public."EnrollmentLicenseAssignments"
                        WHERE "EnrollmentId" = @enrollmentId AND "State" = 'ACTIVE';
                        """;
                    break;
                case "relation-missing":
                    command.Parameters.AddWithValue("missingLicenseId", Guid.NewGuid());
                    command.CommandText = """
                        ALTER TABLE public."EnrollmentLicenseAssignments"
                            DROP CONSTRAINT "FK_EnrollmentLicenseAssignments_Licenses_LicenseId";
                        ALTER TABLE public."EnrollmentLicenseAssignments"
                            DROP CONSTRAINT "FK_EnrollmentLicenseAssignments_LicenseSeats_LicenseSeatId_LicenseId";
                        UPDATE public."EnrollmentLicenseAssignments"
                        SET "LicenseId" = @missingLicenseId
                        WHERE "EnrollmentId" = @enrollmentId AND "State" = 'ACTIVE';
                        """;
                    break;
                default:
                    throw new InvalidOperationException("Unknown assignment graph fixture: " + assignmentState);
            }
            await command.ExecuteNonQueryAsync();
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-assignment-" + assignmentState + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(expectedStatusCode, rejected.StatusCode);
        Assert.Equal(expectedDiagnostic, rejected.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seatAfter = await check.LicenseSeats.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == seatBefore.Id);
        Assert.Equal(enrollmentBefore.State, enrollmentAfter.State);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
        Assert.Equal(enrollmentBefore.HardwareIdHash, enrollmentAfter.HardwareIdHash);
        Assert.Equal(seatBefore.HardwareId, seatAfter.HardwareId);
        Assert.Equal(seatBefore.IsActive, seatAfter.IsActive);
        Assert.Equal(quotaCountBefore, await check.RuntimeEnrollmentQuotas.AsNoTracking().CountAsync());
        Assert.Empty(await check.HardwareAuthorityAliases.AsNoTracking().ToListAsync());
        Assert.Empty(await check.LicenseHistories.AsNoTracking().Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        Assert.Empty(await check.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration").ToListAsync());
    }

    /// <summary>
    /// Proves a reused authenticated JTI with a different exact body remains an idempotency
    /// conflict before a later commercial denial, without changing the migrated generation.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_DivergentReplayPrecedesCommercialDenial()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-divergent-replay-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var migrated = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await MutateScenarioAuthorityAsync(scenario, "license-revoked");

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, Sha256("different-exact-body"), request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status409Conflict, rejected.StatusCode);
        Assert.Equal("replay_rejected", rejected.ErrorCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration").ToListAsync());
        var enrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        Assert.Equal(migrated.Response.NewSecurityEpoch, enrollment.SecurityEpoch);
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// Proves an unresolved critical Runtime incident blocks both a first migration and any
    /// otherwise exact replay, so identity repair cannot bypass the incident authority.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HardwareAuthorityMigration_OpenCriticalIncidentFailsClosed(bool migrateBeforeIncident)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-critical-incident-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        if (migrateBeforeIncident)
        {
            await scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        }

        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await seed.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            seed.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = enrollment.SecurityEpoch,
                OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
                OpenedAtUtc = DateTime.UtcNow
            });
            await seed.SaveChangesAsync();
        }

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status423Locked, rejected.StatusCode);
        Assert.Equal("critical_incident_unresolved", rejected.ErrorCode);
    }

    /// <summary>
    /// Proves revocation, expiry, seat removal, and identity authority divergence always win
    /// over a correctly signed migration request.
    /// </summary>
    [Theory]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("seat-inactive")]
    [InlineData("binding-subject")]
    [InlineData("binding-installation")]
    [InlineData("enrollment-client")]
    [InlineData("binding-product")]
    public async Task HardwareAuthorityMigration_IneligibleAuthorityFailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        if (mutation is "binding-installation" or "binding-product")
        {
            DistributionInstallationBinding bindingBefore;
            await using (var before = await scenario.Factory.CreateDbContextAsync())
            {
                bindingBefore = await before.DistributionInstallationBindings.AsNoTracking()
                    .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
            }

            var graphRejected = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                MutateScenarioAuthorityAsync(scenario, mutation));

            Assert.Equal(Npgsql.PostgresErrorCodes.CheckViolation, graphRejected.SqlState);
            Assert.Contains("binding_mismatch", graphRejected.MessageText, StringComparison.Ordinal);
            await using var unchanged = await scenario.Factory.CreateDbContextAsync();
            var bindingAfter = await unchanged.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
            Assert.Equal(bindingBefore.ProductId, bindingAfter.ProductId);
            Assert.Equal(bindingBefore.InstallationId, bindingAfter.InstallationId);
            Assert.Empty(await unchanged.RuntimeEnrollmentProofNonces.AsNoTracking().Where(candidate =>
                candidate.EnrollmentId == scenario.EnrollmentId
                && candidate.Operation == "hardware-authority-migration").ToListAsync());
            return;
        }
        await MutateScenarioAuthorityAsync(scenario, mutation);
        RuntimeEnrollment enrollmentBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentBefore = await before.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-ineligible-" + mutation + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
        Assert.DoesNotContain(await check.RuntimeEnrollmentProofNonces.AsNoTracking().ToListAsync(), candidate =>
            candidate.EnrollmentId == scenario.EnrollmentId
            && candidate.Operation == "hardware-authority-migration");
        Assert.Empty(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>Creates an application-role HTTP server with an exact product alias compatibility mode and the scenario signing authority.</summary>
    /// <param name="scenario">Isolated PostgreSQL authority graph and signing fixture.</param>
    /// <param name="aliasLogger">Logger used to assert that alias telemetry contains no hardware identifiers or digests.</param>
    /// <param name="aliasMode">Exact default compatibility mode, either enabled or off.</param>
    /// <param name="activationLogger">Optional activation controller logger used by log assertions.</param>
    /// <param name="adminLogger">Optional admin controller logger used by TEMP-FAIL-OPEN log assertions.</param>
    /// <returns>A disposable HTTP factory connected to the isolated application-role database.</returns>
    private static WebApplicationFactory<Program> CreateAliasWebFactory(
        PreparedBootstrapScenario scenario,
        RecordingLogger<HardwareAuthorityAliasResolver> aliasLogger,
        string aliasMode = "enabled",
        RecordingLogger<ActivationController>? activationLogger = null,
        RecordingLogger<AdminController>? adminLogger = null)
    {
        var notification = new Mock<NotificationService>(
            scenario.Factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        notification.Setup(service => service.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));

        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("HardwareAuthorityAliases:DefaultMode", aliasMode);
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseNpgsql(scenario.AppConnectionString));
                services.RemoveAll<ISignedLicenseFileService>();
                services.AddSingleton(scenario.SignedLicenseFiles);
                services.RemoveAll<NotificationService>();
                services.AddSingleton(notification.Object);
                services.RemoveAll<ILogger<HardwareAuthorityAliasResolver>>();
                services.AddSingleton<ILogger<HardwareAuthorityAliasResolver>>(aliasLogger);
                if (activationLogger != null)
                {
                    services.RemoveAll<ILogger<ActivationController>>();
                    services.AddSingleton<ILogger<ActivationController>>(activationLogger);
                }
                if (adminLogger != null)
                {
                    services.RemoveAll<ILogger<AdminController>>();
                    services.AddSingleton<ILogger<AdminController>>(adminLogger);
                }
            });
        });
    }

    /// <summary>Sends the canonical JSON activation shape used by transition clients.</summary>
    private static Task<HttpResponseMessage> PostActivationAsync(
        HttpClient client,
        string licenseKey,
        string appName,
        string hardwareId) =>
        client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = "2.3.393"
        });

    /// <summary>Sends the canonical JSON status shape used by transition clients.</summary>
    private static Task<HttpResponseMessage> PostCheckAsync(
        HttpClient client,
        string licenseKey,
        string appName,
        string hardwareId) =>
        client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = "2.3.393"
        });

    /// <summary>
    /// Makes the already confirmed Runtime fixture require one real legacy HTTP reactivation while preserving its binding authority.
    /// </summary>
    private static async Task PrepareLegacyHttpActivationAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        license.CustomerEmail = "hwid-alias-regression@example.com";
        license.AllowedVersions = "2.*";
        seat.IsActive = false;
        await db.SaveChangesAsync();
    }

    /// <summary>Creates or toggles one exact product-scoped hardware ban for endpoint tests.</summary>
    private static async Task SetHardwareBanAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId,
        bool active,
        string category = BannedHardwareId.Categories.Piracy)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var ban = await db.BannedHardwareIds.SingleOrDefaultAsync(candidate =>
            candidate.HardwareId == hardwareId && candidate.ProductId == scenario.Fixture.ProductId);
        if (ban == null)
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = scenario.Fixture.ProductId,
                BanCategory = category,
                Reason = "hardware-authority-alias-test",
                IsActive = active
            });
        }
        else
        {
        ban.IsActive = active;
        ban.BanCategory = category;
        }
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Captures rendered structured log messages for redaction assertions without changing production logging.
    /// </summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly ConcurrentQueue<string> _messages = new();

        /// <summary>Gets a stable snapshot of rendered messages.</summary>
        public IReadOnlyList<string> Messages => _messages.ToArray();

        /// <inheritdoc />
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        /// <inheritdoc />
        public bool IsEnabled(LogLevel logLevel) => true;

        /// <inheritdoc />
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            _messages.Enqueue(formatter(state, exception));
    }

    /// <summary>Returns one predetermined authority resolution inside the service-owned transaction.</summary>
    private sealed class FixedHardwareAuthorityAliasResolver(HardwareAuthorityResolution resolution)
        : IHardwareAuthorityAliasResolver
    {
        public Task<HardwareAuthorityResolution> ResolveAsync(
            Guid productId,
            Guid licenseId,
            string submittedHardwareId,
            HardwareAuthorityResolutionIntent intent,
            CancellationToken cancellationToken = default) => Task.FromResult(resolution);

        public Task<HardwareAuthorityResolution> ResolveAsync(
            LicenseDbContext authorityDb,
            Guid productId,
            Guid licenseId,
            string submittedHardwareId,
            HardwareAuthorityResolutionIntent intent,
            CancellationToken cancellationToken = default) => Task.FromResult(resolution);
    }

    /// <summary>Creates the exact versioned migration request for an activated test scenario.</summary>
    private static RuntimeHardwareAuthorityMigrationRequest MigrationRequest(
        PreparedBootstrapScenario scenario,
        string legacyHardwareId,
        string hardwareIdV2) => new()
        {
            Schema = RuntimeEnrollmentService.HardwareAuthorityMigrationSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            LegacyHardwareId = legacyHardwareId,
            HardwareIdV2 = hardwareIdV2,
            LegacyAlgorithm = RuntimeEnrollmentService.HardwareMigrationSourceAlgorithm,
            HardwareIdV2Algorithm = RuntimeEnrollmentService.HardwareMigrationTargetAlgorithm,
            SdkVersion = "2.0.0",
            SystemUuid = TestSystemUuid
        };

    /// <summary>Executes one fresh signed legacy-to-V2 migration for alias tests.</summary>
    private static async Task MigrateScenarioAsync(PreparedBootstrapScenario scenario)
    {
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-alias-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
    }

    /// <summary>
    /// Creates one production-shaped intergeneration rotation and prepares, but does not confirm,
    /// the successor Runtime enrollment so tests can mutate exact pre-Confirm authority evidence.
    /// </summary>
    /// <param name="scenario">Isolated PostgreSQL authority graph.</param>
    /// <param name="purpose">Unique ASCII test purpose used only to separate request digests.</param>
    /// <param name="afterMigration">Optional signed-migration continuation before the successor is finalized.</param>
    /// <returns>Disposable signing key and exact successor Confirm inputs.</returns>
    private static async Task<AliasSuccessorConfirmScenario> PrepareAliasSuccessorConfirmScenarioAsync(
        PreparedBootstrapScenario scenario,
        string purpose,
        Func<Task>? afterMigration = null)
    {
        var subjectRef = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(purpose + "-subject")));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);
        if (afterMigration != null)
            await afterMigration();
        Guid aliasId;
        Guid sourceEnrollmentId;
        int aliasSecurityEpoch;
        long aliasAuthorityEpoch;
        await using (var source = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await source.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
            aliasId = alias.Id;
            sourceEnrollmentId = alias.RuntimeEnrollmentId;
            aliasSecurityEpoch = alias.SecurityEpoch;
            aliasAuthorityEpoch = alias.AuthorityEpoch;
        }

        var distribution = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        var finalized = await distribution.Service.FinalizeAsync(
            "website-step1",
            Sha256(purpose + "-finalize-" + Guid.NewGuid().ToString("D")),
            distribution.Request);
        var successorBindingId = Guid.Parse(finalized.Response.BindingId);
        (Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version)
            successorFixture;
        await using (var bindingDb = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await bindingDb.DistributionInstallationBindings.AsNoTracking().SingleAsync(candidate =>
                candidate.Id == successorBindingId);
            successorFixture = (
                binding.ProductId,
                binding.Id,
                binding.HandoffDigestSha256,
                binding.InstallationId,
                binding.Version);
        }

        var key = RSA.Create(3072);
        try
        {
            var prepareRequest = PrepareRequest(
                successorFixture, Guid.NewGuid().ToString("D"), key);
            prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
            var prepared = await scenario.Runtime.PrepareAsync(
                "website-step1",
                Sha256(purpose + "-prepare-" + Guid.NewGuid().ToString("D")),
                prepareRequest);
            var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
            var confirmRequest = new RuntimeEnrollmentConfirmRequest
            {
                Schema = RuntimeEnrollmentService.ConfirmSchema,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                EnrollmentId = enrollmentId.ToString("D"),
                Epoch = 1
            };
            var confirmDigest = Sha256(purpose + "-confirm-" + Guid.NewGuid().ToString("D"));
            var confirmProof = Proof(
                key,
                "confirm",
                enrollmentId,
                scenario.Options.ConfirmAudience,
                prepared.Response.Challenge,
                confirmDigest);
            return new AliasSuccessorConfirmScenario(
                key,
                aliasId,
                scenario.Fixture.BindingId,
                sourceEnrollmentId,
                aliasSecurityEpoch,
                aliasAuthorityEpoch,
                successorBindingId,
                enrollmentId,
                prepared.Response.Challenge,
                confirmRequest,
                confirmDigest,
                confirmProof);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Asserts that a refused or rolled-back Confirm left the successor pending, wrote no Confirm
    /// nonce and preserved both predecessor alias pointers and their pre-Confirm epochs.
    /// </summary>
    /// <param name="scenario">PostgreSQL scenario that owns the database context factory.</param>
    /// <param name="successor">Prepared successor and predecessor identifiers expected after rollback.</param>
    /// <param name="expectedAliasSecurityEpoch">Persisted pre-Confirm alias security epoch, or <see langword="null"/> to use the scenario baseline.</param>
    /// <param name="expectedAliasAuthorityEpoch">Persisted pre-Confirm alias authority epoch, or <see langword="null"/> to use the scenario baseline.</param>
    /// <returns>A task that completes after all PostgreSQL state assertions succeed.</returns>
    /// <exception cref="Xunit.Sdk.XunitException">Thrown when enrollment, nonce, alias pointer or epoch state changed unexpectedly.</exception>
    private static async Task AssertPendingSuccessorAndStaleAliasAsync(
        PreparedBootstrapScenario scenario,
        AliasSuccessorConfirmScenario successor,
        int? expectedAliasSecurityEpoch = null,
        long? expectedAliasAuthorityEpoch = null)
    {
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == successor.EnrollmentId);
        var alias = await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync(candidate =>
            candidate.Id == successor.AliasId);
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(successor.SourceBindingId, alias.BindingId);
        Assert.Equal(successor.SourceEnrollmentId, alias.RuntimeEnrollmentId);
        Assert.Equal(expectedAliasSecurityEpoch ?? successor.AliasSecurityEpoch, alias.SecurityEpoch);
        Assert.Equal(expectedAliasAuthorityEpoch ?? successor.AliasAuthorityEpoch, alias.AuthorityEpoch);
        Assert.Empty(await check.RuntimeEnrollmentProofNonces.Where(candidate =>
            candidate.EnrollmentId == successor.EnrollmentId && candidate.Operation == "confirm").ToListAsync());
    }

    /// <summary>
    /// Maps one adversarial fixture mutation to the first stable server-only Confirm diagnostic
    /// selected by the production invariant order.
    /// </summary>
    /// <param name="mutation">Allowlisted mutation name applied by the invalid-graph theory.</param>
    /// <returns>The expected allowlisted internal diagnostic code.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the mutation is not part of the documented theory inventory.</exception>
    private static string ExpectedConfirmAliasDiagnostic(string mutation) => mutation switch
    {
        "alias-product" or "alias-license" or "alias-seat" or "alias-canonical-hash" =>
            "confirm_alias_boundary_mismatch",
        "predecessor-subject" or "source-release" => "confirm_alias_generation_mismatch",
        "source-client" => "confirm_alias_owner_mismatch",
        "predecessor-binding-state" or "predecessor-binding-reason" =>
            "confirm_alias_predecessor_terminal_mismatch",
        "predecessor-enrollment-state" or "source-terminal-reason" =>
            "confirm_alias_enrollment_terminal_mismatch",
        "alias-security-epoch" or "alias-authority-epoch" or "source-authority-epoch"
            or "successor-initial-security-epoch" => "confirm_alias_epoch_mismatch",
        _ => throw new InvalidOperationException("No Confirm alias diagnostic for mutation: " + mutation)
    };

    /// <summary>Captures one concurrent Confirm outcome without hiding its exact exception.</summary>
    private static async Task<(
        RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>? Result,
        Exception? Error)> CaptureConfirmAsync(
        Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>> task)
    {
        try
        {
            return (await task, null);
        }
        catch (Exception exception)
        {
            return (null, exception);
        }
    }

    /// <summary>Owns one prepared successor enrollment and its client signing key.</summary>
    private sealed record AliasSuccessorConfirmScenario(
        RSA Key,
        Guid AliasId,
        Guid SourceBindingId,
        Guid SourceEnrollmentId,
        int AliasSecurityEpoch,
        long AliasAuthorityEpoch,
        Guid BindingId,
        Guid EnrollmentId,
        string Challenge,
        RuntimeEnrollmentConfirmRequest ConfirmRequest,
        string ConfirmDigest,
        RuntimeProofHeaders ConfirmProof) : IDisposable
    {
        /// <summary>Releases the test-owned successor signing key.</summary>
        public void Dispose() => Key.Dispose();
    }

    /// <summary>
    /// Aligns the activated binding, entitlement, and enrollment on one canonical Website subject
    /// so migration and a later Finalize v2 request prove the same installation authority.
    /// </summary>
    /// <param name="scenario">Activated PostgreSQL Runtime scenario to align before migration.</param>
    /// <param name="subjectRef">Canonical base64url Website subject reference.</param>
    private static async Task SetScenarioSubjectAuthorityAsync(
        PreparedBootstrapScenario scenario,
        string subjectRef)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.SingleAsync(candidate =>
            candidate.Id == binding.EntitlementId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var subjectDigest = Sha256(subjectRef);
        binding.SubjectRefDigestSha256 = subjectDigest;
        binding.HandoffIssuedAtUtc = DateTime.UtcNow.AddMinutes(-10);
        binding.DownloadCompletedAtUtc = DateTime.UtcNow.AddMinutes(-9);
        binding.HandoffExpiresAtUtc = DateTime.UtcNow.AddMinutes(30);
        entitlement.SubjectRefDigestSha256 = subjectDigest;
        enrollment.SubjectRefDigestSha256 = subjectDigest;
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Issues a same-license V3 entitlement and builds the exact Finalize v2 shape emitted after
    /// WebSetup Runtime fallback, with no client replacement candidate or legacy-to-V2 pair.
    /// </summary>
    /// <param name="scenario">Migrated PostgreSQL authority graph.</param>
    /// <param name="subjectRef">Canonical Website subject that owns the existing binding.</param>
    /// <param name="submittedHardwareId">Exact primary identifier placed in the finalize request.</param>
    /// <param name="applicationName">Optional exact PostgreSQL connection identity used by lock-order tests.</param>
    /// <param name="logger">Optional bounded Finalize refusal logger used by diagnostic assertions.</param>
    /// <returns>The production service, mutable request, and target licence identifier.</returns>
    private static async Task<(
        DistributionInstallationBindingService Service,
        DistributionInstallationFinalizeRequest Request,
        Guid LicenseId)> PrepareDistributionFinalizeAsync(
        PreparedBootstrapScenario scenario,
        string subjectRef,
        string submittedHardwareId,
        string? applicationName = null,
        ILogger<DistributionInstallationBindingService>? logger = null,
        IHardwareAuthorityAliasResolver? hardwareAuthorityAliases = null)
    {
        Guid licenseId;
        List<DistributionBinaryEvidence> binaries;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            licenseId = binding.LicenseId;
            var license = await db.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.MaxSeats = 1;
            binaries = await db.ApprovedBinaries.AsNoTracking()
                .Where(candidate => candidate.ProductId == scenario.Fixture.ProductId
                    && candidate.Version == scenario.Fixture.Version
                    && candidate.Source == ApprovedBinaryService.ReleaseSource)
                .OrderBy(candidate => candidate.Key)
                .Select(candidate => new DistributionBinaryEvidence
                {
                    Key = candidate.Key,
                    Sha256 = candidate.Hash
                })
                .ToListAsync();
            await db.SaveChangesAsync();
        }
        Assert.Equal(3, binaries.Count);

        var now = DateTimeOffset.UtcNow;
        var dataProtection = new EphemeralDataProtectionProvider();
        IDbContextFactory<LicenseDbContext> serviceFactory = scenario.Factory;
        if (applicationName != null)
        {
            var taggedConnection = new Npgsql.NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
            {
                ApplicationName = applicationName
            }.ConnectionString;
            serviceFactory = new TestDbFactory(taggedConnection);
        }
        var service = new DistributionInstallationBindingService(
            serviceFactory,
            dataProtection,
            new FixedTimeProvider(now),
            hardwareAuthorityAliases ?? TestHardwareAuthorityAliasResolver.Instance,
            logger);
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("distribution-finalize-entitlement-" + Guid.NewGuid().ToString("D")),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = licenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = subjectRef
            });
        var request = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("distribution-finalize-handoff-" + Guid.NewGuid().ToString("D")),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-2)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-1)),
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = submittedHardwareId,
            AllowSameAuthorityRecovery = true,
            Release = new DistributionReleaseEvidence
            {
                Version = scenario.Fixture.Version,
                InstallerFilename = $"TiaConnect-Setup_v{scenario.Fixture.Version}.msi",
                InstallerSha256 = new string('f', 64)
            },
            Binaries = binaries
        };
        return (service, request, licenseId);
    }

    /// <summary>
    /// Applies the Finalize v4 shape observed in the customer recovery path without granting any
    /// candidate authority over the exact binding already authenticated by the SoftLicence alias.
    /// </summary>
    /// <param name="request">Mutable synthetic Finalize request that receives three unrelated histories.</param>
    private static void ConfigureFinalizeV4WithUnrelatedCandidates(
        DistributionInstallationFinalizeRequest request)
    {
        request.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
        request.LicenseReplacementCandidates = new DistributionLicenseReplacementCandidateSet
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
            Sources =
            [
                CreateUnrelatedV4ReplacementCandidate("one"),
                CreateUnrelatedV4ReplacementCandidate("two"),
                CreateUnrelatedV4ReplacementCandidate("three")
            ]
        };
    }

    /// <summary>
    /// Creates one structurally valid but authority-unrelated Website history candidate.
    /// </summary>
    /// <param name="suffix">Stable test label used only to generate a distinct synthetic subject.</param>
    /// <returns>A candidate that cannot match any server-owned binding, licence, or subject.</returns>
    private static DistributionLicenseReplacementProof CreateUnrelatedV4ReplacementCandidate(
        string suffix) => new()
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
            SourceBindingId = Guid.NewGuid().ToString("D"),
            SourceLicenseId = Guid.NewGuid().ToString("D"),
            SourceSubjectRef = Base64Url(SHA256.HashData(
                Encoding.UTF8.GetBytes("unrelated-v4-candidate-" + suffix)))
        };

    /// <summary>
    /// Captures a concurrent distribution finalize outcome so lock ordering and final database
    /// invariants remain observable even when one serialized contender is rejected.
    /// </summary>
    /// <param name="task">Finalize operation already competing for production advisory locks.</param>
    /// <returns>Either the committed result or its exact exception.</returns>
    private static async Task<(
        DistributionOperationResult<DistributionInstallationBindingResponse>? Result,
        Exception? Error)> CaptureDistributionFinalizeAsync(
        Task<DistributionOperationResult<DistributionInstallationBindingResponse>> task)
    {
        try
        {
            return (await task, null);
        }
        catch (Exception exception)
        {
            return (null, exception);
        }
    }

    /// <summary>
    /// Creates a Runtime service whose database sessions expose an exact PostgreSQL application name.
    /// </summary>
    /// <param name="scenario">Scenario whose options, signer, and application role must be reused.</param>
    /// <param name="applicationName">Exact connection identity observed by lock-order tests.</param>
    /// <returns>The tagged production service and its caller-owned cryptographic dependency.</returns>
    private static (RuntimeEnrollmentService Runtime, RuntimeEnrollmentCryptoService Crypto) CreateTaggedRuntime(
        PreparedBootstrapScenario scenario,
        string applicationName,
        ILogger<RuntimeEnrollmentService>? historyLogger = null)
    {
        var taggedConnection = new Npgsql.NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = applicationName
        }.ConnectionString;
        var factory = new TestDbFactory(taggedConnection);
        var options = Options.Create(scenario.Options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, options);
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, options);
        var crypto = new RuntimeEnrollmentCryptoService(options);
        return (new RuntimeEnrollmentService(
            factory,
            authority,
            registry,
            crypto,
            options,
            signedLicenseFiles: scenario.SignedLicenseFiles,
            historyLogger: historyLogger), crypto);
    }

    /// <summary>
    /// Waits until the requested application sessions are blocked on PostgreSQL advisory locks.
    /// </summary>
    /// <param name="adminConnectionString">Administrative PostgreSQL connection used only for lock observation.</param>
    /// <param name="applicationNames">Exact scenario-owned PostgreSQL connection identities to observe.</param>
    /// <param name="minimumWaiters">Minimum concurrent application sessions that must be waiting.</param>
    /// <param name="cancellationToken">Bounds the complete concurrent lock-order observation.</param>
    /// <exception cref="TimeoutException">The required waiters were not observed within the bounded polling window.</exception>
    private static async Task WaitForAdvisoryWaitersAsync(
        string adminConnectionString,
        string[] applicationNames,
        int minimumWaiters,
        CancellationToken cancellationToken)
    {
        await using var observer = new Npgsql.NpgsqlConnection(adminConnectionString);
        await observer.OpenAsync(cancellationToken);
        for (var attempt = 0; attempt < 100; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT count(*)
                FROM pg_catalog.pg_stat_activity
                WHERE usename = 'softlicence_runtime_test_app'
                  AND application_name = ANY(@applicationNames)
                  AND wait_event_type = 'Lock'
                  AND wait_event = 'advisory';
                """;
            command.Parameters.AddWithValue("applicationNames", applicationNames);
            var waiters = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
            if (waiters >= minimumWaiters)
                return;
            await Task.Delay(20, cancellationToken);
        }
        throw new TimeoutException($"Expected at least {minimumWaiters} advisory-lock waiters.");
    }

    /// <summary>
    /// Installs a test-owned PostgreSQL trigger that raises SQLSTATE <c>P0001</c> when Confirm flushes
    /// any alias pointer or epoch update. Install it immediately before the exercised Confirm and
    /// always pair it with <see cref="RemoveAliasUpdateFailureTriggerAsync"/> in a <c>finally</c> block.
    /// The resulting save failure is expected to surface through EF Core as <see cref="DbUpdateException"/>
    /// and proves that the caller-owned Confirm transaction rolls back enrollment, nonce and alias state.
    /// </summary>
    /// <param name="adminConnectionString">Test-only PostgreSQL administrator connection string for the isolated database.</param>
    /// <returns>A task that completes after the trigger function and trigger are installed.</returns>
    /// <exception cref="Npgsql.NpgsqlException">Thrown when the isolated database cannot install the test trigger.</exception>
    private static async Task InstallAliasUpdateFailureTriggerAsync(string adminConnectionString)
    {
        await using var connection = new Npgsql.NpgsqlConnection(adminConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, """
            CREATE OR REPLACE FUNCTION public.runtime_test_alias_update_failure()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            BEGIN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='injected alias update failure';
            END;
            $body$;
            CREATE TRIGGER runtime_test_alias_update_failure
            BEFORE UPDATE OF "BindingId", "RuntimeEnrollmentId", "SecurityEpoch", "AuthorityEpoch"
            ON public."HardwareAuthorityAliases"
            FOR EACH ROW EXECUTE FUNCTION public.runtime_test_alias_update_failure();
            """);
    }

    /// <summary>
    /// Idempotently removes only the test-owned alias update trigger and function. Cleanup is safe
    /// after either a successful injection or a failed test setup and must run before the isolated
    /// PostgreSQL database is disposed so the trigger cannot affect later assertions.
    /// </summary>
    /// <param name="adminConnectionString">Test-only PostgreSQL administrator connection string for the isolated database.</param>
    /// <returns>A task that completes after both test-owned objects are absent.</returns>
    /// <exception cref="Npgsql.NpgsqlException">Thrown when PostgreSQL cleanup cannot be completed.</exception>
    private static async Task RemoveAliasUpdateFailureTriggerAsync(string adminConnectionString)
    {
        await using var connection = new Npgsql.NpgsqlConnection(adminConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, """
            DROP TRIGGER IF EXISTS runtime_test_alias_update_failure
                ON public."HardwareAuthorityAliases";
            DROP FUNCTION IF EXISTS public.runtime_test_alias_update_failure();
            """);
    }

    /// <summary>
    /// Verifies Finalize left one active V2 seat and one successor binding while terminalizing the
    /// exact source binding and enrollment without duplicate authority.
    /// </summary>
    /// <param name="scenario">Migrated scenario whose source authority must be terminalized.</param>
    /// <param name="licenseId">Exact license expected to retain one active V2 seat.</param>
    /// <param name="cancellationToken">Bounds the relational invariant checks.</param>
    private static async Task AssertFinalizedMigrationAuthorityAsync(
        PreparedBootstrapScenario scenario,
        Guid licenseId,
        CancellationToken cancellationToken)
    {
        await using var check = await scenario.Factory.CreateDbContextAsync(cancellationToken);
        var seats = await check.LicenseSeats
            .Where(candidate => candidate.LicenseId == licenseId)
            .ToListAsync(cancellationToken);
        var seat = Assert.Single(seats);
        Assert.True(seat.IsActive);
        Assert.Equal(StableHardwareId, seat.HardwareId);

        var bindings = await check.DistributionInstallationBindings
            .Where(candidate => candidate.ProductId == scenario.Fixture.ProductId)
            .ToListAsync(cancellationToken);
        Assert.Equal(2, bindings.Count);
        var sourceBinding = Assert.Single(bindings, candidate => candidate.Id == scenario.Fixture.BindingId);
        Assert.Equal("invalidated", sourceBinding.State);
        Assert.Equal("installation_superseded", sourceBinding.InvalidationReason);
        var successorBinding = Assert.Single(bindings, candidate => candidate.State == "active");
        Assert.Equal(sourceBinding.Id, successorBinding.SupersededBindingId);
        Assert.Equal(Sha256(StableHardwareId), successorBinding.HardwareIdHash);

        var sourceEnrollment = await check.RuntimeEnrollments.SingleAsync(
            candidate => candidate.Id == scenario.EnrollmentId,
            cancellationToken);
        Assert.Equal("INVALIDATED", sourceEnrollment.State);
        Assert.Equal("binding_superseded", sourceEnrollment.InvalidationReason);
    }

    /// <summary>Creates the production resolver with explicit enabled compatibility policy.</summary>
    private static HardwareAuthorityAliasResolver CreateAliasResolver(LicenseDbContext db, IRuntimeEnrollmentCryptoService? migrationCrypto = null) =>
        new(
            db,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
            NullLogger<HardwareAuthorityAliasResolver>.Instance, migrationCrypto);

    /// <summary>Mutates one post-migration graph dimension without creating a replacement seat.</summary>
    private static async Task MutateAliasGraphAsync(PreparedBootstrapScenario scenario, string mutation)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var alias = await db.HardwareAuthorityAliases.SingleAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == alias.RuntimeEnrollmentId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate => candidate.Id == alias.BindingId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == alias.LicenseSeatId);
        switch (mutation)
        {
            case "seat-inactive":
                seat.IsActive = false;
                break;
            case "generation-forward":
                enrollment.SecurityEpoch++;
                enrollment.AuthorityEpoch++;
                break;
            case "security-rollback":
                alias.SecurityEpoch = enrollment.SecurityEpoch + 1;
                break;
            case "authority-rollback":
                alias.AuthorityEpoch = enrollment.AuthorityEpoch + 1;
                break;
            case "enrollment-hash":
                enrollment.HardwareIdHash = Sha256("enrollment-divergence");
                break;
            case "binding-hash":
                binding.HardwareIdHash = Sha256("binding-divergence");
                break;
            case "canonical-hash":
                alias.CanonicalHardwareIdSha256 = Sha256("canonical-divergence");
                break;
            case "enrollment-inactive":
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = DateTime.UtcNow;
                enrollment.InvalidationReason = "test";
                break;
            case "binding-inactive":
                binding.State = "invalidated";
                binding.InvalidatedAtUtc = DateTime.UtcNow;
                binding.InvalidationReason = "test";
                break;
            case "alias-disabled":
                alias.IsActive = false;
                alias.DisabledAtUtc = DateTime.UtcNow;
                alias.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason;
                break;
            default:
                throw new InvalidOperationException("Unknown alias mutation: " + mutation);
        }

        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Delivers the initial license, rewrites fixture identity under the production authority
    /// lease, and activates the Runtime enrollment with its original signed challenge.
    /// </summary>
    private static async Task ActivateCanonicalScenarioAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId)
    {
        await scenario.ConsumeAsync();
        await SetScenarioHardwareAuthorityAsync(scenario, hardwareId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1
        };
        var digest = Sha256("hardware-migration-confirm-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "confirm", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        await scenario.Runtime.ConfirmAsync(
            scenario.EnrollmentId, digest, confirm, proof, IPAddress.Loopback);
    }

    /// <summary>Runs one fresh signed UUID migration from the given source identifier to the UUID identifier.</summary>
    private static Task<RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>> MigrateAsync(
        PreparedBootstrapScenario scenario, string sourceHardwareId)
    {
        var request = MigrationRequest(scenario, sourceHardwareId, StableHardwareId);
        var digest = Sha256("uuid-migration-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        return scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
    }

    /// <summary>
    /// Seeds the state left by the retired disk migration: seat and licence on S, an active L to S alias bound to the
    /// current enrollment and binding, and the binding plus enrollment digest on S (production shape) or still on L.
    /// </summary>
    private static async Task SeedPreUuidStableSeatAsync(PreparedBootstrapScenario scenario, bool bindingCarriesLegacy)
    {
        var authority = new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        seat.HardwareId = PreUuidStableHardwareId;
        license.HardwareId = PreUuidStableHardwareId;
        binding.HardwareIdHash = Sha256(bindingCarriesLegacy ? LegacyHardwareId : PreUuidStableHardwareId);
        enrollment.HardwareIdHash = binding.HardwareIdHash;
        db.HardwareAuthorityAliases.Add(new HardwareAuthorityAlias
        {
            ProductId = license.ProductId,
            LicenseId = license.Id,
            LicenseSeatId = seat.Id,
            RuntimeEnrollmentId = enrollment.Id,
            BindingId = binding.Id,
            MigrationRequestId = Guid.NewGuid(),
            LegacyHardwareIdSha256 = Sha256(LegacyHardwareId),
            CanonicalHardwareIdSha256 = Sha256(PreUuidStableHardwareId),
            SecurityEpoch = enrollment.SecurityEpoch,
            AuthorityEpoch = enrollment.AuthorityEpoch,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1)
        });
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Sets the licence type daily seat-change limit and records prior customer changes today.</summary>
    private static async Task SetScenarioDailySeatChangesAsync(
        PreparedBootstrapScenario scenario, int limit, int priorChangesToday)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.Include(candidate => candidate.Type).SingleAsync();
        license.Type!.MaxActivationsPerDay = limit;
        for (var index = 0; index < priorChangesToday; index++)
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Timestamp = DateTime.UtcNow,
                Action = HistoryActions.UnlinkedApi,
                PerformedBy = "127.0.0.1",
                Details = "prior customer seat change"
            });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Runs a WebSetup reinstall Finalize that submits the UUID identifier and proves it keeps exactly one active seat
    /// on U and one active binding on U superseding the migrated one.
    /// </summary>
    private static async Task AssertUuidReinstallKeepsOneSeatAsync(PreparedBootstrapScenario scenario, string subjectRef)
    {
        await using var resolverDb = await scenario.Factory.CreateDbContextAsync();
        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, StableHardwareId,
            hardwareAuthorityAliases: CreateAliasResolver(resolverDb));

        var finalized = await prepared.Service.FinalizeAsync(
            "website-step1",
            Sha256("uuid-migration-reinstall-" + Guid.NewGuid().ToString("D")),
            prepared.Request);

        Assert.Equal(Sha256(StableHardwareId), finalized.Response.HardwareIdHash);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var license = await check.Licenses.Include(candidate => candidate.Seats)
            .SingleAsync(candidate => candidate.Id == prepared.LicenseId);
        var seat = Assert.Single(license.Seats, candidate => candidate.IsActive);
        Assert.Equal(StableHardwareId, seat.HardwareId);
        var active = Assert.Single(await check.DistributionInstallationBindings.AsNoTracking()
            .Where(candidate => candidate.State == "active").ToListAsync());
        Assert.Equal(Sha256(StableHardwareId), active.HardwareIdHash);
        Assert.Equal(scenario.Fixture.BindingId, active.SupersededBindingId);
    }

    /// <summary>Rebinds the seeded fixture to a canonical 16-character hardware authority.</summary>
    private static async Task SetScenarioHardwareAuthorityAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId)
    {
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(
            db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        seat.HardwareId = hardwareId;
        binding.HardwareIdHash = Sha256(hardwareId);
        enrollment.HardwareIdHash = binding.HardwareIdHash;
        license.HardwareId = hardwareId;
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Adds a competing active seat under the same product and authority lease.</summary>
    private static async Task AddCompetingTargetSeatAsync(PreparedBootstrapScenario scenario)
    {
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        license.MaxSeats = 2;
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = license.Id,
            HardwareId = StableHardwareId,
            IsActive = true
        });
        await db.SaveChangesAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Mutates one authoritative dimension under the production mutation lease.</summary>
    private static async Task MutateScenarioAuthorityAsync(
        PreparedBootstrapScenario scenario,
        string mutation)
    {
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        switch (mutation)
        {
            case "license-revoked":
                license.RevokedAt = DateTime.UtcNow;
                break;
            case "license-expired":
                license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
                break;
            case "seat-inactive":
                seat.IsActive = false;
                break;
            case "binding-subject":
                binding.SubjectRefDigestSha256 = Sha256("different-subject");
                break;
            case "binding-installation":
                binding.InstallationId = Guid.NewGuid().ToString("D");
                break;
            case "enrollment-client":
                enrollment.ClientId = "different-client";
                break;
            case "binding-product":
                var differentProduct = new Product
                {
                    Id = Guid.NewGuid(),
                    Name = "Different migration product " + Guid.NewGuid().ToString("N"),
                    PrivateKeyXml = "test",
                    PublicKeyXml = "test",
                    ApiSecret = Guid.NewGuid().ToString("N")
                };
                db.Products.Add(differentProduct);
                binding.ProductId = differentProduct.Id;
                break;
            default:
                throw new InvalidOperationException("Unknown migration authority mutation: " + mutation);
        }
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Captures one concurrent migration outcome without obscuring its exception.</summary>
    private static async Task<(
        RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>? Result,
        Exception? Error)> CaptureHardwareMigrationAsync(
        Task<RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>> task)
    {
        try
        {
            return (await task, null);
        }
        catch (Exception exception)
        {
            return (null, exception);
        }
    }

    /// <summary>Asserts a refused transition left all linked legacy authority rows untouched.</summary>
    private static async Task AssertLegacyAuthorityUnchangedAsync(PreparedBootstrapScenario scenario)
    {
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var binding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await check.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        Assert.Equal(LegacyHardwareId, seat.HardwareId);
        Assert.Equal(Sha256(LegacyHardwareId), binding.HardwareIdHash);
        Assert.Equal(binding.HardwareIdHash, enrollment.HardwareIdHash);
        Assert.DoesNotContain(await check.LicenseHistories.ToListAsync(), candidate =>
            candidate.Action == "HWID_V2_MIGRATED");
    }
}
