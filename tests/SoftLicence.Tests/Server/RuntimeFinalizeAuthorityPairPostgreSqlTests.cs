using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001296: the distribution preflight recognizes a migrated machine through its authenticated alias and
/// the Finalize pair resolver verifies the same alias pair in both directions, on real PostgreSQL rows.
/// </summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    private sealed record PairEvidence(string Cpu, string Board, string Bios, string LegacyDisk, string StableDisk, string Machine)
    {
        public string Legacy => ServerHardwareId(Cpu, Board, Bios, LegacyDisk, Machine);
        public string Stable => ServerHardwareId(Cpu, Board, Bios, StableDisk, Machine);
        public RuntimeDistributionHardwareEvidence ToRequest() => new()
        {
            CpuId = Cpu, MotherboardId = Board, BiosId = Bios, LegacyDiskId = LegacyDisk, StableDiskId = StableDisk, MachineName = Machine
        };
    }

    /// <summary>Mirrors the SDK five-component algorithm the server applies to raw evidence.</summary>
    private static string ServerHardwareId(string cpu, string board, string bios, string disk, string machine) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(cpu + board + bios + disk + machine)))[..16];

    private static readonly PairEvidence PairMachine = new("CPU-PAIR-1", "BOARD-PAIR-1", "BIOS-PAIR-1", "DISK-LEGACY-1", "DISK-STABLE-1", "HOST-PAIR-1");

    /// <summary>Activates the scenario on the legacy identity, then migrates it to the stable identity, which creates the alias.</summary>
    private static async Task<(Guid ProductId, Guid LicenseId, string GrantRefDigest, string ClientId)> MigrateScenarioToPairAsync(
        PreparedBootstrapScenario scenario, PairEvidence machine)
    {
        await ActivateCanonicalScenarioAsync(scenario, machine.Legacy);
        var request = MigrationRequest(scenario, machine.Legacy, machine.Stable);
        var digest = Sha256("hardware-pair-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == binding.EntitlementId);
        var alias = await db.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
        Assert.Equal(Sha256(machine.Legacy), alias.LegacyHardwareIdSha256);
        Assert.Equal(Sha256(machine.Stable), alias.CanonicalHardwareIdSha256);
        return (binding.ProductId, binding.LicenseId, binding.GrantRefDigestSha256, entitlement.ClientId);
    }

    private static RuntimeDistributionPreflightRequest PreflightRequest(
        Guid productId, Guid licenseId, string grantRefDigest, PairEvidence machine) => new()
    {
        Schema = "runtime-distribution-hardware-authority",
        RequestId = Guid.NewGuid().ToString("D"),
        ProductId = productId.ToString("D"),
        SoftLicenceLicenseId = licenseId.ToString("D"),
        GrantRefDigestSha256 = grantRefDigest,
        InstallationId = Guid.NewGuid().ToString("D"),
        // Base64url SHA-256 thumbprint shape (43 characters), never a real key: the installation is unknown on purpose.
        KeyThumbprint = Convert.ToBase64String(SHA256.HashData(Guid.NewGuid().ToByteArray())).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
        HardwareEvidence = machine.ToRequest()
    };

    [Fact]
    public async Task DistributionPreflight_RecognizesMigratedMachineThroughAliasAndChoosesStableDigest()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) = await MigrateScenarioToPairAsync(scenario, PairMachine);
        var service = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        var recognized = await service.EvaluateAsync(
            clientId, Sha256("payload-recognized"), PreflightRequest(productId, licenseId, grantRefDigest, PairMachine), CancellationToken.None);

        Assert.Equal("accepted", recognized.Decision);
        Assert.Equal("alias-recognized", recognized.AuthorityMode);
        Assert.Equal(Sha256(PairMachine.Stable), recognized.HardwareIdHash);

        // Another machine of the same licence has no alias: the historical legacy choice is unchanged.
        var stranger = PairMachine with { Cpu = "CPU-STRANGER", Board = "BOARD-STRANGER" };
        var unchanged = await service.EvaluateAsync(
            clientId, Sha256("payload-stranger"), PreflightRequest(productId, licenseId, grantRefDigest, stranger), CancellationToken.None);
        Assert.Equal(Sha256(stranger.Legacy), unchanged.HardwareIdHash);
        Assert.Equal("server-derived", unchanged.AuthorityMode);
    }

    [Fact]
    public async Task DistributionPreflight_DisabledAliasKeepsLegacyWithoutRefusing()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) = await MigrateScenarioToPairAsync(scenario, PairMachine);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await db.HardwareAuthorityAliases.SingleAsync();
            alias.IsActive = false;
            alias.DisabledAtUtc = DateTime.UtcNow;
            alias.DisabledReason = "operator_disabled";
            await db.SaveChangesAsync();
        }
        var service = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        var response = await service.EvaluateAsync(
            clientId, Sha256("payload-disabled"), PreflightRequest(productId, licenseId, grantRefDigest, PairMachine), CancellationToken.None);

        // Compatibility refusals never block a client that is tolerated today: legacy is kept, only diagnosed.
        Assert.Equal("accepted", response.Decision);
        Assert.Equal(Sha256(PairMachine.Legacy), response.HardwareIdHash);
        Assert.Equal("server-derived", response.AuthorityMode);
    }

    /// <summary>An inactive backfill alias is tolerated by Finalize only; at preflight it stays legacy plus diagnostic.</summary>
    [Fact]
    public async Task DistributionPreflight_InactiveBackfillAliasKeepsLegacy()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) = await MigrateScenarioToPairAsync(scenario, PairMachine);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await db.HardwareAuthorityAliases.SingleAsync();
            alias.IsActive = false;
            alias.DisabledAtUtc = DateTime.UtcNow;
            alias.DisabledReason = HardwareAuthorityAlias.BackfillAuthorityInvalidReason;
            alias.MigrationRequestId = null;
            await db.SaveChangesAsync();
        }
        var service = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        var response = await service.EvaluateAsync(
            clientId, Sha256("payload-backfill"), PreflightRequest(productId, licenseId, grantRefDigest, PairMachine), CancellationToken.None);

        Assert.Equal("accepted", response.Decision);
        Assert.Equal("server-derived", response.AuthorityMode);
        Assert.Equal(Sha256(PairMachine.Legacy), response.HardwareIdHash);
    }

    [Fact]
    public async Task DistributionPreflight_BanOnStableCandidateStillRefusesRecognizedMachine()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) = await MigrateScenarioToPairAsync(scenario, PairMachine);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = PairMachine.Stable, ProductId = productId, Reason = "pair-test", IsActive = true,
                BanCategory = BannedHardwareId.Categories.Manual
            });
            await db.SaveChangesAsync();
        }
        var service = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync(
            clientId, Sha256("payload-banned"), PreflightRequest(productId, licenseId, grantRefDigest, PairMachine), CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
    }

    private static FinalizeAuthorityPairResolver PairResolver(PreparedBootstrapScenario scenario) => new(
        scenario.Factory,
        Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
        NullLoggerFactory.Instance,
        NullLogger<FinalizeAuthorityPairResolver>.Instance);

    private static FinalizeAuthorityPairRequest PairRequest(
        Guid productId, Guid licenseId, string grantRefDigest, string submitted, string expectedHash) => new()
    {
        Schema = FinalizeAuthorityPairResolver.RequestSchema,
        RequestId = Guid.NewGuid().ToString("D"),
        ProductId = productId.ToString("D"),
        SoftLicenceLicenseId = licenseId.ToString("D"),
        GrantRefDigestSha256 = grantRefDigest,
        SubmittedHardwareId = submitted,
        ExpectedHardwareIdHash = expectedHash
    };

    /// <summary>Server authority (canonical stable) and client-presented identity are asserted separately in both directions.</summary>
    [Fact]
    public async Task FinalizeAuthorityPair_ResolvesDirectAndBothAliasDirectionsOnCanonicalStable()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) = await MigrateScenarioToPairAsync(scenario, PairMachine);
        var resolver = PairResolver(scenario);
        var stableHash = Sha256(PairMachine.Stable);
        var legacyHash = Sha256(PairMachine.Legacy);

        // Grant froze the canonical stable digest, Desktop without marker presents legacy.
        var legacySubmitted = await resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy, stableHash), CancellationToken.None);
        Assert.Equal("alias-matched", legacySubmitted.Outcome);
        Assert.Equal("stable-expected-legacy-submitted", legacySubmitted.PairMatchedDirection);
        Assert.Equal(legacyHash, legacySubmitted.SubmittedHardwareIdHash);
        Assert.Equal(stableHash, legacySubmitted.GrantExpectedHardwareIdHash);
        Assert.Equal(stableHash, legacySubmitted.CanonicalEffectiveHardwareIdHash);
        Assert.Equal(productId, legacySubmitted.ProductId);
        Assert.Equal(licenseId, legacySubmitted.LicenseId);
        Assert.NotNull(legacySubmitted.EntitlementId);
        Assert.Equal(grantRefDigest, legacySubmitted.GrantRefDigestSha256);
        Assert.NotNull(legacySubmitted.AliasId);
        Assert.Equal(scenario.Fixture.BindingId, legacySubmitted.BindingId);

        // Grant in flight froze the legacy digest, Desktop that kept its stable marker presents stable.
        var stableSubmitted = await resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Stable, legacyHash), CancellationToken.None);
        Assert.Equal("alias-matched", stableSubmitted.Outcome);
        Assert.Equal("legacy-expected-stable-submitted", stableSubmitted.PairMatchedDirection);
        Assert.Equal(stableHash, stableSubmitted.SubmittedHardwareIdHash);
        Assert.Equal(legacyHash, stableSubmitted.GrantExpectedHardwareIdHash);
        Assert.Equal(stableHash, stableSubmitted.CanonicalEffectiveHardwareIdHash);
        Assert.Equal(legacySubmitted.AliasId, stableSubmitted.AliasId);

        // Direct equality needs no alias.
        var direct = await resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Stable, stableHash), CancellationToken.None);
        Assert.Equal("matched", direct.Outcome);
        Assert.Equal("direct", direct.PairMatchedDirection);
        Assert.Equal(stableHash, direct.CanonicalEffectiveHardwareIdHash);
        Assert.Null(direct.AliasId);

        // A third identity of the same licence is a mismatch, never a guessed match.
        var stranger = PairMachine with { Cpu = "CPU-STRANGER" };
        var mismatch = await resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, stranger.Stable, stableHash), CancellationToken.None);
        Assert.Equal("mismatch", mismatch.Outcome);
        Assert.Equal("none", mismatch.PairMatchedDirection);
        Assert.Null(mismatch.CanonicalEffectiveHardwareIdHash);

        // Identical inputs (same requestId, same payload) answer identically: the resolution is deterministic
        // and writes nothing; the durable idempotent record lives on the Website grant after a successful Finalize.
        var replayRequest = PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy, stableHash);
        var first = await resolver.ResolveAsync(clientId, Sha256("pair-payload-replay"), replayRequest, CancellationToken.None);
        var replay = await resolver.ResolveAsync(clientId, Sha256("pair-payload-replay"), replayRequest, CancellationToken.None);
        Assert.Equal(first, replay);
        Assert.Equal(Sha256("pair-payload-replay"), replay.PayloadDigestSha256);
        // A divergent payload under the same requestId is visibly bound to its own digest.
        var divergent = await resolver.ResolveAsync(clientId, Sha256("pair-payload-divergent"), replayRequest, CancellationToken.None);
        Assert.NotEqual(first.PayloadDigestSha256, divergent.PayloadDigestSha256);
    }

    [Fact]
    public async Task FinalizeAuthorityPair_ConcurrentBanOrRevocationWins()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) = await MigrateScenarioToPairAsync(scenario, PairMachine);
        var resolver = PairResolver(scenario);
        var stableHash = Sha256(PairMachine.Stable);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = PairMachine.Stable, ProductId = productId, Reason = "pair-test", IsActive = true,
                BanCategory = BannedHardwareId.Categories.Manual
            });
            await db.SaveChangesAsync();
        }
        var banned = await resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy, stableHash), CancellationToken.None);
        Assert.Equal("refused", banned.Outcome);
        Assert.Equal("hardware_banned", banned.RefusalReason);
        Assert.Null(banned.CanonicalEffectiveHardwareIdHash);

        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var ban = await db.BannedHardwareIds.SingleAsync(candidate => candidate.HardwareId == PairMachine.Stable);
            ban.IsActive = false;
            var license = await db.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.RevokedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        var revoked = await resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy, stableHash), CancellationToken.None);
        Assert.Equal("refused", revoked.Outcome);
        Assert.Equal("commercial_authority_invalid", revoked.RefusalReason);

        var malformed = await Assert.ThrowsAsync<DistributionOperationException>(() => resolver.ResolveAsync(clientId, Sha256("pair-payload"),
            PairRequest(productId, licenseId, grantRefDigest, "not-a-hardware-id", stableHash), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, malformed.StatusCode);
    }
}
