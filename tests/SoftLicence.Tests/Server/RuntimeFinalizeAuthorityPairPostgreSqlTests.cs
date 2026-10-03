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
/// TKT-001296: the Finalize pair resolver verifies the alias pair in both directions, on real PostgreSQL rows.
/// The distribution preflight no longer recognizes aliases: since TKT-001277 lot 2c it derives the identifier
/// from the system UUID only, so its former alias-recognition tests were removed.
/// </summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Pairs the five-component legacy identity with the canonical identity derived from an accepted system UUID.</summary>
    /// <param name="Cpu">Synthetic CPU evidence used only by the legacy identity.</param>
    /// <param name="Board">Synthetic board evidence used only by the legacy identity.</param>
    /// <param name="Bios">Synthetic BIOS evidence used only by the legacy identity.</param>
    /// <param name="LegacyDisk">Synthetic disk evidence used only by the legacy identity.</param>
    /// <param name="SystemUuid">Accepted UUID supplied to the signed migration request and canonical SDK identity derivation.</param>
    /// <param name="Machine">Synthetic machine name used only by the legacy identity.</param>
    private sealed record PairEvidence(string Cpu, string Board, string Bios, string LegacyDisk, string SystemUuid, string Machine)
    {
        /// <summary>Gets the unchanged legacy five-component hardware identifier.</summary>
        public string Legacy => ServerHardwareId(Cpu, Board, Bios, LegacyDisk, Machine);

        /// <summary>Gets the canonical UUID identifier, failing setup if the synthetic UUID is not accepted.</summary>
        public string Stable => SoftLicence.SDK.MachineIdentity.FromUuid(SystemUuid).HardwareId
            ?? throw new InvalidOperationException("The pair fixture requires an accepted system UUID.");
    }

    /// <summary>Reproduces the legacy SDK identifier without altering any evidence bytes.</summary>
    /// <param name="cpu">Legacy CPU evidence.</param>
    /// <param name="board">Legacy board evidence.</param>
    /// <param name="bios">Legacy BIOS evidence.</param>
    /// <param name="disk">Legacy disk evidence.</param>
    /// <param name="machine">Legacy machine name.</param>
    /// <returns>The first sixteen uppercase hexadecimal characters of the concatenated evidence SHA-256.</returns>
    private static string ServerHardwareId(string cpu, string board, string bios, string disk, string machine) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(cpu + board + bios + disk + machine)))[..16];

    /// <summary>Provides distinct legacy and canonical identities for one synthetic machine.</summary>
    private static readonly PairEvidence PairMachine = new("CPU-PAIR-1", "BOARD-PAIR-1", "BIOS-PAIR-1", "DISK-LEGACY-1", TestSystemUuid, "HOST-PAIR-1");

    /// <summary>Activates the legacy identity and migrates to its UUID identity, asserting the persisted alias pair.</summary>
    /// <param name="scenario">Prepared PostgreSQL scenario whose lifetime remains owned by the caller.</param>
    /// <param name="machine">Legacy evidence and accepted target UUID for the signed migration.</param>
    /// <returns>The binding product, licence, grant digest and entitlement client used by the pair resolver.</returns>
    /// <remarks>Requires distinct identities and writes activation, migration and alias state through production services.</remarks>
    private static async Task<(Guid ProductId, Guid LicenseId, string GrantRefDigest, string ClientId)> MigrateScenarioToPairAsync(
        PreparedBootstrapScenario scenario, PairEvidence machine)
    {
        Assert.NotEqual(machine.Legacy, machine.Stable);
        await ActivateCanonicalScenarioAsync(scenario, machine.Legacy);
        var request = MigrationRequest(scenario, machine.Legacy, machine.Stable);
        request.SystemUuid = machine.SystemUuid;
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
        // A different CPU alone cannot change the UUID-derived canonical identity.
        var stranger = PairMachine with { SystemUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E33" };
        Assert.NotEqual(PairMachine.Stable, stranger.Stable);
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

    /// <summary>
    /// Proves authenticated alias history never substitutes for the current assignment relation or its
    /// exact seat hardware. Every mutation leaves the alias intact while current B rejects the old pair.
    /// </summary>
    [Theory]
    [InlineData("ended")]
    [InlineData("quarantined")]
    [InlineData("seat")]
    [InlineData("license")]
    [InlineData("hardware")]
    public async Task FinalizeAuthorityPair_AliasWithChangedCurrentAssignment_IsCommerciallyRefused(
        string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) =
            await MigrateScenarioToPairAsync(scenario, PairMachine);
        await MutateCurrentPairAssignmentAsync(scenario, mutation);

        var response = await PairResolver(scenario).ResolveAsync(
            clientId, Sha256("pair-current-assignment-" + mutation),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy,
                Sha256(PairMachine.Stable)), CancellationToken.None);

        Assert.Equal("refused", response.Outcome);
        try
        {
            Assert.Equal(
                mutation == "hardware" ? HardwareAuthorityRefusalReason.AuthorityGraphDiverged.ToString()
                    : "commercial_authority_invalid",
                response.RefusalReason);
        }
        catch (Xunit.Sdk.XunitException assertion)
        {
            await using var observed = await scenario.Factory.CreateDbContextAsync();
            var enrollment = await observed.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            var binding = await observed.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            var assignments = await observed.EnrollmentLicenseAssignments.Where(row => row.EnrollmentId == enrollment.Id)
                .OrderBy(row => row.Revision).Select(row => new { row.State, row.EndReason }).ToListAsync();
            throw new InvalidOperationException(
                $"Pair diagnostic {mutation}: enrollment={enrollment.State}; binding={binding.State}; "
                + $"protocol={enrollment.ProtocolVersion == RuntimeEnrollmentService.ProtocolVersion}; epoch={enrollment.Epoch}; "
                + $"handoff={enrollment.HandoffDigestSha256 == binding.HandoffDigestSha256}; "
                + $"subject={enrollment.SubjectRefDigestSha256 == binding.SubjectRefDigestSha256}; "
                + $"version={enrollment.ReleaseVersion == binding.Version}; "
                + $"assignments={System.Text.Json.JsonSerializer.Serialize(assignments)}", assertion);
        }
        Assert.Null(response.CanonicalEffectiveHardwareIdHash);
    }

    /// <summary>Proves changed commercial assignment never hides a corrupted historical graph or an unproved opposite digest.</summary>
    [Theory]
    [InlineData("seat", "hardware")]
    [InlineData("license", "hardware")]
    [InlineData("seat", "binding-digest")]
    [InlineData("license", "binding-digest")]
    [InlineData("seat", "expected-digest")]
    [InlineData("license", "expected-digest")]
    public async Task FinalizeAuthorityPair_ChangedAssignmentWithStructuralDivergence_KeepsStructuralRefusal(
        string mutation, string corruption)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) =
            await MigrateScenarioToPairAsync(scenario, PairMachine);
        await MutateCurrentPairAssignmentAsync(scenario, mutation);
        var expectedDigest = Sha256(PairMachine.Stable);
        await using (var db = await new TestDbFactory(scenario.AdminConnectionString).CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            switch (corruption)
            {
                case "hardware":
                    var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
                    seat.HardwareId = "1111222233334444";
                    break;
                case "binding-digest":
                    binding.HardwareIdHash = new string('f', 64);
                    break;
                case "expected-digest":
                    expectedDigest = new string('e', 64);
                    break;
                default:
                    throw new InvalidOperationException("Unknown structural corruption.");
            }
            await db.SaveChangesAsync();
        }
        var response = await PairResolver(scenario).ResolveAsync(
            clientId, Sha256("pair-mixed-" + mutation + "-" + corruption),
            PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy, expectedDigest), CancellationToken.None);
        Assert.Equal("refused", response.Outcome);
        Assert.Equal(HardwareAuthorityRefusalReason.AuthorityGraphDiverged.ToString(), response.RefusalReason);
        Assert.Null(response.CanonicalEffectiveHardwareIdHash);
    }

    /// <summary>Proves an admissible second terminal enrollment on the historical binding stays infrastructure-ambiguous.</summary>
    [Fact]
    public async Task FinalizeAuthorityPair_AliasWithAmbiguousBindingEnrollments_IsUnavailable()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var (productId, licenseId, grantRefDigest, clientId) =
            await MigrateScenarioToPairAsync(scenario, PairMachine);
        var admin = new TestDbFactory(scenario.AdminConnectionString);
        await using (var db = await admin.CreateDbContextAsync())
        {
            var original = await db.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var duplicate = (RuntimeEnrollment)db.Entry(original).CurrentValues.ToObject();
            duplicate.Id = Guid.NewGuid();
            duplicate.InstallationId = Guid.NewGuid().ToString("D");
            duplicate.KeyThumbprint = Convert.ToBase64String(SHA256.HashData(Guid.NewGuid().ToByteArray()))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            duplicate.State = "INVALIDATED";
            duplicate.InvalidatedAtUtc = DateTime.UtcNow;
            duplicate.InvalidationReason = "test_alias_enrollment_ambiguity";
            db.RuntimeEnrollments.Add(duplicate);
            await db.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            PairResolver(scenario).ResolveAsync(
                clientId, Sha256("pair-ambiguous-enrollment"),
                PairRequest(productId, licenseId, grantRefDigest, PairMachine.Legacy,
                    Sha256(PairMachine.Stable)), CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, exception.StatusCode);
        Assert.Equal("authority_unavailable", exception.ErrorCode);
        Assert.Equal("assignment_enrollment_ambiguous", exception.ReasonCode);
    }

    /// <summary>Mutates only current commercial authority while preserving the authenticated alias row.</summary>
    private static async Task MutateCurrentPairAssignmentAsync(
        PreparedBootstrapScenario scenario,
        string mutation)
    {
        var admin = new TestDbFactory(scenario.AdminConnectionString);
        await using var db = await admin.CreateDbContextAsync();
        var assignment = await db.EnrollmentLicenseAssignments.SingleAsync(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == assignment.LicenseSeatId);
        switch (mutation)
        {
            case "ended":
            case "quarantined":
                assignment.State = "ENDED";
                assignment.EndedAtUtc = DateTime.UtcNow;
                assignment.EndReason = "test_current_authority_removed";
                if (mutation == "quarantined")
                    db.EnrollmentLicenseAssignmentQuarantines.Add(new EnrollmentLicenseAssignmentQuarantine
                    {
                        EnrollmentId = scenario.EnrollmentId,
                        BindingId = scenario.Fixture.BindingId,
                        LicenseId = assignment.LicenseId,
                        LicenseSeatId = assignment.LicenseSeatId,
                        Reason = "live_state_mismatch",
                        ObservedAtUtc = DateTime.UtcNow
                    });
                break;
            case "hardware":
                seat.HardwareId = "1111222233334444";
                break;
            case "seat":
            case "license":
                assignment.State = "ENDED";
                assignment.EndedAtUtc = DateTime.UtcNow;
                assignment.EndReason = "test_current_authority_reassigned";
                seat.IsActive = false;
                seat.UnlinkedAt = DateTime.UtcNow;
                // Complete release before inserting the successor assignment. Otherwise the
                // seat trigger can end the newly inserted row in the same EF save batch.
                await db.SaveChangesAsync();
                var targetLicenseId = assignment.LicenseId;
                if (mutation == "license")
                {
                    var sourceLicense = await db.Licenses.AsNoTracking()
                        .SingleAsync(row => row.Id == assignment.LicenseId);
                    targetLicenseId = Guid.NewGuid();
                    db.Licenses.Add(new License
                    {
                        Id = targetLicenseId,
                        ProductId = sourceLicense.ProductId,
                        LicenseTypeId = sourceLicense.LicenseTypeId,
                        LicenseKey = "PAIR-CHANGED-" + Guid.NewGuid().ToString("N"),
                        IsActive = true,
                        MaxSeats = 1,
                        AllowedVersions = sourceLicense.AllowedVersions
                    });
                }
                var targetSeat = new LicenseSeat
                {
                    LicenseId = targetLicenseId,
                    HardwareId = PairMachine.Stable,
                    IsActive = true
                };
                db.LicenseSeats.Add(targetSeat);
                db.EnrollmentLicenseAssignments.Add(new EnrollmentLicenseAssignment
                {
                    EnrollmentId = scenario.EnrollmentId,
                    LicenseId = targetLicenseId,
                    LicenseSeatId = targetSeat.Id,
                    State = "ACTIVE",
                    ActivatedAtUtc = DateTime.UtcNow,
                    Revision = assignment.Revision + 1
                });
                break;
            default:
                throw new InvalidOperationException("Unknown assignment mutation: " + mutation);
        }
        await db.SaveChangesAsync();
        if (mutation is "seat" or "license")
        {
            var current = await db.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(row =>
                row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            Assert.NotEqual(seat.Id, current.LicenseSeatId);
            Assert.Equal(mutation == "license", current.LicenseId != assignment.LicenseId);
        }
    }
}
