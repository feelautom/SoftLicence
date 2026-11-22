using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-004062: a reinstallation replaces the installed release, so the pre-download decision must not
/// judge the release frozen in the source enrollment against the product minimum or the licence mask.
/// The target release is judged later by Finalize; every other commercial refusal stays in force.
/// </summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed class RuntimeDistributionPreflightSourceVersionPostgreSqlTests(
    RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// Reproduces the refused customer download: an active known enrollment whose frozen release is below the
    /// product minimum (and outside a restrictive licence mask) is accepted, without changing the enrollment.
    /// </summary>
    /// <param name="allowedVersions">Licence mask; the restrictive one is judged on the target at Finalize.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeDistributionPreflightSourceVersionPostgreSqlTests.Tkt4062_KnownEnrollmentBelowMinimum_IsAcceptedForReinstall")]
    [InlineData("*")]
    [InlineData("0.1.*")]
    public async Task Tkt4062_KnownEnrollmentBelowMinimum_IsAcceptedForReinstall(string allowedVersions)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await RaiseMinimumAboveSourceAsync(scenario, allowedVersions);
        var (clientId, request) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        var service = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        RuntimeDistributionPreflightResponse? accepted = null;
        var refusal = await Record.ExceptionAsync(async () => accepted = await service.EvaluateAsync(
            clientId, Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None));

        Assert.True(refusal is null, refusal is DistributionOperationException refused
            ? $"preflight refused: status={refused.StatusCode} error={refused.ErrorCode} reason={refused.ReasonCode}"
            : $"preflight failed: {refusal}");
        Assert.Equal(Sha256(LegacyHardwareId), accepted!.HardwareIdHash);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("known-enrollment", decision.AuthorityMode);
        Assert.Equal("accepted", decision.Outcome);
        var enrollment = await verification.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", enrollment.State);
        Assert.Equal(scenario.Fixture.Version, enrollment.ReleaseVersion);
    }

    /// <summary>
    /// Not judging the source release never relaxes the licence itself: a revoked licence with a source below
    /// the minimum is still refused for its commercial reason, not accepted and not reported as a version issue.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeDistributionPreflightSourceVersionPostgreSqlTests.Tkt4062_RevokedLicenceBelowMinimum_StaysRefused")]
    public async Task Tkt4062_RevokedLicenceBelowMinimum_StaysRefused()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await RaiseMinimumAboveSourceAsync(scenario, "*");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            (await db.Licenses.SingleAsync()).RevokedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }

        // Revocation ends the assignment through the item-2 trigger, so the preflight takes the relink path,
        // which requires hardware evidence exactly like the WebSetup sends it.
        var (clientId, request) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        request.HardwareEvidence = WebSetupEvidence();
        var service = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync(
            clientId, Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None));

        Assert.Equal("not_eligible", refusal.ErrorCode);
        Assert.Equal("commercial_authority_invalid", refusal.ReasonCode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("refused",
            (await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync()).Outcome);
    }

    /// <summary>
    /// Replays the production state of licence ef428ef4 (read on 16/11/2026) through every SoftLicence step of a
    /// WebSetup reinstallation. The modern v3 source (issue_v3 ownership, finalized v3 entitlement, one finalize owner)
    /// stays at the release the 06/11 transition never left: that transition is ISSUED, never consumed and expired,
    /// because the installed update crashed before applying it. The product minimum is now above the source release,
    /// the licence mask is "*" and the licence is still valid. The variant <paramref name="seatReleased"/> adds the
    /// admin unlink done at 16:17:08 UTC (DELETE /api/admin/licenses/{key}/seats/{hwid}), which ends the assignment
    /// with <c>seat_released</c> while the enrollment stays ACTIVE. Expected: discovery finds the modern source, the
    /// preflight accepts (and relinks the released seat on the same machine), the reinstall authority confirms
    /// identity, then the WebSetup Runtime update reserves a transition to the target and the installed target applies
    /// it, as in the production runs of 09/10 and 06/11 (a machine with an active local Runtime is updated, not
    /// finalized as a new installation). Finally, an exact replay of the applied transition is refused once the licence
    /// mask excludes the target the enrollment now runs.
    /// Mapping to the bench: production 2.4.806 / 2.5.0 / 2.7.365 becomes 2.2.979 / 2.2.980 / 2.2.990.
    /// </summary>
    /// <param name="seatReleased">Whether the admin unlink of 16/11 16:17:08 UTC is applied first.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeDistributionPreflightSourceVersionPostgreSqlTests.Tkt4062_ProductionState_ReinstallsThroughEveryStep")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt4062_ProductionState_ReinstallsThroughEveryStep(bool seatReleased)
    {
        const string minimumVersion = "2.2.980";
        const string targetVersion = "2.2.990";
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: PairMachine.Stable);
        await ActivateCanonicalScenarioAsync(scenario, PairMachine.Stable);
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await SeedUnappliedWebSetupTransitionAsync(scenario, "2.2.985");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            (await db.Products.SingleAsync(row => row.Id == scenario.Fixture.ProductId)).MinimumAllowedVersion = minimumVersion;
            var license = await db.Licenses.SingleAsync();
            license.AllowedVersions = "*";
            license.ExpirationDate = DateTime.UtcNow.AddDays(1);
            await db.SaveChangesAsync();
        }

        if (seatReleased)
            await ReleaseSeatThroughAdminApiAsync(scenario, PairMachine.Stable);

        // Step 1, discovery (ResolveReinstallSourceAuthorityAsync).
        var discovery = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync(
            "website-step1", BuildReinstallSourceResolutionRequest(scenario));
        Assert.Equal("source", discovery.Outcome);
        Assert.Equal("modern", discovery.SourceKind);

        // Step 2, preflight before download, exactly as the WebSetup sends it for a known installation.
        var (clientId, preflight) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        preflight.HardwareEvidence = WebSetupEvidence();
        var preflightService = new RuntimeDistributionPreflightService(
            scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        RuntimeDistributionPreflightResponse? accepted = null;
        var preflightRefusal = await Record.ExceptionAsync(async () => accepted = await preflightService.EvaluateAsync(
            clientId, Sha256(JsonSerializer.Serialize(preflight)), preflight, CancellationToken.None));
        // Report the exact public and internal refusal, as recorded in production, when the preflight refuses.
        Assert.True(preflightRefusal is null, preflightRefusal is DistributionOperationException refused
            ? $"preflight refused: status={refused.StatusCode} error={refused.ErrorCode} reason={refused.ReasonCode}"
            : $"preflight failed: {preflightRefusal}");
        Assert.Equal(Sha256(PairMachine.Stable), accepted!.HardwareIdHash);

        // Step 3, reinstall authority (identity of the source installation).
        var identity = await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal("identity_confirmed", identity.Decision);

        // Step 4, a WebSetup run on a machine whose local Runtime is still active is a Runtime update
        // (WebSetup decision active_runtime_update), exactly like the production runs of 09/10 and 06/11:
        // the Website reserves a transition to the downloaded release, then the installed target applies it.
        var targetBinaries = await RegisterTargetReleaseAsync(scenario, targetVersion);
        var issue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            SourceVersion = scenario.Fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = $"TiaConnect-{targetVersion}.msi",
            TargetInstallerSha256 = new string('4', 64)
        };
        var issued = await scenario.Runtime.IssueWebSetupTransitionAsync(
            "website-step1", Sha256(JsonSerializer.Serialize(issue)), issue);

        // Step 5, the installed target release applies the reserved transition (signed by the enrolled key).
        var authorization = new RuntimeWebSetupUpgradeAuthorization
        {
            Schema = RuntimeEnrollmentService.WebSetupUpgradeAuthorizationSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            TransitionId = issued.Response.TransitionId,
            Capability = issued.Response.Capability,
            SourceVersion = scenario.Fixture.Version,
            TargetVersion = targetVersion,
            Binaries = targetBinaries.Select(binary => new RuntimeEnrollmentBinaryEvidenceRequest
            {
                Key = binary.Key,
                Sha256 = binary.Sha256
            }).ToList()
        };
        var authorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
            authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var authorizationDigest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(authorizationBytes));
        var proof = Proof(scenario.EnrollmentKey, "websetup-upgrade", scenario.EnrollmentId,
            RuntimeEnrollmentService.WebSetupUpgradeAudience, "-", authorizationDigest);
        var relay = new RuntimeWebSetupUpgradeRelayRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupUpgradeSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(authorizationBytes),
            ProofTimestamp = proof.Timestamp,
            ProofJti = proof.Jti,
            ProofSignature = proof.Signature
        };
        await scenario.Runtime.UpgradeFromWebSetupAsync(
            "website-step1", "s2s-test", Sha256(JsonSerializer.Serialize(relay)), relay);

        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verification.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", enrollment.State);
        Assert.Equal(targetVersion, enrollment.ReleaseVersion);
        Assert.Equal(targetVersion, (await verification.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId)).Version);
        Assert.Single(await verification.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());

        // Step 6, once applied the enrollment runs the target: an exact replay after the licence mask excludes it
        // stays refused, so the source exemption never re-authorizes a running release the licence now refuses.
        (await verification.Licenses.SingleAsync()).AllowedVersions = "9.*";
        await verification.SaveChangesAsync();
        var replayRefusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.UpgradeFromWebSetupAsync(
                "website-step1", "s2s-test", Sha256(JsonSerializer.Serialize(relay)), relay));
        Assert.Equal("authority_ineligible", replayRefusal.ErrorCode);
        Assert.Equal("version_ineligible", replayRefusal.DiagnosticCode);
    }

    /// <summary>
    /// A Desktop still enrolled below the minimum keeps being refused at startup after the admin unlink: the
    /// released-seat reattachment judges the installed release, and the refusal never invalidates the enrollment.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeDistributionPreflightSourceVersionPostgreSqlTests.Tkt4062_StartupBelowMinimumAfterUnlink_StaysRefusedWithoutInvalidation")]
    public async Task Tkt4062_StartupBelowMinimumAfterUnlink_StaysRefusedWithoutInvalidation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: PairMachine.Stable);
        await ActivateCanonicalScenarioAsync(scenario, PairMachine.Stable);
        await RaiseMinimumAboveSourceAsync(scenario, "*");
        await ReleaseSeatThroughAdminApiAsync(scenario, PairMachine.Stable);
        var request = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var digest = Sha256("tkt4062-startup-" + Guid.NewGuid().ToString("D"));
        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId, digest, request,
            Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId, request.Audience, "-", digest),
            System.Net.IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verification.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", enrollment.State);
        Assert.Null(enrollment.InvalidationReason);
        Assert.Empty(await verification.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// Integrated update (signed upgrade relay) of an installation enrolled below the product minimum, like the seven
    /// production enrollments under 2.5.0. The source release is replaced and is not judged; the target release is:
    /// a target at or above the minimum is applied, a target still below it is refused with <c>version_not_allowed</c>
    /// and changes nothing. After an applied update, an exact replay judges the running target release again and is
    /// refused once the licence mask excludes it. Bench mapping: source 2.2.979, minimum 2.2.980 (or 2.2.985), target
    /// 2.2.990 (or 2.2.984).
    /// </summary>
    /// <param name="minimumVersion">Product minimum placed above the source release.</param>
    /// <param name="targetVersion">Release the integrated update installs.</param>
    /// <param name="expectedRefusal">Expected refusal code, or null when the update must be applied.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeDistributionPreflightSourceVersionPostgreSqlTests.Tkt4062_IntegratedUpgradeFromBelowMinimum_JudgesOnlyTheTarget")]
    [InlineData("2.2.980", "2.2.990", null)]
    [InlineData("2.2.985", "2.2.984", "version_not_allowed")]
    public async Task Tkt4062_IntegratedUpgradeFromBelowMinimum_JudgesOnlyTheTarget(
        string minimumVersion, string targetVersion, string? expectedRefusal)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var targetBinaries = await RegisterTargetReleaseAsync(scenario, targetVersion);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            (await db.Products.SingleAsync(row => row.Id == scenario.Fixture.ProductId)).MinimumAllowedVersion = minimumVersion;
            (await db.Licenses.SingleAsync()).AllowedVersions = "*";
            await db.SaveChangesAsync();
        }

        var receiptId = Guid.NewGuid().ToString("D");
        var authorization = new RuntimeEnrollmentUpgradeAuthorization
        {
            Schema = RuntimeEnrollmentService.UpgradeAuthorizationSchema,
            RequestId = receiptId,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            Epoch = 1,
            SecurityEpoch = 1,
            SourceVersion = scenario.Fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = $"TiaConnect-{targetVersion}.msi",
            TargetInstallerSha256 = new string('4', 64),
            RecoveryReceiptId = receiptId,
            RecoveryReceiptDigestSha256 = new string('5', 64),
            RecoveryHardwareIdHash = new string('9', 64),
            Binaries = targetBinaries.Select(binary => new RuntimeEnrollmentBinaryEvidenceRequest
            {
                Key = binary.Key,
                Sha256 = binary.Sha256
            }).ToList()
        };
        var authorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
            authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var authorizationDigest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(authorizationBytes));
        var proof = Proof(scenario.EnrollmentKey, "upgrade", scenario.EnrollmentId,
            RuntimeEnrollmentService.UpgradeAudience, "-", authorizationDigest);
        var relay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = RuntimeEnrollmentService.UpgradeRelaySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(authorizationBytes),
            ProofTimestamp = proof.Timestamp,
            ProofJti = proof.Jti,
            ProofSignature = proof.Signature
        };

        RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>? upgraded = null;
        var failure = await Record.ExceptionAsync(async () => upgraded = await scenario.Runtime.UpgradeAsync(
            "website-step1", "s2s-test", Sha256(JsonSerializer.Serialize(relay)), relay));

        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verification.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        if (expectedRefusal is null)
        {
            Assert.True(failure is null, failure is RuntimeEnrollmentException refused
                ? $"upgrade refused: status={refused.StatusCode} error={refused.ErrorCode} diagnostic={refused.DiagnosticCode}"
                : $"upgrade failed: {failure}");
            Assert.Equal(targetVersion, upgraded!.Response.TargetVersion);
            Assert.Equal(targetVersion, enrollment.ReleaseVersion);

            // An exact replay runs against the applied target release, which stays judged: once the licence mask
            // excludes it, the replay is refused instead of re-delivering the stored signed upgrade.
            (await verification.Licenses.SingleAsync()).AllowedVersions = "9.*";
            await verification.SaveChangesAsync();
            var replayRefusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.UpgradeAsync(
                "website-step1", "s2s-test", Sha256(JsonSerializer.Serialize(relay)), relay));
            Assert.Equal("authority_ineligible", replayRefusal.ErrorCode);
            Assert.Equal("version_ineligible", replayRefusal.DiagnosticCode);
        }
        else
        {
            var refused = Assert.IsType<RuntimeEnrollmentException>(failure);
            Assert.Equal(expectedRefusal, refused.ErrorCode);
            Assert.Equal(scenario.Fixture.Version, enrollment.ReleaseVersion);
        }

        Assert.Equal("ACTIVE", enrollment.State);
    }

    /// <summary>
    /// The restrictive licence mask is no longer applied to the replaced source release but still protects the target:
    /// issuing a WebSetup transition is accepted when only the target matches the mask (exact version "2.2.990",
    /// source 2.2.979 outside it) and refused with <c>version_not_allowed</c> when the target is outside the mask
    /// ("2.3.*"). This replaces the former preflight variant that refused on the source release mask.
    /// </summary>
    /// <param name="allowedVersions">Licence mask under test.</param>
    /// <param name="expectedRefusal">Expected refusal code, or null when the transition must be issued.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeDistributionPreflightSourceVersionPostgreSqlTests.Tkt4062_RestrictiveMask_IsJudgedOnTheTargetAtTransitionIssue")]
    [InlineData("2.2.990", null)]
    [InlineData("2.3.*", "version_not_allowed")]
    public async Task Tkt4062_RestrictiveMask_IsJudgedOnTheTargetAtTransitionIssue(
        string allowedVersions, string? expectedRefusal)
    {
        const string targetVersion = "2.2.990";
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await RegisterTargetReleaseAsync(scenario, targetVersion);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            (await db.Licenses.SingleAsync()).AllowedVersions = allowedVersions;
            await db.SaveChangesAsync();
        }

        var issue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            SourceVersion = scenario.Fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = $"TiaConnect-{targetVersion}.msi",
            TargetInstallerSha256 = new string('4', 64)
        };
        var failure = await Record.ExceptionAsync(() => scenario.Runtime.IssueWebSetupTransitionAsync(
            "website-step1", Sha256(JsonSerializer.Serialize(issue)), issue));

        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var issuedTransitions = await verification.RuntimeEnrollmentWebSetupTransitions.AsNoTracking().ToListAsync();
        if (expectedRefusal is null)
        {
            Assert.True(failure is null, failure is RuntimeEnrollmentException refused
                ? $"issue refused: status={refused.StatusCode} error={refused.ErrorCode} diagnostic={refused.DiagnosticCode}"
                : $"issue failed: {failure}");
            Assert.Equal(targetVersion, Assert.Single(issuedTransitions).TargetVersion);
        }
        else
        {
            Assert.Equal(expectedRefusal, Assert.IsType<RuntimeEnrollmentException>(failure).ErrorCode);
            Assert.Empty(issuedTransitions);
        }
    }

    /// <summary>Hardware evidence the WebSetup sends for the bench machine whose UUID derives <c>PairMachine.Stable</c>.</summary>
    private static RuntimeDistributionHardwareEvidence WebSetupEvidence() => new()
    {
        SystemUuid = PairMachine.SystemUuid,
        MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680")
    };

    /// <summary>
    /// Inserts the production shape of the 06/11 transition: ISSUED for the active source, never consumed and
    /// expired for ten days. Written with the owner role because the application role cannot forge this ledger.
    /// </summary>
    /// <param name="scenario">Activated scenario whose enrollment is the transition source.</param>
    /// <param name="targetVersion">Release the transition announced and never applied.</param>
    private static async Task SeedUnappliedWebSetupTransitionAsync(PreparedBootstrapScenario scenario, string targetVersion)
    {
        await using var db = await new TestDbFactory(scenario.AdminConnectionString).CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var issuedAt = DateTime.UtcNow.AddDays(-10);
        db.RuntimeEnrollmentWebSetupTransitions.Add(new RuntimeEnrollmentWebSetupTransition
        {
            Id = Guid.NewGuid(),
            ClientId = enrollment.ClientId,
            ProductId = enrollment.ProductId,
            BindingId = enrollment.BindingId,
            EnrollmentId = enrollment.Id,
            InstallationId = enrollment.InstallationId,
            SourceVersion = enrollment.ReleaseVersion,
            TargetVersion = targetVersion,
            TargetInstallerFilename = $"TiaConnect-Setup_v{targetVersion}.msi",
            TargetInstallerSha256 = new string('a', 64),
            CapabilityDigestSha256 = new string('b', 64),
            SourceSecurityEpoch = enrollment.SecurityEpoch,
            AuthorityEpoch = enrollment.AuthorityEpoch,
            State = "ISSUED",
            IssuedAtUtc = issuedAt,
            ExpiresAtUtc = issuedAt.AddMinutes(30)
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Unlinks the seat through the real admin route used in production on 16/11 at 16:17:08 UTC.</summary>
    /// <param name="scenario">Activated scenario.</param>
    /// <param name="hardwareId">Exact seat hardware identifier placed in the route.</param>
    private static async Task ReleaseSeatThroughAdminApiAsync(PreparedBootstrapScenario scenario, string hardwareId)
    {
        string licenseKey;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.SingleAsync();
            license.LicenseKey = license.LicenseKey.ToUpperInvariant();
            licenseKey = license.LicenseKey;
            await db.SaveChangesAsync();
        }

        using var baseFactory = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var web = baseFactory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AdminSettings:ApiSecret", "tkt4062-test-only");
            builder.UseSetting("AdminSettings:AllowedIps", "");
        });
        using var client = web.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt4062-test-only");
        using var response = await client.DeleteAsync($"/api/admin/licenses/{licenseKey}/seats/{hardwareId}");
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("seat_released", (await verification.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId)).EndReason);
        Assert.Equal("ACTIVE", (await verification.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
    }

    /// <summary>
    /// Registers the downloaded target release as an approved baseline with its own fingerprints and returns the
    /// binary evidence a Finalize of that release carries.
    /// </summary>
    /// <param name="scenario">Scenario whose product receives the release.</param>
    /// <param name="version">Target release version.</param>
    /// <returns>The three canonical binary fingerprints of the target release.</returns>
    private static async Task<List<DistributionBinaryEvidence>> RegisterTargetReleaseAsync(
        PreparedBootstrapScenario scenario, string version)
    {
        var artifacts = new List<ApprovedBinaryArtifact>
        {
            new("FP_EXE", Sha256("tkt4062-exe-" + version)),
            new("FP_DLL", Sha256("tkt4062-dll-" + version)),
            new("FP_CORE", Sha256("tkt4062-core-" + version))
        };
        var registration = await new ApprovedBinaryService(scenario.Factory, NullLogger<ApprovedBinaryService>.Instance)
            .RegisterReleaseBaselineAsync(scenario.Fixture.ProductId, version, $"tkt004062-{version}",
                Sha256("tkt4062-manifest-" + version), artifacts);
        Assert.Equal(ApprovedBinaryVerdict.Approved, registration.Result.Verdict);
        return artifacts.Select(artifact => new DistributionBinaryEvidence
        {
            Key = artifact.Key,
            Sha256 = artifact.Sha256
        }).OrderBy(evidence => evidence.Key, StringComparer.Ordinal).ToList();
    }

    /// <summary>Raises the product minimum above the fixture release and sets the licence mask.</summary>
    /// <param name="scenario">Activated scenario whose enrollment keeps the fixture release.</param>
    /// <param name="allowedVersions">Licence version mask to store.</param>
    private static async Task RaiseMinimumAboveSourceAsync(PreparedBootstrapScenario scenario, string allowedVersions)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var product = await db.Products.SingleAsync(candidate => candidate.Id == scenario.Fixture.ProductId);
        product.MinimumAllowedVersion = "9.9.9";
        (await db.Licenses.SingleAsync()).AllowedVersions = allowedVersions;
        await db.SaveChangesAsync();
    }
}
