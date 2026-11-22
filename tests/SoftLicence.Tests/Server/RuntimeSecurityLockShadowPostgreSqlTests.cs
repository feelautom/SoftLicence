using System.Net;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>Creates the authenticated service used by the bounded SHADOW scenarios.</summary>
    protected static RuntimeEnrollmentService CreateTkt001802Runtime(
        PreparedBootstrapScenario scenario,
        RSA acknowledgementKey,
        RuntimeEnrollmentCryptoService crypto,
        IDbContextFactory<LicenseDbContext>? factory = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = acknowledgementKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var effectiveFactory = factory ?? scenario.Factory;
        return new RuntimeEnrollmentService(
            effectiveFactory,
            new RuntimeEnrollmentAuthorityService(effectiveFactory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(effectiveFactory, Options.Create(scenario.Options)),
            crypto,
            Options.Create(scenario.Options),
            new CanaryAckService(effectiveFactory, configuration, TimeProvider.System));
    }

    /// <summary>
    /// Creates an activated, verified enrollment without seeding a lock or critical incident, so each SHADOW
    /// scenario asserts only evidence created by the operation under test.
    /// </summary>
    protected static async Task<(PreparedBootstrapScenario Scenario, SecurityLockAdminService Admin)>
        PrepareTkt001802ScenarioAsync()
    {
        var scenario = await CreatePreparedBootstrapScenarioAsync();
        try
        {
            await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
            return (scenario, new SecurityLockAdminService(
                scenario.Factory,
                new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options))));
        }
        catch
        {
            scenario.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Expires the active assignment license and adds the requested independent ban. Fresh canonical hardware
    /// isolates component rows from product-scoped hardware bans retained by earlier PostgreSQL theory cases.
    /// </summary>
    /// <returns>The exact hardware value the authenticated Canary must report.</returns>
    protected static async Task<string> ApplyCommercialDenialAndBanAsync(
        PreparedBootstrapScenario scenario,
        string banKind)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var assignment = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var license = await db.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == assignment.LicenseSeatId);
        license.ExpirationDate = DateTime.UtcNow.AddDays(-1);

        if (string.Equals(banKind, "canonical-hardware", StringComparison.Ordinal))
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                ProductId = scenario.Fixture.ProductId,
                HardwareId = seat.HardwareId,
                Reason = "TKT-001802 commercial-denial canonical priority proof",
                BanCategory = BannedHardwareId.Categories.Debugger,
                IsActive = true
            });
            await db.SaveChangesAsync();
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        }

        if (string.Equals(banKind, "reported-hardware", StringComparison.Ordinal))
        {
            var reportedHardwareId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                ProductId = scenario.Fixture.ProductId,
                HardwareId = reportedHardwareId,
                Reason = "TKT-001802 commercial-denial reported priority proof",
                BanCategory = BannedHardwareId.Categories.Debugger,
                IsActive = true
            });
            await db.SaveChangesAsync();
            return reportedHardwareId;
        }

        if (!string.Equals(banKind, "component", StringComparison.Ordinal))
            throw new ArgumentOutOfRangeException(nameof(banKind), banKind, "Unknown ban fixture kind.");

        var freshHardwareId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        seat.HardwareId = freshHardwareId;
        var component = await db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == scenario.Fixture.ProductId
                && row.Version == scenario.Fixture.Version)
            .Select(row => new { row.Key, row.Hash })
            .FirstAsync();
        db.BannedComponents.Add(new BannedComponent
        {
            ProductId = scenario.Fixture.ProductId,
            ComponentType = component.Key,
            ComponentHash = component.Hash,
            Reason = "TKT-001802 commercial-denial component priority proof",
            IsActive = true
        });
        await db.SaveChangesAsync();
        return freshHardwareId;
    }

    /// <summary>Builds one canonical authenticated Canary request.</summary>
    protected static CanaryPingRequest Tkt001802Canary(
        PreparedBootstrapScenario scenario,
        string trigger,
        int severity) => new()
    {
        Schema = CanaryAckService.Schema,
        EventId = Guid.NewGuid().ToString("D"),
        SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
        HardwareId = LegacyHardwareId,
        AppVersion = scenario.Fixture.Version,
        Trigger = trigger,
        Severity = severity
    };

    /// <summary>Sends one canonical Canary with a fresh digest and proof.</summary>
    protected static async Task SendTkt001802CanaryAsync(
        RuntimeEnrollmentService runtime,
        PreparedBootstrapScenario scenario,
        CanaryPingRequest canary,
        string suffix)
    {
        var digest = Sha256("tkt001802-" + suffix + "-" + Guid.NewGuid().ToString("D"));
        var result = await runtime.ProcessCanaryAsync(
            scenario.EnrollmentId, digest, canary,
            CanaryProof(scenario.EnrollmentKey, scenario.EnrollmentId, canary.EventId!, digest,
                scenario.Options), IPAddress.Loopback);
        Assert.Equal("ack", result.Response.Decision);
    }

    /// <summary>Proves a non-blocking incident does not become a capability barrier.</summary>
    protected static async Task AssertTkt001802CapabilityAvailableAsync(
        RuntimeEnrollmentService runtime,
        PreparedBootstrapScenario scenario,
        string suffix)
    {
        var securityEpoch = await ReadSecurityEpochAsync(scenario);
        var request = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = securityEpoch,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var digest = Sha256("tkt001802-capability-" + suffix + "-" + Guid.NewGuid().ToString("D"));
        var issued = await runtime.CreateCapabilityAsync(
            scenario.EnrollmentId,
            digest,
            request,
            Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId, request.Audience, "-", digest),
            IPAddress.Loopback);
        Assert.NotNull(issued.Response.CapabilityToken);
    }
}

/// <summary>Runs the tests from RuntimeSecurityLockShadowPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeSecurityLockShadowPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// TKT-001802 regression: SHADOW already releases and alerts a lock; the same effective mode must also preserve
    /// mapped Canary evidence as a non-blocking incident without advancing the security generation.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_ShadowMode_ReleasesLockAndWaivesMappedCanaryWhileAlerting")]
    public async Task Tkt001802_ShadowMode_ReleasesLockAndWaivesMappedCanaryWhileAlerting()
    {
        var prepared = await PrepareTkt001802ScenarioAsync();
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "alice"));
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger", "RuntimeCheck_NativeDllSwapped"];
        var initialEpoch = await ReadSecurityEpochAsync(scenario);
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var shadowLock = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", 'e');
        var lockDigest = Sha256("tkt001802-shadow-lock-" + Guid.NewGuid().ToString("D"));
        var lockVerdict = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, lockDigest, shadowLock, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, shadowLock.ReportId!, lockDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, lockVerdict.Response.Verdict);
        var canary = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        var canaryDigest = Sha256("tkt001802-shadow-canary-" + Guid.NewGuid().ToString("D"));
        var acknowledgement = await runtime.ProcessCanaryAsync(scenario.EnrollmentId, canaryDigest, canary, CanaryProof(scenario.EnrollmentKey, scenario.EnrollmentId, canary.EventId!, canaryDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal("ack", acknowledgement.Response.Decision);
        await AssertTkt001802CapabilityAvailableAsync(runtime, scenario, "shadow");
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var lockRow = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == shadowLock.LockId);
        Assert.Equal(SecurityLockReportStates.Released, lockRow.State);
        Assert.Equal(SecurityLockCauseCatalog.ModeShadow, lockRow.EffectiveMode);
        Assert.Null(lockRow.RememberedReleaseDecisionId);
        Assert.True(await check.SecurityLockAlertDeliveries.AsNoTracking().AnyAsync(delivery => delivery.SecurityLockReportId == lockRow.Id && delivery.Trigger == NotificationService.Triggers.SecurityLockReported));
        var incident = await check.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == canary.EventId);
        Assert.Equal("WAIVED", incident.State);
        Assert.Equal("MODE_SHADOW", incident.NonBlockingReason);
        Assert.Null(incident.RememberedReleaseDecisionId);
        Assert.False(await check.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(row => row.State == "OPEN"));
        Assert.Empty(await check.RuntimeCriticalRecoveries.AsNoTracking().ToListAsync());
        Assert.Empty(await check.SecurityLockReleaseDecisions.AsNoTracking().ToListAsync());
        Assert.Equal("mode_shadow:non_blocking", (await check.CanaryAlerts.AsNoTracking().SingleAsync(row => row.Trigger == "RuntimeCheck_Debugger")).Details);
        Assert.Equal(initialEpoch, await ReadSecurityEpochAsync(scenario));
    }

    /// <summary>Mode changes are prospective and an unmapped Canary trigger remains blocking.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_ShadowMode_IsProspectiveAndDoesNotWaiveUnmappedCanary")]
    public async Task Tkt001802_ShadowMode_IsProspectiveAndDoesNotWaiveUnmappedCanary()
    {
        var prepared = await PrepareTkt001802ScenarioAsync();
        using var scenario = prepared.Scenario;
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger", "RuntimeCheck_NativeDllSwapped"];
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "alice"));
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var unmapped = Tkt001802Canary(scenario, "RuntimeCheck_NativeDllSwapped", 3);
        await SendTkt001802CanaryAsync(runtime, scenario, unmapped, "unmapped");
        var mappedShadow = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        await SendTkt001802CanaryAsync(runtime, scenario, mappedShadow, "mapped-shadow");
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "REVIEW", "alice"));
        var mappedReview = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        await SendTkt001802CanaryAsync(runtime, scenario, mappedReview, "mapped-review");
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "alice"));
        await using (var ban = await scenario.Factory.CreateDbContextAsync())
        {
            ban.BannedHardwareIds.Add(new BannedHardwareId { ProductId = scenario.Fixture.ProductId, HardwareId = LegacyHardwareId, Reason = "TKT-001802 priority proof", BanCategory = BannedHardwareId.Categories.Debugger, IsActive = true });
            await ban.SaveChangesAsync();
        }

        var mappedBanned = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        mappedBanned.HardwareId = "FFFFFFFFFFFFFFFF";
        await SendTkt001802CanaryAsync(runtime, scenario, mappedBanned, "mapped-banned");
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var incidents = await check.RuntimeCriticalIncidents.AsNoTracking().OrderBy(row => row.OpenedAtUtc).ToListAsync();
        Assert.Equal(4, incidents.Count);
        Assert.Equal("OPEN", incidents.Single(row => row.EventId == unmapped.EventId).State);
        Assert.Equal("WAIVED", incidents.Single(row => row.EventId == mappedShadow.EventId).State);
        Assert.Equal("MODE_SHADOW", incidents.Single(row => row.EventId == mappedShadow.EventId).NonBlockingReason);
        Assert.Equal("OPEN", incidents.Single(row => row.EventId == mappedReview.EventId).State);
        Assert.Null(incidents.Single(row => row.EventId == mappedReview.EventId).NonBlockingReason);
        Assert.Equal("OPEN", incidents.Single(row => row.EventId == mappedBanned.EventId).State);
        Assert.Null(incidents.Single(row => row.EventId == mappedBanned.EventId).NonBlockingReason);
        Assert.Equal("hardware_banned:blocking", (await check.CanaryAlerts.AsNoTracking().SingleAsync(row => row.Trigger == "RuntimeCheck_Debugger" && row.Details == "hardware_banned:blocking")).Details);
        Assert.Empty(await check.RuntimeCriticalRecoveries.AsNoTracking().ToListAsync());
    }

    /// <summary>A live approved-binary component ban remains blocking even when the mapped cause is SHADOW.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_ShadowMode_ComponentBanStaysBlocking")]
    public async Task Tkt001802_ShadowMode_ComponentBanStaysBlocking()
    {
        var prepared = await PrepareTkt001802ScenarioAsync();
        using var scenario = prepared.Scenario;
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger"];
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "alice"));
        await using (var ban = await scenario.Factory.CreateDbContextAsync())
        {
            var component = await ban.ApprovedBinaries.AsNoTracking().Where(row => row.ProductId == scenario.Fixture.ProductId && row.Version == scenario.Fixture.Version).Select(row => new { row.Key, row.Hash }).FirstAsync();
            ban.BannedComponents.Add(new BannedComponent { ProductId = scenario.Fixture.ProductId, ComponentType = component.Key, ComponentHash = component.Hash, Reason = "TKT-001802 component priority proof", IsActive = true });
            await ban.SaveChangesAsync();
        }

        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var canary = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        await SendTkt001802CanaryAsync(runtime, scenario, canary, "component-banned");
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var incident = await check.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == canary.EventId);
        Assert.Equal("OPEN", incident.State);
        Assert.Null(incident.NonBlockingReason);
        Assert.Equal("component_banned:blocking", (await check.CanaryAlerts.AsNoTracking().SingleAsync(row => row.Trigger == "RuntimeCheck_Debugger")).Details);
    }

    /// <summary>
    /// An earlier commercial denial cannot hide a canonical-seat or approved-component ban from SHADOW priority;
    /// the Canary remains blocking while the independent capability contract stays commercially denied.
    /// </summary>
    /// <param name = "banKind">Exact recognized ban surface combined with the commercial refusal.</param>
    /// <param name = "expectedDetails">Expected bounded Canary audit detail.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_ShadowMode_CommercialDenialCannotHideActiveBan")]
    [InlineData("canonical-hardware", "hardware_banned:blocking")]
    [InlineData("reported-hardware", "hardware_banned:blocking")]
    [InlineData("component", "component_banned:blocking")]
    public async Task Tkt001802_ShadowMode_CommercialDenialCannotHideActiveBan(string banKind, string expectedDetails)
    {
        var prepared = await PrepareTkt001802ScenarioAsync();
        using var scenario = prepared.Scenario;
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger"];
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "alice"));
        var reportedHardwareId = await ApplyCommercialDenialAndBanAsync(scenario, banKind);
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var canary = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        canary.HardwareId = reportedHardwareId;
        await SendTkt001802CanaryAsync(runtime, scenario, canary, "commercial-denial-" + banKind);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var incident = await check.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == canary.EventId);
        Assert.Equal("OPEN", incident.State);
        Assert.Null(incident.NonBlockingReason);
        Assert.Equal(expectedDetails, (await check.CanaryAlerts.AsNoTracking().SingleAsync(row => row.Trigger == "RuntimeCheck_Debugger")).Details);
    }

    /// <summary>
    /// REVIEW and ENFORCE retain the established commercial-denial detail when an independent canonical or
    /// component ban coexists; only SHADOW uses that extra signal to override the audit detail.
    /// </summary>
    /// <param name = "mode">Exact non-SHADOW effective policy.</param>
    /// <param name = "banKind">Independent recognized ban combined with the commercial refusal.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_NonShadowMode_CommercialDenialKeepsEstablishedDetails")]
    [InlineData("REVIEW", "canonical-hardware")]
    [InlineData("REVIEW", "reported-hardware")]
    [InlineData("REVIEW", "component")]
    [InlineData("ENFORCE", "canonical-hardware")]
    [InlineData("ENFORCE", "reported-hardware")]
    [InlineData("ENFORCE", "component")]
    public async Task Tkt001802_NonShadowMode_CommercialDenialKeepsEstablishedDetails(string mode, string banKind)
    {
        var prepared = await PrepareTkt001802ScenarioAsync();
        using var scenario = prepared.Scenario;
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger"];
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", mode, "alice"));
        var reportedHardwareId = await ApplyCommercialDenialAndBanAsync(scenario, banKind);
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var canary = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        canary.HardwareId = reportedHardwareId;
        await SendTkt001802CanaryAsync(runtime, scenario, canary, "commercial-denial-" + mode + "-" + banKind);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var incident = await check.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == canary.EventId);
        Assert.Equal("OPEN", incident.State);
        Assert.Null(incident.NonBlockingReason);
        Assert.Equal("commercial_denial:commercial_authority_ineligible", (await check.CanaryAlerts.AsNoTracking().SingleAsync(row => row.Trigger == "RuntimeCheck_Debugger")).Details);
    }

    /// <summary>
    /// Once authentication and trigger mapping succeed, SHADOW remains observation-only even when commercial
    /// eligibility is denied or the reported hardware no longer matches the current seat.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_ShadowMode_WaivesCommerciallyDeniedAndUnlinkedCanaries")]
    public async Task Tkt001802_ShadowMode_WaivesCommerciallyDeniedAndUnlinkedCanaries()
    {
        var prepared = await PrepareTkt001802ScenarioAsync();
        using var scenario = prepared.Scenario;
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger"];
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "alice"));
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        await using (var expire = await scenario.Factory.CreateDbContextAsync())
        {
            var licenseId = await expire.RuntimeEnrollments.AsNoTracking().Where(row => row.Id == scenario.EnrollmentId).Select(row => row.LicenseId).SingleAsync();
            var license = await expire.Licenses.SingleAsync(row => row.Id == licenseId);
            license.ExpirationDate = DateTime.UtcNow.AddDays(-1);
            await expire.SaveChangesAsync();
        }

        var commerciallyDenied = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        await SendTkt001802CanaryAsync(runtime, scenario, commerciallyDenied, "commercial-denial-shadow");
        await using (var restore = await scenario.Factory.CreateDbContextAsync())
        {
            var licenseId = await restore.RuntimeEnrollments.AsNoTracking().Where(row => row.Id == scenario.EnrollmentId).Select(row => row.LicenseId).SingleAsync();
            var license = await restore.Licenses.SingleAsync(row => row.Id == licenseId);
            license.ExpirationDate = DateTime.UtcNow.AddDays(30);
            await restore.SaveChangesAsync();
        }

        var unlinked = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        unlinked.HardwareId = "FFFFFFFFFFFFFFFF";
        await SendTkt001802CanaryAsync(runtime, scenario, unlinked, "unlinked-shadow");
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var incidents = await check.RuntimeCriticalIncidents.AsNoTracking().ToListAsync();
        Assert.Equal(2, incidents.Count);
        Assert.All(incidents, incident =>
        {
            Assert.Equal("WAIVED", incident.State);
            Assert.Equal("MODE_SHADOW", incident.NonBlockingReason);
        });
        Assert.Equal(2, await check.CanaryAlerts.AsNoTracking().CountAsync(row => row.Details == "mode_shadow:non_blocking"));
        await AssertTkt001802CapabilityAvailableAsync(runtime, scenario, "shadow-denied-and-unlinked");
    }

    /// <summary>The administrator-facing lock dossier states the non-blocking SHADOW outcome explicitly.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001802_ShadowAlertDossier_StatesThatNothingIsBlocked")]
    public void Tkt001802_ShadowAlertDossier_StatesThatNothingIsBlocked()
    {
        var dossier = new SecurityLockDossier(Product: "T-IA Connect", CustomerName: "Client", CustomerEmail: "client@example.invalid", MaskedLicenseKey: "ABCD…WXYZ", MachineName: "POSTE-01", HardwareId: LegacyHardwareId, AppVersion: "1.0.0", InstallationId: "installation-shadow", EnrollmentId: Guid.NewGuid(), LockId: new string ('a', 32), Cause: "DEBUGGER_ATTACHED_KERNEL", Level: 5, EffectiveMode: SecurityLockCauseCatalog.ModeShadow, ClientMode: SecurityLockCauseCatalog.ModeReview, LastVerdict: SecurityLockVerdicts.Release, State: SecurityLockReportStates.Released, FirstSeenUtc: DateTime.UtcNow, FirstReportedUtc: DateTime.UtcNow, ReportCount: 1, OtherLocksOnHardware: 0, OpenCriticalIncident: false, EvidenceDigestSha256: new string ('b', 64));
        var message = SecurityLockAlertPolicy.BuildDossier(dossier);
        Assert.Contains("Mode SHADOW : alerte uniquement, aucun blocage n’est appliqué.", message, StringComparison.Ordinal);
        var bannedMessage = SecurityLockAlertPolicy.BuildDossier(dossier with { LastVerdict = SecurityLockVerdicts.Ban, State = SecurityLockReportStates.Banned });
        Assert.DoesNotContain("aucun blocage n’est appliqué", bannedMessage, StringComparison.Ordinal);
    }
}
