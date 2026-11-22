using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Components.Shared;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;
using SecurityLocksPage = SoftLicence.Server.Components.Pages.SecurityLocks;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>Creates an authenticated verified report ready for an administrative decision.</summary>
    /// <param name="lockSeed">Lowercase hexadecimal seed used to create the stable test lock identifier.</param>
    /// <param name="cause">Exact catalogued security-lock cause.</param>
    /// <param name="level">Security-lock severity from zero through five.</param>
    /// <param name="mode">Exact client enforcement mode reported by the fixture.</param>
    /// <param name="hardwareId">Exact hardware identifier carried by the authenticated report.</param>
    /// <param name="initialSubjectRef">Optional canonical website subject reference bound before activation.</param>
    /// <returns>The owning PostgreSQL scenario, persisted report identifier, and admin service.</returns>
    protected static async Task<(PreparedBootstrapScenario Scenario, Guid ReportId, SecurityLockAdminService Admin)>
        PrepareAdminReleaseFixtureAsync(
            char lockSeed,
            string cause = "NATIVE_DLL_REPLACED",
            int level = 4,
            string mode = "REVIEW",
            string hardwareId = LegacyHardwareId,
            string? initialSubjectRef = null)
    {
        var scenario = await CreatePreparedBootstrapScenarioAsync(initialSubjectRef: initialSubjectRef);
        try
        {
            await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
            using var acknowledgementKey = RSA.Create(2048);
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CanaryAck:PrivateKeyPem"] = acknowledgementKey.ExportPkcs8PrivateKeyPem()
            }).Build();
            var authority = new RuntimeEnrollmentAuthorityService(
                scenario.Factory, Options.Create(scenario.Options));
            using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
            var runtime = new RuntimeEnrollmentService(
                scenario.Factory,
                authority,
                new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
                crypto,
                Options.Create(scenario.Options),
                new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
            var report = LockRequest(
                hardwareId, scenario.Fixture.Version, cause, level, mode, lockSeed);
            var digest = Sha256("tkt001782-fixture-" + Guid.NewGuid().ToString("D"));
            await runtime.ProcessSecurityLockReportAsync(
                scenario.EnrollmentId, digest, report,
                LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, report.ReportId!, digest, scenario.Options),
                IPAddress.Loopback);
            await using var lookup = await scenario.Factory.CreateDbContextAsync();
            var reportId = await lookup.SecurityLockReports.AsNoTracking()
                .Where(row => row.LockId == report.LockId).Select(row => row.Id).SingleAsync();
            return (scenario, reportId, new SecurityLockAdminService(
                scenario.Factory,
                new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options))));
        }
        catch
        {
            scenario.Dispose();
            throw;
        }
    }

    /// <summary>Reads the exact current security generation from a fresh context.</summary>
    protected static async Task<int> ReadSecurityEpochAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        return await db.RuntimeEnrollments.AsNoTracking()
            .Where(row => row.Id == scenario.EnrollmentId)
            .Select(row => row.SecurityEpoch)
            .SingleAsync();
    }

    /// <summary>
    /// Keeps the authenticated enrollment's legacy license copy on L1 while moving its valid ACTIVE commercial
    /// assignment and canonical seat to a newly cloned L2 license.
    /// </summary>
    /// <returns>The distinct legacy and active-assignment license identifiers.</returns>
    protected static async Task<(Guid LegacyLicenseId, Guid ActiveLicenseId)>
        MoveActiveAssignmentToNewLicenseAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignment = await db.EnrollmentLicenseAssignments
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var sourceLicense = await db.Licenses.AsNoTracking()
            .SingleAsync(row => row.Id == assignment.LicenseId);
        var sourceSeat = await db.LicenseSeats.AsNoTracking()
            .SingleAsync(row => row.Id == assignment.LicenseSeatId);
        Assert.Equal(enrollment.LicenseId, assignment.LicenseId);

        var activeLicense = new License();
        db.Entry(activeLicense).CurrentValues.SetValues(sourceLicense);
        activeLicense.Id = Guid.NewGuid();
        activeLicense.LicenseKey = Guid.NewGuid().ToString("D");
        activeLicense.AuthorityVersion = Guid.NewGuid();
        activeLicense.ProvisioningRequestId = null;
        activeLicense.ProvisioningSequence = null;
        var activeSeat = new LicenseSeat();
        db.Entry(activeSeat).CurrentValues.SetValues(sourceSeat);
        activeSeat.Id = Guid.NewGuid();
        activeSeat.LicenseId = activeLicense.Id;
        db.Licenses.Add(activeLicense);
        db.LicenseSeats.Add(activeSeat);
        assignment.LicenseId = activeLicense.Id;
        assignment.LicenseSeatId = activeSeat.Id;
        assignment.Revision += 1;
        await db.SaveChangesAsync();
        return (enrollment.LicenseId, activeLicense.Id);
    }

    /// <summary>Moves the live credential and assignment to a new enrollment while retaining the old report.</summary>
    protected static async Task<Guid> ReinstallPreparedEnrollmentAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var historical = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var historicalAssignment = await db.EnrollmentLicenseAssignments
            .SingleAsync(row => row.EnrollmentId == historical.Id && row.State == "ACTIVE");
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var spki = crypto.Open("enrollment-spki", historical.Id, historical.Epoch,
            historical.PublicKeySpkiKeyId, historical.PublicKeySpkiCiphertext,
            $"RuntimeEnrollments:{historical.Id:D}:PublicKeySpkiCiphertext");
        var challenge = crypto.Open("enrollment-challenge", historical.Id, historical.Epoch,
            historical.ChallengeKeyId, historical.ChallengeCiphertext,
            $"RuntimeEnrollments:{historical.Id:D}:ChallengeCiphertext");
        var active = new RuntimeEnrollment();
        db.Entry(active).CurrentValues.SetValues(historical);
        active.Id = Guid.NewGuid();
        active.State = "ACTIVE";
        active.InvalidatedAtUtc = null;
        active.InvalidationReason = null;
        var spkiEnvelope = await crypto.SealAsync(db, "enrollment-spki", active.Id, active.Epoch, spki,
            $"RuntimeEnrollments:{active.Id:D}:PublicKeySpkiCiphertext");
        active.PublicKeySpkiCiphertext = spkiEnvelope.Ciphertext;
        active.PublicKeySpkiKeyId = spkiEnvelope.KeyId;
        var challengeEnvelope = await crypto.SealAsync(db, "enrollment-challenge", active.Id, active.Epoch, challenge,
            $"RuntimeEnrollments:{active.Id:D}:ChallengeCiphertext");
        active.ChallengeCiphertext = challengeEnvelope.Ciphertext;
        active.ChallengeKeyId = challengeEnvelope.KeyId;
        CryptographicOperations.ZeroMemory(spki);
        CryptographicOperations.ZeroMemory(challenge);
        historical.State = "INVALIDATED";
        historical.InvalidatedAtUtc = DateTime.UtcNow;
        historical.InvalidationReason = "TKT-001782 re-enrollment fixture";
        historicalAssignment.State = "ENDED";
        historicalAssignment.EndedAtUtc = historical.InvalidatedAtUtc;
        historicalAssignment.EndReason = "tkt001782_reinstalled";
        await db.SaveChangesAsync();
        db.RuntimeEnrollments.Add(active);
        db.EnrollmentLicenseAssignments.Add(new EnrollmentLicenseAssignment
        {
            EnrollmentId = active.Id,
            LicenseId = historicalAssignment.LicenseId,
            LicenseSeatId = historicalAssignment.LicenseSeatId,
            State = "ACTIVE",
            ActivatedAtUtc = DateTime.UtcNow,
            Revision = 1
        });
        await db.SaveChangesAsync();
        await transaction.CommitAsync();
        return active.Id;
    }

    /// <summary>
    /// Rewrites only the immutable-link metadata to the historical UNKNOWN_LEGACY shape. The trigger is disabled for
    /// this administrator-owned fixture operation and always re-enabled, while update failure remains visible.
    /// </summary>
    protected static async Task SetSecurityLockUnknownLegacyAsync(string connectionString, Guid reportId)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using (var disable = new NpgsqlCommand("""
            ALTER TABLE public."SecurityLockReports"
                DISABLE TRIGGER "TR_SecurityLockReports_ImmutableIdentity";
            """, connection))
            await disable.ExecuteNonQueryAsync();
        try
        {
            await using var update = new NpgsqlCommand("""
                UPDATE public."SecurityLockReports"
                SET "LinkStatus" = 'UNKNOWN_LEGACY',
                    "LinkAssignmentId" = NULL,
                    "LinkLicenseSeatId" = NULL,
                    "LinkAliasId" = NULL,
                    "LinkVerifiedAtUtc" = NULL,
                    "LinkReasonCode" = 'legacy_unknown'
                WHERE "Id" = @id;
                """, connection);
            update.Parameters.AddWithValue("id", reportId);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }
        finally
        {
            await using var enable = new NpgsqlCommand("""
                ALTER TABLE public."SecurityLockReports"
                    ENABLE TRIGGER "TR_SecurityLockReports_ImmutableIdentity";
                """, connection);
            await enable.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// Moves one generated PostgreSQL database to the exact named migration and propagates provider failures so tests
    /// can distinguish a guarded rollback refusal from a successful Up/Down transition.
    /// </summary>
    protected static async Task MigrateDatabaseAsync(string connectionString, string targetMigration)
    {
        await using var db = new TestDbFactory(connectionString).CreateDbContext();
        await db.GetService<IMigrator>().MigrateAsync(targetMigration);
    }

    /// <summary>Opens one exact incident for a selected enrollment in the shared stable scope.</summary>
    protected static async Task<string> OpenCriticalIncidentAsync(
        PreparedBootstrapScenario scenario,
        Guid enrollmentId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
        var eventId = Guid.NewGuid().ToString("D");
        db.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
        {
            EnrollmentId = enrollment.Id,
            BindingId = enrollment.BindingId,
            ProductId = enrollment.ProductId,
            InstallationId = enrollment.InstallationId,
            EventId = eventId,
            Trigger = "RuntimeCheck_NativeDllSwapped",
            State = "OPEN",
            OpenedSecurityEpoch = enrollment.SecurityEpoch,
            OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
            OpenedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        return eventId;
    }

    /// <summary>Captures the real security-lock page while preserving framework lifecycle and injection.</summary>
    protected sealed class Tkt1782SecurityLocksActivator : IComponentActivator
    {
        internal IComponent? Page { get; private set; }
        internal SecurityLockDecisionDialog? Dialog { get; private set; }

        public IComponent CreateInstance(Type componentType)
        {
            var component = (IComponent)Activator.CreateInstance(componentType)!;
            if (componentType == typeof(SecurityLocksPage)) Page = component;
            if (componentType == typeof(SecurityLockDecisionDialog)) Dialog = (SecurityLockDecisionDialog)component;
            return component;
        }
    }

    /// <summary>Supplies a synthetic root administrator without cookies or external identity services.</summary>
    protected sealed class Tkt1782RootAuthentication : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync() => Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, "tkt1782-root"), new Claim(ClaimTypes.Role, "CHANGE_ME_RANDOM_SECRET")],
                "synthetic"))));
    }
}

/// <summary>Runs the tests from RuntimeRememberedReleasePostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeRememberedReleasePostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>TKT-001838 proves exact lock selectors and the sole case-insensitive display filter on PostgreSQL.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_SecurityLockReadFilters_PreserveExactAuthoritySemanticsOnPostgreSql")]
    public async Task Tkt001838_SecurityLockReadFilters_PreserveExactAuthoritySemanticsOnPostgreSql()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('e');
        using var scenario = prepared.Scenario;
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var report = await db.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId);
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == report.EnrollmentId);
        var license = await db.Licenses.SingleAsync(row => row.Id == enrollment.LicenseId);
        license.CustomerEmail = "Alice.Mixed@Example.Test";
        await db.SaveChangesAsync();

        var projected = await AnalyticsController.BuildSecurityLockQuery(
            db, scenario.Fixture.ProductId, state: report.State, hardwareId: report.HardwareId,
            email: "alice.mixed@example.test").SingleAsync();
        Assert.True(projected.HasActiveEnrollment);
        Assert.Equal(0, await AnalyticsController.BuildSecurityLockQuery(
            db, scenario.Fixture.ProductId, state: report.State.ToLowerInvariant(),
            hardwareId: report.HardwareId).CountAsync());
        Assert.Equal(0, await AnalyticsController.BuildSecurityLockQuery(
            db, scenario.Fixture.ProductId, state: report.State,
            hardwareId: report.HardwareId.ToLowerInvariant()).CountAsync());
    }

    /// <summary>
    /// TKT-001838 proves explicit UNBAN is atomic for UNKNOWN_LEGACY locks, optional incidents, and every applicable
    /// hardware ban while RELEASE stays refused and no remembered decision is created.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_ExplicitUnban_RecoversIncidentAndDeactivatesBansAtomically")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt001838_ExplicitUnban_RecoversIncidentAndDeactivatesBansAtomically(bool withIncident)
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('a');
        using var scenario = prepared.Scenario;
        if (withIncident)
            await OpenPreparedCriticalIncidentAsync(scenario);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "alice",
            scenario.Fixture.ProductId)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.LockBannedIrreversible, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Release, "must remain refused", "alice",
            scenario.Fixture.ProductId)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.ReasonRequired, (await prepared.Admin.UnbanAsync(
            prepared.ReportId, null, "TKT-001838", "alice", scenario.Fixture.ProductId)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.AuditReferenceInvalid, (await prepared.Admin.UnbanAsync(
            prepared.ReportId, "reviewed", null, "alice", scenario.Fixture.ProductId)).Outcome);

        string hardwareId;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
            hardwareId = (await read.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == prepared.ReportId)).HardwareId;
        await using (var connection = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await connection.OpenAsync();
            await using (var disableTrigger = new NpgsqlCommand("""
                ALTER TABLE public."SecurityLockReports"
                    DISABLE TRIGGER "TR_SecurityLockReports_ImmutableIdentity";
                """, connection))
            {
                await disableTrigger.ExecuteNonQueryAsync();
            }

            try
            {
                await using var legacy = new NpgsqlCommand("""
                    UPDATE public."SecurityLockReports"
                    SET "LinkStatus" = 'UNKNOWN_LEGACY',
                        "LinkAssignmentId" = NULL,
                        "LinkLicenseSeatId" = NULL,
                        "LinkAliasId" = NULL,
                        "LinkVerifiedAtUtc" = NULL,
                        "LinkReasonCode" = 'legacy_unknown'
                    WHERE "Id" = @id;
                    """, connection);
                legacy.Parameters.AddWithValue("id", prepared.ReportId);
                await legacy.ExecuteNonQueryAsync();
            }
            finally
            {
                await using var enableTrigger = new NpgsqlCommand("""
                    ALTER TABLE public."SecurityLockReports"
                        ENABLE TRIGGER "TR_SecurityLockReports_ImmutableIdentity";
                    """, connection);
                await enableTrigger.ExecuteNonQueryAsync();
            }
        }
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            mutate.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId.ToLowerInvariant(), ProductId = null,
                BannedAt = DateTime.UtcNow, IsActive = true, Reason = "global-test-ban",
                BanCategory = BannedHardwareId.Categories.Manual
            });
            await mutate.SaveChangesAsync();
        }

        var result = await prepared.Admin.UnbanAsync(
            prepared.ReportId, "False positive reviewed", "TKT-001838", "alice",
            scenario.Fixture.ProductId);

        Assert.Equal(SecurityLockAdminOutcomes.Ok, result.Outcome);
        Assert.Equal(withIncident ? 1 : 0, result.RecoveredIncidentCount);
        Assert.Equal(2, result.DeactivatedHardwareBanCount);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var released = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId);
        Assert.Equal(SecurityLockReportStates.Released, released.State);
        Assert.Equal(SecurityLockAdminDecisions.Unban, released.AdminDecision);
        Assert.Contains("auditRef=TKT-001838", released.AdminDecisionReason, StringComparison.Ordinal);
        Assert.Null(released.RememberedReleaseDecisionId);
        Assert.Empty(await check.SecurityLockReleaseDecisions.AsNoTracking().ToListAsync());
        Assert.False(await check.BannedHardwareIds.AnyAsync(row => row.IsActive
            && row.HardwareId.ToUpper() == released.HardwareId
            && (row.ProductId == null || row.ProductId == released.ProductId)));
        Assert.False(await check.RuntimeCriticalIncidents.AnyAsync(row => row.State == "OPEN"));
        Assert.Equal(withIncident ? 1 : 0, await check.RuntimeCriticalRecoveries.CountAsync());
    }

    /// <summary>TKT-001838 proves an exact old BAN replay is replaced by RELEASE after explicit UNBAN.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_ExplicitUnban_ReplayDoesNotReturnHistoricalBan")]
    public async Task Tkt001838_ExplicitUnban_ReplayDoesNotReturnHistoricalBan()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('c');
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "alice",
            scenario.Fixture.ProductId)).Outcome);

        using var acknowledgementKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = acknowledgementKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(
            scenario.Factory,
            new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)),
            new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)),
            crypto,
            Options.Create(scenario.Options),
            new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        DateTime firstSeenUtc;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
            firstSeenUtc = (await read.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == prepared.ReportId)).FirstSeenUtc;
        var report = LockRequest(
            LegacyHardwareId, scenario.Fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", 'c');
        report.FirstSeenUtc = SecurityLockReportValidator.FormatUtc(new DateTimeOffset(firstSeenUtc));
        var digest = Sha256("tkt001838-banned-replay-" + Guid.NewGuid().ToString("D"));
        var proof = LockProof(
            scenario.EnrollmentKey, scenario.EnrollmentId, report.ReportId!, digest, scenario.Options);
        Assert.Equal(SecurityLockVerdicts.Ban, (await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, report, proof, IPAddress.Loopback)).Response.Verdict);

        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.UnbanAsync(
            prepared.ReportId, "False positive reviewed", "TKT-001838", "alice",
            scenario.Fixture.ProductId)).Outcome);
        var replay = await runtime.ProcessSecurityLockReportAsync(
            scenario.EnrollmentId, digest, report, proof, IPAddress.Loopback);

        Assert.True(replay.Idempotent);
        Assert.Equal(SecurityLockVerdicts.Release, replay.Response.Verdict);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(SecurityLockReportStates.Released,
            (await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId)).State);
        Assert.Contains("\"verdict\":\"RELEASE\"", (await check.SecurityLockReportNonces.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.Jti == proof.Jti)).ResponseJson,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// TKT-001838 reproduces the exact production-shaped UNKNOWN_LEGACY authority graph and proves the
    /// real WebSetup Finalize v2 boundary rejects it before UNBAN but completes bootstrap, confirmation,
    /// and capability issuance after the audited recovery closes the incident.
    /// </summary>
    /// <param name="unban">Whether the operator performs the required audited UNBAN before WebSetup finalization.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_WebSetupReinstall_RequiresUnbanAndRecoversAuthorityIneligible")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt001838_WebSetupReinstall_RequiresUnbanAndRecoversAuthorityIneligible(bool unban)
    {
        const string productionVersion = "2.4.402";
        // The licence must still be valid when IssueEntitlementAsync runs (it requires ExpirationDate > now). A fixed
        // calendar date made this test fail from its expiry day on (TKT-004122), so the date is relative to the run.
        var licenseExpiration = DateTime.UtcNow.Date.AddDays(365);
        var websiteSubjectRef = Convert.ToBase64String(SHA256.HashData("tkt001838-website-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var prepared = await PrepareAdminReleaseFixtureAsync('7', initialSubjectRef: websiteSubjectRef);
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "alice",
            scenario.Fixture.ProductId)).Outcome);

        Guid licenseId;
        List<ApprovedBinaryArtifact> releaseArtifacts;
        await SetSecurityLockUnknownLegacyAsync(scenario.AdminConnectionString, prepared.ReportId);
        await using (var prepareHistoricalBan = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var historicalBan = Assert.Single(await prepareHistoricalBan.BannedHardwareIds.ToListAsync());
            historicalBan.BanCategory = BannedHardwareId.Categories.Debugger;
            historicalBan.ExpiresAt = null;
            await prepareHistoricalBan.SaveChangesAsync();
        }
        await using (var mutate = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            licenseId = enrollment.LicenseId;
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "authority_ineligible";
            enrollment.ReleaseVersion = productionVersion;
            var assignment = await mutate.EnrollmentLicenseAssignments
                .SingleAsync(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE");
            assignment.State = "ENDED";
            assignment.EndedAtUtc = enrollment.InvalidatedAtUtc;
            assignment.EndReason = "authority_ineligible";
            var report = await mutate.SecurityLockReports.SingleAsync(row => row.Id == prepared.ReportId);
            report.ReportCount = 80;
            report.LastVerdict = SecurityLockVerdicts.Ban;
            report.AdminDecision = null;
            report.AdminDecisionAtUtc = null;
            report.AdminDecisionBy = null;
            report.AdminDecisionReason = null;
            var license = await mutate.Licenses.SingleAsync(row => row.Id == licenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            license.RevocationReason = null;
            license.MaxSeats = 1;
            license.AllowedVersions = "*";
            license.ExpirationDate = licenseExpiration;
            var binding = await mutate.DistributionInstallationBindings
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            binding.State = "active";
            binding.InvalidatedAtUtc = null;
            binding.InvalidationReason = null;
            binding.SupersededBindingId = null;
            binding.Version = productionVersion;
            binding.InstallerFilename = "TiaConnect-Setup_v2.4.402.msi";
            binding.InitialSecurityEpoch = 1;
            var approvedRows = await mutate.ApprovedBinaries
                .Where(row => row.ProductId == scenario.Fixture.ProductId)
                .ToListAsync();
            releaseArtifacts = approvedRows
                .Select(row => new ApprovedBinaryArtifact(row.Key, row.Hash))
                .ToList();
            mutate.ApprovedBinaries.RemoveRange(approvedRows);
            await mutate.SaveChangesAsync();
        }
        await using (var deactivateBan = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            foreach (var existingBan in await deactivateBan.BannedHardwareIds.Where(row => row.IsActive).ToListAsync())
                existingBan.IsActive = false;
            await deactivateBan.SaveChangesAsync();
        }
        var registered = await new ApprovedBinaryService(
                scenario.Factory, NullLogger<ApprovedBinaryService>.Instance)
            .RegisterReleaseBaselineAsync(
                scenario.Fixture.ProductId,
                productionVersion,
                $"tkt001838-websetup-{scenario.Fixture.ProductId:D}",
                new string('e', 64),
                releaseArtifacts);
        Assert.Equal(ApprovedBinaryVerdict.Approved, registered.Result.Verdict);

        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var report = await before.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId);
            Assert.Equal(SecurityLockReportStates.Banned, report.State);
            Assert.Equal(SecurityLockVerdicts.Ban, report.LastVerdict);
            Assert.Null(report.AdminDecision);
            Assert.Equal(SecurityLockReportLinkStatuses.UnknownLegacy, report.LinkStatus);
            Assert.Equal(80, report.ReportCount);
            Assert.Single(await before.RuntimeCriticalIncidents.AsNoTracking()
                .Where(row => row.State == "OPEN").ToListAsync());
            var inactiveEnrollment = Assert.Single(await before.RuntimeEnrollments.AsNoTracking().ToListAsync());
            Assert.Equal("INVALIDATED", inactiveEnrollment.State);
            Assert.Equal("authority_ineligible", inactiveEnrollment.InvalidationReason);
            Assert.Equal(productionVersion, inactiveEnrollment.ReleaseVersion);
            Assert.Equal(1, inactiveEnrollment.SecurityEpoch);
            Assert.False(await before.RuntimeEnrollments.AnyAsync(row => row.State == "ACTIVE"));
            var inactiveBan = Assert.Single(await before.BannedHardwareIds.AsNoTracking().ToListAsync());
            Assert.False(inactiveBan.IsActive);
            Assert.Equal(BannedHardwareId.Categories.Debugger, inactiveBan.BanCategory);
            var activeBinding = await before.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            Assert.Equal("active", activeBinding.State);
            Assert.Null(activeBinding.InvalidatedAtUtc);
            Assert.Null(activeBinding.InvalidationReason);
            Assert.Null(activeBinding.SupersededBindingId);
            Assert.Equal(productionVersion, activeBinding.Version);
            Assert.Equal(1, activeBinding.InitialSecurityEpoch);
            Assert.Equal(ApprovedBinaryService.ReleaseSource, activeBinding.ApprovedBinariesSource);
            var license = await before.Licenses.AsNoTracking().SingleAsync(row => row.Id == licenseId);
            Assert.True(license.IsActive);
            Assert.Null(license.RevokedAt);
            Assert.Equal(1, license.MaxSeats);
            Assert.Equal(licenseExpiration, license.ExpirationDate);
            var read = await AnalyticsController.BuildSecurityLockQuery(
                before, scenario.Fixture.ProductId, id: prepared.ReportId).SingleAsync();
            Assert.False(read.HasActiveEnrollment);
        }

        if (unban)
        {
            var unbanned = await prepared.Admin.UnbanAsync(
                prepared.ReportId, "False positive reviewed", "TKT-001838", "alice",
                scenario.Fixture.ProductId);
            Assert.Equal(SecurityLockAdminOutcomes.Ok, unbanned.Outcome);
            Assert.Equal(SecurityLockAdminOutcomes.ReleaseNoActiveEnrollment, unbanned.DiagnosticCode);
            Assert.Equal(1, unbanned.RecoveredIncidentCount);
            Assert.Equal(0, unbanned.DeactivatedHardwareBanCount);
        }

        List<DistributionBinaryEvidence> binaries;
        await using (var binaryRead = await scenario.Factory.CreateDbContextAsync())
        {
            binaries = await binaryRead.ApprovedBinaries.AsNoTracking()
                .Where(row => row.ProductId == scenario.Fixture.ProductId
                    && row.Version == productionVersion
                    && row.Source == ApprovedBinaryService.ReleaseSource)
                .OrderBy(row => row.Key)
                .Select(row => new DistributionBinaryEvidence { Key = row.Key, Sha256 = row.Hash })
                .ToListAsync();
        }
        Assert.Equal(3, binaries.Count);
        var bindingService = new DistributionInstallationBindingService(
            scenario.Factory,
            new EphemeralDataProtectionProvider(),
            TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await bindingService.IssueEntitlementAsync(
            "website-step1",
            Sha256("tkt001838-websetup-entitlement-" + unban + "-" + Guid.NewGuid().ToString("D")),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = licenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = websiteSubjectRef
            });
        var now = DateTimeOffset.UtcNow;
        var reinstallRequest = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("tkt001838-websetup-handoff-" + Guid.NewGuid().ToString("D")),
            HandoffIssuedAtUtc = FormatUtc(now.AddSeconds(-30)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddSeconds(-15)),
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = LegacyHardwareId,
            AllowSameAuthorityRecovery = true,
            Release = new DistributionReleaseEvidence
            {
                Version = productionVersion,
                InstallerFilename = "TiaConnect-Setup_v2.4.402.msi",
                InstallerSha256 = new string('f', 64)
            },
            Binaries = binaries
        };
        Assert.NotEqual(scenario.Fixture.InstallationId, reinstallRequest.InstallationId);
        var finalizeDigest = Sha256("tkt001838-websetup-finalize-" + unban + "-" + Guid.NewGuid().ToString("D"));
        if (!unban)
        {
            var refused = await Assert.ThrowsAsync<DistributionOperationException>(() => bindingService.FinalizeAsync(
                "website-step1", finalizeDigest, reinstallRequest));
            Assert.Equal("binding_conflict", refused.ErrorCode);
            Assert.Equal("replacement_source_incident", refused.ReasonCode);
            await using var refusedState = await scenario.Factory.CreateDbContextAsync();
            Assert.False(await refusedState.DistributionInstallationBindings.AnyAsync(row =>
                row.InstallationId == reinstallRequest.InstallationId));
            Assert.Equal("active", (await refusedState.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId)).State);
            Assert.Equal(SecurityLockReportStates.Banned, (await refusedState.SecurityLockReports.AsNoTracking()
                .SingleAsync(row => row.Id == prepared.ReportId)).State);
            Assert.Single(await refusedState.RuntimeCriticalIncidents.AsNoTracking()
                .Where(row => row.State == "OPEN").ToListAsync());
            return;
        }

        var finalized = await bindingService.FinalizeAsync("website-step1", finalizeDigest, reinstallRequest);
        Assert.False(finalized.Idempotent);
        var successorBindingId = Guid.Parse(finalized.Response.BindingId);
        Assert.NotEqual(scenario.Fixture.BindingId, successorBindingId);
        Assert.Equal(reinstallRequest.InstallationId, finalized.Response.InstallationId);
        Assert.Equal("active", finalized.Response.State);

        using var reinstallKey = RSA.Create(3072);
        var prepareRequest = PrepareRequest(
            (scenario.Fixture.ProductId, successorBindingId, reinstallRequest.HandoffDigestSha256!,
                reinstallRequest.InstallationId!, productionVersion),
            Guid.NewGuid().ToString("D"), reinstallKey);
        prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var prepareDigest = Sha256("tkt001838-websetup-prepare-v2-" + Guid.NewGuid().ToString("D"));
        var reenrolled = await scenario.Runtime.PrepareAsync("website-step1", prepareDigest, prepareRequest);
        Assert.Equal(RuntimeEnrollmentService.PrepareV2ResponseSchema, reenrolled.Response.Schema);
        var enrollmentId = Guid.Parse(reenrolled.Response.EnrollmentId);

        var bootstrapIssued = await scenario.Bootstrap.IssueAsync(
            "website-step1",
            Sha256("tkt001838-websetup-bootstrap-issue-" + Guid.NewGuid().ToString("D")),
            new DistributionLicenseBootstrapIssueRequest
            {
                Schema = DistributionLicenseBootstrapService.IssueSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                BindingId = successorBindingId.ToString("D"),
                EnrollmentId = enrollmentId.ToString("D")
            });
        Assert.NotEmpty(bootstrapIssued.Response.Capability);
        var redeemRequest = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = successorBindingId.ToString("D"),
            InstallationId = reinstallRequest.InstallationId,
            BootstrapId = bootstrapIssued.Response.BootstrapId,
            Capability = bootstrapIssued.Response.Capability
        };
        var redeemDigest = Sha256("tkt001838-websetup-bootstrap-redeem-" + Guid.NewGuid().ToString("D"));
        var redeemed = await scenario.Runtime.RedeemLicenseBootstrapAsync(
            enrollmentId,
            redeemDigest,
            redeemRequest,
            Proof(reinstallKey, "license-bootstrap", enrollmentId, scenario.Options.ConfirmAudience,
                reenrolled.Response.Challenge, redeemDigest),
            IPAddress.Loopback);
        Assert.NotEmpty(redeemed.Response.LicenseFile);

        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("tkt001838-real-reinstall-confirm-" + Guid.NewGuid().ToString("D"));
        await scenario.Runtime.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(reinstallKey, "confirm", enrollmentId, scenario.Options.ConfirmAudience,
                reenrolled.Response.Challenge, confirmDigest), IPAddress.Loopback);

        var capability = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = reenrolled.Response.SecurityEpoch,
            InstallationId = reinstallRequest.InstallationId,
            ReleaseVersion = productionVersion,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var capabilityDigest = Sha256("tkt001838-real-reinstall-capability-" + Guid.NewGuid().ToString("D"));
        var issued = await scenario.Runtime.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capability,
            Proof(reinstallKey, "capability", enrollmentId, capability.Audience, "-", capabilityDigest),
            IPAddress.Loopback);
        Assert.NotNull(issued.Response.CapabilityToken);
        await using var after = await scenario.Factory.CreateDbContextAsync();
        var active = await after.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == enrollmentId);
        var activeAssignment = await after.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE");
        Assert.Equal(licenseId, activeAssignment.LicenseId);
        Assert.Equal("ACTIVE", active.State);
        Assert.Equal(Sha256(LegacyHardwareId), active.HardwareIdHash);
        Assert.Equal(successorBindingId, active.BindingId);
        Assert.Equal(reinstallRequest.InstallationId, active.InstallationId);
        var successor = await after.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == successorBindingId);
        Assert.Equal("active", successor.State);
        Assert.Equal(scenario.Fixture.BindingId, successor.SupersededBindingId);
        var superseded = await after.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        Assert.Equal("invalidated", superseded.State);
        Assert.Equal("installation_superseded", superseded.InvalidationReason);
        Assert.False(await after.RuntimeCriticalIncidents.AnyAsync(row => row.State == "OPEN"));
        Assert.False(await after.BannedHardwareIds.AnyAsync(row => row.IsActive));
        var released = await after.SecurityLockReports.AsNoTracking()
            .SingleAsync(row => row.Id == prepared.ReportId);
        Assert.Equal(SecurityLockReportStates.Released, released.State);
        Assert.Equal(SecurityLockVerdicts.Release, released.LastVerdict);
        Assert.Equal(SecurityLockAdminDecisions.Unban, released.AdminDecision);
    }

    /// <summary>TKT-001838 proves active-client UNBAN delivers a signed refetch before capability resumes.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_UnbanWithActiveEnrollment_RefetchesSignedRecoveryAndIssuesCapability")]
    public async Task Tkt001838_UnbanWithActiveEnrollment_RefetchesSignedRecoveryAndIssuesCapability()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('8');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "alice",
            scenario.Fixture.ProductId)).Outcome);
        var unbanned = await prepared.Admin.UnbanAsync(
            prepared.ReportId, "False positive reviewed", "TKT-001838", "alice",
            scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, unbanned.Outcome);
        Assert.Null(unbanned.DiagnosticCode);

        var refetchRequest = new RuntimeCriticalRecoveryClientRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryClientRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1
        };
        var refetchDigest = Sha256("tkt001838-unban-refetch-" + Guid.NewGuid().ToString("D"));
        var refetch = await scenario.Runtime.RefetchCriticalRecoveryForClientAsync(
            scenario.EnrollmentId, refetchDigest, refetchRequest,
            Proof(scenario.EnrollmentKey, "critical-recovery-refetch", scenario.EnrollmentId,
                scenario.Options.ConfirmAudience, "-", refetchDigest), IPAddress.Loopback);
        Assert.Equal(2, refetch.Response.NewSecurityEpoch);
        Assert.NotEmpty(refetch.Response.Signature);

        var capability = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 2,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var capabilityDigest = Sha256("tkt001838-unban-capability-" + Guid.NewGuid().ToString("D"));
        var issued = await scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId, capabilityDigest, capability,
            Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId,
                capability.Audience, "-", capabilityDigest), IPAddress.Loopback);
        Assert.NotNull(issued.Response.CapabilityToken);
    }

    /// <summary>TKT-001838 applies PostgreSQL Up/Down and refuses downgrade while either audit marker remains.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_Migration_UsesBoundedLocksAndFailsClosedForUnbanAuditRows")]
    public async Task Tkt001838_Migration_UsesBoundedLocksAndFailsClosedForUnbanAuditRows()
    {
        const string previousMigration = "20261012135819_AddTkt001783RememberedSecurityLockRelease";
        const string currentMigration = "20261013143000_AddTkt001838SecurityLockUnban";
        var prepared = await PrepareAdminReleaseFixtureAsync('9');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "alice",
            scenario.Fixture.ProductId)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.UnbanAsync(
            prepared.ReportId, "False positive reviewed", "TKT-001838", "alice",
            scenario.Fixture.ProductId)).Outcome);

        await using (var scripts = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var migrator = scripts.GetService<IMigrator>();
            Assert.Contains("SET LOCAL lock_timeout = '15s';",
                migrator.GenerateScript(previousMigration, currentMigration), StringComparison.Ordinal);
            Assert.Contains("SET LOCAL lock_timeout = '15s';",
                migrator.GenerateScript(currentMigration, previousMigration), StringComparison.Ordinal);
        }

        var bothMarkers = await Record.ExceptionAsync(() => MigrateDatabaseAsync(
            scenario.AdminConnectionString, previousMigration));
        Assert.NotNull(bothMarkers);
        Assert.Contains("TKT-001838 downgrade refused", bothMarkers.ToString(), StringComparison.Ordinal);

        await using (var relabelReportOnly = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await relabelReportOnly.Database.ExecuteSqlRawAsync(
                "UPDATE public.\"SecurityLockReports\" SET \"AdminDecision\" = 'RELEASE' WHERE \"Id\" = {0};",
                prepared.ReportId);
        }
        var recoveryMarker = await Record.ExceptionAsync(() => MigrateDatabaseAsync(
            scenario.AdminConnectionString, previousMigration));
        Assert.NotNull(recoveryMarker);
        Assert.Contains("TKT-001838 downgrade refused", recoveryMarker.ToString(), StringComparison.Ordinal);

        await using (var removeFinalMarker = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
            await removeFinalMarker.Database.ExecuteSqlRawAsync(
                "UPDATE public.\"RuntimeCriticalRecoveries\" SET \"Source\" = 'ADMIN_RELEASE' WHERE \"Source\" = 'ADMIN_UNBAN';");
        await MigrateDatabaseAsync(scenario.AdminConnectionString, previousMigration);
        await MigrateDatabaseAsync(scenario.AdminConnectionString, currentMigration);
    }

    /// <summary>TKT-001783 RED: a verified administrative RELEASE persists the remembered-decision registry.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_AdminRelease_CreatesRememberedDecisionRegistry")]
    public async Task Tkt001783_AdminRelease_CreatesRememberedDecisionRegistry()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('6');
        using var scenario = prepared.Scenario;
        var released = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT pg_catalog.to_regclass('public.\"SecurityLockReleaseDecisions\"') IS NOT NULL", connection);
        Assert.True(Convert.ToBoolean(await command.ExecuteScalarAsync()));
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var decision = await check.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync();
        Assert.True(decision.IsActive);
        Assert.Equal(scenario.Fixture.ProductId, decision.ProductId);
        Assert.Equal("NATIVE_DLL_REPLACED", decision.Cause);
        Assert.Equal("alice", decision.CreatedBy);
        Assert.False(await check.SecurityLockReleaseDecisions.AsNoTracking().AnyAsync(row => row.ProductId == scenario.Fixture.ProductId && row.LicenseId == decision.LicenseId && row.HardwareId == decision.HardwareId.ToLowerInvariant() && row.Cause == decision.Cause));
        Assert.False(await check.SecurityLockReleaseDecisions.AsNoTracking().AnyAsync(row => row.ProductId == scenario.Fixture.ProductId && row.LicenseId == decision.LicenseId && row.HardwareId == decision.HardwareId && row.Cause == decision.Cause + " "));
        await using var indexCommand = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_indexes
                WHERE schemaname = 'public'
                  AND tablename = 'SecurityLockReleaseDecisions'
                  AND indexdef LIKE '%("ProductId", "LicenseId", "HardwareId", "Cause")%'
                  AND indexdef LIKE 'CREATE UNIQUE INDEX%')
            """, connection);
        Assert.True(Convert.ToBoolean(await indexCommand.ExecuteScalarAsync()));
        await using var explainTransaction = await connection.BeginTransactionAsync();
        await using (var planner = new NpgsqlCommand("SET LOCAL enable_seqscan = off;", connection, explainTransaction))
            await planner.ExecuteNonQueryAsync();
        await using var explain = new NpgsqlCommand("""
            EXPLAIN (FORMAT TEXT)
            SELECT *
            FROM public."SecurityLockReleaseDecisions"
            WHERE "ProductId" = @product
              AND "LicenseId" = @license
              AND "HardwareId" = @hardware
              AND "Cause" = @cause
              AND "IsActive";
            """, connection, explainTransaction);
        explain.Parameters.AddWithValue("product", decision.ProductId);
        explain.Parameters.AddWithValue("license", decision.LicenseId);
        explain.Parameters.AddWithValue("hardware", decision.HardwareId);
        explain.Parameters.AddWithValue("cause", decision.Cause);
        var plan = new List<string>();
        await using (var reader = await explain.ExecuteReaderAsync())
            while (await reader.ReadAsync())
                plan.Add(reader.GetString(0));
        Assert.Contains(plan, line => line.Contains("IX_SecurityLockReleaseDecisions_ProductId_LicenseId_HardwareId~", StringComparison.Ordinal));
        await explainTransaction.RollbackAsync();
    }

    /// <summary>
    /// The production database role must be able to persist and revoke a remembered decision without receiving
    /// DELETE or TRUNCATE authority over the new registry.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_ProductionRole_CanReleaseAndRevokeWithLeastPrivilege")]
    public async Task Tkt001783_ProductionRole_CanReleaseAndRevokeWithLeastPrivilege()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('f');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        var productionConnection = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only",
            Pooling = false
        }.ConnectionString;
        var productionFactory = new TestDbFactory(productionConnection);
        var productionAdmin = new SecurityLockAdminService(productionFactory, new RuntimeEnrollmentAuthorityService(productionFactory, Options.Create(scenario.Options)));
        var released = await productionAdmin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "production-role", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        var decisionId = Assert.IsType<Guid>(released.Row!.RememberedReleaseDecisionId);
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var productionRuntime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto, productionFactory);
        int deliveriesBeforeRecurrence;
        await using (var beforeRecurrence = await scenario.Factory.CreateDbContextAsync())
            deliveriesBeforeRecurrence = await beforeRecurrence.SecurityLockAlertDeliveries.CountAsync();
        var rememberedLock = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", '2');
        var rememberedDigest = Sha256("tkt001783-production-remembered-" + Guid.NewGuid().ToString("D"));
        Assert.Equal(SecurityLockVerdicts.Release, (await productionRuntime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, rememberedDigest, rememberedLock, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, rememberedLock.ReportId!, rememberedDigest, scenario.Options), IPAddress.Loopback)).Response.Verdict);
        await using (var afterRecurrence = await scenario.Factory.CreateDbContextAsync())
            Assert.Equal(deliveriesBeforeRecurrence, await afterRecurrence.SecurityLockAlertDeliveries.CountAsync());
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await productionAdmin.RevokeRememberedReleaseAsync(decisionId, "production-role", scenario.Fixture.ProductId));
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await productionAdmin.SetPolicyAsync(scenario.Fixture.ProductId, "NATIVE_DLL_REPLACED", "SHADOW", "production-role"));
        var shadowLock = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", '3');
        var shadowDigest = Sha256("tkt001783-production-shadow-" + Guid.NewGuid().ToString("D"));
        Assert.Equal(SecurityLockVerdicts.Release, (await productionRuntime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, shadowDigest, shadowLock, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, shadowLock.ReportId!, shadowDigest, scenario.Options), IPAddress.Loopback)).Response.Verdict);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await productionAdmin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "SHADOW", "production-role"));
        var shadowCanary = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger"];
        await SendTkt001802CanaryAsync(productionRuntime, scenario, shadowCanary, "production-role-shadow-canary");
        await using (var afterShadow = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Equal(deliveriesBeforeRecurrence + 1, await afterShadow.SecurityLockAlertDeliveries.CountAsync());
            Assert.Equal("MODE_SHADOW", (await afterShadow.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == shadowCanary.EventId)).NonBlockingReason);
        }

        await using var connection = new NpgsqlConnection(productionConnection);
        await connection.OpenAsync();
        await using var privileges = new NpgsqlCommand("""
            SELECT pg_catalog.has_table_privilege(current_user,
                       'public."SecurityLockReleaseDecisions"', 'SELECT,INSERT')
               AND NOT pg_catalog.has_table_privilege(current_user,
                       'public."SecurityLockReleaseDecisions"', 'UPDATE')
               AND NOT pg_catalog.has_table_privilege(current_user,
                       'public."SecurityLockReleaseDecisions"', 'DELETE,TRUNCATE')
               AND pg_catalog.has_column_privilege(current_user,
                       'public."SecurityLockReleaseDecisions"', 'IsActive', 'UPDATE')
               AND pg_catalog.has_column_privilege(current_user,
                       'public."SecurityLockReleaseDecisions"', 'SourceSecurityLockReportId', 'UPDATE')
               AND NOT pg_catalog.has_column_privilege(current_user,
                       'public."SecurityLockReleaseDecisions"', 'HardwareId', 'UPDATE')
               AND pg_catalog.has_column_privilege(current_user,
                       'public."SecurityLockReports"', 'RememberedReleaseDecisionId', 'UPDATE');
            """, connection);
        Assert.True(Convert.ToBoolean(await privileges.ExecuteScalarAsync()));
    }

    /// <summary>
    /// Downgrading the remembered-release migration advances every enrollment in the stable pair beyond all
    /// synthetic recoveries, so the previous application can create the next Recovery without an epoch collision.
    /// </summary>
    /// <param name = "hasPreexistingRecovery">Whether the pair already owns a Recovery at the active epoch.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_MigrationDown_PreservesPairWideRecoveryContinuity")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt001783_MigrationDown_PreservesPairWideRecoveryContinuity(bool hasPreexistingRecovery)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        Guid activeEnrollmentId;
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await seed.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            activeEnrollmentId = enrollment.Id;
            enrollment.SecurityEpoch = 10;
            var second = new RuntimeEnrollment();
            seed.Entry(second).CurrentValues.SetValues(enrollment);
            second.Id = Guid.NewGuid();
            second.State = "INVALIDATED";
            second.SecurityEpoch = 9;
            second.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-5);
            second.InvalidationReason = "TKT-001783 rollback fixture";
            var third = new RuntimeEnrollment();
            seed.Entry(third).CurrentValues.SetValues(enrollment);
            third.Id = Guid.NewGuid();
            third.State = "INVALIDATED";
            third.SecurityEpoch = 8;
            third.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
            third.InvalidationReason = "TKT-001783 rollback fixture";
            seed.RuntimeEnrollments.AddRange(second, third);
            var openedAt = DateTime.UtcNow.AddMinutes(-3);
            seed.RuntimeCriticalIncidents.AddRange(new RuntimeCriticalIncident { EnrollmentId = second.Id, BindingId = second.BindingId, ProductId = second.ProductId, InstallationId = second.InstallationId, EventId = "00000000-0000-0000-0000-000000000001", Trigger = "RuntimeCheck_Debugger", State = "WAIVED", OpenedSecurityEpoch = 9, OpenedAuthorityEpoch = second.AuthorityEpoch, OpenedAtUtc = openedAt, NonBlockingReason = "MODE_SHADOW" }, new RuntimeCriticalIncident { EnrollmentId = third.Id, BindingId = third.BindingId, ProductId = third.ProductId, InstallationId = third.InstallationId, EventId = "00000000-0000-0000-0000-000000000002", Trigger = "RuntimeCheck_Debugger", State = "WAIVED", OpenedSecurityEpoch = 8, OpenedAuthorityEpoch = third.AuthorityEpoch, OpenedAtUtc = openedAt.AddSeconds(1), NonBlockingReason = "MODE_SHADOW" });
            if (hasPreexistingRecovery)
            {
                seed.RuntimeCriticalRecoveries.Add(new RuntimeCriticalRecovery { EnrollmentId = enrollment.Id, BindingId = enrollment.BindingId, ProductId = enrollment.ProductId, InstallationId = enrollment.InstallationId, RequestedEventId = "00000000-0000-0000-0000-000000000099", OldSecurityEpoch = 9, NewSecurityEpoch = 10, ResolvedIncidentCount = 1, AuthorityEpoch = enrollment.AuthorityEpoch, RecoveredByClientId = "preexisting-recovery", RecoveredByKeyId = "tkt-001783-preexisting", Source = RuntimeCriticalRecoverySources.S2S, RecoveredAtUtc = openedAt.AddMinutes(-1) });
            }

            await seed.SaveChangesAsync();
        }

        await using (var migration = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
            await migration.GetService<IMigrator>().MigrateAsync("20261012125400_AddTkt001782AdminCriticalRecovery");
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT incident."State", incident."RecoveryId" IS NOT NULL,
                   recovery."RecoveredByClientId", recovery."RecoveredByKeyId",
                   recovery."NewSecurityEpoch"
            FROM public."RuntimeCriticalIncidents" incident
            JOIN public."RuntimeCriticalRecoveries" recovery ON recovery."Id" = incident."RecoveryId"
            WHERE recovery."RecoveredByKeyId" = 'tkt-001783-waived'
            ORDER BY recovery."NewSecurityEpoch";
            """, connection);
        await using var reader = await command.ExecuteReaderAsync();
        var epochs = new List<long>();
        while (await reader.ReadAsync())
        {
            Assert.Equal("RESOLVED", reader.GetString(0));
            Assert.True(reader.GetBoolean(1));
            Assert.Equal("migration-rollback", reader.GetString(2));
            Assert.Equal("tkt-001783-waived", reader.GetString(3));
            epochs.Add(reader.GetInt32(4));
        }

        await reader.DisposeAsync();
        Assert.Equal(2, epochs.Count);
        Assert.Equal(epochs.Count, epochs.Distinct().Count());
        Assert.True(epochs.Zip(epochs.Skip(1), (left, right) => left < right).All(value => value));
        var maximumSyntheticEpoch = epochs.Max();
        await using (var enrollmentEpochs = new NpgsqlCommand("""
            SELECT "Id", "SecurityEpoch"
            FROM public."RuntimeEnrollments"
            WHERE "BindingId" = @binding AND "InstallationId" = @installation;
            """, connection))
        {
            enrollmentEpochs.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
            enrollmentEpochs.Parameters.AddWithValue("installation", scenario.Fixture.InstallationId);
            await using var epochReader = await enrollmentEpochs.ExecuteReaderAsync();
            var observed = new Dictionary<Guid, int>();
            while (await epochReader.ReadAsync())
                observed.Add(epochReader.GetGuid(0), epochReader.GetInt32(1));
            Assert.Equal(3, observed.Count);
            Assert.Equal(maximumSyntheticEpoch, observed[activeEnrollmentId]);
            Assert.All(observed.Values, epoch => Assert.True(epoch >= maximumSyntheticEpoch));
        }

        // The downgraded schema belongs to the previous application version. Reproduce its atomic Recovery write
        // directly so this migration test proves the persisted generation is immediately usable without loading
        // current-model columns that the Down migration intentionally removed.
        await using var nextRecovery = new NpgsqlCommand("""
            WITH current_enrollment AS (
                SELECT "Id", "BindingId", "ProductId", "InstallationId", "SecurityEpoch", "AuthorityEpoch"
                FROM public."RuntimeEnrollments"
                WHERE "Id" = @enrollment
                FOR UPDATE
            ), inserted AS (
                INSERT INTO public."RuntimeCriticalRecoveries"
                    ("Id", "EnrollmentId", "BindingId", "ProductId", "InstallationId", "RequestedEventId",
                     "OldSecurityEpoch", "NewSecurityEpoch", "ResolvedIncidentCount", "AuthorityEpoch",
                     "RecoveredByClientId", "RecoveredByKeyId", "Source", "SecurityLockReportId",
                     "RecoveredByAdmin", "RecoveredAtUtc")
                SELECT @recovery, "Id", "BindingId", "ProductId", "InstallationId", @event,
                       "SecurityEpoch", "SecurityEpoch" + 1, 1, "AuthorityEpoch",
                       'post-down-client', 'post-down-key', 'S2S', NULL, NULL, pg_catalog.clock_timestamp()
                FROM current_enrollment
                RETURNING "NewSecurityEpoch"
            )
            UPDATE public."RuntimeEnrollments" enrollment
            SET "SecurityEpoch" = inserted."NewSecurityEpoch"
            FROM inserted
            WHERE enrollment."Id" = @enrollment
            RETURNING inserted."NewSecurityEpoch";
            """, connection);
        nextRecovery.Parameters.AddWithValue("enrollment", activeEnrollmentId);
        nextRecovery.Parameters.AddWithValue("recovery", Guid.NewGuid());
        nextRecovery.Parameters.AddWithValue("event", Guid.NewGuid().ToString("D"));
        Assert.Equal(maximumSyntheticEpoch + 1, Convert.ToInt32(await nextRecovery.ExecuteScalarAsync()));
    }

    /// <summary>
    /// A verified report may close incidents after its seat moved, but the immutable reported hardware must never
    /// authorize a remembered decision for the seat's new hardware.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_AdminRelease_AfterSeatHardwareDrift_SkipsRememberedDecision")]
    public async Task Tkt001783_AdminRelease_AfterSeatHardwareDrift_SkipsRememberedDecision()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('0');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var report = await mutate.SecurityLockReports.SingleAsync(row => row.Id == prepared.ReportId);
            var seat = await mutate.LicenseSeats.SingleAsync(row => row.Id == report.LinkLicenseSeatId);
            seat.HardwareId = "AAAAAAAAAAAAAAAA";
            await mutate.SaveChangesAsync();
        }

        var released = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        Assert.Equal("remembered_release_hardware_changed", released.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await check.SecurityLockReleaseDecisions.AsNoTracking().ToListAsync());
        Assert.Null((await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId)).RememberedReleaseDecisionId);
        Assert.False(await check.RuntimeCriticalIncidents.AnyAsync(row => row.State == "OPEN"));
    }

    /// <summary>
    /// A remembered decision covers a new exact-cause lock and the mapped canary without blocking, then revocation
    /// makes the following lock use REVIEW again.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_RememberedRelease_CoversLockAndCanary_UntilRevoked")]
    public async Task Tkt001783_RememberedRelease_CoversLockAndCanary_UntilRevoked()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('7', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId)).Outcome);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "ENFORCE", "alice"));
        var initialEpoch = await ReadSecurityEpochAsync(scenario);
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger", "RuntimeCheck_NativeDllSwapped"];
        using var acknowledgementKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["CanaryAck:PrivateKeyPem"] = acknowledgementKey.ExportPkcs8PrivateKeyPem() }).Build();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(scenario.Factory, new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)), new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)), crypto, Options.Create(scenario.Options), new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var recurrence = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "ENFORCE", '8');
        var recurrenceDigest = Sha256("tkt001783-lock-" + Guid.NewGuid().ToString("D"));
        var lockVerdict = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, recurrenceDigest, recurrence, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, recurrence.ReportId!, recurrenceDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, lockVerdict.Response.Verdict);
        var repeatedLock = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "ENFORCE", 'd');
        var repeatedDigest = Sha256("tkt001783-repeated-lock-" + Guid.NewGuid().ToString("D"));
        var repeatedVerdict = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, repeatedDigest, repeatedLock, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, repeatedLock.ReportId!, repeatedDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, repeatedVerdict.Response.Verdict);
        var canary = new CanaryPingRequest
        {
            Schema = CanaryAckService.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
            HardwareId = LegacyHardwareId,
            AppVersion = scenario.Fixture.Version,
            Trigger = "RuntimeCheck_Debugger",
            Severity = 3
        };
        var canaryDigest = Sha256("tkt001783-canary-" + Guid.NewGuid().ToString("D"));
        var canaryAck = await runtime.ProcessCanaryAsync(scenario.EnrollmentId, canaryDigest, canary, CanaryProof(scenario.EnrollmentKey, scenario.EnrollmentId, canary.EventId!, canaryDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal("ack", canaryAck.Response.Decision);
        await AssertTkt001802CapabilityAvailableAsync(runtime, scenario, "remembered-release");
        var otherCause = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", 'a');
        var otherCauseDigest = Sha256("tkt001783-other-cause-" + Guid.NewGuid().ToString("D"));
        var otherCauseVerdict = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, otherCauseDigest, otherCause, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, otherCause.ReportId!, otherCauseDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, otherCauseVerdict.Response.Verdict);
        Guid decisionId;
        await using (var covered = await scenario.Factory.CreateDbContextAsync())
        {
            var decision = await covered.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync();
            decisionId = decision.Id;
            Assert.Equal(3, decision.CoveredDetectionCount);
            Assert.NotNull(decision.LastCoveredAtUtc);
            var recurrenceRow = await covered.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == recurrence.LockId);
            Assert.Equal(SecurityLockReportStates.Released, recurrenceRow.State);
            Assert.Equal(1, recurrenceRow.ReportCount);
            Assert.Equal(decisionId, recurrenceRow.RememberedReleaseDecisionId);
            Assert.Equal(3, await covered.SecurityLockReports.AsNoTracking().CountAsync(row => row.RememberedReleaseDecisionId == decisionId));
            var incident = await covered.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == canary.EventId);
            Assert.Equal("WAIVED", incident.State);
            Assert.Equal("REMEMBERED_RELEASE", incident.NonBlockingReason);
            Assert.Equal(decisionId, incident.RememberedReleaseDecisionId);
            Assert.False(await covered.RuntimeCriticalIncidents.AnyAsync(row => row.State == "OPEN"));
            Assert.Empty(await covered.RuntimeCriticalRecoveries.ToListAsync());
            Assert.Single(await covered.CanaryAlerts.Where(row => row.Trigger == "RuntimeCheck_Debugger").ToListAsync());
            Assert.Null((await covered.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == otherCause.LockId)).RememberedReleaseDecisionId);
        }

        Assert.Equal(initialEpoch, await ReadSecurityEpochAsync(scenario));
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.RevokeRememberedReleaseAsync(decisionId, "alice", scenario.Fixture.ProductId));
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "REVIEW", "alice"));
        var afterRevoke = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", '9');
        var afterRevokeDigest = Sha256("tkt001783-after-revoke-" + Guid.NewGuid().ToString("D"));
        var blocked = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, afterRevokeDigest, afterRevoke, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, afterRevoke.ReportId!, afterRevokeDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, blocked.Response.Verdict);
        Guid afterRevokeReportId;
        await using (var final = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.False((await final.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync()).IsActive);
            var afterRevokeRow = await final.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == afterRevoke.LockId);
            afterRevokeReportId = afterRevokeRow.Id;
            Assert.Equal(SecurityLockReportStates.Open, afterRevokeRow.State);
        }

        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(afterRevokeReportId, SecurityLockAdminDecisions.Release, null, "reactivation-admin", scenario.Fixture.ProductId)).Outcome);
        await using var reactivated = await scenario.Factory.CreateDbContextAsync();
        var reactivatedDecision = await reactivated.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync();
        Assert.Equal(decisionId, reactivatedDecision.Id);
        Assert.True(reactivatedDecision.IsActive);
        Assert.Equal(2, reactivatedDecision.ActivationCount);
        Assert.Equal("reactivation-admin", reactivatedDecision.ActivatedBy);
    }

    /// <summary>A remembered decision for another licence cannot release a signed Runtime report.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_RememberedRelease_ForeignLicenseScopeDoesNotCoverRuntimeReport")]
    public async Task Tkt001783_RememberedRelease_ForeignLicenseScopeDoesNotCoverRuntimeReport()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('e', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId)).Outcome);
        await using (var scope = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var source = await scope.Licenses.AsNoTracking().SingleAsync();
            var foreign = new License();
            scope.Entry(foreign).CurrentValues.SetValues(source);
            foreign.Id = Guid.NewGuid();
            foreign.LicenseKey = Guid.NewGuid().ToString("D");
            foreign.AuthorityVersion = Guid.NewGuid();
            scope.Licenses.Add(foreign);
            await scope.SaveChangesAsync();
            var decision = await scope.SecurityLockReleaseDecisions.SingleAsync();
            decision.LicenseId = foreign.Id;
            await scope.SaveChangesAsync();
        }

        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var report = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", 'f');
        var digest = Sha256("tkt001783-foreign-license-runtime-" + Guid.NewGuid().ToString("D"));
        var result = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, digest, report, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, report.ReportId!, digest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, result.Response.Verdict);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Null((await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == report.LockId)).RememberedReleaseDecisionId);
    }

    /// <summary>
    /// A signed Runtime report uses the valid ACTIVE assignment license, not the enrollment's legacy license copy,
    /// when it searches for remembered release authority.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_RememberedRelease_LegacyEnrollmentLicenseDoesNotCoverRuntimeReport")]
    public async Task Tkt001783_RememberedRelease_LegacyEnrollmentLicenseDoesNotCoverRuntimeReport()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('4', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId)).Outcome);
        var licenses = await MoveActiveAssignmentToNewLicenseAsync(scenario);
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var report = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", '5');
        var digest = Sha256("tkt001783-legacy-license-report-" + Guid.NewGuid().ToString("D"));
        var result = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, digest, report, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, report.ReportId!, digest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, result.Response.Verdict);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignment = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var stored = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == report.LockId);
        var decision = await check.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync();
        Assert.Equal(licenses.LegacyLicenseId, enrollment.LicenseId);
        Assert.Equal(licenses.ActiveLicenseId, assignment.LicenseId);
        Assert.Equal(licenses.LegacyLicenseId, decision.LicenseId);
        Assert.True(decision.IsActive);
        Assert.Equal(SecurityLockReportStates.Open, stored.State);
        Assert.Equal(SecurityLockReportLinkStatuses.VerifiedSeat, stored.LinkStatus);
        Assert.Null(stored.RememberedReleaseDecisionId);
    }

    /// <summary>
    /// An authenticated Canary uses the valid ACTIVE assignment license, not the enrollment's legacy license copy,
    /// when it searches for remembered release authority.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_RememberedRelease_LegacyEnrollmentLicenseDoesNotWaiveCanary")]
    public async Task Tkt001783_RememberedRelease_LegacyEnrollmentLicenseDoesNotWaiveCanary()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('6', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId)).Outcome);
        var licenses = await MoveActiveAssignmentToNewLicenseAsync(scenario);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, await prepared.Admin.SetPolicyAsync(scenario.Fixture.ProductId, "DEBUGGER_ATTACHED_KERNEL", "ENFORCE", "alice"));
        scenario.Options.CanaryTriggers = ["RuntimeCheck_Debugger"];
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var canary = Tkt001802Canary(scenario, "RuntimeCheck_Debugger", 3);
        await SendTkt001802CanaryAsync(runtime, scenario, canary, "legacy-license-assignment");
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignment = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var decision = await check.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync();
        var incident = await check.RuntimeCriticalIncidents.AsNoTracking().SingleAsync(row => row.EventId == canary.EventId);
        Assert.Equal(licenses.LegacyLicenseId, enrollment.LicenseId);
        Assert.Equal(licenses.ActiveLicenseId, assignment.LicenseId);
        Assert.Equal(licenses.LegacyLicenseId, decision.LicenseId);
        Assert.True(decision.IsActive);
        Assert.Equal("OPEN", incident.State);
        Assert.Null(incident.NonBlockingReason);
        Assert.Null(incident.RememberedReleaseDecisionId);
        Assert.Null((await check.CanaryAlerts.AsNoTracking().SingleAsync(row => row.Trigger == "RuntimeCheck_Debugger")).Details);
    }

    /// <summary>A different machine cannot gain remembered authority by copying its HWID into the signed body.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_RememberedRelease_SpoofedBodyHardwareDoesNotCoverDifferentMachine")]
    public async Task Tkt001783_RememberedRelease_SpoofedBodyHardwareDoesNotCoverDifferentMachine()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('0', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId)).Outcome);
        await using (var moveSeat = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var seat = await moveSeat.LicenseSeats.SingleAsync(row => row.IsActive);
            seat.HardwareId = "AAAAAAAAAAAAAAAA";
            await moveSeat.SaveChangesAsync();
        }

        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var report = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", '1');
        var digest = Sha256("tkt001783-spoofed-hwid-runtime-" + Guid.NewGuid().ToString("D"));
        var result = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, digest, report, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, report.ReportId!, digest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, result.Response.Verdict);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var stored = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == report.LockId);
        Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, stored.LinkStatus);
        Assert.Null(stored.RememberedReleaseDecisionId);
    }

    /// <summary>A legitimate same-machine reinstallation remains covered through the signed Runtime path.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_RememberedRelease_CoversLegitimateSameMachineReinstallation")]
    public async Task Tkt001783_RememberedRelease_CoversLegitimateSameMachineReinstallation()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('2', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId)).Outcome);
        Guid decisionId;
        await using (var readDecision = await scenario.Factory.CreateDbContextAsync())
            decisionId = await readDecision.SecurityLockReleaseDecisions.AsNoTracking().Select(row => row.Id).SingleAsync();
        var activeEnrollmentId = await ReinstallPreparedEnrollmentAsync(scenario);
        using var acknowledgementKey = RSA.Create(2048);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = CreateTkt001802Runtime(scenario, acknowledgementKey, crypto);
        var report = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW", '3');
        var digest = Sha256("tkt001783-legitimate-reinstall-runtime-" + Guid.NewGuid().ToString("D"));
        var result = await runtime.ProcessSecurityLockReportAsync(activeEnrollmentId, digest, report, LockProof(scenario.EnrollmentKey, activeEnrollmentId, report.ReportId!, digest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Release, result.Response.Verdict);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var stored = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.LockId == report.LockId);
        Assert.Equal(SecurityLockReportLinkStatuses.VerifiedSeat, stored.LinkStatus);
        Assert.Equal(decisionId, stored.RememberedReleaseDecisionId);
    }

    /// <summary>An unverified report can be released once but never creates a remembered authority decision.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_AdminRelease_UnverifiedHardware_DoesNotCreateRememberedDecision")]
    public async Task Tkt001783_AdminRelease_UnverifiedHardware_DoesNotCreateRememberedDecision()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('b', hardwareId: "FFFFFFFFFFFFFFFF");
        using var scenario = prepared.Scenario;
        var released = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await check.SecurityLockReleaseDecisions.AsNoTracking().ToListAsync());
        var report = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId);
        Assert.Equal(SecurityLockReportLinkStatuses.Unlinked, report.LinkStatus);
        Assert.Null(report.RememberedReleaseDecisionId);
    }

    /// <summary>An explicit BAN revokes the exact remembered RELEASE before future detections can use it.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001783_AdminBan_RevokesRememberedDecision")]
    public async Task Tkt001783_AdminBan_RevokesRememberedDecision()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('c', "DEBUGGER_ATTACHED_KERNEL", 5, "REVIEW");
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "release-admin", scenario.Fixture.ProductId)).Outcome);
        var banned = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Ban, null, "ban-admin", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, banned.Outcome);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var decision = await check.SecurityLockReleaseDecisions.AsNoTracking().SingleAsync();
        Assert.False(decision.IsActive);
        Assert.Equal("ban-admin", decision.RevokedBy);
        Assert.Equal(SecurityLockReportStates.Banned, (await check.SecurityLockReports.AsNoTracking().SingleAsync()).State);
        Assert.Single(await check.BannedHardwareIds.AsNoTracking().Where(row => row.IsActive).ToListAsync());
    }

    /// <summary>
    /// TKT-001782: an administrator RELEASE closes every incident in the exact authenticated
    /// installation and advances its security generation in the same transaction.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_ClosesExactIncidentsAndAdvancesSecurityEpoch")]
    public async Task Tkt001782_AdminRelease_ClosesExactIncidentsAndAdvancesSecurityEpoch()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var acknowledgementKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["CanaryAck:PrivateKeyPem"] = acknowledgementKey.ExportPkcs8PrivateKeyPem() }).Build();
        var authority = new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var runtime = new RuntimeEnrollmentService(scenario.Factory, authority, new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)), crypto, Options.Create(scenario.Options), new CanaryAckService(scenario.Factory, configuration, TimeProvider.System));
        var report = LockRequest(LegacyHardwareId, scenario.Fixture.Version, "NATIVE_DLL_REPLACED", 4, "REVIEW", '1');
        var reportDigest = Sha256("tkt001782-release-report-" + Guid.NewGuid().ToString("D"));
        var verdict = await runtime.ProcessSecurityLockReportAsync(scenario.EnrollmentId, reportDigest, report, LockProof(scenario.EnrollmentKey, scenario.EnrollmentId, report.ReportId!, reportDigest, scenario.Options), IPAddress.Loopback);
        Assert.Equal(SecurityLockVerdicts.Maintain, verdict.Response.Verdict);
        var eventId = await OpenPreparedCriticalIncidentAsync(scenario);
        Guid reportId;
        int oldSecurityEpoch;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            reportId = await before.SecurityLockReports.AsNoTracking().Where(row => row.LockId == report.LockId).Select(row => row.Id).SingleAsync();
            oldSecurityEpoch = await before.RuntimeEnrollments.AsNoTracking().Where(row => row.Id == scenario.EnrollmentId).Select(row => row.SecurityEpoch).SingleAsync();
        }

        var admin = new SecurityLockAdminService(scenario.Factory, new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)));
        var released = await admin.DecideAsync(reportId, SecurityLockAdminDecisions.Release, "TKT-001782 regression", "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        await using var after = await scenario.Factory.CreateDbContextAsync();
        var storedReport = await after.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == reportId);
        Assert.Equal(SecurityLockReportStates.Released, storedReport.State);
        Assert.False(await after.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(incident => incident.EnrollmentId == scenario.EnrollmentId && incident.BindingId == scenario.Fixture.BindingId && incident.InstallationId == scenario.Fixture.InstallationId && incident.State == "OPEN"));
        var recovery = await after.RuntimeCriticalRecoveries.AsNoTracking().SingleAsync();
        Assert.Equal(eventId, recovery.RequestedEventId);
        Assert.Equal(1, recovery.ResolvedIncidentCount);
        Assert.Equal(oldSecurityEpoch, recovery.OldSecurityEpoch);
        Assert.Equal(oldSecurityEpoch + 1, recovery.NewSecurityEpoch);
        Assert.Equal(RuntimeCriticalRecoverySources.AdminRelease, recovery.Source);
        Assert.Equal(reportId, recovery.SecurityLockReportId);
        Assert.Equal("alice", recovery.RecoveredByAdmin);
        Assert.Equal(oldSecurityEpoch + 1, await after.RuntimeEnrollments.AsNoTracking().Where(row => row.Id == scenario.EnrollmentId).Select(row => row.SecurityEpoch).SingleAsync());
        Assert.Empty(await after.RuntimeCriticalRecoveryReceipts.AsNoTracking().ToListAsync());
    }

    /// <summary>A RELEASE without an open incident changes no generation and creates no recovery.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_WithoutIncident_DoesNotAdvanceSecurityEpoch")]
    public async Task Tkt001782_AdminRelease_WithoutIncident_DoesNotAdvanceSecurityEpoch()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('2');
        using var scenario = prepared.Scenario;
        var beforeEpoch = await ReadSecurityEpochAsync(scenario);
        var result = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, result.Outcome);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(SecurityLockReportStates.Released, (await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId)).State);
        Assert.Equal(beforeEpoch, await ReadSecurityEpochAsync(scenario));
        Assert.Empty(await check.RuntimeCriticalRecoveries.AsNoTracking().ToListAsync());
    }

    /// <summary>An old RELEASE remains actionable, while concurrent replay creates only one transition.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_AlreadyReleasedAndConcurrentReplay_IsIdempotent")]
    public async Task Tkt001782_AdminRelease_AlreadyReleasedAndConcurrentReplay_IsIdempotent()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('3');
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "first-admin", scenario.Fixture.ProductId)).Outcome);
        var beforeEpoch = await ReadSecurityEpochAsync(scenario);
        await OpenPreparedCriticalIncidentAsync(scenario);
        var first = new SecurityLockAdminService(scenario.Factory, new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)));
        var second = new SecurityLockAdminService(scenario.Factory, new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options)));
        var results = await Task.WhenAll(first.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "admin-a", scenario.Fixture.ProductId), second.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "admin-b", scenario.Fixture.ProductId));
        Assert.All(results, result => Assert.Equal(SecurityLockAdminOutcomes.Ok, result.Outcome));
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.RuntimeCriticalRecoveries.AsNoTracking().ToListAsync());
        Assert.False(await check.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(row => row.State == "OPEN"));
        Assert.Equal(beforeEpoch + 1, await ReadSecurityEpochAsync(scenario));
    }

    /// <summary>Every exact-scope incident is resolved by one recovery and one generation transition.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_ResolvesAllExactIncidentsOnce")]
    public async Task Tkt001782_AdminRelease_ResolvesAllExactIncidentsOnce()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('4');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        await OpenPreparedCriticalIncidentAsync(scenario);
        var beforeEpoch = await ReadSecurityEpochAsync(scenario);
        var result = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, "bulk close", "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, result.Outcome);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var recovery = await check.RuntimeCriticalRecoveries.AsNoTracking().SingleAsync();
        Assert.Equal(2, recovery.ResolvedIncidentCount);
        Assert.Equal(2, await check.RuntimeCriticalIncidents.AsNoTracking().CountAsync(row => row.State == "RESOLVED" && row.RecoveryId == recovery.Id));
        Assert.Equal(beforeEpoch + 1, await ReadSecurityEpochAsync(scenario));
    }

    /// <summary>
    /// Administrative release follows the stable binding and installation across historical enrollments, and its
    /// receipt names the newest incident that Desktop is most likely waiting to clear.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_ClosesHistoricalEnrollmentAndNamesNewestIncident")]
    public async Task Tkt001782_AdminRelease_ClosesHistoricalEnrollmentAndNamesNewestIncident()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('1');
        using var scenario = prepared.Scenario;
        var olderEvent = await OpenPreparedCriticalIncidentAsync(scenario);
        var newestEvent = await OpenPreparedCriticalIncidentAsync(scenario);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var current = await mutate.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
            var historical = new RuntimeEnrollment();
            mutate.Entry(historical).CurrentValues.SetValues(current);
            historical.Id = Guid.NewGuid();
            historical.State = "INVALIDATED";
            historical.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-5);
            historical.InvalidationReason = "TKT-001782 historical enrollment fixture";
            mutate.RuntimeEnrollments.Add(historical);
            var incidents = await mutate.RuntimeCriticalIncidents.Where(row => row.EventId == olderEvent || row.EventId == newestEvent).ToListAsync();
            var older = incidents.Single(row => row.EventId == olderEvent);
            older.OpenedAtUtc = DateTime.UtcNow.AddMinutes(-2);
            var newest = incidents.Single(row => row.EventId == newestEvent);
            newest.EnrollmentId = historical.Id;
            newest.OpenedAtUtc = DateTime.UtcNow.AddMinutes(-1);
            await mutate.SaveChangesAsync();
        }

        var released = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var recovery = await check.RuntimeCriticalRecoveries.AsNoTracking().SingleAsync();
        Assert.Equal(2, recovery.ResolvedIncidentCount);
        Assert.Equal(newestEvent, recovery.RequestedEventId);
        Assert.False(await check.RuntimeCriticalIncidents.AnyAsync(row => row.State == "OPEN"));
    }

    /// <summary>
    /// A report remains an administrative handle after re-enrollment, but recovery authority belongs to the
    /// current ACTIVE enrollment that can actually refetch the signed receipt and resume capability issuance.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_HistoricalReportTargetsActiveReEnrollment")]
    public async Task Tkt001782_AdminRelease_HistoricalReportTargetsActiveReEnrollment()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('9');
        using var scenario = prepared.Scenario;
        var activeEnrollmentId = await ReinstallPreparedEnrollmentAsync(scenario);
        var eventId = await OpenCriticalIncidentAsync(scenario, activeEnrollmentId);
        var released = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var recovery = await check.RuntimeCriticalRecoveries.AsNoTracking().SingleAsync();
            Assert.Equal(activeEnrollmentId, recovery.EnrollmentId);
            Assert.Equal(eventId, recovery.RequestedEventId);
            Assert.Equal(2, await check.RuntimeEnrollments.AsNoTracking().Where(row => row.Id == activeEnrollmentId).Select(row => row.SecurityEpoch).SingleAsync());
        }

        var refetchRequest = new RuntimeCriticalRecoveryClientRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryClientRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = activeEnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1
        };
        var refetchDigest = Sha256("tkt001782-reinstall-refetch-" + Guid.NewGuid().ToString("D"));
        var refetch = await scenario.Runtime.RefetchCriticalRecoveryForClientAsync(activeEnrollmentId, refetchDigest, refetchRequest, Proof(scenario.EnrollmentKey, "critical-recovery-refetch", activeEnrollmentId, scenario.Options.ConfirmAudience, "-", refetchDigest), IPAddress.Loopback);
        Assert.Equal(2, refetch.Response.NewSecurityEpoch);
        var capability = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = activeEnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 2,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var capabilityDigest = Sha256("tkt001782-reinstall-capability-" + Guid.NewGuid().ToString("D"));
        var issued = await scenario.Runtime.CreateCapabilityAsync(activeEnrollmentId, capabilityDigest, capability, Proof(scenario.EnrollmentKey, "capability", activeEnrollmentId, capability.Audience, "-", capabilityDigest), IPAddress.Loopback);
        Assert.NotNull(issued.Response.CapabilityToken);
    }

    /// <summary>The real admin page counts OPEN incidents by stable binding and installation across enrollments.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminUi_HistoricalReportShowsScopedIncidentCountInRowAndConfirmation")]
    public async Task Tkt001782_AdminUi_HistoricalReportShowsScopedIncidentCountInRowAndConfirmation()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('b');
        using var scenario = prepared.Scenario;
        var activeEnrollmentId = await ReinstallPreparedEnrollmentAsync(scenario);
        await OpenCriticalIncidentAsync(scenario, activeEnrollmentId);

        var activator = new Tkt1782SecurityLocksActivator();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization();
        services.AddSingleton<TimeZoneService>();
        services.AddSingleton<ToastService>();
        services.AddSingleton<IDbContextFactory<LicenseDbContext>>(scenario.Factory);
        services.AddSingleton(new AuthService(new Tkt1782RootAuthentication()));
        services.AddSingleton(prepared.Admin);
        services.AddSingleton<IComponentActivator>(activator);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var rendered = await renderer.RenderComponentAsync<SecurityLocksPage>();
            Assert.Contains("1 incident(s) critique(s) ouvert(s)", rendered.ToHtmlString(),
                StringComparison.Ordinal);
            var page = Assert.IsType<SecurityLocksPage>(activator.Page);
            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            page.GetType().GetMethod("RequestLockDecision", flags)!.Invoke(page,
                [prepared.ReportId, SecurityLockDecisionDialog.ReleaseAction]);
            typeof(ComponentBase).GetMethod("StateHasChanged", flags)!.Invoke(page, null);
            var dialog = Assert.IsType<SecurityLockDecisionDialog>(activator.Dialog);
            Assert.Equal(SecurityLockDecisionDialog.ReleaseAction, dialog.Request.Action);
            Assert.Equal(1, dialog.Request.OpenIncidentCount);
        });
    }

    /// <summary>No ACTIVE enrollment still permits auditable closure but explicitly reports that no receipt is deliverable.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_WithoutActiveEnrollment_ClosesForAuditWithoutDeliverableReceipt")]
    public async Task Tkt001782_AdminRelease_WithoutActiveEnrollment_ClosesForAuditWithoutDeliverableReceipt()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('c');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        await using (var invalidate = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            var enrollment = await invalidate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "TKT-001782 no active enrollment fixture";
            var assignment = await invalidate.EnrollmentLicenseAssignments.SingleAsync(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE");
            assignment.State = "ENDED";
            assignment.EndedAtUtc = DateTime.UtcNow;
            assignment.EndReason = "TKT-001782 no active enrollment fixture";
            await invalidate.SaveChangesAsync();
        }

        var released = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, released.Outcome);
        Assert.Equal("release_no_active_enrollment", released.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.False(await check.RuntimeCriticalIncidents.AnyAsync(row => row.State == "OPEN"));
        Assert.Single(await check.RuntimeCriticalRecoveries.AsNoTracking().ToListAsync());
    }

    /// <summary>A future-generation incident aborts both the recovery and the lock RELEASE.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001782_AdminRelease_GenerationConflict_RollsBackDecision")]
    public async Task Tkt001782_AdminRelease_GenerationConflict_RollsBackDecision()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('5');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var incident = await mutate.RuntimeCriticalIncidents.SingleAsync();
            incident.OpenedSecurityEpoch += 1;
            await mutate.SaveChangesAsync();
        }

        var beforeEpoch = await ReadSecurityEpochAsync(scenario);
        var result = await prepared.Admin.DecideAsync(prepared.ReportId, SecurityLockAdminDecisions.Release, null, "alice", scenario.Fixture.ProductId);
        Assert.Equal(SecurityLockAdminOutcomes.RecoveryConflict, result.Outcome);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var report = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId);
        Assert.Equal(SecurityLockReportStates.Open, report.State);
        Assert.Null(report.AdminDecision);
        Assert.Single(await check.RuntimeCriticalIncidents.AsNoTracking().Where(row => row.State == "OPEN").ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveries.AsNoTracking().ToListAsync());
        Assert.Equal(beforeEpoch, await ReadSecurityEpochAsync(scenario));
    }
}
