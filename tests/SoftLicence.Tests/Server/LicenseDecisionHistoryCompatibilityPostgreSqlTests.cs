using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;
using Npgsql;

namespace SoftLicence.Tests.Server;

/// <summary>Routes the seven unchanged early-refusal contract executions to real PostgreSQL and separately checks the configured InMemory test mode.</summary>
[Collection(Tkt976DecisionRelationalCollection.Name)]
public sealed partial class DistributionInstallationBindingServiceTests
{
    /// <summary>Identifies a deliberately provisioned PostgreSQL or InMemory fixture; prevents recursive delegation from the historical SQLite test entry point.</summary>
    private readonly bool _tkt976NativeDecisionFixture;

    /// <summary>Seeds the original fixed synthetic inputs into an already isolated provider; the original public constructor still owns all other SQLite tests.</summary>
    /// <remarks>PostgreSQL schema and roles come from the migrated task harness. The unopened SQLite handle only satisfies the original fixture disposal contract; it stores no data. No business assertion or original method body changes.</remarks>
    private DistributionInstallationBindingServiceTests(DbContextOptions<LicenseDbContext> decisionOptions)
    {
        _tkt976NativeDecisionFixture = true;
        _keepAlive = new SqliteConnection("Data Source=:memory:");
        _options = decisionOptions;
        using (var db = new LicenseDbContext(_options))
        {
            if (!db.Database.IsRelational()) db.Database.EnsureCreated();
            Seed(db);
        }
        _service = new DistributionInstallationBindingService(new TestDbContextFactory(_options),
            new EphemeralDataProtectionProvider(), new FixedTimeProvider(Now), TestHardwareAuthorityAliasResolver.Instance);
    }

    /// <summary>Creates one migrated synthetic PostgreSQL clone per original scenario; no database is deleted during a campaign.</summary>
    /// <remarks>The existing harness requires explicit synthetic PostgreSQL configuration and its exact container finally owns all clone cleanup. Missing infrastructure fails visibly, never skips. Seven clones remain under the monitored768MiB bound.</remarks>
    private static async Task<DistributionInstallationBindingServiceTests> CreateTkt976DecisionPostgresFixtureAsync()
    {
        var connection = await RuntimeEnrollmentPostgreSqlTests.Tkt976_CloneCompatibilityDatabaseAsync();
        return new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);
    }

    /// <summary>Preserves the same early business refusal contracts in IsIntegrationTest's configured InMemory provider without claiming transaction, lock or crash durability.</summary>
    [Theory]
    [InlineData("grant")]
    [InlineData("handoff")]
    [InlineData("alias-unavailable")]
    [InlineData("alias-ambiguous")]
    [InlineData("graph-missing")]
    [InlineData("graph-diverged")]
    [InlineData("identity-missing")]
    public async Task Tkt976_InMemory_EarlyRefusalPreservesExistingBusinessContract(string scenario)
    {
        using var fixture = new DistributionInstallationBindingServiceTests(
            new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase("tkt976-decision-" + Guid.NewGuid().ToString("N")).Options);
        if (scenario == "grant") await fixture.Finalize_V2EntitlementForDifferentGrant_IsRejected();
        else if (scenario == "handoff") await fixture.Finalize_SameHandoffWithNewRequestId_FailsClosedOnGrantOwnershipMismatch();
        else
        {
            var (reason, code) = scenario switch
            {
                "alias-unavailable" => (HardwareAuthorityRefusalReason.AliasUnavailable, "alias_resolution_unavailable"),
                "alias-ambiguous" => (HardwareAuthorityRefusalReason.AmbiguousAlias, "alias_resolution_ambiguous"),
                "graph-missing" => (HardwareAuthorityRefusalReason.AuthorityGraphMissing, "authority_graph_missing"),
                "graph-diverged" => (HardwareAuthorityRefusalReason.AuthorityGraphDiverged, "authority_graph_diverged"),
                "identity-missing" => (HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired, "alias_reconciliation_identity_missing"),
                _ => throw new ArgumentException("Unknown synthetic case.")
            };
            await fixture.Finalize_HardwareAuthorityResolverGuard_EmitsExactBoundedDiagnostic(reason, code);
        }
        await using var db = new LicenseDbContext(fixture._options);
        Assert.Single(await db.LicenseHistories.Where(row => row.Action == "ACTIVATION_DECISION_V1"
            && row.Details!.Contains("\"outcome\":\"refused\"")).ToListAsync());
    }
}

/// <summary>Exposes only the existing migrated, synthetic clone operation to the exact seven compatibility scenarios.</summary>
[Collection(Tkt976DecisionRelationalCollection.Name)]
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Serializes creation of the empty compatibility template; existing Runtime fixture rows are never copied into historical empty-database assertions.</summary>
    private static readonly SemaphoreSlim Tkt976CompatibilityTemplateLock = new(1, 1);

    /// <summary>Owns only the dedicated migrated template connection pair for this synthetic test process; the harness container finally removes template and clones.</summary>
    private static (string Admin, string App)? _tkt976CompatibilityTemplate;

    /// <summary>Creates a separate empty migrated template once, then clones it without business rows from other Runtime/981 scenarios.</summary>
    /// <remarks>Existing synthetic roles are provisioned by the shared harness. A generated identifier creates a new database only; no database or row is cleaned during execution. Full migrations and app-role grants are retained. Eight template/clone databases are bounded by the monitored768MiB container.</remarks>
    internal static async Task<string> Tkt976_CloneCompatibilityDatabaseAsync()
    {
        await Tkt976CompatibilityTemplateLock.WaitAsync();
        try
        {
            if (_tkt976CompatibilityTemplate == null)
            {
                var shared = await ProvisionAsync();
                var name = "tkt976_compat_template_" + Guid.NewGuid().ToString("N");
                var control = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = "postgres", Pooling = false };
                await using (var admin = new NpgsqlConnection(control.ConnectionString))
                {
                    await admin.OpenAsync();
                    await ExecuteAsync(admin, "CREATE DATABASE \"" + name + "\";");
                }
                var templateAdmin = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = name }.ConnectionString;
                var templateApp = new NpgsqlConnectionStringBuilder(shared.App) { Database = name }.ConnectionString;
                await using (var db = new LicenseDbContext(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(templateAdmin).Options))
                    await db.Database.MigrateAsync();
                await using (var grants = new NpgsqlConnection(templateAdmin))
                {
                    await grants.OpenAsync();
                    await GrantApplicationRuntimePrivilegesAsync(grants);
                }
                _tkt976CompatibilityTemplate = (templateAdmin, templateApp);
            }
            return await Tkt976_CloneBaselineDatabaseAsync(_tkt976CompatibilityTemplate.Value);
        }
        finally { Tkt976CompatibilityTemplateLock.Release(); }
    }
}

/// <summary>Serializes the two shared-harness fixture classes so a clone never races another test's connection; explicit concurrency inside a test remains unchanged.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class Tkt976DecisionRelationalCollection
{
    /// <summary>Exact xUnit collection identity for the bounded PostgreSQL decision fixtures.</summary>
    public const string Name = "Tkt976DecisionRelational";
}
