using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Executes every non-concurrent server-applicable corpus fixture with its declared state and persistence deltas.</summary>
public sealed class RecoveryTelemetryContractFixtureTests
{
    private static readonly string[] SequentialFixtureIds =
    [
        "P01_nominal_uac_complete", "P02_already_elevated", "P03_uac_cancelled", "P04_msi_3010",
        "P05_relaunch_warning", "P06_exact_replay", "P08_restart_resume", "N01_sequence_gap",
        "N02_divergent_event_id", "N03_divergent_run_sequence", "N05_completion_too_early",
        "N06_wrong_terminal_class", "N07_after_terminal", "N08_string_canonicalization",
        "N09_identifier_version_time", "N10_unknown_duplicate_null", "N11_sensitive_fields",
        "N12_oversized_malformed", "N14_product_scope"
    ];

    /// <summary>Returns every sequential fixture as an independently isolated theory case.</summary>
    public static IEnumerable<object[]> SequentialFixtures() => SequentialFixtureIds.Select(id => new object[] { id });

    /// <summary>Executes exact corpus bytes through the HTTP boundary and verifies responses, projection state, and row deltas.</summary>
    [Theory]
    [MemberData(nameof(SequentialFixtures))]
    public async Task SequentialFixture_MatchesFrozenContract(string fixtureId)
    {
        using var corpus = LoadCorpus();
        var fixture = FindFixture(corpus.RootElement, fixtureId);
        await using var database = await FixtureDatabase.CreateAsync();
        var requests = MaterializeRequests(fixture);
        var firstValidEnvelope = requests.Select(request => RecoveryTelemetryParser.Parse(request))
            .FirstOrDefault(result => result.Envelope is not null)?.Envelope;
        if (firstValidEnvelope is not null)
            await ApplyPreconditionAsync(database.Service, fixtureId, firstValidEnvelope.RecoveryRunId);

        var beforeRuns = await database.Db.RecoveryTelemetryRuns.CountAsync();
        var beforeEvents = await database.Db.RecoveryTelemetryEvents.CountAsync();
        var beforeRejections = await database.Db.RecoveryTelemetryRejections.CountAsync();
        var expectedStatuses = fixture.GetProperty("expectedHttp").EnumerateArray().Select(item => item.GetInt32()).ToList();
        var expectedCodes = fixture.GetProperty("expectedBodyCodes").EnumerateArray().Select(item => item.GetString()!).ToList();

        Assert.Equal(expectedStatuses.Count, requests.Count);
        for (var index = 0; index < requests.Count; index++)
        {
            var controller = database.CreateIngestionController(requests[index]);
            var result = Assert.IsType<ObjectResult>(await controller.Post(CancellationToken.None));
            var response = Assert.IsType<RecoveryTelemetryResponse>(result.Value);
            Assert.Equal(expectedStatuses[index], result.StatusCode);
            Assert.Equal(expectedCodes[index], response.Code);
        }

        var delta = fixture.GetProperty("persistenceDelta");
        Assert.Equal(delta.GetProperty("runs").GetInt32(), await database.Db.RecoveryTelemetryRuns.CountAsync() - beforeRuns);
        Assert.Equal(delta.GetProperty("events").GetInt32(), await database.Db.RecoveryTelemetryEvents.CountAsync() - beforeEvents);
        Assert.Equal(delta.GetProperty("rejections").GetInt32(), await database.Db.RecoveryTelemetryRejections.CountAsync() - beforeRejections);
        await AssertRunStateAsync(database.Db, firstValidEnvelope?.RecoveryRunId, fixture.GetProperty("runState").GetString()!);

        if (fixture.TryGetProperty("forbiddenPersistenceSentinel", out var sentinel))
            Assert.DoesNotContain(sentinel.GetString()!, SerializeRecoveryPersistence(database.Db), StringComparison.Ordinal);
    }

    /// <summary>Proves the client-only capacity fixture is explicitly non-HTTP and cannot mutate server persistence.</summary>
    [Fact]
    public void N13_IsExplicitlyClientOnly()
    {
        using var corpus = LoadCorpus();
        var fixture = FindFixture(corpus.RootElement, "N13_outbox_bounds");
        Assert.Empty(fixture.GetProperty("expectedHttp").EnumerateArray());
        Assert.Empty(fixture.GetProperty("expectedBodyCodes").EnumerateArray());
        Assert.Equal("local_only", fixture.GetProperty("runState").GetString());
        Assert.Equal(10, fixture.GetProperty("localScenarios").GetArrayLength());
        Assert.All(fixture.GetProperty("persistenceDelta").EnumerateObject(), property => Assert.Equal(0, property.Value.GetInt32()));
    }

    /// <summary>Proves the execution matrix accounts for every frozen fixture exactly once.</summary>
    [Fact]
    public void ExecutionMatrix_CoversAllFrozenFixtures()
    {
        using var corpus = LoadCorpus();
        var corpusIds = corpus.RootElement.GetProperty("fixtures").EnumerateArray()
            .Select(item => item.GetProperty("id").GetString()!).Order(StringComparer.Ordinal).ToList();
        var executedIds = SequentialFixtureIds.Concat(
            ["P07_concurrent_exact_replay", "N04_terminal_race", "N13_outbox_bounds", "N15_postgresql_ordering"])
            .Order(StringComparer.Ordinal).ToList();
        Assert.Equal(corpusIds, executedIds);
    }

    /// <summary>Executes all four N14 product-authorization scenarios against the exact ingested fixture run.</summary>
    [Fact]
    public async Task N14_AuthorizationScenarios_AreProductScoped()
    {
        using var corpus = LoadCorpus();
        var fixture = FindFixture(corpus.RootElement, "N14_product_scope");
        Assert.Equal(
            ["mono_product_own_timeline_allowed", "mono_product_cross_product_forbidden", "global_exact_product_required", "global_cross_product_forbidden"],
            fixture.GetProperty("authorizationScenarios").EnumerateArray().Select(item => item.GetString()!).ToArray());
        await using var database = await FixtureDatabase.CreateAsync();
        var request = Assert.Single(MaterializeRequests(fixture));
        var ingestion = Assert.IsType<ObjectResult>(await database.CreateIngestionController(request).Post(CancellationToken.None));
        Assert.Equal(StatusCodes.Status201Created, ingestion.StatusCode);
        var runId = RecoveryTelemetryParser.Parse(request).Envelope!.RecoveryRunId;
        var analytics = database.CreateAnalyticsController();

        Assert.IsType<OkObjectResult>(await analytics.Timeline(runId, database.ProductKey, null, null, CancellationToken.None));
        Assert.IsType<ForbidResult>(await analytics.Timeline(runId, database.ProductKey, database.OtherProductId, null, CancellationToken.None));
        Assert.IsType<BadRequestObjectResult>(await analytics.Timeline(runId, database.GlobalKey, null, null, CancellationToken.None));
        Assert.IsType<NotFoundObjectResult>(await analytics.Timeline(runId, database.GlobalKey, database.OtherProductId, null, CancellationToken.None));
    }

    /// <summary>Applies the exact valid predecessor chain declared by one stateful fixture.</summary>
    private static async Task ApplyPreconditionAsync(RecoveryTelemetryService service, string fixtureId, Guid runId)
    {
        IReadOnlyList<(string Role, string Stage, string Outcome)> steps = fixtureId switch
        {
            "P04_msi_3010" => AlreadyElevatedThroughRollbackStarted(),
            "P05_relaunch_warning" => AlreadyElevatedThroughRelaunchAttempted(),
            "P08_restart_resume" or "N01_sequence_gap" or "N15_postgresql_ordering" =>
                [("unelevated", "run", "started")],
            "N04_terminal_race" => ElevatedThroughRelaunchSkipped(),
            "N05_completion_too_early" => AlreadyElevatedThroughRollbackSucceeded(),
            "N06_wrong_terminal_class" =>
                [("unelevated", "run", "started"), ("unelevated", "preflight", "succeeded")],
            "N07_after_terminal" => ElevatedThroughRelaunchSkipped().Concat([("elevated", "terminal", "completed")]).ToList(),
            _ => []
        };

        for (var index = 0; index < steps.Count; index++)
        {
            var step = steps[index];
            var sequence = index + 1;
            var envelope = CreatePreconditionEnvelope(runId, sequence, step.Role, step.Stage, step.Outcome);
            var bytes = RecoveryTelemetryParser.SerializeCanonical(envelope);
            Assert.True(RecoveryTelemetryParser.Parse(bytes).IsSuccess);
            var result = await service.IngestAsync(envelope, bytes, Guid.NewGuid(), CancellationToken.None);
            Assert.Equal(RecoveryTelemetryCodes.Accepted, result.Code);
        }
    }

    /// <summary>Builds the minimal already-elevated chain through rollback start.</summary>
    private static IReadOnlyList<(string Role, string Stage, string Outcome)> AlreadyElevatedThroughRollbackStarted() =>
    [
        ("elevated", "run", "started"), ("elevated", "preflight", "succeeded"),
        ("elevated", "confirmation", "skipped"), ("elevated", "process_stop", "skipped"),
        ("elevated", "backup", "skipped"), ("elevated", "elevation", "not_required"),
        ("elevated", "elevated_preflight", "succeeded"), ("elevated", "rollback", "started")
    ];

    /// <summary>Builds the minimal already-elevated chain through rollback success.</summary>
    private static IReadOnlyList<(string Role, string Stage, string Outcome)> AlreadyElevatedThroughRollbackSucceeded() =>
        AlreadyElevatedThroughRollbackStarted().Concat([("elevated", "rollback", "succeeded")]).ToList();

    /// <summary>Builds the minimal verified/committed chain through a relaunch attempt.</summary>
    private static IReadOnlyList<(string Role, string Stage, string Outcome)> AlreadyElevatedThroughRelaunchAttempted() =>
        AlreadyElevatedThroughRollbackSucceeded().Concat(
        [
            ("elevated", "version_verification", "succeeded"),
            ("elevated", "secure_commit", "succeeded"),
            ("elevated", "relaunch", "attempted")
        ]).ToList();

    /// <summary>Builds a thirteen-event elevated chain whose relaunch is skipped.</summary>
    private static IReadOnlyList<(string Role, string Stage, string Outcome)> ElevatedThroughRelaunchSkipped() =>
    [
        ("elevated", "run", "started"), ("elevated", "preflight", "succeeded"),
        ("elevated", "confirmation", "accepted"), ("elevated", "process_stop", "started"),
        ("elevated", "process_stop", "succeeded"), ("elevated", "backup", "skipped"),
        ("elevated", "elevation", "not_required"), ("elevated", "elevated_preflight", "succeeded"),
        ("elevated", "rollback", "started"), ("elevated", "rollback", "succeeded"),
        ("elevated", "version_verification", "succeeded"), ("elevated", "secure_commit", "succeeded"),
        ("elevated", "relaunch", "skipped")
    ];

    /// <summary>Creates one canonical predecessor event with only stage-required optional fields.</summary>
    private static RecoveryTelemetryEnvelope CreatePreconditionEnvelope(
        Guid runId,
        int sequence,
        string role,
        string stage,
        string outcome)
    {
        var occurred = new DateTime(2026, 8, 21, 10, 0, sequence, DateTimeKind.Utc);
        var verifies = stage == "version_verification" && outcome == "succeeded";
        return new RecoveryTelemetryEnvelope(
            1, "TIA_CONNECT", Guid.Parse($"90000000-0000-4000-8000-{sequence:000000000000}"), runId, sequence,
            occurred, occurred.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", System.Globalization.CultureInfo.InvariantCulture),
            "2.3.404", role, stage, outcome, null, verifies ? "2.3.404" : null,
            verifies ? "2.3.404" : null, null, null, null);
    }

    /// <summary>Verifies the corpus-derived projection state for the fixture run only.</summary>
    private static async Task AssertRunStateAsync(LicenseDbContext db, Guid? runId, string expectedState)
    {
        if (!runId.HasValue)
            return;
        var run = await db.RecoveryTelemetryRuns.SingleOrDefaultAsync(item => item.RecoveryRunId == runId.Value);
        switch (expectedState)
        {
            case "absent": Assert.Null(run); break;
            case "active": Assert.NotNull(run); Assert.False(run!.IsTerminal); Assert.Equal(RecoveryTelemetryStatuses.Incomplete, run.Status); break;
            case "completed": Assert.NotNull(run); Assert.True(run!.IsTerminal); Assert.Equal(RecoveryTelemetryStatuses.Completed, run.Status); break;
            case "failed": Assert.NotNull(run); Assert.True(run!.IsTerminal); Assert.Equal(RecoveryTelemetryStatuses.Failed, run.Status); break;
            case "cancelled": Assert.NotNull(run); Assert.True(run!.IsTerminal); Assert.Equal(RecoveryTelemetryStatuses.Cancelled, run.Status); break;
            case "terminal": Assert.NotNull(run); Assert.True(run!.IsTerminal); break;
            default: throw new InvalidOperationException($"Unknown server runState '{expectedState}'.");
        }
    }

    /// <summary>Serializes only approved Recovery columns for a sentinel absence assertion.</summary>
    private static string SerializeRecoveryPersistence(LicenseDbContext db) => JsonSerializer.Serialize(new
    {
        Runs = db.RecoveryTelemetryRuns.AsNoTracking().ToList(),
        Events = db.RecoveryTelemetryEvents.AsNoTracking().ToList(),
        Rejections = db.RecoveryTelemetryRejections.AsNoTracking().ToList()
    });

    /// <summary>Loads the immutable corpus copied from the authorized client handoff.</summary>
    private static JsonDocument LoadCorpus() => JsonDocument.Parse(File.ReadAllBytes(
        Path.Combine(AppContext.BaseDirectory, "TestData", "recovery-telemetry-v1.corpus.json")));

    /// <summary>Returns one exact named fixture.</summary>
    private static JsonElement FindFixture(JsonElement root, string id) => root.GetProperty("fixtures").EnumerateArray()
        .Single(item => item.GetProperty("id").GetString() == id);

    /// <summary>Materializes only corpus-declared byte placeholders in memory.</summary>
    private static IReadOnlyList<byte[]> MaterializeRequests(JsonElement fixture) => fixture.GetProperty("requestBytes")
        .EnumerateArray().Select(item => MaterializeRequest(fixture, item.GetString()!)).ToList();

    /// <summary>Expands a declared ASCII byte placeholder without changing any corpus byte.</summary>
    private static byte[] MaterializeRequest(JsonElement fixture, string request)
    {
        if (!fixture.TryGetProperty("byteMaterialization", out var materialization)
            || !materialization.TryGetProperty(request, out var descriptor))
            return Encoding.UTF8.GetBytes(request);
        var asciiByte = descriptor.GetProperty("asciiByte").GetString()!;
        return Enumerable.Repeat((byte)asciiByte[0], descriptor.GetProperty("count").GetInt32()).ToArray();
    }

    /// <summary>Owns one isolated relational database and ingestion service for a corpus case.</summary>
    private sealed class FixtureDatabase : IAsyncDisposable
    {
        private readonly SqliteConnection connection;
        private readonly TestDbContextFactory factory;

        private FixtureDatabase(SqliteConnection connection, LicenseDbContext db, TestDbContextFactory factory)
        {
            this.connection = connection;
            this.factory = factory;
            Db = db;
            Service = new RecoveryTelemetryService(db, TimeProvider.System);
        }

        public LicenseDbContext Db { get; }
        public RecoveryTelemetryService Service { get; }
        public Guid OtherProductId { get; private init; }
        public string ProductKey { get; private init; } = string.Empty;
        public string GlobalKey { get; private init; } = string.Empty;

        /// <summary>Creates a schema with the exact server-side product mapping.</summary>
        public static async Task<FixtureDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            SqliteFullModelHarness.RegisterConnection(connection);
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseSqlite(connection)
                .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
                .Options;
            var factory = new TestDbContextFactory(options);
            var db = new LicenseDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var product = new Product { Name = "TIAConnect", PrivateKeyXml = "test", PublicKeyXml = "test", ApiSecret = "test" };
            var other = new Product { Name = "Other", PrivateKeyXml = "test", PublicKeyXml = "test", ApiSecret = "test" };
            const string productKey = "sl_recovery_fixture_product";
            const string globalKey = "sl_recovery_fixture_global";
            db.Products.AddRange(product, other);
            db.AnalyticsApiKeys.AddRange(
                new AnalyticsApiKey { Product = product, Name = "product", Prefix = "product", KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(productKey), ScopeKind = AnalyticsApiKeyScopeKinds.Product, Scopes = AnalyticsApiKeyScopes.TelemetryRead, IsActive = true },
                new AnalyticsApiKey { Name = "global", Prefix = "global", KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(globalKey), ScopeKind = AnalyticsApiKeyScopeKinds.Global, Scopes = $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.MultiProductRead}", IsActive = true });
            await db.SaveChangesAsync();
            return new FixtureDatabase(connection, db, factory)
            {
                OtherProductId = other.Id,
                ProductKey = productKey,
                GlobalKey = globalKey
            };
        }

        /// <summary>Creates a fresh controller request over exact bytes.</summary>
        public RecoveryTelemetryController CreateIngestionController(byte[] request)
        {
            var controller = new RecoveryTelemetryController(Service)
            {
                ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
            };
            controller.Request.Body = new MemoryStream(request);
            controller.Request.ContentLength = request.Length;
            controller.Request.ContentType = "application/json";
            return controller;
        }

        /// <summary>Creates product-scoped Recovery analytics over independent contexts on the shared relational connection.</summary>
        public RecoveryTelemetryAnalyticsController CreateAnalyticsController() => new(
            new AnalyticsApiKeyAuthService(factory),
            new RecoveryTelemetryAnalyticsService(factory),
            factory)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        /// <summary>Disposes EF before its shared relational connection.</summary>
        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    /// <summary>Creates independent EF contexts over the fixture's shared relational connection.</summary>
    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options) : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);
    }
}
