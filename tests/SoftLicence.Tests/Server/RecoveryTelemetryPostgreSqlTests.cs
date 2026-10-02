using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves Recovery v1 replay, ordering, terminal races, and index constraints against the production PostgreSQL provider.
/// </summary>
public sealed class RecoveryTelemetryPostgreSqlTests
{
    /// <summary>Proves eight simultaneous identical requests create one event and return only accepted/exact_replay.</summary>
    [Fact]
    public async Task ConcurrentExactReplay_CreatesOneEvent()
    {
        await using var database = await PostgreSqlDatabase.CreateAsync();
        var request = ReadFixture("P07_concurrent_exact_replay")[0];
        var envelope = RecoveryTelemetryParser.Parse(request).Envelope!;
        var tasks = Enumerable.Range(0, 8).Select(async _ =>
        {
            await using var db = database.CreateContext();
            return await new RecoveryTelemetryService(db, TimeProvider.System)
                .IngestAsync(envelope, request, Guid.NewGuid(), CancellationToken.None);
        });
        var results = await Task.WhenAll(tasks);

        Assert.Single(results, item => item.Code == RecoveryTelemetryCodes.Accepted);
        Assert.All(results, item => Assert.Contains(item.Code, new[] { RecoveryTelemetryCodes.Accepted, RecoveryTelemetryCodes.ExactReplay }));
        await using var verify = database.CreateContext();
        Assert.Equal(1, await verify.RecoveryTelemetryRuns.CountAsync());
        Assert.Equal(1, await verify.RecoveryTelemetryEvents.CountAsync());
        Assert.Empty(await verify.RecoveryTelemetryRejections.ToListAsync());
    }

    /// <summary>Proves a concurrent future event remains out_of_order while its immediate predecessor commits once.</summary>
    [Fact]
    public async Task ConcurrentNextAndFuture_AcceptsOnlyNextSequence()
    {
        await using var database = await PostgreSqlDatabase.CreateAsync();
        var requests = ReadFixture("N15_postgresql_ordering");
        var runId = RecoveryTelemetryParser.Parse(requests[0]).Envelope!.RecoveryRunId;
        await SeedRunStartedAsync(database, runId, "00000000-0000-4000-8000-000000000250");

        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = requests.Select(async request =>
        {
            await start.Task;
            await using var db = database.CreateContext();
            return await new RecoveryTelemetryService(db, TimeProvider.System)
                .IngestAsync(RecoveryTelemetryParser.Parse(request).Envelope!, request, Guid.NewGuid(), CancellationToken.None);
        }).ToArray();
        start.SetResult();
        var results = await Task.WhenAll(tasks);

        Assert.Contains(results, item => item.Code == RecoveryTelemetryCodes.Accepted);
        Assert.Contains(results, item => item.Code == RecoveryTelemetryCodes.OutOfOrder);
        await using var verify = database.CreateContext();
        Assert.Equal(1, await verify.RecoveryTelemetryRuns.CountAsync());
        Assert.Equal(2, await verify.RecoveryTelemetryEvents.CountAsync());
        Assert.Equal(1, await verify.RecoveryTelemetryRejections.CountAsync(item => item.Code == RecoveryTelemetryCodes.OutOfOrder));
    }

    /// <summary>Proves competing terminal requests can persist at most one terminal under the partial unique index.</summary>
    [Fact]
    public async Task ConcurrentTerminals_PersistOneTerminalAndRejectLoser()
    {
        await using var database = await PostgreSqlDatabase.CreateAsync();
        var requests = ReadFixture("N04_terminal_race");
        var first = RecoveryTelemetryParser.Parse(requests[0]).Envelope!;
        await SeedElevatedThroughRelaunchSkippedAsync(database, first.RecoveryRunId);

        var tasks = requests.Select(async request =>
        {
            await using var db = database.CreateContext();
            return await new RecoveryTelemetryService(db, TimeProvider.System)
                .IngestAsync(RecoveryTelemetryParser.Parse(request).Envelope!, request, Guid.NewGuid(), CancellationToken.None);
        });
        var results = await Task.WhenAll(tasks);

        Assert.Contains(results, item => item.Code == RecoveryTelemetryCodes.Accepted);
        Assert.Contains(results, item => item.Code == RecoveryTelemetryCodes.TerminalConflict);
        await using var verify = database.CreateContext();
        Assert.Equal(1, await verify.RecoveryTelemetryRuns.CountAsync());
        Assert.Equal(14, await verify.RecoveryTelemetryEvents.CountAsync());
        Assert.Equal(1, await verify.RecoveryTelemetryEvents.CountAsync(item => item.IsTerminal));
        Assert.Equal(1, await verify.RecoveryTelemetryRejections.CountAsync(item => item.Code == RecoveryTelemetryCodes.TerminalConflict));
    }

    /// <summary>Proves all frozen unique and partial indexes exist in the PostgreSQL catalog.</summary>
    [Fact]
    public async Task Migration_CreatesRequiredUniqueAndPartialIndexes()
    {
        await using var database = await PostgreSqlDatabase.CreateAsync();
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND tablename IN ('RecoveryTelemetryRuns','RecoveryTelemetryEvents')", connection);
        await using var reader = await command.ExecuteReaderAsync();
        var definitions = new List<string>();
        while (await reader.ReadAsync()) definitions.Add(reader.GetString(0));
        var combined = string.Join('\n', definitions);
        Assert.Contains("UNIQUE", combined, StringComparison.Ordinal);
        Assert.Contains("\"ProductId\", \"RecoveryRunId\", \"Sequence\"", combined, StringComparison.Ordinal);
        Assert.Contains("WHERE (\"IsTerminal\" = true)", combined, StringComparison.Ordinal);
    }

    private static async Task SeedRunStartedAsync(PostgreSqlDatabase database, Guid runId, string eventId)
    {
        var envelope = new RecoveryTelemetryEnvelope(1, "TIA_CONNECT", Guid.Parse(eventId), runId, 1,
            new DateTime(2026, 8, 21, 12, 22, 1, DateTimeKind.Utc), "2026-08-21T12:22:01.000000Z",
            "2.3.404", "unelevated", "run", "started", null, null, null, null, null, null);
        var bytes = RecoveryTelemetryParser.SerializeCanonical(envelope);
        await using var db = database.CreateContext();
        var result = await new RecoveryTelemetryService(db, TimeProvider.System).IngestAsync(envelope, bytes, Guid.NewGuid(), CancellationToken.None);
        Assert.Equal(RecoveryTelemetryCodes.Accepted, result.Code);
    }

    /// <summary>Persists the complete valid thirteen-event N04 predecessor chain through relaunch/skipped.</summary>
    private static async Task SeedElevatedThroughRelaunchSkippedAsync(PostgreSqlDatabase database, Guid runId)
    {
        (string Stage, string Outcome)[] steps =
        [
            ("run", "started"), ("preflight", "succeeded"), ("confirmation", "accepted"),
            ("process_stop", "started"), ("process_stop", "succeeded"), ("backup", "skipped"),
            ("elevation", "not_required"), ("elevated_preflight", "succeeded"), ("rollback", "started"),
            ("rollback", "succeeded"), ("version_verification", "succeeded"),
            ("secure_commit", "succeeded"), ("relaunch", "skipped")
        ];
        for (var index = 0; index < steps.Length; index++)
        {
            var sequence = index + 1;
            var occurred = new DateTime(2026, 8, 21, 11, 0, sequence, DateTimeKind.Utc);
            var verifies = steps[index].Stage == "version_verification";
            var envelope = new RecoveryTelemetryEnvelope(
                1, "TIA_CONNECT", Guid.Parse($"91000000-0000-4000-8000-{sequence:000000000000}"), runId, sequence,
                occurred, occurred.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", System.Globalization.CultureInfo.InvariantCulture),
                "2.3.404", "elevated", steps[index].Stage, steps[index].Outcome, null,
                verifies ? "2.3.404" : null, verifies ? "2.3.404" : null, null, null, null);
            var bytes = RecoveryTelemetryParser.SerializeCanonical(envelope);
            await using var db = database.CreateContext();
            var result = await new RecoveryTelemetryService(db, TimeProvider.System)
                .IngestAsync(envelope, bytes, Guid.NewGuid(), CancellationToken.None);
            Assert.Equal(RecoveryTelemetryCodes.Accepted, result.Code);
        }
    }

    private static IReadOnlyList<byte[]> ReadFixture(string id)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "TestData", "recovery-telemetry-v1.corpus.json")));
        var fixture = document.RootElement.GetProperty("fixtures").EnumerateArray().Single(item => item.GetProperty("id").GetString() == id);
        return fixture.GetProperty("requestBytes").EnumerateArray().Select(item => Encoding.UTF8.GetBytes(item.GetString()!)).ToList();
    }

    /// <summary>Owns one disposable PostgreSQL database created from the configured local test server.</summary>
    private sealed class PostgreSqlDatabase : IAsyncDisposable
    {
        private readonly string maintenanceConnectionString;
        private readonly string databaseName;

        private PostgreSqlDatabase(string maintenanceConnectionString, string databaseName, string connectionString)
        {
            this.maintenanceConnectionString = maintenanceConnectionString;
            this.databaseName = databaseName;
            ConnectionString = connectionString;
        }

        /// <summary>Gets the isolated database connection string; it is never logged by these tests.</summary>
        public string ConnectionString { get; }

        /// <summary>Creates an independent production-provider context for one concurrent request.</summary>
        public LicenseDbContext CreateContext() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(ConnectionString).Options);

        /// <summary>Creates, migrates, and seeds one random disposable database on the explicitly configured PostgreSQL test server.</summary>
        public static async Task<PostgreSqlDatabase> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for Recovery PostgreSQL tests.");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            var databaseName = "recovery_v1_" + Guid.NewGuid().ToString("N");
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{databaseName}\"", connection);
                await create.ExecuteNonQueryAsync();
            }
            var target = new NpgsqlConnectionStringBuilder(configured) { Database = databaseName }.ConnectionString;
            var database = new PostgreSqlDatabase(maintenance, databaseName, target);
            try
            {
                await using var db = database.CreateContext();
                await db.Database.MigrateAsync();
                db.Products.Add(new Product { Name = "TIAConnect", PrivateKeyXml = "test", PublicKeyXml = "test", ApiSecret = "test" });
                await db.SaveChangesAsync();
                return database;
            }
            catch
            {
                await database.DisposeAsync();
                throw;
            }
        }

        /// <summary>Drops the random database with force after clearing pooled test connections.</summary>
        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{databaseName}\" WITH (FORCE)", connection);
            await drop.ExecuteNonQueryAsync();
        }
    }
}
