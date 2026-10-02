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

/// <summary>
/// Verifies the Recovery FSM, exact replay, ordering, controller response, and privacy persistence independently of PostgreSQL locking.
/// </summary>
public sealed class RecoveryTelemetryServiceTests
{
    /// <summary>Proves every unelevated elevation result, including accepted, rejects an elevated process role.</summary>
    [Theory]
    [InlineData("accepted", null)]
    [InlineData("cancelled", "uac_cancelled")]
    [InlineData("failed", "elevation_start_failed")]
    public void ElevationResult_RequiresUnelevatedRole(string outcome, string? errorCode)
    {
        var run = new RecoveryTelemetryRun
        {
            LastSequence = 8,
            LastStage = "elevation",
            LastOutcome = "requested",
            Status = RecoveryTelemetryStatuses.Incomplete
        };
        var accepted = RecoveryTelemetryParser.Parse(ReadFixture("P01_nominal_uac_complete")[8]).Envelope! with
        {
            Outcome = outcome,
            ErrorCode = errorCode
        };

        Assert.True(RecoveryTelemetryStateMachine.IsAllowed(run, accepted));
        Assert.False(RecoveryTelemetryStateMachine.IsAllowed(run, accepted with { ProcessRole = "elevated" }));
    }

    /// <summary>Proves the complete nominal corpus produces one completed projection and one immutable ordered timeline.</summary>
    [Fact]
    public async Task NominalCorpus_PersistsCompletedTimeline()
    {
        await using var fixture = await SqliteFixture.CreateAsync();
        var requests = ReadFixture("P01_nominal_uac_complete");
        foreach (var request in requests)
        {
            var parsed = RecoveryTelemetryParser.Parse(request);
            var result = await fixture.Service.IngestAsync(parsed.Envelope!, request, Guid.NewGuid(), CancellationToken.None);
            Assert.Equal(RecoveryTelemetryCodes.Accepted, result.Code);
        }

        var run = await fixture.Db.RecoveryTelemetryRuns.SingleAsync();
        Assert.Equal(RecoveryTelemetryStatuses.Completed, run.Status);
        Assert.True(run.IsTerminal);
        Assert.Equal(17, run.LastSequence);
        Assert.Equal("2.3.278", run.VerifiedRestoredVersion);
        Assert.Equal(17, await fixture.Db.RecoveryTelemetryEvents.CountAsync());
        Assert.Equal(1, await fixture.Db.RecoveryTelemetryEvents.CountAsync(item => item.IsTerminal));
    }

    /// <summary>Proves identical canonical bytes return exact_replay without another event or rejection row.</summary>
    [Fact]
    public async Task IdenticalRequest_ReturnsExactReplayWithoutMutation()
    {
        await using var fixture = await SqliteFixture.CreateAsync();
        var request = ReadFixture("P06_exact_replay")[0];
        var envelope = RecoveryTelemetryParser.Parse(request).Envelope!;
        var first = await fixture.Service.IngestAsync(envelope, request, Guid.NewGuid(), CancellationToken.None);
        var replay = await fixture.Service.IngestAsync(envelope, request, Guid.NewGuid(), CancellationToken.None);

        Assert.Equal(StatusCodes.Status201Created, first.StatusCode);
        Assert.Equal(RecoveryTelemetryCodes.ExactReplay, replay.Code);
        Assert.Equal(1, await fixture.Db.RecoveryTelemetryEvents.CountAsync());
        Assert.Empty(await fixture.Db.RecoveryTelemetryRejections.ToListAsync());
    }

    /// <summary>Proves a future sequence remains rejected and stores only bounded closed evidence.</summary>
    [Fact]
    public async Task FutureSequence_ReturnsOutOfOrderAndBoundedRejection()
    {
        await using var fixture = await SqliteFixture.CreateAsync();
        var future = ReadFixture("N01_sequence_gap")[0];
        var futureEnvelope = RecoveryTelemetryParser.Parse(future).Envelope!;
        var firstEnvelope = futureEnvelope with
        {
            EventId = Guid.Parse("00000000-0000-4000-8000-000000000110"),
            Sequence = 1,
            OccurredAtText = "2026-08-21T12:08:01.000000Z",
            OccurredAtUtc = new DateTime(2026, 8, 21, 12, 8, 1, DateTimeKind.Utc),
            Stage = "run",
            Outcome = "started"
        };
        var first = RecoveryTelemetryParser.SerializeCanonical(firstEnvelope);
        await fixture.Service.IngestAsync(firstEnvelope, first, Guid.NewGuid(), CancellationToken.None);

        var correlation = Guid.NewGuid();
        var result = await fixture.Service.IngestAsync(futureEnvelope, future, correlation, CancellationToken.None);

        Assert.Equal(RecoveryTelemetryCodes.OutOfOrder, result.Code);
        var rejection = await fixture.Db.RecoveryTelemetryRejections.SingleAsync();
        Assert.Equal(correlation, rejection.CorrelationId);
        Assert.Equal(futureEnvelope.RecoveryRunId, rejection.RecoveryRunId);
        Assert.Equal(futureEnvelope.EventId, rejection.EventId);
        Assert.Equal(RecoveryTelemetryCodes.OutOfOrder, rejection.Code);
        Assert.Equal(1, await fixture.Db.RecoveryTelemetryEvents.CountAsync());
    }

    /// <summary>Proves the HTTP boundary rejects sensitive unknown fields without persisting request values.</summary>
    [Fact]
    public async Task Controller_SensitiveUnknownField_PersistsNoRawValue()
    {
        await using var fixture = await SqliteFixture.CreateAsync();
        var sensitive = ReadFixture("N11_sensitive_fields")[0];
        var controller = new RecoveryTelemetryController(fixture.Service)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
        controller.Request.Body = new MemoryStream(sensitive);
        controller.Request.ContentLength = sensitive.Length;
        controller.Request.ContentType = "application/json";

        var response = Assert.IsType<ObjectResult>(await controller.Post(CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode);
        var rejection = await fixture.Db.RecoveryTelemetryRejections.SingleAsync();
        Assert.Equal(RecoveryTelemetryCodes.UnknownField, rejection.Code);
        var persistedText = string.Join('|', rejection.Code, rejection.RecoveryRunId, rejection.EventId, rejection.CorrelationId);
        Assert.DoesNotContain("HWID-SENTINEL", persistedText, StringComparison.Ordinal);
    }

    private static IReadOnlyList<byte[]> ReadFixture(string id)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "TestData", "recovery-telemetry-v1.corpus.json")));
        var fixture = document.RootElement.GetProperty("fixtures").EnumerateArray().Single(item => item.GetProperty("id").GetString() == id);
        return fixture.GetProperty("requestBytes").EnumerateArray().Select(item => Encoding.UTF8.GetBytes(item.GetString()!)).ToList();
    }

    /// <summary>Owns one disposable relational SQLite database and the scoped service under test.</summary>
    private sealed class SqliteFixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;

        private SqliteFixture(SqliteConnection connection, LicenseDbContext db)
        {
            this.connection = connection;
            Db = db;
            Service = new RecoveryTelemetryService(db, TimeProvider.System);
        }

        /// <summary>Gets the relational EF context for result inspection.</summary>
        public LicenseDbContext Db { get; }
        /// <summary>Gets the service bound to the fixture context.</summary>
        public RecoveryTelemetryService Service { get; }

        /// <summary>Creates schema and the exact TIAConnect product required by the v1 product-code mapping.</summary>
        public static async Task<SqliteFixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            SqliteFullModelHarness.RegisterConnection(connection);
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseSqlite(connection)
                .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
                .Options;
            var db = new LicenseDbContext(options);
            await db.Database.EnsureCreatedAsync();
            db.Products.Add(new Product { Name = "TIAConnect", PrivateKeyXml = "test", PublicKeyXml = "test", ApiSecret = "test" });
            await db.SaveChangesAsync();
            return new SqliteFixture(connection, db);
        }

        /// <summary>Disposes the EF context before closing the single in-memory SQLite connection.</summary>
        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
