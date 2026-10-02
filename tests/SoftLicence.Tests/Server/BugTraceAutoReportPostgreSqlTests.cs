using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves that the automatic-report outbox survives service recreation on PostgreSQL.</summary>
public sealed class BugTraceAutoReportPostgreSqlTests
{
    private const string ProjectId = "9f3c8fea-8740-42af-be83-6f527c6d102a";
    private const string LicenseKey = "AUTOREPORT-POSTGRES-001";

    /// <summary>
    /// Accepts a report, recreates the service, delivers it, and replays its terminal receipt from PostgreSQL.
    /// </summary>
    [Fact]
    public async Task DurableOutbox_SurvivesServiceRecreationAndReplaysReceipt()
    {
        var connectionString = Environment.GetEnvironmentVariable("SOFTLICENCE_BUGTRACE_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException(
                "SOFTLICENCE_BUGTRACE_TEST_POSTGRES must target a ticket-owned PostgreSQL database.");

        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connectionString)
            .Options;
        var factory = new PostgreSqlContextFactory(options);
        await using (var migration = await factory.CreateDbContextAsync())
            await migration.Database.MigrateAsync();
        await SeedLicenseAsync(factory);

        var proxy = new RecordingProxy();
        var request = CreateRequest();
        using (var firstCache = new MemoryCache(new MemoryCacheOptions()))
        {
            var acceptingService = CreateService(factory, proxy, firstCache);
            var accepted = await acceptingService.EnqueueAsync(request);
            Assert.True(accepted.Accepted);
            Assert.False(accepted.Duplicate);
        }

        using (var secondCache = new MemoryCache(new MemoryCacheOptions()))
        {
            var restartedService = CreateService(factory, proxy, secondCache);
            Assert.Equal(1, await restartedService.ProcessPendingAsync());
        }

        using (var thirdCache = new MemoryCache(new MemoryCacheOptions()))
        {
            var replayService = CreateService(factory, proxy, thirdCache);
            var replay = await replayService.EnqueueAsync(request);
            Assert.True(replay.Accepted);
            Assert.True(replay.Duplicate);
            Assert.Equal("TKT-PG-0001", replay.TicketNumber);
        }

        Assert.Equal(1, proxy.SubmissionCount);
        Assert.Equal(request.ReportId, proxy.LastIdempotencyKey);
    }

    /// <summary>Creates one service instance with an intentionally fresh process-local cache.</summary>
    private static BugTraceAutoReportService CreateService(
        IDbContextFactory<LicenseDbContext> factory,
        IBugTraceProxyService proxy,
        IMemoryCache cache) => new(
            factory,
            proxy,
            cache,
            TimeProvider.System,
            NullLogger<BugTraceAutoReportService>.Instance);

    /// <summary>Seeds the minimum authoritative product and active licence required by the report boundary.</summary>
    private static async Task SeedLicenseAsync(IDbContextFactory<LicenseDbContext> factory)
    {
        await using var db = await factory.CreateDbContextAsync();
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "T-IA Connect PostgreSQL proof",
            PrivateKeyXml = "test-private-placeholder",
            PublicKeyXml = "test-public-placeholder"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "PostgreSQL proof",
            Slug = "PG-PROOF"
        });
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            LicenseKey = LicenseKey,
            CustomerName = "PostgreSQL Test",
            CustomerEmail = "postgres@example.invalid",
            ProductId = productId,
            LicenseTypeId = typeId,
            HardwareId = "BOUND-POSTGRES-HWID",
            IsActive = true
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Builds a valid report with a deliberately mismatched crash-time hardware identifier.</summary>
    private static BugTraceAutoReportRequest CreateRequest()
    {
        const string errorType = "System.InvalidOperationException";
        const string message = "PostgreSQL durable outbox proof";
        return new BugTraceAutoReportRequest
        {
            Schema = BugTraceAutoReportService.Schema,
            ReportId = "c3111111-1111-1111-1111-111111111111",
            LicenseKey = LicenseKey,
            HardwareId = "CRASH-TIME-MISMATCH",
            ProjectId = ProjectId,
            Report = new BugTraceAutoReportBody
            {
                Kind = "crash",
                AppVersion = "2.3.999",
                ErrorType = errorType,
                ErrorSource = "CRASH [PostgreSQLProof]",
                Message = message,
                StackTrace = "at PostgreSql.Proof()",
                Fingerprint = Convert.ToHexString(SHA256.HashData(
                    Encoding.UTF8.GetBytes(errorType + "|" + message))).ToLowerInvariant()
            }
        };
    }

    /// <summary>Creates real PostgreSQL contexts without sharing tracked state between service instances.</summary>
    private sealed class PostgreSqlContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);

        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>Records the one provider relay while returning a stable ticket receipt.</summary>
    private sealed class RecordingProxy : IBugTraceProxyService
    {
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<JsonElement> CreateSupportCaseAsync(object body, string idempotencyKey, CancellationToken ct = default) => throw new NotSupportedException();
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<JsonElement> ListSupportCasesAsync(string reporterEmail, int limit, CancellationToken ct = default, int offset = 0) => throw new NotSupportedException();
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<JsonElement> GetSupportCaseAsync(string supportNumber, CancellationToken ct = default) => throw new NotSupportedException();
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<JsonElement> AddSupportCaseMessageAsync(string supportNumber, object body, CancellationToken ct = default) => throw new NotSupportedException();
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<JsonElement> ResolveSupportCaseAsync(string supportNumber, CancellationToken ct = default) => throw new NotSupportedException();
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<JsonElement> StageSupportAttachmentAsync(Microsoft.AspNetCore.Http.IFormFile file, string reporterEmail, string idempotencyKey, CancellationToken ct = default) => throw new NotSupportedException();
        /// <summary>Rejects support lifecycle calls from this report-only test substitute.</summary>
        public Task<(byte[] Content, string ContentType, string FileName)> DownloadSupportAttachmentAsync(string supportNumber, string attachmentId, CancellationToken ct = default) => throw new NotSupportedException();

        /// <inheritdoc />
        public string ExpectedProjectId => ProjectId;

        /// <inheritdoc />
        public bool IsConfigured => true;

        /// <summary>Gets the number of provider submissions.</summary>
        public int SubmissionCount { get; private set; }

        /// <summary>Gets the exact provider idempotency key observed on delivery.</summary>
        public string? LastIdempotencyKey { get; private set; }

        /// <inheritdoc />
        public Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default) =>
            throw new NotSupportedException();

        /// <inheritdoc />
        public Task<JsonElement> SubmitTicketAsync(
            object ticketBody,
            string idempotencyKey,
            CancellationToken ct = default)
        {
            SubmissionCount++;
            LastIdempotencyKey = idempotencyKey;
            return Task.FromResult(JsonDocument.Parse("{\"ticketNumber\":\"TKT-PG-0001\"}")
                .RootElement.Clone());
        }

        /// <inheritdoc />
        public Task<JsonElement> AddCommentAsync(
            string ticketNumber,
            object commentBody,
            CancellationToken ct = default) => throw new NotSupportedException();

        /// <inheritdoc />
        public Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default) =>
            throw new NotSupportedException();

        /// <inheritdoc />
        public Task<JsonElement> GetTicketCommentsAsync(
            string ticketNumber,
            CancellationToken ct = default) => throw new NotSupportedException();
    }
}
