using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Metadata;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves the report-only boundary recognizes licenses, isolates HWID mismatch tolerance, and deduplicates durably.
/// </summary>
public sealed class BugTraceAutoReportTests : IDisposable
{
    private const string ProjectId = "9f3c8fea-8740-42af-be83-6f527c6d102a";
    private const string LicenseKey = "AUTOREPORT-LICENSE-001";
    private readonly ServiceProvider _provider;
    private readonly RecordingBugTraceProxy _proxy = new();
    private readonly BugTraceAutoReportService _service;
    private readonly Guid _licenseId = Guid.NewGuid();
    /// <summary>Controls retry eligibility without wall-clock delays.</summary>
    private readonly MutableTimeProvider _timeProvider = new(DateTimeOffset.Parse("2026-09-02T08:00:00Z"));
    /// <summary>Shares one in-memory database across the normal and failure-injecting factories.</summary>
    private readonly InMemoryDatabaseRoot _databaseRoot = new();
    /// <summary>Isolates each test fixture's durable outbox state.</summary>
    private readonly string _databaseName = Guid.NewGuid().ToString("N");

    /// <summary>Creates an isolated in-memory authority and seeds one active product license.</summary>
    public BugTraceAutoReportTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddDbContextFactory<LicenseDbContext>(options =>
            options.UseInMemoryDatabase(_databaseName, _databaseRoot));
        _provider = services.BuildServiceProvider();

        var factory = _provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        SeedLicenseAsync(factory).GetAwaiter().GetResult();
        _service = new BugTraceAutoReportService(
            factory,
            _proxy,
            _provider.GetRequiredService<IMemoryCache>(),
            _timeProvider,
            NullLogger<BugTraceAutoReportService>.Instance);
    }

    [Fact]
    public async Task EnqueueAsync_ActiveLicenseWithMismatchedHardware_AcceptsReportOnlyTicket()
    {
        var request = CreateRequest("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

        var result = await _service.EnqueueAsync(request);
        var examined = await _service.ProcessPendingAsync();

        Assert.True(result.Accepted);
        Assert.False(result.Duplicate);
        Assert.Equal(1, examined);
        var ticket = Assert.Single(_proxy.SubmittedTickets);
        Assert.Contains("hardware:mismatch-tolerated", ticket.Tags!);
        Assert.Contains($"License ID: `{_licenseId:D}`", ticket.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(LicenseKey, ticket.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(request.HardwareId, ticket.Description, StringComparison.Ordinal);
        Assert.Equal("customer@example.invalid", ticket.ReporterEmail);
    }

    [Fact]
    public async Task EnqueueAsync_SameFingerprintWithDifferentReportId_IsAcceptedOnce()
    {
        var first = await _service.EnqueueAsync(CreateRequest("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var duplicate = await _service.EnqueueAsync(CreateRequest("cccccccc-cccc-cccc-cccc-cccccccccccc"));
        await _service.ProcessPendingAsync();

        Assert.True(first.Accepted);
        Assert.True(duplicate.Accepted);
        Assert.True(duplicate.Duplicate);
        Assert.Single(_proxy.SubmittedTickets);
    }

    [Fact]
    public async Task EnqueueAsync_ReusedReportIdWithDifferentBinding_ReturnsTypedConflict()
    {
        const string reportId = "dddddddd-dddd-dddd-dddd-dddddddddddd";
        var first = await _service.EnqueueAsync(CreateRequest(reportId));
        var conflicting = await _service.EnqueueAsync(CreateRequest(reportId, "Different controlled failure"));

        Assert.True(first.Accepted);
        Assert.False(conflicting.Accepted);
        Assert.Equal("report_id_conflict", conflicting.ErrorCode);
    }

    [Fact]
    public async Task EnqueueAsync_RevokedLicense_IsRejectedBeforeHardwareMismatchPolicy()
    {
        await SetLicenseActiveAsync(false);

        var result = await _service.EnqueueAsync(
            CreateRequest("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"));

        Assert.False(result.Accepted);
        Assert.Equal("license_revoked", result.ErrorCode);
        Assert.Empty(_proxy.SubmittedTickets);
    }

    [Fact]
    public async Task EnqueueAsync_UnknownField_IsRejectedByClosedSchema()
    {
        var request = CreateRequest("ffffffff-ffff-ffff-ffff-ffffffffffff");
        request.ExtensionData = new Dictionary<string, JsonElement>
        {
            ["manualSupport"] = JsonDocument.Parse("true").RootElement.Clone()
        };

        var result = await _service.EnqueueAsync(request);

        Assert.False(result.Accepted);
        Assert.Equal("unexpected_field", result.ErrorCode);
    }

    [Fact]
    public async Task EnqueueAsync_FingerprintNotDerivedFromBoundedFields_IsRejected()
    {
        var request = CreateRequest("11111111-1111-1111-1111-111111111111");
        request.Report.Fingerprint = new string('0', 64);

        var result = await _service.EnqueueAsync(request);

        Assert.False(result.Accepted);
        Assert.Equal("fingerprint_mismatch", result.ErrorCode);
    }

    [Fact]
    public async Task EnqueueAsync_FourthNewReportWithinWindow_IsRateLimited()
    {
        var first = await _service.EnqueueAsync(CreateRequest("21111111-1111-1111-1111-111111111111", "failure one"));
        var second = await _service.EnqueueAsync(CreateRequest("31111111-1111-1111-1111-111111111111", "failure two"));
        var third = await _service.EnqueueAsync(CreateRequest("41111111-1111-1111-1111-111111111111", "failure three"));
        var fourth = await _service.EnqueueAsync(CreateRequest("51111111-1111-1111-1111-111111111111", "failure four"));

        Assert.True(first.Accepted);
        Assert.True(second.Accepted);
        Assert.True(third.Accepted);
        Assert.False(fourth.Accepted);
        Assert.Equal("rate_limited", fourth.ErrorCode);
    }

    [Fact]
    public async Task EnqueueAsync_OversizedStackTrace_IsRejectedBeforePersistence()
    {
        var request = CreateRequest("61111111-1111-1111-1111-111111111111");
        request.Report.StackTrace = new string('x', 32769);

        var result = await _service.EnqueueAsync(request);

        Assert.False(result.Accepted);
        Assert.Equal("stack_trace_invalid", result.ErrorCode);
    }

    [Fact]
    public async Task EnqueueAsync_ReportIdReplayAfterDelivery_UsesTerminalReceiptWithoutSecondRelay()
    {
        var request = CreateRequest("71111111-1111-1111-1111-111111111111");
        var accepted = await _service.EnqueueAsync(request);
        await _service.ProcessPendingAsync();
        var replay = await _service.EnqueueAsync(request);
        await _service.ProcessPendingAsync();

        Assert.True(accepted.Accepted);
        Assert.True(replay.Accepted);
        Assert.True(replay.Duplicate);
        Assert.Equal("BT-00042", replay.TicketNumber);
        Assert.Single(_proxy.SubmittedTickets);
    }

    [Fact]
    public async Task ProcessPendingAsync_AmbiguousProviderSuccess_ReplaysSameIdempotencyKeyAndTicket()
    {
        const string reportId = "81111111-1111-1111-1111-111111111111";
        _proxy.LoseFirstSuccessfulResponse = true;
        var request = CreateRequest(reportId);

        await _service.EnqueueAsync(request);
        await _service.ProcessPendingAsync();
        _timeProvider.Advance(TimeSpan.FromSeconds(11));
        await _service.ProcessPendingAsync();
        var replay = await _service.EnqueueAsync(request);

        Assert.Equal([reportId, reportId], _proxy.IdempotencyKeys);
        Assert.Equal(1, _proxy.CreatedTicketCount);
        Assert.True(replay.Duplicate);
        Assert.Equal("BT-00042", replay.TicketNumber);
    }

    [Fact]
    public async Task ProcessPendingAsync_ReceiptWriteFailure_RemainsReplayableWithSameProviderKey()
    {
        const string reportId = "91111111-1111-1111-1111-111111111111";
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(_databaseName, _databaseRoot)
            .Options;
        var failingFactory = new FailReceiptSaveDbContextFactory(options);
        var service = new BugTraceAutoReportService(
            failingFactory,
            _proxy,
            _provider.GetRequiredService<IMemoryCache>(),
            _timeProvider,
            NullLogger<BugTraceAutoReportService>.Instance);

        await service.EnqueueAsync(CreateRequest(reportId));
        await Assert.ThrowsAsync<DbUpdateException>(() => service.ProcessPendingAsync());
        await service.ProcessPendingAsync();

        Assert.Equal([reportId, reportId], _proxy.IdempotencyKeys);
        Assert.Equal(1, _proxy.CreatedTicketCount);
        Assert.False(failingFactory.FailNextReceiptSave);
    }

    [Fact]
    public async Task ProcessPendingAsync_SuccessAndFailureLogs_DoNotExposeProviderIdempotencyKeys()
    {
        const string deliveredReportId = "a2111111-1111-1111-1111-111111111111";
        const string failedReportId = "b2111111-1111-1111-1111-111111111111";
        var logger = new ListLogger<BugTraceAutoReportService>();
        var service = new BugTraceAutoReportService(
            _provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>(),
            _proxy,
            _provider.GetRequiredService<IMemoryCache>(),
            _timeProvider,
            logger);

        await service.EnqueueAsync(CreateRequest(deliveredReportId, "delivered failure"));
        await service.ProcessPendingAsync();
        _proxy.LoseFirstSuccessfulResponse = true;
        await service.EnqueueAsync(CreateRequest(failedReportId, "provider response lost"));
        await service.ProcessPendingAsync();

        var deliveredLog = Assert.Single(logger.Entries, entry => entry.Message.Contains(
            "Delivered identified BugTrace auto-report", StringComparison.Ordinal));
        var failedLog = Assert.Single(logger.Entries, entry => entry.Message.Contains(
            "BugTrace auto-report relay failed", StringComparison.Ordinal));
        Assert.Contains("attempt=1", failedLog.Message, StringComparison.Ordinal);
        Assert.Contains("terminal=False", failedLog.Message, StringComparison.Ordinal);
        Assert.Contains("failureType=HttpRequestException", failedLog.Message, StringComparison.Ordinal);
        Assert.Null(deliveredLog.Exception);
        Assert.Null(failedLog.Exception);
        Assert.All(logger.Entries, entry =>
        {
            Assert.DoesNotContain(deliveredReportId, entry.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(failedReportId, entry.Message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task EnqueueAsync_AcceptanceLog_DoesNotExposeServerLicenseIdentity()
    {
        var logger = new ListLogger<BugTraceAutoReportService>();
        var service = new BugTraceAutoReportService(
            _provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>(),
            _proxy,
            _provider.GetRequiredService<IMemoryCache>(),
            _timeProvider,
            logger);

        var result = await service.EnqueueAsync(
            CreateRequest("d2111111-1111-1111-1111-111111111111", "acceptance log"));

        Assert.True(result.Accepted);
        var acceptedLog = Assert.Single(logger.Entries, entry => entry.Message.Contains(
            "Accepted identified BugTrace auto-report", StringComparison.Ordinal));
        Assert.DoesNotContain(_licenseId.ToString("D"), acceptedLog.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OutboxWorker_PersistenceFailureLog_DoesNotAttachExceptionOrIdentity()
    {
        const string sensitiveReceiptIdentity = "e2111111-1111-1111-1111-111111111111";
        var logger = new ListLogger<BugTraceAutoReportOutboxWorker>();
        var worker = new BugTraceAutoReportOutboxWorker(
            new ThrowingAutoReportService(new InvalidOperationException(
                $"Synthetic receipt write failure for {sensitiveReceiptIdentity}")),
            logger);
        var executeAsync = typeof(BugTraceAutoReportOutboxWorker).GetMethod(
            "ExecuteAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        using var cancellation = new CancellationTokenSource();

        var execution = Assert.IsAssignableFrom<Task>(executeAsync.Invoke(worker, [cancellation.Token]));
        var error = Assert.Single(logger.Entries, entry => entry.Message.Contains(
            "BugTrace auto-report outbox processing failed", StringComparison.Ordinal));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => execution);

        Assert.Null(error.Exception);
        Assert.DoesNotContain(sensitiveReceiptIdentity, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AutoReportEndpoint_RequestLimit_CoversMaximumUtf8Envelope()
    {
        var method = typeof(BugTraceController).GetMethod(nameof(BugTraceController.AutoReport));
        var limit = Assert.Single(method!.GetCustomAttributes(typeof(RequestSizeLimitAttribute), inherit: true)
            .Cast<RequestSizeLimitAttribute>());

        Assert.Equal(128 * 1024, ((IRequestSizeLimitMetadata)limit).MaxRequestBodySize);
    }

    /// <summary>Releases the isolated dependency provider and its in-memory cache.</summary>
    public void Dispose() => _provider.Dispose();

    /// <summary>Builds one canonical closed request without any BugTrace credential.</summary>
    private static BugTraceAutoReportRequest CreateRequest(
        string reportId,
        string message = "Controlled failure") => new()
    {
        Schema = BugTraceAutoReportService.Schema,
        ReportId = reportId,
        LicenseKey = LicenseKey,
        HardwareId = "DIFFERENT-HWID",
        ProjectId = ProjectId,
        Report = new BugTraceAutoReportBody
        {
            Kind = "crash",
            AppVersion = "2.3.999",
            ErrorType = "System.InvalidOperationException",
            ErrorSource = "CRASH [UnitTest]",
            Message = message,
            StackTrace = "at Controlled.Test()",
            Fingerprint = ComputeFingerprint("System.InvalidOperationException", message)
        }
    };

    /// <summary>Computes the client proof that the server independently verifies.</summary>
    private static string ComputeFingerprint(string errorType, string message) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(errorType + "|" + message))).ToLowerInvariant();

    /// <summary>Seeds the authoritative product and license records consumed by the service.</summary>
    private async Task SeedLicenseAsync(IDbContextFactory<LicenseDbContext> factory)
    {
        await using var db = await factory.CreateDbContextAsync();
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "T-IA Connect",
            PrivateKeyXml = "test-private-placeholder",
            PublicKeyXml = "test-public-placeholder"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Test",
            Slug = "TEST"
        });
        db.Licenses.Add(new License
        {
            Id = _licenseId,
            LicenseKey = LicenseKey,
            CustomerName = "Test Customer",
            CustomerEmail = "customer@example.invalid",
            ProductId = productId,
            LicenseTypeId = typeId,
            HardwareId = "BOUND-HWID",
            IsActive = true
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Changes only the authoritative active flag for rejection testing.</summary>
    private async Task SetLicenseActiveAsync(bool active)
    {
        var factory = _provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync(item => item.Id == _licenseId);
        license.IsActive = active;
        await db.SaveChangesAsync();
    }

    /// <summary>Records only server-built ticket bodies and exposes no support lifecycle behavior to the tests.</summary>
    private sealed class RecordingBugTraceProxy : IBugTraceProxyService
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

        /// <summary>Models the provider's durable operation-to-ticket mapping with exact key equality.</summary>
        private readonly Dictionary<string, string> _ticketsByIdempotencyKey = new(StringComparer.Ordinal);

        public string ExpectedProjectId => ProjectId;
        public bool IsConfigured => true;
        public List<BugTraceTicketBody> SubmittedTickets { get; } = [];
        /// <summary>Gets the exact keys observed on successive provider submissions.</summary>
        public List<string?> IdempotencyKeys { get; } = [];
        /// <summary>Gets or sets whether the first newly created ticket loses its synthetic response.</summary>
        public bool LoseFirstSuccessfulResponse { get; set; }
        /// <summary>Gets the number of distinct provider tickets created.</summary>
        public int CreatedTicketCount { get; private set; }

        /// <summary>Records the server-owned ticket and returns a synthetic upstream reference.</summary>
        public Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default)
            => SubmitTicketCoreAsync(ticketBody, null);

        /// <summary>Records the exact provider idempotency key used by the report-only relay.</summary>
        public Task<JsonElement> SubmitTicketAsync(
            object ticketBody,
            string idempotencyKey,
            CancellationToken ct = default) => SubmitTicketCoreAsync(ticketBody, idempotencyKey);

        /// <summary>Creates or replays one synthetic provider receipt using exact key semantics.</summary>
        private Task<JsonElement> SubmitTicketCoreAsync(object ticketBody, string? idempotencyKey)
        {
            SubmittedTickets.Add(Assert.IsType<BugTraceTicketBody>(ticketBody));
            IdempotencyKeys.Add(idempotencyKey);
            var providerKey = idempotencyKey ?? Guid.NewGuid().ToString("D");
            if (!_ticketsByIdempotencyKey.TryGetValue(providerKey, out var ticketNumber))
            {
                CreatedTicketCount++;
                ticketNumber = $"BT-{CreatedTicketCount + 41:00000}";
                _ticketsByIdempotencyKey.Add(providerKey, ticketNumber);
                if (LoseFirstSuccessfulResponse)
                {
                    LoseFirstSuccessfulResponse = false;
                    throw new HttpRequestException("Synthetic connection loss after provider acceptance.");
                }
            }
            return Task.FromResult(JsonDocument.Parse($"{{\"ticketNumber\":\"{ticketNumber}\"}}").RootElement.Clone());
        }

        /// <summary>Fails if the report-only service ever attempts to comment.</summary>
        public Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default) =>
            throw new Xunit.Sdk.XunitException("Report-only ingestion must not comment on tickets.");

        /// <summary>Fails if the report-only service ever attempts to read tickets.</summary>
        public Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default) =>
            throw new Xunit.Sdk.XunitException("Report-only ingestion must not read tickets.");

        /// <summary>Fails if the report-only service ever attempts to read comments.</summary>
        public Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default) =>
            throw new Xunit.Sdk.XunitException("Report-only ingestion must not read comments.");
    }

    /// <summary>Provides deterministic retry time without sleeping.</summary>
    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow() => utcNow;
        /// <summary>Advances the synthetic UTC clock by a positive test-controlled duration.</summary>
        public void Advance(TimeSpan duration) => utcNow += duration;
    }

    /// <summary>Creates contexts that fail exactly once before a terminal receipt is persisted.</summary>
    private sealed class FailReceiptSaveDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Gets whether the next terminal receipt save will fail before reaching the store.</summary>
        public bool FailNextReceiptSave { get; private set; } = true;

        /// <summary>Creates a context sharing the fixture store and one failure latch.</summary>
        public LicenseDbContext CreateDbContext() => new FailReceiptSaveDbContext(options, this);

        /// <summary>Creates a context asynchronously without adding scheduling behavior.</summary>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());

        /// <summary>Fails once before committing the outbox-to-receipt transition.</summary>
        private sealed class FailReceiptSaveDbContext(
            DbContextOptions<LicenseDbContext> contextOptions,
            FailReceiptSaveDbContextFactory owner) : LicenseDbContext(contextOptions)
        {
            /// <inheritdoc />
            public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
            {
                if (owner.FailNextReceiptSave && ChangeTracker.Entries<SystemSetting>().Any(entry =>
                        entry.State == EntityState.Added
                        && entry.Entity.Key.StartsWith("BugTraceAutoReportReceipt_v1_", StringComparison.Ordinal)))
                {
                    owner.FailNextReceiptSave = false;
                    throw new DbUpdateException("Synthetic local receipt persistence failure.");
                }
                return base.SaveChangesAsync(cancellationToken);
            }
        }
    }

    /// <summary>Fails every outbox drain with one caller-controlled persistence exception.</summary>
    private sealed class ThrowingAutoReportService(Exception failure) : IBugTraceAutoReportService
    {
        /// <summary>Rejects use outside the hosted-worker failure test.</summary>
        public Task<BugTraceAutoReportEnqueueResult> EnqueueAsync(
            BugTraceAutoReportRequest request,
            CancellationToken cancellationToken = default) =>
            throw new Xunit.Sdk.XunitException("The hosted-worker test must not enqueue reports.");

        /// <summary>Returns the completed failure consumed by the hosted worker.</summary>
        public Task<int> ProcessPendingAsync(CancellationToken cancellationToken = default) =>
            Task.FromException<int>(failure);
    }
}
