using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Regression coverage for durable and concurrency-safe security-lock alert delivery.</summary>
public sealed class SecurityLockAlertOutboxTests : IAsyncDisposable
{
    private readonly SqliteConnection _anchor;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ServiceProvider _services;
    private readonly MutableTimeProvider _time = new(new DateTimeOffset(2026, 9, 19, 10, 0, 0, TimeSpan.Zero));
    private readonly GeoIpService _geoIp;

    /// <summary>Creates a shared in-memory relational database so ExecuteUpdate claims use real SQL semantics.</summary>
    public SecurityLockAlertOutboxTests()
    {
        var databaseName = "security-alert-" + Guid.NewGuid().ToString("N");
        var connectionString = $"Data Source={databaseName};Mode=Memory;Cache=Shared;Foreign Keys=False";
        _anchor = new SqliteConnection(connectionString);
        _anchor.Open();
        SqliteFullModelHarness.RegisterConnection(_anchor);
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseSqlite(connectionString)
            .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
            .Options;
        _dbFactory = new TestContextFactory(options);
        using (var db = _dbFactory.CreateDbContext()) db.Database.EnsureCreated();
        _services = new ServiceCollection().AddLogging().AddTransient<EmailService>().BuildServiceProvider();
        _geoIp = new GeoIpService(new TestEnvironment(), new MemoryCache(new MemoryCacheOptions()),
            NullLogger<GeoIpService>.Instance);
    }

    [Fact]
    public async Task StageAsync_CreatesOneDurableRowPerExactSubscribedChannel()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        db.Webhooks.AddRange(
            new Webhook
            {
                Name = "exact",
                Url = "https://alerts.example.invalid/exact",
                EnabledEvents = NotificationService.Triggers.SecurityLockReported
            },
            new Webhook
            {
                Name = "prefix-only",
                Url = "https://alerts.example.invalid/prefix",
                EnabledEvents = NotificationService.Triggers.SecurityLockReported + ".Extended"
            });
        await db.SaveChangesAsync();
        var report = new SecurityLockReport { Id = Guid.NewGuid() };

        await SecurityLockAlertOutboxProcessor.StageAsync(
            db, report, false, "127.0.0.1", _time.GetUtcNow().UtcDateTime, CancellationToken.None);
        await db.SaveChangesAsync();

        var rows = await db.SecurityLockAlertDeliveries.Where(row => row.SecurityLockReportId == report.Id)
            .OrderBy(row => row.Channel).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal(new[] { "EMAIL", "WEBHOOK" }, rows.Select(row => row.Channel));
        Assert.Contains(rows, row => row.Target == "https://alerts.example.invalid/exact");
        Assert.DoesNotContain(rows, row => row.Target.Contains("prefix", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExplicitServerFailure_IsPersistedForRetryAcrossProcessorRecreation()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var id = await SeedDeliveryAsync("WEBHOOK", "https://alerts.example.invalid/security");
        var firstProcess = CreateProcessor(handler);

        Assert.Equal(1, await firstProcess.ProcessPendingAsync());

        await using (var db = await _dbFactory.CreateDbContextAsync())
        {
            var pending = await db.SecurityLockAlertDeliveries.SingleAsync(row => row.Id == id);
            Assert.Equal(SecurityLockAlertDeliveryStates.Pending, pending.State);
            Assert.Equal(1, pending.AttemptCount);
            Assert.Equal("http_status_503", pending.LastError);
        }
        _time.Advance(TimeSpan.FromMinutes(1));
        handler.Response = _ => new HttpResponseMessage(HttpStatusCode.NoContent);

        Assert.Equal(1, await CreateProcessor(handler).ProcessPendingAsync());
        await using var verification = await _dbFactory.CreateDbContextAsync();
        Assert.Equal(SecurityLockAlertDeliveryStates.Sent,
            (await verification.SecurityLockAlertDeliveries.SingleAsync(row => row.Id == id)).State);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task ConcurrentProcessors_ClaimOneWebhookOnlyOnce()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        var id = await SeedDeliveryAsync("WEBHOOK", "https://alerts.example.invalid/concurrent");
        var first = CreateProcessor(handler);
        var second = CreateProcessor(handler);

        await Task.WhenAll(first.ProcessPendingAsync(1), second.ProcessPendingAsync(1));

        await using var db = await _dbFactory.CreateDbContextAsync();
        var sent = await db.SecurityLockAlertDeliveries.SingleAsync(row => row.Id == id);
        Assert.Equal(SecurityLockAlertDeliveryStates.Sent, sent.State);
        Assert.Equal(1, sent.AttemptCount);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task AmbiguousWebhookFailure_IsUnknownAndIsNotBlindlyRetried()
    {
        var handler = new RecordingHandler(_ => throw new HttpRequestException("connection lost after write"));
        var id = await SeedDeliveryAsync("WEBHOOK", "https://alerts.example.invalid/ambiguous");
        var processor = CreateProcessor(handler);

        Assert.Equal(1, await processor.ProcessPendingAsync());
        Assert.Equal(0, await processor.ProcessPendingAsync());

        await using var db = await _dbFactory.CreateDbContextAsync();
        var unknown = await db.SecurityLockAlertDeliveries.SingleAsync(row => row.Id == id);
        Assert.Equal(SecurityLockAlertDeliveryStates.Unknown, unknown.State);
        Assert.Equal("webhook_outcome_unknown:HttpRequestException", unknown.LastError);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task ExpiredEmailLease_BecomesUnknownWithoutSendingAgain()
    {
        var id = await SeedDeliveryAsync("EMAIL", "ADMIN", SecurityLockAlertDeliveryStates.Processing,
            _time.GetUtcNow().UtcDateTime.AddMinutes(-1));
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));

        Assert.Equal(0, await CreateProcessor(handler).ProcessPendingAsync());

        await using var db = await _dbFactory.CreateDbContextAsync();
        var unknown = await db.SecurityLockAlertDeliveries.SingleAsync(row => row.Id == id);
        Assert.Equal(SecurityLockAlertDeliveryStates.Unknown, unknown.State);
        Assert.Equal("smtp_outcome_unknown_after_worker_interruption", unknown.LastError);
        Assert.Equal(0, handler.CallCount);
    }

    private SecurityLockAlertOutboxProcessor CreateProcessor(RecordingHandler handler) => new(
        _dbFactory,
        new TestHttpClientFactory(handler),
        _services.GetRequiredService<IServiceScopeFactory>(),
        Options.Create(new SmtpSettings()),
        _geoIp,
        _time,
        NullLogger<SecurityLockAlertOutboxProcessor>.Instance);

    private async Task<Guid> SeedDeliveryAsync(
        string channel,
        string target,
        string state = SecurityLockAlertDeliveryStates.Pending,
        DateTime? leaseExpiresUtc = null)
    {
        var id = Guid.NewGuid();
        var now = _time.GetUtcNow().UtcDateTime;
        await using var db = await _dbFactory.CreateDbContextAsync();
        db.SecurityLockAlertDeliveries.Add(new SecurityLockAlertDelivery
        {
            Id = id,
            SecurityLockReportId = Guid.NewGuid(),
            Channel = channel,
            Target = target,
            TargetDigestSha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(target))),
            Trigger = NotificationService.Triggers.SecurityLockReported,
            Title = "Security alert",
            Message = "Frozen dossier",
            State = state,
            NextAttemptUtc = now,
            LeaseToken = state == SecurityLockAlertDeliveryStates.Processing ? Guid.NewGuid() : null,
            LeaseExpiresUtc = leaseExpiresUtc,
            AttemptCount = state == SecurityLockAlertDeliveryStates.Processing ? 1 : 0,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        });
        await db.SaveChangesAsync();
        return id;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        _geoIp.Dispose();
        await _services.DisposeAsync();
        await _anchor.DisposeAsync();
    }

    private sealed class TestContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        private int _callCount;
        public Func<HttpRequestMessage, HttpResponseMessage> Response { get; set; } = response;
        public int CallCount => Volatile.Read(ref _callCount);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _callCount);
            return Task.FromResult(Response(request));
        }
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class MutableTimeProvider(DateTimeOffset current) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan duration) => current = current.Add(duration);
    }

    private sealed class TestEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "SoftLicence.Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string WebRootPath { get; set; } = Path.GetTempPath();
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
