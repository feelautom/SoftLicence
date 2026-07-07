using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryActivationFunnelAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryActivationFunnelAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetActivationFunnelForProductKeyAsync_AggregatesLicensesAndAccessLogs()
    {
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "k",
                PublicKeyXml = "k",
                ApiSecret = "secret"
            });

            AddLicense(db, productId, typeId, "L1", DateTime.UtcNow.AddDays(-2), DateTime.UtcNow.AddDays(-1));
            AddLicense(db, productId, typeId, "L2", DateTime.UtcNow.AddDays(-1), null);
            AddLicense(db, productId, typeId, "L3", DateTime.UtcNow.AddDays(-20), DateTime.UtcNow.AddDays(-1));

            AddLog(db, "TIAConnect", "ACTIVATE", true, "VALID", "HW-A", "10.0.0.1");
            AddLog(db, "TIAConnect", "ACTIVATE", false, "INVALID_KEY", "HW-B", "10.0.0.2");
            AddLog(db, "TIAConnect", "ACTIVATE", false, "MAX_ACTIVATIONS", "HW-B", "10.0.0.2");
            AddLog(db, "TIAConnect", "TRIAL_AUTO", true, "SUCCESS", "HW-C", "10.0.0.3");
            AddLog(db, "TIAConnect", "TRIAL_AUTO", false, "DENIED", "HW-D", "10.0.0.4");
            AddLog(db, "TIAConnect", "CHECK", true, "VALID", "HW-A", "10.0.0.1");
            AddLog(db, "OtherApp", "ACTIVATE", true, "VALID", "HW-Z", "10.0.0.9");

            await db.SaveChangesAsync();
        }

        var service = new TelemetryActivationFunnelAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetActivationFunnelForProductKeyAsync("secret");

        Assert.NotNull(summary);
        Assert.False(summary.Cached);
        Assert.Equal(2, summary.LicensesCreated);
        Assert.Equal(2, summary.LicensesActivated);
        Assert.Equal(1, summary.LicensesCreatedAndNeverActivated);
        Assert.Equal(3, summary.ActivationAttempts);
        Assert.Equal(1, summary.ActivationSuccesses);
        Assert.Equal(2, summary.ActivationFailures);
        Assert.Equal(33.3, summary.ActivationSuccessRate);
        Assert.Equal(2, summary.TrialRequests);
        Assert.Equal(1, summary.TrialSuccesses);
        Assert.Equal(1, summary.TrialFailures);
        Assert.Equal(1, summary.CheckRequests);
        Assert.Equal(2, summary.UniqueActivationDevices);
        Assert.Equal(2, summary.UniqueActivationIps);
        Assert.Contains(summary.FailureStatuses, s => s.Name == "INVALID_KEY" && s.Count == 1);
        Assert.Contains(summary.FailureStatuses, s => s.Name == "MAX_ACTIVATIONS" && s.Count == 1);
        Assert.Equal(7, summary.DailyFunnel.Count);
        Assert.Equal(3, summary.DailyFunnel.Sum(d => d.ActivationAttempts));
    }

    [Fact]
    public async Task GetActivationFunnelForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();
        var typeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddLicense(db, productA, typeId, "A1", DateTime.UtcNow, DateTime.UtcNow);
            AddLicense(db, productB, typeId, "B1", DateTime.UtcNow, null);
            AddLog(db, "AppA", "ACTIVATE", true, "VALID", "HW-A", "10.0.0.1");
            AddLog(db, "AppB", "ACTIVATE", false, "INVALID_KEY", "HW-B", "10.0.0.2");
            await db.SaveChangesAsync();
        }

        var service = new TelemetryActivationFunnelAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetActivationFunnelForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Equal(1, summary.LicensesCreated);
        Assert.Equal(1, summary.LicensesActivated);
        Assert.Equal(1, summary.ActivationAttempts);
        Assert.Equal(1, summary.ActivationSuccesses);
        Assert.Empty(summary.FailureStatuses);
    }

    [Fact]
    public async Task GetActivationFunnelForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryActivationFunnelAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetActivationFunnelForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    private static void AddLicense(
        LicenseDbContext db,
        Guid productId,
        Guid typeId,
        string key,
        DateTime createdAt,
        DateTime? activatedAt)
    {
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = key,
            CustomerName = "Test",
            CustomerEmail = $"{key.ToLowerInvariant()}@example.com",
            CreationDate = createdAt,
            ActivationDate = activatedAt,
            IsActive = true
        });
    }

    private static void AddLog(
        LicenseDbContext db,
        string appName,
        string endpoint,
        bool isSuccess,
        string resultStatus,
        string hardwareId,
        string clientIp)
    {
        db.AccessLogs.Add(new AccessLog
        {
            Timestamp = DateTime.UtcNow,
            ClientIp = clientIp,
            Method = "POST",
            Path = "/api/activation",
            Endpoint = endpoint,
            LicenseKey = "REDACTED",
            HardwareId = hardwareId,
            AppName = appName,
            StatusCode = isSuccess ? 200 : 400,
            ResultStatus = resultStatus,
            IsSuccess = isSuccess,
            DurationMs = 12
        });
    }
}
