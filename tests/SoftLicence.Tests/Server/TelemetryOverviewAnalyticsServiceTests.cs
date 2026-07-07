using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryOverviewAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryOverviewAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetOverviewForProductKeyAsync_AggregatesTelemetryEnvelope()
    {
        var productId = Guid.NewGuid();
        var timestamp = DateTime.UtcNow.AddMinutes(-5);

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

            AddRecord(db, productId, "HW-A", "10.0.0.1", "TIAConnect", "2.1.857", "Startup_AppStarted", TelemetryType.Event, timestamp.AddDays(-1));
            AddRecord(db, productId, "HW-A", "10.0.0.1", "TIAConnect", "2.1.857", "Mcp_ToolCall", TelemetryType.Event, timestamp.AddDays(-1));
            AddRecord(db, productId, "HW-B", "10.0.0.2", "TIAConnect", "2.1.900", "Copilot_ToolCall", TelemetryType.Event, timestamp);
            AddRecord(db, productId, "HW-B", "10.0.0.2", "TIAConnect", "2.1.900", "Diagnostic_Run", TelemetryType.Diagnostic, timestamp);
            AddRecord(db, productId, "HW-B", "10.0.0.2", "TIAConnect", "2.1.900", "UnhandledException", TelemetryType.Error, timestamp);

            await db.SaveChangesAsync();
        }

        var service = new TelemetryOverviewAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetOverviewForProductKeyAsync("secret", days: 7, top: 10);

        Assert.NotNull(summary);
        Assert.Equal(5, summary.RecordsAnalyzed);
        Assert.Equal(2, summary.UniqueDevices);
        Assert.Equal(2, summary.UniqueClientIps);
        Assert.NotNull(summary.FirstActivityUtc);
        Assert.NotNull(summary.LastActivityUtc);
        Assert.Contains(summary.TypeCounts, c => c.Name == "Event" && c.Count == 3);
        Assert.Contains(summary.TypeCounts, c => c.Name == "Diagnostic" && c.Count == 1);
        Assert.Contains(summary.TypeCounts, c => c.Name == "Error" && c.Count == 1);
        Assert.Contains(summary.TopEvents, c => c.Name == "Startup_AppStarted" && c.Count == 1);
        Assert.Contains(summary.EventFamilies, c => c.Name == "startup" && c.Count == 1);
        Assert.Contains(summary.EventFamilies, c => c.Name == "mcp" && c.Count == 1);
        Assert.Contains(summary.TopVersions, c => c.Name == "2.1.900" && c.Count == 3);
        Assert.Contains(summary.TopApps, c => c.Name == "TIAConnect" && c.Count == 5);
        Assert.Equal(7, summary.DailyActivity.Count);
        Assert.Equal(5, summary.DailyActivity.Sum(d => d.Count));
    }

    [Fact]
    public async Task GetOverviewForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();
        var timestamp = DateTime.UtcNow.AddMinutes(-5);

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddRecord(db, productA, "HW-A", "10.0.0.1", "AppA", "1.0", "Startup_AppStarted", TelemetryType.Event, timestamp);
            AddRecord(db, productB, "HW-B", "10.0.0.2", "AppB", "2.0", "Mcp_ToolCall", TelemetryType.Event, timestamp);
            await db.SaveChangesAsync();
        }

        var service = new TelemetryOverviewAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetOverviewForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Equal(1, summary.RecordsAnalyzed);
        Assert.Single(summary.TopApps);
        Assert.Equal("AppA", summary.TopApps[0].Name);
    }

    [Fact]
    public async Task GetOverviewForProductKeyAsync_IncludesDescendantProducts()
    {
        var rootProduct = Guid.NewGuid();
        var childProduct = Guid.NewGuid();
        var otherProduct = Guid.NewGuid();
        var timestamp = DateTime.UtcNow.AddMinutes(-5);

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = rootProduct, Name = "YOUR_APP_NAME", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "root-secret" },
                new Product { Id = childProduct, Name = "YOUR_APP_NAMEPlugins", ParentProductId = rootProduct, PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "child-secret" },
                new Product { Id = otherProduct, Name = "OtherApp", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "other-secret" });

            AddRecord(db, rootProduct, "HW-ROOT", "10.0.0.1", "YOUR_APP_NAME", "1.0", "Startup_AppStarted", TelemetryType.Event, timestamp);
            AddRecord(db, childProduct, "HW-PLUGIN", "10.0.0.2", "YOUR_APP_NAMEPlugins", "1.1", "Mcp_ToolCall", TelemetryType.Event, timestamp);
            AddRecord(db, otherProduct, "HW-OTHER", "10.0.0.3", "OtherApp", "9.9", "Other_Event", TelemetryType.Event, timestamp);
            await db.SaveChangesAsync();
        }

        var service = new TelemetryOverviewAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetOverviewForProductKeyAsync("root-secret", days: 7, top: 10);

        Assert.NotNull(summary);
        Assert.Equal(2, summary.RecordsAnalyzed);
        Assert.Equal(2, summary.UniqueDevices);
        Assert.Contains(summary.TopApps, app => app.Name == "YOUR_APP_NAME" && app.Count == 1);
        Assert.Contains(summary.TopApps, app => app.Name == "YOUR_APP_NAMEPlugins" && app.Count == 1);
        Assert.DoesNotContain(summary.TopApps, app => app.Name == "OtherApp");
    }

    [Fact]
    public async Task GetOverviewForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryOverviewAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetOverviewForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    [Fact]
    public async Task GetOverviewForProductIdAsync_ReturnsCachedResponseOnSecondCall()
    {
        var productId = Guid.NewGuid();
        var timestamp = DateTime.UtcNow.AddMinutes(-5);
        var period = TelemetryAnalyticsPeriod.Resolve(7, null, timestamp.AddDays(-7).ToString("O"), timestamp.AddMinutes(1).ToString("O"));

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

            AddRecord(db, productId, "HW-A", "10.0.0.1", "TIAConnect", "2.1.857", "Startup_AppStarted", TelemetryType.Event, timestamp);
            await db.SaveChangesAsync();
        }

        var service = new TelemetryOverviewAnalyticsService(_dbFactoryMock.Object, _cache);

        var first = await service.GetOverviewForProductIdAsync(productId, period);
        Assert.False(first.Cached);

        var second = await service.GetOverviewForProductIdAsync(productId, period);

        Assert.True(second.Cached);
        Assert.Equal(first.GeneratedAtUtc, second.GeneratedAtUtc);
        Assert.True(second.ExpiresAtUtc > DateTime.UtcNow);
    }

    private static void AddRecord(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string clientIp,
        string appName,
        string version,
        string eventName,
        TelemetryType type,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            ClientIp = clientIp,
            AppName = appName,
            Version = version,
            EventName = eventName,
            Type = type
        });
    }
}
