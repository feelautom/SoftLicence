using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryDevicesAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryDevicesAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetDevicesForProductIdAsync_GroupsDevicesAndRespectsProductScope()
    {
        var productId = Guid.NewGuid();
        var otherProductId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        await using (var db = new LicenseDbContext(_dbOptions))
        {
            AddEvent(db, productId, "HW-A", "Startup_AppStarted", "2.1.900", "10.0.0.1", now.AddHours(-4));
            AddEvent(db, productId, "HW-A", "Mcp_ToolCall", "2.1.901", "10.0.0.2", now.AddHours(-1));
            AddEvent(db, productId, "HW-B", "Wizard_McpToolSelected", "2.1.900", "10.0.0.3", now.AddHours(-2));
            AddEvent(db, otherProductId, "HW-C", "OtherProduct_Event", "1.0.0", "10.0.0.4", now.AddHours(-1));
            await db.SaveChangesAsync();
        }

        var service = new TelemetryDevicesAnalyticsService(_dbFactoryMock.Object, _cache);
        var period = new TelemetryAnalyticsPeriod(7, now.AddDays(-7), now.AddMinutes(1), "range");

        var result = await service.GetDevicesForProductIdAsync(productId, period, take: 10, topEvents: 5);

        Assert.False(result.Cached);
        Assert.Equal(3, result.RecordsAnalyzed);
        Assert.Equal(2, result.TotalDevices);
        Assert.Equal(2, result.DevicesReturned);
        Assert.DoesNotContain(result.Devices, d => d.HardwareId == "HW-C");

        var hwA = Assert.Single(result.Devices, d => d.HardwareId == "HW-A");
        Assert.Equal(2, hwA.EventCount);
        Assert.Equal("2.1.901", hwA.LastVersion);
        Assert.Equal("10.0.0.2", hwA.LastClientIp);
        Assert.Contains(hwA.TopEvents, e => e.Name == "Mcp_ToolCall" && e.Count == 1);
        Assert.Contains(hwA.EventFamilies, e => e.Name == "mcp" && e.Count == 1);
    }

    [Fact]
    public async Task GetDevicesForProductIdAsync_ReturnsTotalDevicesEvenWhenTakeLimitsRows()
    {
        var productId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        await using (var db = new LicenseDbContext(_dbOptions))
        {
            AddEvent(db, productId, "HW-A", "Startup_AppStarted", "2.1.900", null, now.AddHours(-3));
            AddEvent(db, productId, "HW-B", "Startup_AppStarted", "2.1.900", null, now.AddHours(-2));
            AddEvent(db, productId, "HW-C", "Startup_AppStarted", "2.1.900", null, now.AddHours(-1));
            await db.SaveChangesAsync();
        }

        var service = new TelemetryDevicesAnalyticsService(_dbFactoryMock.Object, _cache);
        var period = new TelemetryAnalyticsPeriod(7, now.AddDays(-7), now.AddMinutes(1), "range");

        var result = await service.GetDevicesForProductIdAsync(productId, period, take: 2, topEvents: 5);

        Assert.Equal(3, result.TotalDevices);
        Assert.Equal(2, result.DevicesReturned);
        Assert.Equal(2, result.Devices.Count);
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        string? clientIp,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            ClientIp = clientIp,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent { PropertiesJson = """{"Safe":"Value"}""" }
        });
    }
}
