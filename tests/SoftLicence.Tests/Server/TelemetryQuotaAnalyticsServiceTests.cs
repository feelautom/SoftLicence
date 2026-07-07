using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryQuotaAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryQuotaAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetQuotaSummaryForProductKeyAsync_AggregatesQuotaMetrics()
    {
        var productId = Guid.NewGuid();

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

            AddEvent(db, productId, "Mcp_ToolCall",
                """{"RequestSource":"MCP_Agent","Quota_Mcp_Daily":"3/20","Quota_Api_Daily":"1/10"}""");
            AddEvent(db, productId, "Mcp_ToolCall",
                """{"RequestSource":"MCP_Agent","Quota_Mcp_Daily":"9/20","Quota_Api_Daily":"2/10"}""");
            AddEvent(db, productId, "Copilot_ToolCall",
                """{"RequestSource":"API_Direct","Quota_Copilot_Daily":"5/50","Quota_Mcp_Daily":"4/20"}""");
            AddEvent(db, productId, "UI_Navigate",
                """{"RequestSource":"API_Direct","Page":"Home"}""");

            await db.SaveChangesAsync();
        }

        var service = new TelemetryQuotaAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetQuotaSummaryForProductKeyAsync("secret");

        Assert.NotNull(summary);
        Assert.Equal(4, summary.RecordsAnalyzed);
        Assert.Equal(3, summary.RecordsWithQuota);

        var mcpQuota = Assert.Single(summary.Quotas, q => q.QuotaKey == "Quota_Mcp_Daily");
        Assert.Equal(3, mcpQuota.Samples);
        Assert.Equal(9, mcpQuota.PeakUsed);
        Assert.Equal(20, mcpQuota.Limit);
        Assert.Equal(45.0, mcpQuota.PeakPercentage);
        Assert.Equal(5.3, mcpQuota.AverageUsed);

        var mcp = Assert.Single(summary.Channels, c => c.Channel == "mcp");
        Assert.Equal(2, mcp.Count);
        Assert.Equal(66.7, mcp.Percentage);

        Assert.Contains(summary.RequestSources, s => s.Name == "MCP_Agent" && s.Count == 2);
        Assert.Contains(summary.RequestSources, s => s.Name == "API_Direct" && s.Count == 1);
    }

    [Fact]
    public async Task GetQuotaSummaryForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddEvent(db, productA, "Mcp_ToolCall", """{"Quota_Mcp_Daily":"1/20"}""");
            AddEvent(db, productB, "Mcp_ToolCall", """{"Quota_Mcp_Daily":"9/20"}""");
            await db.SaveChangesAsync();
        }

        var service = new TelemetryQuotaAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetQuotaSummaryForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        var quota = Assert.Single(summary.Quotas);
        Assert.Equal(1, quota.PeakUsed);
    }

    [Fact]
    public async Task GetQuotaSummaryForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryQuotaAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetQuotaSummaryForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    private static void AddEvent(LicenseDbContext db, Guid productId, string eventName, string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = DateTime.UtcNow,
            HardwareId = Guid.NewGuid().ToString("N"),
            AppName = "TIAConnect",
            Version = "2.1.857",
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent
            {
                PropertiesJson = propertiesJson
            }
        });
    }
}
