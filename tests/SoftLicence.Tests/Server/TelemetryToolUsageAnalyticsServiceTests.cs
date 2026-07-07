using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryToolUsageAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryToolUsageAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetToolUsageForProductKeyAsync_AggregatesToolCallsAndQuotaPeaks()
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
                """{"Tool":"list_blocks","RequestSource":"MCP_Agent","Quota_Mcp_Daily":"3/20"}""");
            AddEvent(db, productId, "Mcp_ToolCall",
                """{"Tool":"list_blocks","RequestSource":"MCP_Agent","Quota_Mcp_Daily":"8/20"}""");
            AddEvent(db, productId, "Copilot_ToolCall",
                """{"Tool":"compile_device","Provider":"DeepSeek","Model":"deepseek-chat","RequestSource":"API_Direct","Quota_Copilot_Daily":"4/50"}""");
            AddEvent(db, productId, "UI_Navigate",
                """{"Page":"Telemetry","RequestSource":"API_Direct"}""");

            await db.SaveChangesAsync();
        }

        var service = new TelemetryToolUsageAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetToolUsageForProductKeyAsync("secret");

        Assert.NotNull(summary);
        Assert.Equal(3, summary.ToolCallEvents);
        Assert.DoesNotContain(summary.TopTools, t => t.Name == "Telemetry");

        var listBlocks = Assert.Single(summary.TopTools, t => t.Name == "list_blocks");
        Assert.Equal(2, listBlocks.Count);

        var mcp = Assert.Single(summary.Channels, c => c.Channel == "mcp");
        Assert.Equal(2, mcp.Count);
        Assert.Equal(66.7, mcp.Percentage);

        var copilot = Assert.Single(summary.Channels, c => c.Channel == "copilot");
        Assert.Equal(1, copilot.Count);

        var provider = Assert.Single(summary.TopProviders);
        Assert.Equal("DeepSeek", provider.Name);

        var mcpQuota = Assert.Single(summary.QuotaPeaks, q => q.QuotaKey == "Quota_Mcp_Daily");
        Assert.Equal(8, mcpQuota.PeakUsed);
        Assert.Equal(20, mcpQuota.Limit);
        Assert.Equal(40.0, mcpQuota.PeakPercentage);
    }

    [Fact]
    public async Task GetToolUsageForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddEvent(db, productA, "Mcp_ToolCall", """{"Tool":"a"}""");
            AddEvent(db, productB, "Mcp_ToolCall", """{"Tool":"b"}""");
            await db.SaveChangesAsync();
        }

        var service = new TelemetryToolUsageAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetToolUsageForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Single(summary.TopTools);
        Assert.Equal("a", summary.TopTools[0].Name);
    }

    [Fact]
    public async Task GetToolUsageForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryToolUsageAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetToolUsageForProductKeyAsync("missing");

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
