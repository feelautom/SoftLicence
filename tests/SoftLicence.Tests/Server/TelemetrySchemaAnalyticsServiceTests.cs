using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetrySchemaAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetrySchemaAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetSchemaSummaryForProductKeyAsync_GroupsSchemasByEventName()
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
                ApiSecret = "product-secret"
            });

            AddEvent(db, productId, "Mcp_ToolCall",
                """{"OS":"Windows","Culture":"en","Tool":"list_blocks","Quota_Mcp_Daily":"1/20"}""");
            AddEvent(db, productId, "Mcp_ToolCall",
                """{"OS":"Windows","Culture":"en","Tool":"compile_device","Quota_Mcp_Daily":"2/20"}""");
            AddEvent(db, productId, "Mcp_ToolCall",
                """{"OS":"Windows","Culture":"en","Tool":"download","Quota_Mcp_Daily":"3/20","Quota_Mcp_Hourly":"1/5"}""");
            AddEvent(db, productId, "CertPinningFailed",
                """{"OS":"Windows","Culture":"en","Host":"api.example.com","Fingerprints":"leaf"}""");

            await db.SaveChangesAsync();
        }

        var service = new TelemetrySchemaAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetSchemaSummaryForProductKeyAsync("product-secret");

        Assert.NotNull(summary);
        Assert.Equal(4, summary.RecordsAnalyzed);
        Assert.Contains(summary.CommonKeys, k => k.Key == "OS" && k.Count == 4);

        var mcp = Assert.Single(summary.Events, e => e.EventName == "Mcp_ToolCall");
        Assert.Equal("mcp", mcp.Family);
        Assert.Equal(3, mcp.Count);
        Assert.Equal(2, mcp.SchemaVariants);
        Assert.Equal(66.7, mcp.TopSchemaPercentage);
        Assert.Contains("OS", mcp.CommonKeys);
        Assert.Contains("Quota_Mcp_Hourly", mcp.SpecificKeys);
    }

    [Fact]
    public async Task GetSchemaSummaryForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddEvent(db, productA, "Mcp_ToolCall", """{"Tool":"a","OS":"Windows"}""");
            AddEvent(db, productB, "Copilot_ToolCall", """{"Tool":"b","OS":"Windows"}""");

            await db.SaveChangesAsync();
        }

        var service = new TelemetrySchemaAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetSchemaSummaryForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Equal(1, summary.RecordsAnalyzed);
        Assert.Single(summary.Events);
        Assert.Equal("Mcp_ToolCall", summary.Events[0].EventName);
    }

    [Fact]
    public async Task GetSchemaSummaryForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetrySchemaAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetSchemaSummaryForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    private static void AddEvent(LicenseDbContext db, Guid productId, string eventName, string propertiesJson)
    {
        var record = new TelemetryRecord
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
        };

        db.TelemetryRecords.Add(record);
    }
}
