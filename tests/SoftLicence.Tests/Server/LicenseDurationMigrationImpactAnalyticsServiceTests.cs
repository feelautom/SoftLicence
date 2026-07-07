using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class LicenseDurationMigrationImpactAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public LicenseDurationMigrationImpactAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetImpactForProductIdAsync_ReturnsRedactedFreemiumMigrationImpact()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "private",
                PublicKeyXml = "public",
                ApiSecret = "secret"
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = typeId,
                ProductId = productId,
                Name = "TIA Connect Freemium",
                Slug = "TIA-CONNECT-FREEMIUM",
                IsFree = true
            });

            AddLicense(db, productId, typeId, "AAAA-BBBB-CCCC-DDDD", "active1@example.test", "HW-A", now.AddDays(-10), now.AddDays(20));
            AddLicense(db, productId, typeId, "EEEE-FFFF-GGGG-HHHH", "active3@example.test", "HW-B", now.AddDays(-15), now.AddDays(15));
            AddLicense(db, productId, typeId, "IIII-JJJJ-KKKK-LLLL", "old@example.test", "HW-C", now.AddDays(-29), now.AddDays(1));
            AddLicense(db, productId, typeId, "MMMM-NNNN-OOOO-PPPP", "delivered@example.test", null, null, now.AddDays(30));
            AddLicense(db, productId, typeId, "QQQQ-RRRR-SSSS-TTTT", "too-new@example.test", "HW-D", now.AddDays(-3), now.AddDays(27));

            AddEvent(db, productId, "HW-A", "Mcp_ToolCall", now.AddHours(-12), """{"AccountType":"professional"}""");
            AddEvent(db, productId, "HW-A", "Block_Export", now.AddHours(-10), """{"AccountType":"professional"}""");
            AddEvent(db, productId, "HW-B", "Copilot_ToolCall", now.AddDays(-2), """{"AccountType":"personal"}""");
            AddEvent(db, productId, "HW-C", "Compile_Success", now.AddDays(-8), """{"AccountType":"personal"}""");

            await db.SaveChangesAsync();
        }

        var service = new LicenseDurationMigrationImpactAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetImpactForProductIdAsync(
            productId,
            licenseType: "TIA-CONNECT-FREEMIUM",
            currentDurationDays: 30,
            targetDurationDays: 7,
            activityWindowsDays: "1,3,7",
            includeSamples: true,
            sampleLimit: 10,
            topEvents: 10);

        Assert.Equal(3, result.Summary.TotalCandidates);
        Assert.Equal(1, result.Summary.DeliveredNotActivated);
        Assert.Equal(1, result.Summary.Active1d);
        Assert.Equal(2, result.Summary.Active3d);
        Assert.Equal(2, result.Summary.Active7d);
        Assert.Equal(1, result.Summary.Inactive7d);
        Assert.Equal(1, result.Summary.ProfessionalActive7d);
        Assert.Equal(1, result.Summary.PersonalActive7d);
        Assert.Equal("TIA-CONNECT-FREEMIUM", result.LicenseType);
        Assert.Equal(new[] { 1, 3, 7 }, result.ActivityWindowsDays);

        var dayOne = Assert.Single(result.ByDaysRemaining, d => d.DaysRemaining == 1);
        Assert.Equal(1, dayOne.Total);
        Assert.Equal(0, dayOne.Active7d);

        Assert.Contains(result.TopEvents, e => e.EventName == "Mcp_ToolCall" && e.Count == 1 && e.HardwareIds == 1);
        Assert.Equal(3, result.Samples.Count);
        Assert.DoesNotContain(result.Samples, s => s.CustomerEmailRedacted.Contains("active1@example.test", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(result.Samples, s => s.LicenseKeyRedacted.Contains("AAAA-BBBB-CCCC-DDDD", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Samples, s => s.HardwareIdRedacted.StartsWith("HW-A", StringComparison.OrdinalIgnoreCase) == false);
    }

    private static void AddLicense(
        LicenseDbContext db,
        Guid productId,
        Guid typeId,
        string key,
        string email,
        string? hardwareId,
        DateTime? activationDate,
        DateTime? expirationDate)
    {
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = key,
            CustomerEmail = email,
            CustomerName = email,
            HardwareId = hardwareId,
            ActivationDate = activationDate,
            CreationDate = activationDate ?? DateTime.UtcNow,
            ExpirationDate = expirationDate,
            IsActive = true
        });
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        DateTime timestamp,
        string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = "2.1.900",
            Type = TelemetryType.Event,
            EventName = eventName,
            Timestamp = timestamp,
            EventData = new TelemetryEvent
            {
                PropertiesJson = propertiesJson
            }
        });
    }
}
