using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class LicenseUsageScoringAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public LicenseUsageScoringAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetScoresForProductIdAsync_ClassifiesUsageProfilesAndRedactsSensitiveData()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var trialTypeId = Guid.NewGuid();
        var subscriptionTypeId = Guid.NewGuid();
        var paidTypeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndTypes(db, productId, trialTypeId, subscriptionTypeId, paidTypeId);

            AddLicense(db, productId, trialTypeId, "TRIAL-SECRET-1111", "trial.hot@example.test", "HW-TRIAL-HOT-111111", now.AddDays(-5), now.AddDays(9));
            AddLicense(db, productId, subscriptionTypeId, "SUB-SECRET-2222", "engaged@example.test", "HW-SUB-ENGAGED-222222", now.AddDays(-60), now.AddDays(300));
            AddLicense(db, productId, paidTypeId, "POWER-SECRET-3333", "power@example.test", "HW-POWER-333333", now.AddDays(-15), now.AddDays(200));
            AddLicense(db, productId, subscriptionTypeId, "DORMANT-SECRET-4444", "dormant@example.test", "HW-DORMANT-444444", now.AddDays(-90), now.AddDays(200));
            AddLicense(db, productId, subscriptionTypeId, "RISK-SECRET-5555", "risk@example.test", "HW-RISK-555555", now.AddDays(-20), now.AddDays(200));
            AddLicense(db, productId, paidTypeId, "NONE-SECRET-6666", "none@example.test", "HW-NONE-666666", now.AddDays(-2), now.AddDays(200));

            AddEvent(db, productId, "HW-TRIAL-HOT-111111", "Wizard_Completed", now.AddDays(-5), "{}");
            AddEvent(db, productId, "HW-TRIAL-HOT-111111", "Mcp_ToolCall", now.AddDays(-5).AddMinutes(10), "{}");
            AddEvent(db, productId, "HW-TRIAL-HOT-111111", "Block_Export", now.AddDays(-5).AddMinutes(20), "{}");
            AddEvent(db, productId, "HW-TRIAL-HOT-111111", "Copilot_ToolCall", now.AddDays(-3), """{"RequestSource":"API_Direct"}""");
            AddEvent(db, productId, "HW-TRIAL-HOT-111111", "Compile_Success", now.AddDays(-2), "{}");

            AddEvent(db, productId, "HW-SUB-ENGAGED-222222", "Project_Open", now.AddDays(-4), "{}");
            AddEvent(db, productId, "HW-SUB-ENGAGED-222222", "Mcp_ToolCall", now.AddDays(-2), "{}");
            AddEvent(db, productId, "HW-SUB-ENGAGED-222222", "Compile_Success", now.AddDays(-1), "{}");
            AddEvent(db, productId, "HW-SUB-ENGAGED-222222", "Block_Export", now.AddHours(-2), "{}");

            AddEvent(db, productId, "HW-POWER-333333", "Mcp_ToolCall", now.AddDays(-3), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Copilot_ToolCall", now.AddDays(-2), """{"RequestSource":"MCP"}""");
            AddEvent(db, productId, "HW-POWER-333333", "BlockGeneration_Success", now.AddDays(-2).AddHours(1), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Compile_Success", now.AddDays(-1), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Block_Export", now.AddHours(-1), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Mcp_ToolCall", now.AddDays(-1).AddHours(1), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Copilot_ToolCall", now.AddHours(-8), """{"RequestSource":"MCP"}""");
            AddEvent(db, productId, "HW-POWER-333333", "Tag_Create", now.AddHours(-7), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Project_Save", now.AddHours(-6), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Block_Import", now.AddHours(-5), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Mcp_ToolCall", now.AddHours(-4), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Copilot_Chat_Success", now.AddHours(-3), "{}");
            AddEvent(db, productId, "HW-POWER-333333", "Compile_Success", now.AddHours(-2), "{}");

            AddEvent(db, productId, "HW-DORMANT-444444", "Mcp_ToolCall", now.AddDays(-40), "{}");
            AddEvent(db, productId, "HW-DORMANT-444444", "Compile_Success", now.AddDays(-39), "{}");

            AddEvent(db, productId, "HW-RISK-555555", "Wizard_Completed", now.AddDays(-10), "{}");
            AddEvent(db, productId, "HW-RISK-555555", "API_AuthFailed", now.AddDays(-2), "{}");

            await db.SaveChangesAsync();
        }

        var service = new LicenseUsageScoringAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetScoresForProductIdAsync(
            productId,
            take: 20,
            licenseType: "all",
            status: "all",
            activityWindowDays: 14,
            includeInactive: true,
            sortBy: "score");

        Assert.Equal(6, result.TotalLicensesMatched);
        Assert.Contains(result.Licenses, l => l.CustomerEmailRedacted == "tr***@example.test" && l.Classification == "hot_trial");
        Assert.Contains(result.Licenses, l => l.CustomerEmailRedacted == "en***@example.test" && l.Classification == "engaged_subscriber");
        Assert.Contains(result.Licenses, l => l.CustomerEmailRedacted == "po***@example.test" && l.Classification == "power_user");
        Assert.Contains(result.Licenses, l => l.CustomerEmailRedacted == "do***@example.test" && l.Classification == "dormant");
        Assert.Contains(result.Licenses, l => l.CustomerEmailRedacted == "ri***@example.test" && l.Classification == "at_risk");
        Assert.Contains(result.Licenses, l => l.CustomerEmailRedacted == "no***@example.test" && l.Classification == "dormant");

        var hotTrial = result.Licenses.Single(l => l.CustomerEmailRedacted == "tr***@example.test");
        Assert.True(hotTrial.ConversionPotentialScore >= 70);
        Assert.Contains("multi_day_usage", hotTrial.ReasonCodes);
        Assert.Contains("returned_after_first_session", hotTrial.ReasonCodes);
        Assert.Contains("onboarding_completed", hotTrial.ReasonCodes);

        var dormant = result.Licenses.Single(l => l.CustomerEmailRedacted == "do***@example.test");
        Assert.True(dormant.RetentionConfidenceScore < 40);
        Assert.True(dormant.ChurnRiskScore >= 75);

        var json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("TRIAL-SECRET-1111", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HW-TRIAL-HOT-111111", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trial.hot@example.test", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetScoresForProductIdAsync_SortsAndFiltersByConversionPotential()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var trialTypeId = Guid.NewGuid();
        var subscriptionTypeId = Guid.NewGuid();
        var paidTypeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndTypes(db, productId, trialTypeId, subscriptionTypeId, paidTypeId);
            AddLicense(db, productId, trialTypeId, "HOT-TRIAL", "hot@example.test", "HW-HOT-111111", now.AddDays(-4), now.AddDays(10));
            AddLicense(db, productId, trialTypeId, "COLD-TRIAL", "cold@example.test", "HW-COLD-222222", now.AddDays(-4), now.AddDays(10));

            AddEvent(db, productId, "HW-HOT-111111", "Wizard_Completed", now.AddDays(-4), "{}");
            AddEvent(db, productId, "HW-HOT-111111", "Mcp_ToolCall", now.AddDays(-3), "{}");
            AddEvent(db, productId, "HW-HOT-111111", "Block_Export", now.AddDays(-2), "{}");
            AddEvent(db, productId, "HW-HOT-111111", "Compile_Success", now.AddDays(-1), "{}");

            AddEvent(db, productId, "HW-COLD-222222", "Wizard_Opened", now.AddDays(-4), "{}");
            await db.SaveChangesAsync();
        }

        var service = new LicenseUsageScoringAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetScoresForProductIdAsync(
            productId,
            take: 10,
            licenseType: "trial",
            minScore: 50,
            sortBy: "conversionPotential");

        var item = Assert.Single(result.Licenses);
        Assert.Equal("ho***@example.test", item.CustomerEmailRedacted);
        Assert.Equal("hot_trial", item.Classification);
        Assert.True(item.ConversionPotentialScore >= 70);
    }

    [Fact]
    public async Task GetScoresForProductIdAsync_AllowsExplicitExpiredStatusWithoutIncludeInactive()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var trialTypeId = Guid.NewGuid();
        var subscriptionTypeId = Guid.NewGuid();
        var paidTypeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndTypes(db, productId, trialTypeId, subscriptionTypeId, paidTypeId);
            AddLicense(db, productId, paidTypeId, "ACTIVE-PAID", "active@example.test", "HW-ACTIVE-111111", now.AddDays(-3), now.AddDays(30));
            AddLicense(db, productId, paidTypeId, "EXPIRED-PAID", "expired@example.test", "HW-EXPIRED-222222", now.AddDays(-30), now.AddDays(-1));
            await db.SaveChangesAsync();
        }

        var service = new LicenseUsageScoringAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetScoresForProductIdAsync(
            productId,
            take: 10,
            licenseType: "paid",
            status: "expired");

        var item = Assert.Single(result.Licenses);
        Assert.Equal("expired", item.LicenseStatus);
        Assert.Equal("ex***@example.test", item.CustomerEmailRedacted);
    }

    private static void SeedProductAndTypes(
        LicenseDbContext db,
        Guid productId,
        Guid trialTypeId,
        Guid subscriptionTypeId,
        Guid paidTypeId)
    {
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "T-IA Connect",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = "secret"
        });

        db.LicenseTypes.AddRange(
            new LicenseType
            {
                Id = trialTypeId,
                ProductId = productId,
                Name = "TIA Connect Trial",
                Slug = "TIA-CONNECT-TRIAL",
                IsFree = true
            },
            new LicenseType
            {
                Id = subscriptionTypeId,
                ProductId = productId,
                Name = "TIA Connect Subscription",
                Slug = "TIA-CONNECT-SUB",
                IsRecurring = true
            },
            new LicenseType
            {
                Id = paidTypeId,
                ProductId = productId,
                Name = "TIA Connect Pro",
                Slug = "TIA-CONNECT-PRO"
            });
    }

    private static void AddLicense(
        LicenseDbContext db,
        Guid productId,
        Guid typeId,
        string licenseKey,
        string email,
        string hardwareId,
        DateTime activationDate,
        DateTime expirationDate)
    {
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = licenseKey,
            CustomerEmail = email,
            CustomerName = email,
            HardwareId = hardwareId,
            ActivationDate = activationDate,
            CreationDate = activationDate.AddMinutes(-10),
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
            Version = "2.2.501",
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
