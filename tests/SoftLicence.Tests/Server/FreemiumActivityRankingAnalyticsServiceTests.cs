using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class FreemiumActivityRankingAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public FreemiumActivityRankingAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetRankingForProductIdAsync_RanksExpiredFreemiumByActivityAndRedactsSensitiveData()
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

            AddLicense(db, productId, typeId, "AAAA-BBBB-CCCC-DDDD", "hot@example.test", "HW-HOT-EXPIRED", now.AddDays(-9), now.AddDays(-1), isActive: true);
            AddLicense(db, productId, typeId, "EEEE-FFFF-GGGG-HHHH", "cold@example.test", "HW-COLD-EXPIRED", now.AddDays(-12), now.AddDays(-2), isActive: true);
            AddLicense(db, productId, typeId, "IIII-JJJJ-KKKK-LLLL", "active@example.test", "HW-ACTIVE", now.AddDays(-4), now.AddDays(3), isActive: true);
            AddLicense(db, productId, typeId, "MMMM-NNNN-OOOO-PPPP", "revoked@example.test", "HW-REVOKED", now.AddDays(-20), now.AddDays(10), isActive: false);

            AddEvent(db, productId, "HW-HOT-EXPIRED", "BlockGeneration_Success", now.AddHours(-2), """{"AccountType":"professional","Quota_Mcp_Daily":"10/10"}""");
            AddEvent(db, productId, "HW-HOT-EXPIRED", "Compile_Success", now.AddHours(-1), """{"AccountType":"professional"}""");
            AddEvent(db, productId, "HW-HOT-EXPIRED", "Mcp_ToolCall", now.AddMinutes(-30), """{"AccountType":"professional"}""");
            AddEvent(db, productId, "HW-HOT-EXPIRED", "API_AuthFailed", now.AddMinutes(-10), "{}");
            AddEvent(db, productId, "HW-COLD-EXPIRED", "Startup_AppStarted", now.AddDays(-2), """{"AccountType":"personal"}""");
            AddEvent(db, productId, "HW-ACTIVE", "Block_Export", now.AddHours(-3), "{}");
            AddEvent(db, productId, "HW-REVOKED", "Mcp_ToolCall", now.AddHours(-1), "{}");

            await db.SaveChangesAsync();
        }

        var service = new FreemiumActivityRankingAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetRankingForProductIdAsync(
            productId,
            status: "expired",
            telemetryDays: 7,
            activationAgeMinDays: 7,
            includeSamples: true,
            take: 10);

        Assert.Equal("expired", result.StatusFilter);
        Assert.Equal(2, result.Summary.TotalLicensesInFilter);
        Assert.Equal(2, result.Summary.RankedMachines);
        Assert.Equal(1, result.Summary.ActiveTelemetry1d);
        Assert.Equal(2, result.Summary.ActiveTelemetry3d);
        Assert.Equal(1, result.Summary.QuotaLimitedMachines);
        Assert.Equal(1, result.Summary.MachinesWithNegativeSignals);

        var top = result.Rankings.First();
        Assert.Equal("expired", top.LicenseStatus);
        Assert.True(top.Score > 0);
        Assert.Equal(2, top.ProductiveEvents);
        Assert.Equal(1, top.McpCopilotEvents);
        Assert.Contains("Quota_Mcp_Daily:10/10", top.QuotaFlags);
        Assert.Contains("auth_failed", top.NegativeFlags);
        Assert.Equal("professional", top.UserSegment);
        Assert.Equal("hot@example.test", top.CustomerEmail);
        Assert.NotEqual("hot@example.test", top.CustomerEmailRedacted);
        Assert.DoesNotContain("AAAA-BBBB-CCCC-DDDD", top.LicenseKeyRedacted);
        Assert.DoesNotContain("HW-HOT-EXPIRED", top.HardwareIdRedacted);
        Assert.Equal(16, top.HardwareIdHash.Length);
        Assert.NotEmpty(top.RecentEvents);
    }

    [Fact]
    public async Task GetPaidRankingForProductIdAsync_ExcludesFreemiumAndSupportsTypeFilters()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var freemiumTypeId = Guid.NewGuid();
        var proTypeId = Guid.NewGuid();
        var enterpriseTypeId = Guid.NewGuid();

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
            db.LicenseTypes.AddRange(
                new LicenseType
                {
                    Id = freemiumTypeId,
                    ProductId = productId,
                    Name = "TIA Connect Freemium",
                    Slug = "TIA-CONNECT-FREEMIUM",
                    IsFree = true
                },
                new LicenseType
                {
                    Id = proTypeId,
                    ProductId = productId,
                    Name = "TIA Connect Pro",
                    Slug = "TIA-CONNECT-PRO",
                    IsFree = false
                },
                new LicenseType
                {
                    Id = enterpriseTypeId,
                    ProductId = productId,
                    Name = "TIA Connect Enterprise",
                    Slug = "TIA-CONNECT-ENT",
                    IsFree = false
                });

            AddLicense(db, productId, freemiumTypeId, "FREE-BBBB-CCCC-DDDD", "free@example.test", "HW-FREE", now.AddDays(-9), now.AddDays(5), isActive: true);
            AddLicense(db, productId, proTypeId, "PRO1-BBBB-CCCC-DDDD", "pro@example.test", "HW-PRO", now.AddDays(-40), now.AddDays(40), isActive: true);
            AddLicense(db, productId, enterpriseTypeId, "ENT1-BBBB-CCCC-DDDD", "ent@example.test", "HW-ENT", now.AddDays(-60), now.AddDays(60), isActive: true);

            AddEvent(db, productId, "HW-FREE", "BlockGeneration_Success", now.AddHours(-1), "{}");
            AddEvent(db, productId, "HW-PRO", "BlockGeneration_Success", now.AddHours(-2), """{"Quota_Mcp_Daily":"9/10"}""");
            AddEvent(db, productId, "HW-PRO", "Mcp_ToolCall", now.AddHours(-1), "{}");
            AddEvent(db, productId, "HW-ENT", "Compile_Success", now.AddHours(-3), "{}");

            await db.SaveChangesAsync();
        }

        var service = new FreemiumActivityRankingAnalyticsService(_dbFactoryMock.Object, _cache);

        var allPaid = await service.GetPaidRankingForProductIdAsync(
            productId,
            status: "active",
            telemetryDays: 7,
            take: 10);

        Assert.Equal("paid", allPaid.LicenseType);
        Assert.Equal(2, allPaid.Summary.TotalLicensesInFilter);
        Assert.Equal(2, allPaid.Summary.RankedMachines);
        Assert.DoesNotContain(allPaid.Rankings, r => r.LicenseTypeSlug == "TIA-CONNECT-FREEMIUM");
        Assert.Contains(allPaid.Rankings, r => r.LicenseTypeSlug == "TIA-CONNECT-PRO");
        Assert.Contains(allPaid.Rankings, r => r.LicenseTypeSlug == "TIA-CONNECT-ENT");

        var proOnly = await service.GetPaidRankingForProductIdAsync(
            productId,
            licenseTypes: "TIA-CONNECT-PRO",
            status: "active",
            telemetryDays: 7,
            take: 10);

        Assert.Equal("TIA-CONNECT-PRO", Assert.Single(proOnly.LicenseTypes));
        var pro = Assert.Single(proOnly.Rankings);
        Assert.Equal("TIA-CONNECT-PRO", pro.LicenseTypeSlug);
        Assert.Equal("pro@example.test", pro.CustomerEmail);
        Assert.Contains("Quota_Mcp_Daily:9/10", pro.QuotaFlags);
    }

    [Fact]
    public async Task GetLicenseTypesForProductIdAsync_ReturnsCountsAndCanExcludeFreeTypes()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var freemiumTypeId = Guid.NewGuid();
        var proTypeId = Guid.NewGuid();

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
            db.LicenseTypes.AddRange(
                new LicenseType
                {
                    Id = freemiumTypeId,
                    ProductId = productId,
                    Name = "Freemium",
                    Slug = "TIA-CONNECT-FREEMIUM",
                    IsFree = true
                },
                new LicenseType
                {
                    Id = proTypeId,
                    ProductId = productId,
                    Name = "Pro",
                    Slug = "TIA-CONNECT-PRO",
                    IsFree = false
                });

            AddLicense(db, productId, freemiumTypeId, "FREE-BBBB-CCCC-DDDD", "free@example.test", "HW-FREE", now.AddDays(-9), now.AddDays(5), isActive: true);
            AddLicense(db, productId, proTypeId, "PRO1-BBBB-CCCC-DDDD", "pro@example.test", "HW-PRO", now.AddDays(-40), now.AddDays(40), isActive: true);
            AddLicense(db, productId, proTypeId, "PRO2-BBBB-CCCC-DDDD", "expired@example.test", "HW-PRO-OLD", now.AddDays(-90), now.AddDays(-1), isActive: true);
            AddLicense(db, productId, proTypeId, "PRO3-BBBB-CCCC-DDDD", "revoked@example.test", "HW-PRO-REV", now.AddDays(-90), now.AddDays(30), isActive: false);

            await db.SaveChangesAsync();
        }

        var service = new FreemiumActivityRankingAnalyticsService(_dbFactoryMock.Object, _cache);

        var allTypes = await service.GetLicenseTypesForProductIdAsync(productId);

        Assert.Equal(2, allTypes.TotalTypes);
        Assert.Equal(4, allTypes.TotalLicenses);
        Assert.Contains(allTypes.LicenseTypes, t => t.Slug == "TIA-CONNECT-FREEMIUM" && t.IsFree);
        var pro = Assert.Single(allTypes.LicenseTypes, t => t.Slug == "TIA-CONNECT-PRO");
        Assert.Equal(3, pro.TotalLicenses);
        Assert.Equal(1, pro.ActiveLicenses);
        Assert.Equal(1, pro.ExpiredLicenses);
        Assert.Equal(1, pro.RevokedLicenses);

        var paidOnly = await service.GetLicenseTypesForProductIdAsync(productId, includeFree: false);

        Assert.DoesNotContain(paidOnly.LicenseTypes, t => t.Slug == "TIA-CONNECT-FREEMIUM");
        Assert.Single(paidOnly.LicenseTypes);
    }

    [Fact]
    public async Task GetRankingForProductIdAsync_DoesNotRankLegacyHardwareIdWhenActiveSeatExists()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product { Id = productId, Name = "TIAConnect", PrivateKeyXml = "private", PublicKeyXml = "public", ApiSecret = "secret" });
            db.LicenseTypes.Add(new LicenseType { Id = typeId, ProductId = productId, Name = "TIA Connect Freemium", Slug = "TIA-CONNECT-FREEMIUM", IsFree = true });
            db.Licenses.Add(new License
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                LicenseTypeId = typeId,
                LicenseKey = "FREE-LEGACY-SEAT",
                CustomerEmail = "phantom@example.test",
                CustomerName = "Phantom",
                HardwareId = "HW-LEGACY-PHANTOM",
                ActivationDate = now.AddDays(-3),
                CreationDate = now.AddDays(-3),
                ExpirationDate = now.AddDays(3),
                IsActive = true,
                Seats =
                {
                    new LicenseSeat { HardwareId = "HW-ACTIVE-SEAT", FirstActivatedAt = now.AddDays(-2), LastCheckInAt = now.AddHours(-1), IsActive = true }
                }
            });
            AddEvent(db, productId, "HW-LEGACY-PHANTOM", "BlockGeneration_Success", now.AddHours(-1), "{}");
            await db.SaveChangesAsync();
        }

        var service = new FreemiumActivityRankingAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetRankingForProductIdAsync(productId, status: "active", telemetryDays: 7, take: 10);

        Assert.Equal(1, result.Summary.TotalLicensesInFilter);
        Assert.Equal(0, result.Summary.RankedMachines);
        Assert.Empty(result.Rankings);
    }

    private static void AddLicense(
        LicenseDbContext db,
        Guid productId,
        Guid typeId,
        string key,
        string email,
        string hardwareId,
        DateTime activationDate,
        DateTime expirationDate,
        bool isActive)
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
            CreationDate = activationDate,
            ExpirationDate = expirationDate,
            IsActive = isActive,
            RevokedAt = isActive ? null : DateTime.UtcNow
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
