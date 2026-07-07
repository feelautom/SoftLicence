using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using System.Text.Json;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class FreemiumAbuseRiskAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public FreemiumAbuseRiskAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetRiskForProductIdAsync_GroupsAndScoresFreemiumAbuseSignals()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var freemiumTypeId = Guid.NewGuid();

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
                Id = freemiumTypeId,
                ProductId = productId,
                Name = "TIA Connect Freemium",
                Slug = "TIA-CONNECT-FREEMIUM",
                IsFree = true
            });

            AddLicense(db, productId, freemiumTypeId, "SPAKO-0001", "peter@spako.nl", "HW-SPAKO-1", now.AddDays(-5), now.AddDays(2), true);
            AddLicense(db, productId, freemiumTypeId, "SPAKO-0002", "engineering@spako.nl", "HW-SPAKO-2", now.AddDays(-4), now.AddDays(3), true);
            AddLicense(db, productId, freemiumTypeId, "SPAKO-0003", "automation@spako.nl", "HW-SPAKO-3", now.AddDays(-3), now.AddDays(4), true);

            AddLicense(db, productId, freemiumTypeId, "SOLO-0001", "solo@gmail.com", "HW-SOLO", now.AddDays(-1), now.AddDays(6), true);
            AddLicense(db, productId, freemiumTypeId, "EXPIRED-0001", "old@examplecorp.com", "HW-EXPIRED", now.AddDays(-10), now.AddDays(-1), true);
            AddLicense(db, productId, freemiumTypeId, "REVOKED-0001", "revoked@examplecorp.com", "HW-REVOKED", now.AddDays(-10), now.AddDays(10), false);

            AddEvent(db, productId, "HW-SPAKO-1", "Tag_Export", now.AddHours(-1), "2.1.997", "203.0.113.10", """{"Quota_Copilot_Daily":"100/100"}""");
            AddEvent(db, productId, "HW-SPAKO-1", "Copilot_ToolCall", now.AddHours(-2), "2.1.997", "203.0.113.10", """{"Quota_Mcp_Daily":"18/20"}""");
            AddEvent(db, productId, "HW-SPAKO-2", "Mcp_ToolCall", now.AddHours(-3), "2.1.997", "203.0.113.11", """{"Quota_Mcp_Daily":"20/20"}""");
            AddEvent(db, productId, "HW-SPAKO-3", "Compile_Success", now.AddHours(-4), "2.1.997", "203.0.113.12", "{}");

            AddEvent(db, productId, "HW-SOLO", "Copilot_ToolCall", now.AddHours(-1), "2.1.997", "198.51.100.20", """{"Quota_Copilot_Daily":"100/100"}""");
            AddEvent(db, productId, "HW-EXPIRED", "Mcp_ToolCall", now.AddHours(-1), "2.1.679", "198.51.100.30", "{}");
            AddEvent(db, productId, "HW-REVOKED", "Tag_Create", now.AddHours(-2), "2.1.679", "198.51.100.31", "{}");

            await db.SaveChangesAsync();
        }

        var service = new FreemiumAbuseRiskAnalyticsService(_dbFactoryMock.Object, _cache);
        var period = new TelemetryAnalyticsPeriod(7, now.AddDays(-7), now.AddMinutes(1), "range");

        var result = await service.GetRiskForProductIdAsync(productId, period, take: 20);

        Assert.Equal(3, result.Summary.GroupsAnalyzed);
        Assert.Equal(1, result.Summary.EnterpriseFreemiumGroups);
        Assert.Equal(1, result.Summary.SecuritySignalGroups);
        Assert.True(result.Summary.HighRiskGroups >= 1);

        var spako = Assert.Single(result.Groups, g => g.EmailDomain == "spako.nl");
        Assert.Equal("enterprise_freemium", spako.Classification);
        Assert.Equal("high", spako.RiskBand);
        Assert.Equal(4, spako.PolicyLevel);
        Assert.Equal("request_contact_or_conversion", spako.RecommendedAction);
        Assert.Equal("commercial_review", spako.ReviewCategory);
        Assert.StartsWith("freemium-abuse:enterprise_freemium:L4:", spako.DeduplicationKey);
        Assert.Equal("7d", spako.DeduplicationWindow);
        Assert.Equal(3, spako.EmailCount);
        Assert.Equal(3, spako.HardwareIdCount);
        Assert.Equal(3, spako.ClientIpCount);
        Assert.Contains(spako.Signals, s => s.Code == "business_domain");
        Assert.Contains(spako.Signals, s => s.Code == "quota_saturated");
        Assert.All(spako.HardwareIdsRedacted, h => Assert.DoesNotContain("HW-SPAKO", h));
        Assert.All(spako.ClientIpsRedacted, ip => Assert.EndsWith("***", ip));

        var solo = Assert.Single(result.Groups, g => g.EmailDomain == "gmail.com");
        Assert.Equal("solo_or_low_usage", solo.Classification);
        Assert.Equal(1, solo.PolicyLevel);
        Assert.Equal("observe", solo.RecommendedAction);
        Assert.Single(solo.HardwareIdHashes);
        Assert.Contains(solo.QuotaPeaks, q => q.QuotaKey == "Quota_Copilot_Daily" && q.PeakUsed == 100);

        var security = Assert.Single(result.Groups, g => g.EmailDomain == "examplecorp.com");
        Assert.Equal("security_or_license_signal", security.Classification);
        Assert.Equal(5, security.PolicyLevel);
        Assert.Equal("route_to_license_security_review", security.RecommendedAction);
        Assert.Equal("security_or_license_signal", security.ReviewCategory);
        Assert.Equal(1, security.ExpiredLicenses);
        Assert.Equal(1, security.RevokedLicenses);
        Assert.Contains(security.Signals, s => s.Code == "expired_with_telemetry");
        Assert.Contains(security.Signals, s => s.Code == "revoked_with_telemetry");
    }

    [Fact]
    public async Task GetRiskForProductIdAsync_WhenSameCustomerNameUsesDifferentEmailsAndHardware_FlagsSharedNameCluster()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var freemiumTypeId = Guid.NewGuid();

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
                Id = freemiumTypeId,
                ProductId = productId,
                Name = "TIA Connect Freemium",
                Slug = "TIA-CONNECT-FREEMIUM",
                IsFree = true
            });

            AddLicense(db, productId, freemiumTypeId, "NAME-0001", "first@gmail.com", "HW-NAME-1", now.AddDays(-2), now.AddDays(5), true, "Oussama Essalih");
            AddLicense(db, productId, freemiumTypeId, "NAME-0002", "second@outlook.com", "HW-NAME-2", now.AddDays(-1), now.AddDays(6), true, "Oussama Essalih");

            AddEvent(db, productId, "HW-NAME-1", "Mcp_ToolCall", now.AddHours(-1), "2.1.997", "198.51.100.10", """{"Quota_Mcp_Daily":"20/20"}""");
            AddEvent(db, productId, "HW-NAME-2", "Compile_Success", now.AddHours(-2), "2.1.997", "198.51.100.11", "{}");

            await db.SaveChangesAsync();
        }

        var service = new FreemiumAbuseRiskAnalyticsService(_dbFactoryMock.Object, _cache);
        var period = new TelemetryAnalyticsPeriod(7, now.AddDays(-7), now.AddMinutes(1), "range");

        var result = await service.GetRiskForProductIdAsync(productId, period, take: 20);

        var group = Assert.Single(result.Groups, g => g.GroupType == "customer_name");
        Assert.Equal("probable_multi_account_abuse", group.Classification);
        Assert.Equal(2, group.EmailCount);
        Assert.Equal(2, group.HardwareIdCount);
        Assert.Single(group.CustomerNameHashes);
        Assert.Contains(group.Signals, s => s.Code == "shared_customer_name");
        Assert.DoesNotContain("Oussama", JsonSerializer.Serialize(group), StringComparison.OrdinalIgnoreCase);
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
        bool isActive,
        string? customerName = null)
    {
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = key,
            CustomerEmail = email,
            CustomerName = customerName ?? email,
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
        string version,
        string clientIp,
        string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            HardwareId = hardwareId,
            ClientIp = clientIp,
            AppName = "TIAConnect",
            Version = version,
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
