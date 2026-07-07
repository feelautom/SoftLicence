using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryLicenseHardwareAuditAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryLicenseHardwareAuditAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetAuditForProductIdAsync_ClassifiesTelemetryHardwareAgainstEffectiveLicenses()
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
                });

            AddLicense(db, productId, proTypeId, "PRO1-BBBB-CCCC-DDDD", "pro@example.test", "HW-ACTIVE-PAID", now.AddDays(-10), now.AddDays(30), true);
            AddLicense(db, productId, freemiumTypeId, "FREE-BBBB-CCCC-DDDD", "free@example.test", "HW-ACTIVE-FREE", now.AddDays(-2), now.AddDays(5), true);
            AddLicense(db, productId, freemiumTypeId, "EXPI-BBBB-CCCC-DDDD", "expired@example.test", "HW-EXPIRED", now.AddDays(-9), now.AddDays(-1), true);
            AddLicense(db, productId, proTypeId, "REVO-BBBB-CCCC-DDDD", "revoked@example.test", "HW-REVOKED", now.AddDays(-10), now.AddDays(20), false);
            AddLicense(db, productId, proTypeId, "DUP1-BBBB-CCCC-DDDD", "dup1@example.test", "HW-DUPLICATE", now.AddDays(-10), now.AddDays(20), true);
            AddLicense(db, productId, freemiumTypeId, "DUP2-BBBB-CCCC-DDDD", "dup2@example.test", "HW-DUPLICATE", now.AddDays(-2), now.AddDays(5), true);

            AddEvent(db, productId, "HW-ACTIVE-PAID", "Block_Export", now.AddHours(-1), "2.1.997");
            AddEvent(db, productId, "HW-ACTIVE-FREE", "UI_Navigate", now.AddHours(-1), "2.1.997");
            AddEvent(db, productId, "HW-EXPIRED", "Mcp_ToolCall", now.AddHours(-2), "2.1.990");
            AddEvent(db, productId, "HW-REVOKED", "Copilot_ToolCall", now.AddHours(-3), "2.1.990");
            AddEvent(db, productId, "HW-NO-LICENSE", "Startup_AppStarted", now.AddHours(-4), "2.1.922");
            AddEvent(db, productId, "HW-DUPLICATE", "Compile_Started", now.AddHours(-5), "2.1.997");
            AddEvent(db, productId, "", "Startup_NoLicenseDetected", now.AddHours(-6), "2.1.997");

            await db.SaveChangesAsync();
        }

        var service = new TelemetryLicenseHardwareAuditAnalyticsService(_dbFactoryMock.Object, _cache);
        var period = new TelemetryAnalyticsPeriod(7, now.AddDays(-7), now.AddMinutes(1), "range");

        var result = await service.GetAuditForProductIdAsync(productId, period, "1,3,7", take: 20);

        Assert.Equal(7, result.Summary.TelemetryRecords);
        Assert.Equal(6, result.Summary.TelemetryMachines);
        Assert.Equal(1, result.Summary.TelemetryWithoutHardwareId);
        Assert.Equal(3, result.Summary.MachinesWithActiveValidLicense);
        Assert.Equal(1, result.Summary.MachinesWithActivePaid);
        Assert.Equal(1, result.Summary.MachinesWithActiveFreemium);
        Assert.Equal(1, result.Summary.MachinesWithExpiredLicense);
        Assert.Equal(1, result.Summary.MachinesWithRevokedLicense);
        Assert.Equal(1, result.Summary.MachinesWithoutLicense);
        Assert.Equal(1, result.Summary.MachinesWithMultipleLicenses);
        Assert.True(result.Summary.BlockingMismatchDetected);

        Assert.Contains(result.ClassificationCounts, c => c.Name == "active_paid" && c.Count == 1);
        Assert.Contains(result.ClassificationCounts, c => c.Name == "active_freemium" && c.Count == 1);
        Assert.Contains(result.ClassificationCounts, c => c.Name == "expired" && c.Count == 1);
        Assert.Contains(result.ClassificationCounts, c => c.Name == "revoked" && c.Count == 1);
        Assert.Contains(result.ClassificationCounts, c => c.Name == "no_license" && c.Count == 1);
        Assert.Contains(result.ClassificationCounts, c => c.Name == "multiple_licenses" && c.Count == 1);

        var noLicense = Assert.Single(result.Anomalies, a => a.Classification == "no_license");
        Assert.Equal("2.1.922", noLicense.LastVersion);
        Assert.Equal("Startup_AppStarted", noLicense.LastEventName);
        Assert.Equal(16, noLicense.HardwareIdHash.Length);
        Assert.DoesNotContain("HW-NO-LICENSE", noLicense.HardwareIdRedacted);

        var expired = Assert.Single(result.Anomalies, a => a.Classification == "expired");
        Assert.DoesNotContain("EXPI-BBBB-CCCC-DDDD", expired.LicenseKeyRedacted);
        Assert.NotEqual("expired@example.test", expired.CustomerEmailRedacted);
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
        string version)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            Type = TelemetryType.Event,
            EventName = eventName,
            Timestamp = timestamp,
            EventData = new TelemetryEvent
            {
                PropertiesJson = "{}"
            }
        });
    }
}
