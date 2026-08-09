using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryCertPinningAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryCertPinningAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetCertPinningSummaryForProductKeyAsync_AggregatesIncidents()
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

            AddEvent(db, productId, "HW-A", "2.1.857", "CertPinningFailed",
                """{"Host":"api.t-ia-connect.com","FailureReason":"PinMismatch","SuppressedCount":"2","Fingerprints":"leaf"}""");
            AddEvent(db, productId, "HW-B", "2.1.857", "CertPinningFailed",
                """{"Host":"api.t-ia-connect.com","FailureReason":"PinMismatch","SuppressedFailures":"1"}""");
            AddEvent(db, productId, "HW-B", "2.1.900", "CertPinningRecovered",
                """{"Host":"api.t-ia-connect.com","Reason":"Pinned certificate restored"}""");
            AddEvent(db, productId, "HW-B", "2.1.900", "Mcp_ToolCall",
                """{"Tool":"list_blocks"}""");

            db.TelemetryCertPinningDailyAlerts.Add(new TelemetryCertPinningDailyAlert
            {
                ProductId = productId,
                HardwareId = "HW-A",
                AlertType = CertPinningDailyAlertService.AlertType,
                ParisDate = DateOnly.FromDateTime(DateTime.UtcNow),
                OccurrenceCount = 4,
                ClientSuppressedCount = 9,
                FirstSeenUtc = DateTime.UtcNow.AddHours(-2),
                LastSeenUtc = DateTime.UtcNow,
                FirstHost = "api.t-ia-connect.com",
                LastHost = "softlicence.EXAMPLE.COM",
                LastVersion = "2.1.857",
                LastFailureReason = "PinMismatch",
                LastCertificateIssuer = "CN=Enterprise Forward Trust",
                NotificationSentAtUtc = DateTime.UtcNow.AddHours(-2)
            });

            await db.SaveChangesAsync();
        }

        var service = new TelemetryCertPinningAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetCertPinningSummaryForProductKeyAsync("secret");

        Assert.NotNull(summary);
        Assert.False(summary.Cached);
        Assert.Equal(3, summary.RecordsAnalyzed);
        Assert.Equal(3, summary.Incidents);
        Assert.Equal(2, summary.Failures);
        Assert.Equal(1, summary.Recoveries);
        Assert.Equal(3, summary.SuppressedFailures);
        Assert.Equal(2, summary.UniqueDevices);
        Assert.Equal(1, summary.DailyAlertGroups);
        Assert.Equal(1, summary.DailyNotificationsSent);
        Assert.Equal(4, summary.DailyOccurrencesTracked);
        Assert.Equal(9, summary.DailyClientSuppressedTracked);
        var daily = Assert.Single(summary.RecentDailyAlerts);
        Assert.Equal("HW-A", daily.HardwareId);
        Assert.Equal("softlicence.EXAMPLE.COM", daily.LastHost);
        Assert.Equal("PinMismatch", daily.LastFailureReason);
        Assert.Equal("CN=Enterprise Forward Trust", daily.LastCertificateIssuer);
        Assert.True(daily.NotificationAttempted);
        Assert.True(daily.NotificationSent);
        Assert.Contains(summary.EventNames, e => e.Name == "CertPinningFailed" && e.Count == 2);
        Assert.Contains(summary.Hosts, h => h.Name == "api.t-ia-connect.com" && h.Count == 3);
        Assert.Contains(summary.FailureReasons, r => r.Name == "PinMismatch" && r.Count == 2);
        Assert.Contains(summary.Versions, v => v.Name == "2.1.857" && v.Count == 2);
    }

    [Fact]
    public async Task GetCertPinningSummaryForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddEvent(db, productA, "HW-A", "1.0", "CertPinningFailed", """{"Host":"a.example.com"}""");
            AddEvent(db, productB, "HW-B", "1.0", "CertPinningFailed", """{"Host":"b.example.com"}""");
            await db.SaveChangesAsync();
        }

        var service = new TelemetryCertPinningAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetCertPinningSummaryForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Equal(1, summary.RecordsAnalyzed);
        Assert.Single(summary.Hosts);
        Assert.Equal("a.example.com", summary.Hosts[0].Name);
    }

    [Fact]
    public async Task GetCertPinningSummaryForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryCertPinningAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetCertPinningSummaryForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string version,
        string eventName,
        string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = DateTime.UtcNow,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent
            {
                PropertiesJson = propertiesJson
            }
        });
    }
}
