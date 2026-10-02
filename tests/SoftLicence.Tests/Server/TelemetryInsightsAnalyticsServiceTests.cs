using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryInsightsAnalyticsServiceTests
{
    [Fact]
    public async Task GetInsightsForProductIdAsync_CountsActualUpdPresentationsAndDistinctDevices()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var productId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        await using (var db = new LicenseDbContext(options))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "private",
                PublicKeyXml = "public",
                ApiSecret = "secret"
            });
            AddPresentation(db, productId, "HW-A", now.AddMinutes(-3), "initial");
            AddPresentation(db, productId, "HW-A", now.AddMinutes(-2), "retry");
            AddPresentation(db, productId, "HW-B", now.AddMinutes(-1), "initial");
            db.TelemetryRecords.Add(new TelemetryRecord
            {
                ProductId = productId,
                Timestamp = now,
                HardwareId = "HW-MALFORMED",
                AppName = "TIAConnect",
                Version = "2.4.380",
                EventName = UpdatePreflightFailureAlertService.EventName,
                Type = TelemetryType.Event,
                EventData = new TelemetryEvent { PropertiesJson = "{\"SupportCode\":\"UPD-9999\"}" }
            });
            await db.SaveChangesAsync();
        }

        var factory = new Mock<IDbContextFactory<LicenseDbContext>>();
        factory.Setup(item => item.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(options));
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var service = new TelemetryInsightsAnalyticsService(factory.Object, cache);

        var response = await service.GetInsightsForProductIdAsync(
            productId,
            new TelemetryAnalyticsPeriod(1, now.AddHours(-1), now.AddMinutes(1), "range"));

        var insight = Assert.Single(response.Insights, item => item.Category == "update-preflight");
        Assert.Equal(3, insight.Count);
        Assert.Equal(2, insight.UniqueDevices);
        Assert.Contains(insight.Breakdown, item =>
            item.Name == "UPD-1002 | distribution_downloads_paused | 2.4.380"
            && item.Count == 3);
    }

    private static void AddPresentation(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        DateTime timestamp,
        string stage)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = "2.4.380",
            EventName = UpdatePreflightFailureAlertService.EventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent
            {
                PropertiesJson = "{\"SupportCode\":\"UPD-1002\",\"CurrentVersion\":\"2.4.380\"," +
                    "\"LatestVersion\":\"2.4.309\",\"PresentationStage\":\"" + stage + "\"," +
                    "\"DecisionReason\":\"distribution_downloads_paused\",\"SelectedChannel\":\"paid\"," +
                    "\"ReconciliationOutcome\":\"unknown\",\"UpdateAvailable\":\"False\"," +
                    "\"Mandatory\":\"False\",\"UpToDate\":\"False\"}"
            }
        });
    }
}
