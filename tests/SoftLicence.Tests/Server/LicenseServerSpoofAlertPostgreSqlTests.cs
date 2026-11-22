using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003668 on PostgreSQL: the spoofed-licence-server alert (successful activation through a local host) is
/// recorded per machine and window, alerts at most once per machine and window even under concurrent replicas, and
/// stays within the per-product budget when an unauthenticated sender invents hardware identifiers. Each test seeds
/// its own product so the shared clone needs no cleanup between tests.
/// </summary>
public sealed class LicenseServerSpoofAlertPostgreSqlTests(LicenseServerSpoofAlertPostgreSqlFixture fixture)
    : IClassFixture<LicenseServerSpoofAlertPostgreSqlFixture>
{
    private static readonly DateTime T0 = new(2026, 11, 4, 17, 22, 0, DateTimeKind.Utc);

    /// <summary>
    /// Case F32ED145 (TKT-003671): eight replicas receiving the same spoofed activation at once keep one incident and
    /// send one alert; a repeat in the same window only counts, and the next window alerts again.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SameMachine_ConcurrentReplicas_AlertOncePerWindow()
    {
        var productId = await SeedProductAsync();
        var alerts = new ConcurrentQueue<string>();

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            fixture.Service(alerts).ProcessAsync(productId, Activation("f32ed1455d865823"), "183.196.89.35", null)));

        Assert.Single(alerts);
        Assert.Contains("F32E…5823", alerts.Single(), StringComparison.Ordinal);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var incident = await db.SecurityIncidents.SingleAsync(row => row.ProductId == productId);
            Assert.Equal(ActivationIncidentService.LicenseServerSpoofFamily, incident.Family);
            Assert.Equal("F32ED1455D865823", incident.HardwareId);
            Assert.Equal(8, incident.OccurrenceCount);
            Assert.Equal(5, incident.Severity);
            Assert.NotNull(incident.InitialNotificationSentAtUtc);
        }

        var service = fixture.Service(alerts);
        Assert.True(await service.RecordLicenseServerSpoofAsync(productId, "AAAA000011112222", "2.4.402", null, T0, default));
        Assert.False(await service.RecordLicenseServerSpoofAsync(productId, "AAAA000011112222", "2.4.402", null, T0.AddHours(3), default));
        Assert.True(await service.RecordLicenseServerSpoofAsync(productId, "AAAA000011112222", "2.4.402", null, T0.AddHours(31), default));
    }

    /// <summary>
    /// A burst of 15 activations with 15 different hardware identifiers records 15 incidents but sends only the
    /// product budget of 10 alerts; the budget frees up once the earlier alerts leave the 24-hour window.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task DistinctHardwareBurst_IsCappedByTheProductBudget()
    {
        var productId = await SeedProductAsync();
        var alerts = new ConcurrentQueue<string>();
        var service = fixture.Service(alerts);

        var results = new List<bool>();
        for (var index = 0; index < 15; index++)
            results.Add(await service.RecordLicenseServerSpoofAsync(
                productId, $"BURST{index:D11}", "2.4.402", "203.0.113.9", T0.AddMinutes(index), default));

        Assert.Equal(ActivationIncidentService.MaxLicenseServerSpoofAlertsPerProductPerWindow, results.Count(alert => alert));
        Assert.All(results.Skip(ActivationIncidentService.MaxLicenseServerSpoofAlertsPerProductPerWindow), Assert.False);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var rows = await db.SecurityIncidents.Where(row => row.ProductId == productId).ToListAsync();
            Assert.Equal(15, rows.Count);
            Assert.Equal(5, rows.Count(row => row.InitialNotificationSentAtUtc == null));
        }

        Assert.True(await service.RecordLicenseServerSpoofAsync(
            productId, "BURSTLATE0001", "2.4.402", null, T0.AddHours(25), default));
        Assert.Empty(alerts);
    }

    /// <summary>A genuine activation host and an unusable hardware identifier record nothing and alert nothing.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task GenuineHostOrUnusableHardware_RecordsNothing()
    {
        var productId = await SeedProductAsync();
        var alerts = new ConcurrentQueue<string>();
        var service = fixture.Service(alerts);

        await service.ProcessAsync(productId, Activation("F32ED1455D865823", "softlicence.EXAMPLE.COM"), "203.0.113.9", null);
        await service.ProcessAsync(productId, Activation("bad id!"), "203.0.113.9", null);
        await service.ProcessAsync(null, Activation("F32ED1455D865823"), "203.0.113.9", null);

        Assert.Empty(alerts);
        await using var db = fixture.Factory.CreateDbContext();
        Assert.False(await db.SecurityIncidents.AnyAsync(row => row.ProductId == productId));
    }

    /// <summary>Builds a successful activation event reporting <paramref name="host"/>.</summary>
    private static TelemetryEventRequest Activation(string hardwareId, string host = "127.0.0.1") => new()
    {
        HardwareId = hardwareId,
        AppName = "TIAConnect",
        Version = "2.4.402",
        EventName = "LicenseActivation_Success",
        Properties = new Dictionary<string, string> { ["FailureHost"] = host }
    };

    /// <summary>Seeds one product, required by the incident foreign key.</summary>
    private async Task<Guid> SeedProductAsync()
    {
        var productId = Guid.NewGuid();
        await using var db = fixture.Factory.CreateDbContext();
        db.Products.Add(new Product
        {
            Id = productId, Name = $"Spoof-{productId:N}", PrivateKeyXml = "key", PublicKeyXml = "key",
            ApiSecret = $"secret-{productId:N}"
        });
        await db.SaveChangesAsync();
        return productId;
    }
}

/// <summary>Isolated PostgreSQL clone for the TKT-003668 spoofed-licence-server tests.</summary>
public sealed class LicenseServerSpoofAlertPostgreSqlFixture : IAsyncLifetime
{
    private string _maintenanceConnectionString = string.Empty;
    private string _database = string.Empty;

    /// <summary>Factory bound only to the isolated database.</summary>
    public PortalDeactivationPostgreSqlFixture.TestDbContextFactory Factory { get; private set; } = null!;

    /// <summary>Clones the current-schema model.</summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("spoofserver");
        _database = clone.DatabaseName;
        _maintenanceConnectionString = clone.MaintenanceConnectionString;
        Factory = new PortalDeactivationPostgreSqlFixture.TestDbContextFactory(clone.ConnectionString);
    }

    /// <summary>Drops the clone even when a test fails.</summary>
    public async Task DisposeAsync()
    {
        if (string.IsNullOrEmpty(_database) || string.IsNullOrEmpty(_maintenanceConnectionString))
            return;
        await PostgreSqlModelDatabase.DropAsync(_maintenanceConnectionString, _database);
    }

    /// <summary>
    /// Creates one activation incident service, as one request scope does in production, whose spoofed-server alert
    /// messages are captured into <paramref name="alerts"/>; other notifications are ignored.
    /// </summary>
    /// <param name="alerts">Thread-safe sink shared by concurrent replicas.</param>
    public ActivationIncidentService Service(ConcurrentQueue<string> alerts)
    {
        var notifier = new Mock<NotificationService>(
            Factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        notifier.Setup(n => n.Notify(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
            .Callback<string, string, string, object?>((trigger, _, message, _) =>
            {
                if (trigger == NotificationService.Triggers.SecurityLicenseServerSpoofed)
                    alerts.Enqueue(message);
            });
        return new ActivationIncidentService(Factory, notifier.Object, Mock.Of<ILogger<ActivationIncidentService>>());
    }
}
