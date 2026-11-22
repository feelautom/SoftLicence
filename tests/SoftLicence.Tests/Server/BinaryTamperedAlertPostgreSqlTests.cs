using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Migrations;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003674 on PostgreSQL: per-hardware attachment of ApprovedBinaries mismatches, the 3-starts-in-24-hours alert
/// threshold, its exclusions (missing evidence, fingerprints of another approved version, same start), the single
/// alert per incident under concurrent replicas, the per-product alert budget, and the webhook subscription SQL.
/// Every test seeds its own product so the shared clone needs no cleanup between tests.
/// </summary>
public sealed class BinaryTamperedAlertPostgreSqlTests(BinaryTamperedAlertPostgreSqlFixture fixture)
    : IClassFixture<BinaryTamperedAlertPostgreSqlFixture>
{
    private const string Version = "2.4.402";
    private static readonly DateTime T0 = new(2026, 11, 4, 17, 0, 0, DateTimeKind.Utc);
    private static readonly string ApprovedExe = new('a', 64);
    private static readonly string ApprovedDll = new('b', 64);
    private static readonly string ApprovedCore = new('c', 64);
    private static readonly string PatchedExe = "d1" + new string('e', 62);

    /// <summary>
    /// Two distinct starts do not alert, the third within 24 hours alerts once with the customer, masked licence,
    /// full HWID and IP, and a fourth start the next day does not alert again. The lower-case HWID of the telemetry and
    /// of the seat both resolve to the canonical upper-case incident.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ThirdDistinctStart_AlertsOnce_WithCustomerLicenceHardwareAndIp_AndNeverRepeats()
    {
        const string hardwareId = "F32ED1455D865823";
        var (productId, licenseId) = await SeedProductAsync(seatHardwareId: hardwareId.ToLowerInvariant());
        var (service, alerts) = fixture.Service();

        await service.RecordHardwareBinaryMismatchAsync(productId, hardwareId.ToLowerInvariant(), Version, "183.196.89.35", "CN", "China Mobile", Patched(), T0);
        await service.RecordHardwareBinaryMismatchAsync(productId, hardwareId, Version, "183.196.89.35", "CN", "China Mobile", Patched(), T0.AddHours(1));
        Assert.Empty(alerts);

        var third = await service.RecordHardwareBinaryMismatchAsync(productId, $" {hardwareId} ", Version, "183.196.89.35", "CN", "China Mobile", Patched(), T0.AddHours(2));
        Assert.NotNull(third);
        Assert.True(third.AlertSent);
        Assert.Equal(3, third.StartsInWindow);
        Assert.Equal(licenseId, third.LicenseId);
        Assert.Equal(hardwareId, third.HardwareIdPrefix);

        var alert = Assert.Single(alerts);
        Assert.Equal(NotificationService.Triggers.SecurityBinaryTampered, alert.Trigger);
        Assert.Contains("Synthetic Customer <customer@example.test>", alert.Message, StringComparison.Ordinal);
        Assert.Contains("TAMP...0001", alert.Message, StringComparison.Ordinal);
        Assert.Contains($"HWID {hardwareId} (GUO003)", alert.Message, StringComparison.Ordinal);
        Assert.Contains("183.196.89.35 (CN, China Mobile)", alert.Message, StringComparison.Ordinal);
        Assert.Contains("FP_EXE d1eeeeeeeeee…", alert.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(PatchedExe, alert.Message, StringComparison.OrdinalIgnoreCase);

        var fourth = await service.RecordHardwareBinaryMismatchAsync(productId, hardwareId, Version, "183.196.89.36", null, null, Patched(), T0.AddHours(30));
        Assert.False(fourth!.AlertSent);
        Assert.Single(alerts);

        await using var db = fixture.Factory.CreateDbContext();
        var incident = await db.SecurityIncidents.Include(row => row.Evidence).Include(row => row.Observations)
            .SingleAsync(row => row.ProductId == productId);
        Assert.Equal(hardwareId, incident.HardwareId);
        Assert.Equal(SecurityIncidentService.ApprovedBinaryHardwareMismatchFamily, incident.Family);
        Assert.Equal(licenseId, incident.LicenseId);
        Assert.Equal("183.196.89.36", incident.ClientIp);
        Assert.Equal(Version, incident.Version);
        Assert.Equal(4, incident.OccurrenceCount);
        Assert.Equal(5, incident.Severity);
        Assert.Equal(T0.AddHours(2), incident.InitialNotificationSentAtUtc);
        Assert.Equal(4, incident.Observations.Count);
        var evidence = Assert.Single(incident.Evidence);
        Assert.Equal(PatchedExe.ToUpperInvariant(), evidence.ComponentHash);
        Assert.False(await db.BannedHardwareIds.AnyAsync(row => row.HardwareId.ToUpper() == hardwareId));
    }

    /// <summary>The several fingerprint-bearing events of one start, within five minutes, count as one start.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task EventsOfTheSameStart_CountOnce_AndDoNotAlert()
    {
        var (productId, _) = await SeedProductAsync();
        var (service, alerts) = fixture.Service();

        foreach (var seconds in new[] { 0, 2, 40, 200 })
            await service.RecordHardwareBinaryMismatchAsync(productId, "ABCDEF0123456789", Version, "198.51.100.7", null, null, Patched(), T0.AddSeconds(seconds));

        Assert.Empty(alerts);
        await using var db = fixture.Factory.CreateDbContext();
        var incident = await db.SecurityIncidents.Include(row => row.Observations).SingleAsync(row => row.ProductId == productId);
        Assert.Single(incident.Observations);
        Assert.Equal(4, incident.OccurrenceCount);
        Assert.Null(incident.LicenseId);
    }

    /// <summary>
    /// The window slides: starts at 0 h, 23 h and 25 h leave only two inside 24 hours at 25 h, so no alert; a start at
    /// 26 h makes three (23 h, 25 h, 26 h) and alerts.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Threshold_UsesASliding24HourWindow()
    {
        var (productId, _) = await SeedProductAsync();
        var (service, alerts) = fixture.Service();
        const string hardwareId = "0123456789ABCDEF";

        foreach (var hours in new[] { 0, 23, 25 })
            await service.RecordHardwareBinaryMismatchAsync(productId, hardwareId, Version, null, null, null, Patched(), T0.AddHours(hours));
        Assert.Empty(alerts);

        var outcome = await service.RecordHardwareBinaryMismatchAsync(productId, hardwareId, Version, null, null, null, Patched(), T0.AddHours(26));
        Assert.True(outcome!.AlertSent);
        Assert.Equal(3, outcome.StartsInWindow);
        Assert.Single(alerts);
    }

    /// <summary>
    /// A mismatched fingerprint that is an approved build of another version (interrupted update, mixed install) is
    /// kept as evidence but never counts, whatever the number of starts.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task FingerprintOfAnotherApprovedVersion_NeverCountsNorAlerts()
    {
        var otherVersionExe = new string('9', 64);
        var (productId, _) = await SeedProductAsync(otherVersionExe: otherVersionExe);
        var (service, alerts) = fixture.Service();

        foreach (var hours in Enumerable.Range(0, 5))
        {
            var outcome = await service.RecordHardwareBinaryMismatchAsync(
                productId, "1111222233334444", Version, null, null, null,
                new Dictionary<string, string> { ["FP_EXE"] = otherVersionExe }, T0.AddHours(hours));
            Assert.Equal(0, outcome!.UnapprovedComponentCount);
            Assert.False(outcome.CountedStart);
        }

        Assert.Empty(alerts);
        await using var db = fixture.Factory.CreateDbContext();
        var incident = await db.SecurityIncidents.Include(row => row.Evidence).Include(row => row.Observations)
            .SingleAsync(row => row.ProductId == productId);
        Assert.Empty(incident.Observations);
        Assert.Single(incident.Evidence);
        Assert.Equal(5, incident.OccurrenceCount);
        Assert.Null(incident.InitialNotificationSentAtUtc);
    }

    /// <summary>
    /// Two replicas recording the same machine concurrently, at distinct start times, keep exactly one incident and
    /// send exactly one alert.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ConcurrentReplicas_KeepOneIncident_AndSendOneAlert()
    {
        var (productId, _) = await SeedProductAsync();
        var (first, alerts) = fixture.Service();
        var second = fixture.Service(alerts);

        await Task.WhenAll(Enumerable.Range(0, 12).Select(index => Task.Run(() =>
            (index % 2 == 0 ? first : second.Service).RecordHardwareBinaryMismatchAsync(
                productId, "CAFEBABE00000001", Version, null, null, null, Patched(), T0.AddMinutes(10 * index)))));

        Assert.Single(alerts);
        await using var db = fixture.Factory.CreateDbContext();
        var incident = await db.SecurityIncidents.Include(row => row.Observations).SingleAsync(row => row.ProductId == productId);
        Assert.Equal(12, incident.OccurrenceCount);
        Assert.Equal(12, incident.Observations.Count);
        Assert.NotNull(incident.InitialNotificationSentAtUtc);
    }

    /// <summary>Invented hardware identifiers cannot send more than the per-product daily alert budget.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task AlertBudget_CapsAlertsPerProductAndWindow()
    {
        var (productId, _) = await SeedProductAsync();
        var (service, alerts) = fixture.Service();

        foreach (var machine in Enumerable.Range(1, SecurityIncidentService.MaxTamperedAlertsPerProductPerWindow + 2))
        {
            foreach (var hours in new[] { 0, 1, 2 })
                await service.RecordHardwareBinaryMismatchAsync(
                    productId, $"FAKEHWID{machine:D8}", Version, null, null, null, Patched(), T0.AddHours(hours).AddMinutes(machine));
        }

        Assert.Equal(SecurityIncidentService.MaxTamperedAlertsPerProductPerWindow, alerts.Count);
        await using var db = fixture.Factory.CreateDbContext();
        Assert.Equal(SecurityIncidentService.MaxTamperedAlertsPerProductPerWindow + 2,
            await db.SecurityIncidents.CountAsync(row => row.ProductId == productId));
    }

    /// <summary>
    /// End to end through public telemetry: events without fingerprints (<c>required_key_missing</c>) on a usable HWID
    /// never create a per-hardware incident nor an alert, and a real mismatch is attached to the machine.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Telemetry_RequiredKeyMissingIsExcluded_AndMismatchIsAttachedToTheMachine()
    {
        var productName = $"TIAConnect-{Guid.NewGuid():N}";
        var (productId, licenseId) = await SeedProductAsync(productName: productName, seatHardwareId: "5555666677778888");
        var (telemetry, alerts) = fixture.TelemetryService();

        foreach (var eventName in new[] { "Startup_Diag_Result_AllGood", "Startup_AppStarted", "Startup_PrereqSnapshot", "Startup_AppStarted", "Startup_AppStarted" })
        {
            await telemetry.SaveEventAsync(new TelemetryEventRequest
            {
                AppName = productName, HardwareId = "5555666677778888", Version = Version, EventName = eventName,
                Properties = new Dictionary<string, string>()
            }, "203.0.113.9");
        }

        await using (var db = fixture.Factory.CreateDbContext())
        {
            Assert.False(await db.SecurityIncidents.AnyAsync(row => row.ProductId == productId
                && row.Family == SecurityIncidentService.ApprovedBinaryHardwareMismatchFamily));
            Assert.True(await db.SecurityIncidents.AnyAsync(row => row.ProductId == productId
                && row.Family == SecurityIncidentService.ApprovedBinaryEvidenceMissingFamily));
        }

        await telemetry.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = productName, HardwareId = "5555666677778888", Version = Version, EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = PatchedExe, ["FP_DLL"] = ApprovedDll, ["FP_CORE"] = ApprovedCore
            }
        }, "203.0.113.9");

        Assert.Empty(alerts);
        await using var verify = fixture.Factory.CreateDbContext();
        var incident = await verify.SecurityIncidents.SingleAsync(row => row.ProductId == productId
            && row.Family == SecurityIncidentService.ApprovedBinaryHardwareMismatchFamily);
        Assert.Equal("5555666677778888", incident.HardwareId);
        Assert.Equal(licenseId, incident.LicenseId);
        Assert.Equal("203.0.113.9", incident.ClientIp);
        Assert.False(await verify.SecurityIncidents.AnyAsync(row => row.ProductId == productId
            && row.HardwareId == SecurityIncidentService.PublicTelemetryAggregateIdentity
            && row.Family == SecurityIncidentService.ApprovedBinaryMismatchFamily));
    }

    /// <summary>
    /// The migration subscribes exactly the webhooks receiving serious bans, once, with exact trimmed matching, and
    /// the rollback removes only the new trigger.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task WebhookSubscription_IsExactIdempotentAndReversible()
    {
        var rows = new Dictionary<string, (string Before, string AfterUp, string AfterDown)>
        {
            ["ntfy"] = ("Security.IpBanned,Security.ZombieDetected,Security.ThreatScoreRaised",
                "Security.IpBanned,Security.ZombieDetected,Security.ThreatScoreRaised,Security.BinaryTampered",
                "Security.IpBanned,Security.ZombieDetected,Security.ThreatScoreRaised"),
            ["spaced"] = ("License.Created, Security.IpBanned",
                "License.Created, Security.IpBanned,Security.BinaryTampered",
                "License.Created, Security.IpBanned"),
            ["already"] = ("Security.IpBanned, Security.BinaryTampered",
                "Security.IpBanned, Security.BinaryTampered",
                "Security.IpBanned"),
            ["lookalike"] = ("Security.IpBannedV2,security.ipbanned", "Security.IpBannedV2,security.ipbanned",
                "Security.IpBannedV2,security.ipbanned"),
            ["evidence"] = ("Security.EvidenceObserved", "Security.EvidenceObserved", "Security.EvidenceObserved")
        };
        await using (var db = fixture.Factory.CreateDbContext())
        {
            await db.Webhooks.ExecuteDeleteAsync();
            foreach (var (name, values) in rows)
                db.Webhooks.Add(new Webhook { Name = name, Url = "https://ntfy.example.test/topic", EnabledEvents = values.Before, IsEnabled = true });
            await db.SaveChangesAsync();
        }

        await ExecuteAsync(AddTkt003674HardwareBinaryIncidents.SubscribeBinaryTamperedAlertSql);
        await ExecuteAsync(AddTkt003674HardwareBinaryIncidents.SubscribeBinaryTamperedAlertSql);
        await AssertEventsAsync(rows.ToDictionary(row => row.Key, row => row.Value.AfterUp));

        await ExecuteAsync(AddTkt003674HardwareBinaryIncidents.UnsubscribeBinaryTamperedAlertSql);
        await AssertEventsAsync(rows.ToDictionary(row => row.Key, row => row.Value.AfterDown));
    }

    /// <summary>Mismatched evidence of the patched EXE only, as the baseline lookup reports it (lowercase).</summary>
    private static Dictionary<string, string> Patched() => new(StringComparer.Ordinal) { ["FP_EXE"] = PatchedExe };

    /// <summary>
    /// Seeds one product with an authoritative release baseline for <see cref="Version"/>, optionally another approved
    /// version whose EXE fingerprint is <paramref name="otherVersionExe"/>, and optionally a licence with a seat on
    /// <paramref name="seatHardwareId"/> stored as given.
    /// </summary>
    private async Task<(Guid ProductId, Guid? LicenseId)> SeedProductAsync(
        string? productName = null, string? seatHardwareId = null, string? otherVersionExe = null)
    {
        var productId = Guid.NewGuid();
        await using var db = fixture.Factory.CreateDbContext();
        db.Products.Add(new Product
        {
            Id = productId, Name = productName ?? $"Tamper-{productId:N}", PrivateKeyXml = "key",
            PublicKeyXml = "key", ApiSecret = $"secret-{productId:N}"
        });
        AddBaseline(db, productId, Version, ApprovedExe);
        if (otherVersionExe != null)
            AddBaseline(db, productId, "2.4.300", otherVersionExe);

        Guid? licenseId = null;
        if (seatHardwareId != null)
        {
            var type = new LicenseType { Id = Guid.NewGuid(), Name = "Pro", Slug = $"PRO{productId:N}"[..12], DefaultMaxSeats = 1, ProductId = productId };
            var license = new License
            {
                LicenseKey = $"TAMP-{productId:N}-0001", IsActive = true, ProductId = productId, Type = type,
                LicenseTypeId = type.Id, CustomerName = "Synthetic Customer", CustomerEmail = "customer@example.test"
            };
            db.Licenses.Add(license);
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = seatHardwareId, MachineName = "GUO003" });
            licenseId = license.Id;
        }

        await db.SaveChangesAsync();
        return (productId, licenseId);
    }

    /// <summary>Adds one authoritative release registration and its three approved fingerprints.</summary>
    private static void AddBaseline(LicenseDbContext db, Guid productId, string version, string exe)
    {
        var artifacts = new[]
        {
            new ApprovedBinaryArtifact("FP_EXE", exe),
            new ApprovedBinaryArtifact("FP_DLL", ApprovedDll),
            new ApprovedBinaryArtifact("FP_CORE", ApprovedCore)
        };
        var registration = new ApprovedBinaryRegistration
        {
            ProductId = productId, Version = version,
            RegistrationKey = $"tamper-test/{version}/{Guid.NewGuid():N}",
            ManifestDigestSha256 = new string('d', 64),
            BaselineDigestSha256 = ApprovedBinaryService.ComputeBaselineDigestSha256(artifacts),
            Source = ApprovedBinaryService.ReleaseSource
        };
        db.ApprovedBinaryRegistrations.Add(registration);
        db.ApprovedBinaries.AddRange(artifacts.Select(artifact => new ApprovedBinary
        {
            ProductId = productId, ApprovedBinaryRegistrationId = registration.Id, Version = version,
            Key = artifact.Key, Hash = artifact.Sha256, Source = ApprovedBinaryService.ReleaseSource
        }));
    }

    /// <summary>Runs raw SQL on the clone.</summary>
    private async Task ExecuteAsync(string sql)
    {
        await using var db = fixture.Factory.CreateDbContext();
        await db.Database.ExecuteSqlRawAsync(sql);
    }

    /// <summary>Asserts the exact subscription list of each named webhook.</summary>
    private async Task AssertEventsAsync(IReadOnlyDictionary<string, string> expected)
    {
        await using var db = fixture.Factory.CreateDbContext();
        var actual = await db.Webhooks.AsNoTracking().ToDictionaryAsync(hook => hook.Name, hook => hook.EnabledEvents);
        foreach (var (name, events) in expected)
            Assert.Equal(events, actual[name]);
    }
}

/// <summary>A notification captured from the mocked notification service.</summary>
public sealed record CapturedAlert(string Trigger, string Title, string Message);

/// <summary>Isolated PostgreSQL clone for the TKT-003674 tests; dropped even when a test fails.</summary>
public sealed class BinaryTamperedAlertPostgreSqlFixture : IAsyncLifetime
{
    private string _maintenanceConnectionString = string.Empty;
    private string _database = string.Empty;

    /// <summary>Factory bound only to the isolated database.</summary>
    public PortalDeactivationPostgreSqlFixture.TestDbContextFactory Factory { get; private set; } = null!;

    /// <summary>Clones the current-schema model.</summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("binarytamper");
        _database = clone.DatabaseName;
        _maintenanceConnectionString = clone.MaintenanceConnectionString;
        Factory = new PortalDeactivationPostgreSqlFixture.TestDbContextFactory(clone.ConnectionString);
    }

    /// <summary>Drops the clone.</summary>
    public async Task DisposeAsync()
    {
        if (string.IsNullOrEmpty(_database) || string.IsNullOrEmpty(_maintenanceConnectionString))
            return;
        await PostgreSqlModelDatabase.DropAsync(_maintenanceConnectionString, _database);
    }

    /// <summary>
    /// Creates one incident service, as one request scope does in production, whose notifications are captured into
    /// <paramref name="sink"/> (a new thread-safe sink when omitted). Only modified-binary alerts are captured.
    /// </summary>
    public (SecurityIncidentService Service, ConcurrentQueue<CapturedAlert> Alerts) Service(ConcurrentQueue<CapturedAlert>? sink = null)
    {
        var alerts = sink ?? new ConcurrentQueue<CapturedAlert>();
        return (new SecurityIncidentService(
            Factory, Notifier(alerts).Object, Mock.Of<ILogger<SecurityIncidentService>>(),
            new ConfigurationBuilder().Build()), alerts);
    }

    /// <summary>
    /// Builds the real telemetry pipeline on the clone (GeoIP mocked) with a capturing notifier, to prove which
    /// verdicts reach the per-hardware incident.
    /// </summary>
    public (TelemetryService Service, ConcurrentQueue<CapturedAlert> Alerts) TelemetryService()
    {
        var alerts = new ConcurrentQueue<CapturedAlert>();
        var configuration = new ConfigurationBuilder().Build();
        var notifier = Notifier(alerts).Object;
        var settings = new SettingsService(Factory, configuration, Mock.Of<ILogger<SettingsService>>());
        var environment = new Mock<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
        environment.Setup(e => e.ContentRootPath).Returns(Directory.GetCurrentDirectory());
        var geoIp = new Mock<GeoIpService>(environment.Object,
            Mock.Of<Microsoft.Extensions.Caching.Memory.IMemoryCache>(), Mock.Of<ILogger<GeoIpService>>());
        geoIp.Setup(g => g.GetGeoInfoAsync(It.IsAny<string>()))
            .ReturnsAsync(new GeoInfo { Isp = "Test ISP", CountryCode = "FR" });
        var http = new Mock<IHttpClientFactory>();
        http.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(new HttpClient());
        var service = new SoftLicence.Server.Services.TelemetryService(
            Factory, Mock.Of<ILogger<SoftLicence.Server.Services.TelemetryService>>(), geoIp.Object, http.Object,
            new FingerprintService(Factory, Mock.Of<ILogger<FingerprintService>>(), settings),
            new SecurityService(Factory, Mock.Of<ILogger<SecurityService>>(), notifier, configuration),
            settings,
            securityIncidents: new SecurityIncidentService(
                Factory, notifier, Mock.Of<ILogger<SecurityIncidentService>>(), configuration));
        return (service, alerts);
    }

    /// <summary>Mocked notification service that records modified-binary alerts and ignores everything else.</summary>
    private Mock<NotificationService> Notifier(ConcurrentQueue<CapturedAlert> alerts)
    {
        var notifier = new Mock<NotificationService>(
            Factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        notifier.Setup(n => n.Notify(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
            .Callback<string, string, string, object?>((trigger, title, message, _) =>
            {
                if (trigger == NotificationService.Triggers.SecurityBinaryTampered)
                    alerts.Enqueue(new CapturedAlert(trigger, title, message));
            });
        return notifier;
    }
}
