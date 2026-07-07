using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryMachineProfileAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryMachineProfileAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetMachineProfileForProductKeyAsync_AggregatesMachineTelemetry()
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

            AddEvent(db, productId, "HW-A", "Startup_AppStarted", "2.1.857",
                """{"OverallStatus":"Pass","LicenseKey":"SECRET","Token":"abc","SelectedVersion":"V19"}""",
                DateTime.UtcNow.AddHours(-3));
            AddEvent(db, productId, "HW-A", "Mcp_ToolCall", "2.1.857",
                """{"Tool":"list_blocks","RequestSource":"MCP_Agent"}""",
                DateTime.UtcNow.AddHours(-2));
            AddDiagnostic(db, productId, "HW-A", "Diagnostic_Run", "2.1.900", 87, DateTime.UtcNow.AddHours(-1));
            AddError(db, productId, "HW-A", "UnhandledException", "2.1.900", "FatalUnhandled", DateTime.UtcNow);
            AddEvent(db, productId, "HW-B", "Startup_AppStarted", "2.1.857", """{"OverallStatus":"Fail"}""", DateTime.UtcNow);

            await db.SaveChangesAsync();
        }

        var service = new TelemetryMachineProfileAnalyticsService(_dbFactoryMock.Object, _cache);

        var profile = await service.GetMachineProfileForProductKeyAsync("secret", "HW-A", days: 7, top: 10, take: 10);

        Assert.NotNull(profile);
        Assert.False(profile.Cached);
        Assert.Equal("HW-A", profile.HardwareId);
        Assert.Equal(4, profile.RecordsAnalyzed);
        Assert.NotNull(profile.FirstActivityUtc);
        Assert.NotNull(profile.LastActivityUtc);
        Assert.Contains(profile.TypeCounts, c => c.Name == "Event" && c.Count == 2);
        Assert.Contains(profile.TypeCounts, c => c.Name == "Diagnostic" && c.Count == 1);
        Assert.Contains(profile.TypeCounts, c => c.Name == "Error" && c.Count == 1);
        Assert.Contains(profile.EventFamilies, c => c.Name == "startup" && c.Count == 1);
        Assert.Contains(profile.EventFamilies, c => c.Name == "mcp" && c.Count == 1);
        Assert.Contains(profile.TopEvents, c => c.Name == "Startup_AppStarted" && c.Count == 1);
        Assert.Contains(profile.Versions, c => c.Name == "2.1.900" && c.Count == 2);
        Assert.Equal(4, profile.RecentRecords.Count);

        var startup = Assert.Single(profile.RecentRecords, r => r.EventName == "Startup_AppStarted");
        Assert.Contains("OverallStatus", startup.PropertyKeys);
        Assert.Contains("SelectedVersion", startup.PropertyKeys);
        Assert.DoesNotContain("LicenseKey", startup.PropertyKeys);
        Assert.DoesNotContain("Token", startup.PropertyKeys);

        var diagnostic = Assert.Single(profile.RecentRecords, r => r.Type == "Diagnostic");
        Assert.Equal(87, diagnostic.DiagnosticScore);

        var error = Assert.Single(profile.RecentRecords, r => r.Type == "Error");
        Assert.Equal("FatalUnhandled", error.ErrorType);
    }

    [Fact]
    public async Task GetMachineProfileForProductKeyAsync_SeparatesRealActivityFromSystemNoise()
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

            AddEvent(db, productId, "HW-A", "Update_Check", "2.1.857", """{"UpToDate":true}""", DateTime.UtcNow.AddMinutes(-10));
            AddEvent(db, productId, "HW-A", "Update_Available", "2.1.857", """{"CurrentVersion":"2.1.857"}""", DateTime.UtcNow.AddMinutes(-9));
            AddEvent(db, productId, "HW-A", "Startup_AppStarted", "2.1.857", """{"OverallStatus":"Pass"}""", DateTime.UtcNow.AddMinutes(-8));
            AddEvent(db, productId, "HW-A", "UI_Navigate", "2.1.857", """{"View":"Home"}""", DateTime.UtcNow.AddMinutes(-7));
            AddEvent(db, productId, "HW-A", "Wizard_McpToolSelected", "2.1.857", """{"Tool":"list_blocks"}""", DateTime.UtcNow.AddMinutes(-6));
            AddEvent(db, productId, "HW-A", "Mcp_ToolCall", "2.1.857", """{"Tool":"list_blocks"}""", DateTime.UtcNow.AddMinutes(-5));
            AddEvent(db, productId, "HW-A", "Tag_Create", "2.1.857", """{"Tag":"DB1"}""", DateTime.UtcNow.AddMinutes(-4));

            await db.SaveChangesAsync();
        }

        var service = new TelemetryMachineProfileAnalyticsService(_dbFactoryMock.Object, _cache);

        var profile = await service.GetMachineProfileForProductKeyAsync("secret", "HW-A", days: 7, top: 10, take: 10);

        Assert.NotNull(profile);
        Assert.Equal(7, profile.RecordsAnalyzed);
        Assert.Equal(2, profile.RealActivityEvents);
        Assert.Equal(3, profile.SystemNoiseEvents);
        Assert.Contains(profile.EventFamilies, c => c.Name == "update" && c.Count == 2);
        Assert.Contains(profile.EventFamilies, c => c.Name == "startup" && c.Count == 1);
    }

    [Fact]
    public async Task GetMachineProfileForProductKeyAsync_RespectsProductAndHardwareIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddEvent(db, productA, "HW-A", "Startup_AppStarted", "1.0", """{"OverallStatus":"Pass"}""", DateTime.UtcNow);
            AddEvent(db, productA, "HW-B", "Startup_AppStarted", "1.0", """{"OverallStatus":"Fail"}""", DateTime.UtcNow);
            AddEvent(db, productB, "HW-A", "Mcp_ToolCall", "2.0", """{"Tool":"other"}""", DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var service = new TelemetryMachineProfileAnalyticsService(_dbFactoryMock.Object, _cache);

        var profile = await service.GetMachineProfileForProductKeyAsync("secret-a", "HW-A");

        Assert.NotNull(profile);
        Assert.Equal(1, profile.RecordsAnalyzed);
        Assert.Single(profile.RecentRecords);
        Assert.Equal("Startup_AppStarted", profile.RecentRecords[0].EventName);
    }

    [Fact]
    public async Task GetMachineProfileForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryMachineProfileAnalyticsService(_dbFactoryMock.Object, _cache);

        var profile = await service.GetMachineProfileForProductKeyAsync("missing", "HW-A");

        Assert.Null(profile);
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        string propertiesJson,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent { PropertiesJson = propertiesJson }
        });
    }

    private static void AddDiagnostic(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        int score,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Diagnostic,
            DiagnosticData = new TelemetryDiagnostic { Score = score }
        });
    }

    private static void AddError(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        string errorType,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Error,
            ErrorData = new TelemetryError { ErrorType = errorType, Message = "hidden", StackTrace = "hidden" }
        });
    }
}
