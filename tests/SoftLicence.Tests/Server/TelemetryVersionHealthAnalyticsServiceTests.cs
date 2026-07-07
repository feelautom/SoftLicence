using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryVersionHealthAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryVersionHealthAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetVersionHealthForProductKeyAsync_AggregatesErrorsByVersion()
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

            AddEvent(db, productId, "HW-A", "2.1.857", "Startup_AppStarted", DateTime.UtcNow.AddHours(-5));
            AddEvent(db, productId, "HW-B", "2.1.857", "Mcp_ToolCall", DateTime.UtcNow.AddHours(-4));
            AddDiagnostic(db, productId, "HW-A", "2.1.900", DateTime.UtcNow.AddHours(-3));
            AddError(db, productId, "HW-A", "2.1.900", "UnhandledException", "FatalUnhandled", DateTime.UtcNow.AddHours(-2));
            AddError(db, productId, "HW-B", "2.1.900", "CertPinningFailed", "CertificatePinning", DateTime.UtcNow.AddHours(-1));

            await db.SaveChangesAsync();
        }

        var service = new TelemetryVersionHealthAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetVersionHealthForProductKeyAsync("secret", days: 7, top: 10);

        Assert.NotNull(summary);
        Assert.False(summary.Cached);
        Assert.Equal(5, summary.RecordsAnalyzed);
        Assert.Equal(2, summary.ErrorRecords);
        Assert.Equal(2, summary.UniqueDevices);
        Assert.Contains(summary.TopErrorTypes, e => e.Name == "FatalUnhandled" && e.Count == 1);
        Assert.Contains(summary.TopErrorEvents, e => e.Name == "CertPinningFailed" && e.Count == 1);
        Assert.Single(summary.DailyErrors);

        var regressionVersion = Assert.Single(summary.Versions, v => v.Version == "2.1.900");
        Assert.Equal(3, regressionVersion.Records);
        Assert.Equal(1, regressionVersion.Diagnostics);
        Assert.Equal(2, regressionVersion.Errors);
        Assert.Equal(0.6667, regressionVersion.ErrorRate);
        Assert.Contains(regressionVersion.ErrorTypes, e => e.Name == "CertificatePinning" && e.Count == 1);
        Assert.Contains(regressionVersion.ErrorEvents, e => e.Name == "UnhandledException" && e.Count == 1);

        var stableVersion = Assert.Single(summary.Versions, v => v.Version == "2.1.857");
        Assert.Equal(2, stableVersion.Events);
        Assert.Equal(0, stableVersion.Errors);
        Assert.Equal(0, stableVersion.ErrorRate);
    }

    [Fact]
    public async Task GetVersionHealthForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddError(db, productA, "HW-A", "1.0", "UnhandledException", "FatalUnhandled", DateTime.UtcNow);
            AddError(db, productB, "HW-B", "2.0", "OtherError", "OtherType", DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var service = new TelemetryVersionHealthAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetVersionHealthForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Equal(1, summary.RecordsAnalyzed);
        Assert.Single(summary.Versions);
        Assert.Equal("1.0", summary.Versions[0].Version);
        Assert.Contains(summary.TopErrorTypes, e => e.Name == "FatalUnhandled" && e.Count == 1);
    }

    [Fact]
    public async Task GetVersionHealthForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryVersionHealthAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetVersionHealthForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string version,
        string eventName,
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
            EventData = new TelemetryEvent { PropertiesJson = """{"Safe":"Value"}""" }
        });
    }

    private static void AddDiagnostic(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string version,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = "Diagnostic_Run",
            Type = TelemetryType.Diagnostic,
            DiagnosticData = new TelemetryDiagnostic { Score = 72 }
        });
    }

    private static void AddError(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string version,
        string eventName,
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
            ErrorData = new TelemetryError
            {
                ErrorType = errorType,
                Message = "hidden",
                StackTrace = "hidden"
            }
        });
    }
}
