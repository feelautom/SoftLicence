using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public class TelemetryServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<ILogger<TelemetryService>> _loggerMock;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly Mock<GeoIpService> _geoIpMock;
    private readonly Mock<IHttpClientFactory> _httpFactoryMock;

    public TelemetryServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _loggerMock = new Mock<ILogger<TelemetryService>>();

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));

        var envMock = new Mock<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
        envMock.Setup(e => e.ContentRootPath).Returns(Directory.GetCurrentDirectory());
        var cacheMock = new Mock<Microsoft.Extensions.Caching.Memory.IMemoryCache>();
        var geoLoggerMock = new Mock<ILogger<GeoIpService>>();

        _geoIpMock = new Mock<GeoIpService>(envMock.Object, cacheMock.Object, geoLoggerMock.Object);
        _geoIpMock.Setup(g => g.GetGeoInfoAsync(It.IsAny<string>()))
            .ReturnsAsync(new GeoInfo { Isp = "Test ISP", CountryCode = "FR" });

        _httpFactoryMock = new Mock<IHttpClientFactory>();
        _httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(new HttpClient());
    }

    private async Task SeedProductAsync(LicenseDbContext db, string name)
    {
        db.Products.Add(new Product {
            Id = Guid.NewGuid(),
            Name = name,
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret-" + name
        });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task SaveDiagnosticAsync_ShouldPersistComplexLists()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "YOUR_APP_NAME");
        }
        var service = new TelemetryService(_dbFactoryMock.Object, _loggerMock.Object, _geoIpMock.Object, _httpFactoryMock.Object);

        var request = new TelemetryDiagnosticRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-DIAG",
            EventName = "NETWORK_TEST",
            Score = 85,
            Results = new List<DiagnosticResult>
            {
                new() { ModuleName = "Ping", Success = true, Severity = "Info" },
                new() { ModuleName = "DNS", Success = false, Severity = "Error", Message = "Timeout" }
            },
            Ports = new List<DiagnosticPort>
            {
                new() { Name = "HTTP", ExternalPort = 80, Protocol = "TCP" }
            }
        };

        // Act
        await service.SaveDiagnosticAsync(request);

        // Assert
        using var checkDb = new LicenseDbContext(_dbOptions);
        var record = await checkDb.TelemetryRecords
            .Include(t => t.DiagnosticData).ThenInclude(d => d!.Results)
            .Include(t => t.DiagnosticData).ThenInclude(d => d!.Ports)
            .FirstAsync(t => t.HardwareId == "HW-DIAG");

        Assert.Equal(TelemetryType.Diagnostic, record.Type);
        Assert.NotNull(record.DiagnosticData);
        Assert.Equal(85, record.DiagnosticData.Score);
        Assert.Equal(2, record.DiagnosticData.Results.Count);
        Assert.Single(record.DiagnosticData.Ports);
        Assert.Equal("DNS", record.DiagnosticData.Results.Last().ModuleName);
    }

    [Fact]
    public async Task SaveErrorAsync_ShouldPersistErrorDetails()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "YOUR_APP_NAME");
        }
        var service = new TelemetryService(_dbFactoryMock.Object, _loggerMock.Object, _geoIpMock.Object, _httpFactoryMock.Object);

        var request = new TelemetryErrorRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-ERR",
            EventName = "CRASH",
            ErrorType = "NullReferenceException",
            Message = "Object reference not set",
            StackTrace = "at SomeModule.Method()"
        };

        // Act
        await service.SaveErrorAsync(request);

        // Assert
        using var checkDb = new LicenseDbContext(_dbOptions);
        var record = await checkDb.TelemetryRecords
            .Include(t => t.ErrorData)
            .FirstAsync(t => t.HardwareId == "HW-ERR");

        Assert.Equal(TelemetryType.Error, record.Type);
        Assert.NotNull(record.ErrorData);
        Assert.Equal("NullReferenceException", record.ErrorData.ErrorType);
        Assert.Equal("at SomeModule.Method()", record.ErrorData.StackTrace);
    }

    [Fact]
    public async Task GetTelemetryForProductAsync_ShouldRespectIsolation()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "AppA");
            await SeedProductAsync(db, "AppB");
        }
        var service = new TelemetryService(_dbFactoryMock.Object, _loggerMock.Object, _geoIpMock.Object, _httpFactoryMock.Object);

        // App A data
        await service.SaveEventAsync(new TelemetryEventRequest { AppName = "AppA", HardwareId = "HW-A", EventName = "START" });
        // App B data
        await service.SaveEventAsync(new TelemetryEventRequest { AppName = "AppB", HardwareId = "HW-B", EventName = "START" });

        // Act
        var resultsA = await service.GetTelemetryForProductAsync("secret-AppA");
        var resultsB = await service.GetTelemetryForProductAsync("secret-AppB");

        // Assert
        Assert.Single(resultsA);
        Assert.Equal("AppA", resultsA[0].AppName);
        Assert.Single(resultsB);
        Assert.Equal("AppB", resultsB[0].AppName);
    }
}
