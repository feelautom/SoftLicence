using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using System.Net;
using System.Text.Json;
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
        var service = new TelemetryService(_dbFactoryMock.Object, _loggerMock.Object, _geoIpMock.Object, _httpFactoryMock.Object, null!, null!, null!);

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
        var service = new TelemetryService(_dbFactoryMock.Object, _loggerMock.Object, _geoIpMock.Object, _httpFactoryMock.Object, null!, null!, null!);

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
    public async Task SaveEventAsync_WhenSameEventFloods_ShouldSuppressAfterThreshold()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "YOUR_APP_NAME");
        }

        var service = BuildTelemetryServiceWithFloodSettings(threshold: 3, windowMinutes: 10);
        var request = new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-FLOOD",
            Version = "1.1.34",
            EventName = "NativeExtractionFailed",
            Properties = new Dictionary<string, string>
            {
                ["reason"] = "native dll missing"
            }
        };

        for (var i = 0; i < 5; i++)
        {
            await service.SaveEventAsync(request, "185.162.248.75");
        }

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Equal(3, await checkDb.TelemetryRecords.CountAsync(t =>
            t.HardwareId == "HW-FLOOD" && t.EventName == "NativeExtractionFailed"));

        var counter = await checkDb.TelemetryFloodSuppressionCounters.SingleAsync(c =>
            c.HardwareId == "HW-FLOOD" && c.EventName == "NativeExtractionFailed");
        Assert.Equal(3, counter.RawStoredCount);
        Assert.Equal(2, counter.SuppressedCount);
        Assert.Equal(3, counter.Threshold);
        Assert.Equal("185.162.248.75", counter.LastClientIp);
        Assert.Equal("Test ISP", counter.LastIsp);
        Assert.False(string.IsNullOrWhiteSpace(counter.LastPayloadHash));
    }

    [Fact]
    public async Task SaveEventAsync_WhenOneEventFloods_ShouldStillStoreDifferentEvent()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "YOUR_APP_NAME");
        }

        var service = BuildTelemetryServiceWithFloodSettings(threshold: 1, windowMinutes: 10);

        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-FLOOD-DIFFERENT",
            Version = "1.1.34",
            EventName = "NativeExtractionFailed"
        });
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-FLOOD-DIFFERENT",
            Version = "1.1.34",
            EventName = "NativeExtractionFailed"
        });
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-FLOOD-DIFFERENT",
            Version = "1.1.34",
            EventName = "Startup_AppStarted"
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Single(await checkDb.TelemetryRecords.Where(t => t.EventName == "NativeExtractionFailed").ToListAsync());
        Assert.Single(await checkDb.TelemetryRecords.Where(t => t.EventName == "Startup_AppStarted").ToListAsync());
        Assert.Single(await checkDb.TelemetryFloodSuppressionCounters.ToListAsync());
    }

    [Fact]
    public async Task SaveEventAsync_WhenSecurityEventRepeats_ShouldNotSuppress()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "YOUR_APP_NAME");
        }

        var service = BuildTelemetryServiceWithFloodSettings(threshold: 1, windowMinutes: 10);
        var request = new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-SECURITY-FLOOD",
            Version = "1.1.34",
            EventName = "Startup_SecurityAlert_RuntimeCheck"
        };

        await service.SaveEventAsync(request);
        await service.SaveEventAsync(request);

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Equal(2, await checkDb.TelemetryRecords.CountAsync(t => t.HardwareId == "HW-SECURITY-FLOOD"));
        Assert.False(await checkDb.TelemetryFloodSuppressionCounters.AnyAsync());
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
        var service = new TelemetryService(_dbFactoryMock.Object, _loggerMock.Object, _geoIpMock.Object, _httpFactoryMock.Object, null!, null!, null!);

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

    [Fact]
    public async Task SaveEventAsync_WhenCertPinningFailed_ShouldSendNtfyAlert()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "TIAConnect");
        }

        var capturedRequests = new List<HttpRequestMessage>();
        var handler = new CaptureHttpHandler(capturedRequests);
        _httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(new HttpClient(handler));

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TelemetryCertPinningNtfyUrl"] = "https://ntfy.websitedev.fr/vps-check-tia-pinned-certs"
            })
            .Build();
        var settings = new SettingsService(
            _dbFactoryMock.Object,
            config,
            Mock.Of<ILogger<SettingsService>>());

        var service = new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            settings);

        var request = new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-CERT-PIN",
            Version = "2.1.857",
            EventName = "CertPinningFailed",
            Properties = new Dictionary<string, string>
            {
                ["Host"] = "api.t-ia-connect.com",
                ["OS"] = "Windows 8",
                ["Culture"] = "en",
                ["RequestSource"] = "API_Direct",
                ["Fingerprints"] = "leaf: abc"
            }
        };

        // Act
        await service.SaveEventAsync(request, "1.2.3.4");

        // Assert
        for (var i = 0; i < 20 && capturedRequests.Count == 0; i++)
        {
            await Task.Delay(50);
        }

        var sent = Assert.Single(capturedRequests);
        Assert.Equal(HttpMethod.Post, sent.Method);
        Assert.Contains("ntfy.websitedev.fr/vps-check-tia-pinned-certs", sent.RequestUri!.ToString());
        Assert.Contains("priority=3", sent.RequestUri.ToString(), StringComparison.Ordinal);

        var body = await sent.Content!.ReadAsStringAsync();
        Assert.Contains("CertPinningFailed detected", body);
        Assert.Contains("TIAConnect 2.1.857", body);
        Assert.Contains("HW-CERT-PIN", body);
        Assert.Contains("api.t-ia-connect.com", body);
        Assert.Contains("1.2.3.4", body);
    }

    [Fact]
    public async Task SaveEventAsync_WhenCertPinningRepeatsAcrossHosts_ShouldSendOneDailyNtfyAndCountBoth()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "TIAConnect");
        }

        var capturedRequests = new List<HttpRequestMessage>();
        var handler = new CaptureHttpHandler(capturedRequests);
        _httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(new HttpClient(handler));

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TelemetryCertPinningNtfyUrl"] = "https://ntfy.websitedev.fr/vps-check-tia-pinned-certs"
            })
            .Build();
        var settings = new SettingsService(
            _dbFactoryMock.Object,
            config,
            Mock.Of<ILogger<SettingsService>>());
        var dailyAlerts = new CertPinningDailyAlertService(
            _dbFactoryMock.Object,
            Mock.Of<ILogger<CertPinningDailyAlertService>>());
        var service = new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            settings,
            certPinningDailyAlerts: dailyAlerts);

        var request = new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-CERT-DAILY",
            Version = "2.2.798",
            EventName = "CertPinningFailed",
            Properties = new Dictionary<string, string>
            {
                ["Host"] = "api.t-ia-connect.com",
                ["SuppressedCount"] = "2",
                ["FailureReason"] = "PinMismatch",
                ["CertificateIssuer"] = "CN=Enterprise Forward Trust"
            }
        };

        await service.SaveEventAsync(request, "1.2.3.4");
        for (var i = 0; i < 40; i++)
        {
            await using var db = new LicenseDbContext(_dbOptions);
            if (await db.TelemetryCertPinningDailyAlerts.AnyAsync(a => a.NotificationSentAtUtc != null))
                break;
            await Task.Delay(50);
        }

        request.Version = "2.2.843";
        request.Properties["Host"] = "softlicence.EXAMPLE.COM";
        request.Properties["SuppressedCount"] = "5";
        await service.SaveEventAsync(request, "1.2.3.4");

        for (var i = 0; i < 40; i++)
        {
            await using var db = new LicenseDbContext(_dbOptions);
            var aggregate = await db.TelemetryCertPinningDailyAlerts.SingleAsync();
            if (aggregate.OccurrenceCount == 2)
                break;
            await Task.Delay(50);
        }

        Assert.Single(capturedRequests);
        await using var checkDb = new LicenseDbContext(_dbOptions);
        var daily = await checkDb.TelemetryCertPinningDailyAlerts.SingleAsync();
        Assert.Equal(2, daily.OccurrenceCount);
        Assert.Equal(7, daily.ClientSuppressedCount);
        Assert.Equal("softlicence.EXAMPLE.COM", daily.LastHost);
        Assert.Equal("2.2.843", daily.LastVersion);
        Assert.Equal("PinMismatch", daily.LastFailureReason);
        Assert.Equal("CN=Enterprise Forward Trust", daily.LastCertificateIssuer);
    }

    [Fact]
    public async Task SaveEventAsync_WhenCertPinningFailed_ShouldCreateCriticalBugTraceTicket()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "TIAConnect");
        }

        var bugTrace = new FakeBugTraceAlertProxy();
        var alertService = new CertPinningBugTraceAlertService(
            bugTrace,
            Mock.Of<ILogger<CertPinningBugTraceAlertService>>());

        var service = new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            null!,
            alertService);

        await service.SaveEventAsync(BuildCertPinningRequest("HW-CERT-BUGTRACE-001"), "208.127.173.148");

        for (var i = 0; i < 20 && bugTrace.SubmittedTickets.Count == 0; i++)
        {
            await Task.Delay(50);
        }

        var submitted = Assert.Single(bugTrace.SubmittedTickets);
        var json = JsonSerializer.Serialize(submitted);
        using var document = JsonDocument.Parse(json);
        var description = document.RootElement.GetProperty("description").GetString();

        Assert.Contains("\"priority\":\"CRITICAL\"", json);
        Assert.Contains("CertPinningFailed detected", json);
        Assert.Contains("HW-CERT-BUGTRACE-001", json);
        Assert.Contains("api.t-ia-connect.com", json);
        Assert.Contains("PinMismatch", json);
        Assert.Contains("\"securityCaseId\":\"sec_telemetry_certpinningfailed_", json);
        Assert.Contains("\"trigger\":\"Telemetry.CertPinningFailed\"", json);
        Assert.Contains("\"incidentIp\":\"208.127.173.148\"", json);
        Assert.Contains("\"productName\":\"TIAConnect\"", json);
        Assert.Contains("SecurityCaseId: `sec_telemetry_certpinningfailed_", description);
        Assert.Contains("runtime-validation", json);
        Assert.Contains("dedupe:", json);
    }

    [Fact]
    public async Task SaveEventAsync_WhenCertPinningRecovered_ShouldNotCreateBugTraceTicket()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "TIAConnect");
        }

        var bugTrace = new FakeBugTraceAlertProxy();
        var alertService = new CertPinningBugTraceAlertService(
            bugTrace,
            Mock.Of<ILogger<CertPinningBugTraceAlertService>>());

        var service = new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            null!,
            alertService);

        var request = BuildCertPinningRequest("HW-CERT-RECOVERED-001");
        request.EventName = "CertPinningRecovered";

        await service.SaveEventAsync(request, "208.127.173.148");
        await Task.Delay(100);

        Assert.Empty(bugTrace.SubmittedTickets);
    }

    [Fact]
    public async Task SaveEventAsync_WhenCertPinningFailedDuplicate_ShouldCreateSingleBugTraceTicket()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            await SeedProductAsync(db, "TIAConnect");
        }

        var bugTrace = new FakeBugTraceAlertProxy();
        var alertService = new CertPinningBugTraceAlertService(
            bugTrace,
            Mock.Of<ILogger<CertPinningBugTraceAlertService>>());

        var service = new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            null!,
            alertService);

        var request = BuildCertPinningRequest("HW-CERT-DEDUP-001");

        await service.SaveEventAsync(request, "208.127.173.148");
        await service.SaveEventAsync(request, "208.127.173.148");

        for (var i = 0; i < 20 && bugTrace.SubmittedTickets.Count == 0; i++)
        {
            await Task.Delay(50);
        }

        Assert.Single(bugTrace.SubmittedTickets);
    }

    [Fact]
    public async Task SaveEventAsync_WhenProductWebhookReturnsNonSuccess_ShouldPersistLastError()
    {
        Guid productId;
        using (var db = new LicenseDbContext(_dbOptions))
        {
            productId = Guid.NewGuid();
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "YOUR_APP_NAME",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-YOUR_APP_NAME"
            });
            db.ProductWebhooks.Add(new ProductWebhook
            {
                ProductId = productId,
                Name = "YOUR_APP_NAME_Web_api",
                Url = "https://api.YOUR_APP_NAME.EXAMPLE.COM/api/webhooks/softlicence",
                Secret = "configured-secret",
                IsEnabled = true
            });
            await db.SaveChangesAsync();
        }

        var handler = new StaticHttpHandler(HttpStatusCode.Unauthorized);
        _httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(new HttpClient(handler));

        var service = new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            null!);

        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-WEBHOOK-401",
            Version = "1.1.34",
            EventName = "NativeExtractionFailed"
        });

        ProductWebhook? webhook = null;
        for (var i = 0; i < 20; i++)
        {
            await Task.Delay(50);
            using var checkDb = new LicenseDbContext(_dbOptions);
            webhook = await checkDb.ProductWebhooks.AsNoTracking().SingleAsync(w => w.ProductId == productId);
            if (webhook.LastError != null)
                break;
        }

        Assert.NotNull(webhook);
        Assert.NotNull(webhook.LastTriggeredAt);
        Assert.Equal("HTTP 401 Unauthorized", webhook.LastError);
    }

    [Fact]
    public async Task SaveEventAsync_ProductWebhookReceivesSanitizedCopyInsteadOfRawBinaryValue()
    {
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var productId = Guid.NewGuid();
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "YOUR_APP_NAME",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-YOUR_APP_NAME"
            });
            db.ProductWebhooks.Add(new ProductWebhook
            {
                ProductId = productId,
                Name = "capture",
                Url = "https://example.test/telemetry",
                IsEnabled = true
            });
            await db.SaveChangesAsync();
        }

        var capturedRequests = new List<HttpRequestMessage>();
        _httpFactoryMock.Setup(factory => factory.CreateClient(It.IsAny<string>()))
            .Returns(new HttpClient(new CaptureHttpHandler(capturedRequests)));
        const string malformed = "raw-malformed-binary-value";

        await new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            null!).SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "YOUR_APP_NAME",
            HardwareId = "HW-WEBHOOK-SANITIZED",
            Version = "1.2.3",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = malformed,
                ["OrdinaryProperty"] = "preserved"
            }
        });

        for (var index = 0; index < 50 && capturedRequests.Count == 0; index++)
            await Task.Delay(20);

        var request = Assert.Single(capturedRequests);
        var payload = await request.Content!.ReadAsStringAsync();
        Assert.DoesNotContain(malformed, payload, StringComparison.Ordinal);
        Assert.Contains("[invalid]", payload, StringComparison.Ordinal);
        Assert.Contains("preserved", payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaveEventAsync_WhenOldFeatureEventHasFreeLicenseType_ShouldAutoBan()
    {
        // Arrange
        var productId = Guid.NewGuid();
        var licenseTypeId = Guid.NewGuid();
        const string hardwareId = "HW-OLD-FREE";

        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect",
                MinimumAllowedVersion = "2.1.781"
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = licenseTypeId,
                ProductId = productId,
                Name = "Freemium Custom",
                Slug = "FREEMIUM_2026",
                IsFree = true
            });
            db.Licenses.Add(new License
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                LicenseTypeId = licenseTypeId,
                LicenseKey = "TEST-FREE",
                CustomerEmail = "free@example.test",
                CustomerName = "Free User",
                HardwareId = hardwareId,
                IsActive = true,
                ExpirationDate = DateTime.UtcNow.AddDays(14)
            });
            await db.SaveChangesAsync();
        }

        var service = BuildTelemetryServiceWithSecurity();

        // Act
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = hardwareId,
            Version = "2.1.750",
            EventName = "API_FeatureNotAvailable",
            Properties = new Dictionary<string, string>
            {
                ["FP_CPU"] = "cpu-old-version",
                ["FP_DISK"] = "disk-old-version",
                ["FP_MB"] = "mb-old-version",
                ["FP_HOST"] = "host-old-version",
                ["FP_BIOS"] = "bios-old-version"
            }
        });

        // Assert
        using var checkDb = new LicenseDbContext(_dbOptions);
        var ban = await checkDb.BannedHardwareIds.SingleOrDefaultAsync(b => b.HardwareId == hardwareId);

        Assert.NotNull(ban);
        Assert.True(ban.IsActive);
        Assert.Equal(productId, ban.ProductId);
        Assert.Equal(BannedHardwareId.Categories.OutdatedVersion, ban.BanCategory);
        Assert.Contains("API_FeatureNotAvailable", ban.Reason);
        Assert.Contains("2.1.750", ban.Reason);
        Assert.Contains("2.1.781", ban.Reason);
        Assert.False(await checkDb.BannedComponents.AnyAsync(), "outdated_version auto-ban must not ban component fingerprints.");
    }

    [Fact]
    public async Task SaveEventAsync_WhenOldFeatureEventHasPaidSeat_ShouldNotAutoBan()
    {
        // Arrange
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var licenseTypeId = Guid.NewGuid();
        const string hardwareId = "HW-OLD-PAID-SEAT";

        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect",
                MinimumAllowedVersion = "2.1.781"
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = licenseTypeId,
                ProductId = productId,
                Name = "Pro",
                Slug = "PRO",
                IsFree = false
            });
            db.Licenses.Add(new License
            {
                Id = licenseId,
                ProductId = productId,
                LicenseTypeId = licenseTypeId,
                LicenseKey = "TEST-PAID",
                CustomerEmail = "paid@example.test",
                CustomerName = "Paid User",
                HardwareId = "PRIMARY-HWID",
                IsActive = true,
                ExpirationDate = DateTime.UtcNow.AddDays(14),
                MaxSeats = 2
            });
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId,
                HardwareId = hardwareId,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var service = BuildTelemetryServiceWithSecurity();

        // Act
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = hardwareId,
            Version = "2.1.750",
            EventName = "API_FeatureNotAvailable"
        });

        // Assert
        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.False(await checkDb.BannedHardwareIds.AnyAsync(b => b.HardwareId == hardwareId));
    }

    [Fact]
    public async Task SaveEventAsync_WhenBaselineIsMissing_ReplayedClientEvidenceNeverCreatesBaselineOrBan()
    {
        var productId = Guid.NewGuid();
        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect"
            });
            await db.SaveChangesAsync();
        }

        var service = BuildTelemetryServiceWithSecurity();
        var request = new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-UNTRUSTED-REPLAY",
            Version = "2.2.844",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = new string('a', 64),
                ["FP_DLL"] = new string('b', 64),
                ["FP_CORE"] = new string('c', 64)
            }
        };

        await service.SaveEventAsync(request);
        await service.SaveEventAsync(request);

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Empty(await checkDb.ApprovedBinaries.ToListAsync());
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryBaselineMissingFamily, incident.Family);
        Assert.Equal(2, incident.OccurrenceCount);
        Assert.False(incident.IsHardwareBanned);
    }

    [Fact]
    public async Task SaveEventAsync_WhenOnlyLegacyAutoBaselineExists_DoesNotPromoteOrBan()
    {
        var productId = Guid.NewGuid();
        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect"
            });
            db.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = productId, Version = "2.2.798", Key = "FP_EXE", Hash = new string('a', 64), Source = "auto" },
                new ApprovedBinary { ProductId = productId, Version = "2.2.798", Key = "FP_DLL", Hash = new string('b', 64), Source = "auto" },
                new ApprovedBinary { ProductId = productId, Version = "2.2.798", Key = "FP_CORE", Hash = new string('c', 64), Source = "auto" });
            await db.SaveChangesAsync();
        }

        var service = BuildTelemetryServiceWithSecurity();
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-LEGACY-AUTO",
            Version = "2.2.798",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = new string('f', 64),
                ["FP_DLL"] = new string('e', 64),
                ["FP_CORE"] = new string('d', 64)
            }
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        var baselines = await checkDb.ApprovedBinaries.ToListAsync();
        Assert.Equal(3, baselines.Count);
        Assert.All(baselines, baseline => Assert.Equal("auto", baseline.Source));
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryBaselineMissingFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
    }

    [Fact]
    public async Task SaveEventAsync_WhenClientHashIsMalformed_CreatesObservationWithoutAuthorityOrBan()
    {
        var productId = Guid.NewGuid();
        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect"
            });
            db.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = productId, Version = "2.2.844", Key = "FP_EXE", Hash = new string('a', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = "2.2.844", Key = "FP_DLL", Hash = new string('b', 64), Source = "release" },
                new ApprovedBinary { ProductId = productId, Version = "2.2.844", Key = "FP_CORE", Hash = new string('c', 64), Source = "release" });
            await db.SaveChangesAsync();
        }

        var service = BuildTelemetryServiceWithSecurity();
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-MALFORMED-BINARY",
            Version = "2.2.844",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = "not-a-sha256",
                ["FP_DLL"] = new string('b', 64),
                ["FP_CORE"] = new string('c', 64)
            }
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
        Assert.Equal(3, await checkDb.ApprovedBinaries.CountAsync());
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal("ApprovedBinaryEvidenceInvalid", incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Empty(await checkDb.SecurityIncidentEvidence.ToListAsync());
        var storedProperties = (await checkDb.TelemetryRecords.Include(r => r.EventData).SingleAsync()).EventData!.PropertiesJson!;
        Assert.DoesNotContain("not-a-sha256", storedProperties, StringComparison.Ordinal);
        Assert.Contains("[invalid]", storedProperties, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaveEventAsync_WhenApprovedBinaryKeyIsNonCanonical_RejectsItAndRedactsMalformedValue()
    {
        await SeedApprovedBinaryBaselineAsync("2.2.899");

        await BuildTelemetryServiceWithSecurity().SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-NONCANONICAL-BINARY",
            Version = "2.2.899",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["fp_exe"] = "malformed-client-value",
                ["FP_DLL"] = new string('b', 64),
                ["FP_CORE"] = new string('c', 64)
            }
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryEvidenceInvalidFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Empty(await checkDb.SecurityIncidentEvidence.ToListAsync());
        var storedProperties = (await checkDb.TelemetryRecords.Include(r => r.EventData).SingleAsync()).EventData!.PropertiesJson!;
        Assert.DoesNotContain("malformed-client-value", storedProperties, StringComparison.Ordinal);
        Assert.Contains("[invalid]", storedProperties, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaveEventAsync_WhenApprovedBinaryEvidenceMatches_CreatesNoIncidentOrSanction()
    {
        var productId = await SeedApprovedBinaryBaselineAsync("2.2.900");
        var service = BuildTelemetryServiceWithSecurity();

        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-APPROVED-BINARY",
            Version = "2.2.900",
            EventName = "Startup_AppStarted",
            Properties = ApprovedBinaryProperties()
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Empty(await checkDb.SecurityIncidents.ToListAsync());
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
        Assert.Equal(productId, (await checkDb.TelemetryRecords.SingleAsync()).ProductId);
    }

    [Fact]
    public async Task SaveEventAsync_WhenReleaseRowsAreUnbound_RefusesThemAsAuthoritative()
    {
        await SeedUnboundReleaseBaselineAsync("2.2.900-unbound");

        await BuildTelemetryServiceWithSecurity().SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-UNBOUND-RELEASE",
            Version = "2.2.900-unbound",
            EventName = "Startup_AppStarted",
            Properties = ApprovedBinaryProperties()
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryBaselineMissingFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Empty(await checkDb.SecurityIncidentEvidence.ToListAsync());
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SaveEventAsync_WhenApprovedBinaryEvidenceIsMissing_CreatesObservationWithoutSanction(bool partial)
    {
        await SeedApprovedBinaryBaselineAsync("2.2.901");
        var properties = partial
            ? new Dictionary<string, string> { ["FP_EXE"] = new string('a', 64) }
            : new Dictionary<string, string>();

        await BuildTelemetryServiceWithSecurity().SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = partial ? "HW-PARTIAL-BINARY" : "HW-NO-BINARY",
            Version = "2.2.901",
            EventName = "Startup_AppStarted",
            Properties = properties
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryEvidenceMissingFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Empty(await checkDb.SecurityIncidentEvidence.ToListAsync());
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
    }

    [Fact]
    public async Task SaveEventAsync_WhenNativeCaptureIsUnavailable_CreatesDedicatedObservationWithoutSanction()
    {
        await SeedApprovedBinaryBaselineAsync("2.2.902");

        await BuildTelemetryServiceWithSecurity().SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = "HW-NATIVE-UNAVAILABLE",
            Version = "2.2.902",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string> { ["FP_STATUS"] = "native-unavailable" }
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryCaptureUnavailableFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Empty(await checkDb.SecurityIncidentEvidence.ToListAsync());
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
    }

    [Theory]
    [InlineData("fp_status", "native-unavailable")]
    [InlineData(" FP_STATUS ", "native-unavailable")]
    [InlineData("FP_STATUS", " native-unavailable ")]
    public async Task SaveEventAsync_WhenNativeCaptureMarkerIsNonCanonical_TreatsBinaryEvidenceAsMissing(
        string statusKey,
        string statusValue)
    {
        await SeedApprovedBinaryBaselineAsync("2.2.903");

        await BuildTelemetryServiceWithSecurity().SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = $"HW-STATUS-{Guid.NewGuid():N}",
            Version = "2.2.903",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string> { [statusKey] = statusValue }
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        var incident = await checkDb.SecurityIncidents.SingleAsync();
        Assert.Equal(SecurityIncidentService.ApprovedBinaryEvidenceMissingFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
    }

    [Fact]
    public async Task SaveEventAsync_ManyDeclaredHwidsAndHashes_CreateOneCappedPublicAggregate()
    {
        await SeedApprovedBinaryBaselineAsync("2.2.904");
        var service = BuildTelemetryServiceWithSecurity();

        foreach (var index in Enumerable.Range(1, 25))
        {
            await service.SaveEventAsync(new TelemetryEventRequest
            {
                AppName = "TIAConnect",
                HardwareId = $"DECLARED-HWID-{index:D2}",
                Version = "2.2.904",
                EventName = "Startup_AppStarted",
                Properties = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["FP_EXE"] = index.ToString("x64"),
                    ["FP_DLL"] = new string('b', 64),
                    ["FP_CORE"] = new string('c', 64)
                }
            });
        }

        using var checkDb = new LicenseDbContext(_dbOptions);
        var incident = await checkDb.SecurityIncidents.Include(row => row.Evidence).SingleAsync();
        Assert.Equal(SecurityIncidentService.PublicTelemetryAggregateIdentity, incident.HardwareId);
        Assert.Equal(25, incident.OccurrenceCount);
        Assert.Equal(SecurityIncidentService.MaxEvidencePerPublicAggregate, incident.Evidence.Count);
        Assert.Equal(25, await checkDb.TelemetryRecords.Select(row => row.HardwareId).Distinct().CountAsync());
        Assert.DoesNotContain(incident.Evidence, evidence => evidence.ComponentHash.Contains("DECLARED-HWID", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SaveEventAsync_WhenBinaryHashMismatch_CreatesObservationWithoutDurableSanction()
    {
        // Arrange
        var productId = Guid.NewGuid();
        const string sourceHardwareId = "HW-BINARY-PATCHED";
        const string relatedHardwareId = "HW-RELATED-HARDWARE";
        const string expectedExeHash = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111";
        const string patchedExeHash = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222";
        const string motherboardHash = "shared-mb-hash";

        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect"
            });
            AddAuthoritativeApprovedBinaryBaseline(db, productId, "2.1.839", new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["FP_EXE"] = expectedExeHash,
                ["FP_DLL"] = new string('c', 64),
                ["FP_CORE"] = new string('d', 64)
            });
            db.HardwareFingerprints.Add(new HardwareFingerprint
            {
                HardwareId = relatedHardwareId,
                CpuHash = "shared-cpu-hash",
                MotherboardHash = motherboardHash,
                BiosHash = "shared-bios-hash",
                DiskHash = "related-disk-hash",
                HostHash = "related-host-hash"
            });
            await db.SaveChangesAsync();
        }

        var service = BuildTelemetryServiceWithSecurity();

        // Act
        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = sourceHardwareId,
            Version = "2.1.839",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = patchedExeHash,
                ["FP_DLL"] = new string('c', 64),
                ["FP_CORE"] = new string('d', 64),
                ["FP_CPU"] = "shared-cpu-hash",
                ["FP_MB"] = motherboardHash,
                ["FP_BIOS"] = "shared-bios-hash",
                ["FP_DISK"] = "source-disk-hash",
                ["FP_HOST"] = "source-host-hash"
            }
        });

        // Assert
        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
        Assert.False(await checkDb.BannedHardwareIds.AnyAsync(b => b.HardwareId == relatedHardwareId));

        var incident = await checkDb.SecurityIncidents.Include(i => i.Evidence).SingleAsync();
        Assert.Equal(SecurityIncidentService.PublicTelemetryAggregateIdentity, incident.HardwareId);
        Assert.Null(incident.Version);
        Assert.Null(incident.ClientIp);
        Assert.Equal("ApprovedBinaryMismatch", incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Equal(1, incident.OccurrenceCount);
        var evidence = Assert.Single(incident.Evidence);
        Assert.Equal("FP_EXE", evidence.ComponentType);
        Assert.Equal(patchedExeHash.ToUpperInvariant(), evidence.ComponentHash);
    }

    [Fact]
    public async Task SaveEventAsync_WhenIncidentAggregationFails_DoesNotCreateDurableSanction()
    {
        var productId = Guid.NewGuid();
        const string hardwareId = "HW-FAILSAFE-BINARY";
        const string expectedHash = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111";
        const string patchedHash = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222";

        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret-TIAConnect"
            });
            AddAuthoritativeApprovedBinaryBaseline(db, productId, "2.1.839", new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["FP_EXE"] = expectedHash,
                ["FP_DLL"] = new string('c', 64),
                ["FP_CORE"] = new string('d', 64)
            });
            await db.SaveChangesAsync();
        }

        var config = new ConfigurationBuilder().Build();
        var notifications = new Mock<NotificationService>(
            _dbFactoryMock.Object,
            Mock.Of<ILogger<NotificationService>>(),
            _httpFactoryMock.Object);
        var incidentService = new Mock<SecurityIncidentService>(
            _dbFactoryMock.Object,
            notifications.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            config);
        incidentService.Setup(s => s.RecordApprovedBinaryObservationAsync(
                It.IsAny<Guid>(),
                It.IsAny<ApprovedBinaryObservationKind>(),
                It.IsAny<IReadOnlyDictionary<string, string>?>(),
                It.IsAny<DateTime?>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Simulated incident persistence failure"));
        var service = BuildTelemetryServiceWithSecurity(incidentService.Object);

        await service.SaveEventAsync(new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = hardwareId,
            Version = "2.1.839",
            EventName = "Startup_AppStarted",
            Properties = new Dictionary<string, string>
            {
                ["FP_EXE"] = patchedHash,
                ["FP_DLL"] = new string('c', 64),
                ["FP_CORE"] = new string('d', 64)
            }
        });

        using var checkDb = new LicenseDbContext(_dbOptions);
        Assert.Empty(await checkDb.BannedHardwareIds.ToListAsync());
        Assert.Empty(await checkDb.BannedComponents.ToListAsync());
        Assert.Empty(await checkDb.SecurityIncidents.ToListAsync());
    }

    private TelemetryService BuildTelemetryServiceWithSecurity(SecurityIncidentService? incidentService = null)
    {
        var config = new ConfigurationBuilder().Build();
        var settings = new SettingsService(
            _dbFactoryMock.Object,
            config,
            Mock.Of<ILogger<SettingsService>>());

        var fingerprintService = new FingerprintService(
            _dbFactoryMock.Object,
            Mock.Of<ILogger<FingerprintService>>(),
            settings);

        var notifier = new Mock<NotificationService>(
            _dbFactoryMock.Object,
            Mock.Of<ILogger<NotificationService>>(),
            _httpFactoryMock.Object);
        notifier.Setup(n => n.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));

        var security = new SecurityService(
            _dbFactoryMock.Object,
            Mock.Of<ILogger<SecurityService>>(),
            notifier.Object,
            config);

        incidentService ??= new SecurityIncidentService(
            _dbFactoryMock.Object,
            notifier.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            config);

        return new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            fingerprintService,
            security,
            settings,
            securityIncidents: incidentService);
    }

    private async Task<Guid> SeedApprovedBinaryBaselineAsync(string version)
    {
        var productId = Guid.NewGuid();
        using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TIAConnect",
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret-TIAConnect"
        });
        var properties = ApprovedBinaryProperties();
        AddAuthoritativeApprovedBinaryBaseline(db, productId, version, properties);
        await db.SaveChangesAsync();
        return productId;
    }

    private static void AddAuthoritativeApprovedBinaryBaseline(
        LicenseDbContext db,
        Guid productId,
        string version,
        IReadOnlyDictionary<string, string> properties)
    {
        var artifacts = new[] { "FP_EXE", "FP_DLL", "FP_CORE" }
            .Select(key => new ApprovedBinaryArtifact(key, properties[key]))
            .ToList();
        var registration = new ApprovedBinaryRegistration
        {
            ProductId = productId,
            Version = version,
            RegistrationKey = $"telemetry-test/{version}/{Guid.NewGuid():N}",
            ManifestDigestSha256 = new string('d', 64),
            BaselineDigestSha256 = ApprovedBinaryService.ComputeBaselineDigestSha256(artifacts),
            Source = ApprovedBinaryService.ReleaseSource
        };
        db.ApprovedBinaryRegistrations.Add(registration);
        db.ApprovedBinaries.AddRange(artifacts.Select(artifact => new ApprovedBinary
        {
            ProductId = productId,
            ApprovedBinaryRegistrationId = registration.Id,
            Version = version,
            Key = artifact.Key,
            Hash = artifact.Sha256,
            Source = ApprovedBinaryService.ReleaseSource
        }));
    }

    private async Task SeedUnboundReleaseBaselineAsync(string version)
    {
        var productId = Guid.NewGuid();
        using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TIAConnect",
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret-TIAConnect"
        });
        db.ApprovedBinaries.AddRange(ApprovedBinaryProperties().Select(pair => new ApprovedBinary
        {
            ProductId = productId,
            Version = version,
            Key = pair.Key,
            Hash = pair.Value,
            Source = ApprovedBinaryService.ReleaseSource
        }));
        await db.SaveChangesAsync();
    }

    private static Dictionary<string, string> ApprovedBinaryProperties() => new(StringComparer.Ordinal)
    {
        ["FP_EXE"] = new string('a', 64),
        ["FP_DLL"] = new string('b', 64),
        ["FP_CORE"] = new string('c', 64)
    };

    private TelemetryService BuildTelemetryServiceWithFloodSettings(int threshold, int windowMinutes)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TelemetryFloodSuppressionEnabled"] = "true",
                ["TelemetryFloodSuppressionThreshold"] = threshold.ToString(),
                ["TelemetryFloodSuppressionWindowMinutes"] = windowMinutes.ToString()
            })
            .Build();

        var settings = new SettingsService(
            _dbFactoryMock.Object,
            config,
            Mock.Of<ILogger<SettingsService>>());

        return new TelemetryService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _geoIpMock.Object,
            _httpFactoryMock.Object,
            null!,
            null!,
            settings);
    }

    private static TelemetryEventRequest BuildCertPinningRequest(string hardwareId)
    {
        return new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = hardwareId,
            Version = "2.1.997",
            EventName = "CertPinningFailed",
            Properties = new Dictionary<string, string>
            {
                ["Host"] = "api.t-ia-connect.com",
                ["OS"] = "Windows 8",
                ["Culture"] = "en",
                ["RequestSource"] = "API_Direct",
                ["IsInteractive"] = "False",
                ["FailureReason"] = "PinMismatch",
                ["ExpectedPinsCount"] = "3",
                ["ObservedChainCount"] = "4",
                ["SuppressedCount"] = "0",
                ["CertificateIssuer"] = "CN=PA-ForwardTrustCertificate",
                ["CertificateSubject"] = "CN=softlicence.EXAMPLE.COM",
                ["CertificateThumbprint"] = "5C172B7BE85F804DE472851111E96BB146EA6BDE",
                ["CertificateNotBeforeUtc"] = "2026-05-21T17:02:39.0000000Z",
                ["CertificateNotAfterUtc"] = "2026-08-19T17:02:38.0000000Z",
                ["FirstFailureAt"] = "2026-06-09T10:13:39.2939340Z",
                ["LastFailureAt"] = "2026-06-09T10:13:39.2939340Z"
            }
        };
    }

    private sealed class FakeBugTraceAlertProxy : IBugTraceProxyService
    {
        public string ExpectedProjectId => "test-project";
        public bool IsConfigured { get; set; } = true;
        public List<object> SubmittedTickets { get; } = new();

        public Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default)
        {
            SubmittedTickets.Add(ticketBody);
            var json = JsonSerializer.Serialize(new { ticketNumber = "TKT-TEST-001", id = "ticket-id" });
            return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
        }

        public Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default) =>
            throw new NotImplementedException();

        public Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default) =>
            throw new NotImplementedException();

        public Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default) =>
            throw new NotImplementedException();
    }

    private sealed class CaptureHttpHandler : HttpMessageHandler
    {
        private readonly List<HttpRequestMessage> _capturedRequests;
        private readonly object _captureLock = new();
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public CaptureHttpHandler(List<HttpRequestMessage> capturedRequests)
        {
            _capturedRequests = capturedRequests;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);
            if (request.Content != null)
            {
                clone.Content = new StringContent(await request.Content.ReadAsStringAsync(cancellationToken));
            }

            lock (_captureLock)
            {
                _capturedRequests.Add(clone);
            }
            Interlocked.Increment(ref _count);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class StaticHttpHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;

        public StaticHttpHandler(HttpStatusCode statusCode)
        {
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(_statusCode));
        }
    }
}
