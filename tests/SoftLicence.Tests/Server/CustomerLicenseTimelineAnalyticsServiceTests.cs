using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class CustomerLicenseTimelineAnalyticsServiceTests
{
    private const string FullLicenseKey = "9B1784F2-AAAA-BBBB-CCCC-DDDD1B1E";
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public CustomerLicenseTimelineAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetTimelineForProductIdAsync_ByEmail_ReturnsGenericMultiHardwareTimelineAndServerUnlinkVerdict()
    {
        var productId = await SeedGenericMultiHardwareCaseAsync();
        var service = CreateService();
        var period = TelemetryAnalyticsPeriod.Resolve(
            days: 30,
            date: null,
            fromUtc: "2026-07-01T00:00:00Z",
            toUtc: "2026-07-13T00:00:00Z");

        var result = await service.GetTimelineForProductIdAsync(
            productId,
            email: "customer@example.com",
            emailFragment: null,
            hardwareId: null,
            licenseId: null,
            licenseFragment: null,
            period,
            takeTimeline: 500,
            offset: 0,
            includeAccessLogs: true,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true,
            mode: "full");

        Assert.False(result.Cached);
        Assert.Equal(1, result.Summary.LicenseCount);
        Assert.Equal(3, result.Summary.HardwareIdCount);
        Assert.Equal(1, result.Licenses[0].MaxSeats);
        Assert.Contains("multiple_hardware_ids", result.Summary.VerdictCodes);
        Assert.Contains("seat_limit_conflict", result.Summary.VerdictCodes);
        Assert.Contains("update_revoke_license_seen", result.Summary.VerdictCodes);
        Assert.Contains("no_server_seat_unlink_trace_found", result.Summary.VerdictCodes);
        Assert.True(result.Summary.UpdateRevokeLicenseSeen);
        Assert.False(result.Summary.ServerSeatUnlinkTraceSeen);
        Assert.Equal("no_server_seat_unlink_trace_found", result.Summary.ServerDeactivationVerdict);

        Assert.Contains(result.HardwareIds, h => h.HardwareId == "23D16BA710A9FA38");
        Assert.Contains(result.HardwareIds, h => h.HardwareId == "97EC4EF84C96AD24");
        Assert.Contains(result.HardwareIds, h => h.HardwareId == "55BA0C1BEA1CA1C3");
        Assert.Contains(result.Timeline, item => item.EventName == "Update_RevokeLicense" && item.ReasonCode == "UpdateRevokeLicense");
        Assert.Contains(result.Timeline, item => item.EventName == "LicenseActivation_Failed" && item.ReasonCode == "ActivationLimit");
        Assert.Contains(result.Timeline, item => item.Source == "access_log" && item.Result == "failure");

        var body = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("customer@example.com", body, StringComparison.Ordinal);
        Assert.Contains("23D16BA710A9FA38", body, StringComparison.Ordinal);
        Assert.DoesNotContain(FullLicenseKey, body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AAAA-BBBB-CCCC", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LicenseFile", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Token", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTimelineForProductIdAsync_ByHardwareFragment_ResolvesTelemetryHardwareId()
    {
        var productId = await SeedGenericMultiHardwareCaseAsync();
        var service = CreateService();
        var period = TelemetryAnalyticsPeriod.Resolve(
            days: 30,
            date: null,
            fromUtc: "2026-07-01T00:00:00Z",
            toUtc: "2026-07-13T00:00:00Z");

        var result = await service.GetTimelineForProductIdAsync(
            productId,
            email: null,
            emailFragment: null,
            hardwareId: "55BA0C",
            licenseId: null,
            licenseFragment: null,
            period,
            takeTimeline: 50,
            offset: 0,
            includeAccessLogs: false,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true,
            mode: "timeline");

        Assert.Contains(result.HardwareIds, h => h.HardwareId == "55BA0C1BEA1CA1C3");
        Assert.Contains(result.Timeline, item => item.HardwareId == "55BA0C1BEA1CA1C3");
    }

    [Fact]
    public async Task GetTimelineForProductIdAsync_SummaryMode_KeepsHardwareCountsAndVerdicts()
    {
        var productId = await SeedGenericMultiHardwareCaseAsync();
        var service = CreateService();
        var period = TelemetryAnalyticsPeriod.Resolve(
            days: 30,
            date: null,
            fromUtc: "2026-07-01T00:00:00Z",
            toUtc: "2026-07-13T00:00:00Z");

        var result = await service.GetTimelineForProductIdAsync(
            productId,
            email: "customer@example.com",
            emailFragment: null,
            hardwareId: null,
            licenseId: null,
            licenseFragment: null,
            period,
            takeTimeline: 50,
            offset: 0,
            includeAccessLogs: true,
            includeNoise: false,
            importantOnly: true,
            includeProperties: false,
            mode: "summary");

        Assert.Empty(result.Timeline);
        Assert.Equal(3, result.Summary.HardwareIdCount);
        Assert.Contains("multiple_hardware_ids", result.Summary.VerdictCodes);
        Assert.Contains("seat_limit_conflict", result.Summary.VerdictCodes);
        Assert.Contains(result.HardwareIds, h => h.HardwareId == "23D16BA710A9FA38");
    }

    [Fact]
    public void RedactPropertiesForTimeline_RemovesSecretsAndPathsButKeepsSupportFields()
    {
        var properties = CustomerLicenseTimelineAnalyticsService.RedactPropertiesForTimeline(
            """{"Reason":"ActivationLimit","LicenseKey":"SECRET","LicenseFile":"FILE","Token":"TOK","LocalPath":"C:\\Users\\x","AppVersion":"2.2.1"}""");

        Assert.Equal("ActivationLimit", properties["Reason"]);
        Assert.Equal("2.2.1", properties["AppVersion"]);
        Assert.DoesNotContain("LicenseKey", properties.Keys);
        Assert.DoesNotContain("LicenseFile", properties.Keys);
        Assert.DoesNotContain("Token", properties.Keys);
        Assert.DoesNotContain("LocalPath", properties.Keys);
    }

    private CustomerLicenseTimelineAnalyticsService CreateService()
    {
        return new CustomerLicenseTimelineAnalyticsService(_dbFactoryMock.Object, _cache);
    }

    private async Task<Guid> SeedGenericMultiHardwareCaseAsync()
    {
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();

        await using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TIAConnect",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = "secret"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "TIA Connect Pro",
            Slug = "TIA-CONNECT-PRO",
            DefaultDurationDays = 365
        });
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = FullLicenseKey,
            CustomerName = "Generic Customer",
            CustomerEmail = "customer@example.com",
            HardwareId = "55BA0C1BEA1CA1C3",
            CreationDate = DateTime.Parse("2026-07-01T08:00:00Z").ToUniversalTime(),
            ActivationDate = DateTime.Parse("2026-07-08T09:00:00Z").ToUniversalTime(),
            IsActive = true,
            MaxSeats = 1,
            Seats =
            {
                new LicenseSeat
                {
                    HardwareId = "23D16BA710A9FA38",
                    FirstActivatedAt = DateTime.Parse("2026-07-02T09:00:00Z").ToUniversalTime(),
                    LastCheckInAt = DateTime.Parse("2026-07-07T09:00:00Z").ToUniversalTime(),
                    AppVersion = "2.1.900",
                    IsActive = false
                },
                new LicenseSeat
                {
                    HardwareId = "97EC4EF84C96AD24",
                    FirstActivatedAt = DateTime.Parse("2026-07-08T09:00:00Z").ToUniversalTime(),
                    LastCheckInAt = DateTime.Parse("2026-07-08T10:00:00Z").ToUniversalTime(),
                    AppVersion = "2.1.900",
                    IsActive = false
                },
                new LicenseSeat
                {
                    HardwareId = "55BA0C1BEA1CA1C3",
                    FirstActivatedAt = DateTime.Parse("2026-07-12T11:00:00Z").ToUniversalTime(),
                    LastCheckInAt = DateTime.Parse("2026-07-12T12:00:00Z").ToUniversalTime(),
                    AppVersion = "2.2.100",
                    IsActive = true
                }
            }
        });

        AddEvent(db, productId, "97EC4EF84C96AD24", "LicenseActivation_Success", "2.1.900",
            """{"Reason":"Activated","LicenseKey":"SECRET","Token":"hidden"}""",
            "2026-07-08T09:00:00Z",
            "198.51.100.10");
        AddEvent(db, productId, "55BA0C1BEA1CA1C3", "LicenseActivation_Success", "2.2.100",
            """{"Reason":"Activated"}""",
            "2026-07-12T11:00:00Z",
            "198.51.100.11");
        AddEvent(db, productId, "23D16BA710A9FA38", "LicenseActivation_Failed", "2.1.900",
            """{"Reason":"ActivationLimit","LicenseFile":"secret-file"}""",
            "2026-07-12T11:30:00Z",
            "198.51.100.12");
        AddEvent(db, productId, "23D16BA710A9FA38", "Update_RevokeLicense", "2.1.900",
            """{"ServerStatus":"REVOKED","RevokeCause":"Update_RevokeLicense"}""",
            "2026-07-12T11:35:00Z",
            "198.51.100.12");

        db.AccessLogs.Add(new AccessLog
        {
            Timestamp = DateTime.Parse("2026-07-12T11:30:05Z").ToUniversalTime(),
            ClientIp = "198.51.100.12",
            Method = "POST",
            Path = "/api/activation",
            Endpoint = "Activation",
            LicenseKey = FullLicenseKey,
            HardwareId = "23D16BA710A9FA38",
            AppName = "TIAConnect",
            StatusCode = 400,
            ResultStatus = "ActivationLimit",
            ErrorDetails = "MaxActivationsReached",
            IsSuccess = false
        });

        await db.SaveChangesAsync();
        return productId;
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        string propertiesJson,
        string timestampUtc,
        string clientIp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = DateTime.Parse(timestampUtc).ToUniversalTime(),
            HardwareId = hardwareId,
            ClientIp = clientIp,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent { PropertiesJson = propertiesJson }
        });
    }
}
