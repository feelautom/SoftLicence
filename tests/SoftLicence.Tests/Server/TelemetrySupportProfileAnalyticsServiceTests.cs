using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetrySupportProfileAnalyticsServiceTests
{
    private const string FullLicenseKey = "AAAA-BBBB-CCCC-DDDD";
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetrySupportProfileAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByHardwareId_ReturnsSelectedCandidateAndMachineProfile()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "HW-A",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        Assert.False(profile.Cached);
        Assert.False(profile.IsAmbiguous);
        Assert.Equal(1, profile.CandidateCount);
        Assert.NotNull(profile.SelectedCandidate);
        Assert.Equal("HW-A", profile.SelectedCandidate.HardwareId);
        Assert.Equal("franck@example.com", profile.SelectedCandidate.CustomerEmail);
        Assert.Equal("fr***@example.com", profile.SelectedCandidate.CustomerEmailRedacted);
        Assert.Equal("AAAA****DDDD", profile.SelectedCandidate.LicenseKeyRedacted);
        Assert.Equal("AAAA", profile.SelectedCandidate.LicenseKeyFirstSegment);
        Assert.Equal("TIA-CONNECT-PRO", profile.SelectedCandidate.LicenseTypeSlug);
        Assert.Equal("TIA Connect Pro", profile.SelectedCandidate.LicenseTypeName);
        Assert.Equal(365, profile.SelectedCandidate.LicenseValidityDays);
        Assert.Equal(365, profile.SelectedCandidate.LicenseTypeDefaultDurationDays);
        Assert.Equal("Professional", profile.SelectedCandidate.LicenseEdition);
        Assert.NotNull(profile.MachineProfile);
        Assert.Equal(3, profile.MachineProfile.RecordsAnalyzed);
        Assert.NotNull(profile.Quotas);
        Assert.Equal(3, profile.Quotas.RecordsWithQuota);
        Assert.True(profile.Quotas.HasSaturatedQuota);

        var mcpQuota = Assert.Single(profile.Quotas.Quotas, q => q.QuotaKey == "Quota_Mcp_Daily");
        Assert.Equal(10, mcpQuota.PeakUsed);
        Assert.Equal(10, mcpQuota.PeakLimit);
        Assert.Equal(100.0, mcpQuota.PeakPercentage);
        Assert.True(mcpQuota.IsSaturated);

        Assert.Contains(profile.Quotas.Usage, u => u.Channel == "mcp" && u.PeakValue == 10);
        Assert.Contains(profile.Quotas.Channels, c => c.Channel == "mcp" && c.Count == 1);
        Assert.Contains(profile.Quotas.RequestSources, s => s.Name == "MCP_Agent" && s.Count == 1);
        Assert.Contains(profile.Insights, i => i.Category == "quota" && i.Severity == "opportunity");
        Assert.Contains(profile.Insights, i => i.Category == "auth" && i.Count == 1);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByEmailFragment_RedactsSensitiveLicenseData()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: null,
            email: null,
            emailFragment: "fra",
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        var body = JsonSerializer.Serialize(profile, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("franck@example.com", body, StringComparison.Ordinal);
        Assert.Contains("fr***@example.com", body, StringComparison.Ordinal);
        Assert.DoesNotContain(FullLicenseKey, body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BBBB", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CCCC", body, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(profile.SelectedCandidate);
        Assert.NotNull(profile.MachineProfile);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByLicenseFragment_AllowsCompactFragmentWithoutReturningFullKey()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: null,
            email: null,
            emailFragment: null,
            licenseFragment: "AAAABB",
            clientIp: null,
            days: 7,
            take: 10);

        Assert.Single(profile.Candidates);
        Assert.Equal("AAAA****DDDD", profile.Candidates[0].LicenseKeyRedacted);

        var body = JsonSerializer.Serialize(profile, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.DoesNotContain(FullLicenseKey, body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByHardwareIdPartial_ReturnsSingleCandidateProfile()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "FD14A8",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        Assert.False(profile.IsAmbiguous);
        Assert.Equal(1, profile.CandidateCount);
        Assert.True(profile.Query.HasHardwareId);
        Assert.True(profile.Query.HardwareIdPartialLookupEnabled);
        Assert.Equal(6, profile.Query.HardwareIdLength);
        Assert.NotNull(profile.SelectedCandidate);
        Assert.Equal("769C9325FD14A8AD", profile.SelectedCandidate.HardwareId);
        Assert.Contains("hardware_fragment", profile.SelectedCandidate.MatchType);
        Assert.NotNull(profile.MachineProfile);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_BySixCharHexHardwareIdPartial_ReturnsTelemetryOnlyCandidate()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "D80358",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 30,
            take: 10);

        Assert.False(profile.IsAmbiguous);
        Assert.Equal(1, profile.CandidateCount);
        Assert.True(profile.Query.HardwareIdPartialLookupEnabled);
        Assert.Equal(6, profile.Query.HardwareIdLength);
        Assert.NotNull(profile.SelectedCandidate);
        Assert.Equal("D803580B5152BF70", profile.SelectedCandidate.HardwareId);
        Assert.Equal("telemetry_hardware_fragment", profile.SelectedCandidate.MatchType);
        Assert.NotNull(profile.MachineProfile);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByFormattedHexHardwareIdPartial_NormalizesSeparators()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "d803-58",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 30,
            take: 10);

        Assert.False(profile.IsAmbiguous);
        Assert.Equal(1, profile.CandidateCount);
        Assert.True(profile.Query.HardwareIdPartialLookupEnabled);
        Assert.Equal(6, profile.Query.HardwareIdLength);
        Assert.NotNull(profile.SelectedCandidate);
        Assert.Equal("D803580B5152BF70", profile.SelectedCandidate.HardwareId);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByHardwareIdPartial_ReturnsBoundedAmbiguousCandidates()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "769C9325",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        Assert.True(profile.IsAmbiguous);
        Assert.Null(profile.SelectedCandidate);
        Assert.Null(profile.MachineProfile);
        Assert.Equal(2, profile.CandidateCount);
        Assert.All(profile.Candidates, c => Assert.Contains("769C9325", c.HardwareId, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_HardwareIdExactTakesPriorityOverPartialLookup()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "769C9325ZZZZ0000",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        Assert.False(profile.IsAmbiguous);
        Assert.NotNull(profile.SelectedCandidate);
        Assert.Equal("769C9325ZZZZ0000", profile.SelectedCandidate.HardwareId);
        Assert.Contains("hardware", profile.SelectedCandidate.MatchType);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ShortHardwareIdIsExactOnly()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
                productId,
                hardwareId: "12345",
                email: null,
                emailFragment: null,
                licenseFragment: null,
                clientIp: null,
                days: 7,
                take: 10);

        Assert.False(profile.Query.HardwareIdPartialLookupEnabled);
        Assert.Equal(0, profile.CandidateCount);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByRevokedLicense_ReturnsRevokedStatus()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "HW-REVOKED",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        Assert.NotNull(profile.SelectedCandidate);
        Assert.Equal("revoked", profile.SelectedCandidate.LicenseStatus);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_RejectsTooShortLicenseFragment()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            service.GetSupportProfileForProductIdAsync(
                productId,
                hardwareId: null,
                email: null,
                emailFragment: null,
                licenseFragment: "AAA",
                clientIp: null,
                days: 7,
                take: 10));

        Assert.Contains("licenseFragment", ex.Message);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByIpv6ClientIp_ReturnsTelemetryCandidates()
    {
        var productId = await SeedAsync();
        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: null,
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: "2001:db8::42",
            days: 7,
            take: 10);

        Assert.Single(profile.Candidates);
        Assert.Equal("telemetry_client_ip", profile.Candidates[0].MatchType);
        Assert.Equal("HW-A", profile.Candidates[0].HardwareId);
        Assert.Contains(profile.Candidates[0].ClientIps, ip => ip.Name == "2001:db8::42" && ip.Count == 3);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_ByEmailUsesActiveSeatInsteadOfLegacyHardwareId()
    {
        var productId = await SeedAsync();
        await using (var db = new LicenseDbContext(_dbOptions))
        {
            var typeId = await db.LicenseTypes.Where(t => t.ProductId == productId).Select(t => t.Id).FirstAsync();
            db.Licenses.Add(new License
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                LicenseTypeId = typeId,
                LicenseKey = "LEGA-CYHW-CCCC-DDDD",
                CustomerName = "Legacy Phantom",
                CustomerEmail = "legacyphantom@example.com",
                HardwareId = "HW-LEGACY-PHANTOM",
                ActivationDate = DateTime.UtcNow.AddDays(-3),
                IsActive = true,
                MaxSeats = 1,
                Seats =
                {
                    new LicenseSeat
                    {
                        HardwareId = "HW-ACTIVE-TRUTH",
                        FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
                        LastCheckInAt = DateTime.UtcNow.AddHours(-1),
                        IsActive = true
                    }
                }
            });
            await db.SaveChangesAsync();
        }

        var service = CreateService();

        var byEmail = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: null,
            email: "legacyphantom@example.com",
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        var candidate = Assert.Single(byEmail.Candidates);
        Assert.Equal("HW-ACTIVE-TRUTH", candidate.HardwareId);
        Assert.DoesNotContain("hardware", candidate.MatchType);

        var byLegacyHardware = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "HW-LEGACY-PHANTOM",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        Assert.Equal(0, byLegacyHardware.CandidateCount);
    }

    [Fact]
    public async Task GetSupportProfileForProductIdAsync_FallsBackToLegacyHardwareIdWhenNoSeatHistoryExists()
    {
        var productId = await SeedAsync();
        await using (var db = new LicenseDbContext(_dbOptions))
        {
            var typeId = await db.LicenseTypes.Where(t => t.ProductId == productId).Select(t => t.Id).FirstAsync();
            db.Licenses.Add(new License
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                LicenseTypeId = typeId,
                LicenseKey = "ONLY-LEGA-CCCC-DDDD",
                CustomerName = "Legacy Only",
                CustomerEmail = "legacyonly@example.com",
                HardwareId = "HW-LEGACY-ONLY",
                ActivationDate = DateTime.UtcNow.AddDays(-3),
                IsActive = true,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var service = CreateService();

        var profile = await service.GetSupportProfileForProductIdAsync(
            productId,
            hardwareId: "HW-LEGACY-ONLY",
            email: null,
            emailFragment: null,
            licenseFragment: null,
            clientIp: null,
            days: 7,
            take: 10);

        var candidate = Assert.Single(profile.Candidates);
        Assert.Equal("HW-LEGACY-ONLY", candidate.HardwareId);
        Assert.Contains("hardware", candidate.MatchType);
    }

    private TelemetrySupportProfileAnalyticsService CreateService()
    {
        return new TelemetrySupportProfileAnalyticsService(
            _dbFactoryMock.Object,
            _cache,
            new TelemetryMachineProfileAnalyticsService(_dbFactoryMock.Object, _cache));
    }

    private async Task<Guid> SeedAsync()
    {
        var productId = Guid.NewGuid();
        var otherProductId = Guid.NewGuid();
        var proTypeId = Guid.NewGuid();
        var trialTypeId = Guid.NewGuid();

        await using var db = new LicenseDbContext(_dbOptions);
        db.Products.AddRange(
            new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "k",
                PublicKeyXml = "k",
                ApiSecret = "secret"
            },
            new Product
            {
                Id = otherProductId,
                Name = "Other",
                PrivateKeyXml = "k",
                PublicKeyXml = "k",
                ApiSecret = "other"
            });
        db.LicenseTypes.AddRange(
            new LicenseType
            {
                Id = proTypeId,
                ProductId = productId,
                Name = "TIA Connect Pro",
                Slug = "TIA-CONNECT-PRO",
                DefaultDurationDays = 365
            },
            new LicenseType
            {
                Id = trialTypeId,
                ProductId = productId,
                Name = "TIA Connect Trial",
                Slug = "TIA-CONNECT-TRIAL",
                DefaultDurationDays = 30
            });

        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = proTypeId,
            LicenseKey = FullLicenseKey,
            CustomerName = "Franck",
            CustomerEmail = "franck@example.com",
            HardwareId = "HW-A",
            ActivationDate = DateTime.UtcNow.AddDays(-2),
            ValidityDays = 365,
            IsActive = true,
            MaxSeats = 2,
            Seats =
            {
                new LicenseSeat
                {
                    HardwareId = "HW-A",
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
                    LastCheckInAt = DateTime.UtcNow.AddHours(-1),
                    AppVersion = "2.1.900"
                }
            }
        });

        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = trialTypeId,
            LicenseKey = "REVO-KED1-CCCC-DDDD",
            CustomerName = "Revoked Customer",
            CustomerEmail = "revoked@example.com",
            HardwareId = "HW-REVOKED",
            ActivationDate = DateTime.UtcNow.AddDays(-3),
            ExpirationDate = DateTime.UtcNow.AddDays(10),
            IsActive = false,
            RevokedAt = DateTime.UtcNow.AddDays(-1),
            RevocationReason = "manual",
            MaxSeats = 1,
            Seats =
            {
                new LicenseSeat
                {
                    HardwareId = "HW-REVOKED",
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-3),
                    LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                    AppVersion = "2.1.900",
                    IsActive = false
                }
            }
        });

        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = trialTypeId,
            LicenseKey = "PART-IAL1-CCCC-DDDD",
            CustomerName = "Partial One",
            CustomerEmail = "partial1@example.com",
            HardwareId = "769C9325FD14A8AD",
            ActivationDate = DateTime.UtcNow.AddDays(-1),
            IsActive = true,
            MaxSeats = 1,
            Seats =
            {
                new LicenseSeat
                {
                    HardwareId = "769C9325FD14A8AD",
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                    LastCheckInAt = DateTime.UtcNow.AddHours(-1),
                    AppVersion = "2.1.900"
                }
            }
        });

        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = trialTypeId,
            LicenseKey = "PART-IAL2-CCCC-DDDD",
            CustomerName = "Partial Two",
            CustomerEmail = "partial2@example.com",
            HardwareId = "769C9325ZZZZ0000",
            ActivationDate = DateTime.UtcNow.AddDays(-1),
            IsActive = true,
            MaxSeats = 1,
            Seats =
            {
                new LicenseSeat
                {
                    HardwareId = "769C9325ZZZZ0000",
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                    LastCheckInAt = DateTime.UtcNow.AddHours(-1),
                    AppVersion = "2.1.900"
                }
            }
        });

        AddEvent(db, productId, "HW-A", "Startup_AppStarted", "2.1.900",
            """{"LicenseKey":"SECRET","Token":"hidden","OverallStatus":"Pass","LicenseEdition":"Professional","RequestSource":"API_Direct","Quota_Api_Daily":"9/10","Usage_Api":"9"}""",
            DateTime.UtcNow.AddHours(-2));
        AddEvent(db, productId, "HW-A", "Mcp_ToolCall", "2.1.900",
            """{"Tool":"list_blocks","RequestSource":"MCP_Agent","Quota_Mcp_Daily":"10/10","Usage_Mcp":"10"}""",
            DateTime.UtcNow.AddHours(-1));
        AddEvent(db, productId, "HW-A", "API_AuthFailed", "2.1.900",
            """{"Reason":"InvalidKey","RequestSource":"API_Direct","Quota_Copilot_Daily":"45/50","Usage_Copilot":"45"}""",
            DateTime.UtcNow.AddMinutes(-30));
        AddEvent(db, otherProductId, "HW-A", "OtherProduct_Event", "1.0",
            """{"Safe":"Value"}""",
            DateTime.UtcNow);
        AddEvent(db, productId, "769C9325FD14A8AD", "Mcp_ToolCall", "2.1.900",
            """{"Tool":"get_project_status"}""",
            DateTime.UtcNow.AddMinutes(-20),
            "203.0.113.10");
        AddEvent(db, productId, "769C9325ZZZZ0000", "Startup_AppStarted", "2.1.900",
            """{"OverallStatus":"Pass"}""",
            DateTime.UtcNow.AddMinutes(-10),
            "203.0.113.11");
        AddEvent(db, productId, "D803580B5152BF70", "Startup_AppStarted", "2.1.997",
            """{"OverallStatus":"Pass"}""",
            DateTime.UtcNow.AddMinutes(-5),
            "203.0.113.12");

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
        DateTime timestamp,
        string clientIp = "2001:db8::42")
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
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
