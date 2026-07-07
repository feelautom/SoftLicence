using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RecentLicenseOnboardingMetricsAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public RecentLicenseOnboardingMetricsAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetMetricsForProductIdAsync_ReturnsRecentPaidOnboardingMetricsWithStrictRedaction()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var proTypeId = Guid.NewGuid();
        var freeTypeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndTypes(db, productId, proTypeId, freeTypeId);

            AddLicense(db, productId, proTypeId, "PRO-AAAA-BBBB-CCCC", "copilot@example.test", "HW-COPILOT-123456", now.AddHours(-2), now.AddDays(28));
            AddLicense(db, productId, proTypeId, "PRO-DDDD-EEEE-FFFF", "mcp@example.test", "HW-MCP-987654", now.AddHours(-1), now.AddDays(29));
            AddLicense(db, productId, freeTypeId, "FREE-AAAA-BBBB", "free@example.test", "HW-FREE-111111", now.AddMinutes(-30), now.AddDays(7));

            AddEvent(db, productId, "HW-COPILOT-123456", "Wizard_Opened", now.AddHours(-2).AddMinutes(1), "{}");
            AddEvent(db, productId, "HW-COPILOT-123456", "Wizard_Completed", now.AddHours(-2).AddMinutes(5), "{}");
            AddEvent(db, productId, "HW-COPILOT-123456", "Wizard_McpToolSelected", now.AddHours(-2).AddMinutes(6), "{}");
            AddEvent(db, productId, "HW-COPILOT-123456", "Copilot_Chat", now.AddHours(-2).AddMinutes(8), "{}");
            AddEvent(db, productId, "HW-COPILOT-123456", "Copilot_ToolCall", now.AddHours(-2).AddMinutes(9), """{"RequestSource":"API_Direct"}""");
            AddEvent(db, productId, "HW-COPILOT-123456", "Copilot_Chat_Success", now.AddHours(-2).AddMinutes(10), "{}");
            AddEvent(db, productId, "HW-COPILOT-123456", "Block_Export", now.AddHours(-2).AddMinutes(12), "{}");

            AddEvent(db, productId, "HW-MCP-987654", "Mcp_ToolCall", now.AddHours(-1).AddMinutes(20), "{}");
            AddEvent(db, productId, "HW-MCP-987654", "Compile_Success", now.AddHours(-1).AddMinutes(70), "{}");
            AddEvent(db, productId, "HW-MCP-987654", "API_AuthFailed", now.AddHours(-1).AddMinutes(80), "{}");
            AddEvent(db, productId, "HW-FREE-111111", "Block_Export", now.AddMinutes(-20), "{}");

            await db.SaveChangesAsync();
        }

        var service = new RecentLicenseOnboardingMetricsAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetMetricsForProductIdAsync(productId, take: 10, licenseType: "paid", status: "active");

        Assert.Equal("paid", result.LicenseTypeFilter);
        Assert.Equal(2, result.TotalLicensesMatched);
        Assert.Equal(2, result.LicensesReturned);
        Assert.Equal(2, result.Summary.WithTelemetry);
        Assert.Equal(2, result.Summary.WithProductiveEvent);
        Assert.DoesNotContain(result.Licenses, l => l.LicenseTypeSlug == "TIA-CONNECT-FREEMIUM");

        var mcp = result.Licenses[0];
        Assert.Equal("mc***@example.test", mcp.CustomerEmailRedacted);
        Assert.Equal("mcp_direct", mcp.DetectedPath);
        Assert.Equal("slow", mcp.OnboardingSegment);
        Assert.Equal(70, mcp.MinutesActivationToProductiveEvent);
        Assert.Contains("auth_failed", mcp.NegativeFlags);

        var copilot = result.Licenses[1];
        Assert.Equal("co***@example.test", copilot.CustomerEmailRedacted);
        Assert.Equal("copilot_via_mcp", copilot.DetectedPath);
        Assert.Equal("fast", copilot.OnboardingSegment);
        Assert.Equal(12, copilot.MinutesActivationToProductiveEvent);
        Assert.Equal(5, copilot.MinutesActivationToWizardCompleted);
        Assert.Equal(6, copilot.MinutesActivationToMcpSelected);
        Assert.Equal(8, copilot.MinutesActivationToCopilotChat);
        Assert.Equal(10, copilot.MinutesActivationToCopilotChatSuccess);
        Assert.Equal(16, copilot.HardwareIdHash.Length);

        var json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("PRO-AAAA-BBBB-CCCC", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRO-DDDD-EEEE-FFFF", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HW-COPILOT-123456", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HW-MCP-987654", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("copilot@example.test", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("mcp@example.test", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetMetricsForProductIdAsync_UsesExplicitFallbackSourcesAndSegmentsSetupOnlyAndStuck()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var proTypeId = Guid.NewGuid();
        var freeTypeId = Guid.NewGuid();
        var seatLicenseId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndTypes(db, productId, proTypeId, freeTypeId);

            db.Licenses.Add(new License
            {
                Id = seatLicenseId,
                ProductId = productId,
                LicenseTypeId = proTypeId,
                LicenseKey = "PRO-SEAT-ONLY",
                CustomerEmail = "seat@example.test",
                CustomerName = "Seat Customer",
                CreationDate = now.AddDays(-3),
                IsActive = true,
                Seats =
                {
                    new LicenseSeat
                    {
                        LicenseId = seatLicenseId,
                        HardwareId = "HW-SEAT-222222",
                        FirstActivatedAt = now.AddMinutes(-45),
                        LastCheckInAt = now.AddMinutes(-5),
                        IsActive = true
                    }
                }
            });

            db.Licenses.Add(new License
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                LicenseTypeId = proTypeId,
                LicenseKey = "PRO-CREATED-ONLY",
                CustomerEmail = "created@example.test",
                CustomerName = "Created Customer",
                CreationDate = now.AddMinutes(-15),
                IsActive = true
            });

            AddEvent(db, productId, "HW-SEAT-222222", "Wizard_Opened", now.AddMinutes(-40), "{}");
            AddEvent(db, productId, "HW-SEAT-222222", "Wizard_Completed", now.AddMinutes(-35), "{}");

            await db.SaveChangesAsync();
        }

        var service = new RecentLicenseOnboardingMetricsAnalyticsService(_dbFactoryMock.Object, _cache);

        var result = await service.GetMetricsForProductIdAsync(productId, take: 10, licenseType: "all", status: "all");

        Assert.Equal(2, result.LicensesReturned);
        var createdOnly = result.Licenses[0];
        Assert.Equal("license_creation", createdOnly.ActivationDateSource);
        Assert.Equal("not_activated", createdOnly.LicenseStatus);
        Assert.Equal("stuck", createdOnly.OnboardingSegment);

        var seatOnly = result.Licenses[1];
        Assert.Equal("seat_first_activation", seatOnly.ActivationDateSource);
        Assert.Equal("active", seatOnly.LicenseStatus);
        Assert.Equal("setup_only", seatOnly.OnboardingSegment);
        Assert.Equal("ui_only", seatOnly.DetectedPath);
        Assert.Equal(10, seatOnly.MinutesActivationToWizardCompleted);
    }

    private static void SeedProductAndTypes(LicenseDbContext db, Guid productId, Guid proTypeId, Guid freeTypeId)
    {
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "T-IA Connect",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = "secret"
        });

        db.LicenseTypes.AddRange(
            new LicenseType
            {
                Id = proTypeId,
                ProductId = productId,
                Name = "TIA Connect Pro",
                Slug = "TIA-CONNECT-PRO",
                IsFree = false
            },
            new LicenseType
            {
                Id = freeTypeId,
                ProductId = productId,
                Name = "TIA Connect Freemium",
                Slug = "TIA-CONNECT-FREEMIUM",
                IsFree = true
            });
    }

    private static void AddLicense(
        LicenseDbContext db,
        Guid productId,
        Guid typeId,
        string licenseKey,
        string email,
        string hardwareId,
        DateTime activationDate,
        DateTime expirationDate)
    {
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = licenseKey,
            CustomerEmail = email,
            CustomerName = email,
            HardwareId = hardwareId,
            ActivationDate = activationDate,
            CreationDate = activationDate.AddMinutes(-10),
            ExpirationDate = expirationDate,
            IsActive = true
        });
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        DateTime timestamp,
        string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = "2.2.501",
            Type = TelemetryType.Event,
            EventName = eventName,
            Timestamp = timestamp,
            EventData = new TelemetryEvent
            {
                PropertiesJson = propertiesJson
            }
        });
    }
}
