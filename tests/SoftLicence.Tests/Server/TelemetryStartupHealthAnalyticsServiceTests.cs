using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryStartupHealthAnalyticsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public TelemetryStartupHealthAnalyticsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task GetStartupHealthForProductKeyAsync_AggregatesStartupDiagnostics()
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

            AddEvent(db, productId, "HW-A", "Startup_AppStarted",
                """{"OverallStatus":"Pass","PassCount":"8","WarningCount":"1","FailCount":"0","SelectedVersion":"V19","IsAdministrator":"true","IsVM":"false","IsSandbox":"false","WarnChecks":"WebView2Runtime","LicenseEdition":"Freemium","FP_CPU":"secret-cpu"}""");
            AddEvent(db, productId, "HW-B", "Startup_AppStarted",
                """{"OverallStatus":"Fail","PassCount":"5","WarningCount":"2","FailCount":"1","SelectedVersion":"V18","IsAdministrator":"false","IsVM":"true","IsSandbox":"true","FailedChecks":"TIAOpennessService,SiemensTIAOpenness","WarnChecks":"WebView2Runtime","LicenseTypeSlug":"PRO"}""");
            AddEvent(db, productId, "HW-B", "Mcp_ToolCall",
                """{"Tool":"list_blocks"}""");

            await db.SaveChangesAsync();
        }

        var service = new TelemetryStartupHealthAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetStartupHealthForProductKeyAsync("secret");

        Assert.NotNull(summary);
        Assert.Equal(2, summary.StartupEvents);
        Assert.Equal(2, summary.UniqueDevices);
        Assert.Equal(13, summary.CheckTotals.PassCount);
        Assert.Equal(3, summary.CheckTotals.WarningCount);
        Assert.Equal(1, summary.CheckTotals.FailCount);
        Assert.Equal(1, summary.Flags.AdminTrue);
        Assert.Equal(1, summary.Flags.AdminFalse);
        Assert.Equal(1, summary.Flags.VmTrue);
        Assert.Equal(1, summary.Flags.SandboxTrue);
        Assert.Equal(1, summary.Flags.FingerprintSamples);
        Assert.Contains(summary.OverallStatuses, s => s.Name == "Pass" && s.Count == 1);
        Assert.Contains(summary.OverallStatuses, s => s.Name == "Fail" && s.Count == 1);
        Assert.Contains(summary.SelectedTiaVersions, s => s.Name == "V19" && s.Count == 1);
        Assert.Contains(summary.LicenseEditions, s => s.Name == "Freemium" && s.Count == 1);
        Assert.Contains(summary.LicenseEditions, s => s.Name == "PRO" && s.Count == 1);
        Assert.Contains(summary.FailedChecks, s => s.Name == "TIAOpennessService" && s.Count == 1);
        Assert.Contains(summary.WarningChecks, s => s.Name == "WebView2Runtime" && s.Count == 2);
    }

    [Fact]
    public async Task GetStartupHealthForProductKeyAsync_RespectsProductIsolation()
    {
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.AddRange(
                new Product { Id = productA, Name = "AppA", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" },
                new Product { Id = productB, Name = "AppB", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" });

            AddEvent(db, productA, "HW-A", "Startup_AppStarted", """{"OverallStatus":"Pass"}""");
            AddEvent(db, productB, "HW-B", "Startup_AppStarted", """{"OverallStatus":"Fail"}""");
            await db.SaveChangesAsync();
        }

        var service = new TelemetryStartupHealthAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetStartupHealthForProductKeyAsync("secret-a");

        Assert.NotNull(summary);
        Assert.Equal(1, summary.StartupEvents);
        Assert.Single(summary.OverallStatuses);
        Assert.Equal("Pass", summary.OverallStatuses[0].Name);
    }

    [Fact]
    public async Task GetStartupHealthForProductKeyAsync_ReturnsNullForInvalidProductKey()
    {
        var service = new TelemetryStartupHealthAnalyticsService(_dbFactoryMock.Object, _cache);

        var summary = await service.GetStartupHealthForProductKeyAsync("missing");

        Assert.Null(summary);
    }

    private static void AddEvent(LicenseDbContext db, Guid productId, string hardwareId, string eventName, string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = DateTime.UtcNow,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = "2.1.857",
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent
            {
                PropertiesJson = propertiesJson
            }
        });
    }
}
