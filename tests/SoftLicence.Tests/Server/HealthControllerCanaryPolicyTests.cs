using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class HealthControllerCanaryPolicyTests
{
    [Fact]
    public async Task Ping_WithCriticalCoreTamperReleaseContext_KeepsPermanentBan()
    {
        var dbName = Guid.NewGuid().ToString("N");
        var productId = Guid.NewGuid();
        await SeedProductAsync(dbName, productId);
        var controller = BuildController(dbName);

        await controller.Ping(new CanaryPingRequest
        {
            HardwareId = "HW-RELEASE-TAMPER",
            Trigger = "IntegrityCheck_CoreDllTampered",
            Severity = 3,
            AppVersion = "2.2.216",
            BuildConfiguration = "Release",
            BaseDirectory = @"C:\Program Files\T-IA Connect",
            ProcessPath = @"C:\Program Files\T-IA Connect\TiaPortalApi.App.exe",
            AssemblyLocation = @"C:\Program Files\T-IA Connect\TiaPortalApi.App.exe"
        });

        await using var db = CreateDb(dbName);
        var ban = await db.BannedHardwareIds.SingleAsync(b => b.HardwareId == "HW-RELEASE-TAMPER");
        Assert.True(ban.IsActive);
        Assert.Null(ban.ExpiresAt);
        Assert.Equal(productId, ban.ProductId);

        var alert = await db.CanaryAlerts.SingleAsync(a => a.HardwareId == "HW-RELEASE-TAMPER");
        Assert.Equal("permanent_ban", alert.ServerAction);
        Assert.Equal("Release", alert.BuildConfiguration);
    }

    [Fact]
    public async Task Ping_WithSpoofedLocalDevContextButNoServerTrust_KeepsPermanentBan()
    {
        var dbName = Guid.NewGuid().ToString("N");
        await SeedProductAsync(dbName, Guid.NewGuid());
        var controller = BuildController(dbName);

        await controller.Ping(new CanaryPingRequest
        {
            HardwareId = "HW-SPOOFED-DEV",
            Trigger = "IntegrityCheck_CoreDllTampered",
            Severity = 3,
            AppVersion = "2.2.216",
            BuildConfiguration = "Debug",
            IsLocalDevBuild = true,
            LocalDevBuildReason = "Spoofed local dev marker from untrusted client",
            BaseDirectory = @"D:\Works\TiaMcpServer\TiaPortalApi\Build\Debug\net48",
            ProcessPath = @"D:\Works\TiaMcpServer\TiaPortalApi\Build\Debug\net48\TiaPortalApi.App.exe",
            AssemblyLocation = @"D:\Works\TiaMcpServer\TiaPortalApi\Build\Debug\net48\TiaPortalApi.App.exe"
        });

        await using var db = CreateDb(dbName);
        var ban = await db.BannedHardwareIds.SingleAsync(b => b.HardwareId == "HW-SPOOFED-DEV");
        Assert.True(ban.IsActive);
        Assert.Null(ban.ExpiresAt);

        var alert = await db.CanaryAlerts.SingleAsync(a => a.HardwareId == "HW-SPOOFED-DEV");
        Assert.Equal("permanent_ban", alert.ServerAction);
        Assert.True(alert.IsLocalDevBuild);
        Assert.Equal("Spoofed local dev marker from untrusted client", alert.LocalDevBuildReason);
    }

    [Fact]
    public async Task Ping_WithServerTrustedDevMachineAndLocalCoreTamper_QuarantinesWithoutCascade()
    {
        var dbName = Guid.NewGuid().ToString("N");
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        const string sourceHwid = "HW-TRUSTED-DEV";
        const string linkedSeatHwid = "HW-LINKED-SEAT";

        await using (var db = CreateDb(dbName))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret"
            });

            var licenseType = new LicenseType
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                Name = "Internal Dev",
                Slug = "INTERNAL-DEV"
            };
            db.LicenseTypes.Add(licenseType);
            db.Licenses.Add(new License
            {
                Id = licenseId,
                ProductId = productId,
                LicenseTypeId = licenseType.Id,
                LicenseKey = "DEV-LICENSE",
                CustomerName = "Dev User",
                CustomerEmail = "dev@EXAMPLE.COM",
                HardwareId = sourceHwid,
                IsActive = true,
                ExpirationDate = DateTime.UtcNow.AddDays(30),
                MaxSeats = 2
            });
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId,
                HardwareId = linkedSeatHwid,
                IsActive = true
            });
            db.SystemSettings.Add(new SystemSetting
            {
                Key = "TrustedDevCanaryHardwareIds",
                Value = sourceHwid
            });
            await db.SaveChangesAsync();
        }

        var controller = BuildController(dbName);

        await controller.Ping(new CanaryPingRequest
        {
            HardwareId = sourceHwid,
            Trigger = "IntegrityCheck_CoreDllTampered",
            Severity = 3,
            AppVersion = "2.2.216",
            BuildConfiguration = "Debug",
            BaseDirectory = @"D:\Works\TiaMcpServer\TiaPortalApi\Build\Debug\net48",
            ProcessPath = @"D:\Works\TiaMcpServer\TiaPortalApi\Build\Debug\net48\TiaPortalApi.App.exe",
            AssemblyLocation = @"D:\Works\TiaMcpServer\TiaPortalApi\Build\Debug\net48\TiaPortalApi.App.exe",
            FpExe = new string('a', 64),
            FpDll = new string('b', 64),
            FpCore = new string('c', 64)
        });

        await using var checkDb = CreateDb(dbName);
        var sourceBan = await checkDb.BannedHardwareIds.SingleAsync(b => b.HardwareId == sourceHwid);
        Assert.True(sourceBan.IsActive);
        Assert.NotNull(sourceBan.ExpiresAt);
        Assert.True(sourceBan.ExpiresAt > DateTime.UtcNow);
        Assert.Equal(BannedHardwareId.Categories.DevCanaryQuarantine, sourceBan.BanCategory);

        Assert.False(await checkDb.BannedHardwareIds.AnyAsync(b => b.HardwareId == linkedSeatHwid));

        var license = await checkDb.Licenses.SingleAsync(l => l.Id == licenseId);
        Assert.True(license.IsActive);
        Assert.Null(license.RevokedAt);

        var alert = await checkDb.CanaryAlerts.SingleAsync(a => a.HardwareId == sourceHwid);
        Assert.Equal("dev_quarantine", alert.ServerAction);
        Assert.Equal("Debug", alert.BuildConfiguration);
        Assert.Contains("FP_CORE", alert.BinaryFingerprintsJson);
        Assert.Contains(@"Build\Debug\net48", alert.BaseDirectory);
    }

    private static async Task SeedProductAsync(string dbName, Guid productId)
    {
        await using var db = CreateDb(dbName);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TIAConnect",
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret"
        });
        await db.SaveChangesAsync();
    }

    private static HealthController BuildController(string dbName)
    {
        var dbFactory = new TestDbContextFactory(dbName);
        var configuration = new ConfigurationBuilder().Build();
        var settings = new SettingsService(
            dbFactory,
            configuration,
            Mock.Of<ILogger<SettingsService>>());

        var notifier = new Mock<NotificationService>(
            dbFactory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        notifier.Setup(n => n.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));

        var security = new SecurityService(
            dbFactory,
            Mock.Of<ILogger<SecurityService>>(),
            notifier.Object,
            configuration);

        var email = new EmailService(
            Options.Create(new SmtpSettings { Host = "localhost" }),
            Mock.Of<ILogger<EmailService>>());

        var controller = new HealthController(
            dbFactory,
            Mock.Of<ILogger<HealthController>>(),
            security,
            settings,
            email);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
        controller.ControllerContext.HttpContext.Connection.RemoteIpAddress =
            System.Net.IPAddress.Parse("127.0.0.1");

        return controller;
    }

    private static LicenseDbContext CreateDb(string dbName)
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(dbName)
            .Options;
        return new LicenseDbContext(options);
    }

    private sealed class TestDbContextFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly string _dbName;

        public TestDbContextFactory(string dbName)
        {
            _dbName = dbName;
        }

        public LicenseDbContext CreateDbContext() => CreateDb(_dbName);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}
