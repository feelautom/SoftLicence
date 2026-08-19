using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ActivationSecurityRegressionTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly Mock<NotificationService> _notifierMock;
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public ActivationSecurityRegressionTests(WebApplicationFactory<Program> factory)
    {
        _notifierMock = new Mock<NotificationService>(
            Mock.Of<IDbContextFactory<LicenseDbContext>>(),
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<NotificationService>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase(_dbName));
                services.AddSingleton(_notifierMock.Object);
            });
        });
    }

    [Fact]
    public async Task Activate_WithRevokedPaidLicenseAndOutdatedBan_DoesNotAutoUnban()
    {
        var seeded = await SeedPaidLicenseAsync(isActive: false, revokedAt: DateTime.UtcNow.AddMinutes(-5));
        await SeedBanAsync(seeded.ProductId, "B000000000000001", BannedHardwareId.Categories.OutdatedVersion);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = seeded.LicenseKey,
            HardwareId = "B000000000000001",
            AppName = "SecureApp"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertBanActiveAsync("B000000000000001");
        _notifierMock.Verify(
            n => n.Notify(
                It.IsAny<string>(),
                It.Is<string>(title => title.Contains("AUTO-UNBAN")),
                It.IsAny<string>(),
                It.IsAny<object>()),
            Times.Never);
    }

    [Fact]
    public async Task Activate_WithValidPaidLicenseAndOutdatedBan_AutoUnbansWithVersionLabel()
    {
        var seeded = await SeedPaidLicenseAsync(isActive: true, revokedAt: null);
        await SeedBanAsync(seeded.ProductId, "B000000000000002", BannedHardwareId.Categories.OutdatedVersion);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = seeded.LicenseKey,
            HardwareId = "B000000000000002",
            AppName = "SecureApp",
            CustomerEmail = "paid@example.com"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await AssertBanInactiveAsync("B000000000000002");
        _notifierMock.Verify(
            n => n.Notify(
                NotificationService.Triggers.SecurityIpBanned,
                "AUTO-UNBAN VERSION OBSOLETE",
                It.Is<string>(message => message.Contains("outdated_version")),
                It.IsAny<object>()),
            Times.Once);
    }

    [Fact]
    public async Task CheckStatus_WithOutdatedVersionBan_ReturnsUpdateRequiredNotRevoked()
    {
        var seeded = await SeedPaidLicenseAsync(isActive: true, revokedAt: null);
        await SeedBanAsync(seeded.ProductId, "B000000000000003", BannedHardwareId.Categories.OutdatedVersion);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = seeded.LicenseKey,
            HardwareId = "B000000000000003",
            AppName = "SecureApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("UPDATE_REQUIRED", json.RootElement.GetProperty("status").GetString());
        Assert.Equal("Update required by server", json.RootElement.GetProperty("errorMessage").GetString());
    }

    [Fact]
    public async Task HwidReuseAlert_WhenDistinctEmailsShareHardwareId_SendsRedactedAlert()
    {
        var productId = Guid.NewGuid();
        var currentLicenseId = Guid.NewGuid();
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(options));

        await using (var db = new LicenseDbContext(options))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "SecureApp",
                PrivateKeyXml = "k",
                PublicKeyXml = "k",
                ApiSecret = "secret"
            });
            db.Licenses.AddRange(
                new License
                {
                    Id = Guid.NewGuid(),
                    ProductId = productId,
                    LicenseTypeId = Guid.NewGuid(),
                    LicenseKey = "AAAA-BBBB-CCCC-DDDD",
                    CustomerName = "Old User",
                    CustomerEmail = "old@example.com",
                    HardwareId = "HW-REUSE",
                    ActivationDate = DateTime.UtcNow.AddDays(-2),
                    IsActive = false,
                    RevokedAt = DateTime.UtcNow.AddDays(-1)
                },
                new License
                {
                    Id = currentLicenseId,
                    ProductId = productId,
                    LicenseTypeId = Guid.NewGuid(),
                    LicenseKey = "EEEE-FFFF-GGGG-HHHH",
                    CustomerName = "New User",
                    CustomerEmail = "new@example.com",
                    HardwareId = "HW-REUSE",
                    ActivationDate = DateTime.UtcNow,
                    IsActive = true
                });
            await db.SaveChangesAsync();
        }

        var service = new HwidReuseAlertService(
            dbFactoryMock.Object,
            _notifierMock.Object,
            new SecurityCaseContextService(dbFactoryMock.Object),
            Mock.Of<ILogger<HwidReuseAlertService>>());

        await service.CheckAndNotifyAsync(productId, "HW-REUSE", currentLicenseId);

        _notifierMock.Verify(
            n => n.Notify(
                NotificationService.Triggers.SecurityHwidReuseDetected,
                "HWID REUSE CRITICAL",
                It.Is<string>(message =>
                    message.Contains("HW-REUSE")
                    && message.Contains("SecurityCaseId: sec_security_hwidreusedetected_")
                    && message.Contains("ol***@example.com")
                    && message.Contains("ne***@example.com")
                    && !message.Contains("old@example.com")
                    && !message.Contains("new@example.com")
                    && !message.Contains("AAAA-BBBB-CCCC-DDDD")),
                It.IsAny<object>()),
            Times.Once);
    }

    [Fact]
    public async Task Activate_WithHistoricalFreemiumOnSameHardware_RejectsNewFreemiumLicense()
    {
        var seeded = await SeedFreemiumReuseScenarioAsync(newLicenseIsFreemium: true);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = seeded.NewLicenseKey,
            HardwareId = seeded.HardwareId,
            AppName = "SecureApp",
            CustomerEmail = "new@example.com"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Freemium", body, StringComparison.OrdinalIgnoreCase);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var newLicense = await db.Licenses
            .Include(l => l.Seats)
            .SingleAsync(l => l.LicenseKey == seeded.NewLicenseKey);
        Assert.DoesNotContain(newLicense.Seats, s => s.HardwareId == seeded.HardwareId);
    }

    [Fact]
    public async Task Activate_WithHistoricalFreemiumOnSameHardware_AllowsPaidLicense()
    {
        var seeded = await SeedFreemiumReuseScenarioAsync(newLicenseIsFreemium: false);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = seeded.NewLicenseKey,
            HardwareId = seeded.HardwareId,
            AppName = "SecureApp",
            CustomerEmail = "new@example.com"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var newLicense = await db.Licenses
            .Include(l => l.Seats)
            .SingleAsync(l => l.LicenseKey == seeded.NewLicenseKey);
        Assert.Contains(newLicense.Seats, s => s.HardwareId == seeded.HardwareId && s.IsActive);
    }

    [Fact]
    public async Task Activate_WithHistoricalNonTiaFreemiumOnSameHardware_AllowsNewNonTiaFreemiumLicense()
    {
        var seeded = await SeedFreemiumReuseScenarioAsync(newLicenseIsFreemium: true, isTiaConnect: false);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = seeded.NewLicenseKey,
            HardwareId = seeded.HardwareId,
            AppName = seeded.AppName,
            CustomerEmail = "new@example.com"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var newLicense = await db.Licenses
            .Include(l => l.Seats)
            .SingleAsync(l => l.LicenseKey == seeded.NewLicenseKey);
        Assert.Contains(newLicense.Seats, s => s.HardwareId == seeded.HardwareId && s.IsActive);
    }

    [Fact]
    public async Task Activate_WithConfiguredSingleUseTypeOnSameHardware_RejectsNewLicense()
    {
        var seeded = await SeedFreemiumReuseScenarioAsync(
            newLicenseIsFreemium: true,
            isTiaConnect: false,
            enforceSingleUsePerHardwareId: true);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = seeded.NewLicenseKey,
            HardwareId = seeded.HardwareId,
            AppName = seeded.AppName,
            CustomerEmail = "new@example.com"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var newLicense = await db.Licenses
            .Include(l => l.Seats)
            .SingleAsync(l => l.LicenseKey == seeded.NewLicenseKey);
        Assert.DoesNotContain(newLicense.Seats, s => s.HardwareId == seeded.HardwareId);
    }

    [Fact]
    public async Task CheckStatus_WithHistoricalFreemiumOnSameHardware_ReturnsFreemiumConsumed()
    {
        var seeded = await SeedFreemiumReuseScenarioAsync(newLicenseIsFreemium: true);

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = seeded.NewLicenseKey,
            HardwareId = seeded.HardwareId,
            AppName = "SecureApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("FREEMIUM_HWID_ALREADY_CONSUMED", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(
            "Freemium access has already been used on this machine.",
            json.RootElement.GetProperty("errorMessage").GetString());
        Assert.True(json.RootElement.TryGetProperty("licenseFile", out var licenseFile));
        Assert.Equal(JsonValueKind.Null, licenseFile.ValueKind);
    }

    private async Task<(Guid ProductId, string LicenseKey)> SeedPaidLicenseAsync(bool isActive, DateTime? revokedAt)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var keys = LicenseService.GenerateKeys();
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = "SecureApp",
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
            PublicKeyXml = keys.PublicKey,
            ApiSecret = "secret"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            Name = "Pro",
            Slug = "PRO",
            IsFree = false,
            DefaultDurationDays = 365
        };
        var license = new License
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            LicenseTypeId = type.Id,
            LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant(),
            CustomerName = "Paid User",
            CustomerEmail = "paid@example.com",
            IsActive = isActive,
            RevokedAt = revokedAt,
            RevocationReason = revokedAt == null ? null : "test",
            MaxSeats = 1,
            AllowedVersions = "*"
        };

        db.Products.Add(product);
        db.LicenseTypes.Add(type);
        db.Licenses.Add(license);
        await db.SaveChangesAsync();
        _notifierMock.Invocations.Clear();
        return (product.Id, license.LicenseKey);
    }

    private async Task<(Guid ProductId, string NewLicenseKey, string HardwareId, string AppName)> SeedFreemiumReuseScenarioAsync(
        bool newLicenseIsFreemium,
        bool isTiaConnect = true,
        bool? enforceSingleUsePerHardwareId = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var keys = LicenseService.GenerateKeys();
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = isTiaConnect ? "SecureApp" : "OtherProduct",
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
            PublicKeyXml = keys.PublicKey,
            ApiSecret = "secret"
        };
        var freemiumType = new LicenseType
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            Name = isTiaConnect ? "TIA Connect Freemium" : "Other Product Freemium",
            Slug = isTiaConnect ? "TIA-CONNECT-FREEMIUM" : "OTHER-FREEMIUM",
            IsFree = true,
            EnforceSingleUsePerHardwareId = enforceSingleUsePerHardwareId ?? isTiaConnect,
            DefaultDurationDays = 7
        };
        var paidType = new LicenseType
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            Name = isTiaConnect ? "TIA Connect Pro" : "Other Product Pro",
            Slug = isTiaConnect ? "TIA-CONNECT-PRO" : "OTHER-PRO",
            IsFree = false,
            DefaultDurationDays = 365
        };
        const string hardwareId = "2FB4D3F6265CB5AF";
        var oldLicense = new License
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            LicenseTypeId = freemiumType.Id,
            LicenseKey = "OLD-FREEMIUM-REVOKED",
            CustomerName = "Old User",
            CustomerEmail = "old@example.com",
            HardwareId = null,
            ActivationDate = DateTime.UtcNow.AddDays(-30),
            CreationDate = DateTime.UtcNow.AddDays(-30),
            ExpirationDate = DateTime.UtcNow.AddDays(-23),
            IsActive = false,
            RevokedAt = DateTime.UtcNow.AddDays(-1),
            RevocationReason = "test",
            MaxSeats = 1,
            AllowedVersions = "*"
        };
        var newLicense = new License
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            LicenseTypeId = newLicenseIsFreemium ? freemiumType.Id : paidType.Id,
            LicenseKey = newLicenseIsFreemium ? "NEW-FREEMIUM-ACTIVE" : "NEW-PAID-ACTIVE",
            CustomerName = "New User",
            CustomerEmail = "new@example.com",
            IsActive = true,
            MaxSeats = 1,
            AllowedVersions = "*"
        };

        db.Products.Add(product);
        db.LicenseTypes.AddRange(freemiumType, paidType);
        db.Licenses.AddRange(oldLicense, newLicense);
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = oldLicense.Id,
            HardwareId = hardwareId,
            FirstActivatedAt = DateTime.UtcNow.AddDays(-30),
            LastCheckInAt = DateTime.UtcNow.AddDays(-20),
            IsActive = false,
            UnlinkedAt = DateTime.UtcNow.AddDays(-1)
        });

        await db.SaveChangesAsync();
        _notifierMock.Invocations.Clear();
        return (product.Id, newLicense.LicenseKey, hardwareId, product.Name);
    }

    private async Task SeedBanAsync(Guid productId, string hardwareId, string category)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        db.BannedHardwareIds.Add(new BannedHardwareId
        {
            ProductId = productId,
            HardwareId = hardwareId,
            Reason = "Auto-ban: test",
            BanCategory = category,
            IsActive = true
        });
        await db.SaveChangesAsync();
    }

    private async Task AssertBanActiveAsync(string hardwareId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var ban = await db.BannedHardwareIds.SingleAsync(b => b.HardwareId == hardwareId);
        Assert.True(ban.IsActive);
    }

    private async Task AssertBanInactiveAsync(string hardwareId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var ban = await db.BannedHardwareIds.SingleAsync(b => b.HardwareId == hardwareId);
        Assert.False(ban.IsActive);
    }
}
