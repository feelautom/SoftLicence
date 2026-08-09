using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public class SecurityServiceTests
{
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly Mock<ILogger<SecurityService>> _loggerMock;
    private readonly Mock<NotificationService> _notifierMock;
    private readonly SecurityService _service;
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;

    public SecurityServiceTests()
    {
        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _loggerMock = new Mock<ILogger<SecurityService>>();
        
        var dbFactoryNotifierMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        var loggerNotifierMock = new Mock<ILogger<NotificationService>>();
        var httpFactoryMock = new Mock<System.Net.Http.IHttpClientFactory>();
        
        _notifierMock = new Mock<NotificationService>(
            dbFactoryNotifierMock.Object,
            loggerNotifierMock.Object,
            httpFactoryMock.Object);

        var configMock = new Mock<IConfiguration>();
        configMock.Setup(c => c["AdminSettings:AllowedIps"]).Returns("127.0.0.1,::1");

        _service = new SecurityService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _notifierMock.Object,
            configMock.Object);

        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        // Setup factory to always return a NEW instance of the SAME in-memory database
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(default))
            .Returns(() => Task.FromResult(new LicenseDbContext(_dbOptions)));
    }

    [Fact]
    public async Task ReportThreat_ShouldBanIp_WhenScoreReaches200()
    {
        // Arrange
        var ip = "1.2.3.4";

        // Act 1: Reach 100 points (Quarantine, but not banned yet)
        await _service.ReportThreatAsync(ip, 50, "Test 1");
        await _service.ReportThreatAsync(ip, 50, "Test 2");

        using (var db1 = new LicenseDbContext(_dbOptions))
        {
            var ban1 = await db1.BannedIps.FirstOrDefaultAsync(b => b.IpAddress == ip);
            Assert.Null(ban1); // Should NOT be banned at 100
        }

        // Act 2: Reach 200 points (Ban triggered)
        await _service.ReportThreatAsync(ip, 50, "Test 3");
        await _service.ReportThreatAsync(ip, 50, "Test 4");

        // Assert
        using var db2 = new LicenseDbContext(_dbOptions);
        var ban2 = await db2.BannedIps.FirstOrDefaultAsync(b => b.IpAddress == ip);
        Assert.NotNull(ban2);
        Assert.Equal("Test 4 (Score: 200)", ban2.Reason);
        _notifierMock.Verify(n => n.Notify(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
    }

    [Fact]
    public async Task IsBanned_ShouldReturnTrue_ForBannedIp()
    {
        // Arrange
        var ip = "8.8.8.8";
        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.BannedIps.Add(new BannedIp { IpAddress = ip, Reason = "Manual", BannedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddHours(1) });
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _service.IsBannedAsync(ip);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task BanIpAsync_WhenExistingBanIsInactive_ShouldReactivateAndEscalate()
    {
        // Arrange
        var ip = "9.9.9.9";
        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.BannedIps.Add(new BannedIp
            {
                IpAddress = ip,
                Reason = "Previous ban",
                BannedAt = DateTime.UtcNow.AddDays(-2),
                ExpiresAt = DateTime.UtcNow.AddDays(-1),
                BanCount = 1,
                IsActive = false
            });
            await db.SaveChangesAsync();
        }

        // Act
        await _service.BanIpAsync(ip, "Repeated scan");

        // Assert
        using var db2 = new LicenseDbContext(_dbOptions);
        var ban = await db2.BannedIps.SingleAsync(b => b.IpAddress == ip);
        Assert.True(ban.IsActive);
        Assert.Equal(2, ban.BanCount);
        Assert.Equal("Repeated scan", ban.Reason);
        Assert.True(ban.ExpiresAt > DateTime.UtcNow.AddDays(6));
        Assert.True(await _service.IsBannedAsync(ip));
        _notifierMock.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityIpBanned,
            It.Is<string>(title => title.Contains("x2")),
            It.Is<string>(message => message.Contains("Repeated scan")),
            It.IsAny<object>()), Times.Once);
    }

    [Fact]
    public async Task CheckForZombie_ShouldNotifyWithoutRevoking_WhenMultipleSubnetsDetected()
    {
        // Arrange
        var hwid = "A1B2C3D4E5F60718";
        using (var db = new LicenseDbContext(_dbOptions))
        {
            // Add existing logs with 5 different IPs (Threshold is > 5)
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "1.1.1.1", Timestamp = DateTime.UtcNow.AddMinutes(-10), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "2.2.2.2", Timestamp = DateTime.UtcNow.AddMinutes(-8), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "3.3.3.3", Timestamp = DateTime.UtcNow.AddMinutes(-6), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "4.4.4.4", Timestamp = DateTime.UtcNow.AddMinutes(-4), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "5.5.5.5", Timestamp = DateTime.UtcNow.AddMinutes(-2), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            
            var product = new Product
            {
                Id = Guid.NewGuid(), Name = "Paid Product", PrivateKeyXml = "key",
                PublicKeyXml = "key", ApiSecret = "secret"
            };
            var type = new LicenseType
            {
                Id = Guid.NewGuid(), Name = "Team", DefaultMaxSeats = 3,
                ProductId = product.Id
            };
            var license = new License {
                LicenseKey = "FRAUD-KEY", 
                HardwareId = hwid, 
                IsActive = true,
                ProductId = product.Id,
                Product = product,
                LicenseTypeId = type.Id,
                Type = type,
                CustomerName = "Bot",
                CustomerEmail = "bot@bot.com"
            };
            db.Licenses.Add(license);
            await db.SaveChangesAsync();
        }

        // Act: Test with a 6th subnet (triggers surveillance notification)
        await _service.CheckForZombieAsync(hwid, "6.6.6.6");

        // Assert
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var updatedLicense = await db.Licenses.FirstAsync(l => l.LicenseKey == "FRAUD-KEY");
            Assert.True(updatedLicense.IsActive);
            Assert.Null(updatedLicense.RevocationReason);
        }
        _notifierMock.Verify(n => n.Notify(NotificationService.Triggers.SecurityZombieDetected, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
    }

    [Theory]
    [InlineData("8A96631C...")]
    [InlineData("8a96631c369e5493")]
    [InlineData("A1B2C3D4E5F6071G")]
    [InlineData(" A1B2C3D4E5F60718")]
    public async Task CheckForZombie_ShouldIgnoreNonCanonicalHardwareIds(string hardwareId)
    {
        await _service.CheckForZombieAsync(hardwareId, "9.9.9.9");

        _notifierMock.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityZombieDetected,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Never);
    }

    [Fact]
    public async Task CheckForZombie_ShouldIgnoreCanonicalHardwareWithoutActivePaidMultiSeatLicense()
    {
        const string hardwareId = "27BDD73115CE3A52";
        using (var db = new LicenseDbContext(_dbOptions))
        {
            for (var index = 1; index <= 12; index++)
            {
                db.AccessLogs.Add(new AccessLog
                {
                    HardwareId = hardwareId,
                    ClientIp = $"{index}.1.1.1",
                    Timestamp = DateTime.UtcNow.AddMinutes(-index),
                    AppName = "YOUR_APP_NAME", Endpoint = "CHECK", Path = "/", Method = "POST", ResultStatus = "DENIED"
                });
            }
            await db.SaveChangesAsync();
        }

        await _service.CheckForZombieAsync(hardwareId, "13.1.1.1");

        _notifierMock.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityZombieDetected,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Never);
    }

    [Theory]
    [InlineData("TELEMETRY_EVENT", "OK")]
    [InlineData("CHECK", "LICENSE_REVOKED")]
    [InlineData("HTTP_REQUEST", "OK")]
    public async Task CheckForZombie_ShouldIgnoreNonAuthoritativeOrFailedAccess(
        string endpoint,
        string resultStatus)
    {
        const string hardwareId = "1234567890ABCDEF";
        await SeedPaidMultiSeatZombieAsync(hardwareId, 12);

        await _service.CheckForZombieAsync(hardwareId, "13.1.1.1", endpoint, resultStatus);

        _notifierMock.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityZombieDetected,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Never);
    }

    [Fact]
    public async Task CheckForZombie_ShouldPersistCooldownAcrossServiceInstances()
    {
        const string hardwareId = "ABCDEF0123456789";
        await SeedPaidMultiSeatZombieAsync(hardwareId, 9);
        var secondService = new SecurityService(
            _dbFactoryMock.Object, _loggerMock.Object, _notifierMock.Object,
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AdminSettings:AllowedIps"] = "127.0.0.1,::1"
            }).Build());

        await _service.CheckForZombieAsync(hardwareId, "10.10.10.10");
        await secondService.CheckForZombieAsync(hardwareId, "11.11.11.11");

        _notifierMock.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityZombieDetected,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
        using var db = new LicenseDbContext(_dbOptions);
        var incident = await db.SecurityIncidents
            .Include(row => row.Evidence)
            .SingleAsync(row => row.HardwareId == hardwareId);
        Assert.Equal(10, incident.Evidence.Count);
        Assert.All(incident.Evidence, evidence => Assert.Equal("IP", evidence.ComponentType));
    }

    private async Task SeedPaidMultiSeatZombieAsync(string hardwareId, int subnetCount)
    {
        using var db = new LicenseDbContext(_dbOptions);
        var product = new Product
        {
            Id = Guid.NewGuid(), Name = "Paid Product", PrivateKeyXml = "key",
            PublicKeyXml = "key", ApiSecret = "secret"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(), Name = "Team", DefaultMaxSeats = 3, ProductId = product.Id
        };
        db.Licenses.Add(new License
        {
            LicenseKey = $"KEY-{hardwareId}", HardwareId = hardwareId, IsActive = true,
            ProductId = product.Id, Product = product, LicenseTypeId = type.Id, Type = type,
            CustomerName = "Synthetic", CustomerEmail = "synthetic@example.test"
        });
        for (var index = 1; index <= subnetCount; index++)
        {
            db.AccessLogs.Add(new AccessLog
            {
                HardwareId = hardwareId, ClientIp = $"{index}.2.3.4",
                Timestamp = DateTime.UtcNow.AddMinutes(-index), AppName = "Test",
                Endpoint = "CHECK", Path = "/", Method = "POST", ResultStatus = "OK"
            });
        }
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task HardwareComponentBan_IsRejectedAndLegacyRowIsNeverEnforced()
    {
        var productId = Guid.NewGuid();
        var hash = new string('a', 64);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.BanComponentAsync("FP_MB", hash, "manual test", productId));
        Assert.StartsWith("hardware_component_not_enforceable:", exception.Message);

        using (var db = new LicenseDbContext(_dbOptions))
        {
            Assert.Empty(await db.BannedComponents.ToListAsync());
            db.BannedComponents.Add(new BannedComponent
            {
                ComponentType = "MB",
                ComponentHash = hash,
                ProductId = productId,
                Reason = "legacy row"
            });
            await db.SaveChangesAsync();
        }

        var result = await _service.IsComponentBannedAsync(new Dictionary<string, string>
        {
            ["FP_MB"] = hash
        }, productId);

        Assert.False(result.IsBanned);
    }

    [Fact]
    public async Task BanComponentAsync_WhenCalledWithBinaryFingerprint_ShouldKeepBinaryTypeAndBeEnforced()
    {
        // Arrange
        var productId = Guid.NewGuid();
        var hash = new string('b', 64);

        // Act
        await _service.BanComponentAsync("FP_EXE", hash.ToUpperInvariant(), "binary test", productId);

        // Assert
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var ban = await db.BannedComponents.SingleAsync();
            Assert.Equal("FP_EXE", ban.ComponentType);
            Assert.Equal(hash, ban.ComponentHash);
        }

        var result = await _service.IsComponentBannedAsync(new Dictionary<string, string>
        {
            ["fp_exe"] = hash.ToUpperInvariant()
        }, productId);

        Assert.True(result.IsBanned);
        Assert.Equal("FP_EXE", result.ComponentType);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc123")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public async Task BanComponentAsync_WhenHashIsNotCanonicalSha256_Rejects(string hash)
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.BanComponentAsync("FP_EXE", hash, "binary test", Guid.NewGuid()));

        Assert.StartsWith("component_hash_invalid:", exception.Message);
    }

    [Fact]
    public async Task UnbanComponentAsync_WithAuditReason_DeactivatesAndPersistsAudit()
    {
        Guid banId;
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var ban = new BannedComponent
            {
                ComponentType = "FP_EXE",
                ComponentHash = "patched-binary-hash",
                Reason = "BinaryPatched"
            };
            db.BannedComponents.Add(ban);
            await db.SaveChangesAsync();
            banId = ban.Id;
        }

        var found = await _service.UnbanComponentAsync(
            banId, "Unbanned via MCP | ticket=TKT-999615 | createdBy=Codex");

        Assert.True(found);
        using var verificationDb = new LicenseDbContext(_dbOptions);
        var stored = await verificationDb.BannedComponents.SingleAsync(b => b.Id == banId);
        Assert.False(stored.IsActive);
        Assert.Contains("TKT-999615", stored.Reason);
        Assert.Contains("unban=", stored.Reason);
    }

    [Fact]
    public async Task UnbanHardwareIdAsync_WhenBanDoesNotExist_ReturnsFalse()
    {
        var found = await _service.UnbanHardwareIdAsync(Guid.NewGuid(), "ticket=TKT-999615");

        Assert.False(found);
    }

    [Theory]
    [InlineData(BannedHardwareId.Categories.OutdatedVersion, true)]
    [InlineData(BannedHardwareId.Categories.QuotaAbuse, false)]
    [InlineData(BannedHardwareId.Categories.Debugger, false)]
    [InlineData(BannedHardwareId.Categories.Piracy, false)]
    [InlineData(BannedHardwareId.Categories.Manual, false)]
    [InlineData(BannedHardwareId.Categories.DevCanaryQuarantine, false)]
    [InlineData("future_security_category", false)]
    [InlineData(null, false)]
    public async Task AutoUnbanByHwidAsync_UsesExactVersionAllowlist(
        string? category,
        bool shouldUnban)
    {
        var productId = Guid.NewGuid();
        var hardwareId = "HW-VERSION-" + Guid.NewGuid().ToString("N");
        var banId = await SeedHardwareBanAsync(
            hardwareId,
            productId,
            category,
            "Auto-ban: version policy test");

        var result = await _service.AutoUnbanByHwidAsync(hardwareId, productId);

        Assert.Equal(shouldUnban, result);
        using var db = new LicenseDbContext(_dbOptions);
        Assert.Equal(!shouldUnban, (await db.BannedHardwareIds.FindAsync(banId))!.IsActive);
    }

    [Theory]
    [InlineData(BannedHardwareId.Categories.OutdatedVersion, true, false)]
    [InlineData(BannedHardwareId.Categories.QuotaAbuse, true, false)]
    [InlineData(BannedHardwareId.Categories.Debugger, false, true)]
    [InlineData(BannedHardwareId.Categories.Piracy, false, true)]
    [InlineData(BannedHardwareId.Categories.Manual, false, false)]
    [InlineData(BannedHardwareId.Categories.DevCanaryQuarantine, false, false)]
    [InlineData("future_security_category", false, false)]
    [InlineData(null, false, false)]
    public async Task TryAutoUnbanForPaidLicenseAsync_UsesExactCategoryAllowlist(
        string? category,
        bool canProceed,
        bool permanentBan)
    {
        var productId = Guid.NewGuid();
        var hardwareId = "HW-PAID-" + Guid.NewGuid().ToString("N");
        var banId = await SeedHardwareBanAsync(hardwareId, productId, category);

        using var transactionOwner = new LicenseDbContext(_dbOptions);
        var result = await _service.TryAutoUnbanForPaidLicenseAsync(
            transactionOwner,
            hardwareId,
            productId);

        Assert.Equal(canProceed, result.CanProceed);
        Assert.Equal(permanentBan, result.PermanentBan);
        Assert.Equal(canProceed, result.Notification != null);
        using (var beforeCallerSave = new LicenseDbContext(_dbOptions))
            Assert.True((await beforeCallerSave.BannedHardwareIds.FindAsync(banId))!.IsActive);

        await transactionOwner.SaveChangesAsync();
        using var afterCallerSave = new LicenseDbContext(_dbOptions);
        Assert.Equal(!canProceed, (await afterCallerSave.BannedHardwareIds.FindAsync(banId))!.IsActive);
        _notifierMock.Verify(
            notifier => notifier.Notify(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<object>()),
            Times.Never);
    }

    [Fact]
    public async Task AutoUnbanByHwidAsync_WhenAnyApplicableBanIsIneligible_PerformsZeroMutation()
    {
        var productId = Guid.NewGuid();
        var hardwareId = "HW-MIXED-" + Guid.NewGuid().ToString("N");
        var productBanId = await SeedHardwareBanAsync(
            hardwareId,
            productId,
            BannedHardwareId.Categories.OutdatedVersion,
            "Auto-ban: outdated version");
        var globalBanId = await SeedHardwareBanAsync(
            hardwareId,
            null,
            BannedHardwareId.Categories.DevCanaryQuarantine,
            "Auto-ban: quarantine must stay operator-owned");

        var result = await _service.AutoUnbanByHwidAsync(hardwareId, productId);

        Assert.False(result);
        using var db = new LicenseDbContext(_dbOptions);
        Assert.True((await db.BannedHardwareIds.FindAsync(productBanId))!.IsActive);
        Assert.True((await db.BannedHardwareIds.FindAsync(globalBanId))!.IsActive);
    }

    [Fact]
    public async Task AutoUnbanByHwidAsync_DoesNotLiftTextuallyCorrelatedComponentBan()
    {
        var productId = Guid.NewGuid();
        var hardwareId = "HW-COMPONENT-" + Guid.NewGuid().ToString("N");
        await SeedHardwareBanAsync(
            hardwareId,
            productId,
            BannedHardwareId.Categories.OutdatedVersion,
            "Auto-ban: outdated version");
        Guid componentBanId;
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var componentBan = new BannedComponent
            {
                ProductId = productId,
                ComponentType = "FP_EXE",
                ComponentHash = new string('a', 64),
                Reason = $"Auto-ban: correlated text {hardwareId}",
                IsActive = true
            };
            db.BannedComponents.Add(componentBan);
            await db.SaveChangesAsync();
            componentBanId = componentBan.Id;
        }

        Assert.True(await _service.AutoUnbanByHwidAsync(hardwareId, productId));

        using var verificationDb = new LicenseDbContext(_dbOptions);
        Assert.True((await verificationDb.BannedComponents.FindAsync(componentBanId))!.IsActive);
    }

    [Fact]
    public async Task IsHardwareIdBannedAsync_AfterAnotherInstanceUnbans_ReadsCommittedState()
    {
        var productId = Guid.NewGuid();
        var hardwareId = "HW-REPLICA-" + Guid.NewGuid().ToString("N");
        var banId = await SeedHardwareBanAsync(
            hardwareId,
            productId,
            BannedHardwareId.Categories.Manual);
        var secondInstance = new SecurityService(
            _dbFactoryMock.Object,
            _loggerMock.Object,
            _notifierMock.Object,
            Mock.Of<IConfiguration>());

        Assert.True(await _service.IsHardwareIdBannedAsync(hardwareId, productId));
        Assert.True(await secondInstance.UnbanHardwareIdAsync(banId, "operator restore"));

        Assert.False(await _service.IsHardwareIdBannedAsync(hardwareId, productId));
    }

    [Fact]
    public async Task UnbanHardwareIdAsync_ReplayedAfterLostResponse_IsIdempotent()
    {
        var banId = await SeedHardwareBanAsync(
            "HW-REPLAY-" + Guid.NewGuid().ToString("N"),
            Guid.NewGuid(),
            BannedHardwareId.Categories.Manual);

        Assert.True(await _service.UnbanHardwareIdAsync(banId, "ticket=TKT-000095"));
        Assert.True(await _service.UnbanHardwareIdAsync(banId, "ticket=TKT-000095"));

        using var db = new LicenseDbContext(_dbOptions);
        var stored = await db.BannedHardwareIds.FindAsync(banId);
        Assert.NotNull(stored);
        Assert.False(stored.IsActive);
        Assert.Equal(1, stored.Reason.Split("unban=", StringSplitOptions.None).Length - 1);
    }

    [Theory]
    [InlineData("FUTURE_SECURITY_CATEGORY")]
    [InlineData(" outdated_version")]
    [InlineData("outdated_version ")]
    public async Task BanHardwareIdAsync_WhenCategoryIsNotExactKnownIdentifier_Rejects(string category)
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.BanHardwareIdAsync(
                "HW-CATEGORY-" + Guid.NewGuid().ToString("N"),
                "manual security action",
                Guid.NewGuid(),
                banCategory: category));

        Assert.StartsWith("ban_category_invalid:", exception.Message, StringComparison.Ordinal);
        using var db = new LicenseDbContext(_dbOptions);
        Assert.Empty(await db.BannedHardwareIds.ToListAsync());
    }

    [Fact]
    public async Task BanHardwareIdAsync_WhenCategoryIsOmitted_PersistsManualCategory()
    {
        await _service.BanHardwareIdAsync(
            "HW-MANUAL-" + Guid.NewGuid().ToString("N"),
            "manual security action",
            Guid.NewGuid());

        using var db = new LicenseDbContext(_dbOptions);
        Assert.Equal(BannedHardwareId.Categories.Manual,
            (await db.BannedHardwareIds.SingleAsync()).BanCategory);
    }

    [Fact]
    public async Task HardwareBanIdentifiers_ArePersistedAndComparedUsingCanonicalInvariantCase()
    {
        var productId = Guid.NewGuid();
        var lowerHardwareId = "hw-case-" + Guid.NewGuid().ToString("N");

        await _service.BanHardwareIdAsync(
            lowerHardwareId,
            "operator security action",
            productId,
            banCategory: BannedHardwareId.Categories.Manual);

        using (var db = new LicenseDbContext(_dbOptions))
            Assert.Equal(lowerHardwareId.ToUpperInvariant(),
                (await db.BannedHardwareIds.SingleAsync()).HardwareId);
        Assert.True(await _service.IsHardwareIdBannedAsync(lowerHardwareId.ToUpperInvariant(), productId));
        Assert.True(await _service.IsHardwareIdBannedAsync(lowerHardwareId, productId));
    }

    [Fact]
    public async Task IsHardwareIdBannedAsync_WithExpiredAndLiveApplicableRows_RemainsBanned()
    {
        var productId = Guid.NewGuid();
        var hardwareId = "HW-MULTI-" + Guid.NewGuid().ToString("N");
        await SeedHardwareBanAsync(
            hardwareId,
            null,
            BannedHardwareId.Categories.OutdatedVersion,
            "Auto-ban: expired global");
        await SeedHardwareBanAsync(
            hardwareId,
            productId,
            BannedHardwareId.Categories.Manual,
            "active product ban");
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var expired = await db.BannedHardwareIds.SingleAsync(candidate => candidate.ProductId == null);
            expired.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        Assert.True(await _service.IsHardwareIdBannedAsync(hardwareId, productId));
        Assert.NotNull(await _service.GetActiveHardwareBanAsync(hardwareId, productId));
    }

    private async Task<Guid> SeedHardwareBanAsync(
        string hardwareId,
        Guid? productId,
        string? category,
        string reason = "Auto-ban: test")
    {
        using var db = new LicenseDbContext(_dbOptions);
        var ban = new BannedHardwareId
        {
            HardwareId = hardwareId,
            ProductId = productId,
            Reason = reason,
            BanCategory = category,
            IsActive = true
        };
        db.BannedHardwareIds.Add(ban);
        await db.SaveChangesAsync();
        return ban.Id;
    }
}
