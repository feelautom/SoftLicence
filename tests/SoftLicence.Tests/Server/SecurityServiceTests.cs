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
    public async Task CheckForZombie_ShouldRevokeLicense_WhenMultipleIpsDetected()
    {
        // Arrange
        var hwid = "ZOMBIE-PC";
        using (var db = new LicenseDbContext(_dbOptions))
        {
            // Add existing logs with 5 different IPs (Threshold is > 5)
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "1.1.1.1", Timestamp = DateTime.UtcNow.AddMinutes(-10), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "2.2.2.2", Timestamp = DateTime.UtcNow.AddMinutes(-8), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "3.3.3.3", Timestamp = DateTime.UtcNow.AddMinutes(-6), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "4.4.4.4", Timestamp = DateTime.UtcNow.AddMinutes(-4), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            db.AccessLogs.Add(new AccessLog { HardwareId = hwid, ClientIp = "5.5.5.5", Timestamp = DateTime.UtcNow.AddMinutes(-2), AppName = "Test", Endpoint="ACTIVATE", Path="/", Method="POST", ResultStatus="OK" });
            
            var license = new License { 
                LicenseKey = "FRAUD-KEY", 
                HardwareId = hwid, 
                IsActive = true,
                ProductId = Guid.NewGuid(),
                LicenseTypeId = Guid.NewGuid(),
                CustomerName = "Bot",
                CustomerEmail = "bot@bot.com"
            };
            db.Licenses.Add(license);
            await db.SaveChangesAsync();
        }

        // Act: Test with a 6th IP (triggers revocation)
        await _service.CheckForZombieAsync(hwid, "6.6.6.6");

        // Assert
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var updatedLicense = await db.Licenses.FirstAsync(l => l.LicenseKey == "FRAUD-KEY");
            Assert.False(updatedLicense.IsActive);
            Assert.Contains("ZOMBIE", updatedLicense.RevocationReason);
        }
        _notifierMock.Verify(n => n.Notify(NotificationService.Triggers.SecurityZombieDetected, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
    }
}