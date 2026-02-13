using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public class CleanupServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly Mock<IConfiguration> _configMock;
    private readonly Mock<ILogger<CleanupService>> _loggerMock;

    public CleanupServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(default))
            .Returns(() => Task.FromResult(new LicenseDbContext(_dbOptions)));

        _configMock = new Mock<IConfiguration>();
        _loggerMock = new Mock<ILogger<CleanupService>>();
    }

    [Fact]
    public async Task RunCleanup_ShouldDeleteOldLogs_BasedOnConfig()
    {
        // Arrange
        // 10 jours de rétention pour le test
        var auditSection = new Mock<IConfigurationSection>();
        auditSection.Setup(s => s.Value).Returns("10");
        _configMock.Setup(c => c.GetSection("RetentionSettings:AuditLogsDays")).Returns(auditSection.Object);
        
        var telemetrySection = new Mock<IConfigurationSection>();
        telemetrySection.Setup(s => s.Value).Returns("10");
        _configMock.Setup(c => c.GetSection("RetentionSettings:TelemetryDays")).Returns(telemetrySection.Object);

        var connStringSection = new Mock<IConfigurationSection>();
        connStringSection.Setup(s => s["DefaultConnection"]).Returns("Data Source=:memory:");
        _configMock.Setup(c => c.GetSection("ConnectionStrings")).Returns(connStringSection.Object);

        using (var db = new LicenseDbContext(_dbOptions))
        {
            var oldDate = DateTime.UtcNow.AddDays(-15);
            var recentDate = DateTime.UtcNow.AddDays(-5);

            db.AccessLogs.Add(new AccessLog { Timestamp = oldDate, ClientIp="1", Path="/", Method="G", ResultStatus="OK", AppName="A", Endpoint="E" });
            db.AccessLogs.Add(new AccessLog { Timestamp = recentDate, ClientIp="1", Path="/", Method="G", ResultStatus="OK", AppName="A", Endpoint="E" });
            
            db.TelemetryRecords.Add(new TelemetryRecord { Timestamp = oldDate, HardwareId="H", AppName="A", EventName="E" });
            db.TelemetryRecords.Add(new TelemetryRecord { Timestamp = recentDate, HardwareId="H", AppName="A", EventName="E" });

            await db.SaveChangesAsync();
        }

        // Dummy Services
        var settingsLoggerMock = new Mock<ILogger<SettingsService>>();
        var settingsService = new SettingsService(_dbFactoryMock.Object, _configMock.Object, settingsLoggerMock.Object);

        var backupLoggerMock = new Mock<ILogger<BackupService>>();
        var backupService = new BackupService(_configMock.Object, backupLoggerMock.Object, settingsService);

        // Pour appeler la méthode privée RunCleanupAsync via réflexion pour le test
        var service = new CleanupService(_dbFactoryMock.Object, _configMock.Object, _loggerMock.Object, backupService, settingsService);
        var method = typeof(CleanupService).GetMethod("RunCleanupAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        // Act
        await (Task)method!.Invoke(service, null)!;

        // Assert
        using (var db = new LicenseDbContext(_dbOptions))
        {
            Assert.Single(db.AccessLogs);
            Assert.Single(db.TelemetryRecords);
            Assert.True(db.AccessLogs.First().Timestamp > DateTime.UtcNow.AddDays(-6));
        }
    }
}
