using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using System.Text.Json;
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
        _configMock.Setup(c => c["RetentionSettings:AuditLogsDays"]).Returns("10");
        
        var telemetrySection = new Mock<IConfigurationSection>();
        telemetrySection.Setup(s => s.Value).Returns("10");
        _configMock.Setup(c => c.GetSection("RetentionSettings:TelemetryDays")).Returns(telemetrySection.Object);
        _configMock.Setup(c => c["RetentionSettings:TelemetryDays"]).Returns("10");

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
        await (Task)method!.Invoke(service, [CancellationToken.None])!;

        // Assert
        using (var db = new LicenseDbContext(_dbOptions))
        {
            Assert.Single(db.AccessLogs);
            Assert.Single(db.TelemetryRecords);
            Assert.True(db.AccessLogs.First().Timestamp > DateTime.UtcNow.AddDays(-6));
        }
    }

    [Fact]
    public async Task RunCleanup_TelemetryDaysZero_PreservesTelemetry()
    {
        ConfigureRetention(auditDays: "10", telemetryDays: "0");
        var telemetryId = Guid.Parse("03c46265-07f2-49fb-9aca-84f6e2ae3765");
        const string exactHardwareId = "HWID-Exact- e\u0301-É ";

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.TelemetryRecords.Add(new TelemetryRecord
            {
                Id = telemetryId,
                Timestamp = DateTime.UtcNow.AddYears(-5),
                HardwareId = exactHardwareId,
                AppName = "T-IA Connect",
                EventName = "Historical_Event",
                Type = TelemetryType.Event,
                EventData = new TelemetryEvent { PropertiesJson = "{\"exact\":true}" }
            });
            await db.SaveChangesAsync();
        }

        await InvokeCleanupAsync(CreateService());

        await using var verification = new LicenseDbContext(_dbOptions);
        var preserved = await verification.TelemetryRecords.SingleAsync();
        Assert.Equal(telemetryId, preserved.Id);
        Assert.Equal(exactHardwareId, preserved.HardwareId);
        Assert.Single(verification.TelemetryEvents);
    }

    [Fact]
    public async Task RunCleanup_TelemetryDaysMissing_DefaultsToUnlimitedAndPreservesTelemetry()
    {
        ConfigureRetention(auditDays: "10", telemetryDays: null);
        var telemetryId = Guid.Parse("378dc4b5-a343-4d82-a94d-c8734164966c");

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.TelemetryRecords.Add(new TelemetryRecord
            {
                Id = telemetryId,
                Timestamp = DateTime.UtcNow.AddYears(-5),
                HardwareId = "HWID-Missing- e\u0301-É ",
                AppName = "T-IA Connect",
                EventName = "Missing_Config",
                Type = TelemetryType.Event,
                EventData = new TelemetryEvent { PropertiesJson = "{\"missing\":true}" }
            });
            await db.SaveChangesAsync();
        }

        await InvokeCleanupAsync(CreateService());

        await using var verification = new LicenseDbContext(_dbOptions);
        Assert.Equal(telemetryId, (await verification.TelemetryRecords.SingleAsync()).Id);
        Assert.Single(verification.TelemetryEvents);
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData("0", 0)]
    [InlineData("1", 1)]
    [InlineData("36500", 36500)]
    public void TelemetryRetention_ValidBoundaryConfiguration_IsAccepted(string? configured, int expected)
    {
        ConfigureRetention(auditDays: "10", telemetryDays: configured);

        Assert.Equal(expected, InvokeTelemetryRetentionParser(CreateService()));
    }

    [Theory]
    [InlineData("-1")]
    [InlineData(" 0")]
    [InlineData("0 ")]
    [InlineData("+0")]
    [InlineData("")]
    [InlineData("٠")]
    [InlineData("０")]
    [InlineData("not-a-number")]
    [InlineData("36501")]
    public async Task RunCleanup_InvalidTelemetryDays_FailsClosed(string configured)
    {
        ConfigureRetention(auditDays: "10", telemetryDays: configured);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InvokeCleanupAsync(CreateService()));

        Assert.Equal("telemetry_retention_configuration_invalid", error.Message);
        _dbFactoryMock.Verify(factory => factory.CreateDbContextAsync(default), Times.Never);
    }

    [Fact]
    public void EnvironmentConfiguration_OverridesTelemetryRetentionDefaultWithZero()
    {
        const string prefix = "TKT999881_";
        const string environmentKey = prefix + "RetentionSettings__TelemetryDays";
        var previous = Environment.GetEnvironmentVariable(environmentKey);
        try
        {
            Environment.SetEnvironmentVariable(environmentKey, "0");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["RetentionSettings:TelemetryDays"] = "90"
                })
                .AddEnvironmentVariables(prefix)
                .Build();

            Assert.Equal("0", configuration["RetentionSettings:TelemetryDays"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(environmentKey, previous);
        }
    }

    [Fact]
    [Trait("Category", "PrivateRepository")]
    public void DeploymentDefaults_AreExactlyUnlimited()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var compose = File.ReadAllText(Path.Combine(repositoryRoot, "Docker", "docker-compose.yml"));
        var distributedSettings = File.ReadAllText(Path.Combine(
            repositoryRoot, "src", "SoftLicence.Server", "appsettings.dist.json"));

        Assert.Contains(
            "RetentionSettings__TelemetryDays=${RetentionSettings__TelemetryDays:-0}",
            compose,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "RetentionSettings__TelemetryDays=${RetentionSettings__TelemetryDays:-90}",
            compose,
            StringComparison.Ordinal);
        using var document = JsonDocument.Parse(distributedSettings);
        Assert.Equal(
            0,
            document.RootElement.GetProperty("RetentionSettings").GetProperty("TelemetryDays").GetInt32());
    }

    [Fact]
    public void RunCleanup_Source_UsesBoundedPostgreSqlBatchesWithoutMaintenanceLocks()
    {
        var source = File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "src", "SoftLicence.Server", "Services", "CleanupService.cs"));

        Assert.Contains("FOR UPDATE SKIP LOCKED", source);
        Assert.Contains("pg_try_advisory_lock", source);
        Assert.Contains("AccessLogMaxBatchesPerRun", source);
        Assert.DoesNotContain("var oldLogs = await db.AccessLogs", source);
        Assert.DoesNotContain("RemoveRange(oldLogs)", source);
        Assert.DoesNotContain("var oldTelemetry = await db.TelemetryRecords", source);
        Assert.DoesNotContain("RemoveRange(oldTelemetry)", source);
        Assert.DoesNotContain("ExecuteSqlRawAsync(\"VACUUM", source, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("RetentionSettings:AuditLogsDays", "0")]
    [InlineData("RetentionSettings:AuditLogsDays", " 30")]
    [InlineData("RetentionSettings:AccessLogBatchSize", "10001")]
    [InlineData("RetentionSettings:AccessLogMaxBatchesPerRun", "0")]
    [InlineData("RetentionSettings:AccessLogBatchDelayMilliseconds", "-1")]
    [InlineData("RetentionSettings:AccessLogRunBudgetSeconds", "+300")]
    [InlineData("RetentionSettings:AccessLogStatementTimeoutSeconds", "٣٠")]
    [InlineData("RetentionSettings:AccessLogLockTimeoutMilliseconds", "0")]
    [InlineData("RetentionSettings:AccessLogPartitionHorizonDays", "91")]
    public async Task RunCleanup_InvalidAccessLogRetentionOption_FailsBeforeOpeningDatabase(
        string key,
        string configured)
    {
        ConfigureRetention(auditDays: "30", telemetryDays: "0");
        _configMock.Setup(configuration => configuration[key]).Returns(configured);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InvokeCleanupAsync(CreateService()));

        Assert.Equal($"retention_configuration_invalid:{key}", error.Message);
        _dbFactoryMock.Verify(factory => factory.CreateDbContextAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    [Trait("Category", "PrivateRepository")]
    public void DeploymentDefaults_ExposeBoundedAccessLogCleanupContract()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var compose = File.ReadAllText(Path.Combine(repositoryRoot, "Docker", "docker-compose.yml"));
        var distributedSettings = File.ReadAllText(Path.Combine(
            repositoryRoot, "src", "SoftLicence.Server", "appsettings.dist.json"));

        Assert.Contains("RetentionSettings__AccessLogBatchSize=${RetentionSettings__AccessLogBatchSize:-1000}", compose, StringComparison.Ordinal);
        Assert.Contains("RetentionSettings__AccessLogMaxBatchesPerRun=${RetentionSettings__AccessLogMaxBatchesPerRun:-100}", compose, StringComparison.Ordinal);
        Assert.Contains("RetentionSettings__AccessLogRunBudgetSeconds=${RetentionSettings__AccessLogRunBudgetSeconds:-300}", compose, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(distributedSettings);
        var retention = document.RootElement.GetProperty("RetentionSettings");
        Assert.Equal(30, retention.GetProperty("AuditLogsDays").GetInt32());
        Assert.Equal(1_000, retention.GetProperty("AccessLogBatchSize").GetInt32());
        Assert.Equal(100, retention.GetProperty("AccessLogMaxBatchesPerRun").GetInt32());
        Assert.Equal(300, retention.GetProperty("AccessLogRunBudgetSeconds").GetInt32());
        Assert.Equal(45, retention.GetProperty("AccessLogPartitionHorizonDays").GetInt32());
        Assert.False(retention.TryGetProperty("AuditLogDays", out _));
    }

    [Theory]
    [InlineData("2026-07-29T08:30:00+02:00", "02:00:00", "2026-07-30T02:00:00+02:00")]
    [InlineData("2026-07-29T00:30:00+02:00", "02:00:00", "2026-07-29T02:00:00+02:00")]
    public void NextDailyBackup_IsAnchoredToConfiguredLocalTime(
        string nowText,
        string configuredTime,
        string expectedText)
    {
        var method = typeof(CleanupService).GetMethod(
            "GetNextDailyOccurrence", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static,
            null, [typeof(DateTimeOffset), typeof(TimeSpan)], null);
        Assert.NotNull(method);
        var actual = Assert.IsType<DateTimeOffset>(method.Invoke(null,
            [DateTimeOffset.Parse(nowText), TimeSpan.Parse(configuredTime)]));
        Assert.Equal(DateTimeOffset.Parse(expectedText), actual);
    }

    [Theory]
    [InlineData("2026-03-28T23:30:00Z", "02:30:00", "2026-03-29T01:00:00Z")]
    [InlineData("2026-10-25T00:00:00Z", "02:30:00", "2026-10-25T00:30:00Z")]
    [InlineData("2026-10-25T00:45:00Z", "02:30:00", "2026-10-25T01:30:00Z")]
    public void NextDailyBackup_UsesEuropeParisWallClockAcrossDst(
        string nowText, string configuredTime, string expectedUtcText)
    {
        var method = typeof(CleanupService).GetMethod(
            "GetNextDailyOccurrence", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static,
            null, [typeof(DateTimeOffset), typeof(TimeSpan), typeof(TimeZoneInfo)], null);
        Assert.NotNull(method);
        var zone = TimeZoneInfo.FindSystemTimeZoneById("Europe/Paris");
        var actual = Assert.IsType<DateTimeOffset>(method.Invoke(null,
            [DateTimeOffset.Parse(nowText), TimeSpan.Parse(configuredTime), zone]));
        Assert.Equal(DateTimeOffset.Parse(expectedUtcText).UtcDateTime, actual.UtcDateTime);
    }

    private void ConfigureRetention(string auditDays, string? telemetryDays)
    {
        var auditSection = new Mock<IConfigurationSection>();
        auditSection.Setup(section => section.Value).Returns(auditDays);
        _configMock.Setup(configuration => configuration.GetSection("RetentionSettings:AuditLogsDays"))
            .Returns(auditSection.Object);
        _configMock.Setup(configuration => configuration["RetentionSettings:AuditLogsDays"])
            .Returns(auditDays);

        var telemetrySection = new Mock<IConfigurationSection>();
        telemetrySection.Setup(section => section.Value).Returns(telemetryDays);
        _configMock.Setup(configuration => configuration.GetSection("RetentionSettings:TelemetryDays"))
            .Returns(telemetrySection.Object);
        _configMock.Setup(configuration => configuration["RetentionSettings:TelemetryDays"])
            .Returns(telemetryDays);

        var connectionStrings = new Mock<IConfigurationSection>();
        connectionStrings.Setup(section => section["DefaultConnection"])
            .Returns("Data Source=:memory:");
        _configMock.Setup(configuration => configuration.GetSection("ConnectionStrings"))
            .Returns(connectionStrings.Object);
    }

    private CleanupService CreateService()
    {
        var settingsService = new SettingsService(
            _dbFactoryMock.Object,
            _configMock.Object,
            Mock.Of<ILogger<SettingsService>>());
        var backupService = new BackupService(
            _configMock.Object,
            Mock.Of<ILogger<BackupService>>(),
            settingsService);
        return new CleanupService(
            _dbFactoryMock.Object,
            _configMock.Object,
            _loggerMock.Object,
            backupService,
            settingsService);
    }

    private static async Task InvokeCleanupAsync(CleanupService service)
    {
        var method = typeof(CleanupService).GetMethod(
            "RunCleanupAsync",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        await Assert.IsAssignableFrom<Task>(method.Invoke(service, [CancellationToken.None]));
    }

    private static int InvokeTelemetryRetentionParser(CleanupService service)
    {
        var method = typeof(CleanupService).GetMethod(
            "GetTelemetryRetentionDays",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        return Assert.IsType<int>(method.Invoke(service, null));
    }
}
