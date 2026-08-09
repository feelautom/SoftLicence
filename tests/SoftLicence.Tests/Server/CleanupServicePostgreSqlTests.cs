using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class CleanupServicePostgreSqlTests
{
    private const long AccessLogCleanupAdvisoryLockKey = 0x534C4143434C4F47;

    [Fact]
    public async Task TelemetryRetention_ZeroPreservesExactGraph_AndPositiveDaysCascadeOnlyExpiredGraph()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = provision.ConnectionString,
                ["RetentionSettings:AuditLogsDays"] = "30",
                ["RetentionSettings:TelemetryDays"] = "0"
            })
            .Build();
        var factory = new TestDbContextFactory(provision.ConnectionString);
        var now = new DateTimeOffset(2026, 7, 30, 8, 0, 0, TimeSpan.Zero);
        var oldEventId = Guid.Parse("ce9472e9-51f0-47f5-9308-3bd65f14ba78");
        var oldDiagnosticId = Guid.Parse("fab69bea-aa0c-4891-b7d4-ed1d46df79a0");
        var oldErrorId = Guid.Parse("60a7d659-67b9-49c6-85ad-f6889a31c7d9");
        var recentEventId = Guid.Parse("fd5b687d-67f7-4fc7-906e-ce10de2d7e84");
        var oldEventDataId = Guid.Parse("d4a78c90-25b4-48a0-8d11-42dbe5c46ff5");
        var oldDiagnosticDataId = Guid.Parse("0f976dea-376b-4cc6-92aa-07eb04e88d3e");
        var diagnosticResultId = Guid.Parse("9f363c72-20fd-4f18-af19-d21dd3a797e4");
        var diagnosticPortId = Guid.Parse("bb01f295-19ca-42ef-b6b1-407b7e5a31d1");
        var oldErrorDataId = Guid.Parse("5ec4ccce-00b0-4f20-8b2a-e6a912c39d61");
        var recentEventDataId = Guid.Parse("e706ca51-4a3c-41cb-88ba-93d7ae276030");
        const string exactHistoricalHwid = "HWID-Exact- e\u0301-É ";
        const string exactRecentHwid = "hwid-exact- É-e\u0301";
        const string exactOldEventPayload = "{\"exact\":\" é-É \",\"order\":1}";
        const string exactRecentEventPayload = "{\"recent\":\"É-é\",\"order\":2}";

        await using (var db = factory.CreateDbContext())
        {
            var product = new Product { Name = "Retention PostgreSQL" };
            db.AddRange(
                new TelemetryRecord
                {
                    Id = oldEventId,
                    Product = product,
                    Timestamp = now.UtcDateTime.AddDays(-120),
                    HardwareId = exactHistoricalHwid,
                    AppName = "T-IA Connect",
                    EventName = "Historical_Event",
                    Type = TelemetryType.Event,
                    EventData = new TelemetryEvent { Id = oldEventDataId, PropertiesJson = exactOldEventPayload }
                },
                new TelemetryRecord
                {
                    Id = oldDiagnosticId,
                    Product = product,
                    Timestamp = now.UtcDateTime.AddDays(-119),
                    HardwareId = "DIAGNOSTIC-HWID",
                    AppName = "T-IA Connect",
                    EventName = "Historical_Diagnostic",
                    Type = TelemetryType.Diagnostic,
                    DiagnosticData = new TelemetryDiagnostic
                    {
                        Id = oldDiagnosticDataId,
                        Score = 73,
                        Results = [new TelemetryDiagnosticResult
                        {
                            Id = diagnosticResultId,
                            ModuleName = " Module-e\u0301-É ",
                            Success = true,
                            Severity = " Warning ",
                            Message = " exact-e\u0301-É "
                        }],
                        Ports = [new TelemetryDiagnosticPort
                        {
                            Id = diagnosticPortId,
                            Name = " S7-e\u0301-É ",
                            ExternalPort = 102,
                            Protocol = " TCP "
                        }]
                    }
                },
                new TelemetryRecord
                {
                    Id = oldErrorId,
                    Product = product,
                    Timestamp = now.UtcDateTime.AddDays(-118),
                    HardwareId = "ERROR-HWID",
                    AppName = "T-IA Connect",
                    EventName = "Historical_Error",
                    Type = TelemetryType.Error,
                    ErrorData = new TelemetryError
                    {
                        Id = oldErrorDataId,
                        ErrorType = " Synthetic-e\u0301-É ",
                        Message = " historical-e\u0301-É ",
                        StackTrace = " stack-e\u0301-É "
                    }
                },
                new TelemetryRecord
                {
                    Id = recentEventId,
                    Product = product,
                    Timestamp = now.UtcDateTime.AddDays(-2),
                    HardwareId = exactRecentHwid,
                    AppName = "T-IA Connect",
                    EventName = "Recent_Event",
                    Type = TelemetryType.Event,
                    EventData = new TelemetryEvent { Id = recentEventDataId, PropertiesJson = exactRecentEventPayload }
                },
                new TelemetryFloodSuppressionCounter
                {
                    Product = product,
                    HardwareId = exactHistoricalHwid,
                    EventName = "Historical_Event",
                    Type = TelemetryType.Event,
                    WindowStartUtc = now.UtcDateTime.AddDays(-120),
                    WindowEndUtc = now.UtcDateTime.AddDays(-120).AddMinutes(10),
                    LastSeenUtc = now.UtcDateTime.AddDays(-120)
                },
                new TelemetryCertPinningDailyAlert
                {
                    Product = product,
                    HardwareId = exactHistoricalHwid,
                    AlertType = "Synthetic",
                    ParisDate = new DateOnly(2026, 3, 30),
                    FirstSeenUtc = now.UtcDateTime.AddDays(-120),
                    LastSeenUtc = now.UtcDateTime.AddDays(-120)
                },
                new TelemetryIngestionRejection
                {
                    TimestampUtc = now.UtcDateTime.AddDays(-120),
                    Route = "/api/telemetry/event",
                    ValidationCode = "synthetic",
                    InvalidFields = "none",
                    CorrelationId = "retention-test"
                });
            await db.SaveChangesAsync();
        }

        await InvokeCleanupAsync(CreateService(factory, configuration, now));

        await using (var preserved = factory.CreateDbContext())
        {
            Assert.Equal(4, await preserved.TelemetryRecords.CountAsync());
            Assert.Equal(2, await preserved.TelemetryEvents.CountAsync());
            Assert.Single(await preserved.TelemetryDiagnostics.ToListAsync());
            Assert.Single(await preserved.TelemetryDiagnosticResults.ToListAsync());
            Assert.Single(await preserved.TelemetryDiagnosticPorts.ToListAsync());
            Assert.Single(await preserved.TelemetryErrors.ToListAsync());
            Assert.Equal(exactHistoricalHwid, (await preserved.TelemetryRecords.SingleAsync(row => row.Id == oldEventId)).HardwareId);
            Assert.Equal(exactRecentHwid, (await preserved.TelemetryRecords.SingleAsync(row => row.Id == recentEventId)).HardwareId);
            var events = await preserved.TelemetryEvents.OrderBy(row => row.Id).ToListAsync();
            Assert.Contains(events, row => row.Id == oldEventDataId
                && row.TelemetryRecordId == oldEventId
                && row.PropertiesJson == exactOldEventPayload);
            Assert.Contains(events, row => row.Id == recentEventDataId
                && row.TelemetryRecordId == recentEventId
                && row.PropertiesJson == exactRecentEventPayload);
            var diagnostic = await preserved.TelemetryDiagnostics.SingleAsync();
            Assert.Equal(oldDiagnosticDataId, diagnostic.Id);
            Assert.Equal(oldDiagnosticId, diagnostic.TelemetryRecordId);
            Assert.Equal(73, diagnostic.Score);
            var result = await preserved.TelemetryDiagnosticResults.SingleAsync();
            Assert.Equal(diagnosticResultId, result.Id);
            Assert.Equal(oldDiagnosticDataId, result.TelemetryDiagnosticId);
            Assert.Equal(" Module-e\u0301-É ", result.ModuleName);
            Assert.True(result.Success);
            Assert.Equal(" Warning ", result.Severity);
            Assert.Equal(" exact-e\u0301-É ", result.Message);
            var port = await preserved.TelemetryDiagnosticPorts.SingleAsync();
            Assert.Equal(diagnosticPortId, port.Id);
            Assert.Equal(oldDiagnosticDataId, port.TelemetryDiagnosticId);
            Assert.Equal(" S7-e\u0301-É ", port.Name);
            Assert.Equal(102, port.ExternalPort);
            Assert.Equal(" TCP ", port.Protocol);
            var error = await preserved.TelemetryErrors.SingleAsync();
            Assert.Equal(oldErrorDataId, error.Id);
            Assert.Equal(oldErrorId, error.TelemetryRecordId);
            Assert.Equal(" Synthetic-e\u0301-É ", error.ErrorType);
            Assert.Equal(" historical-e\u0301-É ", error.Message);
            Assert.Equal(" stack-e\u0301-É ", error.StackTrace);
        }

        configuration["RetentionSettings:TelemetryDays"] = "30";
        await InvokeCleanupAsync(CreateService(factory, configuration, now));

        await using (var purged = factory.CreateDbContext())
        {
            var remaining = await purged.TelemetryRecords.SingleAsync();
            Assert.Equal(recentEventId, remaining.Id);
            Assert.Equal(exactRecentHwid, remaining.HardwareId);
            Assert.Single(await purged.TelemetryEvents.ToListAsync());
            Assert.Empty(await purged.TelemetryDiagnostics.ToListAsync());
            Assert.Empty(await purged.TelemetryDiagnosticResults.ToListAsync());
            Assert.Empty(await purged.TelemetryDiagnosticPorts.ToListAsync());
            Assert.Empty(await purged.TelemetryErrors.ToListAsync());
            Assert.Single(await purged.TelemetryFloodSuppressionCounters.ToListAsync());
            Assert.Single(await purged.TelemetryCertPinningDailyAlerts.ToListAsync());
            Assert.Single(await purged.TelemetryIngestionRejections.ToListAsync());
        }
    }

    [Fact]
    public async Task PostgreSqlProvision_WhenMigrationFails_DropsCreatedDatabase()
    {
        string? createdDatabase = null;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => PostgreSqlProvision.CreateAsync(
            _ => throw new InvalidOperationException("synthetic_migration_failure"),
            database => createdDatabase = database));

        Assert.Equal("synthetic_migration_failure", error.Message);
        Assert.NotNull(createdDatabase);
        Assert.False(await PostgreSqlProvision.DatabaseExistsAsync(createdDatabase));
    }

    [Fact]
    public async Task AccessLogPartitionMigration_PreservesLegacyRoutesNewRowsAndRollsBackWithoutLoss()
    {
        const string previousMigration = "20260802075203_AddCanaryAckKeyRegistry";
        var legacyId = Guid.Parse("a6a75102-d047-4912-8068-353283bca4ba");
        var partitionedId = Guid.Parse("f6fb160c-06f9-4496-982d-c062c361f9d9");
        var defaultId = Guid.Parse("9f0e25b6-f6e0-47ff-992b-9116817af1fd");
        const string exactLegacyHardwareId = " Legacy-e\u0301-É ";
        const string exactPartitionedHardwareId = " Partition-e\u0301-É ";
        const string exactDefaultHardwareId = " Default-e\u0301-É ";

        await using var provision = await PostgreSqlProvision.CreateAsync(async db =>
        {
            await db.Database.MigrateAsync(previousMigration);
            var legacyLog = CreateAccessLog(DateTime.UtcNow.AddDays(-10), exactLegacyHardwareId);
            legacyLog.Id = legacyId;
            db.AccessLogs.Add(legacyLog);
            await db.SaveChangesAsync();

            await db.Database.MigrateAsync();
            db.ChangeTracker.Clear();

            var connectionString = db.Database.GetConnectionString()!;
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            var legacyUpperBound = await ExecuteScalarAsync<DateTime>(
                connection,
                "SELECT \"LegacyUpperBoundUtc\" FROM \"AccessLogPartitionState\" WHERE \"Id\" = true");

            var partitionedLog = CreateAccessLog(legacyUpperBound.AddHours(1), exactPartitionedHardwareId);
            partitionedLog.Id = partitionedId;
            db.AccessLogs.Add(partitionedLog);
            await db.SaveChangesAsync();

            var futureTimestamp = DateTime.UtcNow.Date.AddDays(60).AddHours(1);
            var defaultLog = CreateAccessLog(futureTimestamp, exactDefaultHardwareId);
            defaultLog.Id = defaultId;
            db.AccessLogs.Add(defaultLog);
            await db.SaveChangesAsync();

            Assert.Equal(
                "\"AccessLogsLegacy\"",
                await GetAccessLogPartitionNameAsync(connection, legacyId));
            Assert.StartsWith(
                "\"AccessLogs_p",
                await GetAccessLogPartitionNameAsync(connection, partitionedId),
                StringComparison.Ordinal);
            Assert.Equal(
                "\"AccessLogs_default\"",
                await GetAccessLogPartitionNameAsync(connection, defaultId));

            await using (var ensure = new NpgsqlCommand(
                "SELECT public.softlicence_ensure_access_log_partitions(@through)",
                connection))
            {
                ensure.Parameters.AddWithValue("through", DateOnly.FromDateTime(futureTimestamp));
                Assert.True(Convert.ToInt32(await ensure.ExecuteScalarAsync()) > 0);
            }

            Assert.StartsWith(
                "\"AccessLogs_p",
                await GetAccessLogPartitionNameAsync(connection, defaultId),
                StringComparison.Ordinal);

            await db.Database.MigrateAsync(previousMigration);
            db.ChangeTracker.Clear();

            Assert.Equal("r", await ExecuteScalarAsync<string>(
                connection,
                "SELECT relkind::text FROM pg_class WHERE oid = 'public.\"AccessLogs\"'::regclass"));
            var restored = await db.AccessLogs.AsNoTracking().OrderBy(row => row.Timestamp).ToListAsync();
            Assert.Equal(3, restored.Count);
            Assert.Contains(restored, row => row.Id == legacyId && row.HardwareId == exactLegacyHardwareId);
            Assert.Contains(restored, row => row.Id == partitionedId && row.HardwareId == exactPartitionedHardwareId);
            Assert.Contains(restored, row => row.Id == defaultId && row.HardwareId == exactDefaultHardwareId);
            Assert.False(await RelationExistsAsync(connection, "AccessLogsLegacy"));
            Assert.False(await RelationExistsAsync(connection, "AccessLogsPartitionedRollback"));
            Assert.False(await RelationExistsAsync(connection, "AccessLogPartitionState"));
        });
    }

    [Fact]
    public async Task AccessLogRetention_IsBoundedResumableAndSkipsWhenAnotherWorkerOwnsTheLock()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = provision.ConnectionString,
                ["RetentionSettings:AuditLogsDays"] = "30",
                ["RetentionSettings:TelemetryDays"] = "0",
                ["RetentionSettings:AccessLogBatchSize"] = "2",
                ["RetentionSettings:AccessLogMaxBatchesPerRun"] = "2",
                ["RetentionSettings:AccessLogBatchDelayMilliseconds"] = "0",
                ["RetentionSettings:AccessLogRunBudgetSeconds"] = "300",
                ["RetentionSettings:AccessLogStatementTimeoutSeconds"] = "30",
                ["RetentionSettings:AccessLogLockTimeoutMilliseconds"] = "1000"
            })
            .Build();
        var factory = new TestDbContextFactory(provision.ConnectionString);
        var now = new DateTimeOffset(2026, 8, 2, 12, 0, 0, TimeSpan.Zero);
        const string exactRecentHardwareId = " HWID-e\u0301-É ";

        await using (var db = factory.CreateDbContext())
        {
            for (var index = 0; index < 5; index++)
            {
                db.AccessLogs.Add(CreateAccessLog(
                    now.UtcDateTime.AddDays(-45).AddMinutes(index),
                    $"old-{index}"));
            }

            db.AccessLogs.Add(CreateAccessLog(now.UtcDateTime.AddDays(-2), exactRecentHardwareId));
            await db.SaveChangesAsync();
        }

        await using (var lockConnection = new NpgsqlConnection(provision.ConnectionString))
        {
            await lockConnection.OpenAsync();
            await using var lockCommand = new NpgsqlCommand("SELECT pg_advisory_lock(@key)", lockConnection);
            lockCommand.Parameters.AddWithValue("key", AccessLogCleanupAdvisoryLockKey);
            await lockCommand.ExecuteScalarAsync();

            await InvokeCleanupAsync(CreateService(factory, configuration, now));
            await using var lockedVerification = factory.CreateDbContext();
            Assert.Equal(6, await lockedVerification.AccessLogs.CountAsync());

            await using var unlockCommand = new NpgsqlCommand("SELECT pg_advisory_unlock(@key)", lockConnection);
            unlockCommand.Parameters.AddWithValue("key", AccessLogCleanupAdvisoryLockKey);
            Assert.True((bool)(await unlockCommand.ExecuteScalarAsync())!);
        }

        await InvokeCleanupAsync(CreateService(factory, configuration, now));
        await using (var boundedVerification = factory.CreateDbContext())
        {
            Assert.Equal(2, await boundedVerification.AccessLogs.CountAsync());
            Assert.Single(await boundedVerification.AccessLogs.Where(row => row.Timestamp < now.UtcDateTime.AddDays(-30)).ToListAsync());
        }

        await InvokeCleanupAsync(CreateService(factory, configuration, now));
        await using var resumedVerification = factory.CreateDbContext();
        var remaining = await resumedVerification.AccessLogs.SingleAsync();
        Assert.Equal(exactRecentHardwareId, remaining.HardwareId);
    }

    [Fact]
    public async Task AccessLogRetention_AfterPartitioning_PreservesRecentRowWithSameId()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = provision.ConnectionString,
                ["RetentionSettings:AuditLogsDays"] = "30",
                ["RetentionSettings:TelemetryDays"] = "0",
                ["RetentionSettings:AccessLogBatchSize"] = "10",
                ["RetentionSettings:AccessLogMaxBatchesPerRun"] = "1",
                ["RetentionSettings:AccessLogBatchDelayMilliseconds"] = "0",
                ["RetentionSettings:AccessLogRunBudgetSeconds"] = "300",
                ["RetentionSettings:AccessLogStatementTimeoutSeconds"] = "30",
                ["RetentionSettings:AccessLogLockTimeoutMilliseconds"] = "1000"
            })
            .Build();
        var factory = new TestDbContextFactory(provision.ConnectionString);
        var sharedId = Guid.Parse("5b1b3e92-c9ab-4b36-a3fb-37e718f3ef31");
        const string exactRecentHardwareId = " Recent-e\u0301-É ";

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        var legacyUpperBound = await ExecuteScalarAsync<DateTime>(
            connection,
            "SELECT \"LegacyUpperBoundUtc\" FROM \"AccessLogPartitionState\" WHERE \"Id\" = true");
        var expiredTimestamp = legacyUpperBound.AddDays(-60).AddHours(12);
        var recentTimestamp = legacyUpperBound.AddDays(1).AddHours(12);
        var now = new DateTimeOffset(recentTimestamp.AddDays(2), TimeSpan.Zero);

        await using (var db = factory.CreateDbContext())
        {
            var expired = CreateAccessLog(expiredTimestamp, "expired");
            expired.Id = sharedId;
            db.AccessLogs.Add(expired);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();

            var recent = CreateAccessLog(recentTimestamp, exactRecentHardwareId);
            recent.Id = sharedId;
            db.AccessLogs.Add(recent);
            await db.SaveChangesAsync();
        }

        await InvokeCleanupAsync(CreateService(factory, configuration, now));

        await using var verification = factory.CreateDbContext();
        var remaining = await verification.AccessLogs.AsNoTracking()
            .Where(row => row.Id == sharedId)
            .ToListAsync();
        Assert.Single(remaining);
        Assert.Equal(recentTimestamp, remaining[0].Timestamp);
        Assert.Equal(exactRecentHardwareId, remaining[0].HardwareId);
    }

    private static AccessLog CreateAccessLog(DateTime timestamp, string hardwareId) => new()
    {
        Timestamp = timestamp,
        ClientIp = "192.0.2.1",
        Method = "POST",
        Path = "/synthetic",
        Endpoint = "SYNTHETIC",
        HardwareId = hardwareId,
        AppName = "Retention test",
        ResultStatus = "EXACT",
        IsSuccess = true
    };

    private static async Task<string> GetAccessLogPartitionNameAsync(NpgsqlConnection connection, Guid id)
    {
        await using var command = new NpgsqlCommand(
            "SELECT tableoid::regclass::text FROM \"AccessLogs\" WHERE \"Id\" = @id",
            connection);
        command.Parameters.AddWithValue("id", id);
        return (string)(await command.ExecuteScalarAsync())!;
    }

    private static async Task<T> ExecuteScalarAsync<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync())!;
    }

    private static async Task<bool> RelationExistsAsync(NpgsqlConnection connection, string relation)
    {
        await using var command = new NpgsqlCommand("SELECT to_regclass(@relation) IS NOT NULL", connection);
        command.Parameters.AddWithValue("relation", "public.\"" + relation + "\"");
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    private static CleanupService CreateService(
        IDbContextFactory<LicenseDbContext> factory,
        IConfiguration configuration,
        DateTimeOffset now)
    {
        var settings = new SettingsService(factory, configuration, NullLogger<SettingsService>.Instance);
        var backup = new BackupService(configuration, NullLogger<BackupService>.Instance, settings);
        return new CleanupService(
            factory,
            configuration,
            NullLogger<CleanupService>.Instance,
            backup,
            settings,
            new FixedTimeProvider(now));
    }

    private static async Task InvokeCleanupAsync(CleanupService service)
    {
        var method = typeof(CleanupService).GetMethod(
            "RunCleanupAsync",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        await Assert.IsAssignableFrom<Task>(method.Invoke(service, [CancellationToken.None]));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class TestDbContextFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options;

        public LicenseDbContext CreateDbContext() => new(_options);
    }

    private sealed class PostgreSqlProvision(string maintenanceConnectionString, string connectionString, string database)
        : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public static async Task<PostgreSqlProvision> CreateAsync(
            Func<LicenseDbContext, Task>? migrateAsync = null,
            Action<string>? databaseCreated = null)
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");

            var database = "telemetry_retention_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            databaseCreated?.Invoke(database);

            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            try
            {
                var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
                await using var db = new LicenseDbContext(options);
                if (migrateAsync == null)
                    await db.Database.MigrateAsync();
                else
                    await migrateAsync(db);
                return new PostgreSqlProvision(maintenance, target, database);
            }
            catch
            {
                await DropDatabaseAsync(maintenance, database);
                throw;
            }
        }

        public static async Task<bool> DatabaseExistsAsync(string database)
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using var connection = new NpgsqlConnection(maintenance);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = @database)";
            command.Parameters.AddWithValue("database", database);
            return (bool)(await command.ExecuteScalarAsync())!;
        }

        public async ValueTask DisposeAsync()
        {
            await DropDatabaseAsync(maintenanceConnectionString, database);
        }

        private static async Task DropDatabaseAsync(string maintenanceConnectionString, string database)
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync();
        }
    }
}
