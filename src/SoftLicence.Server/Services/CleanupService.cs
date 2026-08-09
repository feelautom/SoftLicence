using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public class CleanupService : BackgroundService
{
    private const int CleanupBatchSize = 1_000;
    private const int DefaultTelemetryRetentionDays = 0;
    private const int MaximumTelemetryRetentionDays = 36_500;
    private const long AccessLogCleanupAdvisoryLockKey = 0x534C4143434C4F47;
    private static readonly Meter RetentionMeter = new("SoftLicence.Server.Retention", "1.0.0");
    private static readonly Counter<long> AccessLogCleanupRuns = RetentionMeter.CreateCounter<long>(
        "softlicence.accesslogs.cleanup.runs");
    private static readonly Counter<long> AccessLogCleanupRows = RetentionMeter.CreateCounter<long>(
        "softlicence.accesslogs.cleanup.rows");
    private static readonly Counter<long> AccessLogPartitionsCreated = RetentionMeter.CreateCounter<long>(
        "softlicence.accesslogs.partitions.created");
    private static readonly Histogram<double> AccessLogCleanupBatchDuration = RetentionMeter.CreateHistogram<double>(
        "softlicence.accesslogs.cleanup.batch.duration", unit: "s");
    private static readonly Histogram<double> AccessLogCleanupRunDuration = RetentionMeter.CreateHistogram<double>(
        "softlicence.accesslogs.cleanup.run.duration", unit: "s");

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<CleanupService> _logger;
    private readonly BackupService _backup;
    private readonly SettingsService _settings;
    private readonly TimeProvider _timeProvider;

    public CleanupService(IDbContextFactory<LicenseDbContext> dbFactory, IConfiguration config, ILogger<CleanupService> logger, BackupService backup, SettingsService settings)
        : this(dbFactory, config, logger, backup, settings, TimeProvider.System)
    {
    }

    public CleanupService(IDbContextFactory<LicenseDbContext> dbFactory, IConfiguration config, ILogger<CleanupService> logger, BackupService backup, SettingsService settings, TimeProvider timeProvider)
    {
        _dbFactory = dbFactory;
        _config = config;
        _logger = logger;
        _backup = backup;
        _settings = settings;
        _timeProvider = timeProvider;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var enabled = _config.GetValue("RetentionSettings:CleanupEnabled", false);
        var intervalHours = _config.GetValue("RetentionSettings:CleanupIntervalHours", 24);
        
        if (!enabled)
        {
            _logger.LogWarning("Cleanup Service est DESACTIVE par configuration (RetentionSettings:CleanupEnabled).");
            return;
        }

        _logger.LogInformation("Cleanup Service démarré. Intervalle : {Hours}h", intervalHours);
        await Task.WhenAll(
            RunCleanupLoopAsync(TimeSpan.FromHours(Math.Clamp(intervalHours, 1, 24 * 30)), stoppingToken),
            RunBackupLoopAsync(stoppingToken));
    }

    private async Task RunCleanupLoopAsync(TimeSpan interval, CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(30), _timeProvider, stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunCleanupAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors du nettoyage automatique.");
            }

            await Task.Delay(interval, _timeProvider, stoppingToken);
        }
    }

    private async Task RunBackupLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (!await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false))
            {
                await Task.Delay(TimeSpan.FromMinutes(5), _timeProvider, stoppingToken);
                continue;
            }

            var configured = _config["BackupSettings:DailyBackupTime"] ?? "00:00";
            if (!TimeSpan.TryParseExact(configured, ["hh\\:mm", "hh\\:mm\\:ss"], CultureInfo.InvariantCulture, out var dailyTime)
                || dailyTime < TimeSpan.Zero || dailyTime >= TimeSpan.FromDays(1))
            {
                _logger.LogError("BackupSettings:DailyBackupTime invalide; sauvegarde désactivée jusqu'à correction.");
                await Task.Delay(TimeSpan.FromMinutes(5), _timeProvider, stoppingToken);
                continue;
            }

            var timeZone = ResolveBackupTimeZone(_config["BackupSettings:TimeZoneId"] ?? "Europe/Paris");
            var next = GetNextDailyOccurrence(_timeProvider.GetUtcNow(), dailyTime, timeZone);
            await Task.Delay(next.UtcDateTime - _timeProvider.GetUtcNow().UtcDateTime, _timeProvider, stoppingToken);
            try
            {
                await _backup.BackupDatabaseAsync(stoppingToken);
                await _settings.SetSettingAsync("BackupSettings:LastBackupDate", _timeProvider.GetUtcNow().ToString("O", CultureInfo.InvariantCulture));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Échec du backup journalier planifié.");
            }
        }
    }

    private async Task RunCleanupAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Démarrage de la purge des anciens logs...");

        var accessLogOptions = GetAccessLogRetentionOptions();
        var telemetryDays = GetTelemetryRetentionDays();

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var auditCutoff = now.AddDays(-accessLogOptions.RetentionDays);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        // 1. Purge Audit
        if (db.Database.IsNpgsql())
            await EnsureAccessLogPartitionsAsync(db, now, accessLogOptions.PartitionHorizonDays, cancellationToken);
        var cleanup = await DeleteOldAccessLogsAsync(db, auditCutoff, accessLogOptions, cancellationToken);
        if (cleanup.DeletedRows > 0)
            _logger.LogInformation(
                "Cleanup AccessLogs terminé : {DeletedRows} lignes, {BatchCount} lots, reste={MoreRowsMayRemain}, résultat={Outcome}.",
                cleanup.DeletedRows,
                cleanup.BatchCount,
                cleanup.MoreRowsMayRemain,
                cleanup.Outcome);

        // 2. Purge Télémétrie (0 = rétention illimitée)
        if (telemetryDays > 0)
        {
            var telemetryCutoff = now.AddDays(-telemetryDays);
            var deletedTelemetry = await DeleteOldTelemetryRecordsAsync(db, telemetryCutoff, cancellationToken);
            if (deletedTelemetry > 0)
                _logger.LogInformation("{Count} enregistrements de télémétrie supprimés.", deletedTelemetry);
        }
        else
        {
            _logger.LogInformation("Rétention télémétrie illimitée (TelemetryDays=0). Aucune purge.");
        }

        // PostgreSQL autovacuum handles maintenance; the application role remains non-owner.
        _logger.LogInformation("Nettoyage terminé.");

    }

    private int GetTelemetryRetentionDays()
    {
        var configured = _config["RetentionSettings:TelemetryDays"];
        if (configured == null)
            return DefaultTelemetryRetentionDays;

        if (!int.TryParse(configured, NumberStyles.None, CultureInfo.InvariantCulture, out var days)
            || days < 0
            || days > MaximumTelemetryRetentionDays)
            throw new InvalidOperationException("telemetry_retention_configuration_invalid");

        return days;
    }

    private AccessLogRetentionOptions GetAccessLogRetentionOptions() => new(
        RetentionDays: GetBoundedInteger("RetentionSettings:AuditLogsDays", 30, 1, MaximumTelemetryRetentionDays),
        BatchSize: GetBoundedInteger("RetentionSettings:AccessLogBatchSize", CleanupBatchSize, 1, 10_000),
        MaxBatchesPerRun: GetBoundedInteger("RetentionSettings:AccessLogMaxBatchesPerRun", 100, 1, 100_000),
        BatchDelayMilliseconds: GetBoundedInteger("RetentionSettings:AccessLogBatchDelayMilliseconds", 100, 0, 60_000),
        RunBudgetSeconds: GetBoundedInteger("RetentionSettings:AccessLogRunBudgetSeconds", 300, 1, 3_600),
        StatementTimeoutSeconds: GetBoundedInteger("RetentionSettings:AccessLogStatementTimeoutSeconds", 30, 1, 300),
        LockTimeoutMilliseconds: GetBoundedInteger("RetentionSettings:AccessLogLockTimeoutMilliseconds", 1_000, 1, 60_000),
        PartitionHorizonDays: GetBoundedInteger("RetentionSettings:AccessLogPartitionHorizonDays", 45, 7, 90));

    private int GetBoundedInteger(string key, int defaultValue, int minimum, int maximum)
    {
        var configured = _config[key];
        if (configured == null)
            return defaultValue;

        if (!int.TryParse(configured, NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            || value < minimum
            || value > maximum)
            throw new InvalidOperationException($"retention_configuration_invalid:{key}");

        return value;
    }

    private static DateTimeOffset GetNextDailyOccurrence(DateTimeOffset now, TimeSpan dailyTime) =>
        GetNextDailyOccurrence(now, dailyTime, ResolveBackupTimeZone("Europe/Paris"));

    private static DateTimeOffset GetNextDailyOccurrence(DateTimeOffset now, TimeSpan dailyTime, TimeZoneInfo timeZone)
    {
        var localNow = TimeZoneInfo.ConvertTime(now, timeZone).DateTime;
        for (var dayOffset = 0; dayOffset <= 2; dayOffset++)
        {
            var localCandidate = DateTime.SpecifyKind(localNow.Date.AddDays(dayOffset).Add(dailyTime), DateTimeKind.Unspecified);
            while (timeZone.IsInvalidTime(localCandidate))
                localCandidate = localCandidate.AddMinutes(1);

            var offsets = timeZone.IsAmbiguousTime(localCandidate)
                ? timeZone.GetAmbiguousTimeOffsets(localCandidate)
                : [timeZone.GetUtcOffset(localCandidate)];
            var candidate = offsets
                .Select(offset => new DateTimeOffset(localCandidate, offset))
                .Where(value => value.UtcDateTime > now.UtcDateTime)
                .OrderBy(value => value.UtcDateTime)
                .FirstOrDefault();
            if (candidate != default)
                return candidate;
        }
        throw new InvalidOperationException("backup_schedule_unresolvable");
    }

    private static TimeZoneInfo ResolveBackupTimeZone(string timeZoneId)
    {
        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
        }
        catch (TimeZoneNotFoundException) when (timeZoneId == "Europe/Paris")
        {
            return TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time");
        }
    }

    private async Task<AccessLogCleanupResult> DeleteOldAccessLogsAsync(
        LicenseDbContext db,
        DateTime cutoff,
        AccessLogRetentionOptions options,
        CancellationToken cancellationToken)
    {
        var query = db.AccessLogs.Where(l => l.Timestamp < cutoff);
        if (db.Database.IsNpgsql())
            return await DeleteOldPostgreSqlAccessLogsAsync(db, query, cutoff, options, cancellationToken);

        var deleted = 0;
        var batchCount = 0;
        while (batchCount < options.MaxBatchesPerRun)
        {
            var ids = await query
                .OrderBy(l => l.Timestamp)
                .ThenBy(l => l.Id)
                .Select(l => l.Id)
                .Take(options.BatchSize)
                .ToListAsync(cancellationToken);

            if (ids.Count == 0)
                break;

            var batch = ids.Select(id => new AccessLog { Id = id }).ToArray();
            db.AccessLogs.RemoveRange(batch);
            deleted += await db.SaveChangesAsync(cancellationToken);
            batchCount++;
        }

        var remains = await query.AnyAsync(cancellationToken);
        return new AccessLogCleanupResult(deleted, batchCount, remains, remains ? "bounded" : "completed");
    }

    private async Task EnsureAccessLogPartitionsAsync(
        LicenseDbContext db,
        DateTime nowUtc,
        int horizonDays,
        CancellationToken cancellationToken)
    {
        var requestedThrough = DateOnly.FromDateTime(nowUtc).AddDays(horizonDays);
        await db.Database.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = "SELECT public.softlicence_ensure_access_log_partitions(@through)";
            var parameter = command.CreateParameter();
            parameter.ParameterName = "through";
            parameter.Value = requestedThrough;
            command.Parameters.Add(parameter);
            var created = Convert.ToInt32(
                await command.ExecuteScalarAsync(cancellationToken),
                CultureInfo.InvariantCulture);
            if (created > 0)
            {
                AccessLogPartitionsCreated.Add(created);
                _logger.LogInformation(
                    "Maintenance AccessLogs : {PartitionCount} partitions créées jusqu'au {RequestedThrough} UTC.",
                    created,
                    requestedThrough);
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    private async Task<AccessLogCleanupResult> DeleteOldPostgreSqlAccessLogsAsync(
        LicenseDbContext db,
        IQueryable<AccessLog> query,
        DateTime cutoff,
        AccessLogRetentionOptions options,
        CancellationToken cancellationToken)
    {
        var runStarted = Stopwatch.GetTimestamp();
        var outcome = "failed";
        var deletedRows = 0;
        var batchCount = 0;
        var lockAcquired = false;

        try
        {
            await db.Database.OpenConnectionAsync(cancellationToken);
            await using (var command = db.Database.GetDbConnection().CreateCommand())
            {
                command.CommandText = "SELECT pg_try_advisory_lock(@key)";
                var parameter = command.CreateParameter();
                parameter.ParameterName = "key";
                parameter.Value = AccessLogCleanupAdvisoryLockKey;
                command.Parameters.Add(parameter);
                lockAcquired = Convert.ToBoolean(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
            }

            if (!lockAcquired)
            {
                outcome = "skipped_lock_held";
                _logger.LogWarning("Cleanup AccessLogs ignoré : un autre worker détient le verrou advisory.");
                return new AccessLogCleanupResult(0, 0, true, outcome);
            }

            while (batchCount < options.MaxBatchesPerRun
                && Stopwatch.GetElapsedTime(runStarted) < TimeSpan.FromSeconds(options.RunBudgetSeconds))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var batchStarted = Stopwatch.GetTimestamp();
                await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
                var lockTimeout = $"{options.LockTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture)}ms";
                var statementTimeout = $"{options.StatementTimeoutSeconds.ToString(CultureInfo.InvariantCulture)}s";
                await db.Database.ExecuteSqlInterpolatedAsync($$"""
                    SELECT set_config('lock_timeout', {{lockTimeout}}, true),
                           set_config('statement_timeout', {{statementTimeout}}, true)
                    """, cancellationToken);
                var affected = await db.Database.ExecuteSqlInterpolatedAsync($$"""
                    WITH doomed AS (
                        SELECT "Id", "Timestamp"
                        FROM "AccessLogs"
                        WHERE "Timestamp" < {{cutoff}}
                        ORDER BY "Timestamp", "Id"
                        LIMIT {{options.BatchSize}}
                        FOR UPDATE SKIP LOCKED
                    )
                    DELETE FROM "AccessLogs" AS target
                    USING doomed
                    WHERE target."Id" = doomed."Id"
                      AND target."Timestamp" = doomed."Timestamp"
                      AND target."Timestamp" < {{cutoff}}
                    """, cancellationToken);
                await transaction.CommitAsync(cancellationToken);

                batchCount++;
                deletedRows += affected;
                AccessLogCleanupRows.Add(affected);
                AccessLogCleanupBatchDuration.Record(Stopwatch.GetElapsedTime(batchStarted).TotalSeconds);
                _logger.LogInformation(
                    "Cleanup AccessLogs lot {BatchNumber} : {DeletedRows} lignes en {ElapsedMilliseconds} ms.",
                    batchCount,
                    affected,
                    Stopwatch.GetElapsedTime(batchStarted).TotalMilliseconds);

                if (affected < options.BatchSize)
                    break;

                if (options.BatchDelayMilliseconds > 0)
                    await Task.Delay(TimeSpan.FromMilliseconds(options.BatchDelayMilliseconds), _timeProvider, cancellationToken);
            }

            var remains = await query.AnyAsync(cancellationToken);
            outcome = remains ? "bounded" : "completed";
            if (remains)
                _logger.LogWarning(
                    "Cleanup AccessLogs borné avec lignes expirées restantes après {BatchCount} lots et {ElapsedSeconds:F3} s.",
                    batchCount,
                    Stopwatch.GetElapsedTime(runStarted).TotalSeconds);
            return new AccessLogCleanupResult(deletedRows, batchCount, remains, outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = "cancelled";
            throw;
        }
        finally
        {
            if (lockAcquired)
            {
                try
                {
                    await using var command = db.Database.GetDbConnection().CreateCommand();
                    command.CommandText = "SELECT pg_advisory_unlock(@key)";
                    var parameter = command.CreateParameter();
                    parameter.ParameterName = "key";
                    parameter.Value = AccessLogCleanupAdvisoryLockKey;
                    command.Parameters.Add(parameter);
                    await command.ExecuteScalarAsync(CancellationToken.None);
                }
                catch (Exception exception)
                {
                    _logger.LogWarning(exception, "Impossible de libérer explicitement le verrou advisory AccessLogs; la fermeture de connexion le libérera.");
                }
            }

            AccessLogCleanupRuns.Add(1, new KeyValuePair<string, object?>("outcome", outcome));
            AccessLogCleanupRunDuration.Record(
                Stopwatch.GetElapsedTime(runStarted).TotalSeconds,
                new KeyValuePair<string, object?>("outcome", outcome));
            await db.Database.CloseConnectionAsync();
        }
    }

    private static async Task<int> DeleteOldTelemetryRecordsAsync(
        LicenseDbContext db,
        DateTime cutoff,
        CancellationToken cancellationToken)
    {
        var query = db.TelemetryRecords.Where(t => t.Timestamp < cutoff);
        if (db.Database.IsRelational())
            return await query.ExecuteDeleteAsync(cancellationToken);

        var deleted = 0;
        while (true)
        {
            var ids = await query
                .OrderBy(t => t.Timestamp)
                .Select(t => t.Id)
                .Take(CleanupBatchSize)
                .ToListAsync(cancellationToken);

            if (ids.Count == 0) return deleted;

            var batch = ids.Select(id => new TelemetryRecord { Id = id }).ToArray();
            db.TelemetryRecords.RemoveRange(batch);
            deleted += await db.SaveChangesAsync(cancellationToken);
        }
    }

    private sealed record AccessLogRetentionOptions(
        int RetentionDays,
        int BatchSize,
        int MaxBatchesPerRun,
        int BatchDelayMilliseconds,
        int RunBudgetSeconds,
        int StatementTimeoutSeconds,
        int LockTimeoutMilliseconds,
        int PartitionHorizonDays);

    private sealed record AccessLogCleanupResult(
        int DeletedRows,
        int BatchCount,
        bool MoreRowsMayRemain,
        string Outcome);
}
