using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public class CleanupService : BackgroundService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<CleanupService> _logger;
    private readonly BackupService _backup;
    private readonly SettingsService _settings;

    public CleanupService(IDbContextFactory<LicenseDbContext> dbFactory, IConfiguration config, ILogger<CleanupService> logger, BackupService backup, SettingsService settings)
    {
        _dbFactory = dbFactory;
        _config = config;
        _logger = logger;
        _backup = backup;
        _settings = settings;
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

        // Attente initiale courte pour laisser le serveur démarrer proprement
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunCleanupAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors du nettoyage automatique.");
            }

            await Task.Delay(TimeSpan.FromHours(intervalHours), stoppingToken);
        }
    }

    private async Task RunCleanupAsync()
    {
        _logger.LogInformation("Démarrage de la purge des anciens logs...");

        var auditDays = _config.GetValue("RetentionSettings:AuditLogsDays", 30);
        var telemetryDays = _config.GetValue("RetentionSettings:TelemetryDays", 90);

        var auditCutoff = DateTime.UtcNow.AddDays(-auditDays);
        var telemetryCutoff = DateTime.UtcNow.AddDays(-telemetryDays);

        using var db = await _dbFactory.CreateDbContextAsync();

        // 1. Purge Audit
        var oldLogs = await db.AccessLogs
            .Where(l => l.Timestamp < auditCutoff)
            .ToListAsync();

        if (oldLogs.Any())
        {
            db.AccessLogs.RemoveRange(oldLogs);
            await db.SaveChangesAsync();
            _logger.LogInformation("{Count} logs d'audit supprimés.", oldLogs.Count);
        }

        // 2. Purge Télémétrie
        var oldTelemetry = await db.TelemetryRecords
            .Where(t => t.Timestamp < telemetryCutoff)
            .ToListAsync();

        if (oldTelemetry.Any())
        {
            db.TelemetryRecords.RemoveRange(oldTelemetry);
            await db.SaveChangesAsync();
            _logger.LogInformation("{Count} enregistrements de télémétrie supprimés.", oldTelemetry.Count);
        }

        // 3. Optimisation PostgreSQL
        if (db.Database.ProviderName != "Microsoft.EntityFrameworkCore.InMemory" && (oldLogs.Any() || oldTelemetry.Any()))
        {
            _logger.LogInformation("Optimisation de la base de données PostgreSQL (VACUUM ANALYZE)...");
            await db.Database.ExecuteSqlRawAsync("VACUUM ANALYZE");
        }

        _logger.LogInformation("Nettoyage terminé.");

        // 4. Sauvegarde journalière Drive (rclone)
        if (await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false))
        {
            var now = DateTime.Now;
            var lastBackupStr = await _settings.GetSettingAsync("BackupSettings:LastBackupDate");
            DateTime.TryParse(lastBackupStr, out var lastBackup);

            if (lastBackup.Date != now.Date)
            {
                _logger.LogInformation("Lancement du backup journalier Drive (Premier de la journée)...");
                await _backup.BackupDatabaseAsync();
                await _settings.SetSettingAsync("BackupSettings:LastBackupDate", now.ToString("O"));
            }
            else
            {
                _logger.LogInformation("Backup journalier déjà effectué aujourd'hui ({Date}). Skip.", lastBackup.ToShortDateString());
            }
        }
    }
}