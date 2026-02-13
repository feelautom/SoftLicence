using System.Diagnostics;
using Npgsql;

namespace SoftLicence.Server.Services;

public class BackupService
{
    private readonly IConfiguration _config;
    private readonly ILogger<BackupService> _logger;
    private readonly SettingsService _settings;
    private readonly string _connectionString;

    public BackupService(IConfiguration config, ILogger<BackupService> logger, SettingsService settings)
    {
        _config = config;
        _logger = logger;
        _settings = settings;
        _connectionString = _config.GetConnectionString("DefaultConnection") ?? "";
        
        if (string.IsNullOrEmpty(_connectionString) && _config["IsIntegrationTest"] != "true")
        {
             throw new Exception("Connection String manquante pour PostgreSQL.");
        }
    }

    public async Task<DbStats> GetDatabaseStatsAsync(string filePath)
    {
        // Pour PostgreSQL (fichier .sql), l'analyse statique est complexe sans import.
        // On retourne des stats vides ou on pourrait parser le texte pour estimer.
        // Pour l'instant, on se concentre sur la restauration pure.
        return await Task.FromResult(new DbStats());
    }

    public async Task<DbStats> GetCurrentDatabaseStatsAsync()
    {
        if (_config["IsIntegrationTest"] == "true") return new DbStats();

        var stats = new DbStats();
        try {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            stats.ProductsCount = await GetCount(conn, "Products");
            stats.LicensesCount = await GetCount(conn, "Licenses");
            stats.LogsCount = await GetCount(conn, "AccessLogs");
            stats.TelemetryCount = await GetCount(conn, "TelemetryRecords");
        } catch (Exception ex) { _logger.LogError(ex, "Erreur stats DB active"); }
        return stats;
    }

    private async Task<int> GetCount(NpgsqlConnection conn, string table)
    {
        try {
            var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT COUNT(*) FROM \"{table}\"";
            var result = await cmd.ExecuteScalarAsync();
            return Convert.ToInt32(result);
        } catch { return 0; }
    }

    public async Task UploadKeyPairAsync(string productName, string privateKeyXml, string publicKeyXml)
    {
        if (!await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false)) return;

        var remote = _config["BackupSettings:RcloneRemote"];
        var path = _config["BackupSettings:KeysBackupPath"];
        var safeName = productName.Replace(" ", "_");
        
        var tempPriv = Path.Combine(Path.GetTempPath(), $"priv_{safeName}_{Guid.NewGuid():N}.xml");
        var tempPub = Path.Combine(Path.GetTempPath(), $"pub_{safeName}_{Guid.NewGuid():N}.xml");

        try
        {
            await File.WriteAllTextAsync(tempPriv, privateKeyXml);
            await RunRcloneAsync($"copyto \"{tempPriv}\" \"{remote}{path}/{safeName}/PrivateKey.xml\"");

            await File.WriteAllTextAsync(tempPub, publicKeyXml);
            await RunRcloneAsync($"copyto \"{tempPub}\" \"{remote}{path}/{safeName}/PublicKey.xml\"");

            _logger.LogInformation("Paire de clés pour {Product} sauvegardée sur Drive.", productName);
        }
        catch (Exception ex) { _logger.LogError(ex, "Erreur sauvegarde clés Cloud."); }
        finally
        {
            if (File.Exists(tempPriv)) File.Delete(tempPriv);
            if (File.Exists(tempPub)) File.Delete(tempPub);
        }
    }

    public async Task BackupDatabaseAsync()
    {
        if (!await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false)) return;
        if (_config["IsIntegrationTest"] == "true") return;

        var remote = _config["BackupSettings:RcloneRemote"];
        var path = _config["BackupSettings:DatabaseBackupPath"];
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm");
        
        string backupName = $"softlicence_{timestamp}.sql";
        string tempPath = Path.Combine(Path.GetTempPath(), backupName);

        try
        {
            var builder = new NpgsqlConnectionStringBuilder(_connectionString);
            var startInfo = new ProcessStartInfo
            {
                FileName = "pg_dump",
                Arguments = $"-h {builder.Host} -p {builder.Port} -U {builder.Username} -d {builder.Database} -F p -f \"{tempPath}\"",
                RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            };
            startInfo.EnvironmentVariables["PGPASSWORD"] = builder.Password;
            using var proc = Process.Start(startInfo);
            await proc!.WaitForExitAsync();
            if (proc.ExitCode != 0) throw new Exception(await proc.StandardError.ReadToEndAsync());

            await RunRcloneAsync($"copy \"{tempPath}\" \"{remote}{path}\"");
            _logger.LogInformation("Backup PostgreSQL réussi.");
        }
        catch (Exception ex) { _logger.LogError(ex, "Erreur backup Cloud."); throw; }
        finally { if (File.Exists(tempPath)) File.Delete(tempPath); }
    }

    public async Task RestoreDatabaseAsync(string tempFilePath)
    {
        _logger.LogWarning("RESTORE: Démarrage de la procédure PostgreSQL.");

        try
        {
            var builder = new NpgsqlConnectionStringBuilder(_connectionString);
            var startInfo = new ProcessStartInfo
            {
                FileName = "psql",
                Arguments = $"-h {builder.Host} -p {builder.Port} -U {builder.Username} -d {builder.Database} -f \"{tempFilePath}\"",
                RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            };
            startInfo.EnvironmentVariables["PGPASSWORD"] = builder.Password;
            using var proc = Process.Start(startInfo);
            await proc!.WaitForExitAsync();
            if (proc.ExitCode != 0) throw new Exception(await proc.StandardError.ReadToEndAsync());

            _logger.LogInformation("RESTORE: Succès. Redémarrage...");
            await Task.Delay(1000);
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RESTORE: Échec.");
            throw;
        }
    }

    public async Task RunRcloneAsync(string args)
    {
        var startInfo = new ProcessStartInfo { FileName = "rclone", Arguments = args, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        using var process = Process.Start(startInfo);
        if (process == null) throw new Exception("rclone non trouvé.");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new Exception(await process.StandardError.ReadToEndAsync());
    }

    public async Task<(bool Success, string Message)> CheckHealthAsync()
    {
        try
        {
            var startInfo = new ProcessStartInfo { FileName = "rclone", Arguments = "version", UseShellExecute = false, CreateNoWindow = true };
            using var p1 = Process.Start(startInfo);
            if (p1 == null) return (false, "rclone absent.");
            await p1.WaitForExitAsync();

            var remote = _config["BackupSettings:RcloneRemote"]?.Replace(":", "");
            var startInfo2 = new ProcessStartInfo { FileName = "rclone", Arguments = "listremotes", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p2 = Process.Start(startInfo2);
            var output = await p2!.StandardOutput.ReadToEndAsync();
            await p2.WaitForExitAsync();

            if (!output.Contains(remote ?? "")) return (false, $"Remote '{remote}' absent.");
            return (true, "Rclone opérationnel.");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<(bool Success, string Message)> TestConnectionAsync()
    {
        var remote = _config["BackupSettings:RcloneRemote"];
        var testFile = Path.Combine(Path.GetTempPath(), "test_cloud.txt");
        try
        {
            await File.WriteAllTextAsync(testFile, "Test Cloud");
            await RunRcloneAsync($"copyto \"{testFile}\" \"{remote}Backups/test_connection.txt\"");
            await RunRcloneAsync($"deletefile \"{remote}Backups/test_connection.txt\"");
            return (true, "Test Cloud réussi.");
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally { if (File.Exists(testFile)) File.Delete(testFile); }
    }

    public async Task<List<BackupFile>> ListBackupsAsync()
    {
        var remote = _config["BackupSettings:RcloneRemote"];
        var list = new List<BackupFile>();
        try
        {
            var startInfo = new ProcessStartInfo { FileName = "rclone", Arguments = $"lsf \"{remote}\" -R --format \"pt\" --separator \"|\"", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var process = Process.Start(startInfo);
            var output = await process!.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split('|');
                if (parts.Length >= 2)
                {
                    var fullPath = parts[0].Trim();
                    if (fullPath.EndsWith("/")) continue;
                    list.Add(new BackupFile { 
                        Name = Path.GetFileName(fullPath), Path = fullPath, 
                        Category = fullPath.EndsWith(".sql") ? "Base de données" : "Clé RSA",
                        Date = DateTime.TryParse(parts[1], out var dt) ? dt : DateTime.MinValue 
                    });
                }
            }
        }
        catch (Exception ex) { _logger.LogError(ex, "Erreur listing backups."); throw; }
        return list.OrderByDescending(b => b.Date).ToList();
    }

    public async Task DownloadBackupAsync(string remotePath, string localPath)
    {
        var remote = _config["BackupSettings:RcloneRemote"];
        await RunRcloneAsync($"copyto \"{remote}{remotePath}\" \"{localPath}\"");
    }
}

public class DbStats
{
    public int ProductsCount { get; set; }
    public int LicensesCount { get; set; }
    public int LogsCount { get; set; }
    public int TelemetryCount { get; set; }
    public double FileSizeMb { get; set; }
}

public class BackupFile
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Category { get; set; } = "";
    public DateTime Date { get; set; }
}