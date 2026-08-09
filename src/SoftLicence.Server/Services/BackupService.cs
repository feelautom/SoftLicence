using System.Text;
using System.Text.Json;
using System.Globalization;
using System.Text.RegularExpressions;
using Npgsql;

namespace SoftLicence.Server.Services;

public class BackupService
{
    private const string DatabasePrefix = "softlicence_";
    private static readonly Regex ManagedDatabaseBackupNamePattern = new(
        "^softlicence_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{3}_[0-9a-f]{32}\\.dump$",
        RegexOptions.CultureInvariant);
    private readonly IConfiguration _config;
    private readonly ILogger<BackupService> _logger;
    private readonly SettingsService _settings;
    private readonly IBackupProcessRunner _runner;
    private readonly TimeProvider _timeProvider;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _databaseBackupGate = new(1, 1);

    public BackupService(
        IConfiguration config,
        ILogger<BackupService> logger,
        SettingsService settings,
        IBackupProcessRunner runner,
        TimeProvider timeProvider)
    {
        _config = config;
        _logger = logger;
        _settings = settings;
        _runner = runner;
        _timeProvider = timeProvider;
        _connectionString = _config.GetConnectionString("DefaultConnection") ?? string.Empty;
        if (string.IsNullOrEmpty(_connectionString) && _config["IsIntegrationTest"] != "true")
            throw new InvalidOperationException("Connection String manquante pour PostgreSQL.");
    }

    public BackupService(IConfiguration config, ILogger<BackupService> logger, SettingsService settings)
        : this(config, logger, settings, new BackupProcessRunner(), TimeProvider.System)
    {
    }

    public Task<DbStats> GetDatabaseStatsAsync(string filePath) => Task.FromResult(new DbStats());

    public async Task<DbStats> GetCurrentDatabaseStatsAsync()
    {
        if (_config["IsIntegrationTest"] == "true") return new DbStats();
        var stats = new DbStats();
        try
        {
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync();
            stats.ProductsCount = await GetCountAsync(connection, "Products");
            stats.LicensesCount = await GetCountAsync(connection, "Licenses");
            stats.LogsCount = await GetCountAsync(connection, "AccessLogs");
            stats.TelemetryCount = await GetCountAsync(connection, "TelemetryRecords");
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Erreur stats DB active");
        }
        return stats;
    }

    public async Task UploadKeyPairAsync(string productName, string privateKeyXml, string publicKeyXml)
    {
        if (!await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false)) return;
        var remote = GetRequiredSetting("BackupSettings:RcloneRemote");
        var path = GetRequiredSetting("BackupSettings:KeysBackupPath");
        var safeName = string.Concat(productName.Select(character =>
            char.IsLetterOrDigit(character) || character is '-' or '_' ? character : '_'));
        await UploadBytesAsync(Encoding.UTF8.GetBytes(privateKeyXml), JoinRemote(remote, path, safeName, "PrivateKey.xml"), default);
        await UploadBytesAsync(Encoding.UTF8.GetBytes(publicKeyXml), JoinRemote(remote, path, safeName, "PublicKey.xml"), default);
        _logger.LogInformation("Paire de clés pour {Product} sauvegardée sur Drive.", productName);
    }

    public async Task BackupDatabaseAsync(CancellationToken cancellationToken = default)
    {
        if (!await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false)) return;
        if (_config["IsIntegrationTest"] == "true") return;
        await _databaseBackupGate.WaitAsync(cancellationToken);
        try
        {
            EnsureMinimumFreeSpace();
            var remote = GetRequiredSetting("BackupSettings:RcloneRemote");
            var path = GetRequiredSetting("BackupSettings:DatabaseBackupPath");
            var timestamp = _timeProvider.GetUtcNow().ToString("yyyy-MM-dd_HH-mm-ss-fff", CultureInfo.InvariantCulture);
            var backupName = $"{DatabasePrefix}{timestamp}_{Guid.NewGuid():N}.dump";
            var remoteFile = JoinRemote(remote, path, backupName);
            var timeout = TimeSpan.FromMinutes(Math.Clamp(
                _config.GetValue("BackupSettings:TimeoutMinutes", 45), 1, 180));
            var attempts = Math.Clamp(_config.GetValue("BackupSettings:RetryCount", 3), 1, 5);

            for (var attempt = 1; attempt <= attempts; attempt++)
            {
                var attemptId = Guid.NewGuid().ToString("N");
                var partialFile = remoteFile + $".partial-{attemptId}";
                var finalManifest = remoteFile + ".manifest.json";
                var partialManifest = finalManifest + $".partial-{attemptId}";
                try
                {
                    var result = await _runner.PipeAsync(
                        CreatePostgreSqlSpec("pg_dump", BuildDumpArguments()),
                        new BackupProcessSpec("rclone", ["rcat", partialFile]),
                        timeout,
                        cancellationToken);
                    EnsurePipelineSuccess(result, attempt);
                    if (string.IsNullOrEmpty(result.Sha256))
                        throw new InvalidOperationException("database_backup_hash_missing");
                    await ValidateRemoteAsync(partialFile, result.BytesTransferred, result.Sha256, cancellationToken);
                    EnsureSuccess(await RunRcloneAsync(["moveto", partialFile, remoteFile], cancellationToken), "backup_promotion_failed");

                    var manifest = JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        schema = "softlicence-backup-manifest-v1",
                        file = backupName,
                        sizeBytes = result.BytesTransferred,
                        sha256 = result.Sha256,
                        createdAtUtc = _timeProvider.GetUtcNow().UtcDateTime.ToString("O"),
                        format = "postgresql-custom"
                    });
                    await UploadBytesAsync(manifest, partialManifest, cancellationToken);
                    EnsureSuccess(await RunRcloneAsync(["moveto", partialManifest, finalManifest], cancellationToken), "backup_manifest_promotion_failed");
                    _logger.LogInformation(
                        "Backup PostgreSQL compressé vérifié et promu. Bytes={Bytes}; Attempt={Attempt}",
                        result.BytesTransferred,
                        attempt);
                    try
                    {
                        await ApplyRetentionAsync(remote, path, cancellationToken);
                    }
                    catch (Exception exception) when (exception is not OperationCanceledException)
                    {
                        _logger.LogWarning(exception, "Backup valide conservé, mais application de la rétention échouée.");
                    }
                    return;
                }
                catch (OperationCanceledException)
                {
                    await CleanupRemoteArtifactsAsync([partialFile, partialManifest, remoteFile, finalManifest]);
                    throw;
                }
                catch (Exception exception)
                {
                    await CleanupRemoteArtifactsAsync([partialFile, partialManifest, remoteFile, finalManifest]);
                    if (attempt == attempts)
                    {
                        if (exception is BackupPipelineException)
                            throw;
                        throw new InvalidOperationException("database_backup_failed", exception);
                    }
                    var delay = TimeSpan.FromSeconds(Math.Min(30, 2 * attempt * attempt));
                    _logger.LogWarning("Backup PostgreSQL échoué; retry {NextAttempt}/{Attempts} après {DelaySeconds}s.",
                        attempt + 1, attempts, delay.TotalSeconds);
                    await Task.Delay(delay, cancellationToken);
                }
            }
        }
        finally
        {
            _databaseBackupGate.Release();
        }
    }

    public async Task RestoreDatabaseAsync(string backupFilePath, CancellationToken cancellationToken = default)
    {
        _logger.LogWarning("RESTORE: Démarrage de la procédure PostgreSQL.");
        var tool = GetRestoreTool(backupFilePath);
        var arguments = tool == "pg_restore"
            ? BuildRestoreArguments(backupFilePath)
            : BuildPsqlRestoreArguments(backupFilePath);
        var result = await _runner.RunAsync(
            CreatePostgreSqlSpec(tool, arguments),
            null,
            TimeSpan.FromMinutes(Math.Clamp(_config.GetValue("BackupSettings:RestoreTimeoutMinutes", 90), 1, 360)),
            cancellationToken);
        EnsureSuccess(result, "database_restore_failed");
        _logger.LogInformation("RESTORE: Succès. Redémarrage...");
        await Task.Delay(1000, cancellationToken);
        Environment.Exit(0);
    }

    public async Task RunRcloneAsync(string args)
    {
        var arguments = args.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = await _runner.RunAsync(new("rclone", arguments), null, TimeSpan.FromMinutes(10), default);
        EnsureSuccess(result, "rclone_failed");
    }

    private Task<BackupProcessResult> RunRcloneAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        _runner.RunAsync(new("rclone", arguments), null, TimeSpan.FromMinutes(10), cancellationToken);

    public async Task<(bool Success, string Message)> CheckHealthAsync()
    {
        try
        {
            var timeout = TimeSpan.FromSeconds(30);
            EnsureSuccess(await _runner.RunAsync(new("rclone", ["version"]), null, timeout, default), "rclone_unavailable");
            var remotes = await _runner.RunAsync(new("rclone", ["listremotes"]), null, timeout, default);
            EnsureSuccess(remotes, "rclone_unavailable");
            var configuredRemote = GetRequiredSetting("BackupSettings:RcloneRemote");
            if (!remotes.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Contains(configuredRemote, StringComparer.Ordinal))
                return (false, "Remote configuré absent.");
            return (true, "Rclone opérationnel.");
        }
        catch (Exception exception)
        {
            return (false, exception.Message);
        }
    }

    public async Task<(bool Success, string Message)> TestConnectionAsync()
    {
        var remote = GetRequiredSetting("BackupSettings:RcloneRemote");
        var remoteFile = JoinRemote(remote, "Backups", $"test_{Guid.NewGuid():N}.txt");
        try
        {
            await UploadBytesAsync("Test Cloud"u8.ToArray(), remoteFile, default);
            var deletion = await _runner.RunAsync(new("rclone", ["deletefile", remoteFile]), null, TimeSpan.FromMinutes(2), default);
            EnsureSuccess(deletion, "rclone_test_cleanup_failed");
            return (true, "Test Cloud réussi.");
        }
        catch (Exception exception)
        {
            return (false, exception.Message);
        }
    }

    public async Task<List<BackupFile>> ListBackupsAsync()
    {
        var remote = GetRequiredSetting("BackupSettings:RcloneRemote");
        var result = await _runner.RunAsync(
            new("rclone", ["lsf", remote, "-R", "--files-only", "--format", "pst", "--separator", "|", "--time-format", "RFC3339"]),
            null,
            TimeSpan.FromMinutes(2),
            default);
        EnsureSuccess(result, "backup_list_failed");
        var entries = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(ParseRemoteListingEntry)
            .Where(entry => entry != null)
            .Cast<RemoteListingEntry>()
            .ToList();
        var remotePaths = entries.Select(entry => entry.Path).ToHashSet(StringComparer.Ordinal);
        var list = new List<BackupFile>();
        foreach (var entry in entries)
        {
            var fullPath = entry.Path;
            if (fullPath.Contains(".partial-", StringComparison.Ordinal)
                || fullPath.EndsWith(".manifest.json", StringComparison.Ordinal))
                continue;
            var isDatabase = fullPath.EndsWith(".sql", StringComparison.OrdinalIgnoreCase)
                || fullPath.EndsWith(".dump", StringComparison.OrdinalIgnoreCase)
                || fullPath.EndsWith(".backup", StringComparison.OrdinalIgnoreCase);
            var fileName = Path.GetFileName(fullPath);
            if (isDatabase
                && ManagedDatabaseBackupNamePattern.IsMatch(fileName)
                && !await HasValidPublishedManifestAsync(remote, entry, remotePaths))
                continue;
            list.Add(new()
            {
                Name = fileName,
                Path = fullPath,
                Category = isDatabase ? "Base de données" : "Clé RSA",
                Date = entry.ModifiedAtUtc.UtcDateTime
            });
        }
        return list.OrderByDescending(candidate => candidate.Date).ToList();
    }

    public async Task DownloadBackupAsync(string remotePath, string localPath)
    {
        ValidateRemotePath(remotePath);
        var remote = GetRequiredSetting("BackupSettings:RcloneRemote");
        var result = await _runner.RunAsync(
            new("rclone", ["copyto", remote + remotePath, localPath]),
            null,
            TimeSpan.FromMinutes(60),
            default);
        EnsureSuccess(result, "backup_download_failed");
    }

    private async Task UploadBytesAsync(byte[] bytes, string remoteFile, CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(
            new("rclone", ["rcat", remoteFile]),
            bytes,
            TimeSpan.FromMinutes(5),
            cancellationToken);
        EnsureSuccess(result, "backup_metadata_upload_failed");
    }

    private async Task ValidateRemoteAsync(string remoteFile, long expectedBytes, string expectedSha256, CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(
            new("rclone", ["size", remoteFile, "--json"]),
            null,
            TimeSpan.FromMinutes(2),
            cancellationToken);
        EnsureSuccess(result, "backup_remote_validation_failed");
        using var json = JsonDocument.Parse(result.StandardOutput);
        if (json.RootElement.GetProperty("count").GetInt64() != 1
            || json.RootElement.GetProperty("bytes").GetInt64() != expectedBytes)
            throw new InvalidOperationException("backup_remote_validation_failed");
        var hashResult = await RunRcloneAsync(["hashsum", "SHA-256", "--download", remoteFile], cancellationToken);
        EnsureSuccess(hashResult, "backup_remote_hash_failed");
        var hashLines = hashResult.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var actualHash = hashLines.Length == 1
            ? hashLines[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()
            : null;
        if (!IsLowerHexSha256(expectedSha256)
            || !IsLowerHexSha256(actualHash)
            || !string.Equals(actualHash, expectedSha256, StringComparison.Ordinal))
            throw new InvalidOperationException("backup_remote_hash_mismatch");
    }

    private async Task CleanupRemoteArtifactsAsync(IEnumerable<string> remoteFiles)
    {
        foreach (var remoteFile in remoteFiles.Distinct(StringComparer.Ordinal))
        {
            try
            {
                var result = await _runner.RunAsync(
                    new("rclone", ["deletefile", remoteFile]),
                    null,
                    TimeSpan.FromMinutes(2),
                    CancellationToken.None);
                if (result.ExitCode != 0)
                    _logger.LogWarning("Nettoyage distant incomplet. ExitCode={ExitCode}", result.ExitCode);
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Nettoyage best-effort d'un fragment de backup échoué.");
            }
        }
    }

    private async Task ApplyRetentionAsync(string remote, string path, CancellationToken cancellationToken)
    {
        var retentionDays = Math.Clamp(_config.GetValue("BackupSettings:RetentionDays", 30), 1, 3650);
        var minimumRetained = Math.Clamp(_config.GetValue("BackupSettings:MinimumRetained", 7), 1, 365);
        var remoteDirectory = JoinRemote(remote, path);
        var result = await _runner.RunAsync(
            new("rclone", ["lsf", remoteDirectory, "--files-only", "--format", "pt", "--separator", "|"]),
            null,
            TimeSpan.FromMinutes(2),
            cancellationToken);
        EnsureSuccess(result, "backup_retention_list_failed");
        var cutoff = _timeProvider.GetUtcNow().UtcDateTime.AddDays(-retentionDays);
        var backups = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('|'))
            .Select(parts => new
            {
                Parts = parts,
                Parsed = parts.Length >= 2
                    && DateTimeOffset.TryParse(parts[1], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var date)
                        ? date
                        : (DateTimeOffset?)null
            })
            .Where(candidate => candidate.Parts.Length >= 2
                && candidate.Parts[0].StartsWith(DatabasePrefix, StringComparison.Ordinal)
                && candidate.Parts[0].EndsWith(".dump", StringComparison.OrdinalIgnoreCase)
                && candidate.Parsed.HasValue)
            .Select(candidate => new { Name = candidate.Parts[0], Date = candidate.Parsed!.Value.UtcDateTime })
            .OrderByDescending(candidate => candidate.Date)
            .ToList();
        foreach (var expired in backups.Skip(minimumRetained).Where(candidate => candidate.Date < cutoff))
        {
            var target = JoinRemote(remote, path, expired.Name);
            EnsureSuccess(await _runner.RunAsync(new("rclone", ["deletefile", target]), null, TimeSpan.FromMinutes(2), cancellationToken), "backup_retention_delete_failed");
            var manifestDeletion = await _runner.RunAsync(
                new("rclone", ["deletefile", target + ".manifest.json"]),
                null,
                TimeSpan.FromMinutes(2),
                cancellationToken);
            if (manifestDeletion.ExitCode != 0)
                _logger.LogWarning("Nettoyage du manifeste de rétention incomplet. ExitCode={ExitCode}", manifestDeletion.ExitCode);
        }
    }

    private async Task<bool> HasValidPublishedManifestAsync(
        string remote,
        RemoteListingEntry backup,
        IReadOnlySet<string> remotePaths)
    {
        var manifestPath = backup.Path + ".manifest.json";
        if (!remotePaths.Contains(manifestPath))
            return false;
        try
        {
            var result = await RunRcloneAsync(["cat", JoinRemote(remote, manifestPath)], CancellationToken.None);
            if (result.ExitCode != 0)
                return false;
            using var document = JsonDocument.Parse(result.StandardOutput);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    return false;
            }
            if (!names.SetEquals(["schema", "file", "sizeBytes", "sha256", "createdAtUtc", "format"]))
                return false;
            if (root.GetProperty("schema").GetString() != "softlicence-backup-manifest-v1"
                || root.GetProperty("file").GetString() != Path.GetFileName(backup.Path)
                || root.GetProperty("format").GetString() != "postgresql-custom"
                || !root.GetProperty("sizeBytes").TryGetInt64(out var manifestSize)
                || manifestSize <= 0
                || manifestSize != backup.SizeBytes
                || !IsLowerHexSha256(root.GetProperty("sha256").GetString())
                || !DateTimeOffset.TryParse(root.GetProperty("createdAtUtc").GetString(), CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var createdAt)
                || createdAt.Offset != TimeSpan.Zero)
                return false;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static RemoteListingEntry? ParseRemoteListingEntry(string line)
    {
        var parts = line.TrimEnd('\r').Split('|');
        if (parts.Length != 3
            || string.IsNullOrEmpty(parts[0])
            || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var sizeBytes)
            || sizeBytes < 0
            || !DateTimeOffset.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var modifiedAt))
            return null;
        return new(parts[0], sizeBytes, modifiedAt.ToUniversalTime());
    }

    private static bool IsLowerHexSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private sealed record RemoteListingEntry(string Path, long SizeBytes, DateTimeOffset ModifiedAtUtc);

    private BackupProcessSpec CreatePostgreSqlSpec(string fileName, IReadOnlyList<string> arguments)
    {
        var builder = new NpgsqlConnectionStringBuilder(_connectionString);
        return new(fileName, arguments, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["PGPASSWORD"] = builder.Password ?? string.Empty
        });
    }

    private IReadOnlyList<string> BuildDumpArguments()
    {
        var builder = new NpgsqlConnectionStringBuilder(_connectionString);
        return ["--host", RequireConnectionValue(builder.Host), "--port", builder.Port.ToString(CultureInfo.InvariantCulture),
            "--username", RequireConnectionValue(builder.Username), "--dbname", RequireConnectionValue(builder.Database),
            "--format", "custom", "--compress", "6", "--no-password"];
    }

    private IReadOnlyList<string> BuildRestoreArguments(string path)
    {
        var builder = new NpgsqlConnectionStringBuilder(_connectionString);
        return ["--host", RequireConnectionValue(builder.Host), "--port", builder.Port.ToString(CultureInfo.InvariantCulture),
            "--username", RequireConnectionValue(builder.Username), "--dbname", RequireConnectionValue(builder.Database),
            "--exit-on-error", "--clean", "--if-exists", "--no-owner", "--no-privileges", path];
    }

    private IReadOnlyList<string> BuildPsqlRestoreArguments(string path)
    {
        var builder = new NpgsqlConnectionStringBuilder(_connectionString);
        return ["--host", RequireConnectionValue(builder.Host), "--port", builder.Port.ToString(CultureInfo.InvariantCulture),
            "--username", RequireConnectionValue(builder.Username), "--dbname", RequireConnectionValue(builder.Database),
            "--no-password", "--set", "ON_ERROR_STOP=1", "--file", path];
    }

    private void EnsureMinimumFreeSpace()
    {
        var minimumBytes = Math.Max(0, _config.GetValue<long>("BackupSettings:MinimumFreeSpaceBytes", 1_073_741_824));
        var root = Path.GetPathRoot(Path.GetTempPath());
        if (!string.IsNullOrEmpty(root) && new DriveInfo(root).AvailableFreeSpace < minimumBytes)
            throw new InvalidOperationException("backup_insufficient_free_space");
    }

    private string GetRequiredSetting(string key)
    {
        var value = _config[key];
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))
            throw new InvalidOperationException("backup_configuration_invalid");
        return value;
    }

    private static string JoinRemote(string remote, params string[] segments) =>
        remote + string.Join('/', segments.Select(segment => segment.Trim('/')).Where(segment => segment.Length > 0));

    private static void ValidateRemotePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl) || path.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException("backup_path_invalid", nameof(path));
    }

    private static string GetRestoreTool(string backupFilePath)
    {
        var extension = Path.GetExtension(backupFilePath);
        if (extension.Equals(".sql", StringComparison.OrdinalIgnoreCase)) return "psql";
        if (extension.Equals(".dump", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".backup", StringComparison.OrdinalIgnoreCase)) return "pg_restore";
        throw new ArgumentException("backup_format_unsupported", nameof(backupFilePath));
    }

    private static string RequireConnectionValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))
            throw new InvalidOperationException("backup_connection_configuration_invalid");
        return value;
    }

    private static void EnsureSuccess(BackupProcessResult result, string errorCode)
    {
        if (result.ExitCode != 0)
            throw new InvalidOperationException(errorCode);
    }

    private void EnsurePipelineSuccess(BackupProcessResult result, int attempt)
    {
        if (result.ExitCode == 0 && result.FailureStage == BackupPipelineFailureStage.None)
            return;

        var effectiveFailureStage = result.FailureStage == BackupPipelineFailureStage.None
            ? BackupPipelineFailureStage.Copy
            : result.FailureStage;
        var failureStage = effectiveFailureStage.ToDiagnosticCode();
        _logger.LogError(
            "Backup pipeline failed. ErrorCode={ErrorCode}; Attempt={Attempt}; FailureStage={FailureStage}; ProducerExitCode={ProducerExitCode}; ConsumerExitCode={ConsumerExitCode}; BytesTransferred={BytesTransferred}; DurationMilliseconds={DurationMilliseconds}",
            "database_backup_failed",
            attempt,
            failureStage,
            result.ProducerExitCode,
            result.ConsumerExitCode,
            result.BytesTransferred,
            result.DurationMilliseconds);
        throw new BackupPipelineException(
            effectiveFailureStage,
            result.ProducerExitCode,
            result.ConsumerExitCode,
            result.BytesTransferred,
            result.DurationMilliseconds,
            attempt);
    }

    private static async Task<int> GetCountAsync(NpgsqlConnection connection, string table)
    {
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT COUNT(*) FROM \"{table}\"";
            return Convert.ToInt32(await command.ExecuteScalarAsync());
        }
        catch
        {
            return 0;
        }
    }
}

public sealed class BackupPipelineException : InvalidOperationException
{
    internal BackupPipelineException(
        BackupPipelineFailureStage failureStage,
        int? producerExitCode,
        int? consumerExitCode,
        long bytesTransferred,
        long durationMilliseconds,
        int attempt)
        : base("database_backup_failed")
    {
        FailureStage = failureStage.ToDiagnosticCode();
        ProducerExitCode = producerExitCode;
        ConsumerExitCode = consumerExitCode;
        BytesTransferred = bytesTransferred;
        DurationMilliseconds = durationMilliseconds;
        Attempt = attempt;
    }

    public string FailureStage { get; }
    public int? ProducerExitCode { get; }
    public int? ConsumerExitCode { get; }
    public long BytesTransferred { get; }
    public long DurationMilliseconds { get; }
    public int Attempt { get; }
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
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public DateTime Date { get; set; }
}
