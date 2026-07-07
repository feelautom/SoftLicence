using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public class SettingsService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<SettingsService> _logger;

    public SettingsService(IDbContextFactory<LicenseDbContext> dbFactory, IConfiguration config, ILogger<SettingsService> logger)
    {
        _dbFactory = dbFactory;
        _config = config;
        _logger = logger;
    }

    public async Task<string?> GetSettingAsync(string key, string? defaultValue = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var setting = await db.SystemSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Key == key);
        
        if (setting == null)
        {
            // Fallback to appsettings if not in DB
            return _config[key] ?? defaultValue;
        }

        return setting.Value;
    }

    public async Task<bool> GetBoolSettingAsync(string key, bool defaultValue = false)
    {
        var val = await GetSettingAsync(key);
        if (string.IsNullOrEmpty(val)) return defaultValue;
        return bool.TryParse(val, out var b) ? b : defaultValue;
    }

    public async Task SetSettingAsync(string key, string value)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var now = DateTime.UtcNow;

        // PostgreSQL UPSERT — avoids race condition with concurrent canary pings
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO \"SystemSettings\" (\"Key\", \"Value\", \"LastUpdated\") VALUES ({key}, {value}, {now}) ON CONFLICT (\"Key\") DO UPDATE SET \"Value\" = {value}, \"LastUpdated\" = {now}");

        _logger.LogInformation("Setting '{Key}' updated to '{Value}'", key, value);
    }
}
