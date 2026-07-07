using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/health")]
public class HealthController : ControllerBase
{
    private const string CoreDllTamperedTrigger = "IntegrityCheck_CoreDllTampered";
    private const string TrustedDevCanaryHardwareIdsSetting = "TrustedDevCanaryHardwareIds";
    private static readonly TimeSpan DevCanaryQuarantineDuration = TimeSpan.FromHours(2);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<HealthController> _logger;
    private readonly SecurityService _security;
    private readonly SettingsService _settings;
    private readonly EmailService _email;

    // In-memory email dedup cache (much faster than DB-based SettingsService)
    private static readonly ConcurrentDictionary<string, DateTime> _emailCache = new();
    private static readonly TimeSpan EmailCooldown = TimeSpan.FromMinutes(15);

    public HealthController(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<HealthController> logger, SecurityService security, SettingsService settings, EmailService email)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _security = security;
        _settings = settings;
        _email = email;
    }

    /// <summary>
    /// Looks like a health check endpoint. Actually receives canary pings
    /// from clients with compromised integrity.
    /// </summary>
    [HttpPost("ping")]
    public async Task<IActionResult> Ping([FromBody] CanaryPingRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.HardwareId)) return Ok(new { status = "ok" });

        var ip = Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim()
            ?? HttpContext.Connection.RemoteIpAddress?.ToString();

        // Clamp severity to valid range
        var severity = Math.Clamp(req.Severity, 1, 3);

        // Server-side override: folder-only detections are always Info (1),
        // regardless of client version (older clients may send 3)
        bool isFolderOnlyEarly = !string.IsNullOrEmpty(req.Details)
            && req.Details.Contains("(folder)")
            && !req.Details.Contains(".exe");
        if (isFolderOnlyEarly && severity > 1)
            severity = 1;

        try
        {
            using var db = await _dbFactory.CreateDbContextAsync();

            // Resolve product
            var product = await db.Products.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Name.ToLower() == "tiaconnect");

            // Already banned: increment repeat counter on existing alert, skip email/ban
            var alreadyBanned = product != null && await _security.IsHardwareIdBannedAsync(req.HardwareId, product.Id);
            if (alreadyBanned)
            {
                _logger.LogDebug("CANARY PING (already banned): {Trigger} from {HardwareId} [severity={Severity}]", req.Trigger, req.HardwareId, severity);

                // Find existing alert with same HWID + Trigger (ignore Details variations for grouping)
                var existing = await db.CanaryAlerts
                    .Where(a => a.HardwareId == req.HardwareId && a.Trigger == req.Trigger)
                    .OrderByDescending(a => a.ReceivedAt)
                    .FirstOrDefaultAsync();

                if (existing != null)
                {
                    existing.RepeatCount++;
                    existing.LastSeenAt = DateTime.UtcNow;
                    // Update severity if higher
                    if (severity > existing.Severity) existing.Severity = severity;
                    ApplyAuditContext(existing, req, "already_banned_repeat");
                }
                else
                {
                    var repeatedAlert = new CanaryAlert
                    {
                        HardwareId = req.HardwareId,
                        MachineName = req.MachineName,
                        UserName = req.UserName,
                        ClientIp = ip,
                        AppVersion = req.AppVersion,
                        Trigger = req.Trigger,
                        Details = req.Details,
                        Severity = severity,
                        OsVersion = req.OsVersion,
                        ProductId = product?.Id
                    };
                    ApplyAuditContext(repeatedAlert, req, "already_banned_repeat");
                    db.CanaryAlerts.Add(repeatedAlert);
                }
                await db.SaveChangesAsync();

                var defaultLevel2 = await _settings.GetSettingAsync("CanaryDefaultLevel", "2");
                var hwidLevel2 = await _settings.GetSettingAsync($"CanaryLevel_{req.HardwareId}", null);
                var level = hwidLevel2 != null && int.TryParse(hwidLevel2, out var hl2) ? hl2
                    : int.TryParse(defaultLevel2, out var dl2) ? dl2 : 2;

                return Ok(new { status = "ok", p = new SecurityPolicy { Level = level, IntervalMinutes = 60, CollectProcesses = false, CollectNetwork = false } });
            }

            // Dedup: for folder-only detections, increment existing alert instead of creating new rows
            bool isFolderOnly = !string.IsNullOrEmpty(req.Details)
                && req.Details.Contains("(folder)")
                && !req.Details.Contains(".exe");

            if (isFolderOnly)
            {
                var existing = await db.CanaryAlerts
                    .Where(a => a.HardwareId == req.HardwareId && a.Trigger == req.Trigger)
                    .OrderByDescending(a => a.ReceivedAt)
                    .FirstOrDefaultAsync();

                if (existing != null)
                {
                    existing.RepeatCount++;
                    existing.LastSeenAt = DateTime.UtcNow;
                    if (severity > existing.Severity) existing.Severity = severity;
                    ApplyAuditContext(existing, req, "folder_only_repeat");
                    await db.SaveChangesAsync();

                    _logger.LogDebug("CANARY PING (folder-only dedup): {Trigger} from {HardwareId} [repeat={Count}]",
                        req.Trigger, req.HardwareId, existing.RepeatCount);

                    var defaultLevel3 = await _settings.GetSettingAsync("CanaryDefaultLevel", "2");
                    var hwidLevel3 = await _settings.GetSettingAsync($"CanaryLevel_{req.HardwareId}", null);
                    var level3 = hwidLevel3 != null && int.TryParse(hwidLevel3, out var hl3) ? hl3
                        : int.TryParse(defaultLevel3, out var dl3) ? dl3 : 2;

                    return Ok(new { status = "ok", p = new SecurityPolicy { Level = level3, IntervalMinutes = 60, CollectProcesses = false, CollectNetwork = false } });
                }
            }

            // Dedup: same HWID + Trigger + Details → increment RepeatCount instead of creating a new row
            var existingAlert = await db.CanaryAlerts
                .Where(a => a.HardwareId == req.HardwareId && a.Trigger == req.Trigger && a.Details == req.Details)
                .OrderByDescending(a => a.ReceivedAt)
                .FirstOrDefaultAsync();

            CanaryAlert alert;
            bool isNewAlert;

            if (existingAlert != null)
            {
                existingAlert.RepeatCount++;
                existingAlert.LastSeenAt = DateTime.UtcNow;
                if (severity > existingAlert.Severity) existingAlert.Severity = severity;
                if (!string.IsNullOrEmpty(ip)) existingAlert.ClientIp = ip;
                if (!string.IsNullOrEmpty(req.AppVersion)) existingAlert.AppVersion = req.AppVersion;
                alert = existingAlert;
                ApplyAuditContext(alert, req, "repeat");
                isNewAlert = false;
            }
            else
            {
                alert = new CanaryAlert
                {
                    HardwareId = req.HardwareId,
                    MachineName = req.MachineName,
                    UserName = req.UserName,
                    ClientIp = ip,
                    AppVersion = req.AppVersion,
                    Trigger = req.Trigger,
                    Details = req.Details,
                    Severity = severity,
                    OsVersion = req.OsVersion,
                    ProductId = product?.Id
                };
                ApplyAuditContext(alert, req, "recorded");
                db.CanaryAlerts.Add(alert);
                isNewAlert = true;
            }

            await db.SaveChangesAsync();

            if (isNewAlert)
            {
                if (severity >= 3)
                    _logger.LogCritical("CANARY ALERT [sev={Severity}]: {Trigger} from {HardwareId} ({MachineName}, v{Version}, IP: {Ip})",
                        severity, req.Trigger, req.HardwareId, req.MachineName, req.AppVersion, ip);
                else if (severity >= 2)
                    _logger.LogWarning("CANARY ALERT [sev={Severity}]: {Trigger} from {HardwareId} ({MachineName}, v{Version}, IP: {Ip})",
                        severity, req.Trigger, req.HardwareId, req.MachineName, req.AppVersion, ip);
                else
                    _logger.LogInformation("CANARY ALERT [sev={Severity}]: {Trigger} from {HardwareId} ({MachineName}, v{Version}, IP: {Ip})",
                        severity, req.Trigger, req.HardwareId, req.MachineName, req.AppVersion, ip);
            }
            else
                _logger.LogDebug("CANARY REPEAT [sev={Severity}]: {Trigger} from {HardwareId} [repeat={Count}]",
                    severity, req.Trigger, req.HardwareId, alert.RepeatCount);

            // Auto-ban ONLY for Critical severity (kernel-level detections = zero false positives)
            // Severity 1 (Info/heuristic) and 2 (Warning) are recorded but NOT banned.
            // TEMPORARY (until next T-IA Connect release lowers folder-only severity to 1):
            // Skip auto-ban when details contain ONLY folder detections (no active process).
            // isFolderOnly already computed above for dedup
            bool isNewBan = false;
            if (severity >= 3 && product != null && !isFolderOnly)
            {
                try
                {
                    var allowDevTreatment = await IsServerTrustedDevCanaryAsync(db, req, product.Id);
                    if (allowDevTreatment)
                    {
                        alert.ServerAction = "dev_quarantine";
                        await db.SaveChangesAsync();

                        await _security.BanHardwareIdAsync(
                            req.HardwareId,
                            $"Dev canary quarantine: {req.Trigger} (machine: {req.MachineName}, user: {req.UserName})",
                            product.Id,
                            DateTime.UtcNow.Add(DevCanaryQuarantineDuration),
                            banCategory: BannedHardwareId.Categories.DevCanaryQuarantine);

                        _logger.LogWarning(
                            "CANARY DEV QUARANTINE: {HardwareId} temporarily quarantined without cascade (severity={Severity}, trigger={Trigger})",
                            req.HardwareId,
                            severity,
                            req.Trigger);
                    }
                    else
                    {
                        alert.ServerAction = "permanent_ban";
                        await db.SaveChangesAsync();

                        await _security.BanHardwareIdAsync(req.HardwareId,
                            $"Canary: {req.Trigger} (machine: {req.MachineName}, user: {req.UserName})",
                            product.Id);
                        isNewBan = true;
                        _logger.LogCritical("CANARY AUTO-BAN: {HardwareId} banned (severity={Severity}, trigger={Trigger})",
                            req.HardwareId, severity, req.Trigger);

                        // Cascade: revoke linked license and ban all other seats.
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                using var cascadeDb = await _dbFactory.CreateDbContextAsync();
                                var linkedLicense = await cascadeDb.Licenses
                                    .Include(l => l.Seats)
                                    .FirstOrDefaultAsync(l => l.ProductId == product.Id
                                        && (l.HardwareId == req.HardwareId || l.Seats.Any(s => s.HardwareId == req.HardwareId)));

                                if (linkedLicense == null)
                                {
                                    _logger.LogCritical("CANARY CASCADE: no linked license found for {HardwareId} (trigger={Trigger})",
                                        req.HardwareId, req.Trigger);
                                    return;
                                }

                                if (linkedLicense.IsActive)
                                {
                                    linkedLicense.IsActive = false;
                                    linkedLicense.RevokedAt = DateTime.UtcNow;
                                    linkedLicense.RevocationReason = $"Canary: {req.Trigger} — auto-revoked";
                                    _logger.LogCritical("CANARY CASCADE: license {LicenseId} revoked for {HardwareId} (trigger={Trigger})",
                                        linkedLicense.Id, req.HardwareId, req.Trigger);
                                }

                                foreach (var seat in linkedLicense.Seats.Where(s => s.HardwareId != req.HardwareId))
                                {
                                    await _security.BanHardwareIdAsync(
                                        seat.HardwareId,
                                        $"Canary cascade: {req.Trigger} (linked seat of {req.HardwareId})",
                                        product.Id,
                                        banCategory: BannedHardwareId.Categories.Piracy);

                                    _logger.LogCritical("CANARY CASCADE: linked seat {SeatHardwareId} banned from license {LicenseId} (source={SourceHardwareId}, trigger={Trigger})",
                                        seat.HardwareId, linkedLicense.Id, req.HardwareId, req.Trigger);
                                }

                                await cascadeDb.SaveChangesAsync();
                            }
                            catch (Exception cascadeEx)
                            {
                                _logger.LogError(cascadeEx, "CANARY CASCADE failed for {HardwareId} (trigger={Trigger})",
                                    req.HardwareId, req.Trigger);
                            }
                        });
                    }
                }
                catch (Exception banEx)
                {
                    _logger.LogWarning(banEx, "Ban race condition (already banned by concurrent ping)");
                }
            }

            // Determine email status label
            string banStatus = isNewBan ? "NEW_BAN" : (severity >= 3 ? "CRITICAL" : (severity >= 2 ? "WARNING" : "INFO"));

            // Notify admin by email - in-memory dedup (15 min cooldown per HWID+Trigger)
            // Severity 1 (Info) = no email, just log. Severity 2+ = email.
            if (severity >= 2)
            {
                var cacheKey = $"{req.HardwareId}_{req.Trigger}";
                var shouldNotify = !_emailCache.TryGetValue(cacheKey, out var lastNotif)
                    || DateTime.UtcNow - lastNotif >= EmailCooldown;

                if (shouldNotify)
                {
                    _emailCache[cacheKey] = DateTime.UtcNow;
                    _logger.LogWarning("CANARY EMAIL: Sending [{Status}] for {Trigger} from {HardwareId}...", banStatus, req.Trigger, req.HardwareId);
                    try
                    {
                        await _email.SendCanaryAlertEmailAsync(
                            req.Trigger, req.HardwareId, req.MachineName, req.UserName,
                            ip, req.AppVersion, req.Details, severity, isNewBan,
                            req.OsVersion, req.DebuggerAttached);
                        _logger.LogWarning("CANARY EMAIL: Sent successfully for {HardwareId}", req.HardwareId);
                    }
                    catch (Exception emailEx)
                    {
                        _logger.LogError(emailEx, "CANARY EMAIL FAILED for {HardwareId}", req.HardwareId);
                    }
                }
            }
            else
            {
                _logger.LogInformation("CANARY INFO (no email): {Trigger} from {HardwareId} [severity=1]", req.Trigger, req.HardwareId);
            }

            // Build security policy response
            var defaultLevel = await _settings.GetSettingAsync("CanaryDefaultLevel", "2");
            var policy = new SecurityPolicy
            {
                Level = int.TryParse(defaultLevel, out var l) ? l : 2,
                IntervalMinutes = severity >= 3 ? 5 : 15,
                CollectProcesses = severity >= 2,
                CollectNetwork = severity >= 2
            };

            // Check if there's a specific policy for this HWID
            var hwidLevel = await _settings.GetSettingAsync($"CanaryLevel_{req.HardwareId}", null);
            if (hwidLevel != null && int.TryParse(hwidLevel, out var hl))
            {
                policy.Level = hl;
            }

            return Ok(new { status = "ok", p = policy });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Canary ping processing failed");
            return Ok(new { status = "ok" });
        }
    }

    private async Task<bool> IsServerTrustedDevCanaryAsync(LicenseDbContext db, CanaryPingRequest req, Guid productId)
    {
        if (!string.Equals(req.Trigger, CoreDllTamperedTrigger, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!IsCoherentLocalDevContext(req))
            return false;

        if (!await IsTrustedDevHardwareIdAsync(req.HardwareId))
            return false;

        return await HasInternalDevLicenseContextAsync(db, req.HardwareId, productId);
    }

    private async Task<bool> IsTrustedDevHardwareIdAsync(string hardwareId)
    {
        var raw = await _settings.GetSettingAsync(TrustedDevCanaryHardwareIdsSetting, "") ?? "";
        return raw
            .Split(new[] { ',', ';', '\n', '\r', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => string.Equals(value, hardwareId, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsCoherentLocalDevContext(CanaryPingRequest req)
    {
        var buildConfiguration = req.BuildConfiguration?.Trim();
        var hasDebugBuild = string.Equals(buildConfiguration, "Debug", StringComparison.OrdinalIgnoreCase)
            || string.Equals(buildConfiguration, "Development", StringComparison.OrdinalIgnoreCase);

        var paths = new[] { req.BaseDirectory, req.ProcessPath, req.AssemblyLocation }
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path!.Replace('/', '\\'))
            .ToList();

        var hasLocalBuildPath = paths.Any(path =>
            path.Contains("\\Build\\Debug\\", StringComparison.OrdinalIgnoreCase)
            || path.Contains("\\bin\\Debug\\", StringComparison.OrdinalIgnoreCase)
            || path.Contains("\\obj\\", StringComparison.OrdinalIgnoreCase));

        return hasDebugBuild && hasLocalBuildPath;
    }

    private static async Task<bool> HasInternalDevLicenseContextAsync(LicenseDbContext db, string hardwareId, Guid productId)
    {
        var now = DateTime.UtcNow;
        var rows = await db.Licenses.AsNoTracking()
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Where(l => l.ProductId == productId
                && l.IsActive
                && (l.ExpirationDate == null || l.ExpirationDate > now)
                && (l.HardwareId == hardwareId || l.Seats.Any(s => s.HardwareId == hardwareId && s.IsActive)))
            .Select(l => new
            {
                l.CustomerEmail,
                TypeSlug = l.Type != null ? l.Type.Slug : "",
                TypeName = l.Type != null ? l.Type.Name : ""
            })
            .ToListAsync();

        return rows.Any(row =>
            IsInternalEmail(row.CustomerEmail)
            || HasInternalDevTypeMarker(row.TypeSlug)
            || HasInternalDevTypeMarker(row.TypeName));
    }

    private static bool IsInternalEmail(string? email) =>
        !string.IsNullOrWhiteSpace(email)
        && (email.EndsWith("@EXAMPLE.COM", StringComparison.OrdinalIgnoreCase)
            || email.EndsWith("@feelautom.com", StringComparison.OrdinalIgnoreCase));

    private static bool HasInternalDevTypeMarker(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return value.Contains("DEV", StringComparison.OrdinalIgnoreCase)
            || value.Contains("INTERNAL", StringComparison.OrdinalIgnoreCase)
            || value.Contains("TEST", StringComparison.OrdinalIgnoreCase)
            || value.Contains("RESELLER", StringComparison.OrdinalIgnoreCase)
            || value.Contains("EVALDEMO", StringComparison.OrdinalIgnoreCase);
    }

    private static void ApplyAuditContext(CanaryAlert alert, CanaryPingRequest req, string fallbackAction)
    {
        alert.BuildConfiguration = Truncate(req.BuildConfiguration, 32);
        alert.BaseDirectory = Truncate(req.BaseDirectory, 500);
        alert.ProcessPath = Truncate(req.ProcessPath, 500);
        alert.AssemblyLocation = Truncate(req.AssemblyLocation, 500);
        alert.IsLocalDevBuild = req.IsLocalDevBuild;
        alert.LocalDevBuildReason = Truncate(req.LocalDevBuildReason, 500);
        alert.BinaryFingerprintsJson = BuildBinaryFingerprintsJson(req);
        alert.ServerAction ??= fallbackAction;
    }

    private static string? BuildBinaryFingerprintsJson(CanaryPingRequest req)
    {
        var fingerprints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        AddFingerprint(fingerprints, "FP_EXE", req.FpExe);
        AddFingerprint(fingerprints, "FP_DLL", req.FpDll);
        AddFingerprint(fingerprints, "FP_CORE", req.FpCore);

        if (req.BinaryFingerprints != null)
        {
            foreach (var (key, value) in req.BinaryFingerprints)
            {
                if (string.Equals(key, "FP_EXE", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(key, "FP_DLL", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(key, "FP_CORE", StringComparison.OrdinalIgnoreCase))
                {
                    AddFingerprint(fingerprints, key.ToUpperInvariant(), value);
                }
            }
        }

        return fingerprints.Count == 0
            ? null
            : JsonSerializer.Serialize(fingerprints);
    }

    private static void AddFingerprint(Dictionary<string, string> fingerprints, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            fingerprints[key] = value.Trim();
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value;

        return value[..maxLength];
    }
}
