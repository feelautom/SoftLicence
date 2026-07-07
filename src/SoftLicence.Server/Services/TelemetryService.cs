using System.Text.Json;
using System.Net.Http.Json;
using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public class TelemetryService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<TelemetryService> _logger;
    private readonly GeoIpService _geoIp;
    private readonly IHttpClientFactory _httpFactory;
    private readonly FingerprintService _fingerprintService;
    private readonly SecurityService _security;
    private readonly SettingsService _settings;
    private readonly CertPinningBugTraceAlertService? _certPinningBugTraceAlerts;
    private readonly FreemiumAbuseBugTraceAlertService? _freemiumAbuseBugTraceAlerts;
    private static readonly ConcurrentDictionary<string, DateTime> _certPinningAlertCache = new();
    private static readonly TimeSpan CertPinningAlertCooldown = TimeSpan.FromMinutes(15);
    private const string DefaultCertPinningAlertUrl = "https://ntfy.websitedev.fr/vps-check-tia-pinned-certs";

    public TelemetryService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<TelemetryService> logger,
        GeoIpService geoIp,
        IHttpClientFactory httpFactory,
        FingerprintService fingerprintService,
        SecurityService security,
        SettingsService settings,
        CertPinningBugTraceAlertService? certPinningBugTraceAlerts = null,
        FreemiumAbuseBugTraceAlertService? freemiumAbuseBugTraceAlerts = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _geoIp = geoIp;
        _httpFactory = httpFactory;
        _fingerprintService = fingerprintService;
        _security = security;
        _settings = settings;
        _certPinningBugTraceAlerts = certPinningBugTraceAlerts;
        _freemiumAbuseBugTraceAlerts = freemiumAbuseBugTraceAlerts;
    }

    public async Task SaveEventAsync(TelemetryEventRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;

        var record = new TelemetryRecord
        {
            Timestamp = DateTime.UtcNow,
            HardwareId = req.HardwareId,
            ClientIp = ip,
            Isp = geo?.Isp,
            AppName = req.AppName,
            Version = req.Version,
            EventName = req.EventName,
            Type = TelemetryType.Event,
            ProductId = productId
        };

        record.EventData = new TelemetryEvent
        {
            PropertiesJson = req.Properties != null ? JsonSerializer.Serialize(req.Properties) : null
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        MaybeAlertCertPinningFailure(req, ip, geo?.Isp);
        MaybeCreateCertPinningBugTraceTicket(productId, req, ip, geo?.Isp);
        MaybeCreateFreemiumAbuseBugTraceTicket(productId, req);

        // Mise à jour du flag uninstall sur la licence (best-effort)
        bool isUninstall = req.EventName != null && req.EventName.Contains("ninstall", StringComparison.OrdinalIgnoreCase);
        bool isStartup = req.EventName != null && req.EventName.StartsWith("Startup_", StringComparison.OrdinalIgnoreCase);
        if ((isUninstall || isStartup) && productId.HasValue)
        {
            try
            {
                var hwId = req.HardwareId;
                var lic = await db.Licenses.FirstOrDefaultAsync(l =>
                    l.ProductId == productId.Value && (
                        l.HardwareId == hwId ||
                        db.LicenseSeats.Any(s => s.LicenseId == l.Id && s.HardwareId == hwId)));
                if (lic != null)
                {
                    if (isUninstall)
                    {
                        lic.HasUninstallEvent = true;
                        lic.LastUninstallAt = DateTime.UtcNow;
                    }
                    else // Startup = réinstallation
                    {
                        lic.HasUninstallEvent = false;
                        lic.LastUninstallAt = null;
                    }
                    await db.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to update uninstall flag for {HardwareId}", req.HardwareId);
            }
        }

        // Extract FP_* fingerprints from Startup events and upsert (best-effort, BEFORE auto-ban)
        Dictionary<string, string>? fingerprints = null;
        if (req.EventName != null && req.EventName.StartsWith("Startup_") && req.Properties != null)
        {
            try
            {
                fingerprints = req.Properties
                    .Where(kv => kv.Key.StartsWith("FP_"))
                    .ToDictionary(kv => kv.Key, kv => kv.Value);
                if (fingerprints.Count > 0)
                    await _fingerprintService.UpsertFingerprintAsync(req.HardwareId, fingerprints);
                else
                    fingerprints = null;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to upsert fingerprints for {HardwareId}", req.HardwareId);
            }
        }

        // Binary hash integrity check (FP_EXE, FP_DLL, FP_CORE) — baseline auto + ban on mismatch
        if (fingerprints != null && fingerprints.Count > 0 && productId.HasValue && !string.IsNullOrEmpty(req.Version))
        {
            try
            {
                var binaryKeys = fingerprints.Keys
                    .Where(k => k == "FP_EXE" || k == "FP_DLL" || k == "FP_CORE")
                    .ToList();

                if (binaryKeys.Count > 0)
                {
                    var approved = await db.ApprovedBinaries.AsNoTracking()
                        .Where(b => b.ProductId == productId.Value && b.Version == req.Version && binaryKeys.Contains(b.Key))
                        .ToListAsync();

                    var approvedMap = approved.ToDictionary(b => b.Key, b => b.Hash);
                    var mismatchedBinaries = new Dictionary<string, string>();
                    var mismatchDetails = new List<string>();

                    foreach (var key in binaryKeys)
                    {
                        var reportedHash = fingerprints[key];
                        if (approvedMap.TryGetValue(key, out var approvedHash))
                        {
                            if (!string.Equals(reportedHash, approvedHash, StringComparison.OrdinalIgnoreCase))
                            {
                                var mismatchDetail = $"{key}: expected={ShortHash(approvedHash)} got={ShortHash(reportedHash)}";
                                mismatchedBinaries[key] = reportedHash;
                                mismatchDetails.Add(mismatchDetail);
                                _logger.LogWarning("Binary hash mismatch for {HardwareId} v{Version}: {Detail}", req.HardwareId, req.Version, mismatchDetail);
                            }
                        }
                        else
                        {
                            // No baseline for this key+version — store as auto-approved reference
                            db.ApprovedBinaries.Add(new ApprovedBinary
                            {
                                ProductId = productId.Value,
                                Version = req.Version,
                                Key = key,
                                Hash = reportedHash,
                                Source = "auto",
                                ApprovedAt = DateTime.UtcNow
                            });
                        }
                    }

                    await db.SaveChangesAsync();

                    if (mismatchedBinaries.Count > 0)
                    {
                        var mismatchDetail = string.Join("; ", mismatchDetails);
                        var banReason = $"BinaryPatched: hash mismatch for v{req.Version} ({mismatchDetail})";

                        // Silent mode if the binary hash is already in BannedComponents (known cracked binary).
                        // The ban still happens (idempotent) but no notification is sent — avoids
                        // spamming the admin when the same cracker retries with the same patched binary.
                        bool knownCrackedBinary = false;
                        foreach (var (key, hash) in mismatchedBinaries)
                        {
                            if (await db.BannedComponents.AsNoTracking()
                                .AnyAsync(b => b.ComponentType == key
                                            && b.ComponentHash == hash
                                            && b.ProductId == productId.Value
                                            && b.IsActive))
                            {
                                knownCrackedBinary = true;
                                break;
                            }
                        }

                        await BanBinaryPatchAsync(req.HardwareId, banReason, productId.Value, mismatchedBinaries, knownCrackedBinary);
                        _logger.LogWarning("Auto-banned {HardwareId} for binary patch{Silent}: {Detail}",
                            req.HardwareId, knownCrackedBinary ? " [silent — known cracked binary]" : "", mismatchDetail);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check binary hashes for {HardwareId}", req.HardwareId);
            }
        }

        // Auto-ban/unban logic for outdated versions below product minimum
        if (productId.HasValue && !string.IsNullOrEmpty(req.Version))
        {
            try
            {
                var product = await db.Products.AsNoTracking()
                    .Where(p => p.Id == productId.Value)
                    .Select(p => new { p.MinimumAllowedVersion })
                    .FirstOrDefaultAsync();

                if (product != null && !string.IsNullOrEmpty(product.MinimumAllowedVersion))
                {
                    if (IsVersionBelow(req.Version, product.MinimumAllowedVersion))
                    {
                        // Skip auto-ban for whitelisted/greylisted machines
                        var listType = await _fingerprintService.GetListTypeAsync(req.HardwareId);
                        if (listType == "white" || listType == "grey")
                        {
                            _logger.LogDebug("Skipping auto-ban for {HardwareId} (list: {ListType})", req.HardwareId, listType);
                        }
                        // Skip auto-ban for paid license holders (non-freemium/trial)
                        else if (await HasPaidLicenseAsync(db, req.HardwareId, productId.Value))
                        {
                            _logger.LogDebug("Skipping auto-ban for {HardwareId} (paid license)", req.HardwareId);
                        }
                        else
                        {
                        // Version is BELOW minimum - ban logic
                        bool isStartupOrUpdate = req.EventName != null &&
                            (req.EventName.StartsWith("Startup_") || req.EventName.StartsWith("Update_"));

                        var alreadyBanned = await _security.IsHardwareIdBannedAsync(req.HardwareId, productId.Value);

                        if (!isStartupOrUpdate && !alreadyBanned)
                        {
                            // Immediate ban on feature events (Block_Export, Project_Open, etc.)
                            var banReason = $"Auto-ban: feature usage ({req.EventName}) with version {req.Version} below minimum {product.MinimumAllowedVersion}";
                            await BanHardwareIdOnlyAsync(req.HardwareId, banReason, productId.Value);
                        }
                        else if (isStartupOrUpdate && !alreadyBanned)
                        {
                            // Progressive ban: if startup events with old version for 5+ consecutive days
                            var graceDays = int.Parse(await _settings.GetSettingAsync("AutoBanGraceDays", "5") ?? "5");
                            var firstOldStartup = await db.TelemetryRecords.AsNoTracking()
                                .Where(t => t.HardwareId == req.HardwareId && t.ProductId == productId.Value
                                    && t.Type == TelemetryType.Event && t.EventName != null
                                    && (t.EventName.StartsWith("Startup_") || t.EventName.StartsWith("Update_")))
                                .OrderBy(t => t.Timestamp)
                                .Select(t => new { t.Timestamp, t.Version })
                                .ToListAsync();

                            // Count distinct days with old version
                            var daysWithOldVersion = firstOldStartup
                                .Where(t => !string.IsNullOrEmpty(t.Version) && IsVersionBelow(t.Version, product.MinimumAllowedVersion))
                                .Select(t => t.Timestamp.Date)
                                .Distinct()
                                .Count();

                            if (daysWithOldVersion >= graceDays)
                            {
                                var banReason = $"Auto-ban: {daysWithOldVersion} days of startup with version {req.Version} below minimum {product.MinimumAllowedVersion}";
                                await BanHardwareIdOnlyAsync(req.HardwareId, banReason, productId.Value);
                            }
                        }
                        }
                    }
                    else
                    {
                        // Version is COMPLIANT (>= minimum) - auto-unban if previously auto-banned
                        try
                        {
                            await _security.AutoUnbanByHwidAsync(req.HardwareId, productId.Value);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "Failed to auto-unban {HardwareId}", req.HardwareId);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check minimum version for {HardwareId}", req.HardwareId);
            }
        }

        if (productId.HasValue)
        {
            var hwShort = req.HardwareId.Length > 8 ? req.HardwareId[..8] : req.HardwareId;
            FireProductWebhooks(productId.Value, "Telemetry.Event",
                $"Event: {req.EventName}",
                $"{req.AppName} v{req.Version} — {hwShort}", req);
        }
    }

    public async Task SaveDiagnosticAsync(TelemetryDiagnosticRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;

        var record = new TelemetryRecord
        {
            Timestamp = DateTime.UtcNow,
            HardwareId = req.HardwareId,
            ClientIp = ip,
            Isp = geo?.Isp,
            AppName = req.AppName,
            Version = req.Version,
            EventName = req.EventName,
            Type = TelemetryType.Diagnostic,
            ProductId = productId
        };

        record.DiagnosticData = new TelemetryDiagnostic
        {
            Score = req.Score,
            Results = req.Results?.Select(r => new TelemetryDiagnosticResult
            {
                ModuleName = r.ModuleName,
                Success = r.Success,
                Severity = r.Severity,
                Message = r.Message
            }).ToList() ?? new List<TelemetryDiagnosticResult>(),
            Ports = req.Ports?.Select(p => new TelemetryDiagnosticPort
            {
                Name = p.Name,
                ExternalPort = p.ExternalPort,
                Protocol = p.Protocol
            }).ToList() ?? new List<TelemetryDiagnosticPort>()
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        if (productId.HasValue)
        {
            var hwShort = req.HardwareId.Length > 8 ? req.HardwareId[..8] : req.HardwareId;
            FireProductWebhooks(productId.Value, "Telemetry.Diagnostic",
                $"Diagnostic: {req.EventName}",
                $"{req.AppName} v{req.Version} — {hwShort}", req);
        }
    }

    public async Task SaveErrorAsync(TelemetryErrorRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;

        var record = new TelemetryRecord
        {
            Timestamp = DateTime.UtcNow,
            HardwareId = req.HardwareId,
            ClientIp = ip,
            Isp = geo?.Isp,
            AppName = req.AppName,
            Version = req.Version,
            EventName = req.EventName,
            Type = TelemetryType.Error,
            ProductId = productId
        };

        record.ErrorData = new TelemetryError
        {
            ErrorType = req.ErrorType,
            Message = req.Message,
            StackTrace = req.StackTrace
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        if (productId.HasValue)
        {
            var hwShort = req.HardwareId.Length > 8 ? req.HardwareId[..8] : req.HardwareId;
            FireProductWebhooks(productId.Value, "Telemetry.Error",
                $"Error: {req.ErrorType}",
                $"{req.AppName} v{req.Version} — {hwShort}", req);
        }
    }

    public async Task<List<TelemetryResponse>> GetTelemetryForProductAsync(string apiSecret, int page = 1, int pageSize = 50, TelemetryType? type = null, List<string>? excludeHwids = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var product = await db.Products.AsNoTracking().FirstOrDefaultAsync(p => p.ApiSecret == apiSecret);
        if (product == null) return new List<TelemetryResponse>();

        var query = db.TelemetryRecords
            .AsNoTracking()
            .AsSplitQuery()
            .Include(t => t.EventData)
            .Include(t => t.DiagnosticData).ThenInclude(d => d!.Results)
            .Include(t => t.DiagnosticData).ThenInclude(d => d!.Ports)
            .Include(t => t.ErrorData)
            .Where(t => t.ProductId == product.Id);

        if (type.HasValue)
        {
            query = query.Where(t => t.Type == type.Value);
        }

        if (excludeHwids is { Count: > 0 })
        {
            query = query.Where(t => !excludeHwids.Contains(t.HardwareId));
        }

        var records = await query
            .OrderByDescending(t => t.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return records.Select(r => new TelemetryResponse
        {
            Id = r.Id,
            Timestamp = r.Timestamp,
            HardwareId = r.HardwareId,
            AppName = r.AppName,
            Version = r.Version,
            EventName = r.EventName,
            Type = r.Type.ToString(),
            Data = GetSpecializedData(r)
        }).ToList();
    }

    private void FireProductWebhooks(Guid productId, string trigger, string title, string message, object data)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var db = await _dbFactory.CreateDbContextAsync();
                var webhooks = await db.ProductWebhooks
                    .Where(w => w.ProductId == productId && w.IsEnabled)
                    .ToListAsync();

                if (!webhooks.Any()) return;

                var client = _httpFactory.CreateClient();
                var payload = new
                {
                    trigger,
                    title,
                    message,
                    timestamp = DateTime.UtcNow,
                    data
                };

                foreach (var hook in webhooks)
                {
                    try
                    {
                        var request = new HttpRequestMessage(HttpMethod.Post, hook.Url)
                        {
                            Content = JsonContent.Create(payload)
                        };

                        if (!string.IsNullOrWhiteSpace(hook.Secret))
                        {
                            request.Headers.Add("X-Webhook-Secret", hook.Secret);
                        }

                        await client.SendAsync(request);
                        hook.LastTriggeredAt = DateTime.UtcNow;
                        hook.LastError = null;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Echec webhook produit {Name} ({Url})", hook.Name, hook.Url);
                        hook.LastError = ex.Message;
                    }
                }

                await db.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur globale webhooks produit");
            }
        });
    }

    private void MaybeAlertCertPinningFailure(TelemetryEventRequest req, string? ip, string? isp)
    {
        if (!string.Equals(req.EventName, "CertPinningFailed", StringComparison.OrdinalIgnoreCase))
            return;

        var host = TryGetProperty(req, "Host") ?? "unknown-host";
        var cacheKey = $"{req.HardwareId}|{req.Version}|{host}";
        var now = DateTime.UtcNow;

        if (_certPinningAlertCache.TryGetValue(cacheKey, out var lastAlert)
            && now - lastAlert < CertPinningAlertCooldown)
        {
            return;
        }

        _certPinningAlertCache[cacheKey] = now;

        _ = Task.Run(async () =>
        {
            try
            {
                var alertUrl = await _settings.GetSettingAsync("TelemetryCertPinningNtfyUrl", DefaultCertPinningAlertUrl)
                    ?? DefaultCertPinningAlertUrl;

                if (string.IsNullOrWhiteSpace(alertUrl))
                    return;

                var client = _httpFactory.CreateClient();
                var os = TryGetProperty(req, "OS") ?? "unknown OS";
                var culture = TryGetProperty(req, "Culture") ?? "unknown culture";
                var source = TryGetProperty(req, "RequestSource") ?? "unknown source";
                var fingerprints = TryGetProperty(req, "Fingerprints");
                var fingerprintLine = string.IsNullOrWhiteSpace(fingerprints)
                    ? string.Empty
                    : $"{Environment.NewLine}Fingerprints: {TrimForAlert(fingerprints, 500)}";

                var message =
                    $"CertPinningFailed detected{Environment.NewLine}" +
                    $"App: {req.AppName} {req.Version ?? "unknown"}{Environment.NewLine}" +
                    $"HWID: {req.HardwareId}{Environment.NewLine}" +
                    $"IP: {ip ?? "unknown"}{Environment.NewLine}" +
                    $"ISP: {isp ?? "unknown"}{Environment.NewLine}" +
                    $"Host: {host}{Environment.NewLine}" +
                    $"OS: {os}{Environment.NewLine}" +
                    $"Culture: {culture}{Environment.NewLine}" +
                    $"Source: {source}" +
                    fingerprintLine;

                var uriBuilder = new UriBuilder(alertUrl);
                var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
                query["title"] = $"TIA pinned cert alert - {req.Version ?? "unknown"}";
                query["tags"] = "warning,lock";
                query["priority"] = "5";
                uriBuilder.Query = query.ToString();

                await client.PostAsync(uriBuilder.ToString(), new StringContent(message));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send CertPinningFailed ntfy alert");
            }
        });
    }

    private void MaybeCreateCertPinningBugTraceTicket(Guid? productId, TelemetryEventRequest req, string? ip, string? isp)
    {
        if (_certPinningBugTraceAlerts == null)
            return;

        if (!string.Equals(req.EventName, "CertPinningFailed", StringComparison.OrdinalIgnoreCase))
            return;

        _ = _certPinningBugTraceAlerts.HandleAsync(req, ip, isp, productId);
    }

    private void MaybeCreateFreemiumAbuseBugTraceTicket(Guid? productId, TelemetryEventRequest req)
    {
        if (!productId.HasValue || _freemiumAbuseBugTraceAlerts == null)
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await _freemiumAbuseBugTraceAlerts.HandleTelemetryAsync(productId.Value, req);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to process Freemium abuse BugTrace alert for {HardwareId}", req.HardwareId);
            }
        });
    }

    private static string? TryGetProperty(TelemetryEventRequest req, string key)
    {
        if (req.Properties == null)
            return null;

        return req.Properties.TryGetValue(key, out var value) ? value : null;
    }

    private static string TrimForAlert(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength] + "...";

    private object? GetSpecializedData(TelemetryRecord r)
    {
        return r.Type switch
        {
            TelemetryType.Event => r.EventData != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(r.EventData.PropertiesJson ?? "{}") : null,
            TelemetryType.Diagnostic => r.DiagnosticData != null ? new {
                r.DiagnosticData.Score,
                Results = r.DiagnosticData.Results.Select(res => new { res.ModuleName, res.Success, res.Severity, res.Message }),
                Ports = r.DiagnosticData.Ports.Select(p => new { p.Name, p.ExternalPort, p.Protocol })
            } : null,
            TelemetryType.Error => r.ErrorData != null ? new {
                r.ErrorData.ErrorType,
                r.ErrorData.Message,
                r.ErrorData.StackTrace
            } : null,
            _ => null
        };
    }

    private async Task<Guid?> GetProductIdAsync(LicenseDbContext db, string appName)
    {
        var product = await db.Products.AsNoTracking().FirstOrDefaultAsync(p => p.Name.ToLower() == appName.ToLower());
        return product?.Id;
    }

    private async Task BanBinaryPatchAsync(string hardwareId, string banReason, Guid productId, Dictionary<string, string> mismatchedBinaries, bool silent)
    {
        await _security.BanHardwareIdAsync(hardwareId, banReason, productId, banCategory: Data.BannedHardwareId.Categories.Piracy, silent: silent);
        _logger.LogWarning("Auto-banned HWID {HardwareId}{Silent}: {Reason}", hardwareId, silent ? " [silent]" : "", banReason);

        foreach (var (key, hash) in mismatchedBinaries)
        {
            await _security.BanComponentAsync(key, hash, banReason, productId, silent: silent);
        }

        _logger.LogWarning("Auto-banned {Count} binary fingerprint(s) for HWID {HardwareId}{Silent}",
            mismatchedBinaries.Count, hardwareId, silent ? " [silent]" : "");
    }

    private async Task BanHardwareIdOnlyAsync(string hardwareId, string banReason, Guid productId, string banCategory = Data.BannedHardwareId.Categories.OutdatedVersion)
    {
        await _security.BanHardwareIdAsync(hardwareId, banReason, productId, banCategory: banCategory);
        _logger.LogWarning("Auto-banned HWID {HardwareId}: {Reason}", hardwareId, banReason);
    }

    private static bool IsVersionBelow(string current, string minimum)
    {
        if (Version.TryParse(current, out var cur) && Version.TryParse(minimum, out var min))
            return cur < min;
        return string.Compare(current, minimum, StringComparison.Ordinal) < 0;
    }

    private static string ShortHash(string hash) =>
        hash.Length <= 12 ? hash : hash[..12] + "...";

    private static readonly string[] FreeSlugs = { "FREEMIUM", "TRIAL", "FREE", "STUDENT" };

    /// <summary>
    /// Returns true if the hardware ID has at least one active paid (non-free) license for this product.
    /// </summary>
    private static async Task<bool> HasPaidLicenseAsync(LicenseDbContext db, string hardwareId, Guid productId)
    {
        var now = DateTime.UtcNow;

        return await db.Licenses.AsNoTracking()
            .Where(l => l.ProductId == productId
                && l.IsActive
                && (l.ExpirationDate == null || l.ExpirationDate > now)
                && (l.HardwareId == hardwareId
                    || db.LicenseSeats.Any(s =>
                        s.LicenseId == l.Id
                        && s.HardwareId == hardwareId
                        && s.IsActive)))
            .Join(db.LicenseTypes.AsNoTracking(), l => l.LicenseTypeId, lt => lt.Id, (l, lt) => new
            {
                lt.IsFree,
                lt.Slug
            })
            .AnyAsync(lt => !lt.IsFree && !FreeSlugs.Contains(lt.Slug.ToUpper()));
    }
}
