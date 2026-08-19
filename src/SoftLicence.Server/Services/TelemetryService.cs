using System.Text.Json;
using System.Net.Http.Json;
using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public class TelemetryService
{
    private const int MaxPersistentCertPinningHardwareIdLength = 256;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<TelemetryService> _logger;
    private readonly GeoIpService _geoIp;
    private readonly IHttpClientFactory _httpFactory;
    private readonly FingerprintService _fingerprintService;
    private readonly SecurityService _security;
    private readonly SettingsService _settings;
    private readonly CertPinningBugTraceAlertService? _certPinningBugTraceAlerts;
    private readonly CertPinningDailyAlertService? _certPinningDailyAlerts;
    private readonly FreemiumAbuseBugTraceAlertService? _freemiumAbuseBugTraceAlerts;
    private readonly ActivationIncidentService? _activationIncidents;
    private readonly SecurityIncidentService? _securityIncidents;
    private readonly ApprovedBinaryService _approvedBinaries;
    private static readonly ConcurrentDictionary<string, DateTime> _certPinningAlertCache = new();
    private static readonly TimeSpan CertPinningAlertCooldown = TimeSpan.FromMinutes(15);
    private const string DefaultCertPinningAlertUrl = "https://ntfy.websitedev.fr/vps-check-tia-pinned-certs";
    private const string FloodSuppressionEnabledSetting = "TelemetryFloodSuppressionEnabled";
    private const string FloodSuppressionWindowMinutesSetting = "TelemetryFloodSuppressionWindowMinutes";
    private const string FloodSuppressionThresholdSetting = "TelemetryFloodSuppressionThreshold";

    public TelemetryService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<TelemetryService> logger,
        GeoIpService geoIp,
        IHttpClientFactory httpFactory,
        FingerprintService fingerprintService,
        SecurityService security,
        SettingsService settings,
        CertPinningBugTraceAlertService? certPinningBugTraceAlerts = null,
        FreemiumAbuseBugTraceAlertService? freemiumAbuseBugTraceAlerts = null,
        ActivationIncidentService? activationIncidents = null,
        SecurityIncidentService? securityIncidents = null,
        ApprovedBinaryService? approvedBinaries = null,
        CertPinningDailyAlertService? certPinningDailyAlerts = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _geoIp = geoIp;
        _httpFactory = httpFactory;
        _fingerprintService = fingerprintService;
        _security = security;
        _settings = settings;
        _certPinningBugTraceAlerts = certPinningBugTraceAlerts;
        _certPinningDailyAlerts = certPinningDailyAlerts;
        _freemiumAbuseBugTraceAlerts = freemiumAbuseBugTraceAlerts;
        _activationIncidents = activationIncidents;
        _securityIncidents = securityIncidents;
        _approvedBinaries = approvedBinaries ?? new ApprovedBinaryService(
            dbFactory,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ApprovedBinaryService>.Instance);
    }

    public async Task SaveEventAsync(TelemetryEventRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;
        var propertiesJson = SerializeTelemetryProperties(req.Properties);
        var receivedAtUtc = DateTime.UtcNow;

        if (!await ShouldStoreTelemetryAsync(
            db,
            productId,
            req.AppName,
            req.HardwareId,
            req.EventName,
            req.Version,
            TelemetryType.Event,
            ip,
            geo?.Isp,
            propertiesJson))
        {
            return;
        }

        var record = new TelemetryRecord
        {
            Timestamp = receivedAtUtc,
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
            PropertiesJson = propertiesJson
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        if (_activationIncidents != null)
        {
            try
            {
                await _activationIncidents.ProcessAsync(productId, req, ip, geo);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Activation incident processing failed for event {EventName}", req.EventName);
            }
        }

        MaybeAlertCertPinningFailure(productId, req, ip, geo?.Isp, receivedAtUtc);
        MaybeCreateCertPinningBugTraceTicket(productId, req, ip, geo?.Isp);
        MaybeCreateFreemiumAbuseBugTraceTicket(productId, req);

        // Public telemetry is immutable evidence, not licensing authority. A hardware identifier
        // can legitimately occur on several historical seats or licences, so neither uninstall
        // nor startup events may mutate the global licence projection.
        bool isStartup = req.EventName != null
            && req.EventName.StartsWith("Startup_", StringComparison.OrdinalIgnoreCase);

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

        // The ApprovedBinaries verdict from public telemetry is observation-only and cannot
        // mutate licensing authority or durable ban state. Orthogonal uninstall and minimum-
        // version policies below remain unchanged and may still update their own state.
        if (isStartup && productId.HasValue && !string.IsNullOrEmpty(req.Version))
        {
            try
            {
                var verdict = await _approvedBinaries.EvaluateTelemetryEvidenceAsync(
                    productId.Value,
                    req.Version,
                    req.Properties);

                ApprovedBinaryObservationKind? observationKind = null;
                IReadOnlyDictionary<string, string>? observedBinaries = null;
                // Machine keys and enum-like values are exact, ordinal protocol tokens.
                // Casing/whitespace variants remain untrusted evidence, matching FP_EXE/FP_DLL/FP_CORE.
                if (req.Properties?.TryGetValue("FP_STATUS", out var fingerprintStatus) == true
                    && string.Equals(fingerprintStatus, "native-unavailable", StringComparison.Ordinal))
                {
                    observationKind = ApprovedBinaryObservationKind.CaptureUnavailable;
                }
                else if (verdict.Verdict == ApprovedBinaryVerdict.Mismatch)
                {
                    observationKind = ApprovedBinaryObservationKind.Mismatch;
                    observedBinaries = verdict.Mismatches;
                    var mismatchDetails = new List<string>();
                    foreach (var (key, reportedHash) in verdict.Mismatches)
                    {
                        var mismatchDetail = $"{key}: got={ShortHash(reportedHash)}";
                        mismatchDetails.Add(mismatchDetail);
                    }
                    _logger.LogWarning(
                        "Public ApprovedBinaries mismatch observed for product {ProductId} version {Version}: {Detail}; no automatic sanction",
                        productId.Value,
                        req.Version,
                        string.Join("; ", mismatchDetails));
                }
                else if (verdict.Verdict == ApprovedBinaryVerdict.BaselineMissing)
                {
                    observationKind = ApprovedBinaryObservationKind.BaselineMissing;
                    _logger.LogWarning(
                        "Approved binary baseline missing or non-authoritative for product {ProductId} version {Version}",
                        productId.Value,
                        req.Version);
                }
                else if (verdict.Verdict == ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted)
                {
                    observationKind = string.Equals(verdict.ErrorCode, "required_key_missing", StringComparison.Ordinal)
                        ? ApprovedBinaryObservationKind.EvidenceMissing
                        : ApprovedBinaryObservationKind.EvidenceInvalid;
                    _logger.LogWarning(
                        "Public ApprovedBinaries evidence rejected for product {ProductId} version {Version}; reason={Reason}; no automatic sanction",
                        productId.Value,
                        req.Version,
                        verdict.ErrorCode);
                }

                if (observationKind.HasValue && _securityIncidents != null)
                {
                    try
                    {
                        await _securityIncidents.RecordApprovedBinaryObservationAsync(
                            productId.Value,
                            observationKind.Value,
                            observedBinaries);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex,
                            "ApprovedBinaries public observation aggregation failed for product {ProductId} version {Version}; no sanction was applied",
                            productId.Value,
                            req.Version);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex,
                    "Failed to evaluate public ApprovedBinaries evidence for product {ProductId} version {Version}",
                    productId.Value,
                    req.Version);
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
            var sanitizedWebhookRequest = CreateSanitizedEventRequest(req);
            FireProductWebhooks(productId.Value, "Telemetry.Event",
                $"Event: {req.EventName}",
                $"{req.AppName} v{req.Version} — {hwShort}", sanitizedWebhookRequest);
        }
    }

    public async Task SaveDiagnosticAsync(TelemetryDiagnosticRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;
        var payloadJson = JsonSerializer.Serialize(new
        {
            req.Score,
            req.Results,
            req.Ports
        });

        if (!await ShouldStoreTelemetryAsync(
            db,
            productId,
            req.AppName,
            req.HardwareId,
            req.EventName,
            req.Version,
            TelemetryType.Diagnostic,
            ip,
            geo?.Isp,
            payloadJson))
        {
            return;
        }

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
        var payloadJson = JsonSerializer.Serialize(new
        {
            req.ErrorType,
            req.Message,
            req.StackTrace
        });

        if (!await ShouldStoreTelemetryAsync(
            db,
            productId,
            req.AppName,
            req.HardwareId,
            req.EventName,
            req.Version,
            TelemetryType.Error,
            ip,
            geo?.Isp,
            payloadJson))
        {
            return;
        }

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

                        var response = await client.SendAsync(request);
                        hook.LastTriggeredAt = DateTime.UtcNow;
                        if (response.IsSuccessStatusCode)
                        {
                            hook.LastError = null;
                        }
                        else
                        {
                            hook.LastError = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}".Trim();
                            _logger.LogWarning("Echec webhook produit {Name} ({Url}): {StatusCode} {ReasonPhrase}",
                                hook.Name,
                                hook.Url,
                                (int)response.StatusCode,
                                response.ReasonPhrase);
                        }
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

    private void MaybeAlertCertPinningFailure(
        Guid? productId,
        TelemetryEventRequest req,
        string? ip,
        string? isp,
        DateTime observedAtUtc)
    {
        if (!string.Equals(req.EventName, "CertPinningFailed", StringComparison.OrdinalIgnoreCase))
            return;

        var host = TryGetProperty(req, "Host") ?? "unknown-host";
        if (productId.HasValue
            && _certPinningDailyAlerts != null
            && !string.IsNullOrEmpty(req.HardwareId)
            && req.HardwareId.Length <= MaxPersistentCertPinningHardwareIdLength)
        {
            _ = Task.Run(() => ProcessPersistentCertPinningAlertAsync(
                productId.Value,
                req,
                ip,
                isp,
                host,
                observedAtUtc));
            return;
        }

        var cacheKey = $"{req.HardwareId}|{req.Version}|{host}";
        var now = observedAtUtc;

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
                await SendCertPinningNtfyAsync(req, ip, isp, host);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send CertPinningFailed ntfy alert");
            }
        });
    }

    private async Task ProcessPersistentCertPinningAlertAsync(
        Guid productId,
        TelemetryEventRequest req,
        string? ip,
        string? isp,
        string host,
        DateTime observedAtUtc)
    {
        CertPinningDailyAlertClaim? claim = null;
        try
        {
            claim = await _certPinningDailyAlerts!.RecordAndClaimAsync(
                productId,
                req.HardwareId,
                host,
                req.Version,
                ParseNonNegativeInt(TryGetProperty(req, "SuppressedCount")),
                observedAtUtc,
                failureReason: TryGetProperty(req, "FailureReason"),
                certificateIssuer: TryGetProperty(req, "CertificateIssuer"));
            if (!claim.ShouldNotify || !claim.ClaimId.HasValue)
                return;

            if (await SendCertPinningNtfyAsync(req, ip, isp, host))
            {
                await _certPinningDailyAlerts.MarkNotificationSentAsync(
                    claim.AggregateId,
                    claim.ClaimId.Value,
                    DateTime.UtcNow);
            }
            else
                _logger.LogWarning(
                    "CertPinningFailed daily notification attempt failed for aggregate {AggregateId}; no automatic retry will be sent today",
                    claim.AggregateId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Failed to process persistent CertPinningFailed ntfy alert; a claimed notification is not retried automatically");
        }
    }

    private async Task<bool> SendCertPinningNtfyAsync(
        TelemetryEventRequest req,
        string? ip,
        string? isp,
        string host)
    {
        var alertUrl = await _settings.GetSettingAsync("TelemetryCertPinningNtfyUrl", DefaultCertPinningAlertUrl)
            ?? DefaultCertPinningAlertUrl;
        if (string.IsNullOrWhiteSpace(alertUrl))
            return true;

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
        query["priority"] = "3";
        uriBuilder.Query = query.ToString();

        using var response = await client.PostAsync(uriBuilder.ToString(), new StringContent(message));
        if (response.IsSuccessStatusCode)
            return true;

        _logger.LogWarning(
            "CertPinningFailed ntfy returned HTTP {StatusCode}",
            (int)response.StatusCode);
        return false;
    }

    private static int ParseNonNegativeInt(string? raw) =>
        int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value
            : 0;

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

    private async Task<bool> ShouldStoreTelemetryAsync(
        LicenseDbContext db,
        Guid? productId,
        string appName,
        string hardwareId,
        string eventName,
        string? version,
        TelemetryType type,
        string? ip,
        string? isp,
        string? payloadJson)
    {
        if (IsFloodSuppressionExempt(eventName, type))
            return true;

        if (_settings is null)
            return true;

        var enabledRaw = await _settings.GetSettingAsync(FloodSuppressionEnabledSetting, "true");
        if (bool.TryParse(enabledRaw, out var enabled) && !enabled)
            return true;

        var windowMinutes = await GetClampedIntSettingAsync(FloodSuppressionWindowMinutesSetting, 10, 1, 1440);
        var threshold = await GetClampedIntSettingAsync(FloodSuppressionThresholdSetting, 10, 1, 1000);
        var now = DateTime.UtcNow;
        var windowStart = FloorToWindow(now, windowMinutes);
        var windowEnd = windowStart.AddMinutes(windowMinutes);

        var rawStoredCount = await db.TelemetryRecords.AsNoTracking().CountAsync(t =>
            t.ProductId == productId
            && t.HardwareId == hardwareId
            && t.EventName == eventName
            && t.Version == version
            && t.Type == type
            && t.Timestamp >= windowStart
            && t.Timestamp < windowEnd);

        if (rawStoredCount < threshold)
            return true;

        var payloadHash = ComputeSha256(payloadJson);
        var counter = await db.TelemetryFloodSuppressionCounters.FirstOrDefaultAsync(c =>
            c.ProductId == productId
            && c.HardwareId == hardwareId
            && c.EventName == eventName
            && c.Version == version
            && c.Type == type
            && c.WindowStartUtc == windowStart);

        if (counter == null)
        {
            db.TelemetryFloodSuppressionCounters.Add(new TelemetryFloodSuppressionCounter
            {
                ProductId = productId,
                HardwareId = hardwareId,
                AppName = appName,
                Version = version,
                EventName = eventName,
                Type = type,
                WindowStartUtc = windowStart,
                WindowEndUtc = windowEnd,
                WindowMinutes = windowMinutes,
                Threshold = threshold,
                RawStoredCount = rawStoredCount,
                SuppressedCount = 1,
                FirstSeenUtc = now,
                LastSeenUtc = now,
                LastClientIp = ip,
                LastIsp = isp,
                LastPayloadHash = payloadHash
            });
        }
        else
        {
            counter.RawStoredCount = Math.Max(counter.RawStoredCount, rawStoredCount);
            counter.SuppressedCount++;
            counter.LastSeenUtc = now;
            counter.LastClientIp = ip;
            counter.LastIsp = isp;
            counter.LastPayloadHash = payloadHash;
        }

        await db.SaveChangesAsync();
        _logger.LogInformation(
            "Suppressed telemetry flood for {AppName} {HardwareId} {EventName} {Type}: raw={RawStoredCount}, suppressed={SuppressedCount}, window={WindowStart:o}",
            appName,
            hardwareId,
            eventName,
            type,
            rawStoredCount,
            counter?.SuppressedCount ?? 1,
            windowStart);

        return false;
    }

    private async Task<int> GetClampedIntSettingAsync(string key, int defaultValue, int min, int max)
    {
        var raw = await _settings.GetSettingAsync(key, defaultValue.ToString());
        return int.TryParse(raw, out var parsed) ? Math.Clamp(parsed, min, max) : defaultValue;
    }

    private static bool IsFloodSuppressionExempt(string eventName, TelemetryType type)
    {
        if (type == TelemetryType.Error)
            return true;

        return eventName.Contains("Security", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Integrity", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventName, "CertPinningFailed", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventName, "CertPinningRecovered", StringComparison.OrdinalIgnoreCase);
    }

    private static DateTime FloorToWindow(DateTime utc, int windowMinutes)
    {
        var ticks = TimeSpan.FromMinutes(windowMinutes).Ticks;
        return new DateTime(utc.Ticks / ticks * ticks, DateTimeKind.Utc);
    }

    private static string? ComputeSha256(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return null;

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
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

    private static string? SerializeTelemetryProperties(IReadOnlyDictionary<string, string>? properties)
    {
        if (properties == null)
            return null;

        return JsonSerializer.Serialize(SanitizeTelemetryProperties(properties));
    }

    private static TelemetryEventRequest CreateSanitizedEventRequest(TelemetryEventRequest request) => new()
    {
        Timestamp = request.Timestamp,
        HardwareId = request.HardwareId,
        AppName = request.AppName,
        Version = request.Version,
        EventName = request.EventName,
        Properties = request.Properties == null ? null : SanitizeTelemetryProperties(request.Properties)
    };

    private static Dictionary<string, string> SanitizeTelemetryProperties(
        IReadOnlyDictionary<string, string> properties)
    {
        var persisted = properties.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        foreach (var key in persisted.Keys.ToArray())
        {
            // Redaction is intentionally broader than validation: non-canonical key casing
            // remains invalid for authority decisions, but its malformed value is still not retained.
            if (key is null || !(key.Equals("FP_EXE", StringComparison.OrdinalIgnoreCase)
                || key.Equals("FP_DLL", StringComparison.OrdinalIgnoreCase)
                || key.Equals("FP_CORE", StringComparison.OrdinalIgnoreCase)))
                continue;

            var value = persisted[key];
            persisted[key] = ApprovedBinaryService.NormalizeSha256(value) ?? "[invalid]";
        }

        return persisted;
    }

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
