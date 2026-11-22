using System.Text.Json;
using System.Net.Http.Json;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// Persists public telemetry and applies bounded server-side observations, alerts, and security
/// transitions without treating client-provided event names as authorization evidence.
/// </summary>
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
    private readonly UpdatePreflightFailureAlertService? _updatePreflightFailureAlerts;
    private readonly NotificationService? _notifications;
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
    /// <summary>
    /// Contains lifecycle protocol identifiers that must never create or lift an outdated-version
    /// hardware ban on their own. Entries use exact ordinal equality so variants remain fail-closed.
    /// </summary>
    private static readonly FrozenSet<string> OutdatedVersionEnforcementNeutralEvents =
        new[] { "Uninstall_Upgrade" }.ToFrozenSet(StringComparer.Ordinal);

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
        CertPinningDailyAlertService? certPinningDailyAlerts = null,
        UpdatePreflightFailureAlertService? updatePreflightFailureAlerts = null,
        NotificationService? notifications = null)
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
        _updatePreflightFailureAlerts = updatePreflightFailureAlerts;
        _notifications = notifications;
        _freemiumAbuseBugTraceAlerts = freemiumAbuseBugTraceAlerts;
        _activationIncidents = activationIncidents;
        _securityIncidents = securityIncidents;
        _approvedBinaries = approvedBinaries ?? new ApprovedBinaryService(
            dbFactory,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ApprovedBinaryService>.Instance);
    }

    /// <summary>
    /// Stores one telemetry event, evaluates bounded incident signals, and applies eligible
    /// outdated-version hardware-ban transitions after the event has been persisted.
    /// </summary>
    /// <param name="req">
    /// Client telemetry. Event names are protocol identifiers and are not trimmed, recased, or
    /// Unicode-normalized before security classification.
    /// </param>
    /// <param name="ip">The server-observed client IP address, or <see langword="null"/> when unavailable.</param>
    /// <remarks>
    /// Public telemetry remains untrusted. Enforcement-neutral lifecycle events only suppress the
    /// outdated-version ban and unban decision for that event; they grant no licence or feature authority.
    /// Best-effort observation failures are logged and do not roll back an already persisted event.
    /// An ApprovedBinaries fingerprint mismatch on a <c>Startup_*</c> event is attached to the incident of its machine
    /// and may send the single modified-binary alert of that machine (TKT-003674); it never sanctions.
    /// </remarks>
    public async Task SaveEventAsync(TelemetryEventRequest req, string? ip = null)
    {
        req = ResolveCompatibilityEnvelope(req);
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;
        var propertiesJson = SerializeTelemetryProperties(req.Properties);
        var receivedAtUtc = DateTime.UtcNow;
        var resolvedType = ResolveEventTelemetryType(req);

        if (!await ShouldStoreTelemetryAsync(
            db,
            productId,
            req.AppName,
            req.HardwareId,
            req.EventName,
            req.Version,
            resolvedType,
            TelemetryPayloadBacking.EventData,
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
            Type = resolvedType,
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
        MaybeAlertUpdatePreflightFailure(productId, req, receivedAtUtc);
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

                    // TKT-003674: a mismatch is attached to the incident of its machine (HWID, licence, IP,
                    // version in the database) and alerts once per machine after repeated starts. The log only
                    // carries the incident id and a 16-character HWID prefix (#1360), never a full fingerprint.
                    // When the HWID is unusable or the per-hardware write fails, the public product aggregate
                    // below still keeps the evidence.
                    HardwareBinaryMismatchOutcome? hardwareOutcome = null;
                    if (_securityIncidents != null)
                    {
                        try
                        {
                            hardwareOutcome = await _securityIncidents.RecordHardwareBinaryMismatchAsync(
                                productId.Value,
                                req.HardwareId,
                                req.Version,
                                ip,
                                geo?.CountryCode,
                                geo?.Isp,
                                verdict.Mismatches);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex,
                                "Per-hardware ApprovedBinaries incident failed for product {ProductId} version {Version}; falling back to the public aggregate, no sanction was applied",
                                productId.Value,
                                req.Version);
                        }
                    }

                    if (hardwareOutcome != null)
                    {
                        observationKind = null;
                        _logger.LogWarning(
                            "Public ApprovedBinaries mismatch observed for product {ProductId} version {Version}: incident={IncidentId} hwid16={HardwareIdPrefix} licence={LicenseId} ip={ClientIp} unapproved={UnapprovedCount} newStart={CountedStart} starts24h={StartsInWindow} alertSent={AlertSent}: {Detail}; no automatic sanction",
                            productId.Value,
                            req.Version,
                            hardwareOutcome.IncidentId,
                            hardwareOutcome.HardwareIdPrefix,
                            hardwareOutcome.LicenseId,
                            ip,
                            hardwareOutcome.UnapprovedComponentCount,
                            hardwareOutcome.CountedStart,
                            hardwareOutcome.StartsInWindow,
                            hardwareOutcome.AlertSent,
                            string.Join("; ", mismatchDetails));
                    }
                    else
                    {
                        _logger.LogWarning(
                            "Public ApprovedBinaries mismatch observed for product {ProductId} version {Version} not attached to a hardware incident (unusable HWID or incident failure): {Detail}; no automatic sanction",
                            productId.Value,
                            req.Version,
                            string.Join("; ", mismatchDetails));
                    }
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

        // A valid upgrade runs the old uninstaller by design. Its exact lifecycle event must not
        // create a transient threat or lift an existing ban before the new application proves usage.
        if (productId.HasValue
            && !string.IsNullOrEmpty(req.Version)
            && !IsOutdatedVersionEnforcementNeutralEvent(req.EventName))
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
            TelemetryPayloadBacking.DiagnosticData,
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
            TelemetryPayloadBacking.ErrorData,
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

    /// <summary>
    /// Reads product telemetry while preserving the persisted specialized payload shape.
    /// </summary>
    /// <param name="apiSecret">The product-scoped read key.</param>
    /// <param name="page">The one-based page number.</param>
    /// <param name="pageSize">The maximum number of rows returned.</param>
    /// <param name="type">An optional persisted telemetry-type filter.</param>
    /// <param name="excludeHwids">Optional hardware identifiers excluded from the result.</param>
    /// <returns>The requested telemetry rows, or an empty list when the product key is unknown.</returns>
    /// <remarks>
    /// An error ingested through the event endpoint remains <c>Type=Error</c>, retains its event name,
    /// and exposes its event properties as the <c>Data</c> dictionary. Classic error-endpoint rows keep
    /// their existing error-data response. This compatibility contract does not reshape either payload.
    /// </remarks>
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

    /// <summary>
    /// Records every valid presentation in the durable aggregate and schedules at most one configured
    /// webhook/ntfy notification for the same signature in each 30-minute UTC window.
    /// </summary>
    private void MaybeAlertUpdatePreflightFailure(
        Guid? productId,
        TelemetryEventRequest request,
        DateTime observedAtUtc)
    {
        if (!productId.HasValue || _updatePreflightFailureAlerts == null || _notifications == null)
            return;
        if (!UpdatePreflightFailureAlertService.TryParse(request, out var observation))
            return;

        _ = Task.Run(async () =>
        {
            UpdatePreflightFailureAlertClaim? claim = null;
            try
            {
                claim = await _updatePreflightFailureAlerts.RecordAndClaimAsync(
                    productId.Value,
                    observation,
                    observedAtUtc);
                if (!claim.ShouldNotify || !claim.ClaimId.HasValue)
                    return;

                var delivery = await _notifications.NotifyAsync(
                    NotificationService.Triggers.UpdatePreflightFailureShown,
                    $"Blocage {observation.SupportCode} affiché",
                    $"{request.AppName} {observation.CurrentVersion} · {observation.DecisionReason} · " +
                    $"canal {observation.SelectedChannel} · étape {observation.PresentationStage}",
                    new
                    {
                        observation.SupportCode,
                        observation.CurrentVersion,
                        observation.LatestVersion,
                        observation.DecisionReason,
                        observation.SelectedChannel,
                        observation.ReconciliationOutcome,
                        observation.PresentationStage,
                        claim.OccurrenceCount,
                        claim.WindowStartUtc,
                        claim.WindowEndUtc
                    });
                if (delivery.Delivered == 0)
                    throw new InvalidOperationException(
                        delivery.Configured == 0
                            ? "upd_preflight_notification_target_missing"
                            : "upd_preflight_notification_delivery_failed");
                await _updatePreflightFailureAlerts.MarkNotificationSentAsync(
                    claim.AggregateId,
                    claim.ClaimId.Value,
                    DateTime.UtcNow);
            }
            catch (Exception ex)
            {
                if (claim?.ClaimId is Guid claimId)
                {
                    try
                    {
                        await _updatePreflightFailureAlerts.ReleaseNotificationClaimAsync(
                            claim.AggregateId,
                            claimId);
                    }
                    catch (Exception releaseException)
                    {
                        _logger.LogError(
                            releaseException,
                            "Failed to release Update_PreflightFailureShown notification claim {ClaimId}",
                            claimId);
                    }
                }
                _logger.LogWarning(ex, "Failed to process Update_PreflightFailureShown alert");
            }
        });
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

    /// <summary>
    /// Builds the public read-model payload from the specialized row that actually owns the data.
    /// Error-classified events deliberately retain <see cref="TelemetryRecord.EventData"/>, while
    /// classic <c>/error</c> records continue to expose <see cref="TelemetryRecord.ErrorData"/>.
    /// </summary>
    /// <param name="r">The record loaded with all specialized navigation properties.</param>
    /// <returns>The compatible payload for the record type, or <see langword="null"/> when absent.</returns>
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
            TelemetryType.Error => r.ErrorData != null
                ? new {
                    r.ErrorData.ErrorType,
                    r.ErrorData.Message,
                    r.ErrorData.StackTrace
                }
                : r.EventData != null
                    ? JsonSerializer.Deserialize<Dictionary<string, string>>(r.EventData.PropertiesJson ?? "{}")
                    : null,
            _ => null
        };
    }

    /// <summary>
    /// Resolves the event endpoint classification without trimming, case folding, normalization, or
    /// broad prefix matching. This keeps the two deployed legacy names compatible while preventing
    /// lookalikes from inflating operational error counts.
    /// </summary>
    /// <param name="request">The effective event request whose protocol values are untrusted.</param>
    /// <returns><see cref="TelemetryType.Error"/> only for the exact explicit or legacy contract.</returns>
    private static TelemetryType ResolveEventTelemetryType(TelemetryEventRequest request)
    {
        if (string.Equals(request.Type, nameof(TelemetryType.Error), StringComparison.Ordinal)
            || string.Equals(request.Req?.Type, nameof(TelemetryType.Error), StringComparison.Ordinal)
            || string.Equals(request.EventName, "LicenseActivation_Failed", StringComparison.Ordinal)
            || string.Equals(request.EventName, "LicenseActivation_ApiError", StringComparison.Ordinal))
        {
            return TelemetryType.Error;
        }

        return TelemetryType.Event;
    }

    /// <summary>
    /// Recovers properties from the compatibility <c>req</c> envelope without allowing it to replace
    /// the outer app, hardware, version, event name, or timestamp used for routing and authorization.
    /// </summary>
    /// <param name="request">The deserialized outer request.</param>
    /// <returns>The original request when no recovery is needed; otherwise a shallow effective copy.</returns>
    private static TelemetryEventRequest ResolveCompatibilityEnvelope(TelemetryEventRequest request)
    {
        if (request.Properties is not null || request.Req?.Properties is null)
            return request;

        return new TelemetryEventRequest
        {
            Timestamp = request.Timestamp,
            HardwareId = request.HardwareId,
            AppName = request.AppName,
            Version = request.Version,
            EventName = request.EventName,
            Type = request.Type,
            Properties = request.Req.Properties,
            Req = request.Req
        };
    }

    private async Task<Guid?> GetProductIdAsync(LicenseDbContext db, string appName)
    {
        var product = await db.Products.AsNoTracking().FirstOrDefaultAsync(p => p.Name.ToLower() == appName.ToLower());
        return product?.Id;
    }

    /// <summary>
    /// Applies the shared flood threshold while preserving payload-specific exemptions. Error-typed
    /// event data remains suppressible; classic error data is retained in full for crash diagnostics.
    /// </summary>
    /// <param name="db">The context that owns the candidate record and suppression counter.</param>
    /// <param name="productId">The resolved product, when the app name is known.</param>
    /// <param name="appName">The canonical or submitted application name.</param>
    /// <param name="hardwareId">The submitted hardware identifier.</param>
    /// <param name="eventName">The exact event protocol identifier.</param>
    /// <param name="version">The submitted client version.</param>
    /// <param name="type">The resolved persisted telemetry type.</param>
    /// <param name="payloadBacking">The specialized relational payload that will back the record.</param>
    /// <param name="ip">The server-observed client address, when available.</param>
    /// <param name="isp">The server-resolved network provider, when available.</param>
    /// <param name="payloadJson">The bounded payload used only for the suppression receipt hash.</param>
    /// <returns><see langword="true"/> when the raw record should be stored.</returns>
    private async Task<bool> ShouldStoreTelemetryAsync(
        LicenseDbContext db,
        Guid? productId,
        string appName,
        string hardwareId,
        string eventName,
        string? version,
        TelemetryType type,
        TelemetryPayloadBacking payloadBacking,
        string? ip,
        string? isp,
        string? payloadJson)
    {
        if (IsFloodSuppressionExempt(eventName, type, payloadBacking))
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

        var matchingRecords = db.TelemetryRecords.AsNoTracking().Where(t =>
            t.ProductId == productId
            && t.HardwareId == hardwareId
            && t.EventName == eventName
            && t.Version == version
            && t.Type == type
            && t.Timestamp >= windowStart
            && t.Timestamp < windowEnd);
        matchingRecords = payloadBacking switch
        {
            TelemetryPayloadBacking.EventData => matchingRecords.Where(t => t.EventData != null),
            TelemetryPayloadBacking.DiagnosticData => matchingRecords.Where(t => t.DiagnosticData != null),
            TelemetryPayloadBacking.ErrorData => matchingRecords.Where(t => t.ErrorData != null),
            _ => matchingRecords.Where(_ => false)
        };
        var rawStoredCount = await matchingRecords.CountAsync();

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

    /// <summary>
    /// Identifies records that must bypass flood suppression. The backing payload distinguishes classic
    /// errors from event-endpoint rows that resolved to the same persisted type.
    /// </summary>
    private static bool IsFloodSuppressionExempt(
        string eventName,
        TelemetryType type,
        TelemetryPayloadBacking payloadBacking)
    {
        if (type == TelemetryType.Error && payloadBacking == TelemetryPayloadBacking.ErrorData)
            return true;

        return eventName.Contains("Security", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Integrity", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventName, "CertPinningFailed", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventName, "CertPinningRecovered", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventName, UpdatePreflightFailureAlertService.EventName, StringComparison.Ordinal);
    }

    /// <summary>
    /// Identifies the specialized relational payload created after the flood decision.
    /// </summary>
    private enum TelemetryPayloadBacking
    {
        EventData,
        DiagnosticData,
        ErrorData
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

    /// <summary>
    /// Determines whether one exact lifecycle protocol identifier must be neutral to both automatic
    /// outdated-version ban and unban authority.
    /// </summary>
    /// <param name="eventName">The unmodified client event identifier, or <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> only for a documented exact allowlist entry; wrong-case, whitespace,
    /// Unicode, and unknown variants return <see langword="false"/> and remain fail-closed.
    /// </returns>
    private static bool IsOutdatedVersionEnforcementNeutralEvent(string? eventName) =>
        eventName is not null && OutdatedVersionEnforcementNeutralEvents.Contains(eventName);

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
