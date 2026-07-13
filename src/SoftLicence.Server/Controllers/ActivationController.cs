using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using Microsoft.Extensions.Localization;

namespace SoftLicence.Server.Controllers
{
    [ApiController]
    [Route("api/activation")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("PublicAPI")]
    public class ActivationController : ControllerBase
    {
        private const string ActivationErrorCodeHeader = "X-SoftLicence-Error-Code";
        private static readonly TimeSpan AnonymousDeactivationGuardWindow = TimeSpan.FromMinutes(5);

        private readonly LicenseDbContext _db;
        private readonly ILogger<ActivationController> _logger;
        private readonly Services.EncryptionService _encryption;
        private readonly Services.EmailService _mailer;
        private readonly Services.TelemetryService _telemetry;
        private readonly Services.GeoIpService _geoIp;
        private readonly IConfiguration _config;
        private readonly IStringLocalizer<SharedResource> _localizer;
        private readonly Services.NotificationService _notifier;
        private readonly Services.SecurityService _security;
        private readonly Services.FingerprintService _fingerprint;
        private readonly Services.SeatCleanupService _seatCleanup;
        private readonly Services.HwidReuseAlertService _hwidReuseAlerts;

        public ActivationController(
            LicenseDbContext db,
            ILogger<ActivationController> logger,
            Services.EncryptionService encryption,
            Services.EmailService mailer,
            Services.TelemetryService telemetry,
            Services.GeoIpService geoIp,
            IConfiguration config,
            IStringLocalizer<SharedResource> localizer,
            Services.NotificationService notifier,
            Services.SecurityService security,
            Services.FingerprintService fingerprint,
            Services.SeatCleanupService seatCleanup,
            Services.HwidReuseAlertService hwidReuseAlerts)
        {
            _db = db;
            _logger = logger;
            _encryption = encryption;
            _mailer = mailer;
            _telemetry = telemetry;
            _geoIp = geoIp;
            _config = config;
            _localizer = localizer;
            _notifier = notifier;
            _security = security;
            _fingerprint = fingerprint;
            _seatCleanup = seatCleanup;
            _hwidReuseAlerts = hwidReuseAlerts;
        }

        public class ActivationRequest
        {
            public required string LicenseKey { get; set; }
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; } // Identifiant unique du produit
            public string? AppVersion { get; set; } // Nouvelle version client
            public string? CustomerEmail { get; set; }
            public string? CustomerName { get; set; }
            public Dictionary<string, string>? ExtraParams { get; set; } // Paramètres additionnels mergés dans le payload signé
            public Dictionary<string, string>? ComponentFingerprints { get; set; }
            public string? HardwareIdV2 { get; set; }
            public bool? HardwareIdV2Differs { get; set; }
            public string? HardwareIdAlgorithm { get; set; }
            public string? HardwareIdV2Algorithm { get; set; }
            public string? SdkVersion { get; set; }
            public string? BuildHash { get; set; }
        }

        public class TrialRequest
        {
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; } // Identifiant unique du produit
            public required string TypeSlug { get; set; } // ex: "TRIAL"
            public string? AppVersion { get; set; }
            public string? CustomerEmail { get; set; }
            public string? CustomerName { get; set; }
            public Dictionary<string, string>? ComponentFingerprints { get; set; }
            public string? HardwareIdV2 { get; set; }
            public bool? HardwareIdV2Differs { get; set; }
            public string? HardwareIdAlgorithm { get; set; }
            public string? HardwareIdV2Algorithm { get; set; }
            public string? SdkVersion { get; set; }
            public string? BuildHash { get; set; }
        }

        private async Task<Product?> FindProductAsync(string name, string? id)
        {
            // 1. Recherche par ID si fourni et valide
            if (!string.IsNullOrEmpty(id) && Guid.TryParse(id, out var appId))
            {
                var p = await _db.Products.FirstOrDefaultAsync(p => p.Id == appId);
                if (p != null) return p;
            }

            // 2. Repli sur le nom
            return await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == name.ToLower());
        }

        private void TagLog(ActivationRequest req, string endpoint)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            if (!string.IsNullOrEmpty(req.AppId)) HttpContext.Items["AppId"] = req.AppId;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey.Trim().ToUpper();
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = endpoint;
            HttpContext.Items[LogKeys.Version] = req.AppVersion ?? "Unknown";
        }

        private void TagLog(TrialRequest req, string endpoint)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            if (!string.IsNullOrEmpty(req.AppId)) HttpContext.Items["AppId"] = req.AppId;
            HttpContext.Items[LogKeys.LicenseKey] = "AUTO-TRIAL";
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = endpoint;
            HttpContext.Items[LogKeys.Version] = req.AppVersion ?? "Unknown";
        }

        private void TagActivationFailure(string resultStatus)
        {
            HttpContext.Items[LogKeys.ResultStatusOverride] = resultStatus;
            Response.Headers[ActivationErrorCodeHeader] = resultStatus;
        }

        private IActionResult ActivationJsonFailure(string errorCode, string errorMessage)
        {
            TagActivationFailure(errorCode);
            return Ok(new { isSuccess = false, errorMessage, errorCode });
        }

        private static Dictionary<string, string> BuildFeatures(IEnumerable<LicenseTypeCustomParam>? customParams)
        {
            if (customParams == null) return new Dictionary<string, string>();
            return customParams.ToDictionary(p => p.Key, p => p.Value);
        }

        private static void SyncLegacyHardwareStateFromSeats(License license)
        {
            var activeSeat = license.Seats
                .Where(s => s.IsActive)
                .OrderByDescending(s => s.LastCheckInAt)
                .ThenByDescending(s => s.FirstActivatedAt)
                .FirstOrDefault();

            license.HardwareId = activeSeat?.HardwareId;
            license.ActivationDate = activeSeat?.FirstActivatedAt;

            if (activeSeat == null)
                license.RecoveryCount = 0;
        }

        private static string NormalizeDeactivationSource(string? source, string? deactivationSource)
        {
            var raw = string.IsNullOrWhiteSpace(source) ? deactivationSource : source;
            if (string.IsNullOrWhiteSpace(raw))
                return "legacy_unknown";

            return raw.Trim().ToLowerInvariant() switch
            {
                "settings_button" or "settings" or "settings-button" => "settings_button",
                "uninstall" or "uninstaller" => "uninstall",
                "portal" => "portal",
                "admin" => "admin",
                "legacy_unknown" => "legacy_unknown",
                "unknown" => "unknown",
                _ => "unknown"
            };
        }

        private static bool IsTrustedImmediateDeactivationSource(string source)
        {
            return source is "settings_button" or "uninstall";
        }

        private static void ApplyPluginMetadataFromReference(LicenseModel model)
        {
            if (string.IsNullOrWhiteSpace(model.Reference)) return;

            var parts = model.Reference.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length < 2 || !string.Equals(parts[0], "plugin", StringComparison.OrdinalIgnoreCase)) return;

            model.PluginId = parts[1];
            model.AllowedFeatures = new[] { "*" };

            if (model.Features.TryGetValue("pluginVersion", out var pluginVersion) && !string.IsNullOrWhiteSpace(pluginVersion))
                model.PluginVersion = pluginVersion;
            if (model.Features.TryGetValue("minAppVersion", out var minAppVersion) && !string.IsNullOrWhiteSpace(minAppVersion))
                model.MinAppVersion = minAppVersion;

            foreach (var part in parts.Skip(2))
            {
                var separatorIndex = part.IndexOf('=');
                if (separatorIndex <= 0 || separatorIndex == part.Length - 1) continue;

                var key = part[..separatorIndex];
                var value = part[(separatorIndex + 1)..];

                if (string.Equals(key, "pluginVersion", StringComparison.OrdinalIgnoreCase))
                    model.PluginVersion = value;
                else if (string.Equals(key, "minAppVersion", StringComparison.OrdinalIgnoreCase))
                    model.MinAppVersion = value;
                else if (string.Equals(key, "allowedFeatures", StringComparison.OrdinalIgnoreCase))
                    model.AllowedFeatures = value
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .DefaultIfEmpty("*")
                        .ToArray();
            }
        }

        private static bool IsValidEmailSyntax(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            return Regex.IsMatch(email.Trim(), @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase);
        }

        private static bool HasValidMxRecord(string email)
        {
            try
            {
                var domain = email.Trim().Split('@').LastOrDefault();
                if (string.IsNullOrEmpty(domain)) return false;
                var hostEntry = Dns.GetHostEntry(domain);
                return hostEntry.AddressList.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsPaidLicenseEligibleForAutoUnban(License license)
        {
            if (!license.IsActive || license.RevokedAt != null)
                return false;

            if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value)
                return false;

            var slug = license.Type?.Slug?.Trim().ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(slug))
                return false;

            if (license.Type?.IsFree == true)
                return false;

            return slug is not ("FREEMIUM" or "TRIAL" or "FREE" or "STUDENT");
        }

        private static bool EnforcesSingleUsePerHardwareId(LicenseType? type)
        {
            return type?.EnforceSingleUsePerHardwareId == true;
        }

        private static bool HasHardwareIdV2Observation(string? hardwareIdV2)
        {
            return !string.IsNullOrWhiteSpace(hardwareIdV2);
        }

        private void AddHardwareIdV2Observation(License license, Product product, string endpoint, string hardwareId, string? hardwareIdV2, bool? hardwareIdV2Differs, string? appVersion, string? sdkVersion, string? buildHash, string? hardwareIdAlgorithm, string? hardwareIdV2Algorithm)
        {
            if (!HasHardwareIdV2Observation(hardwareIdV2))
            {
                return;
            }

            var activeSeat = license.Seats?
                .Where(s => s.IsActive && string.Equals(s.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(s => s.LastCheckInAt)
                .FirstOrDefault();

            var details = JsonSerializer.Serialize(new
            {
                endpoint,
                productId = product.Id,
                productName = product.Name,
                licenseId = license.Id,
                seatId = activeSeat?.Id,
                legacyHardwareId = hardwareId,
                hardwareIdV2 = hardwareIdV2!.Trim(),
                hardwareIdV2Differs = hardwareIdV2Differs ?? !string.Equals(hardwareId, hardwareIdV2, StringComparison.OrdinalIgnoreCase),
                appVersion,
                sdkVersion,
                buildHash,
                hardwareIdAlgorithm,
                hardwareIdV2Algorithm,
                observedAtUtc = DateTime.UtcNow
            });

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.HardwareIdV2Observed,
                Details = details,
                PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });
        }

        private void AddHardwareIdV2Observation(License license, Product product, string endpoint, ActivationRequest req)
        {
            AddHardwareIdV2Observation(license, product, endpoint, req.HardwareId, req.HardwareIdV2, req.HardwareIdV2Differs, req.AppVersion, req.SdkVersion, req.BuildHash, req.HardwareIdAlgorithm, req.HardwareIdV2Algorithm);
        }

        private void AddHardwareIdV2Observation(License license, Product product, string endpoint, TrialRequest req)
        {
            AddHardwareIdV2Observation(license, product, endpoint, req.HardwareId, req.HardwareIdV2, req.HardwareIdV2Differs, req.AppVersion, req.SdkVersion, req.BuildHash, req.HardwareIdAlgorithm, req.HardwareIdV2Algorithm);
        }

        private async Task<bool> HasRecentHardwareIdV2ObservationAsync(Guid licenseId, string legacyHardwareId, string hardwareIdV2)
        {
            var cutoff = DateTime.UtcNow.AddHours(-24);
            var stableHardwareId = hardwareIdV2.Trim();

            return await _db.LicenseHistories.AnyAsync(h =>
                h.LicenseId == licenseId
                && h.Action == HistoryActions.HardwareIdV2Observed
                && h.Timestamp >= cutoff
                && h.Details != null
                && h.Details.Contains(legacyHardwareId)
                && h.Details.Contains(stableHardwareId));
        }

        private static bool DisablesNewActivations(LicenseType? type)
        {
            return type?.DisableNewActivations == true;
        }

        private async Task<bool> HasConsumedLicenseTypeOnHardwareAsync(
            Guid productId,
            Guid licenseTypeId,
            string hardwareId,
            Guid? currentLicenseId = null)
        {
            return await _db.Licenses
                .AsNoTracking()
                .Where(l => l.ProductId == productId
                    && l.LicenseTypeId == licenseTypeId
                    && (!currentLicenseId.HasValue || l.Id != currentLicenseId.Value)
                    && (l.HardwareId == hardwareId
                        || l.Seats.Any(s => s.HardwareId == hardwareId)))
                .AnyAsync();
        }

        private async Task<IActionResult?> RejectIfSingleUseHardwareAlreadyConsumedAsync(
            Guid productId,
            LicenseType? type,
            string hardwareId,
            Guid? currentLicenseId = null)
        {
            if (!EnforcesSingleUsePerHardwareId(type))
                return null;

            if (!await HasConsumedLicenseTypeOnHardwareAsync(productId, type!.Id, hardwareId, currentLicenseId))
                return null;

            TagActivationFailure("FREEMIUM_HWID_ALREADY_CONSUMED");
            _logger.LogWarning(
                "Activation refused: HWID {HardwareId} has already consumed license type {LicenseTypeId} for product {ProductId}. CurrentLicenseId={CurrentLicenseId}",
                hardwareId,
                type.Id,
                productId,
                currentLicenseId);

            return BadRequest("Freemium access has already been used on this machine.");
        }

        private IActionResult? RejectIfNewActivationsDisabled(LicenseType? type, string hardwareId, string? licenseKey = null)
        {
            if (!DisablesNewActivations(type))
                return null;

            TagActivationFailure("LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED");
            _logger.LogWarning(
                "Activation refused: new activations are disabled for license type {LicenseTypeSlug} ({LicenseTypeId}). HWID={HardwareId}, LicenseKey={LicenseKey}",
                type?.Slug,
                type?.Id,
                hardwareId,
                licenseKey);

            return BadRequest("New activations are no longer available for this license type.");
        }

        /// <summary>
        /// Retourne tous les IDs de la hiérarchie produit (racine + enfants + petits-enfants, max 3 niveaux).
        /// </summary>
        private async Task<List<Guid>> GetProductHierarchyIds(Guid rootProductId)
        {
            var ids = new List<Guid> { rootProductId };
            var childIds = await _db.Products
                .Where(p => p.ParentProductId == rootProductId)
                .Select(p => p.Id).ToListAsync();
            ids.AddRange(childIds);
            if (childIds.Count > 0)
            {
                var grandChildIds = await _db.Products
                    .Where(p => p.ParentProductId != null && childIds.Contains(p.ParentProductId.Value))
                    .Select(p => p.Id).ToListAsync();
                ids.AddRange(grandChildIds);
            }
            return ids;
        }

        private bool IsVersionAllowed(string? clientVersion, string allowedMask)
        {
            if (string.IsNullOrEmpty(allowedMask) || allowedMask == "*") return true;
            if (string.IsNullOrEmpty(clientVersion)) return false;

            // Logique simple de préfixe (ex: "1.*" autorise "1.0", "1.2.3")
            if (allowedMask.EndsWith(".*"))
            {
                var prefix = allowedMask.Substring(0, allowedMask.Length - 1); // ex: "1."
                return clientVersion.StartsWith(prefix);
            }

            // Correspondance exacte
            return clientVersion == allowedMask;
        }

        private static bool IsVersionBelow(string? current, string? minimum)
        {
            if (string.IsNullOrWhiteSpace(current) || string.IsNullOrWhiteSpace(minimum))
                return false;

            if (Version.TryParse(current, out var cur) && Version.TryParse(minimum, out var min))
                return cur < min;

            return string.Compare(current, minimum, StringComparison.Ordinal) < 0;
        }

        [HttpPost("trial")]
        public async Task<IActionResult> GetTrial([FromBody] TrialRequest req)
        {
            TagLog(req, "TRIAL_AUTO");

            var hwidBanned = await _security.IsHardwareIdBannedAsync(req.HardwareId);
            var compBanned = false;
            if (!hwidBanned && req.ComponentFingerprints != null)
            {
                var (cb, _, _) = await _security.IsComponentBannedAsync(req.ComponentFingerprints);
                compBanned = cb;
            }
            if (hwidBanned || compBanned)
                return ActivationJsonFailure(compBanned ? "COMPONENT_BANNED" : "BANNED", "Access denied by server");

            if (req.ComponentFingerprints != null)
            {
                _ = Task.Run(async () => { try { await _fingerprint.UpsertFingerprintAsync(req.HardwareId, req.ComponentFingerprints); } catch { } });
            }

            var product = await FindProductAsync(req.AppName, req.AppId);
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;
            
            var type = await _db.LicenseTypes
                .Include(t => t.CustomParams)
                .FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToUpper() == req.TypeSlug.Trim().ToUpper());
            if (type == null) return BadRequest(string.Format(_localizer["Api_LicenseTypeUnknown"].Value, req.TypeSlug));

            // Vérifier si ce PC a déjà une licence pour ce produit
            // Priorité : même type demandé > active > expiration la plus récente
            var requestedSlug = req.TypeSlug.Trim().ToUpper();
            var existing = await _db.Licenses
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Where(l => l.ProductId == product.Id
                    && (l.HardwareId == req.HardwareId
                        || l.Seats.Any(s => s.HardwareId == req.HardwareId)))
                .OrderByDescending(l => l.Type != null && l.Type.Slug.ToUpper() == requestedSlug ? 1 : 0)
                .ThenByDescending(l => l.IsActive ? 1 : 0)
                .ThenByDescending(l => l.ExpirationDate)
                .FirstOrDefaultAsync();

            if (existing != null)
            {
                // Révoquée → 403 Forbidden
                if (!existing.IsActive)
                    return StatusCode(403, _localizer["Api_AccessRevoked"].Value);

                bool isExpired = existing.ExpirationDate.HasValue && DateTime.UtcNow > existing.ExpirationDate.Value;
                bool isDifferentType = !string.Equals(existing.Type?.Slug, req.TypeSlug.Trim(), StringComparison.OrdinalIgnoreCase);
                bool isCommunitySlug = string.Equals(existing.Type?.Slug, "YOUR_APP_NAME-COMMUNITY", StringComparison.OrdinalIgnoreCase);

                // Renouvellement automatique : UNIQUEMENT Community gratuite expirée qui redemande Community
                if (isCommunitySlug && existing.Type?.IsRecurring == true && isExpired && !isDifferentType)
                {
                    existing.ExpirationDate = DateTime.UtcNow.AddDays(existing.Type.DefaultDurationDays);
                    _db.LicenseHistories.Add(new LicenseHistory {
                        LicenseId = existing.Id,
                        Action = HistoryActions.Renewed,
                        Details = $"Renouvellement automatique ({existing.Type.Name}) : +{existing.Type.DefaultDurationDays} jours",
                        PerformedBy = "System"
                    });
                    await _db.SaveChangesAsync();
                    _logger.LogInformation("Renouvellement Community : {HardwareId} → expiration {Expiry}", req.HardwareId, existing.ExpirationDate);
                }

                // Licence expirée + type différent demandé → créer une nouvelle licence
                // Couvre : Trial FIXE expiré → Community, plan payant expiré → Community
                if (isExpired && isDifferentType)
                {
                    _logger.LogInformation("Licence expirée ({OldType}) → création d'une nouvelle licence {NewType} pour {HardwareId}",
                        existing.Type?.Slug, req.TypeSlug, req.HardwareId);
                    // Fall through to licence creation below
                }
                else
                {
                    // Retourner la licence existante (valide, ou plan payant actif non expiré)
                    // Mise à jour des infos client si fournies
                    if (!string.IsNullOrWhiteSpace(req.CustomerEmail))
                        existing.CustomerEmail = req.CustomerEmail;
                    if (!string.IsNullOrWhiteSpace(req.CustomerName))
                        existing.CustomerName = req.CustomerName;

                    var seat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == existing.Id && s.HardwareId == req.HardwareId && s.IsActive);
                    if (seat == null)
                    {
                        _db.LicenseSeats.Add(new LicenseSeat {
                            LicenseId = existing.Id, HardwareId = req.HardwareId,
                            FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow,
                            IsActive = true
                        });
                    }
                    AddHardwareIdV2Observation(existing, product, "TRIAL_EXISTING", req);
                    await _db.SaveChangesAsync();

                    var model = new LicenseModel
                    {
                        Id = existing.Id,
                        LicenseKey = existing.LicenseKey,
                        CustomerName = existing.CustomerName,
                        CustomerEmail = existing.CustomerEmail,
                        TypeSlug = existing.Type?.Slug ?? "STANDARD",
                        Reference = existing.Reference,
                        CreationDate = existing.CreationDate,
                        ExpirationDate = existing.ExpirationDate,
                        HardwareId = existing.HardwareId ?? string.Empty,
                        Features = BuildFeatures(existing.Type?.CustomParams)
                    };

                    try
                    {
                        var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                        if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                        var signed = LicenseService.GenerateLicense(model, decryptedKey);
                        _logger.LogInformation("Licence recovery : Renvoi de la licence existante ({TypeSlug}) pour {HardwareId}", existing.Type?.Slug, req.HardwareId);
                        return Ok(new { LicenseFile = signed });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erreur signature licence recovery pour {HardwareId}", req.HardwareId);
                        return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    }
                }
            }

            // Sinon, création d'une nouvelle licence Trial
            var trialNewActivationsDisabled = RejectIfNewActivationsDisabled(type, req.HardwareId);
            if (trialNewActivationsDisabled != null)
                return trialNewActivationsDisabled;

            var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(product.Id, type, req.HardwareId);
            if (freemiumAlreadyConsumed != null)
                return freemiumAlreadyConsumed;

            using var trialTransaction = _db.Database.ProviderName == "Microsoft.EntityFrameworkCore.InMemory" ? null : await _db.Database.BeginTransactionAsync();
            try
            {
            var newKey = Guid.NewGuid().ToString("D").ToUpper();
            var license = new License
            {
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                LicenseKey = newKey,
                CustomerName = req.CustomerName ?? "Auto Trial",
                CustomerEmail = req.CustomerEmail ?? "trial@auto.local",
                HardwareId = req.HardwareId,
                ActivationDate = DateTime.UtcNow,
                CreationDate = DateTime.UtcNow,
                ExpirationDate = DateTime.UtcNow.AddDays(type.DefaultDurationDays),
                IsActive = true
            };

            _db.Licenses.Add(license);

            // Création du siège initial pour le multi-postes
            var firstSeat = new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = req.HardwareId,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow,
                IsActive = true
            };
            _db.LicenseSeats.Add(firstSeat);

            _db.LicenseHistories.Add(new LicenseHistory {
                LicenseId = license.Id,
                Action = HistoryActions.Created,
                Details = string.Format(_localizer["Licenses_Action_Created"].Value, type.Name, 1),
                PerformedBy = "System"
            });
            AddHardwareIdV2Observation(license, product, "TRIAL_CREATE", req);

            await _db.SaveChangesAsync();

            // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
            await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                req.HardwareId, license.Id, product.Id);

            _logger.LogInformation("Nouveau Trial cree : {TypeSlug} ({Days} jours) pour {HardwareId}", type.Slug, type.DefaultDurationDays, req.HardwareId);

            var licenseModel = new LicenseModel
            {
                Id = license.Id,
                LicenseKey = license.LicenseKey,
                CustomerName = license.CustomerName,
                CustomerEmail = license.CustomerEmail,
                TypeSlug = type.Slug,
                Reference = license.Reference,
                CreationDate = license.CreationDate,
                ExpirationDate = license.ExpirationDate,
                HardwareId = license.HardwareId ?? string.Empty,
                Features = BuildFeatures(type.CustomParams)
            };

            var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
            if (decryptedKey == "ERROR_DECRYPTION_FAILED")
            {
                if (trialTransaction != null) await trialTransaction.RollbackAsync();
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
            var signedLicenseString = LicenseService.GenerateLicense(licenseModel, decryptedKey);
            if (trialTransaction != null) await trialTransaction.CommitAsync();
            return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Exception ex)
            {
                if (trialTransaction != null) await trialTransaction.RollbackAsync();
                _logger.LogError(ex, "Erreur creation trial pour {HardwareId}", req.HardwareId);
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
        }

        [HttpPost]
        public async Task<IActionResult> Activate([FromBody] ActivationRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, "ACTIVATE");

            if (req.ComponentFingerprints != null)
            {
                _ = Task.Run(async () => { try { await _fingerprint.UpsertFingerprintAsync(req.HardwareId, req.ComponentFingerprints); } catch { } });
            }

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                _logger.LogWarning("Activation echouee : Application '{AppName}' inconnue.", req.AppName);
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            // Check ban status. HWID auto-unban is deferred until the license is fully validated.
            var hwidBanned = await _security.IsHardwareIdBannedAsync(req.HardwareId);
            var compBanned = false;
            if (!hwidBanned && req.ComponentFingerprints != null)
            {
                var (cb, _, _) = await _security.IsComponentBannedAsync(req.ComponentFingerprints);
                compBanned = cb;
            }
            if (compBanned)
                return ActivationJsonFailure("COMPONENT_BANNED", "Access denied by server");

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            // --- INTERCEPTION AUTO-TRIAL ---
            if (cleanKey.EndsWith("-FREE-TRIAL") || cleanKey == "FREE-TRIAL")
            {
                if (hwidBanned)
                    return ActivationJsonFailure("BANNED", "Access denied by server");

                _logger.LogInformation("Detection d'une demande AUTO-TRIAL pour {AppName}", product.Name);
                HttpContext.Items[LogKeys.Endpoint] = "TRIAL_AUTO";
                
                // On cherche d'abord une correspondance exacte du Slug avec la clé, sinon le slug "TRIAL" — toujours filtré par produit
                var type = await _db.LicenseTypes.Include(t => t.CustomParams).FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToLower() == cleanKey.ToLower())
                           ?? await _db.LicenseTypes.Include(t => t.CustomParams).FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToLower() == "trial");

                if (type == null) 
                {
                    TagActivationFailure("TRIAL_NOT_ENABLED");
                    _logger.LogWarning("Demande Trial echouee : Aucun type de licence 'TRIAL' n'est configure.");
                    return BadRequest(_localizer["Api_TrialNotEnabled"].Value);
                }

                // On vérifie si ce PC a déjà une licence pour ce produit
                var existing = await _db.Licenses
                    .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                    .FirstOrDefaultAsync(l => l.ProductId == product.Id
                        && (l.HardwareId == req.HardwareId
                            || l.Seats.Any(s => s.HardwareId == req.HardwareId)));

                if (existing != null)
                {
                    // Révoquée → 403 Forbidden
                    if (!existing.IsActive)
                        return StatusCode(403, _localizer["Api_AccessRevoked"].Value);

                    // Récurrent (Community) + expirée → renouvellement automatique
                    if (existing.Type?.IsRecurring == true && existing.ExpirationDate.HasValue && DateTime.UtcNow > existing.ExpirationDate.Value)
                    {
                        existing.ExpirationDate = DateTime.UtcNow.AddDays(existing.Type.DefaultDurationDays);
                        _db.LicenseHistories.Add(new LicenseHistory {
                            LicenseId = existing.Id,
                            Action = HistoryActions.Renewed,
                            Details = $"Renouvellement automatique ({existing.Type.Name}) : +{existing.Type.DefaultDurationDays} jours",
                            PerformedBy = "System"
                        });
                        await _db.SaveChangesAsync();
                        _logger.LogInformation("Renouvellement {TypeSlug} : {HardwareId} → expiration {Expiry}", existing.Type.Slug, req.HardwareId, existing.ExpirationDate);
                    }

                    // Sinon → renvoi tel quel (trial non renouvelable reste expiré côté client)

                    // S'assurer que le siège existe (pour les licences créées avant le système de seats)
                    var seat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == existing.Id && s.HardwareId == req.HardwareId && s.IsActive);
                    if (seat == null)
                    {
                        _db.LicenseSeats.Add(new LicenseSeat {
                            LicenseId = existing.Id, HardwareId = req.HardwareId,
                            FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow,
                            IsActive = true
                        });
                        AddHardwareIdV2Observation(existing, product, "TRIAL_AUTO_EXISTING", req);
                        await _db.SaveChangesAsync();
                    }
                    else {
                        seat.LastCheckInAt = DateTime.UtcNow;
                        AddHardwareIdV2Observation(existing, product, "TRIAL_AUTO_EXISTING", req);
                        await _db.SaveChangesAsync();
                    }

                    // Mise à jour des infos client si fournies
                    if (!string.IsNullOrWhiteSpace(req.CustomerEmail))
                        existing.CustomerEmail = req.CustomerEmail;
                    if (!string.IsNullOrWhiteSpace(req.CustomerName))
                        existing.CustomerName = req.CustomerName;
                    if (!string.IsNullOrWhiteSpace(req.CustomerEmail) || !string.IsNullOrWhiteSpace(req.CustomerName))
                        await _db.SaveChangesAsync();

                    // On met à jour le log avec la vraie clé trouvée
                    HttpContext.Items[LogKeys.LicenseKey] = existing.LicenseKey;

                    var recoveryModel = new LicenseModel {
                        Id = existing.Id, LicenseKey = existing.LicenseKey, CustomerName = existing.CustomerName,
                        CustomerEmail = existing.CustomerEmail, TypeSlug = existing.Type?.Slug ?? "TRIAL",
                        Reference = existing.Reference,
                        CreationDate = existing.CreationDate, ExpirationDate = existing.ExpirationDate, HardwareId = existing.HardwareId ?? string.Empty,
                        Features = BuildFeatures(existing.Type?.CustomParams)
                    };

                    try
                    {
                        var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                        if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                        return Ok(new { LicenseFile = LicenseService.GenerateLicense(recoveryModel, decryptedKey) });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erreur signature recovery trial");
                        return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    }
                }

                // Création auto (atomique)
                var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(product.Id, type, req.HardwareId);
                if (freemiumAlreadyConsumed != null)
                    return freemiumAlreadyConsumed;

                using var autoTrialTx = _db.Database.ProviderName == "Microsoft.EntityFrameworkCore.InMemory" ? null : await _db.Database.BeginTransactionAsync();
                try
                {
                var newKey = Guid.NewGuid().ToString("D").ToUpper();
                var newLic = new License {
                    ProductId = product.Id, LicenseTypeId = type.Id, LicenseKey = newKey,
                    CustomerName = req.CustomerName ?? "Auto Trial", CustomerEmail = req.CustomerEmail ?? "trial@auto.local",
                    HardwareId = req.HardwareId, ActivationDate = DateTime.UtcNow, CreationDate = DateTime.UtcNow,
                    ExpirationDate = DateTime.UtcNow.AddDays(type.DefaultDurationDays), IsActive = true
                };
                _db.Licenses.Add(newLic);

                // Création du siège initial pour le multi-postes
                var firstSeat = new LicenseSeat
                {
                    LicenseId = newLic.Id,
                    HardwareId = req.HardwareId,
                    FirstActivatedAt = DateTime.UtcNow,
                    LastCheckInAt = DateTime.UtcNow,
                    IsActive = true
                };
                _db.LicenseSeats.Add(firstSeat);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = newLic.Id,
                    Action = HistoryActions.Created,
                    Details = string.Format(_localizer["Licenses_Action_Created"].Value, type.Name, 1),
                    PerformedBy = "System"
                });
                AddHardwareIdV2Observation(newLic, product, "TRIAL_AUTO_CREATE", req);

                await _db.SaveChangesAsync();

                // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
                await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                    req.HardwareId, newLic.Id, product.Id);

                await _hwidReuseAlerts.CheckAndNotifyAsync(product.Id, req.HardwareId, newLic.Id);

                // On met à jour le log avec la clé générée
                HttpContext.Items[LogKeys.LicenseKey] = newKey;

                var newModel = new LicenseModel {
                    Id = newLic.Id, LicenseKey = newLic.LicenseKey, CustomerName = newLic.CustomerName,
                    CustomerEmail = newLic.CustomerEmail, TypeSlug = type.Slug,
                    Reference = newLic.Reference,
                    CreationDate = newLic.CreationDate, ExpirationDate = newLic.ExpirationDate, HardwareId = newLic.HardwareId ?? string.Empty,
                    Features = BuildFeatures(type.CustomParams)
                };

                var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                if (decryptedKey == "ERROR_DECRYPTION_FAILED")
                {
                    if (autoTrialTx != null) await autoTrialTx.RollbackAsync();
                    return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                }
                var signed = LicenseService.GenerateLicense(newModel, decryptedKey);
                if (autoTrialTx != null) await autoTrialTx.CommitAsync();
                return Ok(new { LicenseFile = signed });
                }
                catch (Exception ex)
                {
                    if (autoTrialTx != null) await autoTrialTx.RollbackAsync();
                    _logger.LogError(ex, "Erreur creation auto-trial pour {AppName}", req.AppName);
                    return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                }
            }
            // --- FIN INTERCEPTION ---

            var productIds = await GetProductHierarchyIds(product.Id);
            var license = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && productIds.Contains(l.ProductId));

            if (license == null) 
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                _logger.LogWarning("Activation echouee : Cle '{LicenseKey}' non trouvee pour le produit '{ProductName}' (ID: {ProductId}).", cleanKey, product.Name, product.Id);
                return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            }
            
            if (!license.IsActive) 
            {
                TagActivationFailure("LICENSE_DISABLED");
                _logger.LogWarning("Activation echouee : Cle '{LicenseKey}' revoquee.", cleanKey);
                return BadRequest(_localizer["Api_LicenseDisabled"].Value);
            }
            
            if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value)
            {
                TagActivationFailure("LICENSE_EXPIRED");
                _logger.LogWarning(
                    "Activation echouee : licence expiree pour HWID {HardwareId}, app {AppName}, type {TypeSlug}, expiry {Expiry}, version {Version}.",
                    req.HardwareId,
                    product.Name,
                    license.Type?.Slug ?? "UNKNOWN",
                    license.ExpirationDate,
                    req.AppVersion ?? "Unknown");
                return BadRequest(_localizer["Api_LicenseExpired"].Value);
            }

            // Vérification de version
            if (!IsVersionAllowed(req.AppVersion, license.AllowedVersions))
            {
                TagActivationFailure("VERSION_NOT_ALLOWED");
                _logger.LogWarning("Activation echouee : Version '{Version}' non autorisee pour la cle '{LicenseKey}' (Attendu: '{Allowed}')", req.AppVersion, cleanKey, license.AllowedVersions);
                return BadRequest(string.Format(_localizer["Api_VersionNotAllowed"].Value, req.AppVersion));
            }

            // --- VÉRIFICATION PARTENAIRE ---
            bool isResellerLicense = !string.IsNullOrWhiteSpace(license.PartnerCode);
            if (isResellerLicense)
            {
                var partnerExists = await _db.ResellerPartners.AnyAsync(p => p.Code == license.PartnerCode);
                var partner = partnerExists
                    ? await _db.ResellerPartners.FirstOrDefaultAsync(p => p.Code == license.PartnerCode && p.IsActive)
                    : null;
                if (partner == null)
                {
                    if (!partnerExists)
                        _logger.LogError("Activation BLOQUEE : Partner code '{PartnerCode}' N'EXISTE PAS dans ResellerPartners pour la cle '{LicenseKey}' (HWID: {HardwareId}, Email: {Email}). La licence a ete creee avec un PartnerCode non enregistre.", license.PartnerCode, cleanKey, req.HardwareId, req.CustomerEmail);
                    else
                        _logger.LogError("Activation BLOQUEE : Partner code '{PartnerCode}' DESACTIVE pour la cle '{LicenseKey}' (HWID: {HardwareId}, Email: {Email}).", license.PartnerCode, cleanKey, req.HardwareId, req.CustomerEmail);
                    TagActivationFailure("PARTNER_INVALID");
                    return BadRequest(_localizer["Api_LicenseDisabled"].Value);
                }
            }

            // --- VÉRIFICATION EMAIL ---
            bool isAnonymousType = license.Type?.AllowAnonymous == true;
            bool licenseHasEmail = !string.IsNullOrWhiteSpace(license.CustomerEmail);
            bool requestHasEmail = !string.IsNullOrWhiteSpace(req.CustomerEmail);

            if (isResellerLicense)
            {
                // Reseller license: email is optional, just capture it if provided
                if (requestHasEmail && !licenseHasEmail)
                {
                    license.CustomerEmail = req.CustomerEmail!.Trim();
                    if (!string.IsNullOrWhiteSpace(req.CustomerName))
                        license.CustomerName = req.CustomerName.Trim();
                }
            }
            else if (licenseHasEmail && requestHasEmail)
            {
                // Licence avec email : vérifier la correspondance
                if (!string.Equals(license.CustomerEmail.Trim(), req.CustomerEmail!.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    TagActivationFailure("EMAIL_MISMATCH");
                    _logger.LogWarning("Activation echouee : Email '{SentEmail}' ne correspond pas pour la cle '{LicenseKey}'", req.CustomerEmail, cleanKey);
                    return BadRequest(_localizer["Api_EmailMismatch"].Value);
                }
            }
            else if (!licenseHasEmail && isAnonymousType)
            {
                // Licence anonyme sans email : l'email est obligatoire pour la réclamer
                if (!requestHasEmail)
                {
                    TagActivationFailure("EMAIL_REQUIRED");
                    _logger.LogWarning("Activation echouee : Email requis pour cle anonyme '{LicenseKey}'", cleanKey);
                    return BadRequest(_localizer["Api_EmailRequiredAnonymous"].Value);
                }

                // Vérification syntaxe + MX
                if (!IsValidEmailSyntax(req.CustomerEmail!))
                {
                    TagActivationFailure("EMAIL_INVALID");
                    return BadRequest(_localizer["Api_InvalidEmail"].Value);
                }
                if (!HasValidMxRecord(req.CustomerEmail!))
                {
                    TagActivationFailure("EMAIL_DOMAIN_INVALID");
                    _logger.LogWarning("Activation echouee : Domaine email invalide pour '{Email}'", req.CustomerEmail);
                    return BadRequest(_localizer["Api_InvalidEmailDomain"].Value);
                }

                // Associer l'email et le nom à la licence
                license.CustomerEmail = req.CustomerEmail!.Trim();
                if (!string.IsNullOrWhiteSpace(req.CustomerName))
                    license.CustomerName = req.CustomerName.Trim();

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = "CLAIMED",
                    Details = $"Clé anonyme réclamée par {req.CustomerEmail}",
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }

            if (hwidBanned)
            {
                if (!IsPaidLicenseEligibleForAutoUnban(license))
                    return ActivationJsonFailure("BANNED", "Access denied by server");

                var (canProceed, permanentBan) = await _security.TryAutoUnbanForPaidLicenseAsync(req.HardwareId, license.ProductId);
                if (!canProceed)
                    return ActivationJsonFailure("BANNED", permanentBan ? "Access permanently denied" : "Access denied by server");

                hwidBanned = false;
            }

            // --- GESTION MULTI-POSTES (SEATS) ---
            var existingSeat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == license.Id && s.HardwareId == req.HardwareId && s.IsActive);
            
            if (existingSeat != null)
            {
                // Poste déjà connu : On met à jour la date de passage
                existingSeat.LastCheckInAt = DateTime.UtcNow;
                if (!string.IsNullOrEmpty(req.AppVersion)) existingSeat.AppVersion = req.AppVersion;
                license.HardwareId = req.HardwareId;
                license.ActivationDate = existingSeat.FirstActivatedAt;
                var resolvedVersion = req.AppVersion ?? existingSeat.AppVersion ?? "Unknown";
                license.RecoveryCount++;
                TagLog(req, "RECOVERY");
                _logger.LogInformation("Recovery reussi (Multi-Seat) : Cle '{LicenseKey}' sur HWID '{HardwareId}'", cleanKey, req.HardwareId);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Recovery,
                    Details = string.Format(_localizer["Licenses_Action_Activated"].Value, req.HardwareId, resolvedVersion),
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }
            else
            {
                var newActivationsDisabled = RejectIfNewActivationsDisabled(license.Type, req.HardwareId, cleanKey);
                if (newActivationsDisabled != null)
                    return newActivationsDisabled;

                var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(license.ProductId, license.Type, req.HardwareId, license.Id);
                if (freemiumAlreadyConsumed != null)
                    return freemiumAlreadyConsumed;

                // Nouveau poste : On vérifie si on a encore de la place
                var currentSeatsCount = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id && s.IsActive);

                if (currentSeatsCount >= license.MaxSeats)
                {
                    TagActivationFailure("SEAT_LIMIT");
                    _logger.LogWarning("Activation echouee : Limite de postes atteinte ({Max}) pour la clé '{LicenseKey}'", license.MaxSeats, cleanKey);
                    return BadRequest(string.Format(_localizer["Api_MaxActivationsReached"].Value, license.MaxSeats));
                }

                // Vérification du quota d'activations par jour
                var maxPerDay = license.Type?.MaxActivationsPerDay ?? 0;
                if (maxPerDay > 0)
                {
                    var todayStart = DateTime.UtcNow.Date;
                    var activationsToday = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id && s.FirstActivatedAt >= todayStart);
                    if (activationsToday >= maxPerDay)
                    {
                        TagActivationFailure("MAX_DAILY_ACTIVATIONS_REACHED");
                        _logger.LogWarning("Activation echouee : Limite quotidienne atteinte ({Max}/jour) pour la clé '{LicenseKey}'", maxPerDay, cleanKey);
                        return BadRequest(string.Format(_localizer["Api_MaxDailyActivationsReached"].Value, maxPerDay));
                    }
                }

                // On crée le nouveau siège
                var newSeat = new LicenseSeat
                {
                    LicenseId = license.Id,
                    HardwareId = req.HardwareId,
                    FirstActivatedAt = DateTime.UtcNow,
                    LastCheckInAt = DateTime.UtcNow,
                    AppVersion = req.AppVersion,
                    IsActive = true
                };
                _db.LicenseSeats.Add(newSeat);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Activated,
                    Details = string.Format(_localizer["Licenses_Action_Activated"].Value, req.HardwareId, req.AppVersion ?? "Unknown"),
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });

                // Pour la compatibilité v1, on garde le champ principal aligné sur le premier poste actif.
                if (currentSeatsCount == 0 || string.IsNullOrEmpty(license.HardwareId))
                {
                    license.HardwareId = req.HardwareId;
                    license.ActivationDate = newSeat.FirstActivatedAt;

                    // Démarrer le décompte de validité à la première activation
                    if (license.ValidityDays.HasValue && !license.ExpirationDate.HasValue)
                    {
                        license.ExpirationDate = DateTime.UtcNow.AddDays(license.ValidityDays.Value);
                    }
                }

                _logger.LogInformation("Nouveau poste active ({Count}/{Max}) : Cle '{LicenseKey}' sur HWID '{HardwareId}'", currentSeatsCount + 1, license.MaxSeats, cleanKey, req.HardwareId);

                _notifier.Notify(Services.NotificationService.Triggers.LicenseActivated,
                    "✅ Licence Activée",
                    $"Produit: {product.Name}\nType: {license.Type?.Name ?? license.Type?.Slug ?? "Standard"}\nClient: {license.CustomerName}\nClé: {cleanKey}\nHWID: {req.HardwareId}\nPoste: {currentSeatsCount + 1}/{license.MaxSeats}");
            }

            // Mise à jour du nom client uniquement si la licence n'en avait pas (anonyme réclamée)
            // L'email est géré dans la section VÉRIFICATION EMAIL ci-dessus — on ne l'écrase jamais
            if (string.IsNullOrWhiteSpace(license.CustomerName) && !string.IsNullOrWhiteSpace(req.CustomerName))
                license.CustomerName = req.CustomerName.Trim();

            AddHardwareIdV2Observation(license, product, "ACTIVATE", req);
            await _db.SaveChangesAsync();

            // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
            await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                req.HardwareId, license.Id, license.ProductId);

            if (existingSeat == null)
                await _hwidReuseAlerts.CheckAndNotifyAsync(license.ProductId, req.HardwareId, license.Id);

            // Génération du fichier signé
            var features = BuildFeatures(license.Type?.CustomParams);
            if (req.ExtraParams is { Count: > 0 })
            {
                foreach (var kv in req.ExtraParams)
                    features[kv.Key] = kv.Value;
            }

            var licenseModel = new LicenseModel
            {
                Id = license.Id,
                LicenseKey = license.LicenseKey,
                CustomerName = license.CustomerName,
                CustomerEmail = license.CustomerEmail,
                TypeSlug = license.Type?.Slug ?? "STANDARD",
                Reference = license.Reference,
                CreationDate = license.CreationDate,
                ExpirationDate = license.ExpirationDate,
                HardwareId = req.HardwareId,
                Features = features
            };
            ApplyPluginMetadataFromReference(licenseModel);

            try
            {
                // Utiliser la clé privée du produit auquel la licence appartient (peut être un sous-produit/plugin)
                var signingProduct = license.Product ?? product;
                var decryptedKey = _encryption.Decrypt(signingProduct.PrivateKeyXml);
                if (decryptedKey == "ERROR_DECRYPTION_FAILED")
                {
                    _logger.LogError("ERREUR CRITIQUE : Impossible de dechiffrer la cle privee du produit '{ProductName}'. Les cles de DataProtection sont peut-etre manquantes ou invalides.", signingProduct.Name);
                    return StatusCode(500, _localizer["Api_InternalErrorServerKey"].Value);
                }

                var signedLicenseString = LicenseService.GenerateLicense(licenseModel, decryptedKey);
                return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la signature de la licence pour '{AppName}'", req.AppName);
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
        }

        [HttpPost("check")]
        public async Task<IActionResult> CheckStatus([FromBody] ActivationRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, "CHECK");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return NotFound(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            // For CheckStatus, return a logical status instead of 403 so the IP scoring middleware
            // doesn't penalize heartbeat callers. Version-enforcement bans are not license revocations.
            var hwidBan = await _security.GetActiveHardwareBanAsync(req.HardwareId, product.Id);
            if (hwidBan != null)
            {
                if (hwidBan.BanCategory == BannedHardwareId.Categories.OutdatedVersion)
                    return Ok(new { isSuccess = true, status = "UPDATE_REQUIRED", errorMessage = "Update required by server" });

                return Ok(new { isSuccess = true, status = "REVOKED", errorMessage = "Access denied by server" });
            }

            if (req.ComponentFingerprints != null)
            {
                var (compBanned, compType, compReason) = await _security.IsComponentBannedAsync(req.ComponentFingerprints);
                if (compBanned) return Ok(new { isSuccess = true, status = "REVOKED", errorMessage = "Access denied by server" });
                _ = Task.Run(async () => { try { await _fingerprint.UpsertFingerprintAsync(req.HardwareId, req.ComponentFingerprints); } catch { } });
            }

            var checkProductIds = await GetProductHierarchyIds(product.Id);
            var license = await _db.Licenses
                .Include(l => l.Type)
                    .ThenInclude(t => t!.CustomParams)
                .Include(l => l.Product)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && checkProductIds.Contains(l.ProductId));

            if (license == null) return NotFound(_localizer["Api_LicenseNotFound"].Value);

            string status = "VALID";
            if (!license.IsActive || license.RevokedAt != null) status = "REVOKED";
            else if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value) status = "EXPIRED";
            else
            {
                // Vérifier via les seats (multi-postes) au lieu du champ legacy HardwareId.
                var hasAnySeat = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id);
                var hasAnyActiveSeat = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.IsActive);
                if (hasAnyActiveSeat)
                {
                    var hasSeatForHwid = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.HardwareId == req.HardwareId && s.IsActive);
                    if (!hasSeatForHwid)
                    {
                        var hasInactiveSeatForHwid = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.HardwareId == req.HardwareId && !s.IsActive);
                        status = hasInactiveSeatForHwid ? "HARDWARE_NOT_ACTIVATED" : "HARDWARE_MISMATCH";
                    }
                }
                else if (hasAnySeat)
                    status = "HARDWARE_NOT_ACTIVATED";
                else if (string.IsNullOrEmpty(license.HardwareId))
                    status = "REQUIRES_ACTIVATION";
                else if (license.HardwareId != req.HardwareId)
                    status = "HARDWARE_MISMATCH";
            }

            string? errorMessage = null;
            if (status == "VALID" && IsVersionBelow(req.AppVersion, product.MinimumAllowedVersion))
            {
                status = "UPDATE_REQUIRED";
                errorMessage = "Update required by server";
                TagActivationFailure("UPDATE_REQUIRED");
                _logger.LogWarning(
                    "Check requires update: HWID {HardwareId}, app {AppName}, version {Version}, minimum {MinimumAllowedVersion}, license {LicenseId}.",
                    req.HardwareId,
                    product.Name,
                    req.AppVersion ?? "Unknown",
                    product.MinimumAllowedVersion,
                    license.Id);
            }

            if (status is "VALID" or "REQUIRES_ACTIVATION"
                && EnforcesSingleUsePerHardwareId(license.Type)
                && await HasConsumedLicenseTypeOnHardwareAsync(license.ProductId, license.LicenseTypeId, req.HardwareId, license.Id))
            {
                status = "FREEMIUM_HWID_ALREADY_CONSUMED";
                errorMessage = "Freemium access has already been used on this machine.";
                TagActivationFailure("FREEMIUM_HWID_ALREADY_CONSUMED");
                _logger.LogWarning(
                    "Check Freemium refused: HWID {HardwareId} has already consumed a Freemium license for product {ProductId}. LicenseId={LicenseId}",
                    req.HardwareId,
                    license.ProductId,
                    license.Id);
            }

            if (status == "REQUIRES_ACTIVATION" && DisablesNewActivations(license.Type))
            {
                status = "LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED";
                errorMessage = "New activations are no longer available for this license type.";
                TagActivationFailure("LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED");
                _logger.LogWarning(
                    "Check refused: new activations are disabled for license type {LicenseTypeSlug} ({LicenseTypeId}). HWID={HardwareId}, LicenseId={LicenseId}",
                    license.Type?.Slug,
                    license.Type?.Id,
                    req.HardwareId,
                    license.Id);
            }

            // Générer un fichier de licence frais avec les paramètres actuels du LicenseType
            string? licenseFile = null;
            if (status == "VALID")
            {
                try
                {
                    var licenseModel = new LicenseModel
                    {
                        Id = license.Id,
                        LicenseKey = license.LicenseKey,
                        CustomerName = license.CustomerName,
                        CustomerEmail = license.CustomerEmail,
                        TypeSlug = license.Type?.Slug ?? "STANDARD",
                        Reference = license.Reference,
                        CreationDate = license.CreationDate,
                        ExpirationDate = license.ExpirationDate,
                        HardwareId = req.HardwareId,
                        Features = BuildFeatures(license.Type?.CustomParams)
                    };

                    var signingProduct = license.Product ?? product;
                    var decryptedKey = _encryption.Decrypt(signingProduct.PrivateKeyXml);
                    if (decryptedKey != "ERROR_DECRYPTION_FAILED")
                    {
                        licenseFile = LicenseService.GenerateLicense(licenseModel, decryptedKey);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Impossible de generer le fichier de licence frais lors du check pour '{LicenseKey}'", cleanKey);
                }
            }

            if (HasHardwareIdV2Observation(req.HardwareIdV2)
                && !await HasRecentHardwareIdV2ObservationAsync(license.Id, req.HardwareId, req.HardwareIdV2!))
            {
                AddHardwareIdV2Observation(license, product, "CHECK", req);
                await _db.SaveChangesAsync();
            }

            return Ok(new { Status = status, LicenseFile = licenseFile, ErrorMessage = errorMessage });
        }

        public class ResetRequest
        {
            public required string LicenseKey { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; } // Identifiant unique du produit
        }

        public class ResetConfirmRequest : ResetRequest
        {
            public required string ResetCode { get; set; }
        }

        [HttpPost("reset-request")]
        public async Task<IActionResult> RequestReset([FromBody] ResetRequest req)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey;
            HttpContext.Items[LogKeys.Endpoint] = "RESET_REQUEST";

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            var resetProductIds = await GetProductHierarchyIds(product.Id);
            var cleanKey = req.LicenseKey.Trim().ToUpper();            var license = await _db.Licenses.FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && resetProductIds.Contains(l.ProductId));
            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            
            HttpContext.Items[LogKeys.HardwareId] = license.HardwareId; // On logge le HWID actuel qui va etre delie

            if (string.IsNullOrEmpty(license.CustomerEmail)) return BadRequest(_localizer["Api_NoEmail"].Value);

            // Génération Code (6 chiffres sécure)
            var code = System.Security.Cryptography.RandomNumberGenerator.GetInt32(100000, 999999).ToString();
            license.ResetCode = code;
            license.ResetCodeExpiry = DateTime.UtcNow.AddMinutes(15);

            await _db.SaveChangesAsync();

            try
            {
                await _mailer.SendResetCodeEmailAsync(license.CustomerEmail, license.CustomerName, product.Name, code);
                return Ok(new { Message = _localizer["Api_CodeSent"].Value });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur envoi email de reset pour {LicenseKey}", req.LicenseKey);
                return StatusCode(500, _localizer["Api_EmailError"].Value);
            }
        }

        [HttpPost("reset-confirm")]
        public async Task<IActionResult> ConfirmReset([FromBody] ResetConfirmRequest req)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey;
            HttpContext.Items[LogKeys.Endpoint] = "RESET_CONFIRM";

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            var confirmProductIds = await GetProductHierarchyIds(product.Id);
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var license = await _db.Licenses
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && confirmProductIds.Contains(l.ProductId));

            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);

            if (license.ResetCode == null || license.ResetCodeExpiry < DateTime.UtcNow ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(license.ResetCode),
                    Encoding.UTF8.GetBytes(req.ResetCode)))
            {
                return BadRequest(_localizer["Api_InvalidResetCode"].Value);
            }

            // Reset effectif
            license.HardwareId = null;
            license.ActivationDate = null;
            license.ResetCode = null; // Usage unique
            license.ResetCodeExpiry = null;
            license.RecoveryCount = 0; // On reset le compteur d'abus

            if (license.Seats != null) 
            {
                foreach (var seat in license.Seats.Where(s => s.IsActive))
                {
                    seat.IsActive = false;
                    seat.UnlinkedAt = DateTime.UtcNow;
                    
                    _db.LicenseHistories.Add(new LicenseHistory {
                        LicenseId = license.Id,
                        Action = HistoryActions.UnlinkedApi,
                        Details = string.Format(_localizer["Licenses_Action_UnlinkedApiResetCode"].Value, seat.HardwareId),
                        PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                    });
                }

                SyncLegacyHardwareStateFromSeats(license);
            }

            await _db.SaveChangesAsync();

            return Ok(new { Message = _localizer["Api_UnlinkSuccess"].Value });
        }

        public class DeactivateRequest
        {
            public required string LicenseKey { get; set; }
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; }
            public string? Source { get; set; }
            public string? DeactivationSource { get; set; }
            public Dictionary<string, string>? ComponentFingerprints { get; set; }
        }

        [HttpPost("deactivate")]
        public async Task<IActionResult> Deactivate([FromBody] DeactivateRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var source = NormalizeDeactivationSource(req.Source, req.DeactivationSource);
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = cleanKey;
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = "DEACTIVATE";
            HttpContext.Items["DeactivationSource"] = source;

            if (await _security.IsHardwareIdBannedAsync(req.HardwareId))
                return StatusCode(403, "Access denied");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            HttpContext.Items[LogKeys.AppName] = product.Name;

            var deactivateProductIds = await GetProductHierarchyIds(product.Id);
            var license = await _db.Licenses
                .Include(l => l.Seats)
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && deactivateProductIds.Contains(l.ProductId));

            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);

            // Vérification du quota de déliements par jour
            var maxPerDay = license.Type?.MaxActivationsPerDay ?? 0;
            if (maxPerDay > 0)
            {
                var todayStart = DateTime.UtcNow.Date;
                var unlinksToday = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id && !s.IsActive && s.UnlinkedAt >= todayStart);
                if (unlinksToday >= maxPerDay)
                {
                    _logger.LogWarning("Deliement refuse : Limite quotidienne atteinte ({Max}/jour) pour la clé '{LicenseKey}'", maxPerDay, cleanKey);
                    return BadRequest(string.Format(_localizer["Api_MaxDailyUnlinksReached"].Value, maxPerDay));
                }
            }

            var seat = license.Seats?.FirstOrDefault(s => s.HardwareId == req.HardwareId && s.IsActive);
            if (seat == null) return NotFound("Appareil non trouvé ou déjà délié.");

            var seatAge = DateTime.UtcNow - seat.FirstActivatedAt;
            if (seatAge < AnonymousDeactivationGuardWindow
                && !IsTrustedImmediateDeactivationSource(source))
            {
                _logger.LogWarning(
                    "Immediate deactivation refused for license {LicenseId}, HWID {HardwareId}, source {DeactivationSource}, seat age {SeatAgeSeconds}s.",
                    license.Id,
                    req.HardwareId,
                    source,
                    Math.Round(seatAge.TotalSeconds));
                return BadRequest(_localizer["Api_DeactivationTooRecentRequiresSource"].Value);
            }

            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;
            SyncLegacyHardwareStateFromSeats(license);

            _logger.LogInformation(
                "Client deactivation accepted for license {LicenseId}, HWID {HardwareId}, source {DeactivationSource}, seat age {SeatAgeSeconds}s.",
                license.Id,
                req.HardwareId,
                source,
                Math.Round(seatAge.TotalSeconds));

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.UnlinkedApi,
                Details = string.Format(_localizer["Licenses_Action_UnlinkedApi"].Value, req.HardwareId, source),
                PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });

            await _db.SaveChangesAsync();

            return Ok(new { Message = _localizer["Api_UnlinkSuccess"].Value });
        }
    }
}
