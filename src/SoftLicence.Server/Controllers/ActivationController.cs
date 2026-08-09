using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
        private const string ActivationCorrelationIdHeader = "X-SoftLicence-Correlation-Id";
        private const string ActivationErrorContractVersionHeader = "X-SoftLicence-Error-Contract";
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
        private readonly Services.AdminSecretAuthenticationService _adminSecretAuthentication;
        private readonly Services.ISignedLicenseFileService _signedLicenseFiles;

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
            Services.HwidReuseAlertService hwidReuseAlerts,
            Services.AdminSecretAuthenticationService adminSecretAuthentication,
            Services.ISignedLicenseFileService signedLicenseFiles)
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
            _adminSecretAuthentication = adminSecretAuthentication;
            _signedLicenseFiles = signedLicenseFiles;
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
            public Dictionary<string, string>? ExtraParams { get; set; } // Legacy input: any non-null presence is rejected by public activation.
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

        public sealed class OfflineActivationRequest
        {
            public string? LicenseKey { get; set; }
            public string? HardwareId { get; set; }
            public string? OfflineRequestCode { get; set; }

            [JsonExtensionData]
            public Dictionary<string, JsonElement>? UnknownProperties { get; set; }
        }

        private sealed record OfflineActivationContext(Dictionary<string, string> Features);

        private static readonly Regex OfflineRequestCodeRegex = new(
            @"^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

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
            Response.Headers[ActivationCorrelationIdHeader] = HttpContext.TraceIdentifier;
            Response.Headers[ActivationErrorContractVersionHeader] = "1";
        }

        private IActionResult ActivationJsonFailure(string errorCode, string errorMessage)
        {
            TagActivationFailure(errorCode);
            return Ok(new
            {
                isSuccess = false,
                errorCode,
                message = errorMessage,
                // Keep the historical property until a separately announced breaking contract version.
                errorMessage,
                correlationId = HttpContext.TraceIdentifier,
                contractVersion = 1
            });
        }

        private static Dictionary<string, string> BuildFeatures(IEnumerable<LicenseTypeCustomParam>? customParams)
            => Services.SignedLicenseFileService.BuildFeatures(customParams);

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
            => Services.SignedLicenseFileService.ApplyPluginMetadataFromReference(model);

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
                "Activation refused: hardware has already consumed license type {LicenseTypeId} for product {ProductId}. CurrentLicenseId={CurrentLicenseId}",
                type.Id,
                productId,
                currentLicenseId);

            return BadRequest("Freemium access has already been used on this machine.");
        }

        private IActionResult? RejectIfNewActivationsDisabled(LicenseType? type)
        {
            if (!DisablesNewActivations(type))
                return null;

            TagActivationFailure("LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED");
            _logger.LogWarning(
                "Activation refused: new activations are disabled for license type {LicenseTypeSlug} ({LicenseTypeId}).",
                type?.Slug,
                type?.Id);

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
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;
            
            var type = await _db.LicenseTypes
                .Include(t => t.CustomParams)
                .FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToUpper() == req.TypeSlug.Trim().ToUpper());
            if (type == null)
            {
                TagActivationFailure("LICENSE_TYPE_UNKNOWN");
                return BadRequest(string.Format(_localizer["Api_LicenseTypeUnknown"].Value, req.TypeSlug));
            }

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
                await using var existingTrialTransaction = await Services.ProductHardwareSeatLockAuthority
                    .BeginReadCommittedTransactionAsync(_db);
                await Services.ProductHardwareSeatLockAuthority.AcquireAsync(
                    _db, product.Id, req.HardwareId);
                await _db.Entry(existing).ReloadAsync();

                // Révoquée → 403 Forbidden
                if (!existing.IsActive)
                {
                    TagActivationFailure("LICENSE_DISABLED");
                    return StatusCode(403, _localizer["Api_AccessRevoked"].Value);
                }

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
                    await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                        req.HardwareId, existing.Id, product.Id);

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
                        if (existingTrialTransaction != null)
                            await existingTrialTransaction.CommitAsync();
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
            var trialNewActivationsDisabled = RejectIfNewActivationsDisabled(type);
            if (trialNewActivationsDisabled != null)
                return trialNewActivationsDisabled;

            await using var trialTransaction = await Services.ProductHardwareSeatLockAuthority
                .BeginReadCommittedTransactionAsync(_db);
            await Services.ProductHardwareSeatLockAuthority.AcquireAsync(
                _db, product.Id, req.HardwareId);
            var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(product.Id, type, req.HardwareId);
            if (freemiumAlreadyConsumed != null)
                return freemiumAlreadyConsumed;

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
        public Task<IActionResult> Activate([FromBody] ActivationRequest req)
        {
            if (req.ExtraParams != null)
            {
                HttpContext.Items[LogKeys.AppName] = string.IsNullOrWhiteSpace(req.AppName) ? "API_CLIENT" : req.AppName;
                HttpContext.Items[LogKeys.Endpoint] = "ACTIVATE_REJECTED";
                TagActivationFailure("EXTRA_PARAMS_NOT_ALLOWED");
                return Task.FromResult<IActionResult>(BadRequest(new { error = "extra_params_not_allowed" }));
            }

            return ActivateCoreAsync(req, offlineContext: null);
        }

        [HttpPost("offline")]
        [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
        [RequestSizeLimit(4 * 1024)]
        public async Task<IActionResult> ActivateOffline([FromBody] OfflineActivationRequest req)
        {
            HttpContext.Items[LogKeys.AppName] = "SYSTEM";
            HttpContext.Items[LogKeys.Endpoint] = "OFFLINE_ACTIVATE";

            var auth = await _adminSecretAuthentication.AuthenticateAsync(HttpContext);
            if (!auth.Authorized)
                return Unauthorized(new { error = "unauthorized" });

            if (!TryNormalizeOfflineRequest(req, out var cleanKey, out var hardwareId, out var requestCode))
                return BadRequest(new { error = "invalid_request" });

            var candidates = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Include(l => l.Seats)
                .Where(l => l.LicenseKey.ToUpper() == cleanKey)
                .Where(l => !auth.ScopedProductId.HasValue || l.ProductId == auth.ScopedProductId.Value)
                .Take(2)
                .ToListAsync();

            if (candidates.Count != 1)
                return OfflineActivationDenied();

            var license = candidates[0];
            if (!license.IsActive
                || license.RevokedAt != null
                || license.Type == null
                || license.Type.IsFree
                || license.ExpirationDate is DateTime expiration && DateTime.UtcNow > expiration
                || await _security.IsHardwareIdBannedAsync(hardwareId)
                || !TryBuildOfflineFeatures(license.Type.CustomParams, requestCode, out var features))
            {
                return OfflineActivationDenied();
            }

            var activationRequest = new ActivationRequest
            {
                LicenseKey = cleanKey,
                HardwareId = hardwareId,
                AppName = license.Product?.Name ?? string.Empty
            };

            if (string.IsNullOrWhiteSpace(activationRequest.AppName))
                return OfflineActivationDenied();

            var result = await ActivateCoreAsync(activationRequest, new OfflineActivationContext(features));
            if (result is OkObjectResult)
                return result;

            if (result is ObjectResult { StatusCode: >= 500 })
                return StatusCode(StatusCodes.Status500InternalServerError, new { error = "offline_activation_failed" });

            return OfflineActivationDenied();
        }

        private async Task<IActionResult> ActivateCoreAsync(ActivationRequest req, OfflineActivationContext? offlineContext)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, offlineContext == null ? "ACTIVATE" : "OFFLINE_ACTIVATE");

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
            if (offlineContext == null && (cleanKey.EndsWith("-FREE-TRIAL") || cleanKey == "FREE-TRIAL"))
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
                    await using var existingAutoTrialTransaction = await Services.ProductHardwareSeatLockAuthority
                        .BeginReadCommittedTransactionAsync(_db);
                    await Services.ProductHardwareSeatLockAuthority.AcquireAsync(
                        _db, product.Id, req.HardwareId);
                    await _db.Entry(existing).ReloadAsync();

                    // Révoquée → 403 Forbidden
                    if (!existing.IsActive)
                    {
                        TagActivationFailure("LICENSE_DISABLED");
                        return StatusCode(403, _localizer["Api_AccessRevoked"].Value);
                    }

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
                    await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                        req.HardwareId, existing.Id, product.Id);

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
                        var signed = LicenseService.GenerateLicense(recoveryModel, decryptedKey);
                        if (existingAutoTrialTransaction != null)
                            await existingAutoTrialTransaction.CommitAsync();
                        return Ok(new { LicenseFile = signed });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erreur signature recovery trial");
                        return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    }
                }

                // Création auto (atomique)
                await using var autoTrialTx = await Services.ProductHardwareSeatLockAuthority
                    .BeginReadCommittedTransactionAsync(_db);
                await Services.ProductHardwareSeatLockAuthority.AcquireAsync(
                    _db, product.Id, req.HardwareId);
                var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(product.Id, type, req.HardwareId);
                if (freemiumAlreadyConsumed != null)
                    return freemiumAlreadyConsumed;

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
            await using var activationTransaction = await Services.ProductHardwareSeatLockAuthority
                .BeginReadCommittedTransactionAsync(_db);
            await Services.ProductHardwareSeatLockAuthority.AcquireAsync(
                _db, product.Id, req.HardwareId);
            var license = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && productIds.Contains(l.ProductId));

            Services.SecurityService.DeferredNotification? deferredAutoUnbanNotification = null;
            Services.SecurityService.DeferredNotification? deferredActivationNotification = null;

            if (license == null) 
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                _logger.LogWarning("Activation refused: license not found for product {ProductId}.", product.Id);
                return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            }
            
            if (!license.IsActive) 
            {
                TagActivationFailure("LICENSE_DISABLED");
                _logger.LogWarning("Activation refused: license {LicenseId} is disabled.", license.Id);
                return BadRequest(_localizer["Api_LicenseDisabled"].Value);
            }
            
            if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value)
            {
                TagActivationFailure("LICENSE_EXPIRED");
                _logger.LogWarning(
                    "Activation refused: license {LicenseId} expired for product {ProductId}, type {TypeSlug}, expiry {Expiry}.",
                    license.Id,
                    product.Id,
                    license.Type?.Slug ?? "UNKNOWN",
                    license.ExpirationDate);
                return BadRequest(_localizer["Api_LicenseExpired"].Value);
            }

            // Vérification de version
            if (!IsVersionAllowed(req.AppVersion, license.AllowedVersions))
            {
                TagActivationFailure("VERSION_NOT_ALLOWED");
                _logger.LogWarning("Activation refused: version not allowed for license {LicenseId}.", license.Id);
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
                        _logger.LogError("Activation refused: partner configuration is missing for license {LicenseId}.", license.Id);
                    else
                        _logger.LogError("Activation refused: partner is disabled for license {LicenseId}.", license.Id);
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
                    _logger.LogWarning("Activation refused: customer identity mismatch for license {LicenseId}.", license.Id);
                    return BadRequest(_localizer["Api_EmailMismatch"].Value);
                }
            }
            else if (!licenseHasEmail && isAnonymousType)
            {
                // Licence anonyme sans email : l'email est obligatoire pour la réclamer
                if (!requestHasEmail)
                {
                    TagActivationFailure("EMAIL_REQUIRED");
                    _logger.LogWarning("Activation refused: customer identity is required for license {LicenseId}.", license.Id);
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
                    _logger.LogWarning("Activation refused: customer email domain is invalid for license {LicenseId}.", license.Id);
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

                var autoUnban = await _security.TryAutoUnbanForPaidLicenseAsync(
                    _db,
                    req.HardwareId,
                    license.ProductId);
                if (!autoUnban.CanProceed)
                    return ActivationJsonFailure(
                        "BANNED",
                        autoUnban.PermanentBan ? "Access permanently denied" : "Access denied by server");

                hwidBanned = false;
                deferredAutoUnbanNotification = autoUnban.Notification;
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
                TagLog(req, offlineContext == null ? "RECOVERY" : "OFFLINE_ACTIVATE");
                _logger.LogInformation("License recovery succeeded for license {LicenseId}.", license.Id);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Recovery,
                    Details = offlineContext == null
                        ? string.Format(_localizer["Licenses_Action_Activated"].Value, req.HardwareId, resolvedVersion)
                        : "Offline license recovery",
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }
            else
            {
                var newActivationsDisabled = RejectIfNewActivationsDisabled(license.Type);
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
                    _logger.LogWarning("Activation refused: seat limit reached for license {LicenseId}.", license.Id);
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
                        _logger.LogWarning("Activation refused: daily activation limit reached for license {LicenseId}.", license.Id);
                        return BadRequest(string.Format(_localizer["Api_MaxDailyActivationsReached"].Value, maxPerDay));
                    }
                }

                var newSeat = license.Seats
                    .Where(candidate => !candidate.IsActive
                        && string.Equals(candidate.HardwareId, req.HardwareId, StringComparison.Ordinal))
                    .OrderByDescending(candidate => candidate.FirstActivatedAt)
                    .FirstOrDefault();
                if (newSeat == null)
                {
                    newSeat = new LicenseSeat
                    {
                        LicenseId = license.Id,
                        HardwareId = req.HardwareId,
                        FirstActivatedAt = DateTime.UtcNow
                    };
                    _db.LicenseSeats.Add(newSeat);
                }
                newSeat.IsActive = true;
                newSeat.UnlinkedAt = null;
                newSeat.LastCheckInAt = DateTime.UtcNow;
                newSeat.AppVersion = req.AppVersion;

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Activated,
                    Details = offlineContext == null
                        ? string.Format(_localizer["Licenses_Action_Activated"].Value, req.HardwareId, req.AppVersion ?? "Unknown")
                        : "Offline license activation",
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

                _logger.LogInformation("New seat activated ({Count}/{Max}) for license {LicenseId}.", currentSeatsCount + 1, license.MaxSeats, license.Id);

                deferredActivationNotification = new Services.SecurityService.DeferredNotification(
                    Services.NotificationService.Triggers.LicenseActivated,
                    "✅ Licence Activée",
                    $"Produit: {product.Name}\nType: {license.Type?.Name ?? license.Type?.Slug ?? "Standard"}\nLicence: {license.Id}\nPoste: {currentSeatsCount + 1}/{license.MaxSeats}");
            }

            // Mise à jour du nom client uniquement si la licence n'en avait pas (anonyme réclamée)
            // L'email est géré dans la section VÉRIFICATION EMAIL ci-dessus — on ne l'écrase jamais
            if (string.IsNullOrWhiteSpace(license.CustomerName) && !string.IsNullOrWhiteSpace(req.CustomerName))
                license.CustomerName = req.CustomerName.Trim();

            AddHardwareIdV2Observation(license, product, "ACTIVATE", req);
            await _db.SaveChangesAsync();

            // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
            await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                req.HardwareId, license.Id, license.ProductId, redactSensitiveDetails: offlineContext != null);

            // Génération du fichier signé
            var features = offlineContext?.Features ?? BuildFeatures(license.Type?.CustomParams);

            try
            {
                var signedLicenseString = _signedLicenseFiles.Generate(license, req.HardwareId, features);
                if (activationTransaction != null)
                    await activationTransaction.CommitAsync();
                if (deferredAutoUnbanNotification != null)
                {
                    _logger.LogWarning(
                        "AUTO-UNBAN PAID LICENSE committed for {HardwareId}: {Title}",
                        req.HardwareId,
                        deferredAutoUnbanNotification.Title);
                    _notifier.Notify(
                        deferredAutoUnbanNotification.Trigger,
                        deferredAutoUnbanNotification.Title,
                        deferredAutoUnbanNotification.Message);
                }
                if (deferredActivationNotification != null)
                {
                    _notifier.Notify(
                        deferredActivationNotification.Trigger,
                        deferredActivationNotification.Title,
                        deferredActivationNotification.Message);
                }
                if (existingSeat == null)
                    await _hwidReuseAlerts.CheckAndNotifyAsync(license.ProductId, req.HardwareId, license.Id);
                return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la signature de la licence pour '{AppName}'", req.AppName);
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
        }

        private IActionResult OfflineActivationDenied()
        {
            TagActivationFailure("OFFLINE_ACTIVATION_DENIED");
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "offline_activation_denied" });
        }

        private static bool TryNormalizeOfflineRequest(
            OfflineActivationRequest req,
            out string licenseKey,
            out string hardwareId,
            out string requestCode)
        {
            licenseKey = string.Empty;
            hardwareId = string.Empty;
            requestCode = string.Empty;
            var normalizedRequestCode = req.OfflineRequestCode?.ToUpperInvariant();

            if (req.UnknownProperties is { Count: > 0 }
                || string.IsNullOrWhiteSpace(req.LicenseKey)
                || req.LicenseKey.Length > 128
                || string.IsNullOrWhiteSpace(req.HardwareId)
                || req.HardwareId.Length > 512
                || string.IsNullOrWhiteSpace(normalizedRequestCode)
                || normalizedRequestCode.Length != 19
                || !OfflineRequestCodeRegex.IsMatch(normalizedRequestCode))
            {
                return false;
            }

            licenseKey = req.LicenseKey.Trim().ToUpperInvariant();
            hardwareId = req.HardwareId.Trim();
            requestCode = normalizedRequestCode;
            return licenseKey.Length > 0 && hardwareId.Length > 0;
        }

        private static bool TryBuildOfflineFeatures(
            IEnumerable<LicenseTypeCustomParam> customParams,
            string requestCode,
            out Dictionary<string, string> features)
        {
            features = new Dictionary<string, string>(StringComparer.Ordinal);
            LicenseTypeCustomParam? allowOffline = null;

            foreach (var parameter in customParams)
            {
                if (string.IsNullOrWhiteSpace(parameter.Key))
                    return false;

                var normalizedKey = parameter.Key.Trim();
                if (normalizedKey.Equals("offlineMode", StringComparison.OrdinalIgnoreCase)
                    || normalizedKey.Equals("offlineRequestCode", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (normalizedKey.Equals("allowOffline", StringComparison.OrdinalIgnoreCase))
                {
                    if (allowOffline != null || !string.Equals(parameter.Key, "allowOffline", StringComparison.Ordinal))
                        return false;
                    allowOffline = parameter;
                }

                if (!features.TryAdd(parameter.Key, parameter.Value))
                    return false;
            }

            if (allowOffline == null
                || !bool.TryParse(allowOffline.Value, out var enabled)
                || !enabled)
            {
                return false;
            }

            features.Add("offlineMode", bool.TrueString);
            features.Add("offlineRequestCode", requestCode);
            return true;
        }

        [HttpPost("check")]
        public async Task<IActionResult> CheckStatus([FromBody] ActivationRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, "CHECK");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                return NotFound(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

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

            if (license == null)
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                return NotFound(_localizer["Api_LicenseNotFound"].Value);
            }

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
            {
                TagActivationFailure("BANNED");
                return StatusCode(403, "Access denied");
            }

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            HttpContext.Items[LogKeys.AppName] = product.Name;

            var deactivateProductIds = await GetProductHierarchyIds(product.Id);
            var license = await _db.Licenses
                .Include(l => l.Seats)
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && deactivateProductIds.Contains(l.ProductId));

            if (license == null)
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            }

            // Vérification du quota de déliements par jour
            var maxPerDay = license.Type?.MaxActivationsPerDay ?? 0;
            if (maxPerDay > 0)
            {
                var todayStart = DateTime.UtcNow.Date;
                var unlinksToday = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id && !s.IsActive && s.UnlinkedAt >= todayStart);
                if (unlinksToday >= maxPerDay)
                {
                    _logger.LogWarning("Deliement refuse : Limite quotidienne atteinte ({Max}/jour) pour la clé '{LicenseKey}'", maxPerDay, cleanKey);
                    TagActivationFailure("MAX_DAILY_DEACTIVATIONS_REACHED");
                    return BadRequest(string.Format(_localizer["Api_MaxDailyUnlinksReached"].Value, maxPerDay));
                }
            }

            var seat = license.Seats?.FirstOrDefault(s => s.HardwareId == req.HardwareId && s.IsActive);
            if (seat == null)
            {
                TagActivationFailure("SEAT_NOT_FOUND");
                return NotFound("Appareil non trouvé ou déjà délié.");
            }

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
                TagActivationFailure("DEACTIVATION_SOURCE_REQUIRED");
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
