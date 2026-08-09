using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Localization;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Controllers
{
    [ApiController]
    [Route("api/admin")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public class AdminController : ControllerBase
    {
        private const string ResellerEvalDemoTypeSlug = "TIA-RESELLER-EVALDEMO";
        private const int PartnerSaleRenewalDays = 180;
        private const long LicenseAuthorityLockSalt = 999095;

        private readonly LicenseDbContext _db;
        private readonly IConfiguration _config;
        private readonly Services.EncryptionService _encryption;
        private readonly IStringLocalizer<SharedResource> _localizer;
        private readonly Services.SettingsService _settings;
        private readonly Services.SecurityService _security;
        private readonly Services.NotificationService _notifier;
        private readonly ILogger<AdminController> _logger;
        private readonly Services.FingerprintService _fingerprint;
        private readonly Services.AdminSecretAuthenticationService _adminSecretAuthentication;

        public AdminController(LicenseDbContext db, IConfiguration config, Services.EncryptionService encryption, IStringLocalizer<SharedResource> localizer, Services.SettingsService settings, Services.SecurityService security, Services.NotificationService notifier, ILogger<AdminController> logger, Services.FingerprintService fingerprint, Services.AdminSecretAuthenticationService adminSecretAuthentication)
        {
            _db = db;
            _config = config;
            _encryption = encryption;
            _localizer = localizer;
            _settings = settings;
            _security = security;
            _notifier = notifier;
            _logger = logger;
            _fingerprint = fingerprint;
            _adminSecretAuthentication = adminSecretAuthentication;
        }

        // Retourne (authorized, scopedProductId)
        // scopedProductId == null  → secret global, accès complet
        // scopedProductId != null  → secret produit, accès limité à ce produit
        private async Task<(bool Authorized, Guid? ScopedProductId)> GetAuthContextAsync()
        {
            var result = await _adminSecretAuthentication.AuthenticateAsync(HttpContext);
            return (result.Authorized, result.ScopedProductId);
        }

        private void TagLog(string action, string details = "")
        {
            HttpContext.Items[LogKeys.AppName] = "SYSTEM";
            HttpContext.Items[LogKeys.Endpoint] = "ADMIN_" + action;
            HttpContext.Items[LogKeys.LicenseKey] = details;
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

        // ── Helpers internes ──────────────────────────────────────────────────────

        /// <summary>Autorise uniquement les IPs du réseau interne (Docker / RFC 1918).</summary>
        private IActionResult? RequireInternalIp()
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
            if (!_security.IsWhitelisted(ip))
            {
                _logger.LogWarning("[INTERNAL_API] Rejected external IP {IP}", ip);
                return Forbid();
            }
            return null;
        }

        // ── License Types (interne uniquement) ───────────────────────────────────

        public class CreateLicenseTypeRequest
        {
            public required string Name { get; set; }
            public required string Slug { get; set; }
            public string Description { get; set; } = "";
            public int DefaultDurationDays { get; set; } = 30;
            public bool IsRecurring { get; set; } = false;
            public string DefaultAllowedVersions { get; set; } = "*";
            public int DefaultMaxSeats { get; set; } = 1;
            public int MaxActivationsPerDay { get; set; } = 0;
            public bool AllowAnonymous { get; set; } = false;
            public bool IsFree { get; set; } = false;
            public bool EnforceSingleUsePerHardwareId { get; set; } = false;
            public bool DisableNewActivations { get; set; } = false;
            public List<LicenseTypeParamDto> Params { get; set; } = new();
        }

        public class LicenseTypeParamDto
        {
            public required string Key { get; set; }
            public required string Name { get; set; }
            public string Value { get; set; } = "";
        }

        public class UpdateLicenseTypeRequest
        {
            public string? Name { get; set; }
            public string? Description { get; set; }
            public int? DefaultDurationDays { get; set; }
            public bool? IsRecurring { get; set; }
            public string? DefaultAllowedVersions { get; set; }
            public int? DefaultMaxSeats { get; set; }
            public int? MaxActivationsPerDay { get; set; }
            public bool? AllowAnonymous { get; set; }
            public bool? IsFree { get; set; }
            public bool? EnforceSingleUsePerHardwareId { get; set; }
            public bool? DisableNewActivations { get; set; }
        }

        [HttpPost("products/{productName}/license-types")]
        public async Task<IActionResult> CreateLicenseType(string productName, [FromBody] CreateLicenseTypeRequest req)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("CREATE_LICENSE_TYPE", $"{productName}/{req.Slug}");

            if (string.IsNullOrWhiteSpace(req.Name) || string.IsNullOrWhiteSpace(req.Slug))
                return BadRequest("Name et Slug sont requis.");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == productName.ToLower());
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            var slug = req.Slug.Trim().ToUpper().Replace(" ", "_");
            var existingType = await _db.LicenseTypes
                .Include(t => t.CustomParams)
                .FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug == slug);

            if (existingType != null)
            {
                // Idempotent : mettre à jour les params si fournis, retourner le type existant
                if (req.Params.Count > 0)
                {
                    foreach (var p in req.Params)
                    {
                        var key = p.Key.Trim();
                        if (string.IsNullOrWhiteSpace(key)) continue;
                        var existingParam = await _db.LicenseTypeCustomParams
                            .FirstOrDefaultAsync(cp => cp.LicenseTypeId == existingType.Id && cp.Key == key);
                        if (existingParam != null)
                        {
                            if (existingParam.Value != p.Value)
                            {
                                existingParam.Value = p.Value;
                                await _db.SaveChangesAsync();
                            }
                        }
                        else
                        {
                            _db.LicenseTypeCustomParams.Add(new LicenseTypeCustomParam { Key = key, Name = p.Name.Trim(), Value = p.Value, LicenseTypeId = existingType.Id });
                            await _db.SaveChangesAsync();
                        }
                    }
                    // Recharger les params pour la réponse
                    await _db.Entry(existingType).Collection(t => t.CustomParams).LoadAsync();
                }

                return Ok(new
                {
                    existingType.Id,
                    existingType.Name,
                    existingType.Slug,
                    existingType.DefaultDurationDays,
                    existingType.IsRecurring,
                    existingType.AllowAnonymous,
                    existingType.IsFree,
                    existingType.EnforceSingleUsePerHardwareId,
                    existingType.DisableNewActivations,
                    existingType.DefaultMaxSeats,
                    existingType.MaxActivationsPerDay,
                    Params = existingType.CustomParams.Select(cp => new { cp.Key, cp.Name, cp.Value })
                });
            }

            var licenseType = new LicenseType
            {
                ProductId = product.Id,
                Name = req.Name.Trim(),
                Slug = slug,
                Description = req.Description,
                DefaultDurationDays = req.DefaultDurationDays,
                IsRecurring = req.IsRecurring,
                DefaultAllowedVersions = req.DefaultAllowedVersions,
                DefaultMaxSeats = req.DefaultMaxSeats,
                MaxActivationsPerDay = req.MaxActivationsPerDay,
                AllowAnonymous = req.AllowAnonymous,
                IsFree = req.IsFree,
                EnforceSingleUsePerHardwareId = req.EnforceSingleUsePerHardwareId,
                DisableNewActivations = req.DisableNewActivations
            };

            foreach (var p in req.Params)
            {
                var key = p.Key.Trim();
                if (string.IsNullOrWhiteSpace(key)) continue;
                if (licenseType.CustomParams.Any(cp => cp.Key == key)) continue;
                licenseType.CustomParams.Add(new LicenseTypeCustomParam { Key = key, Name = p.Name.Trim(), Value = p.Value });
            }

            // Auto-copy custom params from existing license types of the same product
            var existingParams = await _db.LicenseTypeCustomParams
                .Where(cp => cp.LicenseType!.ProductId == product.Id)
                .ToListAsync();
            var uniqueParams = existingParams
                .GroupBy(cp => cp.Key)
                .Where(g => !licenseType.CustomParams.Any(cp => cp.Key == g.Key));
            foreach (var g in uniqueParams)
            {
                var source = g.First();
                licenseType.CustomParams.Add(new LicenseTypeCustomParam { Key = source.Key, Name = source.Name, Value = source.Value });
            }

            _db.LicenseTypes.Add(licenseType);
            await _db.SaveChangesAsync();

            return Ok(new
            {
                licenseType.Id,
                licenseType.Name,
                licenseType.Slug,
                licenseType.DefaultDurationDays,
                licenseType.IsRecurring,
                licenseType.AllowAnonymous,
                licenseType.IsFree,
                licenseType.EnforceSingleUsePerHardwareId,
                licenseType.DisableNewActivations,
                licenseType.DefaultMaxSeats,
                licenseType.MaxActivationsPerDay,
                Params = licenseType.CustomParams.Select(cp => new { cp.Key, cp.Name, cp.Value })
            });
        }

        [HttpGet("products/{productName}/license-types")]
        public async Task<IActionResult> GetLicenseTypes(string productName)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("LIST_LICENSE_TYPES", productName);

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == productName.ToLower());
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            var types = await _db.LicenseTypes
                .Include(t => t.CustomParams)
                .Where(t => t.ProductId == product.Id)
                .Select(t => new
                {
                    t.Id,
                    t.Name,
                    t.Slug,
                    t.Description,
                    t.DefaultDurationDays,
                    t.IsRecurring,
                    t.DefaultAllowedVersions,
                    t.DefaultMaxSeats,
                    t.MaxActivationsPerDay,
                    t.AllowAnonymous,
                    t.IsFree,
                    t.EnforceSingleUsePerHardwareId,
                    t.DisableNewActivations,
                    Params = t.CustomParams.Select(cp => new { cp.Key, cp.Name, cp.Value })
                })
                .ToListAsync();

            return Ok(types);
        }

        [HttpPut("license-types/{typeId:guid}")]
        public async Task<IActionResult> UpdateLicenseType(Guid typeId, [FromBody] UpdateLicenseTypeRequest req)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("UPDATE_LICENSE_TYPE", typeId.ToString());

            var lt = await _db.LicenseTypes.FindAsync(typeId);
            if (lt == null) return NotFound("Type de licence introuvable.");

            if (req.Name != null) lt.Name = req.Name.Trim();
            if (req.Description != null) lt.Description = req.Description;
            if (req.DefaultDurationDays.HasValue) lt.DefaultDurationDays = req.DefaultDurationDays.Value;
            if (req.IsRecurring.HasValue) lt.IsRecurring = req.IsRecurring.Value;
            if (req.DefaultAllowedVersions != null) lt.DefaultAllowedVersions = req.DefaultAllowedVersions;
            if (req.DefaultMaxSeats.HasValue) lt.DefaultMaxSeats = req.DefaultMaxSeats.Value;
            if (req.MaxActivationsPerDay.HasValue) lt.MaxActivationsPerDay = req.MaxActivationsPerDay.Value;
            if (req.AllowAnonymous.HasValue) lt.AllowAnonymous = req.AllowAnonymous.Value;
            if (req.IsFree.HasValue) lt.IsFree = req.IsFree.Value;
            if (req.EnforceSingleUsePerHardwareId.HasValue) lt.EnforceSingleUsePerHardwareId = req.EnforceSingleUsePerHardwareId.Value;
            if (req.DisableNewActivations.HasValue) lt.DisableNewActivations = req.DisableNewActivations.Value;

            await _db.SaveChangesAsync();
            return Ok(new { lt.Id, lt.Name, lt.Slug, lt.DefaultDurationDays, lt.IsRecurring, lt.AllowAnonymous, lt.IsFree, lt.EnforceSingleUsePerHardwareId, lt.DisableNewActivations, lt.DefaultMaxSeats, lt.MaxActivationsPerDay });
        }

        [HttpDelete("license-types/{typeId:guid}")]
        public async Task<IActionResult> DeleteLicenseType(Guid typeId)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("DELETE_LICENSE_TYPE", typeId.ToString());

            var lt = await _db.LicenseTypes.Include(t => t.Licenses).FirstOrDefaultAsync(t => t.Id == typeId);
            if (lt == null) return NotFound("Type de licence introuvable.");
            if (lt.Licenses.Any()) return Conflict("Ce type a des licences associées, supprimez-les d'abord.");

            _db.LicenseTypes.Remove(lt);
            await _db.SaveChangesAsync();
            return Ok(new { Message = $"Type '{lt.Slug}' supprimé." });
        }

        [HttpPost("license-types/{typeId:guid}/params")]
        public async Task<IActionResult> AddLicenseTypeParam(Guid typeId, [FromBody] LicenseTypeParamDto req)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("ADD_TYPE_PARAM", $"{typeId}/{req.Key}");

            var lt = await _db.LicenseTypes.FindAsync(typeId);
            if (lt == null) return NotFound("Type de licence introuvable.");

            var key = req.Key.Trim();
            if (await _db.LicenseTypeCustomParams.AnyAsync(p => p.LicenseTypeId == typeId && p.Key == key))
                return Conflict($"Un paramètre avec la clé '{key}' existe déjà sur ce type.");

            var param = new LicenseTypeCustomParam { LicenseTypeId = typeId, Key = key, Name = req.Name.Trim(), Value = req.Value };
            _db.LicenseTypeCustomParams.Add(param);
            await _db.SaveChangesAsync();
            return Ok(new { param.Key, param.Name, param.Value });
        }

        [HttpPut("license-types/{typeId:guid}/params/{key}")]
        public async Task<IActionResult> UpdateLicenseTypeParam(Guid typeId, string key, [FromBody] LicenseTypeParamDto req)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("UPDATE_TYPE_PARAM", $"{typeId}/{key}");

            var param = await _db.LicenseTypeCustomParams.FirstOrDefaultAsync(p => p.LicenseTypeId == typeId && p.Key == key);
            if (param == null) return NotFound($"Paramètre '{key}' introuvable.");

            param.Name = req.Name.Trim();
            param.Value = req.Value;
            await _db.SaveChangesAsync();
            return Ok(new { param.Key, param.Name, param.Value });
        }

        [HttpDelete("license-types/{typeId:guid}/params/{key}")]
        public async Task<IActionResult> DeleteLicenseTypeParam(Guid typeId, string key)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("DELETE_TYPE_PARAM", $"{typeId}/{key}");

            var param = await _db.LicenseTypeCustomParams.FirstOrDefaultAsync(p => p.LicenseTypeId == typeId && p.Key == key);
            if (param == null) return NotFound($"Paramètre '{key}' introuvable.");

            _db.LicenseTypeCustomParams.Remove(param);
            await _db.SaveChangesAsync();
            return Ok(new { Message = $"Paramètre '{key}' supprimé." });
        }

        [HttpPost("products")]
        public async Task<IActionResult> CreateProduct([FromBody] string name)
        {
            TagLog("CREATE_PRODUCT", name);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();
            if (string.IsNullOrWhiteSpace(name)) return BadRequest(_localizer["Products_NameRequired"].Value);
            if (await _db.Products.AnyAsync(p => p.Name.ToLower() == name.ToLower())) return BadRequest(_localizer["Api_Exists"].Value);

            var keys = LicenseService.GenerateKeys();
            var encryptedKey = _encryption.Encrypt(keys.PrivateKey);
            var product = new Product { Name = name, PrivateKeyXml = encryptedKey, PublicKeyXml = keys.PublicKey };
            _db.Products.Add(product);
            await _db.SaveChangesAsync();
            return Ok(new { product.Id, product.Name, product.PublicKeyXml });
        }

        [HttpGet("products")]
        public async Task<IActionResult> GetProducts()
        {
            TagLog("LIST_PRODUCTS");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();
            return Ok(await _db.Products.Select(p => new { p.Id, p.Name }).ToListAsync());
        }

        public class CreateAnalyticsApiKeyRequest
        {
            public string? Name { get; set; }
            public string? Scopes { get; set; }
            public DateTime? ExpiresAtUtc { get; set; }
        }

        [HttpPost("products/{id:guid}/analytics-keys")]
        public async Task<IActionResult> CreateAnalyticsApiKey(Guid id, [FromBody] CreateAnalyticsApiKeyRequest? req)
        {
            TagLog("CREATE_ANALYTICS_KEY", id.ToString());
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();

            var product = await _db.Products.FindAsync(id);
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            var rawKey = GenerateAnalyticsApiKey();
            var key = new AnalyticsApiKey
            {
                ProductId = product.Id,
                Name = string.IsNullOrWhiteSpace(req?.Name) ? "MCP analytics" : req.Name.Trim(),
                Prefix = Services.AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
                KeyHash = Services.AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
                Scopes = string.IsNullOrWhiteSpace(req?.Scopes) ? AnalyticsApiKeyScopes.TelemetryRead : req.Scopes.Trim(),
                ScopeKind = AnalyticsApiKeyScopeKinds.Product,
                ExpiresAtUtc = req?.ExpiresAtUtc,
                IsActive = true
            };

            _db.AnalyticsApiKeys.Add(key);
            await _db.SaveChangesAsync();

            return Ok(new
            {
                key.Id,
                key.ProductId,
                key.Name,
                key.Prefix,
                key.Scopes,
                key.ScopeKind,
                key.ExpiresAtUtc,
                ApiKey = rawKey
            });
        }

        [HttpGet("analytics-keys/global")]
        public async Task<IActionResult> GetGlobalAnalyticsApiKeys()
        {
            TagLog("LIST_GLOBAL_ANALYTICS_KEYS");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();

            var keys = await _db.AnalyticsApiKeys
                .AsNoTracking()
                .Where(k => k.ScopeKind == AnalyticsApiKeyScopeKinds.Global)
                .OrderByDescending(k => k.CreatedAtUtc)
                .Select(k => new
                {
                    k.Id,
                    k.Name,
                    k.Prefix,
                    k.Scopes,
                    k.ScopeKind,
                    k.IsActive,
                    k.CreatedAtUtc,
                    k.ExpiresAtUtc,
                    k.LastUsedAtUtc,
                    k.LastUsedIp
                })
                .ToListAsync();

            return Ok(keys);
        }

        [HttpPost("analytics-keys/global")]
        public async Task<IActionResult> CreateGlobalAnalyticsApiKey([FromBody] CreateAnalyticsApiKeyRequest? req)
        {
            TagLog("CREATE_GLOBAL_ANALYTICS_KEY");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();

            var rawKey = GenerateAnalyticsApiKey();
            var key = new AnalyticsApiKey
            {
                ProductId = null,
                Name = string.IsNullOrWhiteSpace(req?.Name) ? "Global MCP analytics" : req.Name.Trim(),
                Prefix = Services.AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
                KeyHash = Services.AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
                Scopes = string.IsNullOrWhiteSpace(req?.Scopes)
                    ? $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.SecurityRead} {AnalyticsApiKeyScopes.MultiProductRead}"
                    : req.Scopes.Trim(),
                ScopeKind = AnalyticsApiKeyScopeKinds.Global,
                ExpiresAtUtc = req?.ExpiresAtUtc,
                IsActive = true
            };

            _db.AnalyticsApiKeys.Add(key);
            await _db.SaveChangesAsync();

            return Ok(new
            {
                key.Id,
                key.ProductId,
                key.Name,
                key.Prefix,
                key.Scopes,
                key.ScopeKind,
                key.ExpiresAtUtc,
                ApiKey = rawKey
            });
        }

        [HttpPost("analytics-keys/{keyId:guid}/revoke")]
        public async Task<IActionResult> RevokeAnalyticsApiKey(Guid keyId)
        {
            TagLog("REVOKE_ANALYTICS_KEY", keyId.ToString());
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();

            var key = await _db.AnalyticsApiKeys.FindAsync(keyId);
            if (key == null) return NotFound();

            key.IsActive = false;
            await _db.SaveChangesAsync();
            return Ok(new { key.Id, key.IsActive });
        }

        private static string GenerateAnalyticsApiKey()
        {
            var bytes = RandomNumberGenerator.GetBytes(32);
            return "sla_" + Convert.ToBase64String(bytes)
                .Replace("+", "-", StringComparison.Ordinal)
                .Replace("/", "_", StringComparison.Ordinal)
                .TrimEnd('=');
        }

        /// <summary>
        /// Diagnostic : vérifie si la clé privée d'un produit est déchiffrable et correspond à la clé publique.
        /// </summary>
        [HttpGet("products/{id:guid}/key-check")]
        public async Task<IActionResult> CheckProductKey(Guid id)
        {
            TagLog("KEY_CHECK", id.ToString());
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();

            var product = await _db.Products.FindAsync(id);
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            var decrypted = _encryption.Decrypt(product.PrivateKeyXml);
            if (decrypted == "ERROR_DECRYPTION_FAILED")
            {
                return Ok(new { Status = "ERROR", Message = _localizer["Api_DecryptError"].Value });
            }

            // Vérifier que la clé privée correspond à la clé publique
            try
            {
                using var rsaPriv = RSA.Create();
                rsaPriv.FromXmlString(decrypted);
                var privModulus = Convert.ToBase64String(rsaPriv.ExportParameters(false).Modulus!);

                using var rsaPub = RSA.Create();
                rsaPub.FromXmlString(product.PublicKeyXml);
                var pubModulus = Convert.ToBase64String(rsaPub.ExportParameters(false).Modulus!);

                var match = privModulus == pubModulus;
                return Ok(new {
                    Status = match ? "OK" : "MISMATCH",
                    PublicModulus = pubModulus[..40] + "...",
                    PrivateModulus = privModulus[..40] + "...",
                    KeysMatch = match
                });
            }
            catch (Exception ex)
            {
                return Ok(new { Status = "ERROR", Message = string.Format(_localizer["Api_KeyInvalid"].Value, ex.Message) });
            }
        }

        public class UpdateKeysRequest
        {
            public required string PrivateKeyXml { get; set; }
        }

        /// <summary>
        /// Ré-injecte une clé privée (rechiffrée avec DataProtection actuel).
        /// La clé publique est extraite automatiquement de la clé privée.
        /// </summary>
        [HttpPut("products/{id:guid}/keys")]
        public async Task<IActionResult> UpdateProductKeys(Guid id, [FromBody] UpdateKeysRequest req)
        {
            TagLog("UPDATE_KEYS", id.ToString());
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();

            var product = await _db.Products.FindAsync(id);
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            // Valider que la clé est un XML RSA valide
            try
            {
                using var rsa = RSA.Create();
                rsa.FromXmlString(req.PrivateKeyXml);

                // Extraire la clé publique correspondante
                var publicKeyXml = rsa.ToXmlString(false);

                // Chiffrer et stocker
                product.PrivateKeyXml = _encryption.Encrypt(req.PrivateKeyXml);
                product.PublicKeyXml = publicKeyXml;
                await _db.SaveChangesAsync();

                return Ok(new {
                    Message = _localizer["Api_KeysUpdated"].Value,
                    PublicKeyXml = publicKeyXml
                });
            }
            catch (Exception ex)
            {
                return BadRequest(string.Format(_localizer["Api_PrivateKeyInvalid"].Value, ex.Message));
            }
        }

        public class CreateLicenseRequest
        {
            public required string ProductName { get; set; }
            public required string CustomerName { get; set; }
            public string CustomerEmail { get; set; } = "";
            public required string TypeSlug { get; set; }
            public int? DaysValidity { get; set; }
            public string? Reference { get; set; }
            public Guid? PluginId { get; set; }
            public string? RuntimePluginId { get; set; }
            public string? PluginVersion { get; set; }
            public string? MinAppVersion { get; set; }
            public string[]? AllowedFeatures { get; set; }
            public string? PartnerCode { get; set; } // Reseller code (ex: AARONLIU-4M0Q)
            public int Quantity { get; set; } = 1; // Batch generation for resellers
            public int? MaxSeats { get; set; }
        }

        private static string? BuildLicenseReference(CreateLicenseRequest req)
        {
            var originalReference = string.IsNullOrWhiteSpace(req.Reference) ? null : req.Reference.Trim();
            if (string.IsNullOrWhiteSpace(req.RuntimePluginId)) return originalReference;

            var reference = originalReference != null && originalReference.StartsWith("plugin:", StringComparison.OrdinalIgnoreCase)
                ? originalReference
                : $"plugin:{req.RuntimePluginId.Trim()}";
            var metadata = new List<string>();

            if (!string.IsNullOrWhiteSpace(originalReference) && !originalReference.StartsWith("plugin:", StringComparison.OrdinalIgnoreCase))
                metadata.Add($"reference={SanitizeReferenceValue(originalReference)}");
            if (!string.IsNullOrWhiteSpace(req.PluginVersion))
                metadata.Add($"pluginVersion={SanitizeReferenceValue(req.PluginVersion)}");
            if (!string.IsNullOrWhiteSpace(req.MinAppVersion))
                metadata.Add($"minAppVersion={SanitizeReferenceValue(req.MinAppVersion)}");
            if (req.AllowedFeatures is { Length: > 0 })
            {
                var features = req.AllowedFeatures
                    .Where(f => !string.IsNullOrWhiteSpace(f))
                    .Select(SanitizeReferenceValue)
                    .ToArray();
                if (features.Length > 0)
                    metadata.Add($"allowedFeatures={string.Join(",", features)}");
            }

            return metadata.Count == 0 ? reference : $"{reference}:{string.Join(":", metadata)}";
        }

        private static string SanitizeReferenceValue(string value)
        {
            return value.Trim().Replace(":", "_", StringComparison.Ordinal);
        }

        private sealed record LicenseProvisioningFingerprint(
            Guid ProductId,
            Guid LicenseTypeId,
            string CustomerName,
            string CustomerEmail,
            string? LicenseReference,
            int? ValidityDays,
            int MaxSeats,
            string? PartnerCode,
            int Quantity);

        private static string ComputeProvisioningRequestHash(LicenseProvisioningFingerprint fingerprint)
        {
            var json = JsonSerializer.Serialize(fingerprint);
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        }

        private static string? NormalizeProvisioningReference(string? reference)
        {
            var trimmed = reference?.Trim();
            return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
        }

        private async Task<LicenseProvisioningRequest?> FindProvisioningRequestAsync(
            Guid productId,
            string reference,
            CancellationToken cancellationToken = default)
        {
            return await _db.LicenseProvisioningRequests
                .AsNoTracking()
                .Include(r => r.Licenses)
                .FirstOrDefaultAsync(
                    r => r.ProductId == productId && r.Reference == reference,
                    cancellationToken);
        }

        private IActionResult BuildLicenseCreationResponse(
            IReadOnlyCollection<License> licenses,
            LicenseType type,
            bool idempotent)
        {
            var ordered = licenses
                .OrderBy(l => l.ProvisioningSequence ?? int.MaxValue)
                .ThenBy(l => l.LicenseKey, StringComparer.Ordinal)
                .ToList();

            if (ordered.Count == 1)
            {
                var license = ordered[0];
                return Ok(new
                {
                    license.LicenseKey,
                    LicenseTypeSlug = type.Slug,
                    license.MaxSeats,
                    license.ValidityDays,
                    license.ExpirationDate,
                    license.Reference,
                    Idempotent = idempotent
                });
            }

            return Ok(new
            {
                LicenseKeys = ordered.Select(l => l.LicenseKey).ToList(),
                Count = ordered.Count,
                LicenseTypeSlug = type.Slug,
                MaxSeats = ordered.FirstOrDefault()?.MaxSeats ?? type.DefaultMaxSeats,
                ValidityDays = ordered.FirstOrDefault()?.ValidityDays,
                Reference = ordered.FirstOrDefault()?.Reference,
                Idempotent = idempotent
            });
        }

        private IActionResult BuildProvisioningRetryResponse(
            LicenseProvisioningRequest existing,
            string requestHash,
            LicenseType type)
        {
            if (!string.Equals(existing.RequestHash, requestHash, StringComparison.Ordinal))
                return Conflict(new { error = "reference_payload_conflict" });

            return BuildLicenseCreationResponse(existing.Licenses.ToList(), type, idempotent: true);
        }

        [HttpPost("licenses")]
        public async Task<IActionResult> CreateLicense([FromBody] CreateLicenseRequest req)
        {
            TagLog("CREATE_LICENSE", $"{req.ProductName} -> {req.CustomerName}");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.ProductName.ToLower());
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            // Si accès scopé, vérifier que le produit demandé correspond au secret utilisé
            if (scopedProductId != null && product.Id != scopedProductId)
                return Unauthorized();

            // Si un PluginId est fourni, résoudre le sous-produit correspondant
            var targetProduct = product;
            if (req.PluginId.HasValue)
            {
                var plugin = await _db.Products.FirstOrDefaultAsync(p => p.Id == req.PluginId.Value);
                if (plugin == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

                // Vérifier que le plugin appartient bien à la hiérarchie du produit parent
                var current = plugin;
                var belongsToProduct = false;
                while (current != null)
                {
                    if (current.Id == product.Id) { belongsToProduct = true; break; }
                    current = current.ParentProductId.HasValue
                        ? await _db.Products.FirstOrDefaultAsync(p => p.Id == current.ParentProductId.Value)
                        : null;
                }
                if (!belongsToProduct) return BadRequest("Plugin does not belong to the specified product.");

                targetProduct = plugin;
            }

            var type = await _db.LicenseTypes.FirstOrDefaultAsync(t => t.ProductId == targetProduct.Id && t.Slug.ToLower() == req.TypeSlug.Trim().ToLower());
            if (type == null) return BadRequest(string.Format(_localizer["Api_LicenseTypeUnknown"].Value, req.TypeSlug));

            var quantity = Math.Clamp(req.Quantity, 1, 100);
            if (req.MaxSeats is < 1 or > 100)
                return BadRequest(new { error = "max_seats_out_of_range" });

            var maxSeats = req.MaxSeats ?? type.DefaultMaxSeats;
            int? validityDays = req.DaysValidity.HasValue
                ? (req.DaysValidity.Value == 0 ? null : req.DaysValidity.Value)
                : type.DefaultDurationDays;
            var licenseReference = BuildLicenseReference(req);
            var provisioningReference = NormalizeProvisioningReference(req.Reference);
            if (provisioningReference?.Length > 512)
                return BadRequest(new { error = "reference_too_long" });

            var normalizedPartnerCode = string.IsNullOrWhiteSpace(req.PartnerCode)
                ? null
                : req.PartnerCode.Trim().ToUpperInvariant();
            var requestHash = ComputeProvisioningRequestHash(new LicenseProvisioningFingerprint(
                targetProduct.Id,
                type.Id,
                req.CustomerName,
                req.CustomerEmail,
                licenseReference,
                validityDays,
                maxSeats,
                normalizedPartnerCode,
                quantity));

            if (provisioningReference != null)
            {
                var existing = await FindProvisioningRequestAsync(targetProduct.Id, provisioningReference);
                if (existing != null)
                    return BuildProvisioningRetryResponse(existing, requestHash, type);
            }

            await using var transaction = _db.Database.IsRelational()
                ? await _db.Database.BeginTransactionAsync()
                : null;
            var generatedLicenses = new List<License>();

            try
            {
                // Validate partner code — auto-create if missing, in the same transaction as provisioning.
                if (normalizedPartnerCode != null)
                {
                    var partner = await _db.ResellerPartners.FirstOrDefaultAsync(p => p.Code == normalizedPartnerCode);
                    if (partner == null)
                    {
                        var partnerName = string.IsNullOrWhiteSpace(req.CustomerName) ? normalizedPartnerCode : req.CustomerName;
                        partner = new ResellerPartner
                        {
                            Code = normalizedPartnerCode,
                            Name = partnerName,
                            ContactEmail = req.CustomerEmail,
                            Notes = "Auto-created from license creation API"
                        };
                        _db.ResellerPartners.Add(partner);
                        _logger.LogInformation("Partner '{PartnerCode}' auto-cree depuis creation licence (Client: {Customer}, Email: {Email})", normalizedPartnerCode, req.CustomerName, req.CustomerEmail);
                    }
                    else if (!partner.IsActive)
                    {
                        return BadRequest($"Partner code '{normalizedPartnerCode}' is disabled.");
                    }
                }

                LicenseProvisioningRequest? provisioningRequest = null;
                if (provisioningReference != null)
                {
                    provisioningRequest = new LicenseProvisioningRequest
                    {
                        ProductId = targetProduct.Id,
                        Reference = provisioningReference,
                        RequestHash = requestHash
                    };
                    _db.LicenseProvisioningRequests.Add(provisioningRequest);
                }

                for (var i = 0; i < quantity; i++)
                {
                    var license = new License
                    {
                        ProductId = targetProduct.Id,
                        LicenseKey = Guid.NewGuid().ToString("D").ToUpperInvariant(),
                        CustomerName = req.CustomerName,
                        CustomerEmail = req.CustomerEmail,
                        LicenseTypeId = type.Id,
                        Reference = licenseReference,
                        ValidityDays = validityDays,
                        MaxSeats = maxSeats,
                        PartnerCode = normalizedPartnerCode,
                        ProvisioningRequest = provisioningRequest,
                        ProvisioningSequence = provisioningRequest == null ? null : i
                    };

                    license.History.Add(new LicenseHistory
                    {
                        Action = HistoryActions.Created,
                        Details = string.Format(_localizer["Licenses_Action_Created"].Value, type.Name, maxSeats)
                            + (normalizedPartnerCode != null ? $" [Partner: {normalizedPartnerCode}]" : ""),
                        PerformedBy = "Admin (API)"
                    });

                    _db.Licenses.Add(license);
                    generatedLicenses.Add(license);
                }

                await ExtendResellerDemoLicenseAfterPartnerSaleAsync(targetProduct.Id, normalizedPartnerCode, type);
                await _db.SaveChangesAsync();
                if (transaction != null)
                    await transaction.CommitAsync();
            }
            catch (DbUpdateException) when (provisioningReference != null)
            {
                if (transaction != null)
                    await transaction.RollbackAsync();
                _db.ChangeTracker.Clear();

                var existing = await FindProvisioningRequestAsync(targetProduct.Id, provisioningReference);
                if (existing == null)
                    throw;

                return BuildProvisioningRetryResponse(existing, requestHash, type);
            }

            var generatedKeys = generatedLicenses.Select(l => l.LicenseKey).ToList();

            var notifMsg = quantity == 1
                ? $"Produit: {targetProduct.Name}\nClient: {req.CustomerName}\nType: {req.TypeSlug}\nClé: {generatedKeys[0]}"
                : $"Produit: {targetProduct.Name}\nClient: {req.CustomerName}\nType: {req.TypeSlug}\nQuantité: {quantity}\nPartner: {req.PartnerCode}";

            _notifier.Notify(Services.NotificationService.Triggers.LicenseCreated,
                quantity == 1 ? "Nouvelle Licence Créée" : $"{quantity} Licences Créées",
                notifMsg);

            return BuildLicenseCreationResponse(generatedLicenses, type, idempotent: false);
        }

        private async Task ExtendResellerDemoLicenseAfterPartnerSaleAsync(Guid productId, string? partnerCode, LicenseType createdLicenseType)
        {
            if (string.IsNullOrWhiteSpace(partnerCode))
                return;

            if (string.Equals(createdLicenseType.Slug, ResellerEvalDemoTypeSlug, StringComparison.OrdinalIgnoreCase))
                return;

            var resellerLicense = await _db.Licenses
                .Include(l => l.Type)
                .Where(l => l.ProductId == productId
                    && l.PartnerCode == partnerCode
                    && l.Type != null
                    && l.Type.Slug == ResellerEvalDemoTypeSlug)
                .OrderByDescending(l => l.IsActive)
                .ThenByDescending(l => l.ExpirationDate ?? DateTime.MinValue)
                .ThenByDescending(l => l.ActivationDate ?? l.CreationDate)
                .FirstOrDefaultAsync();

            if (resellerLicense == null)
            {
                _logger.LogWarning("Partner sale detected for {PartnerCode}, but no reseller demo license found on product {ProductId}", partnerCode, productId);
                return;
            }

            var now = DateTime.UtcNow;
            var baseDate = resellerLicense.ExpirationDate ?? now;
            if (baseDate < now) baseDate = now;

            var previousExpiry = resellerLicense.ExpirationDate;
            resellerLicense.ExpirationDate = baseDate.AddDays(PartnerSaleRenewalDays);
            resellerLicense.IsActive = true;

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = resellerLicense.Id,
                Action = HistoryActions.Renewed,
                Details = $"Partner sale auto-renewal: {partnerCode} +{PartnerSaleRenewalDays} days. Previous expiration: {previousExpiry?.ToString("yyyy-MM-dd HH:mm") ?? "Lifetime"}; New expiration: {resellerLicense.ExpirationDate:yyyy-MM-dd HH:mm}",
                PerformedBy = "Admin (API)"
            });

            _logger.LogInformation(
                "Reseller demo license auto-renewed after partner sale: {PartnerCode} +{Days} days, LicenseId={LicenseId}, NewExpiration={Expiration}",
                partnerCode,
                PartnerSaleRenewalDays,
                resellerLicense.Id,
                resellerLicense.ExpirationDate);
        }

        [HttpGet("licenses")]
        public async Task<IActionResult> GetLicenses([FromQuery] string? productName, [FromQuery] string? partnerCode)
        {
            TagLog("LIST_LICENSES", productName ?? "ALL");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            IQueryable<License> query = _db.Licenses.Include(l => l.Product).Include(l => l.Type);

            if (scopedProductId != null)
            {
                query = query.Where(l => l.ProductId == scopedProductId);
            }
            else if (!string.IsNullOrEmpty(productName))
            {
                query = query.Where(l => l.Product!.Name.ToLower() == productName.ToLower());
            }

            if (!string.IsNullOrEmpty(partnerCode))
            {
                query = query.Where(l => l.PartnerCode == partnerCode.Trim());
            }

            var list = await query.Select(l => new
            {
                l.Id,
                Product = l.Product != null ? l.Product.Name : "Unknown",
                l.LicenseKey,
                l.CustomerName,
                l.CustomerEmail,
                l.Reference,
                l.PartnerCode,
                Type = l.Type != null ? l.Type.Slug : "UNKNOWN",
                IsActive = l.IsActive && (!l.ExpirationDate.HasValue || l.ExpirationDate > DateTime.UtcNow),
                l.HardwareId,
                l.ExpirationDate
            }).ToListAsync();

            return Ok(list);
        }

        public sealed class TargetedLicenseResolutionRequest
        {
            public string Schema { get; set; } = string.Empty;
            public Guid ProductId { get; set; }
            public string? LicenseKey { get; set; }
            public string? HardwareId { get; set; }

            [JsonExtensionData]
            public Dictionary<string, JsonElement>? ExtensionData { get; set; }
        }

        [HttpPost("licenses/resolve")]
        public async Task<IActionResult> ResolveLicense([FromBody] TargetedLicenseResolutionRequest req)
        {
            TagLog("RESOLVE_LICENSE");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            if (req.ExtensionData is { Count: > 0 }
                || req.Schema != "targeted-license-resolution-v1"
                || req.ProductId == Guid.Empty
                || scopedProductId.HasValue && scopedProductId.Value != req.ProductId)
                return BadRequest(new { error = "invalid_request" });

            var hasLicenseKey = req.LicenseKey is not null;
            var hasHardwareId = req.HardwareId is not null;
            if (hasLicenseKey == hasHardwareId)
                return BadRequest(new { error = "invalid_selector" });

            var selector = (hasLicenseKey ? req.LicenseKey : req.HardwareId)!;
            if (!IsCanonicalTargetedSelector(selector))
                return BadRequest(new { error = "invalid_selector" });

            var candidates = hasLicenseKey
                ? await ResolveByLicenseKeyAsync(req.ProductId, selector)
                : await ResolveByHardwareIdAsync(req.ProductId, selector);
            if (candidates.Count == 0)
                return Ok(BuildTargetedResolution(null, null, "Unknown", "license_not_found"));

            var now = DateTime.UtcNow;
            var selected = candidates
                .OrderBy(candidate => GetTargetedResolutionPriority(candidate.License, candidate.Seat, now))
                .ThenByDescending(candidate => candidate.Seat?.LastCheckInAt
                    ?? candidate.License.ActivationDate
                    ?? candidate.License.CreationDate)
                .ThenBy(candidate => candidate.License.Id)
                .First();
            var reasonCode = GetTargetedResolutionReason(selected.License, selected.Seat, now);
            var status = reasonCode == "active_license_found" ? "Active" : "Inactive";
            return Ok(BuildTargetedResolution(selected.License, selected.Seat, status, reasonCode));
        }

        private async Task<List<TargetedLicenseCandidate>> ResolveByLicenseKeyAsync(Guid productId, string licenseKey)
        {
            var license = await _db.Licenses.AsNoTracking()
                .Include(candidate => candidate.Type)
                .Include(candidate => candidate.Seats)
                .SingleOrDefaultAsync(candidate => candidate.ProductId == productId
                    && candidate.LicenseKey == licenseKey);
            if (license == null)
                return [];
            var seat = license.Seats
                .Where(candidate => candidate.IsActive)
                .OrderByDescending(candidate => candidate.LastCheckInAt)
                .FirstOrDefault();
            return [new TargetedLicenseCandidate(license, seat)];
        }

        private async Task<List<TargetedLicenseCandidate>> ResolveByHardwareIdAsync(Guid productId, string hardwareId)
        {
            var seatMatches = await _db.LicenseSeats.AsNoTracking()
                .Include(candidate => candidate.License)
                    .ThenInclude(license => license!.Type)
                .Where(candidate => candidate.HardwareId == hardwareId
                    && candidate.License != null
                    && candidate.License.ProductId == productId)
                .ToListAsync();
            var candidates = seatMatches
                .Select(candidate => new TargetedLicenseCandidate(candidate.License!, candidate))
                .ToList();
            var legacyMatches = await _db.Licenses.AsNoTracking()
                .Include(candidate => candidate.Type)
                .Include(candidate => candidate.Seats)
                .Where(candidate => candidate.ProductId == productId
                    && candidate.Seats.Count == 0
                    && candidate.HardwareId == hardwareId)
                .ToListAsync();
            candidates.AddRange(legacyMatches.Select(candidate => new TargetedLicenseCandidate(candidate, null)));
            return candidates;
        }

        private static object BuildTargetedResolution(
            License? license,
            LicenseSeat? seat,
            string status,
            string reasonCode) => new
        {
            schema = "targeted-license-resolution-v1",
            status,
            reasonCode,
            licenseId = license?.Id,
            licenseTypeSlug = license?.Type?.Slug,
            allowedVersions = license?.AllowedVersions,
            expirationDateUtc = license?.ExpirationDate,
            seatActive = seat?.IsActive
        };

        private static int GetTargetedResolutionPriority(License license, LicenseSeat? seat, DateTime now) =>
            GetTargetedResolutionReason(license, seat, now) switch
            {
                "active_license_found" => 0,
                "license_revoked" => 1,
                "license_expired" => 2,
                "seat_inactive" => 3,
                _ => 9
            };

        private static string GetTargetedResolutionReason(License license, LicenseSeat? seat, DateTime now)
        {
            if (!license.IsActive)
                return "license_revoked";
            if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
                return "license_expired";
            if (seat is { IsActive: false })
                return "seat_inactive";
            return "active_license_found";
        }

        private sealed record TargetedLicenseCandidate(License License, LicenseSeat? Seat);

        private static bool IsCanonicalTargetedSelector(string value) =>
            value.Length is >= 3 and <= 256
            && value.All(character => character is >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-' or '_' or '.');

        [HttpDelete("licenses/{licenseKey}/seats/{hardwareId}")]
        public async Task<IActionResult> DeactivateSeat(string licenseKey, string hardwareId)
        {
            TagLog("DEACTIVATE_SEAT", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var license = await _db.Licenses
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey.ToUpper());

            if (license == null) return NotFound(_localizer["Api_LicenseNotFound"].Value);

            if (scopedProductId != null && license.ProductId != scopedProductId)
                return Unauthorized();

            var seat = license.Seats?.FirstOrDefault(s => s.HardwareId == hardwareId && s.IsActive);
            if (seat == null) return NotFound("Appareil non trouvé ou déjà délié.");

            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;
            SyncLegacyHardwareStateFromSeats(license);

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.UnlinkedApi,
                Details = $"Délié via API admin : {hardwareId}",
                PerformedBy = "Admin (API)"
            });

            await _db.SaveChangesAsync();
            return Ok(new { Message = "Appareil délié avec succès." });
        }

        public class RevokeByEmailRequest
        {
            public required string Email { get; set; }
            public string? ProductName { get; set; }
        }

        [HttpPost("licenses/revoke-by-email")]
        public async Task<IActionResult> RevokeByEmail([FromBody] RevokeByEmailRequest req)
        {
            TagLog("REVOKE_BY_EMAIL", req.Email);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            if (string.IsNullOrWhiteSpace(req.Email))
                return BadRequest("Email est requis.");

            IQueryable<License> query = _db.Licenses.Include(l => l.Product);

            if (scopedProductId != null)
            {
                query = query.Where(l => l.ProductId == scopedProductId);
            }
            else if (!string.IsNullOrEmpty(req.ProductName))
            {
                query = query.Where(l => l.Product!.Name.ToLower() == req.ProductName.ToLower());
            }

            var licenses = await query
                .Where(l => l.CustomerEmail.ToLower() == req.Email.ToLower() && l.IsActive)
                .ToListAsync();

            if (licenses.Count == 0)
                return NotFound("Aucune licence active trouvée pour cet email.");

            foreach (var license in licenses)
            {
                license.IsActive = false;

                _db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Action = HistoryActions.Revoked,
                    Details = $"Révoquée via API admin (par email: {req.Email})",
                    PerformedBy = "Admin (API)"
                });
            }

            await _db.SaveChangesAsync();

            _notifier.Notify(Services.NotificationService.Triggers.LicenseRevoked,
                "🚫 Licences Révoquées par Email",
                $"Email: {req.Email}\nLicences révoquées: {licenses.Count}\nClés: {string.Join(", ", licenses.Select(l => l.LicenseKey))}");

            return Ok(new
            {
                Message = $"{licenses.Count} licence(s) révoquée(s).",
                RevokedKeys = licenses.Select(l => new { l.LicenseKey, Product = l.Product?.Name ?? "Unknown" })
            });
        }

        // ── Révocation / Réactivation par clé ──────────────────────────────────

        public class RevokeLicenseByKeyRequest
        {
            public string? Reason { get; set; }
        }

        public class RevokeInactiveFreemiumRequest
        {
            public string ProductName { get; set; } = "T-IA Connect";
            public string LicenseTypeSlug { get; set; } = "TIA-CONNECT-FREEMIUM";
            public string Reason { get; set; } = "Freemium gratuit arrêté - clé non activée avant fermeture";
            public int SampleSize { get; set; } = 20;
        }

        private static string RedactEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
                return "";

            var parts = email.Split('@', 2);
            var local = parts[0];
            var prefix = local.Length <= 2 ? local[..1] : local[..2];
            return $"{prefix}***@{parts[1]}";
        }

        private static string RedactKey(string? key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return "";

            var compact = key.Replace("-", "", StringComparison.Ordinal);
            if (compact.Length <= 8)
                return "***";

            return $"{compact[..4]}...{compact[^4..]}";
        }

        private IQueryable<License> BuildInactiveFreemiumRevocationQuery(
            Guid productId,
            string licenseTypeSlug)
        {
            var normalizedSlug = licenseTypeSlug.Trim().ToUpperInvariant();

            return _db.Licenses
                .Include(l => l.Type)
                .Include(l => l.Seats)
                .Where(l => l.ProductId == productId
                    && l.IsActive
                    && l.Type != null
                    && l.Type.Slug.ToUpper() == normalizedSlug
                    && l.ActivationDate == null
                    && string.IsNullOrEmpty(l.HardwareId)
                    && !l.Seats.Any());
        }

        [HttpPost("licenses/freemium-unactivated-revocation/dry-run")]
        public async Task<IActionResult> DryRunRevokeUnactivatedFreemium([FromBody] RevokeInactiveFreemiumRequest req)
        {
            TagLog("DRY_RUN_REVOKE_UNACTIVATED_FREEMIUM", $"{req.ProductName}/{req.LicenseTypeSlug}");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.ProductName.Trim().ToLower());
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);
            if (scopedProductId != null && product.Id != scopedProductId) return Unauthorized();

            var query = BuildInactiveFreemiumRevocationQuery(product.Id, req.LicenseTypeSlug);
            var count = await query.CountAsync();
            var sampleSize = Math.Clamp(req.SampleSize, 0, 100);
            var sampleRows = await query
                .OrderBy(l => l.CreationDate)
                .Take(sampleSize)
                .Select(l => new
                {
                    l.Id,
                    l.LicenseKey,
                    l.CustomerEmail,
                    l.CustomerName,
                    l.CreationDate
                })
                .ToListAsync();
            var samples = sampleRows.Select(l => new
            {
                l.Id,
                LicenseKey = RedactKey(l.LicenseKey),
                CustomerEmail = RedactEmail(l.CustomerEmail),
                l.CustomerName,
                l.CreationDate
            });

            return Ok(new
            {
                DryRun = true,
                Product = product.Name,
                LicenseTypeSlug = req.LicenseTypeSlug.Trim().ToUpperInvariant(),
                Reason = req.Reason,
                Count = count,
                Samples = samples
            });
        }

        [HttpPost("licenses/freemium-unactivated-revocation/execute")]
        public async Task<IActionResult> ExecuteRevokeUnactivatedFreemium([FromBody] RevokeInactiveFreemiumRequest req)
        {
            TagLog("EXECUTE_REVOKE_UNACTIVATED_FREEMIUM", $"{req.ProductName}/{req.LicenseTypeSlug}");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.ProductName.Trim().ToLower());
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);
            if (scopedProductId != null && product.Id != scopedProductId) return Unauthorized();

            var reason = string.IsNullOrWhiteSpace(req.Reason)
                ? "Freemium gratuit arrêté - clé non activée avant fermeture"
                : req.Reason.Trim();

            var licenses = await BuildInactiveFreemiumRevocationQuery(product.Id, req.LicenseTypeSlug)
                .OrderBy(l => l.CreationDate)
                .ToListAsync();

            var now = DateTime.UtcNow;
            foreach (var license in licenses)
            {
                license.IsActive = false;
                license.RevocationReason = reason;
                license.RevokedAt = now;

                _db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Action = HistoryActions.Revoked,
                    Details = reason,
                    PerformedBy = "Admin (Freemium closure)"
                });
            }

            await _db.SaveChangesAsync();

            _notifier.Notify(Services.NotificationService.Triggers.LicenseRevoked,
                "Licences Freemium non activées révoquées",
                $"Produit: {product.Name}\nType: {req.LicenseTypeSlug.Trim().ToUpperInvariant()}\nLicences révoquées: {licenses.Count}\nRaison: {reason}");

            return Ok(new
            {
                DryRun = false,
                Product = product.Name,
                LicenseTypeSlug = req.LicenseTypeSlug.Trim().ToUpperInvariant(),
                Reason = reason,
                RevokedCount = licenses.Count
            });
        }

        [HttpPost("licenses/{licenseKey}/revoke")]
        public async Task<IActionResult> RevokeLicenseByKey(string licenseKey, [FromBody] RevokeLicenseByKeyRequest? req = null)
        {
            TagLog("REVOKE_LICENSE", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            await using var transaction = await BeginLicenseAuthorityMutationAsync(licenseKey);

            var license = await _db.Licenses.Include(l => l.Product).Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound("Licence introuvable.");
            if (scopedProductId != null && license.ProductId != scopedProductId) return Unauthorized();
            if (!license.IsActive)
                return Ok(new
                {
                    license.LicenseKey,
                    IsActive = false,
                    license.RevocationReason,
                    license.RevokedAt,
                    Idempotent = true
                });

            license.IsActive = false;
            license.RevocationReason = req?.Reason;
            license.RevokedAt = DateTime.UtcNow;

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.Revoked,
                Details = $"Révoquée via API admin{(string.IsNullOrWhiteSpace(req?.Reason) ? "" : $" — {req.Reason}")}",
                PerformedBy = "Admin (API)"
            });

            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();

            var typeSlug = license.Type?.Slug ?? "?";
            // Don't notify for silent upgrade replacements (Freemium/Trial → paid license)
            var isUpgradeRevocation = req?.Reason != null && (
                req.Reason.Contains("Remplacee par licence payante") ||
                req.Reason.Contains("upgrade") ||
                req.Reason.Contains("Remplacee par licence invoice"));
            if (!isUpgradeRevocation)
            {
                _notifier.Notify(Services.NotificationService.Triggers.LicenseRevoked,
                    "🚫 Licence Révoquée",
                    $"Produit: {license.Product?.Name ?? "?"}\nType: {typeSlug}\nClient: {license.CustomerName}\nClé: {licenseKey}\nRaison: {req?.Reason ?? "Non spécifiée"}");
            }

            return Ok(new
            {
                license.LicenseKey,
                IsActive = false,
                license.RevocationReason,
                license.RevokedAt,
                Idempotent = false
            });
        }

        [HttpPost("licenses/{licenseKey}/unrevoke")]
        public async Task<IActionResult> UnrevokeLicenseByKey(string licenseKey)
        {
            TagLog("UNREVOKE_LICENSE", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            await using var transaction = await BeginLicenseAuthorityMutationAsync(licenseKey);

            var license = await _db.Licenses.Include(l => l.Product)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound("Licence introuvable.");
            if (scopedProductId != null && license.ProductId != scopedProductId) return Unauthorized();
            if (license.IsActive)
                return Ok(new { license.LicenseKey, IsActive = true, Idempotent = true });

            license.IsActive = true;
            license.RevocationReason = null;
            license.RevokedAt = null;

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = "UNREVOKED",
                Details = "Réactivée via API admin",
                PerformedBy = "Admin (API)"
            });

            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();

            return Ok(new { license.LicenseKey, IsActive = true, Idempotent = false });
        }

        private async Task<IDbContextTransaction?> BeginLicenseAuthorityMutationAsync(string licenseKey)
        {
            if (!_db.Database.IsRelational()) return null;

            var transaction = await _db.Database.BeginTransactionAsync(
                _db.Database.IsNpgsql() ? IsolationLevel.ReadCommitted : IsolationLevel.Serializable);
            try
            {
                if (_db.Database.IsNpgsql())
                {
                    var lockKey = $"license-authority-v1|{licenseKey}";
                    await _db.Database.ExecuteSqlRawAsync(
                        "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';");
                    await _db.Database.ExecuteSqlInterpolatedAsync(
                        $"SELECT pg_advisory_xact_lock(hashtextextended({lockKey}, {LicenseAuthorityLockSalt}))");
                }
                return transaction;
            }
            catch
            {
                await transaction.RollbackAsync();
                await transaction.DisposeAsync();
                throw;
            }
        }

        // ── Modification de licence (upgrade/downgrade) ─────────────────────────

        public class UpdateLicenseRequest
        {
            public Guid? LicenseTypeId { get; set; }
            public string? LicenseTypeSlug { get; set; }
            public int? MaxSeats { get; set; }
            public string? AllowedVersions { get; set; }
            public int? DaysToAdd { get; set; }
            public DateTime? ExpirationDate { get; set; }
            public string? CustomerName { get; set; }
            public string? CustomerEmail { get; set; }
        }

        [HttpGet("licenses/{licenseKey}")]
        public async Task<IActionResult> GetLicenseByKey(string licenseKey)
        {
            TagLog("GET_LICENSE", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var license = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound("Licence introuvable.");
            if (scopedProductId != null && license.ProductId != scopedProductId) return Unauthorized();

            return Ok(new
            {
                license.Id,
                Product = license.Product?.Name ?? "Unknown",
                license.LicenseKey,
                license.CustomerName,
                license.CustomerEmail,
                license.Reference,
                license.PartnerCode,
                LicenseTypeSlug = license.Type?.Slug ?? "UNKNOWN",
                LicenseTypeId = license.Type?.Id,
                IsActive = license.IsActive && (!license.ExpirationDate.HasValue || license.ExpirationDate > DateTime.UtcNow),
                license.ExpirationDate,
                license.MaxSeats,
                CurrentActivations = license.Seats.Count(s => s.IsActive),
                Activations = license.Seats.Where(s => s.IsActive).Select(s => new { s.HardwareId, ActivatedAt = s.FirstActivatedAt }),
                CreatedAt = license.CreationDate,
                Params = license.Type?.CustomParams.Select(cp => new { cp.Key, cp.Name, cp.Value }),
            });
        }

        [HttpPut("licenses/{licenseKey}")]
        public async Task<IActionResult> UpdateLicense(string licenseKey, [FromBody] UpdateLicenseRequest req)
        {
            TagLog("UPDATE_LICENSE", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var license = await _db.Licenses
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound("Licence introuvable.");

            if (scopedProductId != null && license.ProductId != scopedProductId)
                return Unauthorized();

            var changes = new List<string>();

            // Changement de type de licence
            if (req.LicenseTypeId.HasValue || !string.IsNullOrWhiteSpace(req.LicenseTypeSlug))
            {
                LicenseType? newType;
                if (req.LicenseTypeId.HasValue)
                {
                    newType = await _db.LicenseTypes.Include(t => t.CustomParams)
                        .FirstOrDefaultAsync(t => t.Id == req.LicenseTypeId.Value);
                }
                else
                {
                    var slug = req.LicenseTypeSlug!.Trim().ToUpper();
                    newType = await _db.LicenseTypes.Include(t => t.CustomParams)
                        .FirstOrDefaultAsync(t => t.ProductId == license.ProductId && t.Slug == slug);
                }

                if (newType == null)
                    return BadRequest("Type de licence introuvable.");

                if (newType.ProductId != license.ProductId)
                    return BadRequest("Le type de licence n'appartient pas au même produit.");

                var oldTypeName = license.Type?.Name ?? license.Type?.Slug ?? "?";
                license.LicenseTypeId = newType.Id;
                changes.Add($"Type: {oldTypeName} → {newType.Name}");
            }

            // Modification du nombre de postes
            if (req.MaxSeats.HasValue)
            {
                var activeSeats = license.Seats.Count(s => s.IsActive);
                if (req.MaxSeats.Value < activeSeats)
                    return BadRequest($"Impossible de réduire à {req.MaxSeats.Value} postes : {activeSeats} poste(s) actuellement actif(s).");

                var oldSeats = license.MaxSeats;
                license.MaxSeats = req.MaxSeats.Value;
                changes.Add($"MaxSeats: {oldSeats} → {req.MaxSeats.Value}");
            }

            // Modification des versions autorisées
            if (req.AllowedVersions != null)
            {
                var oldVersions = license.AllowedVersions;
                license.AllowedVersions = req.AllowedVersions;
                changes.Add($"AllowedVersions: {oldVersions} → {req.AllowedVersions}");
            }

            // Prolongation de la date d'expiration
            if (req.DaysToAdd.HasValue && req.ExpirationDate.HasValue)
                return BadRequest("Spécifiez DaysToAdd ou ExpirationDate, pas les deux.");

            if (req.DaysToAdd.HasValue)
            {
                if (req.DaysToAdd.Value < 1 || req.DaysToAdd.Value > 3650)
                    return BadRequest("DaysToAdd doit être entre 1 et 3650.");

                var baseDate = license.ExpirationDate ?? DateTime.UtcNow;
                if (baseDate < DateTime.UtcNow) baseDate = DateTime.UtcNow;
                var oldExpiry = license.ExpirationDate?.ToString("yyyy-MM-dd HH:mm") ?? "Lifetime";
                license.ExpirationDate = baseDate.AddDays(req.DaysToAdd.Value);
                license.IsActive = true;
                changes.Add($"Expiration: {oldExpiry} → {license.ExpirationDate.Value:yyyy-MM-dd HH:mm} (+{req.DaysToAdd.Value}j)");
            }
            else if (req.ExpirationDate.HasValue)
            {
                if (req.ExpirationDate.Value.Kind == DateTimeKind.Unspecified)
                    req.ExpirationDate = DateTime.SpecifyKind(req.ExpirationDate.Value, DateTimeKind.Utc);

                var oldExpiry = license.ExpirationDate?.ToString("yyyy-MM-dd HH:mm") ?? "Lifetime";
                license.ExpirationDate = req.ExpirationDate.Value.ToUniversalTime();
                license.IsActive = true;
                changes.Add($"Expiration: {oldExpiry} → {license.ExpirationDate.Value:yyyy-MM-dd HH:mm}");
            }

            // Modification du nom client
            if (!string.IsNullOrWhiteSpace(req.CustomerName) && req.CustomerName != license.CustomerName)
            {
                var oldName = license.CustomerName ?? "(vide)";
                license.CustomerName = req.CustomerName.Trim();
                changes.Add($"CustomerName: {oldName} → {license.CustomerName}");
            }

            // Modification de l'email client
            if (!string.IsNullOrWhiteSpace(req.CustomerEmail) && req.CustomerEmail != license.CustomerEmail)
            {
                var oldEmail = license.CustomerEmail ?? "(vide)";
                license.CustomerEmail = req.CustomerEmail.Trim();
                changes.Add($"CustomerEmail: {oldEmail} → {license.CustomerEmail}");
            }

            if (changes.Count == 0)
                return BadRequest("Aucune modification demandée.");

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = "UPDATED",
                Details = string.Join(" | ", changes),
                PerformedBy = "Admin (API)"
            });

            await _db.SaveChangesAsync();

            // Recharger le type pour la réponse
            var updatedType = await _db.LicenseTypes.FindAsync(license.LicenseTypeId);

            return Ok(new
            {
                license.LicenseKey,
                LicenseTypeId = license.LicenseTypeId,
                LicenseTypeName = updatedType?.Name ?? "?",
                LicenseTypeSlug = updatedType?.Slug ?? "?",
                license.MaxSeats,
                ActiveSeats = license.Seats.Count(s => s.IsActive),
                license.ExpirationDate,
                license.IsActive
            });
        }

        // ── Renouvellement ────────────────────────────────────────────────────────

        public class RenewLicenseRequest
        {
            public required string TransactionId { get; set; }
            public string? Reference { get; set; }
            public int? DaysToAdd { get; set; }
        }

        private IActionResult BuildRenewalResponse(
            License license,
            LicenseRenewal renewal,
            bool idempotent)
        {
            return Ok(new
            {
                license.LicenseKey,
                NewExpirationDate = renewal.ResultingExpirationDate ?? license.ExpirationDate,
                Reference = renewal.ResultingReference ?? license.Reference,
                renewal.DaysAdded,
                Idempotent = idempotent,
                Message = string.Format(_localizer["Api_Extended"].Value, renewal.DaysAdded)
            });
        }

        [HttpPost("licenses/{licenseKey}/renew")]
        public async Task<IActionResult> RenewLicense(string licenseKey, [FromBody] RenewLicenseRequest req)
        {
            TagLog("RENEW_LICENSE", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            if (string.IsNullOrEmpty(req.TransactionId) || req.TransactionId.Length > 256)
                return BadRequest(new { error = "invalid_transaction_id" });

            if (req.DaysToAdd is < 1 or > 3650)
                return BadRequest(new { error = "days_to_add_out_of_range" });

            var license = await _db.Licenses
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound(_localizer["Api_LicenseNotFound"].Value);

            // Si accès scopé, vérifier que la licence appartient au produit autorisé
            if (scopedProductId != null && license.ProductId != scopedProductId)
                return Unauthorized();

            if (license.Type == null) return BadRequest(_localizer["Api_LicenseTypeUnknown"].Value);

            if (!license.Type.IsRecurring)
                return BadRequest(_localizer["Api_RenewalNotAllowed"].Value);

            var existingRenewal = await _db.LicenseRenewals
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.TransactionId == req.TransactionId);
            if (existingRenewal != null)
            {
                if (existingRenewal.LicenseId != license.Id)
                    return Conflict(new { error = "transaction_used_by_another_license" });

                return BuildRenewalResponse(license, existingRenewal, idempotent: true);
            }

            var daysToAdd = req.DaysToAdd ?? license.Type.DefaultDurationDays;
            if (daysToAdd is < 1 or > 3650)
                return BadRequest(new { error = "days_to_add_out_of_range" });

            await using var transaction = _db.Database.IsRelational()
                ? await _db.Database.BeginTransactionAsync()
                : null;

            var currentExpiry = license.ExpirationDate ?? DateTime.UtcNow;
            if (currentExpiry < DateTime.UtcNow) currentExpiry = DateTime.UtcNow;

            license.ExpirationDate = currentExpiry.AddDays(daysToAdd);
            license.IsActive = true;

            if (!string.IsNullOrWhiteSpace(req.Reference))
                license.Reference = req.Reference.Trim();

            var renewal = new LicenseRenewal
            {
                LicenseId = license.Id,
                TransactionId = req.TransactionId,
                DaysAdded = daysToAdd,
                RenewalDate = DateTime.UtcNow,
                ResultingExpirationDate = license.ExpirationDate,
                ResultingReference = license.Reference
            };
            _db.LicenseRenewals.Add(renewal);

            try
            {
                await _db.SaveChangesAsync();
                if (transaction != null)
                    await transaction.CommitAsync();
            }
            catch (DbUpdateException)
            {
                if (transaction != null)
                    await transaction.RollbackAsync();
                _db.ChangeTracker.Clear();

                var concurrentRenewal = await _db.LicenseRenewals
                    .AsNoTracking()
                    .FirstOrDefaultAsync(r => r.TransactionId == req.TransactionId);
                if (concurrentRenewal == null)
                    throw;

                var persistedLicense = await _db.Licenses
                    .AsNoTracking()
                    .FirstAsync(l => l.Id == license.Id);
                if (concurrentRenewal.LicenseId != persistedLicense.Id)
                    return Conflict(new { error = "transaction_used_by_another_license" });

                return BuildRenewalResponse(persistedLicense, concurrentRenewal, idempotent: true);
            }

            return BuildRenewalResponse(license, renewal, idempotent: false);
        }

        // --- HARDWARE ID BLACKLIST ---

        [HttpGet("banned-hwids")]
        public async Task<IActionResult> GetBannedHardwareIds()
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var list = await _security.GetBannedHardwareIdsAsync();
            return Ok(list.Select(b => new {
                b.Id,
                b.HardwareId,
                ProductName = b.Product?.Name,
                b.ProductId,
                b.Reason,
                b.BannedAt,
                b.ExpiresAt,
                b.IsActive,
                b.BanCategory,
                b.PiracySuspectId
            }));
        }

        public class BanHardwareIdRequest
        {
            public required string HardwareId { get; set; }
            public string Reason { get; set; } = "Manual ban";
            public Guid? ProductId { get; set; }
            public DateTime? ExpiresAt { get; set; }
            public string? BanCategory { get; set; }
        }

        [HttpPost("banned-hwids")]
        public async Task<IActionResult> BanHardwareId([FromBody] BanHardwareIdRequest req)
        {
            var (auth, scopedProductId) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();
            if (string.IsNullOrWhiteSpace(req.HardwareId) || req.HardwareId.Trim().Length > 200)
                return BadRequest("HardwareId is required and must be at most 200 characters.");
            if (string.IsNullOrWhiteSpace(req.Reason) || req.Reason.Length > 500)
                return BadRequest("Reason is required and must be at most 500 characters.");
            if (req.BanCategory != null && !BannedHardwareId.Categories.IsKnown(req.BanCategory))
                return BadRequest(new
                {
                    error = "ban_category_invalid",
                    message = "BanCategory must be an exact known category identifier.",
                    allowedCategories = new[]
                    {
                        BannedHardwareId.Categories.QuotaAbuse,
                        BannedHardwareId.Categories.OutdatedVersion,
                        BannedHardwareId.Categories.Debugger,
                        BannedHardwareId.Categories.Piracy,
                        BannedHardwareId.Categories.Manual,
                        BannedHardwareId.Categories.DevCanaryQuarantine
                    }
                });
            if (scopedProductId.HasValue && req.ProductId.HasValue && req.ProductId != scopedProductId)
                return Unauthorized();
            if (scopedProductId.HasValue) req.ProductId = scopedProductId;

            await _security.BanHardwareIdAsync(req.HardwareId.Trim(), req.Reason, req.ProductId, req.ExpiresAt, banCategory: req.BanCategory);
            return Ok(new { Message = $"Hardware ID {req.HardwareId} banned" });
        }

        [HttpDelete("banned-hwids/{id}")]
        public async Task<IActionResult> UnbanHardwareId(Guid id, [FromQuery] string? auditReason = null)
        {
            var (auth, scopedProductId) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();
            var target = await _db.BannedHardwareIds.AsNoTracking()
                .Where(b => b.Id == id)
                .Select(b => new { b.ProductId })
                .SingleOrDefaultAsync();
            if (target == null) return NotFound();
            if (scopedProductId.HasValue && target.ProductId != scopedProductId) return Unauthorized();

            var found = await _security.UnbanHardwareIdAsync(id, auditReason);
            if (!found) return NotFound();
            return Ok(new { Message = "Hardware ID unbanned" });
        }

        // --- RESELLER PARTNERS ---

        [HttpGet("partners")]
        public async Task<IActionResult> GetPartners()
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var list = await _db.ResellerPartners.OrderBy(p => p.Name).ToListAsync();
            return Ok(list);
        }

        public class CreatePartnerRequest
        {
            public required string Code { get; set; }
            public required string Name { get; set; }
            public string? ContactEmail { get; set; }
            public string? Country { get; set; }
            public string? Notes { get; set; }
        }

        [HttpPost("partners")]
        public async Task<IActionResult> CreatePartner([FromBody] CreatePartnerRequest req)
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var code = req.Code.Trim().ToUpper();
            var exists = await _db.ResellerPartners.AnyAsync(p => p.Code == code);
            if (exists) return BadRequest($"Partner code '{code}' already exists");

            var partner = new ResellerPartner
            {
                Code = code,
                Name = req.Name.Trim(),
                ContactEmail = req.ContactEmail?.Trim(),
                Country = req.Country?.Trim(),
                Notes = req.Notes
            };

            _db.ResellerPartners.Add(partner);
            await _db.SaveChangesAsync();

            return Ok(partner);
        }

        [HttpPut("partners/{id}")]
        public async Task<IActionResult> UpdatePartner(Guid id, [FromBody] CreatePartnerRequest req)
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var partner = await _db.ResellerPartners.FindAsync(id);
            if (partner == null) return NotFound();

            partner.Name = req.Name.Trim();
            partner.ContactEmail = req.ContactEmail?.Trim();
            partner.Country = req.Country?.Trim();
            partner.Notes = req.Notes;
            await _db.SaveChangesAsync();

            return Ok(partner);
        }

        [HttpDelete("partners/{id}")]
        public async Task<IActionResult> DeactivatePartner(Guid id)
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var partner = await _db.ResellerPartners.FindAsync(id);
            if (partner == null) return NotFound();

            partner.IsActive = false;
            await _db.SaveChangesAsync();

            return Ok(new { Message = $"Partner {partner.Code} deactivated" });
        }

        // ── Hardware Fingerprints ─────────────────────────────────────────────────

        [HttpGet("fingerprints")]
        public async Task<IActionResult> GetFingerprints([FromQuery] int page = 1, [FromQuery] int pageSize = 50)
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var fps = await _fingerprint.GetFingerprintsAsync(page, pageSize);
            return Ok(fps);
        }

        [HttpGet("fingerprints/clusters")]
        public async Task<IActionResult> GetClusters()
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var clusters = await _fingerprint.GetClustersAsync();
            return Ok(clusters);
        }

        [HttpGet("fingerprints/{hardwareId}/related")]
        public async Task<IActionResult> GetRelatedHwids(string hardwareId)
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var related = await _fingerprint.FindRelatedHwidsAsync(hardwareId);
            return Ok(related);
        }

        [HttpPost("fingerprints/cluster-scan")]
        public async Task<IActionResult> RunClusterScan()
        {
            var (auth, _) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            await _fingerprint.RunClusteringAsync();
            return Ok(new { Message = "Clustering completed" });
        }

        [HttpGet("banned-components")]
        public async Task<IActionResult> GetBannedComponents()
        {
            var (auth, scopedProductId) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            var banned = await _security.GetBannedComponentsAsync(scopedProductId);
            return Ok(banned.Select(b => new
            {
                b.Id,
                b.ComponentType,
                b.ComponentHash,
                ProductId = b.ProductId,
                ProductName = b.Product?.Name,
                b.Reason,
                b.BannedAt,
                b.ExpiresAt,
                b.IsActive,
                IsEnforceable = Services.SecurityService.IsEnforceableComponentType(b.ComponentType)
            }));
        }

        [HttpGet("banned-components/impact")]
        public async Task<IActionResult> GetComponentBanImpact(
            [FromQuery] string componentType,
            [FromQuery] string componentHash,
            [FromQuery] Guid? productId = null)
        {
            var (auth, scopedProductId) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();
            if (string.IsNullOrWhiteSpace(componentType))
                return BadRequest(new { ErrorCode = "component_type_required" });
            if (!Services.SecurityService.TryNormalizeComponentHash(componentHash, out var normalizedHash))
                return BadRequest(new { ErrorCode = "component_hash_invalid" });
            if (scopedProductId.HasValue && productId.HasValue && productId != scopedProductId)
                return Unauthorized();
            if (scopedProductId.HasValue) productId = scopedProductId;

            var impact = await _fingerprint.GetComponentImpactAsync(componentType, normalizedHash, productId);
            return Ok(impact);
        }

        public class BanComponentRequest
        {
            public required string ComponentType { get; set; }
            public required string ComponentHash { get; set; }
            public string Reason { get; set; } = "";
            public Guid? ProductId { get; set; }
            public DateTime? ExpiresAt { get; set; }
        }

        [HttpPost("banned-components")]
        public async Task<IActionResult> BanComponent([FromBody] BanComponentRequest req)
        {
            var (auth, scopedProductId) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();

            if (string.IsNullOrWhiteSpace(req.ComponentType)) return BadRequest("ComponentType is required.");
            if (!Services.SecurityService.TryNormalizeComponentHash(req.ComponentHash, out var normalizedHash))
                return BadRequest(new
                {
                    ErrorCode = "component_hash_invalid",
                    Message = "ComponentHash must be exactly 64 ASCII hexadecimal characters."
                });
            if (string.IsNullOrWhiteSpace(req.Reason) || req.Reason.Length > 500)
                return BadRequest("Reason is required and must be at most 500 characters.");
            if (scopedProductId.HasValue && req.ProductId.HasValue && req.ProductId != scopedProductId)
                return Unauthorized();
            if (scopedProductId.HasValue) req.ProductId = scopedProductId;

            var validTypes = new[] { "CPU", "MB", "BIOS", "DISK", "HOST", "FP_CPU", "FP_MB", "FP_BIOS", "FP_DISK", "FP_HOST", "FP_EXE", "FP_DLL", "FP_CORE" };
            var normalizedType = req.ComponentType.Trim().ToUpperInvariant();
            if (!validTypes.Contains(normalizedType, StringComparer.Ordinal))
                return BadRequest($"Invalid component type. Valid: {string.Join(", ", validTypes)}");

            var impact = await _fingerprint.GetComponentImpactAsync(
                normalizedType, normalizedHash, req.ProductId);
            if (!Services.SecurityService.IsEnforceableComponentType(normalizedType))
            {
                return Conflict(new
                {
                    ErrorCode = "hardware_component_not_enforceable",
                    Message = "Hardware component fingerprints are correlation-only and cannot be globally banned.",
                    Impact = impact
                });
            }

            await _security.BanComponentAsync(normalizedType, normalizedHash, req.Reason, req.ProductId, req.ExpiresAt);
            return Ok(new { Message = $"Component {normalizedType} banned", Impact = impact });
        }

        [HttpDelete("banned-components/{id}")]
        public async Task<IActionResult> UnbanComponent(Guid id, [FromQuery] string? auditReason = null)
        {
            var (auth, scopedProductId) = await GetAuthContextAsync();
            if (!auth) return Unauthorized();
            var target = await _db.BannedComponents.AsNoTracking()
                .Where(b => b.Id == id)
                .Select(b => new { b.ProductId })
                .SingleOrDefaultAsync();
            if (target == null) return NotFound();
            if (scopedProductId.HasValue && target.ProductId != scopedProductId) return Unauthorized();

            var found = await _security.UnbanComponentAsync(id, auditReason);
            if (!found) return NotFound();
            return Ok(new { Message = "Component unbanned" });
        }
    }
}
