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
    public partial class AdminController : ControllerBase
    {
        private const string ResellerEvalDemoTypeSlug = "TIA-RESELLER-EVALDEMO";
        private const int PartnerSaleRenewalDays = 180;
        private const long LicenseAuthorityLockSalt = 999095;
        private const int LicenseRenewalFingerprintVersion = 1;

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

        /// <summary>
        /// TEMP-FAIL-OPEN(TKT-001262): temporary compatibility only. Strict Runtime-graph authority
        /// is the intended behavior, but the current code or persisted graph is known to be buggy;
        /// Franck requested logging instead of refusing legitimate clients. Every logged case must
        /// be analysed and corrected, then this branch must return to the strict decision and this
        /// marker must be removed. Cross-authority aliases remain closed and no HWID is logged.
        /// </summary>
        private async Task<string?> TryResolveLoggedCompatibilityAliasAsync(
            License license,
            Services.HardwareAuthorityResolution resolution)
        {
            if (resolution.RefusalReason != Services.HardwareAuthorityRefusalReason.AuthorityGraphDiverged
                || resolution.AliasId is not Guid aliasId
                || resolution.LicenseSeatId is not Guid seatId)
                return null;

            var candidate = await _db.HardwareAuthorityAliases.AsNoTracking()
                .Where(alias => alias.Id == aliasId
                    && alias.IsActive && alias.DisabledAtUtc == null
                    && alias.ProductId == license.ProductId && alias.LicenseId == license.Id
                    && alias.LicenseSeatId == seatId
                    && alias.LicenseSeat!.IsActive
                    && alias.LicenseSeat.LicenseId == license.Id
                    && alias.Binding!.ProductId == license.ProductId
                    && alias.Binding.LicenseId == license.Id
                    && alias.Binding.LicenseSeatId == seatId
                    && alias.RuntimeEnrollment!.ProductId == license.ProductId
                    && alias.RuntimeEnrollment.LicenseId == license.Id
                    && alias.RuntimeEnrollment.LicenseSeatId == seatId)
                .Select(alias => new
                {
                    SeatHardwareId = alias.LicenseSeat!.HardwareId,
                    BindingId = alias.Binding!.Id
                })
                .SingleOrDefaultAsync(HttpContext.RequestAborted);
            if (candidate == null
                || !Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(candidate.SeatHardwareId))
                return null;

            var binding = await _db.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(item => item.Id == candidate.BindingId, HttpContext.RequestAborted);
            var enrollmentRows = await _db.RuntimeEnrollments.AsNoTracking()
                .Where(enrollment => enrollment.BindingId == candidate.BindingId)
                .ToListAsync(HttpContext.RequestAborted);
            var now = DateTime.UtcNow;
            var coherentSeatRelease = Services.RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
                binding, enrollmentRows, now);
            var enrollments = enrollmentRows
                .Select(enrollment => new Services.RuntimeAuthorityEnrollmentSnapshot(
                    enrollment.State,
                    enrollment.InvalidationReason,
                    enrollment.ChallengeExpiresAtUtc,
                    enrollment.ChallengeConsumedAtUtc,
                    enrollment.ActivatedAtUtc,
                    enrollment.InvalidatedAtUtc))
                .ToList();
            var enrollmentDecision = Services.RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
                enrollments, now);

            _logger.LogWarning(
                "TEMP-FAIL-OPEN(TKT-001262) Hardware authority compatibility fail-open used for alias {AliasId}, product {ProductId}, licence {LicenseId}, seat {LicenseSeatId}, binding {BindingId}; reason {RefusalReason}, binding state {BindingState}, binding invalidation {BindingInvalidationReason}, enrollment count {EnrollmentCount}, enrollment states {EnrollmentStates}, enrollment invalidations {EnrollmentInvalidationReasons}, coherent seat release {CoherentSeatRelease}, enrollment decision {EnrollmentDecision}.",
                aliasId,
                license.ProductId,
                license.Id,
                seatId,
                binding.Id,
                resolution.RefusalReason,
                binding.State,
                binding.InvalidationReason ?? "none",
                enrollmentRows.Count,
                string.Join(',', enrollmentRows.Select(item => item.State).OrderBy(value => value, StringComparer.Ordinal)),
                string.Join(',', enrollmentRows.Select(item => item.InvalidationReason ?? "none").OrderBy(value => value, StringComparer.Ordinal)),
                coherentSeatRelease,
                enrollmentDecision);
            return candidate.SeatHardwareId;
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

        /// <summary>Returns one exact product-scoped type without materializing the complete catalogue.</summary>
        [HttpGet("products/{productName}/license-types/by-slug/{slug}")]
        public async Task<IActionResult> GetLicenseTypeBySlug(string productName, string slug)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("GET_LICENSE_TYPE_BY_SLUG", productName);
            if (string.IsNullOrEmpty(slug) || slug.Length > 120) return BadRequest("Invalid license type slug.");
            var auth = await GetAuthContextAsync();
            if (!auth.Authorized) return Unauthorized();

            var product = await _db.Products.SingleOrDefaultAsync(p => p.Name == productName);
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);
            if (auth.ScopedProductId.HasValue && auth.ScopedProductId.Value != product.Id) return Forbid();
            var matches = await _db.LicenseTypes.Include(t => t.CustomParams)
                .Where(t => t.ProductId == product.Id && t.Slug == slug)
                .Take(2).ToListAsync();
            if (matches.Count == 0) return NotFound("Type de licence introuvable.");
            if (matches.Count != 1) return Conflict("Type de licence ambigu.");
            return Ok(ProjectLicenseType(matches[0]));
        }

        /// <summary>Returns one exact product-scoped type identifier without exposing unrelated catalogue entries.</summary>
        [HttpGet("products/{productName}/license-types/by-id/{typeId:guid}")]
        public async Task<IActionResult> GetLicenseTypeById(string productName, Guid typeId)
        {
            var deny = RequireInternalIp(); if (deny != null) return deny;
            TagLog("GET_LICENSE_TYPE_BY_ID", productName);
            var auth = await GetAuthContextAsync();
            if (!auth.Authorized) return Unauthorized();

            var product = await _db.Products.SingleOrDefaultAsync(p => p.Name == productName);
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);
            if (auth.ScopedProductId.HasValue && auth.ScopedProductId.Value != product.Id) return Forbid();
            var type = await _db.LicenseTypes.Include(t => t.CustomParams)
                .SingleOrDefaultAsync(t => t.ProductId == product.Id && t.Id == typeId);
            return type == null ? NotFound("Type de licence introuvable.") : Ok(ProjectLicenseType(type));
        }

        /// <summary>Projects the complete immutable type contract consumed by internal billing clients.</summary>
        private static object ProjectLicenseType(LicenseType type) => new
        {
            type.Id,
            type.Name,
            type.Slug,
            type.Description,
            type.DefaultDurationDays,
            type.IsRecurring,
            type.DefaultAllowedVersions,
            type.DefaultMaxSeats,
            type.MaxActivationsPerDay,
            type.AllowAnonymous,
            type.IsFree,
            type.EnforceSingleUsePerHardwareId,
            type.DisableNewActivations,
            Params = type.CustomParams.Select(param => new { param.Key, param.Name, param.Value })
        };

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
            /// <summary>
            /// Gets or sets the exact provider-owned commercial subject for the complete batch.
            /// The UUID is opaque and is never inferred from customer or license presentation data.
            /// </summary>
            public Guid? CommercialSubjectId { get; set; }
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

        /// <summary>
        /// Captures the exact provider-owned values whose serialized form defines provisioning replay identity.
        /// </summary>
        /// <param name="ProductId">The exact target product identifier.</param>
        /// <param name="CommercialSubjectId">The explicit provider-owned commercial subject identifier.</param>
        /// <param name="LicenseTypeId">The exact product-scoped license type identifier.</param>
        /// <param name="CustomerName">The customer presentation name preserved without normalization.</param>
        /// <param name="CustomerEmail">The customer presentation email preserved without normalization.</param>
        /// <param name="LicenseReference">The optional license-facing reference derived before hashing.</param>
        /// <param name="ValidityDays">The resolved validity duration, or null for no expiration.</param>
        /// <param name="MaxSeats">The resolved seat limit.</param>
        /// <param name="PartnerCode">The optional canonical partner code.</param>
        /// <param name="Quantity">The bounded number of licenses in the batch.</param>
        /// <remarks>
        /// Positional order is cryptographically significant because the record is serialized directly before hashing.
        /// </remarks>
        private sealed record LicenseProvisioningFingerprint(
            Guid ProductId,
            Guid CommercialSubjectId,
            Guid LicenseTypeId,
            string CustomerName,
            string CustomerEmail,
            string? LicenseReference,
            int? ValidityDays,
            int MaxSeats,
            string? PartnerCode,
            int Quantity);

        /// <summary>Computes the canonical lowercase ASCII hexadecimal SHA-256 provisioning hash.</summary>
        /// <param name="fingerprint">The exact provisioning values protected by replay identity.</param>
        /// <returns>Exactly 64 lowercase ASCII hexadecimal characters.</returns>
        private static string ComputeProvisioningRequestHash(LicenseProvisioningFingerprint fingerprint)
        {
            var json = JsonSerializer.Serialize(fingerprint);
            return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        }

        /// <summary>
        /// Accepts either the canonical hash or the exact historical uppercase ASCII representation
        /// of that same digest, while rejecting mixed case, malformed text, and Unicode lookalikes.
        /// </summary>
        /// <param name="storedHash">The hash text already persisted in the provisioning ledger.</param>
        /// <param name="canonicalHash">The newly computed lowercase ASCII hexadecimal hash.</param>
        /// <returns><see langword="true"/> only for the canonical or exact legacy-uppercase representation.</returns>
        private static bool MatchesProvisioningRequestHash(string? storedHash, string canonicalHash)
        {
            if (string.Equals(storedHash, canonicalHash, StringComparison.Ordinal))
                return true;
            if (storedHash is null || storedHash.Length != 64 || canonicalHash.Length != 64)
                return false;

            for (var index = 0; index < canonicalHash.Length; index++)
            {
                var canonical = canonicalHash[index];
                var stored = storedHash[index];
                if (canonical is >= '0' and <= '9')
                {
                    if (stored != canonical)
                        return false;
                    continue;
                }

                // ASCII arithmetic is intentional: accepting a culture or Unicode case mapping would widen replay.
                if (canonical is < 'a' or > 'f' || stored != (char)(canonical - ('a' - 'A')))
                    return false;
            }

            return true;
        }

        private static string? NormalizeProvisioningReference(string? reference)
        {
            var trimmed = reference?.Trim();
            return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
        }

        private async Task<LicenseProvisioningRequest?> FindAttributedProvisioningRequestAsync(
            string reference,
            CancellationToken cancellationToken = default)
        {
            return await _db.LicenseProvisioningRequests
                .AsNoTracking()
                .Include(request => request.Licenses)
                .FirstOrDefaultAsync(
                    request => request.Reference == reference
                        && request.AuthorityProvenance == LicenseProvisioningRequest.ProviderAdminApiProvenance,
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

        /// <summary>
        /// Builds an idempotent response only when product, commercial subject, and provisioning hash
        /// match the canonical request or its exact historical uppercase ASCII hash representation.
        /// </summary>
        /// <param name="existing">The provider-attributed ledger row and its frozen license batch.</param>
        /// <param name="requestHash">The newly computed canonical lowercase provisioning hash.</param>
        /// <param name="productId">The exact target product identifier.</param>
        /// <param name="commercialSubjectId">The explicit provider-owned commercial subject identifier.</param>
        /// <param name="type">The resolved product-scoped license type used to shape the response.</param>
        /// <returns>An idempotent success response for an exact replay; otherwise a fail-closed conflict.</returns>
        private IActionResult BuildProvisioningRetryResponse(
            LicenseProvisioningRequest existing,
            string requestHash,
            Guid productId,
            Guid commercialSubjectId,
            LicenseType type)
        {
            if (existing.ProductId != productId
                || existing.CommercialSubjectId != commercialSubjectId
                || !MatchesProvisioningRequestHash(existing.RequestHash, requestHash))
                return Conflict(new { error = "reference_payload_conflict" });

            return BuildLicenseCreationResponse(existing.Licenses.ToList(), type, idempotent: true);
        }

        /// <summary>
        /// Creates one provider-owned license batch and persists a canonical lowercase provisioning hash,
        /// or returns the frozen batch for an exact canonical or historical-uppercase replay.
        /// </summary>
        /// <param name="req">The explicit product, subject, reference, and license presentation request.</param>
        /// <returns>
        /// A created or idempotently replayed license batch, or the existing authentication, validation,
        /// product-scope, and reference-conflict responses.
        /// </returns>
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
            if (!req.CommercialSubjectId.HasValue || req.CommercialSubjectId.Value == Guid.Empty)
                return BadRequest(new { error = "commercial_subject_required" });
            if (provisioningReference == null)
                return BadRequest(new { error = "provisioning_reference_required" });
            if (provisioningReference.Length > 512)
                return BadRequest(new { error = "reference_too_long" });

            var commercialSubjectId = req.CommercialSubjectId.Value;

            var normalizedPartnerCode = string.IsNullOrWhiteSpace(req.PartnerCode)
                ? null
                : req.PartnerCode.Trim().ToUpperInvariant();
            var requestHash = ComputeProvisioningRequestHash(new LicenseProvisioningFingerprint(
                targetProduct.Id,
                commercialSubjectId,
                type.Id,
                req.CustomerName,
                req.CustomerEmail,
                licenseReference,
                validityDays,
                maxSeats,
                normalizedPartnerCode,
                quantity));

            var existing = await FindAttributedProvisioningRequestAsync(provisioningReference);
            if (existing != null)
                return BuildProvisioningRetryResponse(
                    existing, requestHash, targetProduct.Id, commercialSubjectId, type);

            await using var transaction = _db.Database.IsRelational()
                ? await _db.Database.BeginTransactionAsync()
                : null;
            var generatedLicenses = new List<License>();

            try
            {
                if (_db.Database.IsRelational())
                {
                    await _db.Database.ExecuteSqlInterpolatedAsync($"""
                        INSERT INTO "RuntimeRecoveryCommercialSubjects" ("ProductId", "Id", "CreatedAtUtc")
                        VALUES ({targetProduct.Id}, {commercialSubjectId}, {DateTime.UtcNow})
                        ON CONFLICT ("ProductId", "Id") DO NOTHING;
                        """);
                }
                else if (!await _db.RuntimeRecoveryCommercialSubjects.AnyAsync(subject =>
                    subject.ProductId == targetProduct.Id && subject.Id == commercialSubjectId))
                {
                    _db.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
                    {
                        ProductId = targetProduct.Id,
                        Id = commercialSubjectId,
                        CreatedAtUtc = DateTime.UtcNow
                    });
                }

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

                var provisioningRequest = new LicenseProvisioningRequest
                {
                    ProductId = targetProduct.Id,
                    Reference = provisioningReference,
                    RequestHash = requestHash,
                    CommercialSubjectId = commercialSubjectId,
                    AuthorityProvenance = LicenseProvisioningRequest.ProviderAdminApiProvenance
                };
                _db.LicenseProvisioningRequests.Add(provisioningRequest);

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
                    _db.RuntimeRecoveryCommercialOwnerships.Add(new RuntimeRecoveryCommercialOwnership
                    {
                        Id = Guid.NewGuid(),
                        ProductId = targetProduct.Id,
                        LicenseId = license.Id,
                        OwnerSubjectId = commercialSubjectId,
                        State = "ACTIVE",
                        CreatedAtUtc = DateTime.UtcNow
                    });
                    generatedLicenses.Add(license);
                }

                await ExtendResellerDemoLicenseAfterPartnerSaleAsync(targetProduct.Id, normalizedPartnerCode, type);
                await _db.SaveChangesAsync();
                if (transaction != null)
                    await transaction.CommitAsync();
            }
            catch (DbUpdateException)
            {
                if (transaction != null)
                    await transaction.RollbackAsync();
                _db.ChangeTracker.Clear();

                existing = await FindAttributedProvisioningRequestAsync(provisioningReference);
                if (existing == null)
                    throw;

                return BuildProvisioningRetryResponse(
                    existing, requestHash, targetProduct.Id, commercialSubjectId, type);
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
        public async Task<IActionResult> ResolveLicense(
            [FromBody] TargetedLicenseResolutionRequest req,
            [FromServices] Services.IHardwareAuthorityAliasResolver hardwareAuthorityAliases)
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
                : await ResolveByHardwareIdAsync(req.ProductId, selector, hardwareAuthorityAliases);
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

        /// <summary>
        /// Collects every licence candidate for one hardware selector: seats and legacy licence rows
        /// matching the identifier exactly, plus the canonical seat of every server-authenticated alias
        /// of that identifier (SUP-000040). The caller keeps its priority ordering, so an active aliased
        /// seat outranks a stale inactive seat of the legacy identifier.
        /// </summary>
        /// <param name="productId">Exact product scope.</param>
        /// <param name="hardwareId">Canonical hardware selector, compared exactly.</param>
        /// <param name="hardwareAuthorityAliases">Server-owned alias resolver.</param>
        /// <returns>All candidates; empty when nothing matches.</returns>
        private async Task<List<TargetedLicenseCandidate>> ResolveByHardwareIdAsync(
            Guid productId,
            string hardwareId,
            Services.IHardwareAuthorityAliasResolver hardwareAuthorityAliases)
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

            // TEMP-FAIL-OPEN(TKT-001262): TEMPORARY observation path, never leave as is. The update
            // check resolved the raw legacy identifier only, so a machine known through an
            // authenticated alias was reported "seat_inactive" by its stale legacy seat and the
            // Desktop update preflight failed after a successful activation (SUP-000040). Franck's
            // directive (2026-09-21): no known HWID alias divergence blocks a legitimate client; accept
            // and log. Every alias of this legacy digest in the product is examined (no arbitrary cap,
            // so the only active licence can never be skipped) through the shared resolver, which
            // keeps ambiguous, disabled, missing and cross-licence aliases refused and requires an
            // eligible licence. Active HWID bans are checked by the resolver only in its divergent
            // graph branch; this read-only resolution grants nothing by itself, and activation, check
            // and the distribution preflight keep enforcing bans. Keep during observation; removal
            // requires conclusive telemetry and Franck's approval.
            if (Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(hardwareId))
            {
                var legacyDigest = Services.HardwareAuthorityAliasResolver.Sha256(hardwareId);
                var aliasLicenseIds = await _db.HardwareAuthorityAliases.AsNoTracking()
                    .Where(alias => alias.ProductId == productId && alias.LegacyHardwareIdSha256 == legacyDigest)
                    .Select(alias => alias.LicenseId)
                    .Distinct()
                    .OrderBy(licenseId => licenseId)
                    .ToListAsync();
                foreach (var licenseId in aliasLicenseIds)
                {
                    var resolution = await hardwareAuthorityAliases.ResolveAsync(
                        _db,
                        productId,
                        licenseId,
                        hardwareId,
                        Services.HardwareAuthorityResolutionIntent.StatusCheck,
                        HttpContext.RequestAborted);
                    if (!resolution.UsedAlias || resolution.LicenseSeatId is not Guid seatId)
                        continue;
                    var seat = await _db.LicenseSeats.AsNoTracking()
                        .Include(candidate => candidate.License)
                            .ThenInclude(license => license!.Type)
                        .SingleOrDefaultAsync(candidate => candidate.Id == seatId
                            && candidate.LicenseId == licenseId
                            && candidate.License != null
                            && candidate.License.ProductId == productId);
                    if (seat?.License == null)
                        continue;
                    _logger.LogWarning(
                        "TEMP-FAIL-OPEN(TKT-001262) Targeted licence resolution used alias {AliasId} for product {ProductId}: licence {LicenseId}, canonical seat {LicenseSeatId} (active {SeatActive}), raw identifier candidates {RawCandidateCount}, correlation {CorrelationId}.",
                        resolution.AliasId?.ToString() ?? "none",
                        productId,
                        licenseId,
                        seat.Id,
                        seat.IsActive,
                        seatMatches.Count + legacyMatches.Count,
                        System.Diagnostics.Activity.Current?.Id ?? "none");
                    candidates.Add(new TargetedLicenseCandidate(seat.License, seat));
                }
            }
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

        /// <summary>Authorizes and atomically releases one exact seat and its commercial assignment.</summary>
        [HttpDelete("licenses/{licenseKey}/seats/{hardwareId}")]
        public async Task<IActionResult> DeactivateSeat(string licenseKey, string hardwareId)
        {
            TagLog("DEACTIVATE_SEAT", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            await using var releaseTransaction = await Services.SeatRuntimeReleaseAuthority.BeginAsync(_db, HttpContext.RequestAborted);
            var license = await _db.Licenses
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey.ToUpper());

            if (license == null) return NotFound(_localizer["Api_LicenseNotFound"].Value);

            if (scopedProductId != null && license.ProductId != scopedProductId)
                return Unauthorized();

            var seat = license.Seats?.FirstOrDefault(s => s.HardwareId == hardwareId && s.IsActive);
            if (seat == null) return NotFound("Appareil non trouvé ou déjà délié.");

            try
            {
                var releaseScope = await Services.SeatRuntimeReleaseAuthority.PrepareAsync(
                    _db, license.ProductId, license, [seat], DateTime.UtcNow, HttpContext.RequestAborted);
                seat.IsActive = false;
                seat.UnlinkedAt = releaseScope.ObservedAtUtc;
                SyncLegacyHardwareStateFromSeats(license);

                _db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Action = HistoryActions.UnlinkedApi,
                    Details = $"Délié via API admin : {hardwareId}",
                    PerformedBy = "Admin (API)",
                    Timestamp = releaseScope.ObservedAtUtc
                });

                await Services.SeatRuntimeReleaseAuthority.CompleteAsync(
                    _db, releaseScope, [seat], HttpContext.RequestAborted);
                if (releaseTransaction != null)
                    await releaseTransaction.CommitAsync(HttpContext.RequestAborted);
                return Ok(new { Message = "Appareil délié avec succès." });
            }
            catch (Services.DistributionOperationException exception)
            {
                return StatusCode(exception.StatusCode, new { Error = exception.ErrorCode });
            }
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

        /// <summary>
        /// Serializes legacy revoke/unrevoke before their EF read. PostgreSQL takes the existing
        /// per-license advisory lock, trigger authority lock, then license row lock in that order;
        /// non-PostgreSQL relational providers retain their serializable transaction behavior.
        /// </summary>
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
                    // The runtime-enrollment BEFORE STATEMENT trigger takes this authority lock
                    // before any UPDATE row lock. Acquire it in that same order to avoid a cycle
                    // with independent SQL/Razor writers, which do not take the per-license lock.
                    await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
                    // Legacy advisory locks do not coordinate Razor/SQL writers. Lock the exact
                    // row before its EF read so a concurrent revocation cannot be overwritten by
                    // a stale tracked state. Keep advisory -> license-row order for both actions.
                    await _db.Database.ExecuteSqlInterpolatedAsync(
                        $"SELECT \"Id\" FROM public.\"Licenses\" WHERE \"LicenseKey\" = {licenseKey} FOR UPDATE");
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

        /// <summary>
        /// Carries one exact canonical hardware identifier for a licence-scoped seat coverage check.
        /// </summary>
        public sealed class HardwareAuthorityCoverageRequest
        {
            /// <summary>Gets or sets the exact 16-character uppercase hexadecimal identifier.</summary>
            public required string HardwareId { get; set; }
        }

        /// <summary>
        /// Reads a product-scoped license, preserving effective expiry status while exposing the
        /// independent revocation state and opaque database version for conditional reactivation.
        /// HasAnyActivation includes released seats, legacy hardware and activation timestamps; zero active seats is not first-use proof.
        /// SeatChangeQuota reports the live daily seat-change quota (limit, used today, remaining,
        /// exhaustion, next UTC reset) so the dashboard can block an unlink before offering it.
        /// </summary>
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

            // Read on every request so a limit changed in SoftLicence is visible to the Website
            // dashboard immediately, without caching or a client release (TKT-001206).
            var seatChangeQuota = await Services.SeatChangeQuota.GetStatusAsync(
                _db, license, DateTime.UtcNow, HttpContext.RequestAborted);

            return Ok(new
            {
                license.Id,
                Product = license.Product?.Name ?? "Unknown",
                license.ProductId,
                license.AuthorityVersion,
                AuthorityIsActive = license.IsActive,
                // Expose the ownership version, never the provider-private subject identifier.
                CommercialOwnershipId = await _db.RuntimeRecoveryCommercialOwnerships
                    .Where(o => o.LicenseId == license.Id && o.ProductId == license.ProductId && o.State == "ACTIVE")
                    .Select(o => (Guid?)o.Id).SingleOrDefaultAsync(),
                license.RevocationReason,
                license.RevokedAt,
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
                // An inactive historical seat still proves that this is not a never-activated pass.
                HasAnyActivation = license.ActivationDate.HasValue || license.HardwareId != null || license.Seats.Any(),
                Activations = license.Seats.Where(s => s.IsActive).Select(s => new { s.HardwareId, ActivatedAt = s.FirstActivatedAt }),
                CreatedAt = license.CreationDate,
                Params = license.Type?.CustomParams.Select(cp => new { cp.Key, cp.Name, cp.Value }),
                // Advisory read model for the dashboard; enforcement stays in the release paths.
                // Limit 0 means unlimited and then Remaining is null.
                SeatChangeQuota = new
                {
                    seatChangeQuota.Limit,
                    seatChangeQuota.UsedToday,
                    seatChangeQuota.Remaining,
                    seatChangeQuota.IsExhausted,
                    seatChangeQuota.ResetAtUtc,
                },
            });
        }

        /// <summary>
        /// Reports whether the submitted identifier is covered by an existing active seat, either
        /// directly or through one server-authenticated same-licence alias. No alias or canonical
        /// identifier is returned to the caller. A bounded same-licence Runtime-graph drift is
        /// logged and tolerated; disabled, ambiguous and cross-authority aliases remain closed.
        /// </summary>
        /// <param name="licenseKey">Exact licence key owned by the authenticated admin caller.</param>
        /// <param name="request">Exact identifier whose active-seat coverage is requested.</param>
        /// <param name="hardwareAuthorityAliases">Server-owned alias authority resolver.</param>
        /// <returns>An explicit boolean authority proof that never changes seat ownership or count.</returns>
        [HttpPost("licenses/{licenseKey}/hardware-authority")]
        public async Task<IActionResult> GetHardwareAuthorityCoverage(
            string licenseKey,
            [FromBody] HardwareAuthorityCoverageRequest request,
            [FromServices] Services.IHardwareAuthorityAliasResolver hardwareAuthorityAliases)
        {
            TagLog("GET_HARDWARE_AUTHORITY");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();
            if (!Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(request.HardwareId))
                return BadRequest(new { error = "hardware_id_invalid" });

            var license = await _db.Licenses
                .Include(candidate => candidate.Seats)
                .SingleOrDefaultAsync(candidate => candidate.LicenseKey == licenseKey);
            if (license == null) return NotFound("Licence introuvable.");
            if (scopedProductId != null && license.ProductId != scopedProductId) return Unauthorized();
            if (!license.IsActive || license.RevokedAt != null
                || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= DateTime.UtcNow))
                return Ok(new { CoveredByActiveSeat = false });

            var resolution = await hardwareAuthorityAliases.ResolveAsync(
                _db,
                license.ProductId,
                license.Id,
                request.HardwareId,
                Services.HardwareAuthorityResolutionIntent.StatusCheck,
                HttpContext.RequestAborted);
            if (resolution.Refused)
            {
                var compatibilityHardwareId = await TryResolveLoggedCompatibilityAliasAsync(
                    license, resolution);
                if (compatibilityHardwareId == null)
                {
                    _logger.LogWarning(
                        "Hardware authority coverage refused for alias {AliasId}, licence {LicenseId}; reason {RefusalReason}.",
                        resolution.AliasId,
                        license.Id,
                        resolution.RefusalReason);
                    return Ok(new { CoveredByActiveSeat = false });
                }
                return Ok(new { CoveredByActiveSeat = true });
            }

            var effectiveHardwareId = resolution.EffectiveHardwareId;
            var coveredByActiveSeat = license.Seats.Any(seat =>
                seat.IsActive && seat.HardwareId == effectiveHardwareId);
            return Ok(new { CoveredByActiveSeat = coveredByActiveSeat });
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

        /// <summary>
        /// Describes an idempotent recurring-license renewal request.
        /// </summary>
        public class RenewLicenseRequest
        {
            private string? _reference;
            private int? _daysToAdd;
            private DateTimeOffset? _targetExpirationUtc;

            /// <summary>
            /// Gets or sets the opaque payment transaction identifier used as the idempotency key.
            /// </summary>
            public required string TransactionId { get; set; }

            /// <summary>
            /// Gets or sets the optional human-readable billing reference.
            /// </summary>
            public string? Reference
            {
                get => _reference;
                set
                {
                    _reference = value;
                    ReferenceSpecified = true;
                }
            }

            /// <summary>
            /// Gets whether the JSON payload explicitly contained the reference property, including an explicit null.
            /// </summary>
            [JsonIgnore]
            public bool ReferenceSpecified { get; private set; }

            /// <summary>
            /// Gets or sets the legacy number of days to add to the current entitlement.
            /// </summary>
            public int? DaysToAdd
            {
                get => _daysToAdd;
                set
                {
                    _daysToAdd = value;
                    DaysToAddSpecified = true;
                }
            }

            /// <summary>
            /// Gets whether the JSON payload explicitly contained the legacy duration property.
            /// </summary>
            [JsonIgnore]
            public bool DaysToAddSpecified { get; private set; }

            /// <summary>
            /// Gets or sets the exact UTC entitlement expiration requested by the billing authority.
            /// </summary>
            public DateTimeOffset? TargetExpirationUtc
            {
                get => _targetExpirationUtc;
                set
                {
                    _targetExpirationUtc = value;
                    TargetExpirationUtcSpecified = true;
                }
            }

            /// <summary>
            /// Gets whether the JSON payload explicitly contained the exact-target property.
            /// </summary>
            [JsonIgnore]
            public bool TargetExpirationUtcSpecified { get; private set; }
        }

        /// <summary>
        /// Captures every canonical request value and presence marker protected by renewal replay identity.
        /// </summary>
        /// <param name="ContractVersion">The serialization contract version stored beside the digest.</param>
        /// <param name="LicenseId">The exact license targeted by the transaction.</param>
        /// <param name="TransactionId">The opaque transaction identifier preserved without normalization.</param>
        /// <param name="ReferenceSpecified">Whether the request contained the reference property.</param>
        /// <param name="Reference">The trim-only canonical billing reference, or null when it has no effect.</param>
        /// <param name="DaysToAddSpecified">Whether the request contained the duration property.</param>
        /// <param name="DaysToAdd">The explicit duration, not the server-resolved default.</param>
        /// <param name="TargetExpirationUtcSpecified">Whether the request contained the exact-target property.</param>
        /// <param name="TargetExpirationUtc">The target canonicalized to PostgreSQL microsecond precision.</param>
        /// <remarks>Positional order is cryptographically significant and may change only with a new contract version.</remarks>
        private sealed record LicenseRenewalRequestFingerprint(
            int ContractVersion,
            Guid LicenseId,
            string TransactionId,
            bool ReferenceSpecified,
            string? Reference,
            bool DaysToAddSpecified,
            int? DaysToAdd,
            bool TargetExpirationUtcSpecified,
            DateTime? TargetExpirationUtc);

        /// <summary>
        /// Builds the stable response returned for both an initial renewal and its retries.
        /// </summary>
        /// <param name="license">The license after the stored renewal result has been applied.</param>
        /// <param name="renewal">The immutable billing transaction ledger row.</param>
        /// <param name="idempotent">Whether this response replays an already-persisted transaction.</param>
        /// <returns>The frozen public renewal result.</returns>
        private IActionResult BuildRenewalResponse(
            License license,
            LicenseRenewal renewal,
            bool idempotent)
        {
            return Ok(new
            {
                license.LicenseKey,
                NewExpirationDate = renewal.ResultingExpirationDate,
                Reference = renewal.ResultingReference,
                renewal.DaysAdded,
                Idempotent = idempotent,
                Message = string.Format(_localizer["Api_Extended"].Value, renewal.DaysAdded)
            });
        }

        /// <summary>
        /// Canonicalizes an exact UTC target to PostgreSQL timestamp precision.
        /// </summary>
        /// <param name="targetExpirationUtc">The exact UTC entitlement target supplied by the caller.</param>
        /// <returns>The same instant truncated to PostgreSQL's microsecond precision.</returns>
        private static DateTime CanonicalizeTargetExpiration(DateTimeOffset targetExpirationUtc)
        {
            var utcTicks = targetExpirationUtc.UtcTicks;
            return new DateTime(utcTicks - (utcTicks % 10), DateTimeKind.Utc);
        }

        /// <summary>
        /// Applies the endpoint's existing trim-only reference semantics without Unicode or culture normalization.
        /// </summary>
        /// <param name="reference">The optional caller-supplied human reference.</param>
        /// <returns>The trimmed value, or null when the reference has no renewal effect.</returns>
        private static string? CanonicalizeRenewalReference(string? reference)
        {
            var trimmed = reference?.Trim();
            return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
        }

        /// <summary>
        /// Computes the canonical lowercase ASCII SHA-256 digest for a versioned renewal request.
        /// </summary>
        /// <param name="fingerprint">The ordered request representation, including omission markers.</param>
        /// <returns>Exactly 64 lowercase ASCII hexadecimal characters.</returns>
        private static string ComputeLicenseRenewalRequestFingerprint(
            LicenseRenewalRequestFingerprint fingerprint)
        {
            var json = JsonSerializer.Serialize(fingerprint);
            return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        }

        /// <summary>
        /// Determines whether a persisted renewal fingerprint is canonical and supported by this server.
        /// </summary>
        /// <param name="renewal">The persisted renewal ledger row.</param>
        /// <returns><see langword="true"/> only for version 1 lowercase ASCII SHA-256 text.</returns>
        private static bool HasVerifiableLicenseRenewalFingerprint(LicenseRenewal renewal)
        {
            if (renewal.RequestFingerprintVersion != LicenseRenewalFingerprintVersion
                || renewal.RequestFingerprint is not { Length: 64 } stored)
                return false;

            foreach (var character in stored)
            {
                if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compares a verified persisted renewal digest with the current canonical request in constant time.
        /// </summary>
        /// <param name="storedFingerprint">A prevalidated lowercase 64-character hexadecimal digest.</param>
        /// <param name="requestFingerprint">The canonical lowercase digest computed for the current request.</param>
        /// <returns><see langword="true"/> only when both SHA-256 byte sequences are identical.</returns>
        private static bool MatchesLicenseRenewalRequestFingerprint(
            string storedFingerprint,
            string requestFingerprint)
        {
            var storedBytes = Convert.FromHexString(storedFingerprint);
            var requestBytes = Convert.FromHexString(requestFingerprint);
            return CryptographicOperations.FixedTimeEquals(storedBytes, requestBytes);
        }

        /// <summary>
        /// Applies the strict replay policy shared by ordinary lookup and unique-conflict recovery.
        /// </summary>
        /// <param name="license">The provider-authorized license targeted by the current request.</param>
        /// <param name="renewal">The existing immutable transaction result.</param>
        /// <param name="requestFingerprint">The digest of the complete current canonical request.</param>
        /// <returns>The frozen success response or a deterministic conflict response.</returns>
        private IActionResult BuildLicenseRenewalReplayResponse(
            License license,
            LicenseRenewal renewal,
            string requestFingerprint)
        {
            // Historical, malformed, or unsupported fingerprints cannot prove request equality and fail closed.
            if (!HasVerifiableLicenseRenewalFingerprint(renewal))
                return Conflict(new { error = "legacy_transaction_unverified", retryable = false });

            if (renewal.LicenseId != license.Id)
                return Conflict(new { error = "transaction_used_by_another_license" });

            if (!MatchesLicenseRenewalRequestFingerprint(renewal.RequestFingerprint!, requestFingerprint))
                return Conflict(new { error = "transaction_payload_conflict" });

            return BuildRenewalResponse(license, renewal, idempotent: true);
        }

        /// <summary>
        /// Renews a recurring license once for an opaque billing transaction and safely replays exact retries.
        /// </summary>
        /// <param name="licenseKey">The provider-authorized recurring license to renew.</param>
        /// <param name="req">The complete billing transaction request whose omission-aware fingerprint is persisted.</param>
        /// <returns>
        /// The frozen renewal result, a deterministic conflict for a reused transaction, or the endpoint's
        /// existing validation and authorization response.
        /// </returns>
        /// <remarks>
        /// A persisted transaction is replayable only when its supported request fingerprint matches exactly.
        /// Historical, malformed, and unsupported fingerprints fail closed with
        /// <c>legacy_transaction_unverified</c> and are never synthesized or backfilled.
        /// Pass-backed licenses acquire the shared paid-horizon lock order before renewal so a simultaneous
        /// daily, monthly, or annual period cannot lose either purchased duration.
        /// </remarks>
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

            if (req.DaysToAdd.HasValue && req.TargetExpirationUtc.HasValue)
                return BadRequest(new { error = "renewal_duration_is_ambiguous" });

            if (req.TargetExpirationUtc is { Offset: var offset } && offset != TimeSpan.Zero)
                return BadRequest(new { error = "target_expiration_must_be_utc" });

            var requestedTargetExpiration = req.TargetExpirationUtc.HasValue
                ? CanonicalizeTargetExpiration(req.TargetExpirationUtc.Value)
                : (DateTime?)null;
            var canonicalReference = CanonicalizeRenewalReference(req.Reference);

            await using var transaction = _db.Database.IsRelational()
                ? await _db.Database.BeginTransactionAsync()
                : null;
            if (_db.Database.IsNpgsql())
            {
                // Even a license without a pass can acquire its first paid period concurrently.
                // Serialize before reading either authority, not only after observing an existing pass.
                // This also precedes renewal FK writes and their license locks, avoiding lock inversion.
                await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';");
                await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            }

            var license = await _db.Licenses
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound(_localizer["Api_LicenseNotFound"].Value);

            // Si accès scopé, vérifier que la licence appartient au produit autorisé
            if (scopedProductId != null && license.ProductId != scopedProductId)
                return Unauthorized();

            if (license.Type == null) return BadRequest(_localizer["Api_LicenseTypeUnknown"].Value);

            var paidPeriod = await _db.PersonalDayPasses.FirstOrDefaultAsync(pass => pass.LicenseId == license.Id);
            if (!license.Type.IsRecurring && paidPeriod is null)
                return BadRequest(_localizer["Api_RenewalNotAllowed"].Value);

            var requestFingerprint = ComputeLicenseRenewalRequestFingerprint(
                new LicenseRenewalRequestFingerprint(
                    LicenseRenewalFingerprintVersion,
                    license.Id,
                    req.TransactionId,
                    req.ReferenceSpecified,
                    canonicalReference,
                    req.DaysToAddSpecified,
                    req.DaysToAdd,
                    req.TargetExpirationUtcSpecified,
                    requestedTargetExpiration));

            var existingRenewal = await _db.LicenseRenewals
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.TransactionId == req.TransactionId);
            if (existingRenewal != null)
                return BuildLicenseRenewalReplayResponse(license, existingRenewal, requestFingerprint);

            if (paidPeriod is not null && _db.Database.IsNpgsql())
            {
                // Pass-backed renewals share the same global authority lock as paid-period insertion.
                // Lock the pass before its License so both paths preserve one order and cannot lose time.
                _ = await _db.PersonalDayPasses.FromSqlInterpolated($"""
                    SELECT * FROM public."PersonalDayPasses" WHERE "Id" = {paidPeriod.Id} AND "LicenseId" = {license.Id} FOR UPDATE
                    """).AsNoTracking().SingleAsync();
                _ = await _db.Licenses.FromSqlInterpolated($"""
                    SELECT * FROM public."Licenses" WHERE "Id" = {license.Id} FOR UPDATE
                    """).AsNoTracking().SingleAsync();
                await _db.Entry(paidPeriod).ReloadAsync();
                await _db.Entry(license).ReloadAsync();
            }

            var renewalTime = DateTime.UtcNow;
            var pendingFirstActivation = paidPeriod is not null
                && !license.ExpirationDate.HasValue
                && !paidPeriod.InitialPaidThroughUtc.HasValue
                && !license.ActivationDate.HasValue;
            var currentExpiry = pendingFirstActivation ? paidPeriod!.PaidThroughUtc : license.ExpirationDate ?? renewalTime;
            if (!pendingFirstActivation && currentExpiry < renewalTime) currentExpiry = renewalTime;

            int daysToAdd;
            if (requestedTargetExpiration.HasValue)
            {
                if (pendingFirstActivation)
                    return BadRequest(new { error = "target_expiration_requires_activation" });
                if (requestedTargetExpiration.Value <= currentExpiry)
                    return BadRequest(new { error = "target_expiration_must_extend_entitlement" });

                if ((requestedTargetExpiration.Value - currentExpiry).TotalDays > 3650)
                    return BadRequest(new { error = "target_expiration_out_of_range" });

                daysToAdd = (int)Math.Ceiling(
                    (requestedTargetExpiration.Value - currentExpiry).TotalDays);
                license.ExpirationDate = requestedTargetExpiration.Value;
            }
            else
            {
                daysToAdd = req.DaysToAdd ?? license.Type.DefaultDurationDays;
                if (daysToAdd is < 1 or > 3650)
                    return BadRequest(new { error = "days_to_add_out_of_range" });

                if (pendingFirstActivation)
                    paidPeriod!.PaidThroughUtc = currentExpiry.AddDays(daysToAdd);
                else
                    license.ExpirationDate = currentExpiry.AddDays(daysToAdd);
            }

            license.IsActive = true;
            if (pendingFirstActivation)
            {
                // Force the existing database trigger to rotate deferred authority even though expiry stays null.
                await _db.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE public."Licenses" SET "AuthorityVersion" = "AuthorityVersion"
                    WHERE "Id" = {license.Id}
                    """);
                await _db.Entry(license).ReloadAsync();
            }
            else if (paidPeriod is not null)
                paidPeriod.PaidThroughUtc = license.ExpirationDate!.Value;

            if (canonicalReference is not null)
                license.Reference = canonicalReference;

            var renewal = new LicenseRenewal
            {
                LicenseId = license.Id,
                TransactionId = req.TransactionId,
                DaysAdded = daysToAdd,
                RenewalDate = renewalTime,
                ResultingExpirationDate = pendingFirstActivation ? paidPeriod!.PaidThroughUtc : license.ExpirationDate,
                ResultingReference = license.Reference,
                RequestFingerprintVersion = LicenseRenewalFingerprintVersion,
                RequestFingerprint = requestFingerprint
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
                return BuildLicenseRenewalReplayResponse(
                    persistedLicense,
                    concurrentRenewal,
                    requestFingerprint);
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
