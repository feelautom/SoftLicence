using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using System.Security.Cryptography;
using System.Text;

namespace SoftLicence.Server.Controllers
{
    [ApiController]
    [Route("api/admin")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public class AdminController : ControllerBase
    {
        private readonly LicenseDbContext _db;
        private readonly IConfiguration _config;
        private readonly Services.EncryptionService _encryption;
        private readonly IStringLocalizer<SharedResource> _localizer;
        private readonly Services.SettingsService _settings;

        public AdminController(LicenseDbContext db, IConfiguration config, Services.EncryptionService encryption, IStringLocalizer<SharedResource> localizer, Services.SettingsService settings)
        {
            _db = db;
            _config = config;
            _encryption = encryption;
            _localizer = localizer;
            _settings = settings;
        }

        // Retourne (authorized, scopedProductId)
        // scopedProductId == null  → secret global, accès complet
        // scopedProductId != null  → secret produit, accès limité à ce produit
        private async Task<(bool Authorized, Guid? ScopedProductId)> GetAuthContextAsync()
        {
            if (!Request.Headers.TryGetValue("X-Admin-Secret", out var secret))
                return (false, null);

            var secretStr = secret.ToString();

            // 1. Vérification du secret global (config) — seulement si activé
            var globalEnabled = await _settings.GetBoolSettingAsync("GlobalApiSecretEnabled", true);
            if (globalEnabled)
            {
                var configuredSecret = _config["AdminSettings:ApiSecret"];
                if (!string.IsNullOrEmpty(configuredSecret))
                {
                    var secretBytes = Encoding.UTF8.GetBytes(secretStr);
                    var expectedBytes = Encoding.UTF8.GetBytes(configuredSecret);
                    if (CryptographicOperations.FixedTimeEquals(secretBytes, expectedBytes))
                    {
                        var allowedIpsStr = _config["AdminSettings:AllowedIps"];
                        if (!string.IsNullOrEmpty(allowedIpsStr))
                        {
                            var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
                            var allowedIps = allowedIpsStr.Split(',').Select(ip => ip.Trim()).ToList();
                            if (!allowedIps.Contains(clientIp) && clientIp != "127.0.0.1" && clientIp != "::1")
                                return (false, null);
                        }
                        return (true, null); // accès complet
                    }
                }
            }

            // 2. Vérification des secrets par produit
            var product = await _db.Products.FirstOrDefaultAsync(p => p.ApiSecret == secretStr);
            if (product != null)
                return (true, product.Id); // accès scopé à ce produit

            return (false, null);
        }

        private void TagLog(string action, string details = "")
        {
            HttpContext.Items[LogKeys.AppName] = "SYSTEM";
            HttpContext.Items[LogKeys.Endpoint] = "ADMIN_" + action;
            HttpContext.Items[LogKeys.LicenseKey] = details;
        }

        [HttpPost("products")]
        public async Task<IActionResult> CreateProduct([FromBody] string name)
        {
            TagLog("CREATE_PRODUCT", name);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized || scopedProductId != null) return Unauthorized();
            if (string.IsNullOrWhiteSpace(name)) return BadRequest(_localizer["Products_NameRequired"].Value);
            if (await _db.Products.AnyAsync(p => p.Name == name)) return BadRequest(_localizer["Api_Exists"].Value);

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
        }

        [HttpPost("licenses")]
        public async Task<IActionResult> CreateLicense([FromBody] CreateLicenseRequest req)
        {
            TagLog("CREATE_LICENSE", $"{req.ProductName} -> {req.CustomerName}");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name == req.ProductName);
            if (product == null) return NotFound(_localizer["Api_ProductNotFound"].Value);

            // Si accès scopé, vérifier que le produit demandé correspond au secret utilisé
            if (scopedProductId != null && product.Id != scopedProductId)
                return Unauthorized();

            var type = await _db.LicenseTypes.FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug == req.TypeSlug);
            if (type == null) return BadRequest(string.Format(_localizer["Api_LicenseTypeUnknown"].Value, req.TypeSlug));

            var licenseKey = Guid.NewGuid().ToString("D").ToUpper();
            var license = new License
            {
                ProductId = product.Id,
                LicenseKey = licenseKey,
                CustomerName = req.CustomerName,
                CustomerEmail = req.CustomerEmail,
                LicenseTypeId = type.Id,
                Reference = req.Reference,
                ExpirationDate = req.DaysValidity.HasValue ? DateTime.UtcNow.AddDays(req.DaysValidity.Value) : null
            };

            _db.Licenses.Add(license);

            license.History.Add(new LicenseHistory
            {
                Action = HistoryActions.Created,
                Details = string.Format(_localizer["Licenses_Action_Created"].Value, type.Name, 1),
                PerformedBy = "Admin (API)"
            });

            await _db.SaveChangesAsync();
            return Ok(new { LicenseKey = licenseKey });
        }

        [HttpGet("licenses")]
        public async Task<IActionResult> GetLicenses([FromQuery] string? productName)
        {
            TagLog("LIST_LICENSES", productName ?? "ALL");
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

            IQueryable<License> query = _db.Licenses.Include(l => l.Product).Include(l => l.Type);

            if (scopedProductId != null)
            {
                // Accès scopé : forcer le filtre sur le produit autorisé
                query = query.Where(l => l.ProductId == scopedProductId);
            }
            else if (!string.IsNullOrEmpty(productName))
            {
                query = query.Where(l => l.Product!.Name == productName);
            }

            var list = await query.Select(l => new
            {
                l.Id,
                Product = l.Product != null ? l.Product.Name : "Unknown",
                l.LicenseKey,
                l.CustomerName,
                Type = l.Type != null ? l.Type.Slug : "UNKNOWN",
                l.IsActive,
                l.HardwareId,
                l.ExpirationDate
            }).ToListAsync();

            return Ok(list);
        }

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

        public class RenewLicenseRequest
        {
            public required string TransactionId { get; set; }
            public string? Reference { get; set; }
        }

        [HttpPost("licenses/{licenseKey}/renew")]
        public async Task<IActionResult> RenewLicense(string licenseKey, [FromBody] RenewLicenseRequest req)
        {
            TagLog("RENEW_LICENSE", licenseKey);
            var (authorized, scopedProductId) = await GetAuthContextAsync();
            if (!authorized) return Unauthorized();

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

            var alreadyProcessed = await _db.LicenseRenewals.AnyAsync(r => r.TransactionId == req.TransactionId);
            if (alreadyProcessed)
                return Conflict(_localizer["Api_TransactionUsed"].Value);

            var currentExpiry = license.ExpirationDate ?? DateTime.UtcNow;
            if (currentExpiry < DateTime.UtcNow) currentExpiry = DateTime.UtcNow;

            var daysToAdd = license.Type.DefaultDurationDays;
            license.ExpirationDate = currentExpiry.AddDays(daysToAdd);
            license.IsActive = true;

            if (!string.IsNullOrEmpty(req.Reference))
                license.Reference = req.Reference;

            _db.LicenseRenewals.Add(new LicenseRenewal
            {
                LicenseId = license.Id,
                TransactionId = req.TransactionId,
                DaysAdded = daysToAdd,
                RenewalDate = DateTime.UtcNow
            });

            await _db.SaveChangesAsync();

            return Ok(new {
                license.LicenseKey,
                NewExpirationDate = license.ExpirationDate,
                Reference = license.Reference,
                Message = string.Format(_localizer["Api_Extended"].Value, daysToAdd)
            });
        }
    }
}
