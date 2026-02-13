using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Core;
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

        public AdminController(LicenseDbContext db, IConfiguration config, Services.EncryptionService encryption)
        {
            _db = db;
            _config = config;
            _encryption = encryption;
        }

        private bool IsAuthorized()
        {
            var configuredSecret = _config["AdminSettings:ApiSecret"];
            if (string.IsNullOrEmpty(configuredSecret)) return false;

            if (!Request.Headers.TryGetValue("X-Admin-Secret", out var secret)) return false;
            var secretBytes = Encoding.UTF8.GetBytes(secret.ToString());
            var expectedBytes = Encoding.UTF8.GetBytes(configuredSecret);
            if (!CryptographicOperations.FixedTimeEquals(secretBytes, expectedBytes)) return false;

            var allowedIpsStr = _config["AdminSettings:AllowedIps"];
            if (!string.IsNullOrEmpty(allowedIpsStr))
            {
                var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
                var allowedIps = allowedIpsStr.Split(',').Select(ip => ip.Trim()).ToList();
                if (!allowedIps.Contains(clientIp) && clientIp != "127.0.0.1" && clientIp != "::1") return false;
            }
            return true;
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
            if (!IsAuthorized()) return Unauthorized();
            if (string.IsNullOrWhiteSpace(name)) return BadRequest("Nom requis");
            if (await _db.Products.AnyAsync(p => p.Name == name)) return BadRequest("Existe déjà");

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
            if (!IsAuthorized()) return Unauthorized();
            return Ok(await _db.Products.Select(p => new { p.Id, p.Name }).ToListAsync());
        }

        public class CreateLicenseRequest
        {
            public required string ProductName { get; set; }
            public required string CustomerName { get; set; }
            public string CustomerEmail { get; set; } = "";
            public required string TypeSlug { get; set; } // Changé en string
            public int? DaysValidity { get; set; }
            public string? Reference { get; set; }
        }

        [HttpPost("licenses")]
        public async Task<IActionResult> CreateLicense([FromBody] CreateLicenseRequest req)
        {
            TagLog("CREATE_LICENSE", $"{req.ProductName} -> {req.CustomerName}");
            if (!IsAuthorized()) return Unauthorized();

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name == req.ProductName);
            if (product == null) return NotFound("Produit introuvable");

            var type = await _db.LicenseTypes.FirstOrDefaultAsync(t => t.Slug == req.TypeSlug);
            if (type == null) return BadRequest($"Type de licence '{req.TypeSlug}' inconnu.");

            var licenseKey = Guid.NewGuid().ToString("D").ToUpper();
            var license = new License
            {
                ProductId = product.Id,
                LicenseKey = licenseKey,
                CustomerName = req.CustomerName,
                CustomerEmail = req.CustomerEmail,
                LicenseTypeId = type.Id, // Lien avec le type dynamique
                Reference = req.Reference,
                ExpirationDate = req.DaysValidity.HasValue ? DateTime.UtcNow.AddDays(req.DaysValidity.Value) : null
            };

            _db.Licenses.Add(license);
            await _db.SaveChangesAsync();
            return Ok(new { LicenseKey = licenseKey });
        }

        [HttpGet("licenses")]
        public async Task<IActionResult> GetLicenses([FromQuery] string? productName)
        {
            TagLog("LIST_LICENSES", productName ?? "ALL");
            if (!IsAuthorized()) return Unauthorized();

            IQueryable<License> query = _db.Licenses.Include(l => l.Product).Include(l => l.Type);
            if (!string.IsNullOrEmpty(productName)) query = query.Where(l => l.Product!.Name == productName);

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

        public class RenewLicenseRequest
        {
            public required string TransactionId { get; set; }
            public string? Reference { get; set; }
        }

        [HttpPost("licenses/{licenseKey}/renew")]
        public async Task<IActionResult> RenewLicense(string licenseKey, [FromBody] RenewLicenseRequest req)
        {
            TagLog("RENEW_LICENSE", licenseKey);
            if (!IsAuthorized()) return Unauthorized();

            var license = await _db.Licenses
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey);

            if (license == null) return NotFound("Licence introuvable");
            if (license.Type == null) return BadRequest("Type de licence inconnu.");

            // Sécurité 1 : Vérifier si le type autorise le renouvellement
            if (!license.Type.IsRecurring)
            {
                return BadRequest("Ce type de licence n'autorise pas le renouvellement automatique (Mode FIXE).");
            }

            // Sécurité 2 : Vérifier si la transaction a déjà été traitée
            var alreadyProcessed = await _db.LicenseRenewals.AnyAsync(r => r.TransactionId == req.TransactionId);
            if (alreadyProcessed)
            {
                return Conflict("Cette transaction a déjà été utilisée pour un renouvellement.");
            }

            // On prolonge de la durée par défaut du type de licence
            var currentExpiry = license.ExpirationDate ?? DateTime.UtcNow;
            if (currentExpiry < DateTime.UtcNow) currentExpiry = DateTime.UtcNow;

            var daysToAdd = license.Type.DefaultDurationDays;
            license.ExpirationDate = currentExpiry.AddDays(daysToAdd);
            license.IsActive = true; 
            
            if (!string.IsNullOrEmpty(req.Reference))
            {
                license.Reference = req.Reference;
            }

            // Enregistrement de la transaction
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
                Message = $"Licence prolongée de {daysToAdd} jours." 
            });
        }
    }
}
