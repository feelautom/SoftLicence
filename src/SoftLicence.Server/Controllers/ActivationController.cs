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
        private readonly LicenseDbContext _db;
        private readonly ILogger<ActivationController> _logger;
        private readonly Services.EncryptionService _encryption;
        private readonly Services.EmailService _mailer;
        private readonly Services.TelemetryService _telemetry;
        private readonly Services.GeoIpService _geoIp;
        private readonly IConfiguration _config;
        private readonly IStringLocalizer<SharedResource> _localizer;

        public ActivationController(
            LicenseDbContext db, 
            ILogger<ActivationController> logger, 
            Services.EncryptionService encryption,
            Services.EmailService mailer,
            Services.TelemetryService telemetry,
            Services.GeoIpService geoIp,
            IConfiguration config,
            IStringLocalizer<SharedResource> localizer)
        {
            _db = db;
            _logger = logger;
            _encryption = encryption;
            _mailer = mailer;
            _telemetry = telemetry;
            _geoIp = geoIp;
            _config = config;
            _localizer = localizer;
        }

        public class ActivationRequest
        {
            public required string LicenseKey { get; set; }
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppVersion { get; set; } // Nouvelle version client
        }

        public class TrialRequest
        {
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public required string TypeSlug { get; set; } // ex: "TRIAL"
            public string? AppVersion { get; set; }
        }

        private void TagLog(ActivationRequest req, string endpoint)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey.Trim().ToUpper();
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = endpoint;
            HttpContext.Items[LogKeys.Version] = req.AppVersion ?? "Unknown";
        }

        private void TagLog(TrialRequest req, string endpoint)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = "AUTO-TRIAL";
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = endpoint;
            HttpContext.Items[LogKeys.Version] = req.AppVersion ?? "Unknown";
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

        [HttpPost("trial")]
        public async Task<IActionResult> GetTrial([FromBody] TrialRequest req)
        {
            TagLog(req, "TRIAL_AUTO");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest($"Application '{req.AppName}' inconnue.");

            var type = await _db.LicenseTypes.FirstOrDefaultAsync(t => t.Slug.ToUpper() == req.TypeSlug.Trim().ToUpper());
            if (type == null) return BadRequest($"Type de licence '{req.TypeSlug}' inconnu.");

            // Vérifier si ce PC a déjà une licence pour ce produit (Trial ou autre)
            var existing = await _db.Licenses
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.ProductId == product.Id && l.HardwareId == req.HardwareId);

            if (existing != null)
            {
                // Si une licence existe déjà pour ce matériel, on la renvoie simplement (comme un Recovery)
                if (!existing.IsActive) return BadRequest(_localizer["Api_AccessRevoked"].Value);
                
                // S'assurer que le siège existe
                var seat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == existing.Id && s.HardwareId == req.HardwareId);
                if (seat == null)
                {
                    _db.LicenseSeats.Add(new LicenseSeat {
                        LicenseId = existing.Id, HardwareId = req.HardwareId,
                        FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();
                }

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
                    HardwareId = existing.HardwareId ?? string.Empty
                };

                try
                {
                    var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                    if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    var signed = LicenseService.GenerateLicense(model, decryptedKey);
                    _logger.LogInformation("Trial Recovery : Renvoi de la licence existante pour {HardwareId}", req.HardwareId);
                    return Ok(new { LicenseFile = signed });
                }
                catch (Exception ex)
                {
                    return StatusCode(500, $"Erreur de signature : {ex.Message}");
                }
            }

            // Sinon, création d'une nouvelle licence Trial
            var newKey = Guid.NewGuid().ToString("D").ToUpper();
            var license = new License
            {
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                LicenseKey = newKey,
                CustomerName = "Auto Trial",
                CustomerEmail = "trial@auto.local",
                HardwareId = req.HardwareId,
                ActivationDate = DateTime.UtcNow,
                CreationDate = DateTime.UtcNow,
                ExpirationDate = DateTime.UtcNow.AddDays(type.DefaultDurationDays),
                IsActive = true
            };

            _db.Licenses.Add(license);
            await _db.SaveChangesAsync();

            // Création du siège initial pour le multi-postes
            var firstSeat = new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = req.HardwareId,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow
            };
            _db.LicenseSeats.Add(firstSeat);
            await _db.SaveChangesAsync();

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
                HardwareId = license.HardwareId ?? string.Empty
            };

            try
            {
                var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                var signedLicenseString = LicenseService.GenerateLicense(licenseModel, decryptedKey);
                return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Erreur de signature : {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Activate([FromBody] ActivationRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, "ACTIVATE");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) 
            {
                _logger.LogWarning("Activation echouee : Application '{AppName}' inconnue.", req.AppName);
                return BadRequest($"Application '{req.AppName}' inconnue.");
            }

            // --- INTERCEPTION AUTO-TRIAL ---
            if (cleanKey.EndsWith("-FREE-TRIAL") || cleanKey == "FREE-TRIAL")
            {
                _logger.LogInformation("Detection d'une demande AUTO-TRIAL pour {AppName}", product.Name);
                HttpContext.Items[LogKeys.Endpoint] = "TRIAL_AUTO";
                
                // On cherche d'abord une correspondance exacte du Slug avec la clé
                // Sinon on cherche un type TRIAL
                var type = await _db.LicenseTypes.FirstOrDefaultAsync(t => t.Slug == cleanKey)
                           ?? await _db.LicenseTypes.FirstOrDefaultAsync(t => t.Slug == "TRIAL") 
                           ?? await _db.LicenseTypes.FirstOrDefaultAsync(t => t.Slug.Contains("TRIAL"));

                if (type == null) 
                {
                    _logger.LogWarning("Demande Trial echouee : Aucun type de licence 'TRIAL' n'est configure.");
                    return BadRequest(_localizer["Api_TrialNotEnabled"].Value);
                }

                // On vérifie si ce PC a déjà une licence pour ce produit
                var existing = await _db.Licenses
                    .Include(l => l.Type)
                    .FirstOrDefaultAsync(l => l.ProductId == product.Id && l.HardwareId == req.HardwareId);

                if (existing != null)
                {
                    if (!existing.IsActive) return BadRequest(_localizer["Api_AccessRevoked"].Value);
                    
                    // S'assurer que le siège existe (pour les licences créées avant le système de seats)
                    var seat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == existing.Id && s.HardwareId == req.HardwareId);
                    if (seat == null)
                    {
                        _db.LicenseSeats.Add(new LicenseSeat {
                            LicenseId = existing.Id, HardwareId = req.HardwareId,
                            FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow
                        });
                        await _db.SaveChangesAsync();
                    }
                    else {
                        seat.LastCheckInAt = DateTime.UtcNow;
                        await _db.SaveChangesAsync();
                    }

                    // On met à jour le log avec la vraie clé trouvée
                    HttpContext.Items[LogKeys.LicenseKey] = existing.LicenseKey;

                    var recoveryModel = new LicenseModel {
                        Id = existing.Id, LicenseKey = existing.LicenseKey, CustomerName = existing.CustomerName,
                        CustomerEmail = existing.CustomerEmail, TypeSlug = existing.Type?.Slug ?? "TRIAL",
                        Reference = existing.Reference,
                        CreationDate = existing.CreationDate, ExpirationDate = existing.ExpirationDate, HardwareId = existing.HardwareId ?? string.Empty
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
                        return StatusCode(500, $"Erreur de signature : {ex.Message}");
                    }
                }

                // Création auto
                var newKey = Guid.NewGuid().ToString("D").ToUpper();
                var newLic = new License {
                    ProductId = product.Id, LicenseTypeId = type.Id, LicenseKey = newKey,
                    CustomerName = "Auto Trial", CustomerEmail = "trial@auto.local",
                    HardwareId = req.HardwareId, ActivationDate = DateTime.UtcNow, CreationDate = DateTime.UtcNow,
                    ExpirationDate = DateTime.UtcNow.AddDays(type.DefaultDurationDays), IsActive = true
                };
                _db.Licenses.Add(newLic);
                await _db.SaveChangesAsync();

                // Création du siège initial pour le multi-postes
                var firstSeat = new LicenseSeat
                {
                    LicenseId = newLic.Id,
                    HardwareId = req.HardwareId,
                    FirstActivatedAt = DateTime.UtcNow,
                    LastCheckInAt = DateTime.UtcNow
                };
                _db.LicenseSeats.Add(firstSeat);
                await _db.SaveChangesAsync();

                // On met à jour le log avec la clé générée
                HttpContext.Items[LogKeys.LicenseKey] = newKey;

                var newModel = new LicenseModel {
                    Id = newLic.Id, LicenseKey = newLic.LicenseKey, CustomerName = newLic.CustomerName,
                    CustomerEmail = newLic.CustomerEmail, TypeSlug = type.Slug,
                    Reference = newLic.Reference,
                    CreationDate = newLic.CreationDate, ExpirationDate = newLic.ExpirationDate, HardwareId = newLic.HardwareId ?? string.Empty
                };

                try
                {
                    var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                    if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    return Ok(new { LicenseFile = LicenseService.GenerateLicense(newModel, decryptedKey) });
                }
                catch (Exception ex)
                {
                    return StatusCode(500, $"Erreur de signature : {ex.Message}");
                }
            }
            // --- FIN INTERCEPTION ---

            var license = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);

            if (license == null) 
            {
                _logger.LogWarning("Activation echouee : Cle '{LicenseKey}' non trouvee pour le produit '{ProductName}' (ID: {ProductId}).", cleanKey, product.Name, product.Id);
                return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            }
            
            if (!license.IsActive) 
            {
                _logger.LogWarning("Activation echouee : Cle '{LicenseKey}' revoquee.", cleanKey);
                return BadRequest(_localizer["Api_LicenseDisabled"].Value);
            }
            
            if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value)
            {
                _logger.LogWarning("Activation echouee : Cle '{LicenseKey}' expiree ({Expiry}).", cleanKey, license.ExpirationDate);
                return BadRequest(_localizer["Api_LicenseExpired"].Value);
            }

            // Vérification de version
            if (!IsVersionAllowed(req.AppVersion, license.AllowedVersions))
            {
                _logger.LogWarning("Activation echouee : Version '{Version}' non autorisee pour la cle '{LicenseKey}' (Attendu: '{Allowed}')", req.AppVersion, cleanKey, license.AllowedVersions);
                return BadRequest($"Cette licence n'est pas valide pour la version {req.AppVersion} du logiciel.");
            }

            // --- GESTION MULTI-POSTES (SEATS) ---
            var existingSeat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == license.Id && s.HardwareId == req.HardwareId);
            
            if (existingSeat != null)
            {
                // Poste déjà connu : On met à jour la date de passage
                existingSeat.LastCheckInAt = DateTime.UtcNow;
                license.RecoveryCount++;
                TagLog(req, "RECOVERY");
                _logger.LogInformation("Recovery reussi (Multi-Seat) : Cle '{LicenseKey}' sur HWID '{HardwareId}'", cleanKey, req.HardwareId);
            }
            else
            {
                // Nouveau poste : On vérifie si on a encore de la place
                var currentSeatsCount = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id);
                
                if (currentSeatsCount >= license.MaxSeats)
                {
                    _logger.LogWarning("Activation echouee : Limite de postes atteinte ({Max}) pour la clé '{LicenseKey}'", license.MaxSeats, cleanKey);
                    return BadRequest(string.Format(_localizer["Api_MaxActivationsReached"].Value, license.MaxSeats));
                }

                // On crée le nouveau siège
                var newSeat = new LicenseSeat
                {
                    LicenseId = license.Id,
                    HardwareId = req.HardwareId,
                    FirstActivatedAt = DateTime.UtcNow,
                    LastCheckInAt = DateTime.UtcNow
                };
                _db.LicenseSeats.Add(newSeat);
                
                // Pour la compatibilité v1, on met à jour le HardwareId principal si c'est le premier poste
                if (string.IsNullOrEmpty(license.HardwareId))
                {
                    license.HardwareId = req.HardwareId;
                    license.ActivationDate = DateTime.UtcNow;
                }

                _logger.LogInformation("Nouveau poste active ({Count}/{Max}) : Cle '{LicenseKey}' sur HWID '{HardwareId}'", currentSeatsCount + 1, license.MaxSeats, cleanKey, req.HardwareId);
            }

            await _db.SaveChangesAsync();

            // Génération du fichier signé
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
                HardwareId = license.HardwareId ?? string.Empty
            };

            try
            {
                var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                if (decryptedKey == "ERROR_DECRYPTION_FAILED")
                {
                    _logger.LogError("ERREUR CRITIQUE : Impossible de dechiffrer la cle privee du produit '{ProductName}'. Les cles de DataProtection sont peut-etre manquantes ou invalides.", product.Name);
                    return StatusCode(500, _localizer["Api_InternalErrorServerKey"].Value);
                }

                var signedLicenseString = LicenseService.GenerateLicense(licenseModel, decryptedKey);
                return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la signature de la licence pour '{AppName}'", req.AppName);
                return StatusCode(500, $"Erreur de signature : {ex.Message}");
            }
        }

        [HttpPost("check")]
        public async Task<IActionResult> CheckStatus([FromBody] ActivationRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, "CHECK");

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return NotFound("App unknown");

            var license = await _db.Licenses
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);

            if (license == null) return NotFound("License not found");

            string status = "VALID";
            if (!license.IsActive) status = "REVOKED";
            else if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value) status = "EXPIRED";
            else if (string.IsNullOrEmpty(license.HardwareId)) status = "REQUIRES_ACTIVATION";
            else if (license.HardwareId != req.HardwareId) status = "HARDWARE_MISMATCH";

            return Ok(new { Status = status });
        }

        public class ResetRequest
        {
            public required string LicenseKey { get; set; }
            public required string AppName { get; set; }
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
            if (product == null) return BadRequest("Application inconnue.");

            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var license = await _db.Licenses.FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);
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
            catch (Exception)
            {
                return StatusCode(500, "Erreur lors de l'envoi de l'email.");
            }
        }

        [HttpPost("reset-confirm")]
        public async Task<IActionResult> ConfirmReset([FromBody] ResetConfirmRequest req)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey;
            HttpContext.Items[LogKeys.Endpoint] = "RESET_CONFIRM";

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest("Application inconnue.");

            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var license = await _db.Licenses.FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);
            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);

            if (license.ResetCode == null || license.ResetCode != req.ResetCode || license.ResetCodeExpiry < DateTime.UtcNow)
            {
                return BadRequest(_localizer["Api_InvalidResetCode"].Value);
            }

            // Reset effectif
            license.HardwareId = null;
            license.ActivationDate = null;
            license.ResetCode = null; // Usage unique
            license.ResetCodeExpiry = null;
            license.RecoveryCount = 0; // On reset le compteur d'abus

            if (license.Seats != null) _db.LicenseSeats.RemoveRange(license.Seats);

            await _db.SaveChangesAsync();

            return Ok(new { Message = _localizer["Api_UnlinkSuccess"].Value });
        }
    }
}