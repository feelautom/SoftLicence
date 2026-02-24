using System.Security.Cryptography;
using System.Text;
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
            public string? AppId { get; set; } // Identifiant unique du produit
            public string? AppVersion { get; set; } // Nouvelle version client
            public string? CustomerEmail { get; set; }
            public string? CustomerName { get; set; }
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

        private static Dictionary<string, string> BuildFeatures(IEnumerable<LicenseTypeCustomParam>? customParams)
        {
            if (customParams == null) return new Dictionary<string, string>();
            return customParams.ToDictionary(p => p.Key, p => p.Value);
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
                .Where(l => l.ProductId == product.Id && l.HardwareId == req.HardwareId)
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

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) 
            {
                _logger.LogWarning("Activation echouee : Application '{AppName}' inconnue.", req.AppName);
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            // --- INTERCEPTION AUTO-TRIAL ---
            if (cleanKey.EndsWith("-FREE-TRIAL") || cleanKey == "FREE-TRIAL")
            {
                _logger.LogInformation("Detection d'une demande AUTO-TRIAL pour {AppName}", product.Name);
                HttpContext.Items[LogKeys.Endpoint] = "TRIAL_AUTO";
                
                // On cherche d'abord une correspondance exacte du Slug avec la clé, sinon le slug "TRIAL" — toujours filtré par produit
                var type = await _db.LicenseTypes.Include(t => t.CustomParams).FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug == cleanKey)
                           ?? await _db.LicenseTypes.Include(t => t.CustomParams).FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug == "TRIAL");

                if (type == null) 
                {
                    _logger.LogWarning("Demande Trial echouee : Aucun type de licence 'TRIAL' n'est configure.");
                    return BadRequest(_localizer["Api_TrialNotEnabled"].Value);
                }

                // On vérifie si ce PC a déjà une licence pour ce produit
                var existing = await _db.Licenses
                    .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                    .FirstOrDefaultAsync(l => l.ProductId == product.Id && l.HardwareId == req.HardwareId);

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
                        await _db.SaveChangesAsync();
                    }
                    else {
                        seat.LastCheckInAt = DateTime.UtcNow;
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

                await _db.SaveChangesAsync();

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

            var license = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
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
                return BadRequest(string.Format(_localizer["Api_VersionNotAllowed"].Value, req.AppVersion));
            }

            // --- GESTION MULTI-POSTES (SEATS) ---
            var existingSeat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == license.Id && s.HardwareId == req.HardwareId && s.IsActive);
            
            if (existingSeat != null)
            {
                // Poste déjà connu : On met à jour la date de passage
                existingSeat.LastCheckInAt = DateTime.UtcNow;
                license.RecoveryCount++;
                TagLog(req, "RECOVERY");
                _logger.LogInformation("Recovery reussi (Multi-Seat) : Cle '{LicenseKey}' sur HWID '{HardwareId}'", cleanKey, req.HardwareId);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Recovery,
                    Details = string.Format(_localizer["Licenses_Action_Activated"].Value, req.HardwareId, req.AppVersion ?? "Unknown"),
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }
            else
            {
                // Nouveau poste : On vérifie si on a encore de la place
                var currentSeatsCount = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id && s.IsActive);
                
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
                    LastCheckInAt = DateTime.UtcNow,
                    IsActive = true
                };
                _db.LicenseSeats.Add(newSeat);
                
                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Activated,
                    Details = string.Format(_localizer["Licenses_Action_Activated"].Value, req.HardwareId, req.AppVersion ?? "Unknown"),
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });

                // Pour la compatibilité v1, on met à jour le HardwareId principal si c'est le premier poste
                if (string.IsNullOrEmpty(license.HardwareId))
                {
                    license.HardwareId = req.HardwareId;
                    license.ActivationDate = DateTime.UtcNow;
                }

                _logger.LogInformation("Nouveau poste active ({Count}/{Max}) : Cle '{LicenseKey}' sur HWID '{HardwareId}'", currentSeatsCount + 1, license.MaxSeats, cleanKey, req.HardwareId);
            }

            // Mise à jour des infos client si fournies par le client WPF
            if (!string.IsNullOrWhiteSpace(req.CustomerEmail))
                license.CustomerEmail = req.CustomerEmail;
            if (!string.IsNullOrWhiteSpace(req.CustomerName))
                license.CustomerName = req.CustomerName;

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
                HardwareId = license.HardwareId ?? string.Empty,
                Features = BuildFeatures(license.Type?.CustomParams)
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
            
            var license = await _db.Licenses
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);

            if (license == null) return NotFound(_localizer["Api_LicenseNotFound"].Value);

            string status = "VALID";
            if (!license.IsActive) status = "REVOKED";
            else if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value) status = "EXPIRED";
            else
            {
                // Vérifier via les seats (multi-postes) au lieu du champ legacy HardwareId
                var hasAnySeat = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.IsActive);
                if (!hasAnySeat && string.IsNullOrEmpty(license.HardwareId))
                    status = "REQUIRES_ACTIVATION";
                else
                {
                    var hasSeatForHwid = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.HardwareId == req.HardwareId && s.IsActive);
                    if (!hasSeatForHwid && license.HardwareId != req.HardwareId)
                        status = "HARDWARE_MISMATCH";
                }
            }

            return Ok(new { Status = status });
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
            
            var cleanKey = req.LicenseKey.Trim().ToUpper();            var license = await _db.Licenses.FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);
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
            
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var license = await _db.Licenses
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);
            
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
                        Details = string.Format(_localizer["Licenses_Action_UnlinkedApi"].Value, seat.HardwareId),
                        PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                    });
                }
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
        }

        [HttpPost("deactivate")]
        public async Task<IActionResult> Deactivate([FromBody] DeactivateRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = cleanKey;
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = "DEACTIVATE";

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            HttpContext.Items[LogKeys.AppName] = product.Name;

            var license = await _db.Licenses
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && l.ProductId == product.Id);

            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);

            var seat = license.Seats?.FirstOrDefault(s => s.HardwareId == req.HardwareId && s.IsActive);
            if (seat == null) return NotFound("Appareil non trouvé ou déjà délié.");

            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.UnlinkedApi,
                Details = string.Format(_localizer["Licenses_Action_UnlinkedApi"].Value, req.HardwareId),
                PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });

            await _db.SaveChangesAsync();

            return Ok(new { Message = _localizer["Api_UnlinkSuccess"].Value });
        }
    }
}