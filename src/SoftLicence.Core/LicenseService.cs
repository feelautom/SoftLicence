using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SoftLicence.Core
{
    public class LicenseService
    {
        // Génère une paire de clés RSA (4096 bits)
        // Retourne { PrivateKeyXml, PublicKeyXml }
        public static (string PrivateKey, string PublicKey) GenerateKeys()
        {
            using var rsa = RSA.Create(4096);
            return (rsa.ToXmlString(true), rsa.ToXmlString(false));
        }

        // Crée une chaîne de licence signée
        public static string GenerateLicense(LicenseModel model, string privateKeyXml)
        {
            // 1. On nettoie la signature existante pour signer le contenu
            model.Signature = string.Empty;
            
            // 2. Sérialisation
            var json = JsonSerializer.Serialize(model);
            var dataBytes = Encoding.UTF8.GetBytes(json);

            // 3. Signature
            using var rsa = RSA.Create();
            rsa.FromXmlString(privateKeyXml);
            var signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            
            // 4. On réinjecte la signature dans le modèle
            model.Signature = Convert.ToBase64String(signatureBytes);

            // 5. On retourne le tout encodé en Base64 pour faciliter le transport (copier-coller)
            var finalJson = JsonSerializer.Serialize(model);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(finalJson));
        }

        // Valide une licence
        public static (bool IsValid, LicenseModel? License, string ErrorMessage) ValidateLicense(string licenseString, string publicKeyXml, string? currentHardwareId = null)
        {
            try
            {
                // 1. Décodage Base64
                var jsonBytes = Convert.FromBase64String(licenseString);
                var json = Encoding.UTF8.GetString(jsonBytes);
                var model = JsonSerializer.Deserialize<LicenseModel>(json);

                if (model == null) return (false, null, "Format de licence invalide.");

                // 2. Extraction de la signature
                var signatureToCheck = model.Signature;
                if (string.IsNullOrEmpty(signatureToCheck)) return (false, null, "Licence non signée.");

                // 3. Préparation des données à vérifier (On remet la signature à vide comme lors de la génération)
                model.Signature = string.Empty;
                var dataToVerify = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(model));
                
                // 4. Remettre la signature dans l'objet retourné (pour l'affichage ou sauvegarde)
                model.Signature = signatureToCheck;

                // 5. Vérification RSA
                using var rsa = RSA.Create();
                rsa.FromXmlString(publicKeyXml);
                
                var signatureBytes = Convert.FromBase64String(signatureToCheck);
                bool isSignatureValid = rsa.VerifyData(dataToVerify, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                if (!isSignatureValid) return (false, null, "Signature invalide. La licence a été altérée.");

                // 6. Vérification Expiration
                if (model.IsExpired) return (false, model, "Licence expirée.");

                // 7. Vérification Hardware (si la licence l'exige)
                if (!string.IsNullOrEmpty(model.HardwareId) && !string.IsNullOrEmpty(currentHardwareId))
                {
                    if (model.HardwareId != currentHardwareId)
                    {
                        return (false, model, "Cette licence n'est pas valide pour cette machine.");
                    }
                }

                return (true, model, "Licence valide.");
            }
            catch (Exception ex)
            {
                return (false, null, $"Erreur de validation : {ex.Message}");
            }
        }

        public static async Task<string> CheckOnlineStatusAsync(HttpClient client, string serverUrl, string appName, string licenseKey, string hardwareId)
        {
            try
            {
                var payload = new
                {
                    LicenseKey = licenseKey,
                    HardwareId = hardwareId,
                    AppName = appName
                };

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                // Ensure no trailing slash issues
                var url = serverUrl.TrimEnd('/') + "/api/activation/check";
                
                var response = await client.PostAsync(url, content);

                if (!response.IsSuccessStatusCode) return "SERVER_ERROR";

                var json = await response.Content.ReadAsStringAsync();
                
                using (var doc = JsonDocument.Parse(json))
                {
                    // Recherche de la propriété "Status" ou "status"
                    if (doc.RootElement.TryGetProperty("status", out var prop) || 
                        doc.RootElement.TryGetProperty("Status", out prop))
                    {
                        return prop.GetString() ?? "UNKNOWN";
                    }
                }

                return "UNKNOWN_RESPONSE";
            }
            catch
            {
                return "NETWORK_ERROR";
            }
        }
    }
}
