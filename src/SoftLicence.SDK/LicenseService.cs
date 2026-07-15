using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SoftLicence.SDK
{
    public class LicenseService
    {
        private const string ReservedSignatureFeatureKey = "Signature";
        private const string SignedExpirationSnapshotProperty = "IsExpired";

        // Génère une paire de clés RSA (4096 bits)
        // Retourne { PrivateKeyXml, PublicKeyXml }
        public static (string PrivateKey, string PublicKey) GenerateKeys()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 4096;
            return (rsa.ToXmlString(true), rsa.ToXmlString(false));
        }

        /// <summary>
        /// Crée une chaîne de licence signée.
        /// </summary>
        /// <remarks>
        /// La clé de feature <c>Signature</c> est réservée au contrat cryptographique racine
        /// et ne peut pas être utilisée dans <see cref="LicenseModel.Features"/>.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        /// Levée lorsque les features contiennent la clé réservée <c>Signature</c>.
        /// </exception>
        public static string GenerateLicense(LicenseModel model, string privateKeyXml)
        {
            if (model.Features?.Keys.Any(key => string.Equals(key, ReservedSignatureFeatureKey, StringComparison.Ordinal)) == true)
            {
                throw new InvalidOperationException("La clé de feature 'Signature' est réservée au contrat de licence signé.");
            }

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
            var finalJson = BuildFinalLicenseJson(json, model.Signature);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(finalJson));
        }

        private static string BuildFinalLicenseJson(string signedJsonWithEmptySignature, string signature)
        {
            var signedJsonBytes = Encoding.UTF8.GetBytes(signedJsonWithEmptySignature);
            var reader = new Utf8JsonReader(signedJsonBytes);
            long signatureTokenStart = -1;
            long signatureTokenEnd = -1;

            while (reader.Read())
            {
                if (reader.TokenType != JsonTokenType.PropertyName ||
                    reader.CurrentDepth != 1 ||
                    !reader.ValueTextEquals(ReservedSignatureFeatureKey))
                {
                    continue;
                }

                if (signatureTokenStart >= 0 ||
                    !reader.Read() ||
                    reader.TokenType != JsonTokenType.String ||
                    reader.CurrentDepth != 1 ||
                    !string.IsNullOrEmpty(reader.GetString()))
                {
                    throw new InvalidOperationException("Le contrat JSON de licence contient un champ Signature racine invalide.");
                }

                signatureTokenStart = reader.TokenStartIndex;
                signatureTokenEnd = reader.BytesConsumed;
            }

            if (signatureTokenStart < 0 || signatureTokenEnd <= signatureTokenStart)
            {
                throw new InvalidOperationException("Le contrat JSON de licence ne contient pas le champ Signature racine attendu.");
            }

            var signatureBytes = Encoding.UTF8.GetBytes(signature);
            var prefixLength = checked((int)signatureTokenStart + 1);
            var suffixOffset = checked((int)signatureTokenEnd - 1);
            var finalJsonBytes = new byte[prefixLength + signatureBytes.Length + signedJsonBytes.Length - suffixOffset];

            Buffer.BlockCopy(signedJsonBytes, 0, finalJsonBytes, 0, prefixLength);
            Buffer.BlockCopy(signatureBytes, 0, finalJsonBytes, prefixLength, signatureBytes.Length);
            Buffer.BlockCopy(
                signedJsonBytes,
                suffixOffset,
                finalJsonBytes,
                prefixLength + signatureBytes.Length,
                signedJsonBytes.Length - suffixOffset);

            return Encoding.UTF8.GetString(finalJsonBytes);
        }

        /// <summary>
        /// Valide une licence signée en conservant le contrat tuple historique.
        /// </summary>
        /// <param name="licenseString">Contenu de licence encodé en Base64.</param>
        /// <param name="publicKeyXml">Clé publique RSA utilisée pour vérifier la signature.</param>
        /// <param name="currentHardwareId">
        /// HWID contractuel courant. Il peut être omis uniquement lorsque le HWID signé de la licence
        /// est null ou vide. Une licence hardware-bound est rejetée si cette valeur manque ou est blanche.
        /// </param>
        public static (bool IsValid, LicenseModel? License, string ErrorMessage) ValidateLicense(string licenseString, string publicKeyXml, string? currentHardwareId = null)
        {
            var result = ValidateLicenseDetailed(licenseString, publicKeyXml, currentHardwareId);
            return (result.IsValid, result.License, result.ErrorMessage);
        }

        /// <summary>
        /// Valide une licence signée et retourne un code d'erreur stable et typé.
        /// </summary>
        /// <remarks>
        /// Un HWID signé null ou vide désigne une licence volontairement non liée au matériel.
        /// Un HWID signé composé uniquement d'espaces est un contrat invalide. Le HWID V2/stable
        /// est un signal d'observation et ne constitue jamais une identité de validation alternative.
        /// </remarks>
        public static LicenseValidationResult ValidateLicenseDetailed(
            string licenseString,
            string publicKeyXml,
            string? currentHardwareId = null)
        {
            return ValidateLicenseDetailed(licenseString, publicKeyXml, currentHardwareId, DateTime.UtcNow);
        }

        internal static LicenseValidationResult ValidateLicenseDetailed(
            string licenseString,
            string publicKeyXml,
            string? currentHardwareId,
            DateTime utcNow)
        {
            try
            {
                // 1. Décodage Base64
                LicenseModel? model;
                bool signedExpirationSnapshot;
                try
                {
                    var jsonBytes = Convert.FromBase64String(licenseString);
                    signedExpirationSnapshot = ReadSignedExpirationSnapshot(jsonBytes);
                    var json = Encoding.UTF8.GetString(jsonBytes);
                    model = JsonSerializer.Deserialize<LicenseModel>(json);
                }
                catch (Exception ex) when (ex is FormatException || ex is JsonException)
                {
                    return LicenseValidationResult.Invalid(
                        LicenseValidationErrorCode.InvalidFormat,
                        "Format de licence invalide.");
                }

                if (model == null)
                {
                    return LicenseValidationResult.Invalid(
                        LicenseValidationErrorCode.InvalidFormat,
                        "Format de licence invalide.");
                }

                // 2. Extraction de la signature
                var signatureToCheck = model.Signature;
                if (string.IsNullOrEmpty(signatureToCheck))
                {
                    return LicenseValidationResult.Invalid(
                        LicenseValidationErrorCode.Unsigned,
                        "Licence non signée.");
                }

                // 3. Préparation des données à vérifier (On remet la signature à vide comme lors de la génération)
                model.Signature = string.Empty;
                var serializedModel = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(model));
                var dataToVerify = RestoreSignedExpirationSnapshot(serializedModel, signedExpirationSnapshot);
                
                // 4. Remettre la signature dans l'objet retourné (pour l'affichage ou sauvegarde)
                model.Signature = signatureToCheck;

                // 5. Vérification RSA
                using var rsa = RSA.Create();
                rsa.FromXmlString(publicKeyXml);
                
                byte[] signatureBytes;
                try
                {
                    signatureBytes = Convert.FromBase64String(signatureToCheck);
                }
                catch (FormatException)
                {
                    return LicenseValidationResult.Invalid(
                        LicenseValidationErrorCode.InvalidSignature,
                        "Signature invalide. La licence a été altérée.");
                }

                bool isSignatureValid = rsa.VerifyData(dataToVerify, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                if (!isSignatureValid)
                {
                    return LicenseValidationResult.Invalid(
                        LicenseValidationErrorCode.InvalidSignature,
                        "Signature invalide. La licence a été altérée.");
                }

                // 6. Vérification Expiration
                if (model.ExpirationDate.HasValue && utcNow > model.ExpirationDate.Value)
                {
                    return LicenseValidationResult.Invalid(
                        LicenseValidationErrorCode.Expired,
                        "Licence expirée.",
                        model);
                }

                // 7. Vérification Hardware (si la licence l'exige)
                if (!string.IsNullOrEmpty(model.HardwareId))
                {
                    if (string.IsNullOrWhiteSpace(model.HardwareId))
                    {
                        return LicenseValidationResult.Invalid(
                            LicenseValidationErrorCode.InvalidHardwareBinding,
                            "Le hardware ID signé de la licence est invalide.",
                            model);
                    }

                    if (string.IsNullOrWhiteSpace(currentHardwareId))
                    {
                        return LicenseValidationResult.Invalid(
                            LicenseValidationErrorCode.HardwareIdRequired,
                            "Un hardware ID courant est requis pour valider cette licence.",
                            model);
                    }

                    if (!string.Equals(model.HardwareId, currentHardwareId, StringComparison.Ordinal))
                    {
                        return LicenseValidationResult.Invalid(
                            LicenseValidationErrorCode.HardwareIdMismatch,
                            "Cette licence n'est pas valide pour cette machine.",
                            model);
                    }
                }

                return LicenseValidationResult.Valid(model);
            }
            catch
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationErrorCode.ValidationError,
                    "Erreur de validation.");
            }
        }

        private static bool ReadSignedExpirationSnapshot(byte[] jsonBytes)
        {
            var reader = new Utf8JsonReader(jsonBytes);
            bool? snapshot = null;

            while (reader.Read())
            {
                if (reader.TokenType != JsonTokenType.PropertyName ||
                    reader.CurrentDepth != 1 ||
                    !reader.ValueTextEquals(SignedExpirationSnapshotProperty))
                {
                    continue;
                }

                if (snapshot.HasValue || !reader.Read() || reader.CurrentDepth != 1)
                {
                    throw new JsonException("Le contrat JSON de licence contient un champ IsExpired racine invalide.");
                }

                if (reader.TokenType == JsonTokenType.True)
                {
                    snapshot = true;
                }
                else if (reader.TokenType == JsonTokenType.False)
                {
                    snapshot = false;
                }
                else
                {
                    throw new JsonException("Le contrat JSON de licence contient un champ IsExpired racine invalide.");
                }
            }

            return snapshot ?? throw new JsonException(
                "Le contrat JSON de licence ne contient pas le champ IsExpired racine attendu.");
        }

        private static byte[] RestoreSignedExpirationSnapshot(byte[] serializedModel, bool signedExpirationSnapshot)
        {
            var reader = new Utf8JsonReader(serializedModel);
            long tokenStart = -1;
            long tokenEnd = -1;

            while (reader.Read())
            {
                if (reader.TokenType != JsonTokenType.PropertyName ||
                    reader.CurrentDepth != 1 ||
                    !reader.ValueTextEquals(SignedExpirationSnapshotProperty))
                {
                    continue;
                }

                if (tokenStart >= 0 ||
                    !reader.Read() ||
                    reader.CurrentDepth != 1 ||
                    (reader.TokenType != JsonTokenType.True && reader.TokenType != JsonTokenType.False))
                {
                    throw new InvalidOperationException("Le contrat JSON sérialisé contient un champ IsExpired racine invalide.");
                }

                tokenStart = reader.TokenStartIndex;
                tokenEnd = reader.BytesConsumed;
            }

            if (tokenStart < 0 || tokenEnd <= tokenStart)
            {
                throw new InvalidOperationException("Le contrat JSON sérialisé ne contient pas le champ IsExpired racine attendu.");
            }

            var snapshotBytes = Encoding.UTF8.GetBytes(signedExpirationSnapshot ? "true" : "false");
            var prefixLength = checked((int)tokenStart);
            var suffixOffset = checked((int)tokenEnd);
            var restoredBytes = new byte[prefixLength + snapshotBytes.Length + serializedModel.Length - suffixOffset];

            Buffer.BlockCopy(serializedModel, 0, restoredBytes, 0, prefixLength);
            Buffer.BlockCopy(snapshotBytes, 0, restoredBytes, prefixLength, snapshotBytes.Length);
            Buffer.BlockCopy(
                serializedModel,
                suffixOffset,
                restoredBytes,
                prefixLength + snapshotBytes.Length,
                serializedModel.Length - suffixOffset);

            return restoredBytes;
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

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return "NOT_FOUND";
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
