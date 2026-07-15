using System.Net;
using System.Text;
using System.Text.Json;

namespace SoftLicence.SDK
{
    public class SoftLicenceClient : ISoftLicenceClient
    {
        private const string SdkVersion = "1.1.11";
        private const string LegacyHardwareIdAlgorithm = "legacy-wmi-first-disk";
        private const string StableHardwareIdAlgorithm = "v2-wmi-disk-index-0";

        private readonly string _serverUrl;
        private readonly string? _publicKeyXml;
        private readonly HttpClient _httpClient;

        public SoftLicenceClient(string serverUrl, string? publicKeyXml = null, HttpClient? httpClient = null)
        {
            _serverUrl = serverUrl.TrimEnd('/');
            _publicKeyXml = publicKeyXml;
            _httpClient = httpClient ?? new HttpClient();
        }

        public async Task<ActivationResult> ActivateAsync(string licenseKey, string appName, string? appId = null, string? appVersion = null, string? customerEmail = null, string? customerName = null)
        {
            try
            {
                var migrationInfo = HardwareInfo.GetHardwareIdMigrationInfo();
                Dictionary<string, string>? fingerprints = null;
                try { fingerprints = HardwareInfo.GetComponentFingerprints(); } catch { }

                var payload = new Dictionary<string, object?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["HardwareId"] = migrationInfo.LegacyHardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["AppVersion"] = appVersion,
                    ["CustomerEmail"] = customerEmail,
                    ["CustomerName"] = customerName,
                    ["ComponentFingerprints"] = fingerprints,
                    ["HardwareIdV2"] = migrationInfo.StableHardwareId,
                    ["HardwareIdV2Differs"] = migrationInfo.HasStableHardwareId ? migrationInfo.HasDistinctHardwareIds : null,
                    ["HardwareIdAlgorithm"] = LegacyHardwareIdAlgorithm,
                    ["HardwareIdV2Algorithm"] = migrationInfo.HasStableHardwareId ? StableHardwareIdAlgorithm : null,
                    ["SdkVersion"] = SdkVersion
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation", content);

                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    var licenseFile = ExtractLicenseFile(body);
                    return licenseFile != null
                        ? ActivationResult.Ok(licenseFile)
                        : ActivationResult.Fail(ActivationErrorCode.ServerError, "Missing LicenseFile in response");
                }

                var errorBody = await response.Content.ReadAsStringAsync();
                var errorCode = MapHttpErrorToActivationCode(response.StatusCode, errorBody);
                return ActivationResult.Fail(errorCode, errorBody);
            }
            catch (HttpRequestException ex)
            {
                return ActivationResult.Fail(ActivationErrorCode.NetworkError, ex.Message);
            }
            catch (TaskCanceledException ex)
            {
                return ActivationResult.Fail(ActivationErrorCode.NetworkError, ex.Message);
            }
        }

        public async Task<ActivationResult> RequestTrialAsync(string appName, string? appId = null, string typeSlug = "TRIAL", string? appVersion = null, string? customerEmail = null, string? customerName = null)
        {
            try
            {
                var migrationInfo = HardwareInfo.GetHardwareIdMigrationInfo();
                Dictionary<string, string>? fingerprints = null;
                try { fingerprints = HardwareInfo.GetComponentFingerprints(); } catch { }

                var payload = new Dictionary<string, object?>
                {
                    ["HardwareId"] = migrationInfo.LegacyHardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["TypeSlug"] = typeSlug,
                    ["AppVersion"] = appVersion,
                    ["CustomerEmail"] = customerEmail,
                    ["CustomerName"] = customerName,
                    ["ComponentFingerprints"] = fingerprints,
                    ["HardwareIdV2"] = migrationInfo.StableHardwareId,
                    ["HardwareIdV2Differs"] = migrationInfo.HasStableHardwareId ? migrationInfo.HasDistinctHardwareIds : null,
                    ["HardwareIdAlgorithm"] = LegacyHardwareIdAlgorithm,
                    ["HardwareIdV2Algorithm"] = migrationInfo.HasStableHardwareId ? StableHardwareIdAlgorithm : null,
                    ["SdkVersion"] = SdkVersion
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/trial", content);

                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    var licenseFile = ExtractLicenseFile(body);
                    return licenseFile != null
                        ? ActivationResult.Ok(licenseFile)
                        : ActivationResult.Fail(ActivationErrorCode.ServerError, "Missing LicenseFile in response");
                }

                var errorBody = await response.Content.ReadAsStringAsync();
                var errorCode = MapHttpErrorToActivationCode(response.StatusCode, errorBody);
                return ActivationResult.Fail(errorCode, errorBody);
            }
            catch (HttpRequestException ex)
            {
                return ActivationResult.Fail(ActivationErrorCode.NetworkError, ex.Message);
            }
            catch (TaskCanceledException ex)
            {
                return ActivationResult.Fail(ActivationErrorCode.NetworkError, ex.Message);
            }
        }

        public async Task<LicenseStatusResult> CheckStatusAsync(string licenseKey, string appName, string? appId = null, string? appVersion = null)
        {
            try
            {
                var migrationInfo = HardwareInfo.GetHardwareIdMigrationInfo();
                Dictionary<string, string>? fingerprints = null;
                try { fingerprints = HardwareInfo.GetComponentFingerprints(); } catch { }

                var payload = new Dictionary<string, object?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["HardwareId"] = migrationInfo.LegacyHardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["AppVersion"] = appVersion,
                    ["ComponentFingerprints"] = fingerprints,
                    ["HardwareIdV2"] = migrationInfo.StableHardwareId,
                    ["HardwareIdV2Differs"] = migrationInfo.HasStableHardwareId ? migrationInfo.HasDistinctHardwareIds : null,
                    ["HardwareIdAlgorithm"] = LegacyHardwareIdAlgorithm,
                    ["HardwareIdV2Algorithm"] = migrationInfo.HasStableHardwareId ? StableHardwareIdAlgorithm : null,
                    ["SdkVersion"] = SdkVersion
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/check", content);

                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return LicenseStatusResult.NotFound();
                }

                if (response.StatusCode == HttpStatusCode.Forbidden)
                {
                    return LicenseStatusResult.Revoked("Access denied by server");
                }

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync();
                    return LicenseStatusResult.Fail(StatusErrorCode.ServerError, errorBody);
                }

                var json = await response.Content.ReadAsStringAsync();
                using (var doc = JsonDocument.Parse(json))
                {
                    if (doc.RootElement.TryGetProperty("status", out var prop) ||
                        doc.RootElement.TryGetProperty("Status", out prop))
                    {
                        var status = prop.GetString();
                        if (status == null)
                            return LicenseStatusResult.Fail(StatusErrorCode.UnknownResponse, "Null status in response");

                        string? licenseFile = null;
                        if (doc.RootElement.TryGetProperty("licenseFile", out var lfProp) ||
                            doc.RootElement.TryGetProperty("LicenseFile", out lfProp))
                        {
                            licenseFile = lfProp.GetString();
                        }

                        string? errorMessage = null;
                        if (doc.RootElement.TryGetProperty("errorMessage", out var emProp) ||
                            doc.RootElement.TryGetProperty("ErrorMessage", out emProp))
                        {
                            errorMessage = emProp.GetString();
                        }

                        return LicenseStatusResult.Ok(status, licenseFile, errorMessage);
                    }
                }

                return LicenseStatusResult.Fail(StatusErrorCode.UnknownResponse, "No status field in response");
            }
            catch (HttpRequestException ex)
            {
                return LicenseStatusResult.Fail(StatusErrorCode.NetworkError, ex.Message);
            }
            catch (TaskCanceledException ex)
            {
                return LicenseStatusResult.Fail(StatusErrorCode.NetworkError, ex.Message);
            }
        }

        public (bool IsValid, LicenseModel? License, string ErrorMessage) ValidateLocal(string licenseString, string hardwareId)
        {
            if (string.IsNullOrEmpty(_publicKeyXml))
            {
                throw new InvalidOperationException("Public key was not provided at construction. Pass publicKeyXml to the SoftLicenceClient constructor to use local validation.");
            }

            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                throw new ArgumentException("Le hardwareId est obligatoire pour ValidateLocal. Utilisez ValidateForCurrentMachine pour une validation automatique.", nameof(hardwareId));
            }

            return LicenseService.ValidateLicense(licenseString, _publicKeyXml!, hardwareId);
        }

        public async Task<(bool IsValid, LicenseModel? License, string ErrorMessage)> ValidateLocalAsync(string licenseString, string hardwareId)
        {
            return await Task.Run(() => ValidateLocal(licenseString, hardwareId));
        }

        public (bool IsValid, LicenseModel? License, string ErrorMessage) ValidateForCurrentMachine(string licenseString)
        {
            var hwId = HardwareInfo.GetHardwareId();
            return ValidateLocal(licenseString, hwId);
        }

        public async Task<(bool IsValid, LicenseModel? License, string ErrorMessage)> ValidateForCurrentMachineAsync(string licenseString)
        {
            return await Task.Run(() => ValidateForCurrentMachine(licenseString));
        }

        public async Task<DeactivationResult> DeactivateAsync(string licenseKey, string appName, string? appId = null)
        {
            var hwId = HardwareInfo.GetHardwareId();
            return await DeactivateAsync(licenseKey, appName, hwId, "settings_button", appId);
        }

        public async Task<DeactivationResult> DeactivateAsync(string licenseKey, string appName, string hardwareId, string source, string? appId = null)
        {
            try
            {
                var payload = new Dictionary<string, string?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["HardwareId"] = hardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["Source"] = source
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/deactivate", content);

                if (response.IsSuccessStatusCode)
                    return DeactivationResult.Ok();

                var errorBody = await response.Content.ReadAsStringAsync();
                return DeactivationResult.Fail(errorBody);
            }
            catch (HttpRequestException ex)
            {
                return DeactivationResult.Fail(ex.Message);
            }
            catch (TaskCanceledException ex)
            {
                return DeactivationResult.Fail(ex.Message);
            }
        }

        public async Task<bool> ResetRequestAsync(string licenseKey, string appName, string? appId = null)
        {
            try
            {
                var payload = new Dictionary<string, string?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["AppName"] = appName,
                    ["AppId"] = appId
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/reset-request", content);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ResetConfirmAsync(string licenseKey, string appName, string resetCode, string? appId = null)
        {
            try
            {
                var payload = new Dictionary<string, string?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["AppName"] = appName,
                    ["ResetCode"] = resetCode,
                    ["AppId"] = appId
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/reset-confirm", content);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private static string? ExtractLicenseFile(string json)
        {
            try
            {
                using (var doc = JsonDocument.Parse(json))
                {
                    if (doc.RootElement.TryGetProperty("LicenseFile", out var prop) ||
                        doc.RootElement.TryGetProperty("licenseFile", out prop))
                    {
                        return prop.GetString();
                    }
                }
            }
            catch (JsonException)
            {
            }
            return null;
        }

        private static ActivationErrorCode MapHttpErrorToActivationCode(HttpStatusCode statusCode, string body)
        {
            if ((int)statusCode >= 500)
                return ActivationErrorCode.ServerError;

            var lower = body.ToLowerInvariant();

            if (lower.Contains("invalid") || lower.Contains("invalide") || lower.Contains("not found") || lower.Contains("introuvable"))
                return ActivationErrorCode.InvalidKey;

            if (lower.Contains("disabled") || lower.Contains("revoked") || lower.Contains("desactiv") || lower.Contains("révoqu"))
                return ActivationErrorCode.LicenseDisabled;

            if (lower.Contains("expired") || lower.Contains("expir"))
                return ActivationErrorCode.LicenseExpired;

            if (lower.Contains("max") || lower.Contains("activation") || lower.Contains("seat"))
                return ActivationErrorCode.MaxActivationsReached;

            if (lower.Contains("version"))
                return ActivationErrorCode.VersionNotAllowed;

            if (lower.Contains("app") || lower.Contains("product") || lower.Contains("produit"))
                return ActivationErrorCode.AppNotFound;

            return ActivationErrorCode.ServerError;
        }
    }
}
