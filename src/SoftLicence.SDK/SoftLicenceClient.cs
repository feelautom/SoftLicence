using System.Net;
using System.Text;
using System.Text.Json;

namespace SoftLicence.SDK
{
    public class SoftLicenceClient : ISoftLicenceClient
    {
        private readonly string _serverUrl;
        private readonly string? _publicKeyXml;
        private readonly HttpClient _httpClient;

        public SoftLicenceClient(string serverUrl, string? publicKeyXml = null, HttpClient? httpClient = null)
        {
            _serverUrl = serverUrl.TrimEnd('/');
            _publicKeyXml = publicKeyXml;
            _httpClient = httpClient ?? new HttpClient();
        }

        public async Task<ActivationResult> ActivateAsync(string licenseKey, string appName, string? appVersion = null)
        {
            try
            {
                var hwId = HardwareInfo.GetHardwareId();
                var payload = new
                {
                    LicenseKey = licenseKey,
                    HardwareId = hwId,
                    AppName = appName,
                    AppVersion = appVersion
                };

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

        public async Task<ActivationResult> RequestTrialAsync(string appName, string typeSlug, string? appVersion = null)
        {
            try
            {
                var hwId = HardwareInfo.GetHardwareId();
                var payload = new
                {
                    HardwareId = hwId,
                    AppName = appName,
                    TypeSlug = typeSlug,
                    AppVersion = appVersion
                };

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

        public async Task<LicenseStatusResult> CheckStatusAsync(string licenseKey, string appName)
        {
            try
            {
                var hwId = HardwareInfo.GetHardwareId();
                var payload = new
                {
                    LicenseKey = licenseKey,
                    HardwareId = hwId,
                    AppName = appName
                };

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/check", content);

                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return LicenseStatusResult.NotFound();
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
                        return status != null
                            ? LicenseStatusResult.Ok(status)
                            : LicenseStatusResult.Fail(StatusErrorCode.UnknownResponse, "Null status in response");
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

            if (string.IsNullOrEmpty(hardwareId)) 
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
