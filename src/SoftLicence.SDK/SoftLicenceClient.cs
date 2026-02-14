using System.Text;
using System.Text.Json;

namespace SoftLicence.SDK
{
    public class SoftLicenceClient
    {
        private readonly string _serverUrl;
        private readonly HttpClient _httpClient;

        public SoftLicenceClient(string serverUrl, HttpClient? httpClient = null)
        {
            _serverUrl = serverUrl.TrimEnd('/');
            _httpClient = httpClient ?? new HttpClient();
        }

        public async Task<string> ActivateAsync(string licenseKey, string appName, string? appVersion = null)
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

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Activation failed: {response.ReasonPhrase}");
            }

            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> CheckStatusAsync(string licenseKey, string appName)
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

            if (!response.IsSuccessStatusCode)
            {
                return "SERVER_ERROR";
            }

            var json = await response.Content.ReadAsStringAsync();
            using (var doc = JsonDocument.Parse(json))
            {
                if (doc.RootElement.TryGetProperty("status", out var prop) || 
                    doc.RootElement.TryGetProperty("Status", out prop))
                {
                    return prop.GetString() ?? "UNKNOWN";
                }
            }
            return "UNKNOWN_RESPONSE";
        }
    }
}
