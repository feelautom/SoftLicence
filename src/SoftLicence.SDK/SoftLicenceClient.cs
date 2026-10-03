using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.SDK
{
    public class SoftLicenceClient : ISoftLicenceClient
    {
        private const string SdkVersion = "2.0.0";
        private const string ErrorCodeHeader = "X-SoftLicence-Error-Code";
        private const string CorrelationIdHeader = "X-SoftLicence-Correlation-Id";
        private const string DeviceRefusedServerCode = "DEVICE_REFUSED";

        /// <summary>Serializes request payloads; evidence statuses are sent as their names, not numbers.</summary>
        private static readonly JsonSerializerOptions PayloadJsonOptions = new JsonSerializerOptions
        {
            Converters = { new JsonStringEnumConverter() }
        };

        private readonly string _serverUrl;
        private readonly string? _publicKeyXml;
        private readonly HttpClient _httpClient;

        public SoftLicenceClient(string serverUrl, string? publicKeyXml = null, HttpClient? httpClient = null)
        {
            _serverUrl = serverUrl.TrimEnd('/');
            _publicKeyXml = publicKeyXml;
            _httpClient = httpClient ?? new HttpClient();
        }

        /// <inheritdoc />
        public Task<ActivationResult> ActivateAsync(string licenseKey, string appName, string? appId = null, string? appVersion = null, string? customerEmail = null, string? customerName = null)
        {
            var identity = MachineIdentity.Resolve();
            if (!identity.IsAccepted)
                return Task.FromResult(ActivationResult.Fail(ActivationErrorCode.DeviceRefused, DeviceRefusedMessage(identity), DeviceRefusedServerCode, null));
            return ActivateCoreAsync(licenseKey, appName, appId, appVersion, customerEmail, customerName, identity.HardwareId!, identity.CanonicalUuid!);
        }

        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): caller-held identifier overload, used while a seat still carries its pre-UUID
        // identifier (TKT-001277 lot 5). Remove by 31/12/2026 (see TKT-001430).
        /// <inheritdoc />
        public Task<ActivationResult> ActivateAsync(string licenseKey, string appName, string? appId, string? appVersion, string? customerEmail, string? customerName, string authoritativeHardwareId)
        {
            ValidateAuthoritativeHardwareId(authoritativeHardwareId);
            return ActivateCoreAsync(licenseKey, appName, appId, appVersion, customerEmail, customerName, authoritativeHardwareId, SystemUuidDerivingTo(authoritativeHardwareId));
        }

        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): pre-UUID to UUID identifier switch. Remove by 31/12/2026 (see TKT-001430).
        /// <inheritdoc />
        public Task<ActivationResult> ActivateReplacingHardwareIdAsync(string licenseKey, string appName, string previousHardwareId, string? appId = null, string? appVersion = null, string? customerEmail = null, string? customerName = null)
        {
            ValidateAuthoritativeHardwareId(previousHardwareId);
            var identity = MachineIdentity.Resolve();
            if (!identity.IsAccepted)
                return Task.FromResult(ActivationResult.Fail(ActivationErrorCode.DeviceRefused, DeviceRefusedMessage(identity), DeviceRefusedServerCode, null));
            return ActivateCoreAsync(licenseKey, appName, appId, appVersion, customerEmail, customerName, identity.HardwareId!, identity.CanonicalUuid!, previousHardwareId);
        }

        /// <summary>
        /// Sends the activation payload with the hardware identifier, the system UUID it must derive from, and the
        /// machine evidence. The server applies the UUID rule and refuses with "device refused" and a support code.
        /// When <paramref name="previousHardwareId"/> is set, the server replaces that seat with the current identifier.
        /// A <see langword="null"/> <paramref name="systemUuid"/> sends neither the UUID nor the evidence (pre-UUID identifier).
        /// </summary>
        private async Task<ActivationResult> ActivateCoreAsync(string licenseKey, string appName, string? appId, string? appVersion, string? customerEmail, string? customerName, string hardwareId, string? systemUuid, string? previousHardwareId = null)
        {
            try
            {
                var payload = new Dictionary<string, object?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["HardwareId"] = hardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["AppVersion"] = appVersion,
                    ["CustomerEmail"] = customerEmail,
                    ["CustomerName"] = customerName,
                    ["SystemUuid"] = systemUuid,
                    ["MachineEvidence"] = systemUuid == null ? null : TryCollectEvidence(),
                    ["PreviousHardwareId"] = previousHardwareId,
                    ["SdkVersion"] = SdkVersion
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload, PayloadJsonOptions), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation", content);

                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    if (response.Headers.Contains(ErrorCodeHeader))
                        return MapActivationFailure(response, body);
                    var licenseFile = ExtractLicenseFile(body);
                    return licenseFile != null
                        ? ActivationResult.Ok(licenseFile)
                        : ActivationResult.Fail(ActivationErrorCode.ServerError, "Missing LicenseFile in response");
                }

                var errorBody = await response.Content.ReadAsStringAsync();
                return MapActivationFailure(response, errorBody);
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
                var identity = MachineIdentity.Resolve();
                if (!identity.IsAccepted)
                    return ActivationResult.Fail(ActivationErrorCode.DeviceRefused, DeviceRefusedMessage(identity), DeviceRefusedServerCode, null);

                var payload = new Dictionary<string, object?>
                {
                    ["HardwareId"] = identity.HardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["TypeSlug"] = typeSlug,
                    ["AppVersion"] = appVersion,
                    ["CustomerEmail"] = customerEmail,
                    ["CustomerName"] = customerName,
                    ["SystemUuid"] = identity.CanonicalUuid,
                    ["MachineEvidence"] = TryCollectEvidence(),
                    ["SdkVersion"] = SdkVersion
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload, PayloadJsonOptions), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/activation/trial", content);

                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    if (response.Headers.Contains(ErrorCodeHeader))
                        return MapActivationFailure(response, body);
                    var licenseFile = ExtractLicenseFile(body);
                    return licenseFile != null
                        ? ActivationResult.Ok(licenseFile)
                        : ActivationResult.Fail(ActivationErrorCode.ServerError, "Missing LicenseFile in response");
                }

                var errorBody = await response.Content.ReadAsStringAsync();
                return MapActivationFailure(response, errorBody);
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

        /// <inheritdoc />
        public Task<LicenseStatusResult> CheckStatusAsync(string licenseKey, string appName, string? appId = null, string? appVersion = null)
        {
            var identity = MachineIdentity.Resolve();
            if (!identity.IsAccepted)
                return Task.FromResult(LicenseStatusResult.Fail(StatusErrorCode.DeviceRefused, DeviceRefusedMessage(identity), DeviceRefusedServerCode, null));
            return CheckStatusCoreAsync(licenseKey, appName, appId, appVersion, identity.HardwareId!, identity.CanonicalUuid!);
        }

        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): caller-held identifier overload, used while a seat still carries its pre-UUID
        // identifier (TKT-001277 lot 5). Remove by 31/12/2026 (see TKT-001430).
        /// <inheritdoc />
        public Task<LicenseStatusResult> CheckStatusAsync(string licenseKey, string appName, string? appId, string? appVersion, string authoritativeHardwareId)
        {
            ValidateAuthoritativeHardwareId(authoritativeHardwareId);
            return CheckStatusCoreAsync(licenseKey, appName, appId, appVersion, authoritativeHardwareId, SystemUuidDerivingTo(authoritativeHardwareId));
        }

        /// <summary>
        /// Sends a status request with the hardware identifier, the system UUID it must derive from, and the machine
        /// evidence. A refused UUID comes back as the logical status <c>DEVICE_REFUSED</c> with a support code.
        /// A <see langword="null"/> <paramref name="systemUuid"/> sends neither the UUID nor the evidence (pre-UUID identifier).
        /// </summary>
        private async Task<LicenseStatusResult> CheckStatusCoreAsync(string licenseKey, string appName, string? appId, string? appVersion, string hardwareId, string? systemUuid)
        {
            try
            {
                var payload = new Dictionary<string, object?>
                {
                    ["LicenseKey"] = licenseKey,
                    ["HardwareId"] = hardwareId,
                    ["AppName"] = appName,
                    ["AppId"] = appId,
                    ["AppVersion"] = appVersion,
                    ["SystemUuid"] = systemUuid,
                    ["MachineEvidence"] = systemUuid == null ? null : TryCollectEvidence(),
                    ["SdkVersion"] = SdkVersion
                }.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);

                var content = new StringContent(JsonSerializer.Serialize(payload, PayloadJsonOptions), Encoding.UTF8, "application/json");
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
                    return LicenseStatusResult.Fail(
                        StatusErrorCode.ServerError,
                        ExtractPublicErrorMessage(errorBody),
                        TryGetSingleHeader(response, ErrorCodeHeader),
                        TryGetSingleHeader(response, CorrelationIdHeader));
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
            string hwId;
            try
            {
                hwId = HardwareInfo.GetHardwareId();
            }
            catch (MachineIdentityRefusedException ex)
            {
                return (false, null, ex.Message);
            }
            return ValidateLocal(licenseString, hwId);
        }

        public async Task<(bool IsValid, LicenseModel? License, string ErrorMessage)> ValidateForCurrentMachineAsync(string licenseString)
        {
            return await Task.Run(() => ValidateForCurrentMachine(licenseString));
        }

        public async Task<DeactivationResult> DeactivateAsync(string licenseKey, string appName, string? appId = null)
        {
            string hwId;
            try
            {
                hwId = HardwareInfo.GetHardwareId();
            }
            catch (MachineIdentityRefusedException ex)
            {
                return DeactivationResult.Fail(ex.Message, DeviceRefusedServerCode, null);
            }
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
                return DeactivationResult.Fail(
                    ExtractPublicErrorMessage(errorBody),
                    TryGetSingleHeader(response, ErrorCodeHeader),
                    TryGetSingleHeader(response, CorrelationIdHeader));
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

        /// <summary>
        /// Enforces the Runtime hardware-authority wire contract without silently rewriting caller input.
        /// </summary>
        /// <param name="hardwareId">Candidate authoritative hardware identifier.</param>
        /// <exception cref="ArgumentException">Thrown when the value is not exactly 16 uppercase ASCII hexadecimal characters.</exception>
        private static void ValidateAuthoritativeHardwareId(string hardwareId)
        {
            if (hardwareId == null)
                throw new ArgumentNullException(nameof(hardwareId));

            if (hardwareId.Length != 16 || hardwareId.Any(character => character is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
                throw new ArgumentException("The authoritative hardware ID must contain exactly 16 uppercase ASCII hexadecimal characters.", nameof(hardwareId));
        }

        /// <summary>Builds the customer message for a machine without an acceptable UUID; it only carries the support code.</summary>
        /// <param name="identity">A refused identity.</param>
        /// <returns>For example "Device refused (code AR-01).".</returns>
        private static string DeviceRefusedMessage(MachineIdentityResult identity) =>
            "Device refused (code " + identity.SupportCode + ").";

        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): a caller-held identifier that is not derived from this machine's UUID is the
        // pre-UUID seat identifier and is sent without UUID. Remove by 31/12/2026 (see TKT-001430).
        /// <summary>
        /// Returns the canonical system UUID to send with a caller-held identifier: only when that identifier is the one
        /// derived from this machine's accepted UUID. Otherwise it is a pre-UUID seat identifier and nothing is sent, so the
        /// server keeps its pre-UUID rule instead of refusing the identifier as not derived (AR-05).
        /// </summary>
        /// <param name="hardwareId">Canonical identifier held by the caller.</param>
        /// <returns>The canonical UUID, or <see langword="null"/>.</returns>
        private static string? SystemUuidDerivingTo(string hardwareId)
        {
            var identity = MachineIdentity.Resolve();
            return identity.IsAccepted && string.Equals(identity.HardwareId, hardwareId, StringComparison.Ordinal)
                ? identity.CanonicalUuid
                : null;
        }

        /// <summary>Collects the machine evidence sent for investigation; a collection failure never blocks the call.</summary>
        /// <returns>The evidence, or <see langword="null"/> when it could not be collected.</returns>
        private static MachineEvidence? TryCollectEvidence()
        {
            try
            {
                return MachineIdentity.CollectEvidence();
            }
            catch
            {
                return null;
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

        private static ActivationResult MapActivationFailure(HttpResponseMessage response, string body)
        {
            var correlationId = TryGetSingleHeader(response, CorrelationIdHeader);
            var structuredCode = TryGetSingleHeader(response, ErrorCodeHeader);

            if (response.Headers.Contains(ErrorCodeHeader))
            {
                var mappedCode = MapStructuredActivationCode(structuredCode ?? string.Empty);
                return ActivationResult.Fail(mappedCode, ExtractPublicErrorMessage(body), structuredCode, correlationId);
            }

            return ActivationResult.FailLegacy(MapLegacyHttpErrorToActivationCode(response.StatusCode, body), body, correlationId);
        }

        private static string ExtractPublicErrorMessage(string body)
        {
            try
            {
                using var document = JsonDocument.Parse(body);
                if (document.RootElement.TryGetProperty("message", out var message) ||
                    document.RootElement.TryGetProperty("errorMessage", out message))
                {
                    return message.GetString() ?? body;
                }
            }
            catch (JsonException)
            {
            }

            return body;
        }

        /// <summary>
        /// Maps canonical protocol values with ordinal semantics. Unknown values fail closed and never fall back to response text.
        /// </summary>
        private static ActivationErrorCode MapStructuredActivationCode(string code) => code switch
        {
            "INVALID_LICENSE_KEY" => ActivationErrorCode.InvalidKey,
            "LICENSE_DISABLED" or "PARTNER_INVALID" or "BANNED" or "COMPONENT_BANNED" => ActivationErrorCode.LicenseDisabled,
            "LICENSE_EXPIRED" => ActivationErrorCode.LicenseExpired,
            "SEAT_LIMIT" or "MAX_DAILY_ACTIVATIONS_REACHED" or "MAX_DAILY_DEACTIVATIONS_REACHED" => ActivationErrorCode.MaxActivationsReached,
            "VERSION_NOT_ALLOWED" or "UPDATE_REQUIRED" => ActivationErrorCode.VersionNotAllowed,
            "APP_UNKNOWN" => ActivationErrorCode.AppNotFound,
            DeviceRefusedServerCode => ActivationErrorCode.DeviceRefused,
            _ => ActivationErrorCode.ServerError
        };

        private static string? TryGetSingleHeader(HttpResponseMessage response, string headerName)
        {
            if (!response.Headers.TryGetValues(headerName, out var values))
                return null;

            var materializedValues = values.Take(2).ToArray();
            return materializedValues.Length == 1 && !string.IsNullOrWhiteSpace(materializedValues[0])
                ? materializedValues[0]
                : null;
        }

        /// <summary>
        /// Preserves compatibility with servers that predate the structured error contract.
        /// Remove this bounded fallback after the documented legacy-server support window.
        /// </summary>
        private static ActivationErrorCode MapLegacyHttpErrorToActivationCode(HttpStatusCode statusCode, string body)
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
