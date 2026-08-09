namespace SoftLicence.SDK
{
    public enum ActivationErrorCode
    {
        None,
        InvalidKey,
        LicenseDisabled,
        LicenseExpired,
        MaxActivationsReached,
        VersionNotAllowed,
        AppNotFound,
        ServerError,
        NetworkError
    }

    public class ActivationResult
    {
        public bool Success { get; }
        public bool IsSuccess => Success; // Alias pour DX
        public string? LicenseFile { get; }
        public ActivationErrorCode ErrorCode { get; }
        public string? ErrorMessage { get; }
        public string? ServerErrorCode { get; }
        public string? CorrelationId { get; }
        public bool UsedLegacyErrorFallback { get; }

        private ActivationResult(bool success, string? licenseFile, ActivationErrorCode errorCode, string? errorMessage, string? serverErrorCode = null, string? correlationId = null, bool usedLegacyErrorFallback = false)
        {
            Success = success;
            LicenseFile = licenseFile;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
            ServerErrorCode = serverErrorCode;
            CorrelationId = correlationId;
            UsedLegacyErrorFallback = usedLegacyErrorFallback;
        }

        public static ActivationResult Ok(string licenseFile) =>
            new ActivationResult(true, licenseFile, ActivationErrorCode.None, null);

        public static ActivationResult Fail(ActivationErrorCode code, string? message = null) =>
            new ActivationResult(false, null, code, message);

        /// <summary>Creates a failed result from the versioned server error contract.</summary>
        public static ActivationResult Fail(ActivationErrorCode code, string? message, string? serverErrorCode, string? correlationId) =>
            new ActivationResult(false, null, code, message, serverErrorCode, correlationId);

        internal static ActivationResult FailLegacy(ActivationErrorCode code, string? message, string? correlationId) =>
            new ActivationResult(false, null, code, message, null, correlationId, true);
    }
}
