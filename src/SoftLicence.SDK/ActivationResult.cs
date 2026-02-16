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
        public string? LicenseFile { get; }
        public ActivationErrorCode ErrorCode { get; }
        public string? ErrorMessage { get; }

        private ActivationResult(bool success, string? licenseFile, ActivationErrorCode errorCode, string? errorMessage)
        {
            Success = success;
            LicenseFile = licenseFile;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
        }

        public static ActivationResult Ok(string licenseFile) =>
            new ActivationResult(true, licenseFile, ActivationErrorCode.None, null);

        public static ActivationResult Fail(ActivationErrorCode code, string? message = null) =>
            new ActivationResult(false, null, code, message);
    }
}
