namespace SoftLicence.SDK
{
    public enum StatusErrorCode
    {
        None,
        ServerError,
        NetworkError,
        UnknownResponse
    }

    public class LicenseStatusResult
    {
        public bool Success { get; }
        public bool IsSuccess => Success; // Alias pour DX
        public string? Status { get; }
        public string? LicenseFile { get; }
        public StatusErrorCode ErrorCode { get; }
        public string? ErrorMessage { get; }

        private LicenseStatusResult(bool success, string? status, StatusErrorCode errorCode, string? errorMessage, string? licenseFile = null)
        {
            Success = success;
            Status = status;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
            LicenseFile = licenseFile;
        }

        public static LicenseStatusResult Ok(string status, string? licenseFile = null) =>
            new LicenseStatusResult(true, status, StatusErrorCode.None, null, licenseFile);

        public static LicenseStatusResult NotFound() =>
            new LicenseStatusResult(true, "NOT_FOUND", StatusErrorCode.None, null);

        public static LicenseStatusResult Revoked(string? message = null) =>
            new LicenseStatusResult(true, "REVOKED", StatusErrorCode.None, message);

        public static LicenseStatusResult Fail(StatusErrorCode code, string? message = null) =>
            new LicenseStatusResult(false, null, code, message);
    }
}
