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
        public string? ServerErrorCode { get; }
        public string? CorrelationId { get; }

        private LicenseStatusResult(bool success, string? status, StatusErrorCode errorCode, string? errorMessage, string? licenseFile = null, string? serverErrorCode = null, string? correlationId = null)
        {
            Success = success;
            Status = status;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
            LicenseFile = licenseFile;
            ServerErrorCode = serverErrorCode;
            CorrelationId = correlationId;
        }

        public static LicenseStatusResult Ok(string status, string? licenseFile = null, string? errorMessage = null) =>
            new LicenseStatusResult(true, status, StatusErrorCode.None, errorMessage, licenseFile);

        public static LicenseStatusResult NotFound() =>
            new LicenseStatusResult(true, "NOT_FOUND", StatusErrorCode.None, null);

        public static LicenseStatusResult Revoked(string? message = null) =>
            new LicenseStatusResult(true, "REVOKED", StatusErrorCode.None, message);

        public static LicenseStatusResult Fail(StatusErrorCode code, string? message = null) =>
            new LicenseStatusResult(false, null, code, message);

        /// <summary>Creates a failed status result with structured support diagnostics.</summary>
        public static LicenseStatusResult Fail(StatusErrorCode code, string? message, string? serverErrorCode, string? correlationId) =>
            new LicenseStatusResult(false, null, code, message, null, serverErrorCode, correlationId);
    }
}
