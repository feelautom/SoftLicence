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
        public StatusErrorCode ErrorCode { get; }
        public string? ErrorMessage { get; }

        private LicenseStatusResult(bool success, string? status, StatusErrorCode errorCode, string? errorMessage)
        {
            Success = success;
            Status = status;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
        }

        public static LicenseStatusResult Ok(string status) =>
            new LicenseStatusResult(true, status, StatusErrorCode.None, null);

        public static LicenseStatusResult NotFound() =>
            new LicenseStatusResult(true, "NOT_FOUND", StatusErrorCode.None, null);

        public static LicenseStatusResult Fail(StatusErrorCode code, string? message = null) =>
            new LicenseStatusResult(false, null, code, message);
    }
}
