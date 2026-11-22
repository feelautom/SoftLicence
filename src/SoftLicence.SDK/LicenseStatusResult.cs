namespace SoftLicence.SDK
{
    public enum StatusErrorCode
    {
        None,
        ServerError,
        NetworkError,
        UnknownResponse,
        /// <summary>The machine has no acceptable system UUID (device refused, support code in the message).</summary>
        DeviceRefused
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

        /// <summary>
        /// Gets the single-use control token answer (server TKT-003615), or <see langword="null"/> when the server sent
        /// none: request without <see cref="CloneGuardPresentation"/>, server older than the feature, or failure before
        /// a parsable answer. A <see langword="null"/> value after a guarded request means "keep the pair and resend it".
        /// </summary>
        public CloneGuardOutcome? CloneGuard { get; private set; }

        /// <summary>Attaches the parsed clone guard member to a result built by one of the factories; returns the same instance.</summary>
        /// <param name="cloneGuard">Parsed member, or <see langword="null"/> when absent.</param>
        internal LicenseStatusResult WithCloneGuard(CloneGuardOutcome? cloneGuard)
        {
            CloneGuard = cloneGuard;
            return this;
        }

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
