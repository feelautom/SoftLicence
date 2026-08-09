namespace SoftLicence.SDK
{
    public class DeactivationResult
    {
        public bool Success { get; }
        public bool IsSuccess => Success;
        public string? ErrorMessage { get; }
        public string? ServerErrorCode { get; }
        public string? CorrelationId { get; }

        private DeactivationResult(bool success, string? errorMessage, string? serverErrorCode = null, string? correlationId = null)
        {
            Success = success;
            ErrorMessage = errorMessage;
            ServerErrorCode = serverErrorCode;
            CorrelationId = correlationId;
        }

        public static DeactivationResult Ok() =>
            new DeactivationResult(true, null);

        public static DeactivationResult Fail(string message) =>
            new DeactivationResult(false, message);

        /// <summary>Creates a failed deactivation result with structured support diagnostics.</summary>
        public static DeactivationResult Fail(string message, string? serverErrorCode, string? correlationId) =>
            new DeactivationResult(false, message, serverErrorCode, correlationId);
    }
}
