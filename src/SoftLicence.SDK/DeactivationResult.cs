namespace SoftLicence.SDK
{
    public class DeactivationResult
    {
        public bool Success { get; }
        public bool IsSuccess => Success;
        public string? ErrorMessage { get; }

        private DeactivationResult(bool success, string? errorMessage)
        {
            Success = success;
            ErrorMessage = errorMessage;
        }

        public static DeactivationResult Ok() =>
            new DeactivationResult(true, null);

        public static DeactivationResult Fail(string message) =>
            new DeactivationResult(false, message);
    }
}
