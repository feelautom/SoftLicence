namespace SoftLicence.SDK
{
    /// <summary>
    /// Identifies the reason why local license validation failed.
    /// </summary>
    public enum LicenseValidationErrorCode
    {
        None = 0,
        InvalidFormat = 1,
        Unsigned = 2,
        InvalidSignature = 3,
        Expired = 4,
        HardwareIdRequired = 5,
        HardwareIdMismatch = 6,
        InvalidHardwareBinding = 7,
        ValidationError = 8
    }

    /// <summary>
    /// Detailed result returned by local signed-license validation.
    /// </summary>
    public sealed class LicenseValidationResult
    {
        public bool IsValid { get; }

        public LicenseModel? License { get; }

        public LicenseValidationErrorCode ErrorCode { get; }

        public string ErrorMessage { get; }

        private LicenseValidationResult(
            bool isValid,
            LicenseModel? license,
            LicenseValidationErrorCode errorCode,
            string errorMessage)
        {
            IsValid = isValid;
            License = license;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
        }

        internal static LicenseValidationResult Valid(LicenseModel license) =>
            new LicenseValidationResult(true, license, LicenseValidationErrorCode.None, "Licence valide.");

        internal static LicenseValidationResult Invalid(
            LicenseValidationErrorCode errorCode,
            string errorMessage,
            LicenseModel? license = null) =>
            new LicenseValidationResult(false, license, errorCode, errorMessage);
    }
}
