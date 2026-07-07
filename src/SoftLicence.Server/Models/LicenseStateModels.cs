namespace SoftLicence.Server.Models;

public sealed class LicenseStateRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public sealed class LicenseStateResponse
{
    public string Status { get; set; } = LicenseStateStatuses.ServerError;
    public string Email { get; set; } = string.Empty;
    public bool HasAccount { get; set; }
    public bool HasActiveLicense { get; set; }
    public string? LastLicenseTypeSlug { get; set; }
    public string? LastLicenseStatus { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string DashboardUrl { get; set; } = "https://t-ia-connect.com/account";
    public string Message { get; set; } = string.Empty;
}

public static class LicenseStateStatuses
{
    public const string NoAccount = "no_account";
    public const string InvalidCredentials = "invalid_credentials";
    public const string ActiveLicense = "active_license";
    public const string FreemiumExpired = "freemium_expired";
    public const string LicenseRevoked = "license_revoked";
    public const string AccountSuspended = "account_suspended";
    public const string ServerError = "server_error";
}
