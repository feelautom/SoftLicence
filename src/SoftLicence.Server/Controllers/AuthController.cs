using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting("PublicAPI")]
public class AuthController : ControllerBase
{
    private const string FreemiumSlug = "TIA-CONNECT-FREEMIUM";
    private readonly LicenseDbContext _db;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        LicenseDbContext db,
        IConfiguration configuration,
        ILogger<AuthController> logger)
    {
        _db = db;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpPost("license-state")]
    public async Task<IActionResult> GetLicenseState([FromBody] LicenseStateRequest request)
    {
        var email = NormalizeEmail(request.Email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(request.Password))
            return Ok(BuildResponse(LicenseStateStatuses.InvalidCredentials, email, false, false,
                message: "Invalid credentials."));

        try
        {
            var licenses = await _db.Licenses
                .AsNoTracking()
                .Include(l => l.Type)
                .Include(l => l.Product)
                .Where(l => l.CustomerEmail.ToLower() == email)
                .ToListAsync();

            if (licenses.Count == 0)
            {
                return Ok(BuildResponse(LicenseStateStatuses.NoAccount, email, false, false,
                    message: "No account is known for this email."));
            }

            var authenticated = licenses.Any(l =>
                string.Equals(l.LicenseKey.Trim(), request.Password.Trim(), StringComparison.OrdinalIgnoreCase));

            if (!authenticated)
            {
                return Ok(BuildResponse(LicenseStateStatuses.InvalidCredentials, email, true, false,
                    message: "Invalid credentials."));
            }

            var tiaLicenses = licenses
                .Where(IsTiaConnectLicense)
                .OrderByDescending(GetLicenseSortDate)
                .ToList();

            var scopedLicenses = tiaLicenses.Count > 0 ? tiaLicenses : licenses.OrderByDescending(GetLicenseSortDate).ToList();
            var lastLicense = scopedLicenses.FirstOrDefault();
            var activeLicense = scopedLicenses.FirstOrDefault(IsCurrentlyActive);

            if (scopedLicenses.Any(IsSuspended))
            {
                return Ok(BuildResponse(LicenseStateStatuses.AccountSuspended, email, true, false, lastLicense,
                    "This account is suspended. Please contact support."));
            }

            if (activeLicense != null)
            {
                return Ok(BuildResponse(LicenseStateStatuses.ActiveLicense, email, true, true, activeLicense,
                    "An active T-IA Connect license is available."));
            }

            if (lastLicense != null && IsFreemium(lastLicense))
            {
                return Ok(BuildResponse(LicenseStateStatuses.FreemiumExpired, email, true, false, lastLicense,
                    "Your 30-day Freemium period has ended. Please choose a paid license to continue."));
            }

            if (lastLicense != null && !lastLicense.IsActive)
            {
                return Ok(BuildResponse(LicenseStateStatuses.LicenseRevoked, email, true, false, lastLicense,
                    "This license is no longer active. Please contact support."));
            }

            return Ok(BuildResponse(LicenseStateStatuses.ServerError, email, true, false, lastLicense,
                "Unable to determine the license state."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to evaluate license state for email (redacted)");
            return StatusCode(500, BuildResponse(LicenseStateStatuses.ServerError, email, false, false,
                message: "Unexpected server error."));
        }
    }

    private LicenseStateResponse BuildResponse(
        string status,
        string email,
        bool hasAccount,
        bool hasActiveLicense,
        License? license = null,
        string message = "")
    {
        return new LicenseStateResponse
        {
            Status = status,
            Email = email,
            HasAccount = hasAccount,
            HasActiveLicense = hasActiveLicense,
            LastLicenseTypeSlug = license?.Type?.Slug,
            LastLicenseStatus = license == null ? null : GetLicenseStatus(license),
            ExpiresAt = license?.ExpirationDate,
            DashboardUrl = _configuration["TiaConnect:DashboardUrl"] ?? "https://t-ia-connect.com/account",
            Message = message
        };
    }

    private static string NormalizeEmail(string? email) =>
        (email ?? string.Empty).Trim().ToLowerInvariant();

    private static bool IsTiaConnectLicense(License license)
    {
        var typeSlug = license.Type?.Slug ?? string.Empty;
        var productName = license.Product?.Name ?? string.Empty;
        var normalizedProductName = productName.Replace("-", string.Empty).Replace(" ", string.Empty);

        return typeSlug.StartsWith("TIA-CONNECT", StringComparison.OrdinalIgnoreCase)
            || normalizedProductName.Contains("TIACONNECT", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFreemium(License license) =>
        string.Equals(license.Type?.Slug, FreemiumSlug, StringComparison.OrdinalIgnoreCase);

    private static bool IsCurrentlyActive(License license) =>
        license.IsActive && (!license.ExpirationDate.HasValue || license.ExpirationDate.Value > DateTime.UtcNow);

    private static bool IsSuspended(License license)
    {
        var reason = license.RevocationReason ?? string.Empty;
        return reason.Contains("suspend", StringComparison.OrdinalIgnoreCase)
            || reason.Contains("blocked", StringComparison.OrdinalIgnoreCase)
            || reason.Contains("bloqu", StringComparison.OrdinalIgnoreCase);
    }

    private static DateTime GetLicenseSortDate(License license) =>
        license.RevokedAt ?? license.ExpirationDate ?? license.ActivationDate ?? license.CreationDate;

    private static string GetLicenseStatus(License license)
    {
        if (!license.IsActive)
            return "REVOKED";

        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= DateTime.UtcNow)
            return "EXPIRED";

        return "ACTIVE";
    }
}
