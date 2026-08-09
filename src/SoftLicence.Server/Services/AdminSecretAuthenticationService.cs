using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed record AdminSecretAuthenticationResult(bool Authorized, Guid? ScopedProductId);

public sealed class AdminSecretAuthenticationService
{
    private readonly LicenseDbContext _db;
    private readonly IConfiguration _config;
    private readonly SettingsService _settings;
    private readonly SecurityService _security;
    private readonly NotificationService _notifier;
    private readonly ILogger<AdminSecretAuthenticationService> _logger;

    public AdminSecretAuthenticationService(
        LicenseDbContext db,
        IConfiguration config,
        SettingsService settings,
        SecurityService security,
        NotificationService notifier,
        ILogger<AdminSecretAuthenticationService> logger)
    {
        _db = db;
        _config = config;
        _settings = settings;
        _security = security;
        _notifier = notifier;
        _logger = logger;
    }

    public async Task<AdminSecretAuthenticationResult> AuthenticateAsync(HttpContext httpContext)
    {
        var clientIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        if (!httpContext.Request.Headers.TryGetValue("X-Admin-Secret", out var suppliedHeader))
            return Reject(httpContext, clientIp, "missing_header");

        var suppliedSecret = suppliedHeader.ToString();
        if (string.IsNullOrEmpty(suppliedSecret))
            return Reject(httpContext, clientIp, "empty_header");

        if (await _settings.GetBoolSettingAsync("GlobalApiSecretEnabled", true))
        {
            var configuredSecret = _config["AdminSettings:ApiSecret"];
            if (!string.IsNullOrEmpty(configuredSecret) && SecretsEqual(suppliedSecret, configuredSecret))
                return IsIpAllowed(clientIp)
                    ? new AdminSecretAuthenticationResult(true, null)
                    : Reject(httpContext, clientIp, "ip_rejected");
        }

        var products = await _db.Products
            .AsNoTracking()
            .Where(p => p.ApiSecret == suppliedSecret)
            .Select(p => new { p.Id })
            .Take(2)
            .ToListAsync();

        if (products.Count != 1)
            return Reject(httpContext, clientIp, "invalid_secret");

        return IsIpAllowed(clientIp)
            ? new AdminSecretAuthenticationResult(true, products[0].Id)
            : Reject(httpContext, clientIp, "ip_rejected");
    }

    private bool IsIpAllowed(string clientIp)
    {
        var configured = _config["AdminSettings:AllowedIps"];
        if (string.IsNullOrWhiteSpace(configured))
            return true;

        if (_security.IsWhitelisted(clientIp))
            return true;

        return configured
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(clientIp, StringComparer.OrdinalIgnoreCase);
    }

    private AdminSecretAuthenticationResult Reject(HttpContext httpContext, string clientIp, string reasonCode)
    {
        _logger.LogWarning(
            "[ADMIN_AUTH] Request rejected from {IP}; reason={ReasonCode}; path={Path}",
            clientIp,
            reasonCode,
            httpContext.Request.Path);
        _notifier.Notify(
            NotificationService.Triggers.SecurityAuthFailure,
            "Admin authentication failure",
            $"IP: {clientIp}\nReason: {reasonCode}\nEndpoint: {httpContext.Request.Path}");
        return new AdminSecretAuthenticationResult(false, null);
    }

    private static bool SecretsEqual(string supplied, string expected)
    {
        var suppliedBytes = Encoding.UTF8.GetBytes(supplied);
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        return suppliedBytes.Length == expectedBytes.Length
            && CryptographicOperations.FixedTimeEquals(suppliedBytes, expectedBytes);
    }
}
