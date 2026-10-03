using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

public partial class ActivationController
{
    /// <summary>Builds a correlated refusal before legacy issuance without modifying licence or seat authority.</summary>
    private IActionResult? RejectMinimumVersion(Product product, string? version, License? existing = null)
    {
        var reason = LegacyMinimumVersionPolicy.Evaluate(product.Name, version, product.MinimumAllowedVersion);
        if (reason == null) return null;
        if (existing?.ExpirationDate is DateTime expiry && expiry < DateTime.UtcNow)
        {
            TagActivationFailure("LICENSE_EXPIRED");
            return BadRequest(_localizer["Api_LicenseExpired"].Value);
        }
        return MinimumVersionRefusal(product, reason, existing?.Id, false, version);
    }

    /// <summary>Preserves heartbeat HTTP200 for update requests, with HTTP503 for invalid server configuration.</summary>
    /// <remarks>Logs only parsed numeric versions or missing/invalid markers, never raw invalid input, keys or HWIDs.</remarks>
    private IActionResult MinimumVersionRefusal(Product product, string reason, Guid? licenseId, bool check, string? version)
    {
        var configurationError = reason == "MINIMUM_VERSION_CONFIGURATION_INVALID";
        var status = configurationError ? "SERVER_CONFIGURATION_ERROR" : "UPDATE_REQUIRED";
        // History reads the contextual reason, while SDK 1.x/2.x classify the public header first.
        // Preserve both contracts: a detailed durable refusal and a stable update classification.
        TagActivationFailure(reason);
        Response.Headers[ActivationErrorCodeHeader] = status;
        _logger.LogWarning(
            "Minimum version refusal: ProductId={ProductId} LicenseId={LicenseId} ReasonCode={ReasonCode} Version={Version} MinimumVersion={MinimumVersion} Stage={Stage} CorrelationId={CorrelationId}",
            product.Id, licenseId, reason, LegacyMinimumVersionPolicy.DescribeForDiagnostics(version),
            LegacyMinimumVersionPolicy.DescribeForDiagnostics(product.MinimumAllowedVersion),
            check ? "check" : "activation", HttpContext.TraceIdentifier);
        var message = configurationError ? "Server version policy is unavailable. Contact support." : "Update required by server";
        var body = new
        {
            isSuccess = check && !configurationError,
            status,
            errorCode = status,
            reasonCode = reason,
            message,
            errorMessage = message,
            minimumVersion = configurationError ? null : product.MinimumAllowedVersion?.Trim(),
            correlationId = HttpContext.TraceIdentifier,
            contractVersion = 1
        };
        return configurationError ? StatusCode(503, body) : Ok(body);
    }
}
