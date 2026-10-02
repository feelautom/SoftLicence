using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Resolves preflight evidence for the existing authenticated analytics consumer.</summary>
public sealed partial class AnalyticsController
{
    /// <summary>
    /// Reads a unique request/product/grant and matches its digest against only that license's stored
    /// seats and legacy identity. No activation, identity repair, or security authority is modified.
    /// Raw identity stays on this protected analytics boundary, just as on machine-profile reads.
    /// </summary>
    [HttpGet("support/runtime-distribution-hardware-identity")]
    public async Task<IActionResult> GetPreflightDiagnosticIdentity(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? requestId, [FromQuery] string? grantRefDigestSha256,
        [FromQuery] string? productId = null, [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null) return AnalyticsApiKeyHttp.Failure(HttpContext);
        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null) return product.Error;
        if (!Guid.TryParseExact(requestId, "D", out var requestGuid) || requestGuid.ToString("D") != requestId
            || grantRefDigestSha256 is null || !ValidHash(grantRefDigestSha256))
            return BadRequest(new { errorCode = "INVALID_PREFLIGHT_IDENTITY_QUERY" });
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var decisions = await db.RuntimeDistributionHardwareDecisions.AsNoTracking()
                .Where(row => row.ProductId == product.ProductId && row.RequestId == requestId)
                .Take(2).ToListAsync(cancellationToken);
            if (decisions.Count != 1)
                return StatusCode(409, new { errorCode = decisions.Count == 0
                    ? "PREFLIGHT_DECISION_NOT_FOUND" : "PREFLIGHT_DECISION_AMBIGUOUS" });
            var decision = decisions[0];
            if (decision.GrantRefDigestSha256 != grantRefDigestSha256)
                return StatusCode(409, new { errorCode = "PREFLIGHT_GRANT_MISMATCH" });
            var candidates = await db.LicenseSeats.AsNoTracking()
                .Where(seat => seat.LicenseId == decision.LicenseId && seat.License!.ProductId == product.ProductId)
                .Select(seat => seat.HardwareId).Distinct().Take(1001).ToListAsync(cancellationToken);
            if (candidates.Count > 1000)
                return StatusCode(409, new { errorCode = "PREFLIGHT_IDENTITY_BOUND_EXCEEDED" });
            var legacy = await db.Licenses.AsNoTracking()
                .Where(license => license.Id == decision.LicenseId && license.ProductId == product.ProductId)
                .Select(license => license.HardwareId).SingleOrDefaultAsync(cancellationToken);
            var identity = decision.HardwareIdHash is null ? null
                : PreflightDiagnosticIdentity.Resolve(decision.HardwareIdHash, candidates.Append(legacy));
            return Ok(new { productId = product.ProductId, requestId, grantRefDigestSha256,
                hardwareIdHash = decision.HardwareIdHash, hardwareId = identity,
                status = identity is null ? "not_found" : "resolved",
                basis = "exact_product_license_hardware_digest" });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            // Preserve the exception in provider diagnostics without exposing identifiers or SQL publicly.
            HttpContext.RequestServices.GetRequiredService<ILogger<AnalyticsController>>()
                .LogError(exception, "Preflight diagnostic identity lookup failed.");
            return StatusCode(503, new { errorCode = "PREFLIGHT_IDENTITY_UNAVAILABLE" });
        }
    }
}
