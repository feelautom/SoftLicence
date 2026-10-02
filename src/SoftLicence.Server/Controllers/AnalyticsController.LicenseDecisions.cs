using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Provides administrator analytics under the existing telemetry permission and product selector; targeted decision reads intersect exact identifiers and expose validated projections only.</summary>
public sealed partial class AnalyticsController
{
    /// <summary>Reads one exact request atomically and fails closed if its bounded result cannot be returned completely.</summary>
    [HttpGet("support/license-decisions/request-snapshot")]
    public async Task<IActionResult> GetLicenseDecisionRequestSnapshot(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? requestId = null, [FromQuery] string? productId = null,
        [FromQuery] string? productName = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
            if (auth == null) return AnalyticsApiKeyHttp.Failure(HttpContext);
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null) return product.Error;
            var items = await new LicenseDecisionHistoryQueryService(_dbFactory).ReadRequestSnapshotAsync(
                product.ProductId, requestId!, cancellationToken);
            return Ok(new { productId = product.ProductId, requestId, items, complete = true });
        }
        catch (ArgumentException)
        {
            return BadRequest(new { errorCode = "INVALID_DECISION_REQUEST_SNAPSHOT",
                message = "Provide one exact request ID bounded to 200 characters." });
        }
        catch (InvalidOperationException)
        {
            return StatusCode(409, new { errorCode = "DECISION_REQUEST_SNAPSHOT_BOUND_EXCEEDED",
                message = "The exact request contains too many decisions for a complete diagnostic." });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            return StatusCode(503, new { errorCode = "DECISION_HISTORY_UNAVAILABLE",
                message = "Decision history could not be read." });
        }
    }

    /// <summary>Reads exact stored licence decisions under existing Analytics TelemetryRead authentication and product scope.</summary>
    /// <remarks>Requires at least one exact licence/HWID/request target; combined targets intersect. Returns 401 for invalid credentials, existing product-selector 400/403/404 errors, 400 for invalid targets/pages, and redacted 503 on provider failure. Pages contain 1..200 rows at offsets 0..10000. No raw history JSON, licence key, inferred Website correlation or new authority decision is returned. Existing API-key usage auditing remains active.</remarks>
    [HttpGet("support/license-decisions")]
    public async Task<IActionResult> GetLicenseDecisions(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] Guid? licenseId = null, [FromQuery] string? hardwareId = null,
        [FromQuery] string? requestId = null, [FromQuery] int take = 50, [FromQuery] int offset = 0,
        [FromQuery] string? productId = null, [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
            if (auth == null) return AnalyticsApiKeyHttp.Failure(HttpContext);
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null) return product.Error;
            var items = await new LicenseDecisionHistoryQueryService(_dbFactory).ReadAsync(
                product.ProductId, licenseId, hardwareId, requestId, take, offset, cancellationToken);
            return Ok(new { productId = product.ProductId, take, offset, items });
        }
        catch (ArgumentException)
        {
            return BadRequest(new { errorCode = "INVALID_DECISION_HISTORY_REQUEST",
                message = "Provide an exact target; take must be 1..200 and offset 0..10000. HWID is bounded to 512 characters and request ID to 200." });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            return StatusCode(503, new { errorCode = "DECISION_HISTORY_UNAVAILABLE",
                message = "Decision history could not be read." });
        }
    }
}
