using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.LicenseTypeChanges;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Licence-type write routes for the MCP (TKT-002781): preview, apply with the preview fingerprint, and the journal.
/// Writing requires the <c>license-types:write</c> scope and, like the administration routes of types (TKT-002469),
/// an internal address: the MCP container reaches the server on the Docker network and forwards a trusted address, so
/// the write routes stay closed to the Internet even with a valid key.
/// </summary>
public sealed partial class AnalyticsController
{
    /// <summary>Shows what a batch would change and its fingerprint; writes nothing.</summary>
    [HttpPost("license-types/changes/preview")]
    public async Task<IActionResult> PreviewLicenseTypeChanges(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromBody] LicenseTypeChangeRequest? request,
        [FromServices] LicenseTypeChangeService changes,
        [FromServices] SecurityService security,
        CancellationToken cancellationToken)
    {
        var gate = await AuthorizeLicenseTypeWriteAsync(analyticsKey, request, security, cancellationToken);
        if (gate.Error != null) return gate.Error;
        try
        {
            return Ok(await changes.PreviewAsync(gate.ProductId, gate.Auth!.IsGlobal, request!, cancellationToken));
        }
        catch (LicenseTypeChangeException ex)
        {
            return ChangeRefusal(ex);
        }
    }

    /// <summary>Applies a previewed batch when its fingerprint still matches; one journal row per batch.</summary>
    [HttpPost("license-types/changes/apply")]
    public async Task<IActionResult> ApplyLicenseTypeChanges(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromBody] LicenseTypeChangeRequest? request,
        [FromServices] LicenseTypeChangeService changes,
        [FromServices] SecurityService security,
        CancellationToken cancellationToken)
    {
        var gate = await AuthorizeLicenseTypeWriteAsync(analyticsKey, request, security, cancellationToken);
        if (gate.Error != null) return gate.Error;
        try
        {
            return Ok(await changes.ApplyAsync(gate.ProductId, gate.Auth!.IsGlobal, gate.Auth.KeyId,
                HttpContext.Connection.RemoteIpAddress?.ToString(), request!, cancellationToken));
        }
        catch (LicenseTypeChangeException ex)
        {
            return ChangeRefusal(ex);
        }
    }

    /// <summary>
    /// Reads the change journal of one product, newest first. Read scope <c>analytics:multi-product:read</c>; a product
    /// key only reads its own product.
    /// </summary>
    [HttpGet("license-types/changes/audit")]
    public async Task<IActionResult> GetLicenseTypeChangeAudit(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromServices] LicenseTypeChangeService changes,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var auth = await _apiKeyAuth.ValidateForRequestAsync(HttpContext, analyticsKey, AnalyticsApiKeyScopes.MultiProductRead, cancellationToken);
        if (auth == null) return AnalyticsApiKeyHttp.Failure(HttpContext);
        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null) return product.Error;
        var rows = await changes.GetAuditAsync(product.ProductId, take, cancellationToken);
        return Ok(rows.Select(row => new
        {
            row.Id,
            row.AppliedAtUtc,
            row.ProductId,
            row.AnalyticsKeyId,
            row.CallerIp,
            row.RequestedBy,
            row.PreviewHash,
            row.OperationCount,
            Changes = System.Text.Json.JsonDocument.Parse(row.ChangesJson).RootElement
        }));
    }

    /// <summary>Result of the write gate: the key, the resolved product, or the refusal to return.</summary>
    private sealed record LicenseTypeWriteGate(AnalyticsApiKeyAuthResult? Auth, Guid ProductId, IActionResult? Error);

    /// <summary>
    /// Internal address first (same barrier as the administration routes), then the write scope, then the product the key
    /// may reach. A missing body is a 400.
    /// </summary>
    private async Task<LicenseTypeWriteGate> AuthorizeLicenseTypeWriteAsync(
        string? analyticsKey, LicenseTypeChangeRequest? request, SecurityService security, CancellationToken cancellationToken)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        if (!security.IsWhitelisted(ip))
            return new LicenseTypeWriteGate(null, Guid.Empty, StatusCode(StatusCodes.Status403Forbidden, new
            {
                errorCode = "INTERNAL_NETWORK_REQUIRED",
                message = "Licence-type writes are accepted only from the internal network (the MCP)."
            }));
        var auth = await _apiKeyAuth.ValidateForRequestAsync(HttpContext, analyticsKey, AnalyticsApiKeyScopes.LicenseTypesWrite, cancellationToken);
        if (auth == null) return new LicenseTypeWriteGate(null, Guid.Empty, AnalyticsApiKeyHttp.Failure(HttpContext));
        if (request == null)
            return new LicenseTypeWriteGate(auth, Guid.Empty, BadRequest(new { errorCode = "REQUEST_REQUIRED", message = "A JSON batch is required." }));
        var product = await ResolveAnalyticsProductAsync(auth, request.ProductId, request.ProductName, cancellationToken);
        return product.Error != null
            ? new LicenseTypeWriteGate(auth, Guid.Empty, product.Error)
            : new LicenseTypeWriteGate(auth, product.ProductId, null);
    }

    /// <summary>Turns a refusal of the change service into its HTTP status with a stable code.</summary>
    private ObjectResult ChangeRefusal(LicenseTypeChangeException ex) =>
        StatusCode(ex.Status, new { errorCode = ex.Code, message = ex.Message });
}
