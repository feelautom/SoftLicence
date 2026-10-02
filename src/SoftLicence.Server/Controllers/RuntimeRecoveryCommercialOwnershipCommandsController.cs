using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Exposes only provider-authenticated, product-scoped commercial ownership transfer and revocation commands.
/// </summary>
/// <param name="authentication">
/// Authenticates the global or exact product-scoped provider secret before any command reaches the service.
/// </param>
/// <param name="commands">
/// Executes the authorized transition and returns its frozen provider-private readback.
/// </param>
[ApiController]
[Route("api/admin/products/{productId:guid}/runtime-recovery-commercial-ownership-commands")]
[EnableRateLimiting("AdminAPI")]
public sealed class RuntimeRecoveryCommercialOwnershipCommandsController(
    AdminSecretAuthenticationService authentication,
    IRuntimeRecoveryCommercialOwnershipCommandService commands) : ControllerBase
{
    /// <summary>
    /// Executes or exactly replays one closed ownership command without coupling it to license revocation or recovery.
    /// </summary>
    /// <param name="productId">Exact route product checked against a product-scoped provider secret.</param>
    /// <param name="request">Typed command containing only opaque UUID authority selectors.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through PostgreSQL locks and rollback.</param>
    /// <returns>The frozen canonical command terminal, or a stable fail-closed error.</returns>
    [HttpPost]
    public async Task<IActionResult> Execute(
        Guid productId,
        [FromBody] RuntimeRecoveryCommercialOwnershipCommandRequest? request,
        CancellationToken cancellationToken)
    {
        SetNoStore();
        var principal = await authentication.AuthenticateAsync(HttpContext);
        if (!principal.Authorized)
            return Unauthorized(new { error = "unauthorized" });
        if (principal.ScopedProductId.HasValue && principal.ScopedProductId.Value != productId)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "product_scope_forbidden" });
        if (request is null)
            return BadRequest(new { error = "invalid_request" });

        try
        {
            var result = await commands.ExecuteAsync(productId, request, cancellationToken);
            return Content(result.ResponseJson, "application/json; charset=utf-8", Encoding.UTF8);
        }
        catch (RuntimeRecoveryCommercialOwnershipCommandException exception)
        {
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
    }

    /// <summary>Prevents storage of provider-private transition readbacks by intermediaries.</summary>
    private void SetNoStore()
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
    }
}
