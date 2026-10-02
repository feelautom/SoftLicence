using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Exposes product-scoped Recovery support analytics with identical mono-product/global authorization semantics.
/// </summary>
[ApiController]
[Route("api/analytics/recovery")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
public sealed class RecoveryTelemetryAnalyticsController : ControllerBase
{
    private readonly AnalyticsApiKeyAuthService authService;
    private readonly RecoveryTelemetryAnalyticsService analytics;
    private readonly IDbContextFactory<LicenseDbContext> dbFactory;

    /// <summary>Creates the controller with authentication, product lookup, and read-only analytics dependencies.</summary>
    public RecoveryTelemetryAnalyticsController(
        AnalyticsApiKeyAuthService authService,
        RecoveryTelemetryAnalyticsService analytics,
        IDbContextFactory<LicenseDbContext> dbFactory)
    {
        this.authService = authService;
        this.analytics = analytics;
        this.dbFactory = dbFactory;
    }

    /// <summary>Returns an ordered timeline for one opaque Recovery run under one authorized product.</summary>
    [HttpGet("runs/{recoveryRunId:guid}")]
    public async Task<IActionResult> Timeline(
        Guid recoveryRunId,
        [FromHeader(Name = "X-Analytics-Key")] string? key,
        [FromQuery] Guid? productId,
        [FromQuery] string? productName,
        CancellationToken cancellationToken)
    {
        var scope = await ResolveScopeAsync(key, productId, productName, cancellationToken);
        if (scope.Result is not null) return scope.Result;
        var timeline = await analytics.GetTimelineAsync(scope.ProductId!.Value, recoveryRunId, cancellationToken);
        return timeline is null ? NotFound(new { errorCode = "RECOVERY_RUN_NOT_FOUND" }) : Ok(timeline);
    }

    /// <summary>Returns newest-first bounded closed rejections for one authorized product.</summary>
    [HttpGet("rejections")]
    public async Task<IActionResult> Rejections(
        [FromHeader(Name = "X-Analytics-Key")] string? key,
        [FromQuery] Guid? recoveryRunId,
        [FromQuery] int take,
        [FromQuery] Guid? productId,
        [FromQuery] string? productName,
        CancellationToken cancellationToken)
    {
        var scope = await ResolveScopeAsync(key, productId, productName, cancellationToken);
        if (scope.Result is not null) return scope.Result;
        var rows = await analytics.GetRejectionsAsync(scope.ProductId!.Value, recoveryRunId, take == 0 ? 100 : take, cancellationToken);
        return Ok(new { generatedAtUtc = DateTime.UtcNow, count = rows.Count, rejections = rows });
    }

    /// <summary>Resolves exactly one product under mono/global key rules without trimming or case-folding product names.</summary>
    private async Task<(Guid? ProductId, IActionResult? Result)> ResolveScopeAsync(
        string? key,
        Guid? selectedProductId,
        string? selectedProductName,
        CancellationToken cancellationToken)
    {
        var auth = await authService.ValidateAsync(key ?? string.Empty, AnalyticsApiKeyScopes.TelemetryRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
        if (auth is null)
            return (null, Unauthorized(new { errorCode = "ANALYTICS_KEY_INVALID" }));

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        if (!auth.IsGlobal)
        {
            if (!auth.ProductId.HasValue)
                return (null, Forbid());
            if (selectedProductId.HasValue && selectedProductId.Value != auth.ProductId.Value)
                return (null, Forbid());
            if (selectedProductName is not null)
            {
                var exactName = await db.Products.Where(item => item.Id == auth.ProductId.Value).Select(item => item.Name)
                    .SingleOrDefaultAsync(cancellationToken);
                if (exactName is null || selectedProductName != exactName)
                    return (null, Forbid());
            }
            return (auth.ProductId.Value, null);
        }

        if (!selectedProductId.HasValue && selectedProductName is null)
            return (null, BadRequest(new { errorCode = "PRODUCT_SELECTOR_REQUIRED" }));
        if (selectedProductId.HasValue && selectedProductName is not null)
            return (null, BadRequest(new { errorCode = "PRODUCT_SELECTOR_AMBIGUOUS" }));
        var resolved = selectedProductId.HasValue
            ? await db.Products.Where(item => item.Id == selectedProductId.Value).Select(item => (Guid?)item.Id).SingleOrDefaultAsync(cancellationToken)
            : await db.Products.Where(item => item.Name == selectedProductName).Select(item => (Guid?)item.Id).SingleOrDefaultAsync(cancellationToken);
        return resolved.HasValue
            ? (resolved.Value, null)
            : (null, NotFound(new { errorCode = "PRODUCT_NOT_FOUND" }));
    }
}
