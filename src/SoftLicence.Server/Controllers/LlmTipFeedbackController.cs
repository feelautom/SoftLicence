using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/llm-tips-feedback")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("TelemetryAPI")]
public sealed class LlmTipFeedbackController : ControllerBase
{
    private readonly LlmTipFeedbackService _feedbackService;
    private readonly AnalyticsApiKeyAuthService _apiKeyAuth;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<LlmTipFeedbackController> _logger;

    public LlmTipFeedbackController(
        LlmTipFeedbackService feedbackService,
        AnalyticsApiKeyAuthService apiKeyAuth,
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<LlmTipFeedbackController> logger)
    {
        _feedbackService = feedbackService;
        _apiKeyAuth = apiKeyAuth;
        _dbFactory = dbFactory;
        _logger = logger;
    }

    [HttpPost("usage")]
    public async Task<IActionResult> PostUsage(
        [FromBody] LlmTipFeedbackUsageRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await _feedbackService.SaveUsageAsync(request, cancellationToken);
            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_llm_tip_feedback_payload", message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "LLM tips usage feedback ingestion failed");
            return StatusCode(503, new
            {
                error = "llm_tip_feedback_persistence_failed",
                message = "LLM tips usage feedback could not be persisted."
            });
        }
    }

    [HttpPost("tips")]
    public async Task<IActionResult> PostTip(
        [FromBody] LlmTipFeedbackTipRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await _feedbackService.SaveTipAsync(request, cancellationToken);
            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_llm_tip_feedback_payload", message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "LLM tips feedback ingestion failed");
            return StatusCode(503, new
            {
                error = "llm_tip_feedback_persistence_failed",
                message = "LLM tips feedback could not be persisted."
            });
        }
    }

    [HttpGet("tips")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> ListTips(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? category,
        [FromQuery] string? sortBy,
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var auth = await _apiKeyAuth.ValidateAsync(
            analyticsKey ?? "",
            AnalyticsApiKeyScopes.TelemetryRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);

        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");
        if (!auth.ProductId.HasValue)
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                errorCode = "PRODUCT_SELECTOR_REQUIRED",
                message = "This endpoint requires a product-scoped analytics key."
            });

        var result = await _feedbackService.ListTipsAsync(
            auth.ProductId.Value,
            category,
            sortBy,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("admin/tips")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> ListAdminTips(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] DateTime? fromUtc,
        [FromQuery] DateTime? toUtc,
        [FromQuery] string? productId,
        [FromQuery] string? productName,
        [FromQuery] string? appVersion,
        [FromQuery] string? category,
        [FromQuery] string? severity,
        [FromQuery] string? reviewStatus,
        [FromQuery] string? search,
        [FromQuery] int limit = 50,
        [FromQuery] int offset = 0,
        [FromQuery] string? sortBy = "occurrenceCount",
        [FromQuery] string? sortDir = "desc",
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");
        var resolvedProduct = await ResolveProductAsync(auth, productId, productName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        try
        {
            var result = await _feedbackService.ListAdminTipsAsync(new LlmTipFeedbackAdminQuery
            {
                ProductId = resolvedProduct.ProductId,
                FromUtc = fromUtc,
                ToUtc = toUtc,
                AppVersion = appVersion,
                Category = category,
                Severity = severity,
                ReviewStatus = reviewStatus,
                Search = search,
                Limit = limit,
                Offset = offset,
                SortBy = sortBy,
                SortDir = sortDir,
                Days = 0
            }, cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("admin/tips/{idOrContentHash}")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> GetAdminTipDetail(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        string idOrContentHash,
        [FromQuery] string? productId,
        [FromQuery] string? productName,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");
        var resolvedProduct = await ResolveProductAsync(auth, productId, productName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        var result = await _feedbackService.GetTipDetailAsync(idOrContentHash, resolvedProduct.ProductId, cancellationToken);
        return result == null ? NotFound() : Ok(result);
    }

    [HttpGet("admin/stats")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> GetAdminStats(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] DateTime? fromUtc,
        [FromQuery] DateTime? toUtc,
        [FromQuery] string? productId,
        [FromQuery] string? productName,
        [FromQuery] string? appVersion,
        [FromQuery] string? category,
        [FromQuery] string? severity,
        [FromQuery] string? reviewStatus,
        [FromQuery] string? search,
        [FromQuery] int days = 30,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");
        var resolvedProduct = await ResolveProductAsync(auth, productId, productName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        try
        {
            var result = await _feedbackService.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery
            {
                ProductId = resolvedProduct.ProductId,
                FromUtc = fromUtc,
                ToUtc = toUtc,
                AppVersion = appVersion,
                Category = category,
                Severity = severity,
                ReviewStatus = reviewStatus,
                Search = search,
                Days = days,
                Take = 10,
                Limit = 10,
                SortBy = "occurrenceCount",
                SortDir = "desc"
            }, cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPatch("admin/tips/review-status")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> UpdateAdminReviewStatus(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? productId,
        [FromQuery] string? productName,
        [FromBody] LlmTipFeedbackReviewStatusRequest request,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");
        var resolvedProduct = await ResolveProductAsync(auth, productId, productName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        try
        {
            var updated = await _feedbackService.UpdateReviewStatusAsync(
                request.Id,
                request.ContentHash,
                resolvedProduct.ProductId,
                request.ReviewStatus,
                cancellationToken);

            return updated ? Ok(new { status = "updated" }) : NotFound(new { error = "llm_tip_feedback_tip_not_found" });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("admin/tips/convert-to-bugtrace")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> ConvertAdminTipToBugTrace(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromBody] LlmTipFeedbackBugTraceConversionRequest request,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");
        if (!auth.ProductId.HasValue)
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                errorCode = "PRODUCT_SELECTOR_REQUIRED",
                message = "This endpoint requires a product-scoped analytics key."
            });

        try
        {
            var result = await _feedbackService.ConvertToBugTraceAsync(
                request.Id,
                request.ContentHash,
                auth.ProductId.Value,
                request.Priority,
                request.Type,
                cancellationToken);

            return result == null
                ? NotFound(new { error = "llm_tip_feedback_tip_not_found" })
                : Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "bugtrace_unavailable", message = ex.Message });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    private async Task<AnalyticsApiKeyAuthResult?> AuthenticateAsync(
        string? analyticsKey,
        CancellationToken cancellationToken)
    {
        return await _apiKeyAuth.ValidateAsync(
            analyticsKey ?? "",
            AnalyticsApiKeyScopes.TelemetryRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);
    }

    private async Task<ResolvedProduct> ResolveProductAsync(
        AnalyticsApiKeyAuthResult auth,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        var hasProductId = !string.IsNullOrWhiteSpace(productId);
        var hasProductName = !string.IsNullOrWhiteSpace(productName);
        if (hasProductId && hasProductName)
            return ResolvedProduct.BadRequest("Provide either productId or productName, not both.", "PRODUCT_SELECTOR_AMBIGUOUS");

        if (!hasProductId && !hasProductName)
        {
            if (auth.IsGlobal)
            {
                return ResolvedProduct.BadRequest(
                    "Global analytics keys must provide productId or productName for product-scoped endpoints.",
                    "PRODUCT_SELECTOR_REQUIRED");
            }

            if (!auth.ProductId.HasValue)
                return ResolvedProduct.Forbid("The analytics key is not configured for a product.", "PRODUCT_SCOPE_INVALID");

            return new ResolvedProduct(auth.ProductId.Value, null);
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        Product? requestedProduct;
        if (hasProductId)
        {
            if (!Guid.TryParse(productId, out var parsedProductId))
                return ResolvedProduct.BadRequest("productId must be a valid UUID.", "PRODUCT_ID_INVALID");

            requestedProduct = await db.Products.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == parsedProductId, cancellationToken);
        }
        else
        {
            var normalizedProductName = productName!.Trim();
            var matches = await db.Products.AsNoTracking()
                .Where(p => p.Name.ToLower() == normalizedProductName.ToLower())
                .Take(2)
                .ToListAsync(cancellationToken);

            if (matches.Count > 1)
                return ResolvedProduct.BadRequest("productName matches multiple products. Use productId.", "PRODUCT_NAME_AMBIGUOUS");

            requestedProduct = matches.SingleOrDefault();
        }

        if (requestedProduct == null)
            return ResolvedProduct.NotFound("Requested product was not found.", "PRODUCT_NOT_FOUND");

        if (!auth.IsGlobal && (!auth.ProductId.HasValue || requestedProduct.Id != auth.ProductId.Value))
            return ResolvedProduct.Forbid("The analytics key is scoped to a different product.", "PRODUCT_SCOPE_FORBIDDEN");

        return new ResolvedProduct(requestedProduct.Id, null);
    }

    private sealed record ResolvedProduct(Guid ProductId, IActionResult? Error)
    {
        public static ResolvedProduct BadRequest(string message, string code) =>
            new(Guid.Empty, new BadRequestObjectResult(new { errorCode = code, message }));

        public static ResolvedProduct NotFound(string message, string code) =>
            new(Guid.Empty, new NotFoundObjectResult(new { errorCode = code, message }));

        public static ResolvedProduct Forbid(string message, string code) =>
            new(Guid.Empty, new ObjectResult(new { errorCode = code, message }) { StatusCode = StatusCodes.Status403Forbidden });
    }
}
