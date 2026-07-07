using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/llm-tips-feedback")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("TelemetryAPI")]
public sealed class LlmTipFeedbackController : ControllerBase
{
    private readonly LlmTipFeedbackService _feedbackService;
    private readonly AnalyticsApiKeyAuthService _apiKeyAuth;
    private readonly ILogger<LlmTipFeedbackController> _logger;

    public LlmTipFeedbackController(
        LlmTipFeedbackService feedbackService,
        AnalyticsApiKeyAuthService apiKeyAuth,
        ILogger<LlmTipFeedbackController> logger)
    {
        _feedbackService = feedbackService;
        _apiKeyAuth = apiKeyAuth;
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

        var result = await _feedbackService.ListTipsAsync(
            auth.ProductId,
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
        [FromQuery] Guid? productId,
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
        if (productId.HasValue && productId != auth.ProductId)
            return Forbid();

        try
        {
            var result = await _feedbackService.ListAdminTipsAsync(new LlmTipFeedbackAdminQuery
            {
                ProductId = auth.ProductId,
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
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _feedbackService.GetTipDetailAsync(idOrContentHash, auth.ProductId, cancellationToken);
        return result == null ? NotFound() : Ok(result);
    }

    [HttpGet("admin/stats")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> GetAdminStats(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] DateTime? fromUtc,
        [FromQuery] DateTime? toUtc,
        [FromQuery] Guid? productId,
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
        if (productId.HasValue && productId != auth.ProductId)
            return Forbid();

        try
        {
            var result = await _feedbackService.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery
            {
                ProductId = auth.ProductId,
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
        [FromBody] LlmTipFeedbackReviewStatusRequest request,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var updated = await _feedbackService.UpdateReviewStatusAsync(
                request.Id,
                request.ContentHash,
                auth.ProductId,
                request.ReviewStatus,
                cancellationToken);

            return updated ? Ok(new { status = "updated" }) : NotFound(new { error = "llm_tip_feedback_tip_not_found" });
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
}
