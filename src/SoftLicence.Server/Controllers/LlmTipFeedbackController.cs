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

    /// <summary>
    /// Longest time the server spends storing one received feedback item. It replaces the client
    /// connection token on purpose (TKT-003573): a client that stops waiting after a few seconds must
    /// not make the server drop an event it already received in full.
    /// </summary>
    internal static readonly TimeSpan PersistenceTimeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Non-standard status (nginx convention) recorded when the client closed the connection before
    /// the answer; the client never reads it, it only labels the audit log.
    /// </summary>
    internal const int ClientClosedRequestStatusCode = 499;

    /// <summary>
    /// Public ingestion of one anonymized usage event (for example <c>llm_tip_searched</c>).
    /// </summary>
    /// <param name="request">Usage event validated by <see cref="LlmTipFeedbackService.SaveUsageAsync"/>.</param>
    /// <returns>
    /// 200 with the stored identifier; 400 <c>invalid_llm_tip_feedback_payload</c> for a rejected
    /// payload; 499 without body when the client left before the answer (the event is still stored);
    /// 503 <c>llm_tip_feedback_persistence_failed</c> only for a real storage failure or a server
    /// timeout of <see cref="PersistenceTimeout"/>.
    /// </returns>
    [HttpPost("usage")]
    public Task<IActionResult> PostUsage([FromBody] LlmTipFeedbackUsageRequest request) =>
        IngestAsync(
            token => _feedbackService.SaveUsageAsync(request, token),
            "LLM tips usage feedback ingestion failed",
            "LLM tips usage feedback could not be persisted.");

    /// <summary>
    /// Public ingestion of one anonymized tip, deduplicated by content hash.
    /// </summary>
    /// <param name="request">Tip validated by <see cref="LlmTipFeedbackService.SaveTipAsync"/>.</param>
    /// <returns>Same status contract as <see cref="PostUsage"/>.</returns>
    [HttpPost("tips")]
    public Task<IActionResult> PostTip([FromBody] LlmTipFeedbackTipRequest request) =>
        IngestAsync(
            token => _feedbackService.SaveTipAsync(request, token),
            "LLM tips feedback ingestion failed",
            "LLM tips feedback could not be persisted.");

    /// <summary>
    /// Runs one feedback write under the server deadline and maps its outcome to HTTP (TKT-003573).
    /// </summary>
    /// <param name="save">Write to run; receives the deadline token, never the connection token.</param>
    /// <param name="failureLog">Warning text logged, with the exception, for a real persistence failure.</param>
    /// <param name="failureMessage">Message returned in the 503 body.</param>
    /// <returns>See <see cref="PostUsage"/> for the status contract.</returns>
    /// <remarks>
    /// A client disconnection is not a persistence failure: it is logged at debug level without stack
    /// trace and never answered 503. The 503 is kept for real database errors and for the deadline,
    /// both server-side problems an operator must see.
    /// </remarks>
    private async Task<IActionResult> IngestAsync(
        Func<CancellationToken, Task<LlmTipFeedbackIngestResponse>> save,
        string failureLog,
        string failureMessage)
    {
        using var deadline = new CancellationTokenSource(PersistenceTimeout);
        try
        {
            var result = await save(deadline.Token);
            // HttpContext is null only when the controller is built outside the MVC pipeline (unit tests).
            if (HttpContext?.RequestAborted.IsCancellationRequested == true)
            {
                _logger.LogDebug(
                    "LLM tips feedback {FeedbackId} stored after the client closed the connection.",
                    result.Id);
                return StatusCode(ClientClosedRequestStatusCode);
            }

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_llm_tip_feedback_payload", message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "{FailureLog}", failureLog);
            return StatusCode(503, new
            {
                error = "llm_tip_feedback_persistence_failed",
                message = failureMessage
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
        var auth = await _apiKeyAuth.ValidateForRequestAsync(
            HttpContext,
            analyticsKey,
            AnalyticsApiKeyScopes.TelemetryRead,
            cancellationToken);

        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);
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

    /// <summary>
    /// Admin page of tips for an analytics key with <c>telemetry:read</c>, product resolved from the key or the
    /// selector. <paramref name="shared"/> filters on the administrator sharing decision (TKT-003574).
    /// </summary>
    /// <returns>200 with a paged list; 400 for an invalid period or product selector; 401/403 for the key or product scope.</returns>
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
        [FromQuery] bool? shared,
        [FromQuery] int limit = 50,
        [FromQuery] int offset = 0,
        [FromQuery] string? sortBy = "occurrenceCount",
        [FromQuery] string? sortDir = "desc",
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);
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
                Shared = shared,
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
            return AnalyticsApiKeyHttp.Failure(HttpContext);
        var resolvedProduct = await ResolveProductAsync(auth, productId, productName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        var result = await _feedbackService.GetTipDetailAsync(idOrContentHash, resolvedProduct.ProductId, cancellationToken);
        return result == null ? NotFound() : Ok(result);
    }

    /// <summary>
    /// Admin aggregates of tips over <paramref name="days"/> (or an explicit period), same key and product rules as
    /// <see cref="ListAdminTips"/>, with the same sharing filter and the count of shared tips (TKT-003574).
    /// </summary>
    /// <returns>200 with the overview; 400 for an invalid period or product selector; 401/403 for the key or product scope.</returns>
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
        [FromQuery] bool? shared,
        [FromQuery] int days = 30,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);
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
                Shared = shared,
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
            return AnalyticsApiKeyHttp.Failure(HttpContext);
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

    /// <summary>
    /// Publishes a tip to every client or retracts it (TKT-003574): the API path used by a Claude instance directly or
    /// through the MCP tool <c>set_llm_tip_feedback_sharing</c>.
    /// </summary>
    /// <param name="analyticsKey">Analytics key holding <see cref="AnalyticsApiKeyScopes.LlmTipsShare"/>.</param>
    /// <param name="request">Tip selector, requested state, reason (mandatory for a retraction) and source.</param>
    /// <param name="security">Gives the internal-network whitelist shared with the administration routes.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>
    /// 200 with <see cref="LlmTipFeedbackSharingResult"/> (<c>changed</c> false for a repeat);
    /// 403 <c>INTERNAL_NETWORK_REQUIRED</c> outside the internal network, before the key is even checked;
    /// 401/403 for a missing, invalid or under-scoped key (403 <c>ANALYTICS_SCOPE_REQUIRED</c> names the scope);
    /// 400 <c>invalid_llm_tip_sharing_request</c> for a missing body or selector, unknown source or missing reason;
    /// product selector errors as for the other admin routes; 404 <c>llm_tip_feedback_tip_not_found</c>.
    /// </returns>
    /// <remarks>
    /// The network check comes first on purpose, as for licence-type writes: this route publishes content to every
    /// client, so it must stay unreachable from the Internet even with a stolen key. The actor recorded in the journal
    /// is the key identifier, never the key itself.
    /// </remarks>
    [HttpPost("admin/tips/sharing")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> SetAdminTipSharing(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromBody] LlmTipFeedbackSharingRequest? request,
        [FromServices] SecurityService security,
        CancellationToken cancellationToken = default)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        if (!security.IsWhitelisted(ip))
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                errorCode = "INTERNAL_NETWORK_REQUIRED",
                message = "LLM tip sharing decisions are accepted only from the internal network (the MCP)."
            });

        var auth = await _apiKeyAuth.ValidateForRequestAsync(
            HttpContext,
            analyticsKey,
            AnalyticsApiKeyScopes.LlmTipsShare,
            cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);
        if (request == null)
            return BadRequest(new { error = "invalid_llm_tip_sharing_request", message = "A JSON body is required." });

        var source = string.IsNullOrWhiteSpace(request.Source) ? "api" : request.Source.Trim().ToLowerInvariant();
        if (source is not ("api" or "mcp"))
            return BadRequest(new { error = "invalid_llm_tip_sharing_request", message = "source must be api or mcp." });

        var resolvedProduct = await ResolveProductAsync(auth, request.ProductId, request.ProductName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        try
        {
            var result = await _feedbackService.SetSharingAsync(
                request.Id,
                request.ContentHash,
                resolvedProduct.ProductId,
                request.Shared,
                request.Reason,
                $"analytics-key:{auth.KeyId}",
                source,
                ip,
                cancellationToken);

            return result == null
                ? NotFound(new { error = "llm_tip_feedback_tip_not_found" })
                : Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_llm_tip_sharing_request", message = ex.Message });
        }
    }

    /// <summary>
    /// Public, unauthenticated, read-only snapshot of the tips an administrator shared for one product (TKT-003574),
    /// fetched by T-IA Connect at start-up and when it searches tips.
    /// </summary>
    /// <param name="appName">Product name, 1 to 120 characters, case-insensitive (same rule as ingestion).</param>
    /// <param name="category">Optional category, compared lower-case.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// 200 with <see cref="LlmTipSharedTipsResponse"/> and an <c>ETag</c>; 304 without body when
    /// <c>If-None-Match</c> carries the same ETag; 400 <c>invalid_app_name</c>; 429 past the <c>DocsAPI</c> limit
    /// (30 requests per minute and per public address).
    /// </returns>
    /// <remarks>
    /// Security review (TKT-003574): the route only reads, exposes only the anonymized content an administrator
    /// reviewed and shared (see <see cref="LlmTipSharedTip"/>), answers an unknown product with an empty list so it does
    /// not reveal which names exist, bounds the response to <see cref="LlmTipFeedbackService.MaxSharedTipsPerSnapshot"/>
    /// tips, and is rate-limited per address. The ETag hashes the items only (not <c>generatedAtUtc</c>), so an
    /// unchanged snapshot is answered 304 and costs the client almost nothing. <c>Cache-Control: public, max-age=300</c>
    /// lets intermediaries absorb bursts; a retraction therefore reaches clients within five minutes at most.
    /// </remarks>
    [HttpGet("shared")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("DocsAPI")]
    public async Task<IActionResult> GetSharedTips(
        [FromQuery] string? appName,
        [FromQuery] string? category,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<LlmTipSharedTip> items;
        try
        {
            items = await _feedbackService.ListSharedTipsAsync(appName, category, cancellationToken);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_app_name", message = ex.Message });
        }

        var etag = ComputeSharedTipsETag(items);
        Response.Headers.CacheControl = "public, max-age=300";
        Response.Headers.ETag = etag;
        if (Request.Headers.IfNoneMatch.Any(value => string.Equals(value?.Trim(), etag, StringComparison.Ordinal)))
            return StatusCode(StatusCodes.Status304NotModified);

        return Ok(new LlmTipSharedTipsResponse("1", DateTime.UtcNow, items.Count, items));
    }

    /// <summary>
    /// Strong ETag of a shared-tips snapshot: quoted lower-case hexadecimal SHA-256 of the serialized items. Two
    /// snapshots with the same tips in the same order give the same value, whatever the request time.
    /// </summary>
    /// <param name="items">Snapshot items, already in their stable order.</param>
    /// <returns>The ETag header value, quotes included (RFC 9110).</returns>
    internal static string ComputeSharedTipsETag(IReadOnlyList<LlmTipSharedTip> items)
    {
        var json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(items);
        var hash = System.Security.Cryptography.SHA256.HashData(json);
        return "\"" + Convert.ToHexString(hash).ToLowerInvariant() + "\"";
    }

    /// <summary>
    /// Converts one tip of the caller's product into a BugTrace ticket in that product's project
    /// (TKT-003093). Requires a product-scoped analytics key with telemetry read scope.
    /// </summary>
    /// <remarks>
    /// Responses: 200 with <c>created=true</c> for a new ticket, or <c>created=false</c> and the existing
    /// reference when the tip was already converted; 404 when the tip is unknown for this product;
    /// 409 <c>LLM_TIP_BUGTRACE_PROJECT_NOT_CONFIGURED</c> when no BugTrace project is configured for the
    /// product (no provider call made); 503 <c>bugtrace_unavailable</c> when the T-IA authority is not
    /// configured or its project identity cannot be verified; 502 <c>bugtrace_relay_failed</c> when
    /// BugTrace rejects the ticket or is unreachable. Provider bodies and tokens are never returned.
    /// </remarks>
    /// <param name="analyticsKey">Product-scoped analytics key from the <c>X-Analytics-Key</c> header.</param>
    /// <param name="request">Tip selector (id or content hash) and optional priority and type.</param>
    /// <param name="cancellationToken">Cancels the conversion; a provider mutation may still commit.</param>
    /// <returns>The HTTP result described in the remarks.</returns>
    [HttpPost("admin/tips/convert-to-bugtrace")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
    public async Task<IActionResult> ConvertAdminTipToBugTrace(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromBody] LlmTipFeedbackBugTraceConversionRequest request,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);
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
        catch (LlmTipBugTraceProjectNotConfiguredException ex)
        {
            // A configuration decision, not an outage: refused before any provider call, never rerouted.
            _logger.LogWarning(
                "LLM tip conversion refused: no BugTrace project configured (productId={ProductId}, mappingInvalid={MappingInvalid})",
                ex.ProductId,
                ex.MappingInvalid);
            return Conflict(new
            {
                errorCode = LlmTipBugTraceProjectNotConfiguredException.ErrorCode,
                message = ex.Message
            });
        }
        catch (BugTraceTiaAuthorityException ex)
        {
            _logger.LogWarning(ex, "LLM tip conversion: BugTrace T-IA authority unavailable (reason={Reason})", ex.Reason);
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                error = "bugtrace_unavailable",
                message = "The BugTrace T-IA authority is unavailable.",
                reason = ex.Reason.ToString()
            });
        }
        catch (InvalidOperationException ex)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "bugtrace_unavailable", message = ex.Message });
        }
        catch (HttpRequestException ex)
        {
            // The proxy already logged the sanitized provider status; keep the exception chain here too.
            _logger.LogError(ex, "LLM tip conversion: BugTrace relay failed");
            return StatusCode(StatusCodes.Status502BadGateway, new
            {
                error = "bugtrace_relay_failed",
                message = "BugTrace rejected the ticket or could not be reached; retrying replays the same ticket."
            });
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
        return await _apiKeyAuth.ValidateForRequestAsync(
            HttpContext,
            analyticsKey,
            AnalyticsApiKeyScopes.TelemetryRead,
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
