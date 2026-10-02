using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using System.Text.Json;

namespace SoftLicence.Server.Controllers;

/// <summary>Separates human support, strict legacy tickets and durable report-only authority; credentials stay server-side.</summary>
/// <remarks>SUP actions require configured provider and product binding, an active licence and authoritative customer email. Missing configuration returns503; failed licence/product/customer authority returns403. The dedicated IP limiter allows30 requests/minute including private IPs. Quota capacity returns503 and exhaustion429; provider failures return bounded codes without upstream bodies. Expiration does not restrict support; changed HWID is permitted only within this support family. Caller cancellation propagates.</remarks>
[ApiController]
[Route("api/bugtrace")]
[EnableRateLimiting("BugTraceAPI")]
public class BugTraceController : ControllerBase
{
    private readonly IBugTraceProxyService _bugTrace;
    private readonly IBugTraceAutoReportService _autoReports;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    /// <summary>
    /// Resolves only server-authenticated, product-and-licence-scoped hardware aliases; callers
    /// must still revalidate the returned active seat before granting a manual report capability.
    /// </summary>
    private readonly IHardwareAuthorityAliasResolver _hardwareAuthorityAliases;
    /// <summary>Server-owned product boundary for the configured BugTrace project; empty fails closed for SUP only.</summary>
    private readonly Guid _supportProductId;
    /// <summary>Shared atomic SUP admission state; absent registration fails closed.</summary>
    private readonly BugTraceSupportQuota? _supportQuota;
    private readonly IMemoryCache _cache;
    private readonly ILogger<BugTraceController> _logger;

    /// <summary>
    /// Creates the BugTrace boundary while keeping report-only ingestion separate from support lifecycle access.
    /// </summary>
    /// <remarks>Missing/malformed optional product configuration maps to Guid.Empty; absent quota also disables SUP with503. No provider call or inferred legacy product mapping occurs. Cache is legacy-only; quota must be singleton.</remarks>
    /// <param name="bugTrace">Credential-owning relay for manual support operations.</param>
    /// <param name="autoReports">Durable write-only service for automatic diagnostic reports.</param>
    /// <param name="dbFactory">Factory for short-lived licensing authority contexts.</param>
    /// <param name="hardwareAuthorityAliases">Server-owned compatibility authority for authenticated hardware aliases.</param>
    /// <param name="cache">Process-local limiter state for legacy manual endpoints.</param>
    /// <param name="logger">Sanitized operational telemetry sink.</param>
    /// <param name="supportConfiguration">Maps the server-held BugTrace project to one SoftLicence product; no client fallback.</param>
    /// <param name="supportQuota">Singleton bounded SUP quota and exact replay admission.</param>
    public BugTraceController(
        IBugTraceProxyService bugTrace,
        IBugTraceAutoReportService autoReports,
        IDbContextFactory<LicenseDbContext> dbFactory,
        IHardwareAuthorityAliasResolver hardwareAuthorityAliases,
        IMemoryCache cache,
        ILogger<BugTraceController> logger,
        IConfiguration? supportConfiguration = null,
        BugTraceSupportQuota? supportQuota = null)
    {
        _supportQuota = supportQuota;
        _bugTrace = bugTrace;
        _autoReports = autoReports;
        _dbFactory = dbFactory;
        _hardwareAuthorityAliases = hardwareAuthorityAliases;
        _cache = cache;
        _logger = logger;
        _supportProductId = Guid.TryParseExact(supportConfiguration?["BUGTRACE_SUPPORT_PRODUCT_ID"], "D", out var productId) ? productId : Guid.Empty;
    }

    /// <summary>
    /// Durably accepts an identified automatic crash or error report without granting ticket access.
    /// </summary>
    /// <param name="payload">The closed report-only request envelope.</param>
    /// <param name="ct">Cancels request validation and durable acceptance.</param>
    /// <returns>A typed accepted, rejected, conflict, or throttled response.</returns>
    [HttpPost("auto-report")]
    [EnableRateLimiting("BugTraceAutoReportAPI")]
    [RequestSizeLimit(128 * 1024)]
    public async Task<IActionResult> AutoReport(
        [FromBody] BugTraceAutoReportRequest payload,
        CancellationToken ct)
    {
        var result = await _autoReports.EnqueueAsync(payload, ct);
        if (result.Accepted)
        {
            return Accepted(new BugTraceAutoReportAcceptedResponse(
                BugTraceAutoReportService.Schema,
                result.ReportId,
                "accepted",
                result.Duplicate,
                result.TicketNumber));
        }

        var error = new BugTraceAutoReportErrorResponse(result.ErrorCode ?? "request_rejected");
        return result.ErrorCode switch
        {
            "rate_limited" => StatusCode(StatusCodes.Status429TooManyRequests, error),
            "bugtrace_unavailable" => StatusCode(StatusCodes.Status503ServiceUnavailable, error),
            "report_id_conflict" => Conflict(error),
            "license_invalid" or "license_revoked" or "license_expired" =>
                StatusCode(StatusCodes.Status403Forbidden, error),
            _ => BadRequest(error)
        };
    }

    // -------------------------------------------------------------------------
    // POST /api/bugtrace/submit
    // -------------------------------------------------------------------------
    /// <summary>
    /// Relays one manual support ticket only after project, content, and hardware authority validation.
    /// Keyed requests require direct licence history, one active same-licence seat, or an authenticated
    /// alias revalidated against that seat; missing and sentinel identities fail closed.
    /// </summary>
    /// <param name="payload">Manual support request whose authority fields are never forwarded to BugTrace.</param>
    /// <param name="ct">Cancels licensing reads and the provider relay.</param>
    /// <returns>A bounded validation, throttle, relay, or provider-unavailable HTTP result.</returns>
    [HttpPost("submit")]
    public async Task<IActionResult> Submit([FromBody] BugTraceSubmitRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured)
            return StatusCode(503, new { error = "BugTrace proxy is not configured" });

        if (!ValidateProjectId(payload.ProjectId, out var projectIdError))
            return BadRequest(new { error = projectIdError });

        if (string.IsNullOrWhiteSpace(payload.Ticket?.Title))
            return BadRequest(new { error = "ticket.title is required" });

        if (string.IsNullOrWhiteSpace(payload.Ticket?.Description))
            return BadRequest(new { error = "ticket.description is required" });

        var (valid, validationError) = await ValidateLicenseAsync(
            payload.LicenseKey,
            payload.HardwareId,
            ct);
        if (!valid)
            return BadRequest(new { error = validationError });

        var rateLimitKey = BuildRateLimitKey(payload.LicenseKey, payload.HardwareId);
        if (IsRateLimited(rateLimitKey, limit: 3, windowMinutes: 10))
        {
            _logger.LogWarning("BugTrace submit rate limited.");
            return RateLimitedResult();
        }

        // Manual reports do not need a persisted hardware identifier after authority validation.
        TagAuditLog(payload.LicenseKey, null, "BUGTRACE_SUBMIT");

        try
        {
            var result = await _bugTrace.SubmitTicketAsync(payload.Ticket, ct);
            // Retourner uniquement les champs utiles au client (ticketNumber + id minimum)
            return Ok(result);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "BugTrace submit relay failed");
            return StatusCode(502, new { error = "Failed to reach BugTrace service" });
        }
    }

    // -------------------------------------------------------------------------
    // POST /api/bugtrace/comment
    // -------------------------------------------------------------------------
    [HttpPost("comment")]
    public async Task<IActionResult> Comment([FromBody] BugTraceCommentRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured)
            return StatusCode(503, new { error = "BugTrace proxy is not configured" });

        if (!ValidateProjectId(payload.ProjectId, out var projectIdError))
            return BadRequest(new { error = projectIdError });

        if (string.IsNullOrWhiteSpace(payload.TicketNumber))
            return BadRequest(new { error = "ticketNumber is required" });

        if (string.IsNullOrWhiteSpace(payload.Content))
            return BadRequest(new { error = "content is required" });

        var (valid, validationError, license) = await ValidateRequiredLicenseAsync(payload.LicenseKey, payload.HardwareId);
        if (!valid)
            return BadRequest(new { error = validationError });

        var rateLimitKey = BuildRateLimitKey(payload.LicenseKey, payload.HardwareId);
        if (IsRateLimited(rateLimitKey, limit: 10, windowMinutes: 10))
        {
            _logger.LogWarning("BugTrace comment rate limited for key={Key}", rateLimitKey);
            return RateLimitedResult();
        }

        TagAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_COMMENT");

        try
        {
            var (ownsTicket, ownershipError) = await TicketBelongsToLicenseAsync(payload.TicketNumber, license!, ct);
            if (!ownsTicket)
                return StatusCode(403, new { error = ownershipError });

            var commentBody = new
            {
                content = payload.Content,
                authorName = string.IsNullOrWhiteSpace(payload.AuthorName) ? license!.CustomerName : payload.AuthorName,
                authorEmail = license!.CustomerEmail
            };
            var result = await _bugTrace.AddCommentAsync(payload.TicketNumber, commentBody, ct);
            return Ok(result);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "BugTrace comment relay failed for ticket {TicketNumber}", payload.TicketNumber);
            return StatusCode(502, new { error = "Failed to reach BugTrace service" });
        }
    }

    // -------------------------------------------------------------------------
    // GET /api/bugtrace/tickets?email=...&licenseKey=...&hardwareId=...&projectId=...
    // -------------------------------------------------------------------------
    [HttpGet("tickets")]
    public async Task<IActionResult> GetTickets(
        [FromQuery] string email,
        [FromQuery] string? licenseKey,
        [FromQuery] string? hardwareId,
        [FromQuery] string projectId,
        CancellationToken ct)
    {
        return await GetTicketsCore(email, licenseKey, hardwareId, projectId, ct);
    }

    // -------------------------------------------------------------------------
    // POST /api/bugtrace/tickets
    // Body: { email, licenseKey, hardwareId, projectId }
    // -------------------------------------------------------------------------
    [HttpPost("tickets")]
    public async Task<IActionResult> PostTickets([FromBody] BugTraceTicketsRequest payload, CancellationToken ct)
    {
        if (payload == null)
            return BadRequest(new { error = "request body is required" });

        return await GetTicketsCore(
            payload.Email,
            payload.LicenseKey,
            payload.HardwareId,
            payload.ProjectId,
            ct);
    }

    private async Task<IActionResult> GetTicketsCore(
        string email,
        string? licenseKey,
        string? hardwareId,
        string projectId,
        CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured)
            return StatusCode(503, new { error = "BugTrace proxy is not configured" });

        if (!ValidateProjectId(projectId, out var projectIdError))
            return BadRequest(new { error = projectIdError });

        if (string.IsNullOrWhiteSpace(email))
            return BadRequest(new { error = "email is required" });

        var (valid, validationError, license) = await ValidateLicenseWithEmailAsync(licenseKey, hardwareId, email);
        if (!valid)
        {
            LogTicketsValidationFailure(validationError, email, hardwareId, licenseKey);
            if (IsClientContractError(validationError))
                return BadRequest(new { error = validationError });

            return StatusCode(403, new { error = validationError });
        }

        TagAuditLog(licenseKey, hardwareId, "BUGTRACE_TICKETS");

        try
        {
            var result = await _bugTrace.GetTicketsByEmailAsync(email, ct);
            return Ok(result);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "BugTrace tickets relay failed for email (redacted)");
            return StatusCode(502, new { error = "Failed to reach BugTrace service" });
        }
    }

    // -------------------------------------------------------------------------
    // GET /api/bugtrace/tickets/{ticketNumber}/comments
    // -------------------------------------------------------------------------
    [HttpGet("tickets/{ticketNumber}/comments")]
    public async Task<IActionResult> GetTicketComments(
        string ticketNumber,
        [FromQuery(Name = "licenseKey")] string? queryLicenseKey,
        [FromHeader(Name = "X-License-Key")] string? headerLicenseKey,
        [FromQuery] string? hardwareId,
        [FromQuery] string projectId,
        CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured)
            return StatusCode(503, new { error = "BugTrace proxy is not configured" });

        if (!ValidateProjectId(projectId, out var projectIdError))
            return BadRequest(new { error = projectIdError });

        if (string.IsNullOrWhiteSpace(ticketNumber))
            return BadRequest(new { error = "ticketNumber is required" });

        var (licenseKey, credentialError) = ResolveLicenseKeyCredential(queryLicenseKey, headerLicenseKey);
        if (credentialError != null)
            return BadRequest(new { error = credentialError });

        var (valid, validationError, license) = await ValidateRequiredLicenseAsync(licenseKey, hardwareId);
        if (!valid)
            return BadRequest(new { error = validationError });

        TagAuditLog(licenseKey, hardwareId, "BUGTRACE_COMMENTS");

        try
        {
            var (ownsTicket, ownershipError) = await TicketBelongsToLicenseAsync(ticketNumber, license!, ct);
            if (!ownsTicket)
                return StatusCode(403, new { error = ownershipError });

            var result = await _bugTrace.GetTicketCommentsAsync(ticketNumber, ct);
            return Ok(result);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "BugTrace comments relay failed for ticket {TicketNumber}", ticketNumber);
            return StatusCode(502, new { error = "Failed to reach BugTrace service" });
        }
    }

    /// <summary>
    /// Resolves the licence credential without forcing desktop clients to expose it in the URL.
    /// </summary>
    /// <remarks>
    /// The header is canonical when present. The legacy query parameter remains supported, but
    /// supplying two different trimmed values is rejected to avoid ambiguous authentication.
    /// </remarks>
    private static (string? licenseKey, string? error) ResolveLicenseKeyCredential(
        string? queryLicenseKey,
        string? headerLicenseKey)
    {
        var normalizedQuery = string.IsNullOrWhiteSpace(queryLicenseKey) ? null : queryLicenseKey.Trim();
        var normalizedHeader = string.IsNullOrWhiteSpace(headerLicenseKey) ? null : headerLicenseKey.Trim();

        if (normalizedQuery != null
            && normalizedHeader != null
            && !string.Equals(normalizedQuery, normalizedHeader, StringComparison.Ordinal))
        {
            return (null, "Conflicting license credentials");
        }

        return (normalizedHeader ?? normalizedQuery, null);
    }

    // -------------------------------------------------------------------------
    // Dedicated Desktop SupportCase proxy. These routes deliberately keep the
    // legacy Ticket authentication and behavior unchanged.
    // -------------------------------------------------------------------------

    /// <summary>Creates or replays one authenticated customer-owned support case.</summary>
    /// <param name="payload">Licence/HWID/project and matching reporter; title up to240 and description up to50000 UTF-16 units, at most5 canonical distinct attachment UUIDs.</param>
    /// <param name="ct">Cancels outbound work; an ambiguous cancellation may leave a provider-created case.</param>
    /// <returns>201 with the provider receipt, including replay;400 for invalid fields/header,403 for authority refusal,429 for quota, or a bounded provider failure.</returns>
    /// <remarks>Requires an exact printable ASCII Idempotency-Key header of16–128 characters. Three distinct creates/10min per licence; exact key/payload replay is admitted, changed payload conflicts409. Server selects reporter/sourceDESKTOP. JSON envelope512KiB; provider response2MiB/40s. Reuse the same key after an ambiguous response; no automatic retry occurs.</remarks>
    [HttpPost("support-cases")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> CreateSupportCase([FromBody] BugTraceSupportCaseCreateRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        if (!ValidateProjectId(payload.ProjectId, out var projectError)) return BadRequest(new { error = projectError });
        var (valid, error, license) = await ValidateSupportIdentityAsync(payload.LicenseKey, payload.HardwareId, payload.ReporterEmail);
        if (!valid) return StatusCode(403, new { error });
        if (payload.SupportCase == null || string.IsNullOrWhiteSpace(payload.SupportCase.Title) || string.IsNullOrWhiteSpace(payload.SupportCase.Description))
            return BadRequest(new { error = "supportCase title and description are required" });
        if (payload.SupportCase.Title.Length > 240 || payload.SupportCase.Description.Length > 50_000
            || !ValidSupportAttachments(payload.SupportCase.AttachmentIds))
            return BadRequest(new { error = "support_content_invalid" });
        var key = Request.Headers["Idempotency-Key"].ToString();
        if (!ValidSupportIdempotencyKey(key))
            return BadRequest(new { error = "A valid Idempotency-Key is required" });

        try
        {
            _supportQuota!.Admit(license!.Id, "create", 3, key, JsonSerializer.Serialize(payload.SupportCase));
            TagSupportAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUPPORT_CREATE");
            return StatusCode(201, await _bugTrace.CreateSupportCaseAsync(new
            {
                title = payload.SupportCase.Title,
                description = payload.SupportCase.Description,
                reporterEmail = license!.CustomerEmail,
                category = payload.SupportCase.Category,
                priority = payload.SupportCase.Priority,
                source = "DESKTOP",
                attachmentIds = payload.SupportCase.AttachmentIds
            }, key, ct));
        }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    /// <summary>Lists a bounded customer-owned support history.</summary>
    /// <param name="payload">Licence identity and matching reporter; limit is clamped to1–200 and offset to0–100000.</param>
    /// <param name="ct">Cancels the provider page read.</param>
    /// <returns>200 with the public provider page,403 for authority refusal, or a bounded quota/provider failure.</returns>
    /// <remarks>The server derives the owner filter from the licence email. Sixty reads/10min per licence; JSON response2MiB and deadline40s. The page is not a complete-history or ownership proof by itself; callers must honor total/offset. No provider mutation or retry occurs.</remarks>
    [HttpPost("support-cases/list")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> ListSupportCases([FromBody] BugTraceSupportCaseListRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        if (!ValidateProjectId(payload.ProjectId, out var projectError)) return BadRequest(new { error = projectError });
        var (valid, error, license) = await ValidateSupportIdentityAsync(payload.LicenseKey, payload.HardwareId, payload.ReporterEmail);
        if (!valid) return StatusCode(403, new { error });
        TagSupportAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUPPORT_LIST");
        try
        {
            _supportQuota!.Admit(license!.Id, "list", 60);
            return Ok(await _bugTrace.ListSupportCasesAsync(license.CustomerEmail, Math.Clamp(payload.Limit, 1, 200), ct, Math.Clamp(payload.Offset, 0, 100000)));
        }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    /// <summary>Stages one bounded customer attachment; the provider verifies content and binding.</summary>
    /// <param name="licenseKey">Established plaintext licence key; encrypted/unknown/inactive/foreign-product authority is rejected.</param>
    /// <param name="hardwareId">Nonempty current HWID; it is not reporter authority.</param>
    /// <param name="projectId">Public project identifier matching server configuration.</param>
    /// <param name="reporterEmail">Claim that must match the licence customer; server supplies the actual provider reporter.</param>
    /// <param name="file">Nonempty multipart file up to40MiB; basename up to180 characters without controls or separators; MIME text up to128 characters.</param>
    /// <param name="ct">Cancels hashing and transport; staged provider state may survive an ambiguous cancellation.</param>
    /// <returns>201 staged receipt;400 invalid input,413 size refusal,409 conflicting replay, or bounded authority/quota/provider errors.</returns>
    /// <remarks>Request envelope41MiB. Exact Idempotency-Key header16–128 printable ASCII characters. Thirty attempts/10min are reserved before hashing; ten distinct uploads/10min, with replay bound to filename/MIME/content digest. Streams are request-owned and disposed. Provider enforces antivirus, TTL, aggregate size and project/reporter attachment binding; staging alone does not attach a file to a case.</remarks>
    [HttpPost("support-cases/attachments")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(41L * 1024 * 1024)]
    public async Task<IActionResult> StageSupportAttachment(
        [FromForm] string? licenseKey,
        [FromForm] string? hardwareId,
        [FromForm] string projectId,
        [FromForm] string reporterEmail,
        [FromForm] IFormFile file,
        CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        if (!ValidateProjectId(projectId, out var projectError)) return BadRequest(new { error = projectError });
        var (valid, error, license) = await ValidateSupportIdentityAsync(licenseKey, hardwareId, reporterEmail);
        if (!valid) return StatusCode(403, new { error });
        TagSupportAuditLog(licenseKey, hardwareId, "BUGTRACE_SUPPORT_ATTACHMENT_STAGE");
        var key = Request.Headers["Idempotency-Key"].ToString();
        if (file == null || file.Length <= 0 || !ValidSupportIdempotencyKey(key)
            || string.IsNullOrEmpty(file.FileName) || file.FileName.Length > 180
            || file.FileName.Any(character => char.IsControl(character) || character is '/' or '\\')
            || file.ContentType.Length > 128)
            return BadRequest(new { error = "A file and valid Idempotency-Key are required" });
        try
        {
            if (file.Length > 40L * 1024 * 1024) return StatusCode(413, new { error = "attachment_too_large" });
            _supportQuota!.Admit(license!.Id, "upload-attempt", 30);
            await using var input = file.OpenReadStream();
            var hash = await System.Security.Cryptography.SHA256.HashDataAsync(input, ct);
            _supportQuota.Admit(license.Id, "upload", 10, key,
                JsonSerializer.Serialize(new { file.FileName, file.ContentType, digest = Convert.ToHexString(hash) }));
            return StatusCode(201, await _bugTrace.StageSupportAttachmentAsync(file, license.CustomerEmail, key, ct));
        }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    /// <summary>Reads a public conversation only after a complete owner lookup.</summary>
    /// <param name="supportNumber">Exact uppercase SUP- plus six ASCII digits; alternate spellings fail400.</param>
    /// <param name="payload">Licence/HWID/project authority envelope.</param>
    /// <param name="ct">Cancels ownership lookup and the subsequent provider read.</param>
    /// <returns>200 public conversation after owner match;403 absent,502 malformed page,503 incomplete lookup,504 deadline, or bounded provider error.</returns>
    /// <remarks>Ownership reserves one of60 lookups/10min and reads200-item pages through offset100000 with a40s total lookup deadline. The subsequent conversation read has its own40s/2MiB bound. Concurrent list drift may deny legitimate access; it never grants access without exact reference and reporter match.</remarks>
    [HttpPost("support-cases/{supportNumber}/detail")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> GetSupportCase(string supportNumber, [FromBody] BugTraceSupportIdentityRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        var ownership = await AuthorizeOwnedSupportCaseAsync(supportNumber, payload, ct);
        if (ownership.Error != null) return ownership.Error;
        TagSupportAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUPPORT_DETAIL");
        try { return Ok(await _bugTrace.GetSupportCaseAsync(supportNumber, ct)); }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    /// <summary>Posts a bounded human reply to an owned case.</summary>
    /// <param name="supportNumber">Canonical SUP reference belonging to the licence customer.</param>
    /// <param name="payload">Authority envelope, content1–50000 UTF-16 units and up to5 distinct canonical attachment UUIDs.</param>
    /// <param name="ct">Cancels lookup/send; provider-accepted messages may survive cancellation.</param>
    /// <returns>201 message receipt;400 invalid content,403 ownership refusal, or bounded quota/provider errors.</returns>
    /// <remarks>Ownership precedes the ten-message/10min reservation. Server sends customer content, never operator identity. No idempotency header or automatic retry: ambiguous outcomes require readback before resending. Provider validates attachment binding. Request512KiB; response2MiB/40s after bounded lookup.</remarks>
    [HttpPost("support-cases/{supportNumber}/messages")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> AddSupportCaseMessage(string supportNumber, [FromBody] BugTraceSupportCaseMessageRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        var ownership = await AuthorizeOwnedSupportCaseAsync(supportNumber, payload, ct);
        if (ownership.Error != null) return ownership.Error;
        TagSupportAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUPPORT_MESSAGE");
        if (string.IsNullOrWhiteSpace(payload.Content) || payload.Content.Length > 50_000 || !ValidSupportAttachments(payload.AttachmentIds)) return BadRequest(new { error = "content is required" });
        try { _supportQuota!.Admit(ownership.License!.Id, "message", 10); return StatusCode(201, await _bugTrace.AddSupportCaseMessageAsync(supportNumber, new { content = payload.Content, attachmentIds = payload.AttachmentIds }, ct)); }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    /// <summary>Resolves an owned case without granting legacy ticket authority.</summary>
    /// <param name="supportNumber">Canonical customer-owned SUP reference.</param>
    /// <param name="payload">Licence/HWID/project authority envelope.</param>
    /// <param name="ct">Cancels lookup/PATCH without rollback of provider state.</param>
    /// <returns>200 provider lifecycle projection after ownership proof, or bounded authority/quota/provider errors.</returns>
    /// <remarks>Ten resolution attempts/10min after ownership admission; provider PATCH owns transitions and409 conflicts. No automatic retry. Response2MiB/40s after independently bounded lookup; legacy Ticket authority is not granted.</remarks>
    [HttpPost("support-cases/{supportNumber}/resolve")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> ResolveSupportCase(string supportNumber, [FromBody] BugTraceSupportIdentityRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        var ownership = await AuthorizeOwnedSupportCaseAsync(supportNumber, payload, ct);
        if (ownership.Error != null) return ownership.Error;
        TagSupportAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUPPORT_RESOLVE");
        try { _supportQuota!.Admit(ownership.License!.Id, "resolve", 10); return Ok(await _bugTrace.ResolveSupportCaseAsync(supportNumber, ct)); }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    /// <summary>Downloads a canonical attachment only within an owned case.</summary>
    /// <param name="supportNumber">Canonical customer-owned SUP reference.</param>
    /// <param name="attachmentId">Exact lowercase hyphenated UUID; invalid forms fail400 before lookup.</param>
    /// <param name="payload">Licence/HWID/project authority envelope.</param>
    /// <param name="ct">Cancels lookup/download; partial upstream bytes are discarded.</param>
    /// <returns>Attachment response up to40MiB, neutralized basename and allowlisted MIME, or bounded errors.</returns>
    /// <remarks>Ownership precedes the20-download/10min reservation; provider must also bind UUID to case. Binary read deadline40s after bounded lookup. No filesystem path is accepted or written. no-store/nosniff and attachment disposition constrain caching/content interpretation.</remarks>
    [HttpPost("support-cases/{supportNumber}/attachments/{attachmentId}/download")]
    [EnableRateLimiting("BugTraceSupportAPI")]
    [RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> DownloadSupportAttachment(string supportNumber, string attachmentId, [FromBody] BugTraceSupportIdentityRequest payload, CancellationToken ct)
    {
        if (!_bugTrace.IsConfigured || _supportProductId == Guid.Empty || _supportQuota == null) return StatusCode(503, new { error = "BugTrace proxy is not configured" });
        if (!IsCanonicalAttachmentId(attachmentId)) return BadRequest(new { error = "Invalid attachment reference" });
        var ownership = await AuthorizeOwnedSupportCaseAsync(supportNumber, payload, ct);
        if (ownership.Error != null) return ownership.Error;
        TagSupportAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUPPORT_ATTACHMENT_DOWNLOAD");
        try
        {
            _supportQuota!.Admit(ownership.License!.Id, "download", 20);
            Response.Headers.CacheControl = "no-store";
            Response.Headers["X-Content-Type-Options"] = "nosniff";
            var download = await _bugTrace.DownloadSupportAttachmentAsync(supportNumber, attachmentId, ct);
            return File(download.Content, download.ContentType, download.FileName);
        }
        catch (BugTraceSupportException ex) { return SupportFailure(ex); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "support_unavailable" }); }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>Checks the configured public project identifier without inferring licence or token authority.</summary>
    private bool ValidateProjectId(string projectId, out string error)
    {
        if (string.IsNullOrWhiteSpace(projectId))
        {
            error = "projectId is required";
            return false;
        }

        if (!string.Equals(projectId, _bugTrace.ExpectedProjectId, StringComparison.OrdinalIgnoreCase))
        {
            error = "Invalid projectId";
            return false;
        }

        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Authenticates human support by active licence and exact reporter ownership.
    /// A changed HWID is accepted only on this dedicated, rate-limited support family
    /// so a customer can report the identity problem itself; legacy Ticket routes remain strict.
    /// </summary>
    /// <returns>Validated licence or fixed public refusal string; no provider call or licence mutation.</returns>
    /// <remarks>Key length256, trimmed/uppercased before exact DB lookup; encrypted keys rejected. HWID length256, nonempty and not unknown, never reporter authority. Product must match configured nonempty UUID and licence must be active with customer email. Optional reporter comparison trims only the claim, ordinal-ignore-case. Expiration is deliberately not checked; Website support is a separate licence-independent journey. DB errors propagate; this helper does not accept cancellation.</remarks>
    private async Task<(bool Valid, string Error, Data.License? License)> ValidateSupportIdentityAsync(
        string? licenseKey,
        string? hardwareId,
        string? reporterEmail = null)
    {
        if (string.IsNullOrWhiteSpace(licenseKey) || licenseKey.Length > 256 || IsEncryptedLicenseKey(licenseKey))
            return (false, "A valid license is required", null);
        if (string.IsNullOrWhiteSpace(hardwareId) || hardwareId.Length > 256 || string.Equals(hardwareId, "unknown", StringComparison.OrdinalIgnoreCase))
            return (false, "A valid hardware identity is required", null);

        await using var db = await _dbFactory.CreateDbContextAsync();
        var license = await db.Licenses.FirstOrDefaultAsync(item => item.LicenseKey == licenseKey.Trim().ToUpperInvariant());
        // Support eligibility does not depend on expiration. The Desktop shell controls access to its page; Website support uses its own authority.
        if (_supportProductId == Guid.Empty || license == null || license.ProductId != _supportProductId
            || !license.IsActive || string.IsNullOrWhiteSpace(license.CustomerEmail))
            return (false, "A valid active license is required", null);
        if (reporterEmail != null && !string.Equals(license.CustomerEmail, reporterEmail.Trim(), StringComparison.OrdinalIgnoreCase))
            return (false, "Reporter does not match the license customer", null);

        if (!string.IsNullOrWhiteSpace(license.HardwareId) && !string.Equals(license.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase))
            _logger.LogWarning("Human support request accepted with a mismatched hardware identity for an active licence (identities redacted)");
        return (true, string.Empty, license);
    }

    /// <summary>Paginates owner-filtered results within a forty-second deadline; incomplete lookup fails closed.</summary>
    /// <returns>Null Error plus authoritative licence only for exact SUP/reporter match; otherwise fixed400/403/429/502/503/504 and no licence.</returns>
    /// <remarks>Reserves one of60 per-licence lookups/10min. Pages require numeric total/offset and object items; offset must match the request. Incomplete pages fail closed. Total lookup deadline40s and offset100000 ceiling bound work. No cache or provider mutation. Caller cancellation propagates.</remarks>
    private async Task<(IActionResult? Error, Data.License? License)> AuthorizeOwnedSupportCaseAsync(
        string supportNumber,
        BugTraceSupportIdentityRequest payload,
        CancellationToken ct)
    {
        if (!ValidateProjectId(payload.ProjectId, out var projectError)) return (BadRequest(new { error = projectError }), null);
        if (!IsCanonicalReference(supportNumber, "SUP-")) return (BadRequest(new { error = "Invalid support reference" }), null);
        var identity = await ValidateSupportIdentityAsync(payload.LicenseKey, payload.HardwareId);
        if (!identity.Valid) return (StatusCode(403, new { error = identity.Error }), null);
        try
        {
            _supportQuota!.Admit(identity.License!.Id, "ownership", 60);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(40));
            for (var offset = 0; offset <= 100000; offset += 200)
            {
                var list = await _bugTrace.ListSupportCasesAsync(identity.License.CustomerEmail, 200, deadline.Token, offset);
                if (!list.TryGetProperty("total", out var total) || total.ValueKind != JsonValueKind.Number || !total.TryGetInt32(out var count)
                    || !list.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array
                    || count < 0 || items.GetArrayLength() > 200
                    || items.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.Object)
                    || !list.TryGetProperty("offset", out var pageOffset) || pageOffset.ValueKind != JsonValueKind.Number
                    || !pageOffset.TryGetInt32(out var actualOffset) || actualOffset != offset)
                    return (StatusCode(502, new { error = "support_invalid_response" }), null);
                if (ContainsSupportNumber(list, supportNumber, identity.License.CustomerEmail)) return (null, identity.License);
                if (offset + items.GetArrayLength() >= count)
                    return (StatusCode(403, new { error = "Support request does not belong to the license customer" }), null);
                if (items.GetArrayLength() != 200)
                    return (StatusCode(503, new { error = "support_ownership_incomplete" }), null);
            }
            return (StatusCode(503, new { error = "support_ownership_incomplete" }), null);
        }
        catch (BugTraceSupportException ex) { return (SupportFailure(ex), null); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return (StatusCode(504, new { error = "support_timeout" }), null); }
        catch (HttpRequestException)
        { return (StatusCode(502, new { error = "support_unavailable" }), null); }
    }

    /// <summary>Returns only server-selected failure fields and bounded retry guidance.</summary>
    /// <returns>Selected status/code and optional bounded numeric Retry-After; never exception details or upstream content.</returns>
    private IActionResult SupportFailure(BugTraceSupportException failure)
    {
        if (failure.RetryAfterSeconds is int seconds) Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return StatusCode(failure.Status, new { error = failure.Code });
    }

    /// <summary>Matches a case reference exactly within the provider's owner-filtered page.</summary>
    /// <remarks>Caller has validated every item is an object. Reference is ordinal; reporter is ordinal-ignore-case against licence email. Missing or non-string fields cannot match. No trimming or authority inference.</remarks>
    private static bool ContainsSupportNumber(JsonElement result, string supportNumber, string email)
    {
        if (!result.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array) return false;
        return items.EnumerateArray().Any(item => item.TryGetProperty("supportNumber", out var value)
            && value.ValueKind == JsonValueKind.String && string.Equals(value.GetString(), supportNumber, StringComparison.Ordinal)
            && item.TryGetProperty("reporterEmail", out var reporter) && reporter.ValueKind == JsonValueKind.String
            && string.Equals(reporter.GetString(), email, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Validates opaque header bytes without trimming, case folding or accepting control characters.</summary>
    private static bool ValidSupportIdempotencyKey(string key) => key.Length is >= 16 and <= 128
        && key.All(character => character is >= '!' and <= '~' && character != ',');

    /// <summary>Accepts at most five distinct canonical provider attachment identifiers.</summary>
    private static bool ValidSupportAttachments(List<string>? ids) => ids == null ||
        (ids.Count <= 5 && ids.All(IsCanonicalAttachmentId) && ids.Distinct(StringComparer.Ordinal).Count() == ids.Count);

    /// <summary>Requires the provider's lowercase hyphenated UUID wire form; no alternate route spellings.</summary>
    private static bool IsCanonicalAttachmentId(string? value) => Guid.TryParseExact(value, "D", out var id)
        && string.Equals(id.ToString("D"), value, StringComparison.Ordinal);

    /// <summary>Accepts only the provider's fixed-width ASCII support or ticket number.</summary>
    private static bool IsCanonicalReference(string value, string prefix) =>
        value?.Length == 10 && value.StartsWith(prefix, StringComparison.Ordinal)
        && value[prefix.Length..].All(character => character is >= '0' and <= '9');

    /// <summary>
    /// Validates the manual report authority without exposing or rewriting a hardware identifier.
    /// A keyed request requires a concrete hardware identifier matching the licence's direct
    /// historical identity, an active same-licence seat, or an authenticated alias that resolves
    /// to an active same-licence seat. A licence key alone never grants submission authority, and
    /// keyed missing, empty, whitespace-only, or <c>unknown</c> identifiers fail closed. The
    /// unkeyed legacy report-only mode continues to accept <c>unknown</c> but still requires the
    /// hardware field to be present.
    /// </summary>
    /// <param name="licenseKey">Opaque licence key used only to select one active licence boundary.</param>
    /// <param name="hardwareId">
    /// Exact client hardware identifier. The <c>unknown</c> sentinel is valid only for unkeyed
    /// legacy reports and is rejected whenever <paramref name="licenseKey"/> is present.
    /// </param>
    /// <param name="cancellationToken">Cancels database and alias authority reads.</param>
    /// <returns>A bounded validation result whose error never exposes authority identifiers.</returns>
    private async Task<(bool valid, string error)> ValidateLicenseAsync(
        string? licenseKey,
        string? hardwareId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(licenseKey))
        {
            // The legacy unkeyed channel requires the field but preserves its historical unknown sentinel.
            if (string.IsNullOrWhiteSpace(hardwareId))
                return (false, "hardwareId is required when licenseKey is absent");

            return (true, string.Empty);
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var license = await db.Licenses
            .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey.ToUpperInvariant(), cancellationToken);

        if (license == null)
            return (false, "Invalid license");

        if (!license.IsActive)
            return (false, "License is revoked");

        if (string.IsNullOrWhiteSpace(hardwareId)
            || string.Equals(hardwareId, "unknown", StringComparison.OrdinalIgnoreCase))
            return (false, "Hardware ID mismatch");

        if (!string.IsNullOrEmpty(license.HardwareId)
            && string.Equals(license.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase))
            return (true, string.Empty);

        // Exact persisted HWIDs are canonical machine identifiers. Keeping the indexed equality
        // avoids culture-dependent rewrites and proves that only one same-license seat authorizes relay.
        var activeSeatMatches = await db.LicenseSeats
            .AsNoTracking()
            .Where(seat => seat.LicenseId == license.Id
                && seat.IsActive
                && seat.HardwareId == hardwareId)
            .Take(2)
            .Select(seat => seat.Id)
            .ToListAsync(cancellationToken);
        if (activeSeatMatches.Count == 1)
            return (true, string.Empty);
        if (activeSeatMatches.Count > 1)
            return (false, "Hardware ID mismatch");

        var resolution = await _hardwareAuthorityAliases.ResolveAsync(
            db,
            license.ProductId,
            license.Id,
            hardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck,
            cancellationToken);
        if (resolution.Status != HardwareAuthorityResolutionStatus.Resolved
            || !resolution.LicenseSeatId.HasValue)
            return (false, "Hardware ID mismatch");

        // Treat resolver output as evidence, not authorization by itself. The consuming boundary
        // re-proves ownership and active state so stale or adversarial results fail closed.
        var resolvedSeatIsActive = await db.LicenseSeats
            .AsNoTracking()
            .AnyAsync(seat => seat.Id == resolution.LicenseSeatId.Value
                && seat.LicenseId == license.Id
                && seat.IsActive
                && seat.HardwareId == resolution.EffectiveHardwareId,
                cancellationToken);
        if (!resolvedSeatIsActive)
            return (false, "Hardware ID mismatch");

        return (true, string.Empty);
    }

    /// <summary>
    /// Comme ValidateLicenseAsync + verifie que l'email correspond a la licence si disponible.
    /// </summary>
    private async Task<(bool valid, string error, Data.License? license)> ValidateLicenseWithEmailAsync(
        string? licenseKey, string? hardwareId, string email)
    {
        var (valid, error, license) = await ValidateRequiredLicenseAsync(licenseKey, hardwareId, email);
        if (!valid)
            return (false, error, null);

        // Verification email : si la licence a un email enregistre, l'email demande doit correspondre
        if (string.IsNullOrWhiteSpace(license!.CustomerEmail))
            return (false, "License has no customer email", null);

        if (!string.Equals(license.CustomerEmail, email, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Email does not match the license", null);
        }

        return (true, string.Empty, license);
    }

    /// <summary>
    /// Valide une licence obligatoire. Les endpoints de lecture/commentaires ne
    /// peuvent pas utiliser le mode degrade hardwareId seul.
    /// </summary>
    private async Task<(bool valid, string error, Data.License? license)> ValidateRequiredLicenseAsync(
        string? licenseKey, string? hardwareId, string? email = null)
    {
        if (string.IsNullOrWhiteSpace(licenseKey))
            return (false, "licenseKey is required for this operation", null);

        await using var db = await _dbFactory.CreateDbContextAsync();
        Data.License? license;
        if (IsEncryptedLicenseKey(licenseKey))
        {
            license = await FindLicenseByEncryptedClientContextAsync(db, email, hardwareId);
            if (license == null)
                return (false, "Invalid encrypted license context", null);
        }
        else
        {
            license = await db.Licenses
                .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey.Trim().ToUpperInvariant());
        }

        if (license == null)
            return (false, "Invalid license", null);

        if (!license.IsActive)
            return (false, "License is revoked", null);

        // Verification coherence HWID
        if (!string.IsNullOrEmpty(license.HardwareId)
            && !string.IsNullOrEmpty(hardwareId)
            && !string.Equals(hardwareId, "unknown", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(license.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Hardware ID mismatch", null);
        }

        return (true, string.Empty, license);
    }

    private static async Task<Data.License?> FindLicenseByEncryptedClientContextAsync(
        LicenseDbContext db,
        string? email,
        string? hardwareId)
    {
        if (string.IsNullOrWhiteSpace(email)
            || string.IsNullOrWhiteSpace(hardwareId)
            || string.Equals(hardwareId, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var normalizedEmail = email.Trim().ToLowerInvariant();
        var normalizedHardwareId = hardwareId.Trim().ToLowerInvariant();

        return await db.Licenses
            .Include(l => l.Seats)
            .FirstOrDefaultAsync(l =>
                l.IsActive
                && l.CustomerEmail.ToLower() == normalizedEmail
                && ((l.HardwareId != null && l.HardwareId.ToLower() == normalizedHardwareId)
                    || l.Seats.Any(s => s.IsActive && s.HardwareId.ToLower() == normalizedHardwareId)));
    }

    private async Task<(bool ownsTicket, string error)> TicketBelongsToLicenseAsync(
        string ticketNumber,
        Data.License license,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(license.CustomerEmail))
            return (false, "License has no customer email");

        var tickets = await _bugTrace.GetTicketsByEmailAsync(license.CustomerEmail, ct);
        if (!ContainsTicketNumber(tickets, ticketNumber))
            return (false, "Ticket does not belong to the license customer");

        return (true, string.Empty);
    }

    private static bool ContainsTicketNumber(JsonElement tickets, string ticketNumber)
    {
        if (tickets.ValueKind != JsonValueKind.Array)
            return false;

        foreach (var ticket in tickets.EnumerateArray())
        {
            if (ticket.TryGetProperty("ticketNumber", out var value)
                && string.Equals(value.GetString(), ticketNumber, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Rate limit en memoire par cle composite (licenseKey ou hardwareId).
    /// Complement au rate limit IP applique par le middleware.
    /// </summary>
    private bool IsRateLimited(string key, int limit, int windowMinutes)
    {
        var cacheKey = $"btrl:{key}";

        if (!_cache.TryGetValue<int>(cacheKey, out var count))
        {
            _cache.Set(cacheKey, 1, TimeSpan.FromMinutes(windowMinutes));
            return false;
        }

        if (count >= limit)
            return true;

        _cache.Set(cacheKey, count + 1, TimeSpan.FromMinutes(windowMinutes));
        return false;
    }

    private static string BuildRateLimitKey(string? licenseKey, string? hardwareId)
    {
        if (!string.IsNullOrEmpty(licenseKey) && !IsEncryptedLicenseKey(licenseKey))
            return $"lic:{licenseKey.Trim().ToUpperInvariant()}";

        if (!string.IsNullOrEmpty(hardwareId) &&
            !string.Equals(hardwareId, "unknown", StringComparison.OrdinalIgnoreCase))
            return $"hw:{hardwareId}";

        if (!string.IsNullOrEmpty(licenseKey))
            return "lic:ENC";

        return "anon";
    }

    private ObjectResult RateLimitedResult()
    {
        const int retryAfterSeconds = 60;
        Response.Headers.RetryAfter = retryAfterSeconds.ToString();
        return StatusCode(429, new { error = "rate_limited", retryAfterSeconds });
    }

    private void TagAuditLog(string? licenseKey, string? hardwareId, string endpoint)
    {
        HttpContext.Items[LogKeys.LicenseKey] = RedactLicenseKeyForAudit(licenseKey);
        HttpContext.Items[LogKeys.HardwareId] = hardwareId ?? string.Empty;
        HttpContext.Items[LogKeys.Endpoint] = endpoint;
        HttpContext.Items[LogKeys.AppName] = "BugTrace";
    }

    /// <summary>Tags human-support audit context without persisting the complete machine identifier.</summary>
    private void TagSupportAuditLog(string? licenseKey, string? hardwareId, string endpoint)
    {
        TagAuditLog(licenseKey, RedactHardwareId(hardwareId), endpoint);
    }

    /// <summary>Records a server-selected legacy refusal reason and redacted identity hints; never logs the licence key itself. This helper does not authorize or change the response.</summary>
    private void LogTicketsValidationFailure(
        string reason,
        string? email,
        string? hardwareId,
        string? licenseKey)
    {
        _logger.LogWarning(
            "BugTrace tickets validation failed: reason={Reason}, email={Email}, hardwareId={HardwareId}, hasLicenseKey={HasLicenseKey}, encryptedLicenseKey={EncryptedLicenseKey}",
            reason,
            RedactEmail(email),
            RedactHardwareId(hardwareId),
            !string.IsNullOrWhiteSpace(licenseKey),
            IsEncryptedLicenseKey(licenseKey));
    }

    private static bool IsClientContractError(string error)
    {
        return error.Contains("required", StringComparison.OrdinalIgnoreCase)
            || error.Contains("projectId", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsEncryptedLicenseKey(string? licenseKey)
    {
        return !string.IsNullOrWhiteSpace(licenseKey)
            && licenseKey.Trim().StartsWith("ENC:", StringComparison.OrdinalIgnoreCase);
    }

    private static string RedactLicenseKeyForAudit(string? licenseKey)
    {
        if (string.IsNullOrWhiteSpace(licenseKey))
            return string.Empty;

        return IsEncryptedLicenseKey(licenseKey)
            ? "ENC:<redacted>"
            : licenseKey;
    }

    private static string RedactEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "<empty>";

        var trimmed = email.Trim();
        var at = trimmed.IndexOf('@');
        if (at <= 1)
            return "<redacted>";

        return $"{trimmed[0]}***{trimmed[at..]}";
    }

    private static string RedactHardwareId(string? hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "<empty>";

        var trimmed = hardwareId.Trim();
        if (trimmed.Length <= 8)
            return "<redacted>";

        return $"{trimmed[..4]}...{trimmed[^4..]}";
    }
}
