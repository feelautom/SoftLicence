using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using System.Text.Json;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/bugtrace")]
[EnableRateLimiting("BugTraceAPI")]
public class BugTraceController : ControllerBase
{
    private readonly IBugTraceProxyService _bugTrace;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;
    private readonly ILogger<BugTraceController> _logger;

    public BugTraceController(
        IBugTraceProxyService bugTrace,
        IDbContextFactory<LicenseDbContext> dbFactory,
        IMemoryCache cache,
        ILogger<BugTraceController> logger)
    {
        _bugTrace = bugTrace;
        _dbFactory = dbFactory;
        _cache = cache;
        _logger = logger;
    }

    // -------------------------------------------------------------------------
    // POST /api/bugtrace/submit
    // -------------------------------------------------------------------------
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

        var (valid, validationError) = await ValidateLicenseAsync(payload.LicenseKey, payload.HardwareId);
        if (!valid)
            return BadRequest(new { error = validationError });

        var rateLimitKey = BuildRateLimitKey(payload.LicenseKey, payload.HardwareId);
        if (IsRateLimited(rateLimitKey, limit: 3, windowMinutes: 10))
        {
            _logger.LogWarning("BugTrace submit rate limited for key={Key}", rateLimitKey);
            return RateLimitedResult();
        }

        TagAuditLog(payload.LicenseKey, payload.HardwareId, "BUGTRACE_SUBMIT");

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
        [FromQuery] string? licenseKey,
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

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

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
    /// Valide la coherence licenseKey + hardwareId.
    /// Mode degrade accepte : licenseKey absent + hardwareId present (meme "unknown").
    /// </summary>
    private async Task<(bool valid, string error)> ValidateLicenseAsync(string? licenseKey, string? hardwareId)
    {
        if (string.IsNullOrEmpty(licenseKey))
        {
            // Mode degrade : hardwareId obligatoire (peut etre "unknown" pour tickets anti-RE)
            if (string.IsNullOrWhiteSpace(hardwareId))
                return (false, "hardwareId is required when licenseKey is absent");

            return (true, string.Empty);
        }

        await using var db = await _dbFactory.CreateDbContextAsync();
        var license = await db.Licenses
            .FirstOrDefaultAsync(l => l.LicenseKey == licenseKey.ToUpper());

        if (license == null)
            return (false, "Invalid license");

        if (!license.IsActive)
            return (false, "License is revoked");

        // Verification coherence HWID si la licence est deja attachee a une machine
        if (!string.IsNullOrEmpty(license.HardwareId)
            && !string.IsNullOrEmpty(hardwareId)
            && !string.Equals(hardwareId, "unknown", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(license.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Hardware ID mismatch");
        }

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
