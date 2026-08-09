using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/analytics/telemetry/operations")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
public sealed class TelemetryOperationsAnalyticsController : ControllerBase
{
    private readonly AnalyticsApiKeyAuthService _auth;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public TelemetryOperationsAnalyticsController(AnalyticsApiKeyAuthService auth, IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _auth = auth;
        _dbFactory = dbFactory;
    }

    [HttpGet("rejections")]
    public async Task<IActionResult> Rejections([FromHeader(Name = "X-Analytics-Key")] string? key, [FromQuery] int take = 100, CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(key, cancellationToken);
        if (auth == null) return Unauthorized("Missing or invalid X-Analytics-Key header.");
        if (!auth.IsGlobal) return Forbid();
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var rows = await db.TelemetryIngestionRejections.AsNoTracking()
            .OrderByDescending(x => x.TimestampUtc).Take(Math.Clamp(take, 1, 500))
            .Select(x => new
            {
                x.Id, x.TimestampUtc, x.Route, x.ValidationCode, x.InvalidFields,
                x.AppName, x.Version, x.EventName, x.HardwareIdMasked,
                x.ClientIpMasked, x.ClientName, x.CorrelationId, x.Alerted
            }).ToListAsync(cancellationToken);
        return Ok(new { generatedAtUtc = DateTime.UtcNow, count = rows.Count, rejections = rows });
    }

    [HttpGet("activation-incidents")]
    public async Task<IActionResult> Incidents([FromHeader(Name = "X-Analytics-Key")] string? key, [FromQuery] string? status = null, [FromQuery] int take = 100, CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(key, cancellationToken);
        if (auth == null) return Unauthorized("Missing or invalid X-Analytics-Key header.");
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.ActivationIncidents.AsNoTracking().AsQueryable();
        if (!auth.IsGlobal) query = query.Where(x => x.ProductId == auth.ProductId);
        if (!string.IsNullOrWhiteSpace(status)) query = query.Where(x => x.Status == status.Trim().ToUpperInvariant());
        var rows = await query.OrderByDescending(x => x.LastSeenUtc).Take(Math.Clamp(take, 1, 500))
            .Select(x => new
            {
                x.Id, x.ProductId, x.HardwareIdMasked, x.Category, x.Status, x.Severity,
                x.FirstSeenUtc, x.LastSeenUtc, x.RepeatCount, x.Version, x.CountryCode,
                x.Isp, x.ClientIpMasked, x.LastNotifiedSeverity, x.RecoveredAtUtc
            }).ToListAsync(cancellationToken);
        return Ok(new { generatedAtUtc = DateTime.UtcNow, count = rows.Count, incidents = rows });
    }

    [HttpGet("rejection-summary")]
    public async Task<IActionResult> RejectionSummary([FromHeader(Name = "X-Analytics-Key")] string? key, [FromQuery] int days = 7, CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAsync(key, cancellationToken);
        if (auth == null) return Unauthorized("Missing or invalid X-Analytics-Key header.");
        if (!auth.IsGlobal) return Forbid();
        var fromUtc = DateTime.UtcNow.AddDays(-Math.Clamp(days, 1, 90));
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var counters = await db.TelemetryIngestionRejections.AsNoTracking()
            .Where(x => x.TimestampUtc >= fromUtc)
            .GroupBy(x => new { x.Version, x.EventName, x.ValidationCode })
            .Select(g => new { g.Key.Version, g.Key.EventName, g.Key.ValidationCode, Count = g.Count(), LastSeenUtc = g.Max(x => x.TimestampUtc) })
            .OrderByDescending(x => x.Count).ThenByDescending(x => x.LastSeenUtc)
            .Take(500).ToListAsync(cancellationToken);
        return Ok(new { generatedAtUtc = DateTime.UtcNow, fromUtc, count = counters.Count, counters });
    }

    private Task<AnalyticsApiKeyAuthResult?> AuthenticateAsync(string? key, CancellationToken cancellationToken) =>
        _auth.ValidateAsync(key ?? string.Empty, AnalyticsApiKeyScopes.TelemetryRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
}
