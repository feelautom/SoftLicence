using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;

namespace SoftLicence.Server.Controllers;

public sealed partial class AnalyticsController
{
    /// <summary>Lists bounded product-scoped security locks for authenticated security analytics callers.</summary>
    [HttpGet("security/locks")]
    public async Task<IActionResult> ListSecurityLocks(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? state = null,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? email = null,
        [FromQuery] int take = 50,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;
        if (!ValidSecurityLockState(state))
            return BadRequest(new { errorCode = "SECURITY_LOCK_STATE_INVALID", message = "state must be OPEN, RELEASED, or BANNED." });
        if (take is < 1 or > 100)
            return BadRequest(new { errorCode = "SECURITY_LOCK_TAKE_INVALID", message = "take must be between 1 and 100." });

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var rows = await BuildSecurityLockQuery(
                db, product.ProductId, state: state, hardwareId: hardwareId, email: email)
            .OrderByDescending(row => row.LastReportedUtc)
            .ThenBy(row => row.Id)
            .Take(take)
            .ToListAsync(cancellationToken);
        return Ok(new { recordsReturned = rows.Count, locks = rows });
    }

    /// <summary>Gets one exact product-scoped security-lock report by its row identifier.</summary>
    [HttpGet("security/locks/{id:guid}")]
    public async Task<IActionResult> GetSecurityLock(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        Guid id,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var row = await BuildSecurityLockQuery(db, product.ProductId, id: id)
            .SingleOrDefaultAsync(cancellationToken);
        return row == null ? NotFound() : Ok(row);
    }

    /// <summary>Lists bounded remembered RELEASE decisions without weakening their exact matching scope.</summary>
    [HttpGet("security/lock-release-decisions")]
    public async Task<IActionResult> ListSecurityLockReleaseDecisions(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] Guid? decisionId = null,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? cause = null,
        [FromQuery] bool includeInactive = false,
        [FromQuery] int take = 50,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return AnalyticsApiKeyHttp.Failure(HttpContext);

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;
        if (take is < 1 or > 100)
            return BadRequest(new { errorCode = "SECURITY_LOCK_TAKE_INVALID", message = "take must be between 1 and 100." });

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.SecurityLockReleaseDecisions.AsNoTracking()
            .Where(row => row.ProductId == product.ProductId);
        if (decisionId.HasValue)
            query = query.Where(row => row.Id == decisionId.Value);
        if (!includeInactive)
            query = query.Where(row => row.IsActive);
        if (hardwareId != null)
            query = query.Where(row => row.HardwareId == hardwareId);
        if (cause != null)
            query = query.Where(row => row.Cause == cause);

        var rows = await query.OrderByDescending(row => row.ActivatedAtUtc).ThenBy(row => row.Id).Take(take)
            .Select(row => new
            {
                row.Id,
                row.ProductId,
                row.LicenseId,
                row.HardwareId,
                row.Cause,
                row.IsActive,
                row.CreatedAtUtc,
                row.CreatedBy,
                row.SourceSecurityLockReportId,
                row.ActivatedAtUtc,
                row.ActivatedBy,
                row.ActivationCount,
                row.RevokedAtUtc,
                row.RevokedBy,
                row.CoveredDetectionCount,
                row.LastCoveredAtUtc
            }).ToListAsync(cancellationToken);
        return Ok(new { recordsReturned = rows.Count, decisions = rows });
    }

    /// <summary>Returns whether an optional state is absent or one of the exact persisted security-lock states.</summary>
    private static bool ValidSecurityLockState(string? state) => state == null
        || state is SecurityLockReportStates.Open or SecurityLockReportStates.Released or SecurityLockReportStates.Banned;

    /// <summary>
    /// Builds the product-scoped relational lock projection, including exact ACTIVE enrollment existence and
    /// stable-scope open incidents. Machine authority fields remain exact while only the display email filter folds case.
    /// </summary>
    internal static IQueryable<SecurityLockAnalyticsRow> BuildSecurityLockQuery(
        LicenseDbContext db,
        Guid productId,
        Guid? id = null,
        string? state = null,
        string? hardwareId = null,
        string? email = null)
    {
        var query = from report in db.SecurityLockReports.AsNoTracking()
                    join product in db.Products.AsNoTracking() on report.ProductId equals product.Id
                    join enrollment in db.RuntimeEnrollments.AsNoTracking() on report.EnrollmentId equals enrollment.Id
                    join license in db.Licenses.AsNoTracking() on enrollment.LicenseId equals license.Id
                    where report.ProductId == productId
                    select new { report, product, license };
        if (id.HasValue)
            query = query.Where(row => row.report.Id == id.Value);
        if (state != null)
            query = query.Where(row => row.report.State == state);
        if (hardwareId != null)
            query = query.Where(row => row.report.HardwareId == hardwareId);
        if (email != null)
        {
            var emailSearch = email.ToLower();
            query = query.Where(row => row.license.CustomerEmail.ToLower().Contains(emailSearch));
        }
        return query.Select(value => new SecurityLockAnalyticsRow(
            value.report.Id,
            value.report.ProductId,
            value.product.Name,
            value.report.EnrollmentId,
            value.report.BindingId,
            value.report.InstallationId,
            value.report.HardwareId,
            value.license.CustomerEmail,
            value.report.AppVersion,
            value.report.LockId,
            value.report.Cause,
            value.report.Level,
            value.report.ClientMode,
            value.report.EffectiveMode,
            value.report.EvidenceDigestSha256,
            value.report.FirstSeenUtc,
            value.report.FirstReportedUtc,
            value.report.LastReportedUtc,
            value.report.ReportCount,
            value.report.State,
            value.report.LastVerdict,
            value.report.LinkStatus,
            value.report.LinkReasonCode,
            value.report.AdminDecision,
            value.report.AdminDecisionAtUtc,
            value.report.AdminDecisionBy,
            value.report.AdminDecisionReason,
            value.report.RememberedReleaseDecisionId,
            db.RuntimeEnrollments.Any(enrollment => enrollment.ProductId == value.report.ProductId
                && enrollment.BindingId == value.report.BindingId
                && enrollment.InstallationId == value.report.InstallationId
                && enrollment.State == "ACTIVE"),
            db.RuntimeCriticalIncidents.Count(incident => incident.BindingId == value.report.BindingId
                && incident.InstallationId == value.report.InstallationId
                && incident.State == "OPEN")));
    }

    /// <summary>
    /// Stable analytics projection for one security-lock report, including whether its binding and installation can
    /// receive a recovery immediately or require a client reinstall after explicit UNBAN.
    /// </summary>
    internal sealed record SecurityLockAnalyticsRow(
        Guid Id, Guid ProductId, string ProductName, Guid EnrollmentId, Guid BindingId,
        string InstallationId, string HardwareId, string CustomerEmail, string AppVersion,
        string LockId, string Cause, int Level, string ClientMode, string EffectiveMode,
        string EvidenceDigestSha256, DateTime FirstSeenUtc, DateTime FirstReportedUtc,
        DateTime LastReportedUtc, int ReportCount, string State, string LastVerdict,
        string LinkStatus, string? LinkReasonCode, string? AdminDecision,
        DateTime? AdminDecisionAtUtc, string? AdminDecisionBy, string? AdminDecisionReason,
        Guid? RememberedReleaseDecisionId, bool HasActiveEnrollment, int OpenIncidentCount);
}
