using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services.SecurityLocks;

namespace SoftLicence.Server.Controllers;

/// <summary>Admin decision request for one security lock (TKT-001177).</summary>
public sealed class SecurityLockDecisionRequest
{
    /// <summary>RELEASE or BAN.</summary>
    public string? Decision { get; set; }
    /// <summary>Free-text reason kept with the decision.</summary>
    public string? Reason { get; set; }
    /// <summary>Administrator recording the decision.</summary>
    public string? DecidedBy { get; set; }
}

/// <summary>Admin request changing the enforcement mode of one irreversible-candidate cause.</summary>
public sealed class SecurityLockPolicyRequest
{
    /// <summary>Exact product name.</summary>
    public string? ProductName { get; set; }
    /// <summary>Catalogued level-4 or level-5 cause.</summary>
    public string? Cause { get; set; }
    /// <summary>SHADOW, REVIEW or ENFORCE.</summary>
    public string? Mode { get; set; }
    /// <summary>Administrator making the change.</summary>
    public string? UpdatedBy { get; set; }
}

public partial class AdminController
{
    /// <summary>
    /// Lists operational security-lock alert delivery states without returning dossier contents or webhook URLs.
    /// Product-scoped admin keys only see deliveries for their product.
    /// </summary>
    /// <param name="state">Optional exact delivery state.</param>
    /// <param name="take">Maximum rows (1..500).</param>
    [HttpGet("security-lock-alert-deliveries")]
    public async Task<IActionResult> ListSecurityLockAlertDeliveries([FromQuery] string? state = null, [FromQuery] int take = 100)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        var states = new[]
        {
            SecurityLockAlertDeliveryStates.Pending, SecurityLockAlertDeliveryStates.Processing,
            SecurityLockAlertDeliveryStates.Sent, SecurityLockAlertDeliveryStates.Skipped,
            SecurityLockAlertDeliveryStates.Failed, SecurityLockAlertDeliveryStates.Unknown
        };
        if (state != null && !states.Contains(state, StringComparer.Ordinal))
            return BadRequest(new { error = "state_invalid" });
        take = Math.Clamp(take, 1, 500);

        var query = _db.SecurityLockAlertDeliveries.AsNoTracking();
        if (auth.ScopedProductId.HasValue)
            query = query.Where(delivery => delivery.SecurityLockReport!.ProductId == auth.ScopedProductId.Value);
        if (state != null) query = query.Where(delivery => delivery.State == state);
        var rows = await query.OrderByDescending(delivery => delivery.UpdatedAtUtc).Take(take)
            .Select(delivery => new
            {
                delivery.Id,
                delivery.SecurityLockReportId,
                delivery.Channel,
                delivery.Trigger,
                delivery.State,
                delivery.AttemptCount,
                delivery.NextAttemptUtc,
                delivery.LeaseExpiresUtc,
                delivery.LastError,
                delivery.CreatedAtUtc,
                delivery.UpdatedAtUtc,
                delivery.SentAtUtc
            }).ToListAsync();
        TagLog("SECURITY_LOCK_ALERT_DELIVERIES", state ?? "all");
        return Ok(rows);
    }

    /// <summary>
    /// Lists security lock reports, newest first, optionally filtered by exact state. Product-scoped admin keys
    /// only see their product.
    /// </summary>
    /// <param name="state">Optional exact state (OPEN, RELEASED, BANNED).</param>
    /// <param name="take">Maximum rows (1..500).</param>
    [HttpGet("security-locks")]
    public async Task<IActionResult> ListSecurityLocks([FromQuery] string? state = null, [FromQuery] int take = 100)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        if (state != null && state is not (SecurityLockReportStates.Open or SecurityLockReportStates.Released or SecurityLockReportStates.Banned))
            return BadRequest(new { error = "state_invalid" });
        take = Math.Clamp(take, 1, 500);

        var query = _db.SecurityLockReports.AsNoTracking();
        if (auth.ScopedProductId.HasValue) query = query.Where(row => row.ProductId == auth.ScopedProductId.Value);
        if (state != null) query = query.Where(row => row.State == state);
        var rows = await query.OrderByDescending(row => row.LastReportedUtc).Take(take).Select(row => new
        {
            row.Id, row.ProductId, row.EnrollmentId, row.InstallationId, row.HardwareId, row.AppVersion,
            row.LockId, row.Cause, row.Level, row.ClientMode, row.EffectiveMode, row.EvidenceDigestSha256,
            row.FirstSeenUtc, row.FirstReportedUtc, row.LastReportedUtc, row.ReportCount, row.State, row.LastVerdict,
            row.AdminDecision, row.AdminDecisionAtUtc, row.AdminDecisionBy, row.AdminDecisionReason
        }).ToListAsync();
        TagLog("SECURITY_LOCKS_LIST", state ?? "all");
        return Ok(rows);
    }

    /// <summary>
    /// Records an admin decision. Security contract: BAN adds an active hardware ban immediately; RELEASE is
    /// delivered as a signed verdict at the next report (within five minutes); a lock already banned by ENFORCE
    /// can never be released, because levels 4 and 5 enforced are irreversible by decision of the owner.
    /// </summary>
    /// <param name="id">Report row identifier.</param>
    /// <param name="request">Decision payload.</param>
    [HttpPost("security-locks/{id:guid}/decision")]
    public async Task<IActionResult> DecideSecurityLock(Guid id, [FromBody] SecurityLockDecisionRequest request)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        if (request is null) return BadRequest(new { error = SecurityLockAdminOutcomes.DecisionInvalid });

        var admin = HttpContext.RequestServices.GetRequiredService<SecurityLockAdminService>();
        var result = await admin.DecideAsync(id, request.Decision, request.Reason, request.DecidedBy,
            auth.ScopedProductId, HttpContext.RequestAborted);
        switch (result.Outcome)
        {
            case SecurityLockAdminOutcomes.Ok:
                var row = result.Row!;
                TagLog("SECURITY_LOCK_DECISION", row.LockId + ":" + row.AdminDecision);
                return Ok(new { row.Id, row.State, row.AdminDecision, row.AdminDecisionAtUtc });
            case SecurityLockAdminOutcomes.NotFound:
                return NotFound();
            case SecurityLockAdminOutcomes.Forbidden:
                return Forbid();
            case SecurityLockAdminOutcomes.LockBannedIrreversible:
                return Conflict(new { error = result.Outcome });
            default:
                return BadRequest(new { error = result.Outcome });
        }
    }

    /// <summary>Lists the enforcement modes configured for irreversible-candidate causes (absent = REVIEW).</summary>
    /// <param name="productName">Exact product name.</param>
    [HttpGet("security-lock-policies")]
    public async Task<IActionResult> ListSecurityLockPolicies([FromQuery] string productName)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        var product = await _db.Products.AsNoTracking().SingleOrDefaultAsync(p => p.Name == productName);
        if (product == null) return NotFound();
        if (auth.ScopedProductId.HasValue && auth.ScopedProductId.Value != product.Id) return Forbid();
        var configured = await _db.SecurityLockEnforcementPolicies.AsNoTracking()
            .Where(policy => policy.ProductId == product.Id)
            .ToDictionaryAsync(policy => policy.Cause, StringComparer.Ordinal);
        var causes = SecurityLockCauseCatalog.AllCauses
            .Where(cause => SecurityLockCauseCatalog.TryGetLevel(cause, out var level) && SecurityLockCauseCatalog.IsIrreversibleCandidate(level))
            .OrderBy(cause => cause, StringComparer.Ordinal)
            .Select(cause => new
            {
                Cause = cause,
                Mode = configured.TryGetValue(cause, out var policy) ? policy.Mode : SecurityLockVerdictPolicy.DefaultIrreversibleMode,
                Configured = configured.ContainsKey(cause),
                UpdatedAtUtc = configured.TryGetValue(cause, out var updated) ? updated.UpdatedAtUtc : (DateTime?)null,
                UpdatedBy = configured.TryGetValue(cause, out var by) ? by.UpdatedBy : null
            })
            .ToList();
        return Ok(causes);
    }

    /// <summary>
    /// Sets the mode of one level-4/5 cause. ENFORCE makes the next matching detection an automatic permanent
    /// ban, so it is only accepted as an explicit, attributed administrator action.
    /// </summary>
    /// <param name="request">Policy change.</param>
    [HttpPut("security-lock-policies")]
    public async Task<IActionResult> SetSecurityLockPolicy([FromBody] SecurityLockPolicyRequest request)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        if (request is null || !SecurityLockCauseCatalog.TryGetLevel(request.Cause, out var level)
            || !SecurityLockCauseCatalog.IsIrreversibleCandidate(level))
            return BadRequest(new { error = "cause_invalid" });
        if (!SecurityLockCauseCatalog.IsPolicyMode(request.Mode))
            return BadRequest(new { error = "mode_invalid" });
        var updatedBy = request.UpdatedBy?.Trim();
        if (string.IsNullOrEmpty(updatedBy) || updatedBy.Length > 100)
            return BadRequest(new { error = "updated_by_invalid" });
        var product = await _db.Products.SingleOrDefaultAsync(p => p.Name == request.ProductName);
        if (product == null) return NotFound();
        if (auth.ScopedProductId.HasValue && auth.ScopedProductId.Value != product.Id) return Forbid();

        var policy = await _db.SecurityLockEnforcementPolicies
            .SingleOrDefaultAsync(row => row.ProductId == product.Id && row.Cause == request.Cause);
        if (policy == null)
        {
            policy = new SecurityLockEnforcementPolicy { ProductId = product.Id, Cause = request.Cause! };
            _db.SecurityLockEnforcementPolicies.Add(policy);
        }
        policy.Mode = request.Mode!;
        policy.UpdatedAtUtc = DateTime.UtcNow;
        policy.UpdatedBy = updatedBy;
        await _db.SaveChangesAsync();
        TagLog("SECURITY_LOCK_POLICY", request.Cause + ":" + request.Mode);
        return Ok(new { policy.Cause, policy.Mode, policy.UpdatedAtUtc, policy.UpdatedBy });
    }
}
