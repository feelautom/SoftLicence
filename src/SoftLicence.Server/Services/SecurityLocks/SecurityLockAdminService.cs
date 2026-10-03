using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>Closed outcome codes of an admin decision.</summary>
public static class SecurityLockAdminOutcomes
{
    /// <summary>Decision recorded.</summary>
    public const string Ok = "ok";
    /// <summary>Decision is neither RELEASE nor BAN.</summary>
    public const string DecisionInvalid = "decision_invalid";
    /// <summary>Missing or too long administrator name.</summary>
    public const string DecidedByInvalid = "decided_by_invalid";
    /// <summary>Reason longer than 500 characters.</summary>
    public const string ReasonTooLong = "reason_too_long";
    /// <summary>Unknown report row.</summary>
    public const string NotFound = "not_found";
    /// <summary>Row outside the caller's product scope.</summary>
    public const string Forbidden = "forbidden";
    /// <summary>A banned lock can never be released.</summary>
    public const string LockBannedIrreversible = "lock_banned_irreversible";
    /// <summary>The reported hardware has no provable assignment or alias at server receipt time.</summary>
    public const string HardwareUnlinked = "hardware_unlinked";
}

/// <summary>Result of one admin decision.</summary>
/// <param name="Outcome">Closed outcome code.</param>
/// <param name="Row">Updated row when <paramref name="Outcome"/> is ok.</param>
/// <param name="DiagnosticCode">Bounded internal cause; never includes reported hardware or credentials.</param>
public sealed record SecurityLockAdminDecisionResult(
    string Outcome, SecurityLockReport? Row, string? DiagnosticCode = null);

/// <summary>
/// Admin decisions on security locks (TKT-001177), shared by the admin API and the "Verrous" page so both apply the
/// exact same rules. Security contract: BAN requires authoritative hardware linkage at the server's first receipt
/// time from the immutable report snapshot and adds a permanent ban unless a live ban already exists
/// (historical bans are matched case-insensitively);
/// RELEASE is delivered as a
/// signed verdict at the next report; a banned lock can never be released, because levels 4 and 5 are irreversible.
/// </summary>
public sealed class SecurityLockAdminService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    /// <summary>Creates the service.</summary>
    /// <param name="dbFactory">Database factory.</param>
    public SecurityLockAdminService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    /// <summary>
    /// Validates and records one decision. Validation failures and scope violations change nothing; the ban and the
    /// decision are saved in one transaction so a partially applied BAN cannot exist.
    /// </summary>
    /// <param name="id">Report row identifier.</param>
    /// <param name="decision">RELEASE or BAN (exact, ordinal).</param>
    /// <param name="reason">Optional reason (at most 500 characters).</param>
    /// <param name="decidedBy">Administrator name (1..100 characters after trimming).</param>
    /// <param name="scopedProductId">Product scope of the caller, or null for a global administrator.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The closed outcome and the updated row on success.</returns>
    public async Task<SecurityLockAdminDecisionResult> DecideAsync(
        Guid id,
        string? decision,
        string? reason,
        string? decidedBy,
        Guid? scopedProductId,
        CancellationToken cancellationToken = default)
    {
        if (decision is not (SecurityLockAdminDecisions.Release or SecurityLockAdminDecisions.Ban))
            return new(SecurityLockAdminOutcomes.DecisionInvalid, null);
        var admin = decidedBy?.Trim();
        if (string.IsNullOrEmpty(admin) || admin.Length > 100)
            return new(SecurityLockAdminOutcomes.DecidedByInvalid, null);
        if (reason is { Length: > 500 })
            return new(SecurityLockAdminOutcomes.ReasonTooLong, null);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        // This immutable pre-read selects the hardware advisory key without taking the report row lock.
        var preflight = await db.SecurityLockReports.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == id, cancellationToken);
        if (preflight == null) return new(SecurityLockAdminOutcomes.NotFound, null);
        if (scopedProductId.HasValue && scopedProductId.Value != preflight.ProductId)
            return new(SecurityLockAdminOutcomes.Forbidden, null);
        if (decision == SecurityLockAdminDecisions.Ban && !IsCanonicalHardwareId(preflight.HardwareId))
            return Unlinked("report_hardware_noncanonical");
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if (string.Equals(decision, SecurityLockAdminDecisions.Ban, StringComparison.Ordinal))
        {
            // BAN can insert or reactivate BannedHardwareIds. Global authority must precede the
            // hardware and report locks; otherwise Runtime can hold global/shared while this path
            // holds hardware/report and both wait on the other side.
            await SecurityService.AcquireHardwareBanWriteAuthorityAsync(db, preflight.HardwareId);
        }
        // RELEASE never waits for the hardware advisory while holding the report row.
        var row = await db.SecurityLockReports.FromSqlInterpolated($"""
            SELECT * FROM public."SecurityLockReports" WHERE "Id" = {id} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (row is null) return new(SecurityLockAdminOutcomes.NotFound, null);
        if (scopedProductId.HasValue && scopedProductId.Value != row.ProductId)
            return new(SecurityLockAdminOutcomes.Forbidden, null);
        if (decision == SecurityLockAdminDecisions.Release
            && row.State == SecurityLockReportStates.Banned)
            return new(SecurityLockAdminOutcomes.LockBannedIrreversible, null);
        if (decision == SecurityLockAdminDecisions.Ban)
        {
            if (!string.Equals(row.HardwareId, preflight.HardwareId, StringComparison.Ordinal)
                || !IsCanonicalHardwareId(row.HardwareId))
                return Unlinked("report_hardware_changed");
            if (row.LinkStatus is not (SecurityLockReportLinkStatuses.VerifiedSeat
                or SecurityLockReportLinkStatuses.VerifiedAlias))
                return Unlinked(row.LinkStatus == SecurityLockReportLinkStatuses.UnknownLegacy
                    ? "report_link_legacy_unknown" : row.LinkReasonCode ?? "report_hardware_unlinked");

            var now = DateTime.UtcNow;
            row.AdminDecision = decision;
            row.AdminDecisionAtUtc = now;
            row.AdminDecisionBy = admin;
            row.AdminDecisionReason = reason;
            row.State = SecurityLockReportStates.Banned;
            // row.HardwareId is the validated canonical upper-case value; historical ban rows may use any case.
            var alreadyBanned = await db.BannedHardwareIds.AnyAsync(ban =>
                ban.HardwareId.ToUpper() == row.HardwareId && ban.IsActive
                && (ban.ProductId == null || ban.ProductId == row.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now), cancellationToken);
            if (!alreadyBanned)
            {
                await SecurityLockBans.StagePermanentBanAsync(db, row.HardwareId, row.ProductId,
                    "security-lock-admin:" + row.Cause + ":" + row.LockId,
                    SecurityLockCauseCatalog.IsIrreversibleCandidate(row.Level)
                        ? SecurityLockVerdictPolicy.BanCategoryFor(row.Level)
                        : BannedHardwareId.Categories.Manual,
                    now, cancellationToken);
            }
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(SecurityLockAdminOutcomes.Ok, row);
        }
        var releaseTime = DateTime.UtcNow;
        row.AdminDecision = decision;
        row.AdminDecisionAtUtc = releaseTime;
        row.AdminDecisionBy = admin;
        row.AdminDecisionReason = reason;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(SecurityLockAdminOutcomes.Ok, row);
    }

    /// <summary>Returns a stable public refusal with a bounded internal diagnostic and no hardware value.</summary>
    private static SecurityLockAdminDecisionResult Unlinked(string diagnosticCode) =>
        new(SecurityLockAdminOutcomes.HardwareUnlinked, null, diagnosticCode);

    /// <summary>Requires the report's exact upper-case ASCII hardware alphabet without normalization.</summary>
    private static bool IsCanonicalHardwareId(string? hardwareId) =>
        hardwareId is { Length: >= 1 and <= 128 }
        && hardwareId.All(character => character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '.' or '-');

    /// <summary>
    /// Sets the server mode of one level-4/5 cause for a product. Security contract: only catalogued irreversible
    /// causes and the closed modes SHADOW, REVIEW and ENFORCE are accepted, and every change is attributed, because
    /// ENFORCE turns the next matching detection into an automatic permanent ban.
    /// </summary>
    /// <param name="productId">Product.</param>
    /// <param name="cause">Catalogued level-4/5 cause.</param>
    /// <param name="mode">SHADOW, REVIEW or ENFORCE.</param>
    /// <param name="updatedBy">Administrator name (1..100 characters after trimming).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Closed outcome: ok, cause_invalid, mode_invalid, updated_by_invalid or not_found.</returns>
    public async Task<string> SetPolicyAsync(
        Guid productId, string? cause, string? mode, string? updatedBy, CancellationToken cancellationToken = default)
    {
        if (!SecurityLockCauseCatalog.TryGetLevel(cause, out var level) || !SecurityLockCauseCatalog.IsIrreversibleCandidate(level))
            return "cause_invalid";
        if (!SecurityLockCauseCatalog.IsPolicyMode(mode))
            return "mode_invalid";
        var admin = updatedBy?.Trim();
        if (string.IsNullOrEmpty(admin) || admin.Length > 100)
            return "updated_by_invalid";

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (!await db.Products.AnyAsync(product => product.Id == productId, cancellationToken))
            return SecurityLockAdminOutcomes.NotFound;
        var policy = await db.SecurityLockEnforcementPolicies
            .SingleOrDefaultAsync(row => row.ProductId == productId && row.Cause == cause, cancellationToken);
        if (policy == null)
        {
            policy = new SecurityLockEnforcementPolicy { ProductId = productId, Cause = cause! };
            db.SecurityLockEnforcementPolicies.Add(policy);
        }
        policy.Mode = mode!;
        policy.UpdatedAtUtc = DateTime.UtcNow;
        policy.UpdatedBy = admin;
        await db.SaveChangesAsync(cancellationToken);
        return SecurityLockAdminOutcomes.Ok;
    }
}
