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
    /// <summary>An explicit unban requires a nonblank operator reason.</summary>
    public const string ReasonRequired = "reason_required";
    /// <summary>An explicit unban requires a bounded named audit reference.</summary>
    public const string AuditReferenceInvalid = "audit_reference_invalid";
    /// <summary>Unknown report row.</summary>
    public const string NotFound = "not_found";
    /// <summary>Row outside the caller's product scope.</summary>
    public const string Forbidden = "forbidden";
    /// <summary>A banned lock can never be released.</summary>
    public const string LockBannedIrreversible = "lock_banned_irreversible";
    /// <summary>The reported hardware has no provable assignment or alias at server receipt time.</summary>
    public const string HardwareUnlinked = "hardware_unlinked";
    /// <summary>The incident generation changed while the administrative recovery was being prepared.</summary>
    public const string RecoveryConflict = "recovery_conflict";
    /// <summary>Only a currently banned report can use the explicit unban operation.</summary>
    public const string LockNotBanned = "lock_not_banned";

    /// <summary>The incident release succeeded, but the current seat no longer matches the immutable report hardware.</summary>
    public const string RememberedReleaseHardwareChanged = "remembered_release_hardware_changed";
    /// <summary>The incidents were closed for audit, but no ACTIVE enrollment can receive the recovery receipt.</summary>
    public const string ReleaseNoActiveEnrollment = "release_no_active_enrollment";
}

/// <summary>Result of one admin decision.</summary>
/// <param name="Outcome">Closed outcome code.</param>
/// <param name="Row">Updated row when <paramref name="Outcome"/> is ok.</param>
/// <param name="DiagnosticCode">Bounded internal cause; never includes reported hardware or credentials.</param>
public sealed record SecurityLockAdminDecisionResult(
    string Outcome,
    SecurityLockReport? Row,
    string? DiagnosticCode = null,
    int RecoveredIncidentCount = 0,
    int DeactivatedHardwareBanCount = 0);

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
    private readonly IRuntimeEnrollmentAuthorityService _authority;

    /// <summary>Creates the service.</summary>
    /// <param name="dbFactory">Database factory.</param>
    /// <param name="authority">Runtime authority lock service.</param>
    public SecurityLockAdminService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IRuntimeEnrollmentAuthorityService authority)
    {
        _dbFactory = dbFactory;
        _authority = authority;
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
        if (string.Equals(decision, SecurityLockAdminDecisions.Ban, StringComparison.Ordinal))
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            // BAN can insert or reactivate BannedHardwareIds. Global authority must precede the
            // hardware and report locks; otherwise Runtime can hold global/shared while this path
            // holds hardware/report and both wait on the other side.
            await SecurityService.AcquireHardwareBanWriteAuthorityAsync(db, preflight.HardwareId);
            var banRow = await db.SecurityLockReports.FromSqlInterpolated($"""
                SELECT * FROM public."SecurityLockReports" WHERE "Id" = {id} FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken);
            if (banRow is null) return new(SecurityLockAdminOutcomes.NotFound, null);
            if (scopedProductId.HasValue && scopedProductId.Value != banRow.ProductId)
                return new(SecurityLockAdminOutcomes.Forbidden, null);
            if (!string.Equals(banRow.HardwareId, preflight.HardwareId, StringComparison.Ordinal)
                || !IsCanonicalHardwareId(banRow.HardwareId))
                return Unlinked("report_hardware_changed");
            if (banRow.LinkStatus is not (SecurityLockReportLinkStatuses.VerifiedSeat
                or SecurityLockReportLinkStatuses.VerifiedAlias))
                return Unlinked(banRow.LinkStatus == SecurityLockReportLinkStatuses.UnknownLegacy
                    ? "report_link_legacy_unknown" : banRow.LinkReasonCode ?? "report_hardware_unlinked");

            var now = DateTime.UtcNow;
            banRow.AdminDecision = decision;
            banRow.AdminDecisionAtUtc = now;
            banRow.AdminDecisionBy = admin;
            banRow.AdminDecisionReason = reason;
            banRow.State = SecurityLockReportStates.Banned;
            // banRow.HardwareId is canonical upper-case; historical ban rows may use any case.
            var alreadyBanned = await db.BannedHardwareIds.AnyAsync(ban =>
                ban.HardwareId.ToUpper() == banRow.HardwareId && ban.IsActive
                && (ban.ProductId == null || ban.ProductId == banRow.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now), cancellationToken);
            if (!alreadyBanned)
            {
                await SecurityLockBans.StagePermanentBanAsync(db, banRow.HardwareId, banRow.ProductId,
                    "security-lock-admin:" + banRow.Cause + ":" + banRow.LockId,
                    SecurityLockCauseCatalog.IsIrreversibleCandidate(banRow.Level)
                        ? SecurityLockVerdictPolicy.BanCategoryFor(banRow.Level)
                        : BannedHardwareId.Categories.Manual,
                    now, cancellationToken);
            }
            if (banRow.LinkLicenseSeatId.HasValue)
            {
                var seat = await db.LicenseSeats.AsNoTracking()
                    .SingleOrDefaultAsync(candidate => candidate.Id == banRow.LinkLicenseSeatId.Value,
                        cancellationToken);
                if (seat is not null)
                {
                    var remembered = await SecurityLockRememberedReleaseStore.FindActiveAsync(
                        db, banRow.ProductId, seat.LicenseId, seat.HardwareId, banRow.Cause,
                        cancellationToken);
                    if (remembered is not null)
                        SecurityLockRememberedReleaseStore.Revoke(remembered, admin, now);
                }
            }
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(SecurityLockAdminOutcomes.Ok, banRow);
        }

        await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
        // The clicked report is a stable administrative handle. Recovery authority instead belongs to the
        // current ACTIVE credential, so a report from an earlier installation generation remains actionable.
        var scopedEnrollments = await db.RuntimeEnrollments.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollments"
            WHERE "BindingId" = {preflight.BindingId}
              AND "InstallationId" = {preflight.InstallationId}
              AND "ProductId" = {preflight.ProductId}
            ORDER BY "Id" FOR UPDATE
            """).ToListAsync(cancellationToken);
        var activeEnrollments = scopedEnrollments
            .Where(candidate => string.Equals(candidate.State, "ACTIVE", StringComparison.Ordinal))
            .ToList();
        if (activeEnrollments.Count > 1 || scopedEnrollments.Count == 0)
        {
            return new(SecurityLockAdminOutcomes.RecoveryConflict, null, "release_enrollment_scope_changed");
        }
        var activeEnrollment = activeEnrollments.SingleOrDefault();
        // When no credential is active, keep closure auditable on the most advanced historical generation.
        // Its inactive state prevents client refetch, while choosing the maximum epoch avoids a false conflict.
        var recoveryEnrollment = activeEnrollment ?? scopedEnrollments
            .OrderByDescending(candidate => candidate.SecurityEpoch)
            .ThenByDescending(candidate => candidate.Id)
            .First();
        await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
        var row = await db.SecurityLockReports.FromSqlInterpolated($"""
            SELECT * FROM public."SecurityLockReports" WHERE "Id" = {id} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (row is null) return new(SecurityLockAdminOutcomes.NotFound, null);
        if (scopedProductId.HasValue && scopedProductId.Value != row.ProductId)
            return new(SecurityLockAdminOutcomes.Forbidden, null);
        if (row.State == SecurityLockReportStates.Banned)
            return new(SecurityLockAdminOutcomes.LockBannedIrreversible, null);
        if (row.EnrollmentId != preflight.EnrollmentId
            || row.BindingId != preflight.BindingId
            || row.InstallationId != preflight.InstallationId
            || row.ProductId != preflight.ProductId)
        {
            return new(SecurityLockAdminOutcomes.RecoveryConflict, null, "release_report_scope_changed");
        }

        var releaseTime = DateTime.UtcNow;
        string? releaseDiagnosticCode = null;
        row.AdminDecision = decision;
        row.AdminDecisionAtUtc = releaseTime;
        row.AdminDecisionBy = admin;
        row.AdminDecisionReason = reason;
        row.State = SecurityLockReportStates.Released;
        row.LastVerdict = SecurityLockVerdicts.Release;
        try
        {
            await RuntimeCriticalRecoveryTransition.StageAsync(
                db, recoveryEnrollment, lease.AuthorityEpoch, releaseTime, recoveryEnrollment.ClientId, "admin-release",
                RuntimeCriticalRecoverySources.AdminRelease, null, row.Id, admin, cancellationToken);
            if (activeEnrollment is null)
                releaseDiagnosticCode = SecurityLockAdminOutcomes.ReleaseNoActiveEnrollment;
            if (row.LinkStatus is SecurityLockReportLinkStatuses.VerifiedSeat
                    or SecurityLockReportLinkStatuses.VerifiedAlias
                && row.LinkLicenseSeatId.HasValue)
            {
                var seat = await db.LicenseSeats.AsNoTracking()
                    .SingleOrDefaultAsync(candidate => candidate.Id == row.LinkLicenseSeatId.Value,
                        cancellationToken);
                if (seat is not null
                    && string.Equals(seat.HardwareId, row.HardwareId, StringComparison.Ordinal))
                {
                    var remembered = await SecurityLockRememberedReleaseStore.CreateOrReactivateAsync(
                        db, row.ProductId, seat.LicenseId, row.HardwareId, row.Cause, row.Id,
                        admin, releaseTime, cancellationToken);
                    row.RememberedReleaseDecisionId = remembered.Id;
                }
                else if (seat is not null)
                {
                    releaseDiagnosticCode ??= SecurityLockAdminOutcomes.RememberedReleaseHardwareChanged;
                }
            }
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (InvalidOperationException exception)
            when (exception.Message == "critical_recovery_generation_conflict")
        {
            return new(SecurityLockAdminOutcomes.RecoveryConflict, null, "release_generation_conflict");
        }
        await lease.CommitAsync(cancellationToken);
        return new(SecurityLockAdminOutcomes.Ok, row, releaseDiagnosticCode);
    }

    /// <summary>
    /// Explicitly reverses one BANNED lock, closes matching open incidents through the shared recovery transition,
    /// and deactivates every applicable active hardware ban in the same authority transaction. This operation does
    /// not create or reactivate a remembered RELEASE decision.
    /// </summary>
    /// <param name="id">Exact security-lock report row identifier.</param>
    /// <param name="reason">Required human reason.</param>
    /// <param name="auditReference">Required named audit reference.</param>
    /// <param name="decidedBy">Named administrator.</param>
    /// <param name="scopedProductId">Product scope, or null for a global administrator.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The closed outcome, updated row, and mutation counts.</returns>
    public async Task<SecurityLockAdminDecisionResult> UnbanAsync(
        Guid id,
        string? reason,
        string? auditReference,
        string? decidedBy,
        Guid? scopedProductId,
        CancellationToken cancellationToken = default)
    {
        var admin = decidedBy?.Trim();
        if (string.IsNullOrEmpty(admin) || admin.Length > 100)
            return new(SecurityLockAdminOutcomes.DecidedByInvalid, null);
        if (string.IsNullOrWhiteSpace(reason))
            return new(SecurityLockAdminOutcomes.ReasonRequired, null);
        if (string.IsNullOrWhiteSpace(auditReference) || auditReference.Length > 100
            || auditReference.Any(char.IsControl))
            return new(SecurityLockAdminOutcomes.AuditReferenceInvalid, null);
        var auditedReason = $"{reason.Trim()} | auditRef={auditReference.Trim()}";
        if (auditedReason.Length > 500)
            return new(SecurityLockAdminOutcomes.ReasonTooLong, null);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var preflight = await db.SecurityLockReports.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == id, cancellationToken);
        if (preflight == null)
            return new(SecurityLockAdminOutcomes.NotFound, null);
        if (scopedProductId.HasValue && scopedProductId.Value != preflight.ProductId)
            return new(SecurityLockAdminOutcomes.Forbidden, null);
        if (!IsCanonicalHardwareId(preflight.HardwareId))
            return Unlinked("report_hardware_noncanonical");

        await using var lease = await _authority.AcquireMutationAsync(db, preflight.BindingId, cancellationToken);
        await SecurityService.AcquireHardwareBanMutationAsync(db, preflight.HardwareId);
        var scopedEnrollments = await db.RuntimeEnrollments.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollments"
            WHERE "BindingId" = {preflight.BindingId}
              AND "InstallationId" = {preflight.InstallationId}
              AND "ProductId" = {preflight.ProductId}
            ORDER BY "Id" FOR UPDATE
            """).ToListAsync(cancellationToken);
        var activeEnrollments = scopedEnrollments
            .Where(candidate => string.Equals(candidate.State, "ACTIVE", StringComparison.Ordinal))
            .ToList();
        if (activeEnrollments.Count > 1 || scopedEnrollments.Count == 0)
            return new(SecurityLockAdminOutcomes.RecoveryConflict, null, "unban_enrollment_scope_changed");
        var activeEnrollment = activeEnrollments.SingleOrDefault();
        var recoveryEnrollment = activeEnrollment ?? scopedEnrollments
            .OrderByDescending(candidate => candidate.SecurityEpoch)
            .ThenByDescending(candidate => candidate.Id)
            .First();

        await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
        var row = await db.SecurityLockReports.FromSqlInterpolated($"""
            SELECT * FROM public."SecurityLockReports" WHERE "Id" = {id} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (row == null)
            return new(SecurityLockAdminOutcomes.NotFound, null);
        if (scopedProductId.HasValue && scopedProductId.Value != row.ProductId)
            return new(SecurityLockAdminOutcomes.Forbidden, null);
        if (row.State != SecurityLockReportStates.Banned)
            return new(SecurityLockAdminOutcomes.LockNotBanned, null);
        if (row.EnrollmentId != preflight.EnrollmentId
            || row.BindingId != preflight.BindingId
            || row.InstallationId != preflight.InstallationId
            || row.ProductId != preflight.ProductId
            || !string.Equals(row.HardwareId, preflight.HardwareId, StringComparison.Ordinal))
            return new(SecurityLockAdminOutcomes.RecoveryConflict, null, "unban_report_scope_changed");

        var now = DateTime.UtcNow;
        row.AdminDecision = SecurityLockAdminDecisions.Unban;
        row.AdminDecisionAtUtc = now;
        row.AdminDecisionBy = admin;
        row.AdminDecisionReason = auditedReason;
        row.State = SecurityLockReportStates.Released;
        row.LastVerdict = SecurityLockVerdicts.Release;
        row.RememberedReleaseDecisionId = null;
        try
        {
            var recovery = await RuntimeCriticalRecoveryTransition.StageAsync(
                db, recoveryEnrollment, lease.AuthorityEpoch, now, recoveryEnrollment.ClientId, "admin-unban",
                RuntimeCriticalRecoverySources.AdminUnban, null, row.Id, admin, cancellationToken);
            var deactivatedBanCount = await SecurityLockBans.StageUnbanAsync(
                db, row.HardwareId, row.ProductId, admin, auditedReason, now, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new(SecurityLockAdminOutcomes.Ok, row,
                activeEnrollment is null ? SecurityLockAdminOutcomes.ReleaseNoActiveEnrollment : null,
                recovery.Incidents.Count, deactivatedBanCount);
        }
        catch (InvalidOperationException exception)
            when (exception.Message == "critical_recovery_generation_conflict")
        {
            return new(SecurityLockAdminOutcomes.RecoveryConflict, null, "unban_generation_conflict");
        }
    }

    /// <summary>Revokes one remembered RELEASE for future detections without reopening historical evidence.</summary>
    public async Task<string> RevokeRememberedReleaseAsync(
        Guid id,
        string? revokedBy,
        Guid? scopedProductId,
        CancellationToken cancellationToken = default)
    {
        var admin = revokedBy?.Trim();
        if (string.IsNullOrEmpty(admin) || admin.Length > 100)
            return SecurityLockAdminOutcomes.DecidedByInvalid;
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var preflight = await db.SecurityLockReleaseDecisions.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == id, cancellationToken);
        if (preflight is null)
            return SecurityLockAdminOutcomes.NotFound;
        if (scopedProductId.HasValue && scopedProductId.Value != preflight.ProductId)
            return SecurityLockAdminOutcomes.Forbidden;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await SecurityLockRememberedReleaseStore.AcquireScopeLockAsync(
            db, preflight.ProductId, preflight.LicenseId, preflight.HardwareId, preflight.Cause,
            cancellationToken);
        var decision = await db.SecurityLockReleaseDecisions.FromSqlInterpolated($"""
            SELECT * FROM public."SecurityLockReleaseDecisions" WHERE "Id" = {id} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (decision is null)
            return SecurityLockAdminOutcomes.NotFound;
        if (scopedProductId.HasValue && scopedProductId.Value != decision.ProductId)
            return SecurityLockAdminOutcomes.Forbidden;
        SecurityLockRememberedReleaseStore.Revoke(decision, admin, DateTime.UtcNow);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return SecurityLockAdminOutcomes.Ok;
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
