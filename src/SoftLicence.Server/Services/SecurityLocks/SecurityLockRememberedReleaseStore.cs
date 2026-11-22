using System.Globalization;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>Transaction-local persistence helpers for exact remembered RELEASE decisions.</summary>
internal static class SecurityLockRememberedReleaseStore
{
    private const long AdvisorySalt = 1783;

    /// <summary>Maps the closed set of authenticated canary triggers to security-lock causes.</summary>
    internal static bool TryMapCanaryTrigger(string trigger, out string cause)
    {
        if (string.Equals(trigger, "RuntimeCheck_Debugger", StringComparison.Ordinal))
        {
            cause = "DEBUGGER_ATTACHED_KERNEL";
            return true;
        }
        cause = string.Empty;
        return false;
    }

    /// <summary>Serializes mutations and coverage counters for one exact decision scope.</summary>
    internal static Task AcquireScopeLockAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        string hardwareId,
        string cause,
        CancellationToken cancellationToken)
    {
        var scope = string.Join('|',
            productId.ToString("D", CultureInfo.InvariantCulture),
            licenseId.ToString("D", CultureInfo.InvariantCulture),
            hardwareId.Length.ToString(CultureInfo.InvariantCulture), hardwareId,
            cause.Length.ToString(CultureInfo.InvariantCulture), cause);
        return db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({scope}, {AdvisorySalt}));",
            cancellationToken);
    }

    /// <summary>Locks the exact scope and returns its active remembered decision, if any.</summary>
    internal static async Task<SecurityLockReleaseDecision?> FindActiveAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        string hardwareId,
        string cause,
        CancellationToken cancellationToken)
    {
        await AcquireScopeLockAsync(db, productId, licenseId, hardwareId, cause, cancellationToken);
        return await db.SecurityLockReleaseDecisions.SingleOrDefaultAsync(decision =>
            decision.ProductId == productId
            && decision.LicenseId == licenseId
            && decision.HardwareId == hardwareId
            && decision.Cause == cause
            && decision.IsActive,
            cancellationToken);
    }

    /// <summary>Creates or reactivates the unique exact-scope decision while preserving its first attribution.</summary>
    internal static async Task<SecurityLockReleaseDecision> CreateOrReactivateAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        string hardwareId,
        string cause,
        Guid sourceReportId,
        string admin,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await AcquireScopeLockAsync(db, productId, licenseId, hardwareId, cause, cancellationToken);
        var decision = await db.SecurityLockReleaseDecisions.SingleOrDefaultAsync(candidate =>
            candidate.ProductId == productId
            && candidate.LicenseId == licenseId
            && candidate.HardwareId == hardwareId
            && candidate.Cause == cause,
            cancellationToken);
        if (decision is null)
        {
            decision = new SecurityLockReleaseDecision
            {
                ProductId = productId,
                LicenseId = licenseId,
                HardwareId = hardwareId,
                Cause = cause,
                IsActive = true,
                CreatedAtUtc = nowUtc,
                CreatedBy = admin,
                SourceSecurityLockReportId = sourceReportId,
                ActivatedAtUtc = nowUtc,
                ActivatedBy = admin,
                ActivationCount = 1
            };
            db.SecurityLockReleaseDecisions.Add(decision);
            return decision;
        }
        if (!decision.IsActive)
        {
            decision.IsActive = true;
            decision.ActivatedAtUtc = nowUtc;
            decision.ActivatedBy = admin;
            decision.ActivationCount = checked(decision.ActivationCount + 1);
            decision.SourceSecurityLockReportId = sourceReportId;
            decision.RevokedAtUtc = null;
            decision.RevokedBy = null;
        }
        return decision;
    }

    /// <summary>Records one new covered detection without changing any Runtime generation.</summary>
    internal static void RecordCoverage(SecurityLockReleaseDecision decision, DateTime nowUtc)
    {
        decision.CoveredDetectionCount = checked(decision.CoveredDetectionCount + 1);
        decision.LastCoveredAtUtc = nowUtc;
    }

    /// <summary>Revokes an active decision and retains its complete historical attribution.</summary>
    internal static void Revoke(SecurityLockReleaseDecision decision, string admin, DateTime nowUtc)
    {
        if (!decision.IsActive)
            return;
        decision.IsActive = false;
        decision.RevokedAtUtc = nowUtc;
        decision.RevokedBy = admin;
    }
}
