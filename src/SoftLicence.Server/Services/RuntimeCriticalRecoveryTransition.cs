using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Closed origins recorded for a critical recovery transition.</summary>
public static class RuntimeCriticalRecoverySources
{
    /// <summary>The existing authenticated S2S recovery endpoint initiated the transition.</summary>
    public const string S2S = "S2S";

    /// <summary>An authenticated administrator released a security lock.</summary>
    public const string AdminRelease = "ADMIN_RELEASE";
    /// <summary>An authenticated administrator explicitly reversed a banned security lock.</summary>
    public const string AdminUnban = "ADMIN_UNBAN";
}

/// <summary>Result staged by the shared critical-incident recovery core.</summary>
/// <param name="Recovery">Recovery row, or <see langword="null"/> when no incident was open.</param>
/// <param name="Incidents">The exact incidents resolved by the staged recovery.</param>
public sealed record RuntimeCriticalRecoveryTransitionResult(
    RuntimeCriticalRecovery? Recovery,
    IReadOnlyList<RuntimeCriticalIncident> Incidents);

/// <summary>
/// Stages the database portion shared by S2S Recovery and an administrative security-lock release.
/// The caller owns the authority lease, enrollment row lock, commercial read barrier, save and commit.
/// </summary>
public static class RuntimeCriticalRecoveryTransition
{
    /// <summary>
    /// Locks and resolves every open incident for the stable binding and installation, including incidents opened by
    /// historical enrollments, creates one auditable recovery, and advances the current enrollment security generation
    /// exactly once.
    /// </summary>
    public static async Task<RuntimeCriticalRecoveryTransitionResult> StageAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        long authorityEpoch,
        DateTime recoveredAtUtc,
        string recoveredByClientId,
        string recoveredByKeyId,
        string source,
        string? requiredEventId,
        Guid? securityLockReportId,
        string? recoveredByAdmin,
        CancellationToken cancellationToken = default)
    {
        var incidents = await db.RuntimeCriticalIncidents.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeCriticalIncidents"
            WHERE "BindingId" = {enrollment.BindingId}
              AND "InstallationId" = {enrollment.InstallationId}
              AND "State" = 'OPEN'
            ORDER BY "OpenedAtUtc" DESC, "EventId" DESC FOR UPDATE
            """).ToListAsync(cancellationToken);
        if (incidents.Count == 0)
            return new(null, incidents);
        if (incidents.Any(incident => incident.OpenedSecurityEpoch > enrollment.SecurityEpoch)
            || (requiredEventId is not null && !incidents.Any(incident => incident.EventId == requiredEventId)))
        {
            throw new InvalidOperationException("critical_recovery_generation_conflict");
        }

        var newSecurityEpoch = checked(enrollment.SecurityEpoch + 1);
        var recovery = new RuntimeCriticalRecovery
        {
            EnrollmentId = enrollment.Id,
            BindingId = enrollment.BindingId,
            ProductId = enrollment.ProductId,
            InstallationId = enrollment.InstallationId,
            RequestedEventId = requiredEventId ?? incidents[0].EventId,
            OldSecurityEpoch = enrollment.SecurityEpoch,
            NewSecurityEpoch = newSecurityEpoch,
            ResolvedIncidentCount = incidents.Count,
            AuthorityEpoch = authorityEpoch,
            RecoveredByClientId = recoveredByClientId,
            RecoveredByKeyId = recoveredByKeyId,
            Source = source,
            SecurityLockReportId = securityLockReportId,
            RecoveredByAdmin = recoveredByAdmin,
            RecoveredAtUtc = recoveredAtUtc
        };
        db.RuntimeCriticalRecoveries.Add(recovery);
        foreach (var incident in incidents)
        {
            incident.State = "RESOLVED";
            incident.RecoveryId = recovery.Id;
            incident.RecoveredSecurityEpoch = newSecurityEpoch;
            incident.RecoveredAuthorityEpoch = authorityEpoch;
            incident.RecoveredAtUtc = recoveredAtUtc;
        }
        enrollment.SecurityEpoch = newSecurityEpoch;
        return new(recovery, incidents);
    }
}
