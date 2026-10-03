using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Validates the enrolled credential and approved release independently of commercial ownership.
/// Workflow-specific proof, challenge and replay checks remain with their callers.
/// </summary>
internal static class RuntimeEnrollmentIdentityValidator
{
    internal sealed record ApprovedRelease(IReadOnlyDictionary<string, string> Binaries);

    /// <summary>
    /// Validates a bootstrap credential in either lifecycle state that can receive a signed
    /// licence file. The explicit allowlist prevents a terminal enrollment from selecting its
    /// own required state; commercial eligibility is assessed separately by the caller.
    /// </summary>
    /// <param name="db">Context used only to read credential incident and approved release evidence.</param>
    /// <param name="enrollment">Enrollment required to be PENDING or ACTIVE and structurally complete.</param>
    /// <param name="cancellationToken">Cancels evidence reads without mutating identity.</param>
    /// <returns>Approved release hashes for the caller's separate commercial assessment.</returns>
    internal static Task<ApprovedRelease> ValidateBootstrapAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        CancellationToken cancellationToken)
    {
        if (enrollment.State is not ("PENDING" or "ACTIVE"))
            throw new RuntimeEnrollmentException(
                "enrollment_inactive", StatusCodes.Status422UnprocessableEntity,
                "enrollment_state_invalid");
        return ValidateAsync(db, enrollment, enrollment.State, false, null, cancellationToken);
    }

    /// <summary>
    /// Reads only enrollment, incident and release evidence. It never changes enrollment state and
    /// never infers identity from a seat, licence, assignment or copied hardware identifier.
    /// </summary>
    internal static async Task<ApprovedRelease> ValidateAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        string requiredState,
        bool rejectOpenIncident,
        IReadOnlyDictionary<string, string>? presentedBinaries,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(enrollment.State, requiredState, StringComparison.Ordinal))
            throw new RuntimeEnrollmentException(
                requiredState == "PENDING" ? "enrollment_conflict" : "enrollment_inactive",
                requiredState == "PENDING" ? StatusCodes.Status409Conflict : StatusCodes.Status422UnprocessableEntity,
                "enrollment_state_invalid");

        if (enrollment.Id == Guid.Empty || enrollment.ProductId == Guid.Empty
            || enrollment.ProtocolVersion != RuntimeEnrollmentService.ProtocolVersion
            || enrollment.Algorithm != "PS256"
            || enrollment.Epoch != 1 || enrollment.SecurityEpoch < 1
            || string.IsNullOrWhiteSpace(enrollment.InstallationId)
            || string.IsNullOrWhiteSpace(enrollment.ReleaseVersion)
            || string.IsNullOrWhiteSpace(enrollment.PublicKeySpkiCiphertext)
            || string.IsNullOrWhiteSpace(enrollment.PublicKeySpkiKeyId)
            || enrollment.PublicKeySpkiSha256.Length != 64
            || string.IsNullOrWhiteSpace(enrollment.KeyThumbprint))
            throw new RuntimeEnrollmentException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "enrollment_credential_incomplete");

        if (rejectOpenIncident && await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                incident => incident.BindingId == enrollment.BindingId
                    && incident.InstallationId == enrollment.InstallationId
                    && incident.State == "OPEN", cancellationToken))
            throw new RuntimeEnrollmentException(
                "critical_incident_unresolved", StatusCodes.Status423Locked,
                "critical_incident_unresolved");

        var rows = await db.ApprovedBinaries.AsNoTracking().Where(row =>
                row.ProductId == enrollment.ProductId && row.Version == enrollment.ReleaseVersion)
            .Select(row => new { row.Key, row.Hash, row.Source })
            .ToListAsync(cancellationToken);
        var expected = new[] { "FP_CORE", "FP_DLL", "FP_EXE" };
        if (rows.Count != expected.Length || rows.Any(row =>
                row.Source != ApprovedBinaryService.ReleaseSource
                || !expected.Contains(row.Key, StringComparer.Ordinal)
                || row.Hash.Length != 64
                || row.Hash.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            || rows.Select(row => row.Key).Distinct(StringComparer.Ordinal).Count() != expected.Length)
            throw new RuntimeEnrollmentException(
                "authority_ineligible", StatusCodes.Status422UnprocessableEntity,
                "release_unapproved");

        var baselines = rows.ToDictionary(row => row.Key, row => row.Hash, StringComparer.OrdinalIgnoreCase);
        if (presentedBinaries is not null && (presentedBinaries.Count != expected.Length
            || presentedBinaries.Any(binary => !baselines.TryGetValue(binary.Key, out var hash)
                || !string.Equals(binary.Value, hash, StringComparison.Ordinal))))
            throw new RuntimeEnrollmentException(
                "capability_binary_mismatch", StatusCodes.Status409Conflict,
                "release_binary_mismatch");

        return new ApprovedRelease(baselines);
    }
}
