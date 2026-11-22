using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Shared licence-scoped machine exclusion check called by every seat admission path. An excluded
/// machine can neither create nor reactivate a seat on exactly this licence; every other licence
/// and every other product stay unaffected. This is a commercial admission refusal, never a
/// security ban: <see cref="SoftLicence.Server.Data.BannedHardwareId"/> and security locks are
/// not involved.
/// </summary>
internal static class LicenseHardwareExclusionChecker
{
    /// <summary>Gets the stable public refusal code returned to every admission path.</summary>
    internal const string PublicErrorCode = "license_hardware_excluded";

    /// <summary>
    /// Refuses when an active exclusion of the licence matches the submitted or the resolved
    /// hardware identity. Matching is exact ordinal equality on the canonical 16-character form:
    /// candidates are read through the <c>LicenseId</c> index and compared in memory, so the
    /// decision never depends on a database collation.
    /// </summary>
    /// <param name="db">Caller-owned context whose transaction scopes the read.</param>
    /// <param name="licenseId">Exact licence being admitted to.</param>
    /// <param name="submittedHardwareId">Identifier exactly as received from the client.</param>
    /// <param name="effectiveHardwareId">Identifier resolved by the hardware authority, when known.</param>
    /// <param name="cancellationToken">Cancels the read before any seat mutation.</param>
    /// <exception cref="DistributionOperationException">The machine is excluded on this licence.</exception>
    internal static async Task EnsureNotExcludedAsync(
        LicenseDbContext db,
        Guid licenseId,
        string? submittedHardwareId,
        string? effectiveHardwareId,
        CancellationToken cancellationToken = default)
    {
        var identities = new HashSet<string>(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(submittedHardwareId))
            identities.Add(submittedHardwareId);
        if (!string.IsNullOrEmpty(effectiveHardwareId) && !identities.Contains(effectiveHardwareId))
            identities.Add(effectiveHardwareId);
        if (identities.Count == 0)
            return;

        var activeExclusionHardwareIds = await db.LicenseHardwareExclusions.AsNoTracking()
            .Where(exclusion => exclusion.LicenseId == licenseId && exclusion.LiftedAtUtc == null)
            .Select(exclusion => exclusion.HardwareId)
            .ToListAsync(cancellationToken);
        if (activeExclusionHardwareIds.Any(identities.Contains))
            throw new DistributionOperationException(PublicErrorCode, StatusCodes.Status403Forbidden);
    }
}
