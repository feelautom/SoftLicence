using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

internal static class LicenseSeatHardwareResolver
{
    public static List<ResolvedLicenseHardwareId> ResolveActiveHardwareIds(License license)
    {
        var activeSeats = ResolveActiveSeats(license);
        if (activeSeats.Count > 0)
        {
            return activeSeats
                .Select(s => new ResolvedLicenseHardwareId(s.HardwareId, s.FirstActivatedAt, s))
                .DistinctByHardwareId()
                .ToList();
        }

        // Contract: LicenseSeats is the source of truth. Legacy License.HardwareId is only
        // a compatibility fallback for old licenses that have no seat history at all.
        if (!HasSeatHistory(license) && !string.IsNullOrWhiteSpace(license.HardwareId))
            return [new ResolvedLicenseHardwareId(license.HardwareId, license.ActivationDate, null)];

        return [];
    }

    public static LicenseSeat? ResolvePrimaryActiveSeat(License license) =>
        ResolveActiveSeats(license).FirstOrDefault();

    public static bool HasSeatHistory(License license) => license.Seats.Count > 0;

    public static bool HasHardwareMatch(License license, string hardwareId, bool partial)
    {
        var resolved = ResolveActiveHardwareIds(license);
        return partial
            ? resolved.Any(h => h.HardwareId.Contains(hardwareId, StringComparison.OrdinalIgnoreCase))
            : resolved.Any(h => string.Equals(h.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase));
    }

    private static List<LicenseSeat> ResolveActiveSeats(License license) =>
        license.Seats
            .Where(s => s.IsActive && !string.IsNullOrWhiteSpace(s.HardwareId))
            .OrderBy(s => s.FirstActivatedAt)
            .ToList();

    private static IEnumerable<ResolvedLicenseHardwareId> DistinctByHardwareId(this IEnumerable<ResolvedLicenseHardwareId> hardwareIds) =>
        hardwareIds
            .GroupBy(h => h.HardwareId, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First());
}

internal sealed record ResolvedLicenseHardwareId(
    string HardwareId,
    DateTime? FirstActivatedAt,
    LicenseSeat? Seat);
