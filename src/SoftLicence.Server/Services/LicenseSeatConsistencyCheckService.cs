using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class LicenseSeatConsistencyCheckService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public LicenseSeatConsistencyCheckService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<LicenseSeatConsistencyResponse> CheckProductAsync(
        Guid productId,
        int take = 100,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, 500);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Product)
            .Where(l => productScopeIds.Contains(l.ProductId))
            .ToListAsync(cancellationToken);
        var licenseIds = licenses.Select(l => l.Id).ToList();
        var allSeats = await db.LicenseSeats.AsNoTracking()
            .Where(s => licenseIds.Contains(s.LicenseId))
            .ToListAsync(cancellationToken);
        var seatsByLicenseId = allSeats
            .GroupBy(s => s.LicenseId)
            .ToDictionary(g => g.Key, g => g.ToList());

        var anomalies = new List<LicenseSeatConsistencyAnomaly>();

        foreach (var license in licenses)
        {
            seatsByLicenseId.TryGetValue(license.Id, out var seats);
            seats ??= new List<LicenseSeat>();

            var activeSeats = seats
                .Where(s => s.IsActive)
                .OrderByDescending(s => s.LastCheckInAt)
                .ThenByDescending(s => s.FirstActivatedAt)
                .ToList();

            var expectedSeat = activeSeats.FirstOrDefault();
            var expectedHardwareId = expectedSeat?.HardwareId;
            var expectedActivationDate = expectedSeat?.FirstActivatedAt;
            var legacyHardwareId = Normalize(license.HardwareId);

            if (expectedSeat == null)
            {
                if (seats.Count > 0 && legacyHardwareId != null)
                {
                    anomalies.Add(BuildAnomaly(
                        license,
                        "STALE_LEGACY_WITH_NO_ACTIVE_SEAT",
                        legacyHardwareId,
                        null,
                        license.ActivationDate,
                        null,
                        activeSeats.Count,
                        seats.Count));
                }

                continue;
            }

            if (!string.Equals(legacyHardwareId, expectedHardwareId, StringComparison.OrdinalIgnoreCase))
            {
                anomalies.Add(BuildAnomaly(
                    license,
                    "LEGACY_DIFFERS_FROM_ACTIVE_SEAT",
                    legacyHardwareId,
                    expectedHardwareId,
                    license.ActivationDate,
                    expectedActivationDate,
                    activeSeats.Count,
                    seats.Count));
                continue;
            }

            if (license.ActivationDate != expectedActivationDate)
            {
                anomalies.Add(BuildAnomaly(
                    license,
                    "ACTIVATION_DATE_DIFFERS_FROM_ACTIVE_SEAT",
                    legacyHardwareId,
                    expectedHardwareId,
                    license.ActivationDate,
                    expectedActivationDate,
                    activeSeats.Count,
                    seats.Count));
            }
        }

        var now = DateTime.UtcNow;
        var response = new LicenseSeatConsistencyResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now,
            LicensesChecked = licenses.Count,
            AnomaliesDetected = anomalies.Count,
            AnomaliesReturned = Math.Min(anomalies.Count, take),
            AnomalyCounts = anomalies
                .GroupBy(a => a.AnomalyType)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            Anomalies = anomalies
                .OrderBy(a => a.ProductName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(a => a.LicenseKeyRedacted, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .ToList()
        };

        return response;
    }

    private static LicenseSeatConsistencyAnomaly BuildAnomaly(
        License license,
        string anomalyType,
        string? legacyHardwareId,
        string? expectedHardwareId,
        DateTime? legacyActivationDate,
        DateTime? expectedActivationDate,
        int activeSeatCount,
        int totalSeatCount)
    {
        return new LicenseSeatConsistencyAnomaly
        {
            LicenseId = license.Id,
            ProductName = license.Product?.Name,
            LicenseTypeSlug = license.Type?.Slug,
            CustomerEmailRedacted = RedactEmail(license.CustomerEmail),
            LicenseKeyRedacted = RedactKey(license.LicenseKey),
            AnomalyType = anomalyType,
            LegacyHardwareId = legacyHardwareId,
            ExpectedHardwareId = expectedHardwareId,
            LegacyActivationDateUtc = legacyActivationDate,
            ExpectedActivationDateUtc = expectedActivationDate,
            ActiveSeatCount = activeSeatCount,
            TotalSeatCount = totalSeatCount
        };
    }

    private static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string RedactEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "";

        var parts = email.Split('@', 2);
        if (parts.Length != 2)
            return "***";

        var local = parts[0];
        var prefix = local.Length <= 2 ? local[..1] : local[..Math.Min(2, local.Length)];
        return $"{prefix}***@{parts[1]}";
    }

    private static string RedactKey(string key)
    {
        var compact = key.Replace("-", "").Replace(" ", "");
        if (compact.Length <= 8)
            return "***";

        return $"{compact[..4]}...{compact[^4..]}";
    }
}
