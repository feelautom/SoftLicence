using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryLicenseHardwareAuditAnalyticsService
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly int[] DefaultWindows = [1, 3, 7, 30];

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryLicenseHardwareAuditAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryLicenseHardwareAuditResponse> GetAuditForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        string? activityWindowsDays = null,
        int take = 50,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, 100);
        var windows = ParseWindows(activityWindowsDays);
        var cacheKey = string.Join(':',
            "telemetry-license-hwid-audit",
            productId.ToString("N"),
            period.FromUtc.ToString("O"),
            period.ToUtc.ToString("O"),
            string.Join(',', windows),
            take);

        if (_cache.TryGetValue(cacheKey, out TelemetryLicenseHardwareAuditResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var now = DateTime.UtcNow;

        var totalTelemetryRecords = await db.TelemetryRecords.AsNoTracking()
            .CountAsync(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Timestamp >= period.FromUtc
                && r.Timestamp <= period.ToUtc,
                cancellationToken);

        var telemetryWithoutHardwareId = await db.TelemetryRecords.AsNoTracking()
            .CountAsync(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Timestamp >= period.FromUtc
                && r.Timestamp <= period.ToUtc
                && string.IsNullOrWhiteSpace(r.HardwareId),
                cancellationToken);

        var telemetrySummaries = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Timestamp >= period.FromUtc
                && r.Timestamp <= period.ToUtc
                && !string.IsNullOrWhiteSpace(r.HardwareId))
            .GroupBy(r => r.HardwareId)
            .Select(g => new AuditTelemetrySummary(
                g.Key,
                g.Count(),
                g.Max(r => r.Timestamp),
                g.OrderByDescending(r => r.Timestamp).Select(r => r.EventName).FirstOrDefault(),
                g.OrderByDescending(r => r.Timestamp).Select(r => r.Version).FirstOrDefault()))
            .ToListAsync(cancellationToken);

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Where(l => productScopeIds.Contains(l.ProductId))
            .ToListAsync(cancellationToken);

        var telemetryByHardware = telemetrySummaries
            .ToDictionary(r => r.HardwareId, StringComparer.OrdinalIgnoreCase);

        var licenseBindings = BuildLicenseBindings(licenses, now);
        var licensesByHardware = licenseBindings
            .GroupBy(l => l.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var observedHardwareIds = telemetryByHardware.Keys.ToList();
        var items = new List<TelemetryLicenseHardwareAuditItem>();

        foreach (var hardwareId in observedHardwareIds)
        {
            var telemetry = telemetryByHardware[hardwareId];
            licensesByHardware.TryGetValue(hardwareId, out var bindings);
            bindings ??= new List<AuditLicenseBinding>();

            var classification = Classify(bindings);
            var selected = SelectBestBinding(bindings);

            items.Add(new TelemetryLicenseHardwareAuditItem
            {
                HardwareIdRedacted = RedactHardwareId(hardwareId),
                HardwareIdHash = HashHardwareId(hardwareId),
                Classification = classification,
                LicenseCount = bindings.Select(b => b.LicenseId).Distinct().Count(),
                LicenseTypeSlug = selected?.LicenseTypeSlug,
                LicenseTypeName = selected?.LicenseTypeName,
                LicenseStatus = selected?.LicenseStatus ?? "none",
                CustomerEmailRedacted = RedactEmail(selected?.CustomerEmail),
                LicenseKeyRedacted = RedactKey(selected?.LicenseKey),
                LastTelemetryUtc = telemetry.LastTelemetryUtc,
                LastVersion = telemetry.LastVersion,
                LastEventName = telemetry.LastEventName,
                EventCount = telemetry.EventCount
            });
        }

        var allLicenseHardwareIds = licenseBindings
            .Select(b => b.HardwareId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var activeValidHardwareIds = licenseBindings
            .Where(b => b.LicenseStatus == "active")
            .Select(b => b.HardwareId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var response = new TelemetryLicenseHardwareAuditResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            ActivityWindowsDays = windows,
            Summary = new TelemetryLicenseHardwareAuditSummary
            {
                TelemetryRecords = totalTelemetryRecords,
                TelemetryMachines = observedHardwareIds.Count,
                TelemetryWithoutHardwareId = telemetryWithoutHardwareId,
                LicenseBoundMachines = allLicenseHardwareIds.Count,
                MachinesWithActiveValidLicense = observedHardwareIds.Count(activeValidHardwareIds.Contains),
                MachinesWithActiveFreemium = CountObservedWith(items, "active_freemium"),
                MachinesWithActivePaid = CountObservedWith(items, "active_paid"),
                MachinesWithExpiredLicense = CountObservedWith(items, "expired"),
                MachinesWithRevokedLicense = CountObservedWith(items, "revoked"),
                MachinesWithoutLicense = CountObservedWith(items, "no_license"),
                MachinesWithMultipleLicenses = CountObservedWith(items, "multiple_licenses"),
                BlockingMismatchDetected = observedHardwareIds.Count > observedHardwareIds.Count(activeValidHardwareIds.Contains)
            },
            WindowActivity = windows
                .Select(w =>
                {
                    var since = now.AddDays(-w);
                    var activeTelemetry = telemetryByHardware.Count(kv => kv.Value.LastTelemetryUtc >= since);
                    var activeValid = telemetryByHardware.Count(kv =>
                        activeValidHardwareIds.Contains(kv.Key)
                        && kv.Value.LastTelemetryUtc >= since);
                    return new TelemetryLicenseHardwareAuditWindow
                    {
                        WindowDays = w,
                        TelemetryMachines = activeTelemetry,
                        MachinesWithActiveValidLicense = activeValid,
                        MachinesWithoutActiveValidLicense = activeTelemetry - activeValid
                    };
                })
                .ToList(),
            ClassificationCounts = items
                .GroupBy(i => i.Classification)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            Anomalies = items
                .Where(i => i.Classification is "no_license" or "expired" or "revoked" or "multiple_licenses")
                .OrderByDescending(i => i.LastTelemetryUtc ?? DateTime.MinValue)
                .ThenBy(i => i.HardwareIdHash, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .ToList()
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static List<AuditLicenseBinding> BuildLicenseBindings(List<License> licenses, DateTime now)
    {
        var result = new List<AuditLicenseBinding>();

        foreach (var license in licenses)
        {
            var status = ResolveLicenseStatus(license, now);
            var hardwareIds = new List<string>();
            if (!string.IsNullOrWhiteSpace(license.HardwareId))
                hardwareIds.Add(license.HardwareId);

            hardwareIds.AddRange(license.Seats
                .Where(s => s.IsActive && !string.IsNullOrWhiteSpace(s.HardwareId))
                .Select(s => s.HardwareId));

            foreach (var hardwareId in hardwareIds.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                result.Add(new AuditLicenseBinding(
                    license.Id,
                    license.Type?.Slug ?? "",
                    license.Type?.Name ?? "",
                    IsPaidType(license.Type),
                    license.LicenseKey,
                    license.CustomerEmail,
                    hardwareId,
                    status));
            }
        }

        return result;
    }

    private static string Classify(List<AuditLicenseBinding> bindings)
    {
        if (bindings.Count == 0)
            return "no_license";

        var licenseCount = bindings.Select(b => b.LicenseId).Distinct().Count();
        if (licenseCount > 1)
            return "multiple_licenses";

        if (bindings.Any(b => b.LicenseStatus == "active" && b.IsPaid))
            return "active_paid";
        if (bindings.Any(b => b.LicenseStatus == "active"))
            return "active_freemium";
        if (bindings.Any(b => b.LicenseStatus == "expired"))
            return "expired";
        if (bindings.Any(b => b.LicenseStatus == "revoked"))
            return "revoked";

        return "unknown";
    }

    private static AuditLicenseBinding? SelectBestBinding(List<AuditLicenseBinding> bindings)
    {
        return bindings
            .OrderByDescending(b => b.LicenseStatus == "active")
            .ThenByDescending(b => b.IsPaid)
            .ThenBy(b => b.LicenseTypeSlug, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    private static string ResolveLicenseStatus(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt.HasValue)
            return "revoked";

        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
            return "expired";

        return "active";
    }

    private static bool IsPaidType(LicenseType? type)
    {
        if (type == null || type.IsFree)
            return false;

        var slug = type.Slug ?? "";
        var name = type.Name ?? "";
        return !slug.Contains("freemium", StringComparison.OrdinalIgnoreCase)
            && !slug.Contains("trial", StringComparison.OrdinalIgnoreCase)
            && !slug.Contains("free", StringComparison.OrdinalIgnoreCase)
            && !name.Contains("freemium", StringComparison.OrdinalIgnoreCase)
            && !name.Contains("trial", StringComparison.OrdinalIgnoreCase)
            && !name.Contains("free", StringComparison.OrdinalIgnoreCase);
    }

    private static int CountObservedWith(List<TelemetryLicenseHardwareAuditItem> items, string classification)
    {
        return items.Count(i => string.Equals(i.Classification, classification, StringComparison.OrdinalIgnoreCase));
    }

    private static List<int> ParseWindows(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return DefaultWindows.ToList();

        var windows = value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(v => int.TryParse(v, out var parsed) ? Math.Clamp(parsed, 1, 30) : (int?)null)
            .Where(v => v.HasValue)
            .Select(v => v!.Value)
            .Distinct()
            .OrderBy(v => v)
            .ToList();

        return windows.Count == 0 ? DefaultWindows.ToList() : windows;
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

    private static string RedactKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return "";

        var compact = key.Replace("-", "").Replace(" ", "");
        if (compact.Length <= 8)
            return "***";

        return $"{compact[..4]}...{compact[^4..]}";
    }

    private static string RedactHardwareId(string hardwareId)
    {
        if (hardwareId.Length <= 8)
            return "***";

        return $"{hardwareId[..6]}...{hardwareId[^4..]}";
    }

    private static string HashHardwareId(string hardwareId)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private sealed record AuditTelemetrySummary(
        string HardwareId,
        int EventCount,
        DateTime LastTelemetryUtc,
        string? LastEventName,
        string? LastVersion);

    private sealed record AuditLicenseBinding(
        Guid LicenseId,
        string LicenseTypeSlug,
        string LicenseTypeName,
        bool IsPaid,
        string LicenseKey,
        string CustomerEmail,
        string HardwareId,
        string LicenseStatus);
}
