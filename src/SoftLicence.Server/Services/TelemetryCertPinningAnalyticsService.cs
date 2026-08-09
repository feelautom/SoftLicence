using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryCertPinningAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryCertPinningAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryCertPinningSummaryResponse?> GetCertPinningSummaryForProductKeyAsync(
        string productKey,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var product = await db.Products.AsNoTracking()
            .Where(p => p.ApiSecret == productKey)
            .Select(p => new { p.Id })
            .FirstOrDefaultAsync(cancellationToken);

        if (product == null)
            return null;

        return await GetCertPinningSummaryForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryCertPinningSummaryResponse> GetCertPinningSummaryForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-cert-pinning-summary:{productId:N}:{days}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryCertPinningSummaryResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Type == TelemetryType.Event
                && r.Timestamp >= since
                && r.EventName.Contains("CertPinning"))
            .Select(r => new
            {
                r.EventName,
                r.HardwareId,
                r.Version,
                PropertiesJson = r.EventData != null ? r.EventData.PropertiesJson : null
            })
            .ToListAsync(cancellationToken);

        var dailyAlerts = await db.TelemetryCertPinningDailyAlerts.AsNoTracking()
            .Where(a => productScopeIds.Contains(a.ProductId)
                && a.AlertType == CertPinningDailyAlertService.AlertType
                && a.LastSeenUtc >= since)
            .OrderByDescending(a => a.LastSeenUtc)
            .Select(a => new TelemetryCertPinningDailyAlertSummary
            {
                ParisDate = a.ParisDate,
                HardwareId = a.HardwareId,
                OccurrenceCount = a.OccurrenceCount,
                ClientSuppressedCount = a.ClientSuppressedCount,
                FirstSeenUtc = a.FirstSeenUtc,
                LastSeenUtc = a.LastSeenUtc,
                FirstHost = a.FirstHost,
                LastHost = a.LastHost,
                LastVersion = a.LastVersion,
                LastFailureReason = a.LastFailureReason,
                LastCertificateIssuer = a.LastCertificateIssuer,
                NotificationAttempted = a.NotificationClaimedAtUtc.HasValue || a.NotificationSentAtUtc.HasValue,
                NotificationSent = a.NotificationSentAtUtc.HasValue
            })
            .ToListAsync(cancellationToken);

        var eventCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var hostCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var reasonCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var versionCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var suppressedFailures = 0;
        var failures = 0;
        var recoveries = 0;

        foreach (var row in rows)
        {
            Increment(eventCounts, row.EventName);

            if (row.EventName.Contains("Recover", StringComparison.OrdinalIgnoreCase))
                recoveries++;
            if (row.EventName.Contains("Fail", StringComparison.OrdinalIgnoreCase))
                failures++;

            if (!string.IsNullOrWhiteSpace(row.Version))
                Increment(versionCounts, row.Version.Trim());

            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
            IncrementIfPresent(hostCounts, props, "Host");

            if (!IncrementIfPresent(reasonCounts, props, "FailureReason"))
                IncrementIfPresent(reasonCounts, props, "Reason");

            suppressedFailures += ParseInt(props, "SuppressedCount");
            suppressedFailures += ParseInt(props, "SuppressedFailures");
        }

        var now = DateTime.UtcNow;
        var response = new TelemetryCertPinningSummaryResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            RecordsAnalyzed = rows.Count,
            Incidents = rows.Count,
            Failures = failures,
            Recoveries = recoveries,
            SuppressedFailures = suppressedFailures,
            UniqueDevices = rows
                .Where(r => !string.IsNullOrWhiteSpace(r.HardwareId))
                .Select(r => r.HardwareId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            DailyAlertGroups = dailyAlerts.Count,
            DailyNotificationsSent = dailyAlerts.Count(a => a.NotificationSent),
            DailyOccurrencesTracked = dailyAlerts.Sum(a => a.OccurrenceCount),
            DailyClientSuppressedTracked = dailyAlerts.Sum(a => a.ClientSuppressedCount),
            EventNames = ToTopCounts(eventCounts, top),
            Hosts = ToTopCounts(hostCounts, top),
            FailureReasons = ToTopCounts(reasonCounts, top),
            Versions = ToTopCounts(versionCounts, top),
            RecentDailyAlerts = dailyAlerts.Take(top).ToList()
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static bool IncrementIfPresent(Dictionary<string, int> counts, Dictionary<string, string> props, string key)
    {
        if (!props.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            return false;

        Increment(counts, value.Trim());
        return true;
    }

    private static int ParseInt(Dictionary<string, string> props, string key)
    {
        return props.TryGetValue(key, out var raw) && int.TryParse(raw, out var value)
            ? value
            : 0;
    }

    private static void Increment(Dictionary<string, int> counts, string key)
    {
        counts[key] = counts.GetValueOrDefault(key) + 1;
    }

    private static List<TelemetryToolCount> ToTopCounts(Dictionary<string, int> counts, int top)
    {
        return counts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .Select(kv => new TelemetryToolCount { Name = kv.Key, Count = kv.Value })
            .ToList();
    }
}
