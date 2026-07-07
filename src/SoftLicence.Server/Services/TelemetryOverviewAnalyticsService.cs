using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryOverviewAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryOverviewAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryOverviewResponse?> GetOverviewForProductKeyAsync(
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

        return await GetOverviewForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryOverviewResponse> GetOverviewForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);
        var period = TelemetryAnalyticsPeriod.Resolve(days, null, null, null);

        return await GetOverviewForProductIdAsync(productId, period, top, cancellationToken);
    }

    public async Task<TelemetryOverviewResponse> GetOverviewForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-overview:{productId:N}:{period.CacheKey}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryOverviewResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= period.FromUtc && r.Timestamp < period.ToUtc)
            .Select(r => new
            {
                r.Timestamp,
                r.HardwareId,
                r.ClientIp,
                r.AppName,
                r.Version,
                r.EventName,
                r.Type
            })
            .ToListAsync(cancellationToken);

        var now = DateTime.UtcNow;
        var response = new TelemetryOverviewResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            RecordsAnalyzed = rows.Count,
            UniqueDevices = rows
                .Where(r => !string.IsNullOrWhiteSpace(r.HardwareId))
                .Select(r => r.HardwareId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            UniqueClientIps = rows
                .Where(r => !string.IsNullOrWhiteSpace(r.ClientIp))
                .Select(r => r.ClientIp!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            FirstActivityUtc = rows.Count == 0 ? null : rows.Min(r => r.Timestamp),
            LastActivityUtc = rows.Count == 0 ? null : rows.Max(r => r.Timestamp),
            TypeCounts = rows
                .GroupBy(r => r.Type.ToString())
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .OrderByDescending(c => c.Count)
                .ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            TopEvents = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => r.EventName)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            EventFamilies = ToTopCounts(rows
                .Where(r => r.Type == TelemetryType.Event && !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => TelemetrySchemaRegistry.ClassifyFamily(r.EventName))
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            TopVersions = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.Version))
                .GroupBy(r => r.Version!)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            TopApps = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.AppName))
                .GroupBy(r => r.AppName)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            DailyActivity = BuildDailyActivity(rows.Select(r => r.Timestamp), GetDailyActivityStartDate(period), period.Days)
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static DateTime GetDailyActivityStartDate(TelemetryAnalyticsPeriod period)
    {
        var lastIncludedDate = period.ToUtc.AddTicks(-1).Date;
        return lastIncludedDate.AddDays(1 - period.Days);
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

    private static List<TelemetryDailyCount> BuildDailyActivity(IEnumerable<DateTime> timestamps, DateTime startDateUtc, int days)
    {
        var counts = timestamps
            .GroupBy(ts => ts.Date)
            .ToDictionary(g => g.Key, g => g.Count());

        var result = new List<TelemetryDailyCount>(days);
        for (var i = 0; i < days; i++)
        {
            var date = startDateUtc.AddDays(i);
            result.Add(new TelemetryDailyCount
            {
                DateUtc = date,
                Count = counts.GetValueOrDefault(date)
            });
        }

        return result;
    }
}
