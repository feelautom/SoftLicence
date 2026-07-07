using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryQuotaAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private static readonly string[] QuotaKeys =
    {
        "Quota_Api_Hourly",
        "Quota_Api_Daily",
        "Quota_Mcp_Hourly",
        "Quota_Mcp_Daily",
        "Quota_Copilot_Hourly",
        "Quota_Copilot_Daily"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryQuotaAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryQuotaSummaryResponse?> GetQuotaSummaryForProductKeyAsync(
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

        return await GetQuotaSummaryForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryQuotaSummaryResponse> GetQuotaSummaryForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-quota-summary:{productId:N}:{days}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryQuotaSummaryResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Type == TelemetryType.Event
                && r.Timestamp >= since)
            .Select(r => new
            {
                r.EventName,
                PropertiesJson = r.EventData != null ? r.EventData.PropertiesJson : null
            })
            .ToListAsync(cancellationToken);

        var quotaStats = QuotaKeys.ToDictionary(
            key => key,
            key => new QuotaAccumulator(key),
            StringComparer.OrdinalIgnoreCase);
        var channelCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var sourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var recordsWithQuota = 0;

        foreach (var row in rows)
        {
            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
            var hasQuota = false;

            foreach (var key in QuotaKeys)
            {
                if (!props.TryGetValue(key, out var raw))
                    continue;

                var parsed = ParseQuota(raw);
                if (parsed == null)
                    continue;

                quotaStats[key].Add(parsed.Value.Used, parsed.Value.Limit);
                hasQuota = true;
            }

            if (!hasQuota)
                continue;

            recordsWithQuota++;
            Increment(channelCounts, GetChannel(row.EventName, props));

            if (props.TryGetValue("RequestSource", out var source) && !string.IsNullOrWhiteSpace(source))
                Increment(sourceCounts, source.Trim());
        }

        var now = DateTime.UtcNow;
        var response = new TelemetryQuotaSummaryResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            RecordsAnalyzed = rows.Count,
            RecordsWithQuota = recordsWithQuota,
            Quotas = quotaStats.Values
                .Where(q => q.Samples > 0)
                .OrderBy(q => q.QuotaKey, StringComparer.OrdinalIgnoreCase)
                .Select(q => q.ToMetric())
                .ToList(),
            Channels = channelCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kv => new TelemetryToolChannelSummary
                {
                    Channel = kv.Key,
                    Count = kv.Value,
                    Percentage = recordsWithQuota == 0 ? 0 : Math.Round(kv.Value * 100.0 / recordsWithQuota, 1)
                })
                .ToList(),
            RequestSources = sourceCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(top)
                .Select(kv => new TelemetryToolCount { Name = kv.Key, Count = kv.Value })
                .ToList()
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static string GetChannel(string eventName, Dictionary<string, string> props)
    {
        if (eventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase))
            return "mcp";
        if (eventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase))
            return "copilot";

        if (props.TryGetValue("RequestSource", out var source)
            && source.Contains("MCP", StringComparison.OrdinalIgnoreCase))
        {
            return "mcp";
        }

        return "api";
    }

    private static void Increment(Dictionary<string, int> counts, string key)
    {
        counts[key] = counts.GetValueOrDefault(key) + 1;
    }

    private static (int Used, int? Limit)? ParseQuota(string raw)
    {
        var parts = raw.Split('/', StringSplitOptions.TrimEntries);
        if (parts.Length == 0 || !int.TryParse(parts[0], out var used))
            return null;

        int? limit = null;
        if (parts.Length > 1 && int.TryParse(parts[1], out var parsedLimit))
            limit = parsedLimit;

        return (used, limit);
    }

    private sealed class QuotaAccumulator
    {
        private int _totalUsed;

        public QuotaAccumulator(string quotaKey)
        {
            QuotaKey = quotaKey;
        }

        public string QuotaKey { get; }
        public int Samples { get; private set; }
        public int PeakUsed { get; private set; }
        public int? Limit { get; private set; }

        public void Add(int used, int? limit)
        {
            Samples++;
            _totalUsed += used;

            if (used > PeakUsed)
                PeakUsed = used;

            if (limit.HasValue)
                Limit = limit;
        }

        public TelemetryQuotaMetric ToMetric()
        {
            return new TelemetryQuotaMetric
            {
                QuotaKey = QuotaKey,
                Samples = Samples,
                PeakUsed = PeakUsed,
                Limit = Limit,
                PeakPercentage = Limit is > 0
                    ? Math.Round(PeakUsed * 100.0 / Limit.Value, 1)
                    : null,
                AverageUsed = Samples == 0 ? 0 : Math.Round(_totalUsed * 1.0 / Samples, 1)
            };
        }
    }
}
