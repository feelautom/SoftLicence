using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetrySchemaAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTopEvents = 25;
    private const int MaxTopEvents = 100;
    private const int MaxTopSchemasPerEvent = 5;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly string NoPropertiesSignature = "<no-properties>";

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetrySchemaAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetrySchemaSummaryResponse?> GetSchemaSummaryForProductKeyAsync(
        string productKey,
        int days = DefaultDays,
        int topEvents = DefaultTopEvents,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        topEvents = Math.Clamp(topEvents, 1, MaxTopEvents);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var product = await db.Products.AsNoTracking()
            .Where(p => p.ApiSecret == productKey)
            .Select(p => new { p.Id })
            .FirstOrDefaultAsync(cancellationToken);

        if (product == null)
            return null;

        return await GetSchemaSummaryForProductIdAsync(product.Id, days, topEvents, cancellationToken);
    }

    public async Task<TelemetrySchemaSummaryResponse> GetSchemaSummaryForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int topEvents = DefaultTopEvents,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        topEvents = Math.Clamp(topEvents, 1, MaxTopEvents);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-schema-summary:{productId:N}:{days}:{topEvents}";
        if (_cache.TryGetValue(cacheKey, out TelemetrySchemaSummaryResponse? cached) && cached != null)
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

        var keyCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var rowsWithKeys = new List<ParsedTelemetryProperties>(rows.Count);

        foreach (var row in rows)
        {
            var keys = TelemetrySchemaRegistry.ParseKeys(row.PropertiesJson);
            if (keys.Count > 0)
            {
                foreach (var key in keys)
                    keyCounts[key] = keyCounts.GetValueOrDefault(key) + 1;
            }

            rowsWithKeys.Add(new ParsedTelemetryProperties(row.EventName, keys));
        }

        var now = DateTime.UtcNow;
        var response = new TelemetrySchemaSummaryResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            RecordsAnalyzed = rows.Count,
            EventsWithProperties = rowsWithKeys.Count(r => r.Keys.Count > 0),
            CommonKeys = keyCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(50)
                .Select(kv => new TelemetryPropertyKeySummary
                {
                    Key = kv.Key,
                    Count = kv.Value,
                    Percentage = rows.Count == 0 ? 0 : Math.Round(kv.Value * 100.0 / rows.Count, 1)
                })
                .ToList()
        };

        response.Events = rowsWithKeys
            .GroupBy(r => r.EventName)
            .Select(BuildEventSummary)
            .OrderByDescending(e => e.Count)
            .ThenBy(e => e.EventName, StringComparer.OrdinalIgnoreCase)
            .Take(topEvents)
            .ToList();

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static TelemetryEventSchemaSummary BuildEventSummary(IGrouping<string, ParsedTelemetryProperties> group)
    {
        var records = group.ToList();
        var keyCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var schemaCounts = new Dictionary<string, (int Count, List<string> Keys)>(StringComparer.Ordinal);

        foreach (var record in records)
        {
            foreach (var key in record.Keys)
                keyCounts[key] = keyCounts.GetValueOrDefault(key) + 1;

            var signature = record.Keys.Count == 0
                ? NoPropertiesSignature
                : string.Join("|", record.Keys);

            if (schemaCounts.TryGetValue(signature, out var current))
            {
                schemaCounts[signature] = (current.Count + 1, current.Keys);
            }
            else
            {
                schemaCounts[signature] = (1, record.Keys);
            }
        }

        var topSchemas = schemaCounts.Values
            .OrderByDescending(s => s.Count)
            .ThenBy(s => string.Join("|", s.Keys), StringComparer.Ordinal)
            .Take(MaxTopSchemasPerEvent)
            .Select(s => new TelemetrySchemaVariantSummary
            {
                Count = s.Count,
                Percentage = records.Count == 0 ? 0 : Math.Round(s.Count * 100.0 / records.Count, 1),
                Keys = s.Keys
            })
            .ToList();

        return new TelemetryEventSchemaSummary
        {
            EventName = group.Key,
            Family = TelemetrySchemaRegistry.ClassifyFamily(group.Key),
            Count = records.Count,
            EventsWithProperties = records.Count(r => r.Keys.Count > 0),
            SchemaVariants = schemaCounts.Count,
            TopSchemaPercentage = topSchemas.Count == 0 ? 0 : topSchemas[0].Percentage,
            KeyCount = keyCounts.Count,
            CommonKeys = keyCounts
                .Where(kv => kv.Value == records.Count)
                .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kv => kv.Key)
                .ToList(),
            SpecificKeys = keyCounts
                .Where(kv => kv.Value < records.Count)
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(30)
                .Select(kv => kv.Key)
                .ToList(),
            TopSchemas = topSchemas
        };
    }

    private sealed record ParsedTelemetryProperties(string EventName, List<string> Keys);
}
