using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryVersionHealthAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private const string UnknownVersion = "(unknown)";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryVersionHealthAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryVersionHealthResponse?> GetVersionHealthForProductKeyAsync(
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

        return await GetVersionHealthForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryVersionHealthResponse> GetVersionHealthForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-version-health:{productId:N}:{days}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryVersionHealthResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= since)
            .Select(r => new VersionHealthRow(
                r.Timestamp,
                r.HardwareId,
                r.Version,
                r.Type,
                r.EventName,
                r.ErrorData != null ? r.ErrorData.ErrorType : null))
            .ToListAsync(cancellationToken);

        var errorRows = rows.Where(r => r.Type == TelemetryType.Error).ToList();

        var versions = rows
            .GroupBy(r => NormalizeVersion(r.Version), StringComparer.OrdinalIgnoreCase)
            .Select(g => BuildVersionSummary(g.Key, g.ToList(), top))
            .OrderByDescending(v => v.ErrorRate)
            .ThenByDescending(v => v.Errors)
            .ThenByDescending(v => v.Records)
            .ThenBy(v => v.Version, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryVersionHealthResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            RecordsAnalyzed = rows.Count,
            ErrorRecords = errorRows.Count,
            UniqueDevices = rows.Select(r => r.HardwareId).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            Versions = versions,
            TopErrorTypes = ToTopCounts(errorRows
                .Select(r => string.IsNullOrWhiteSpace(r.ErrorType) ? "(unknown)" : r.ErrorType!.Trim()), top),
            TopErrorEvents = ToTopCounts(errorRows
                .Select(r => string.IsNullOrWhiteSpace(r.EventName) ? "(unknown)" : r.EventName.Trim()), top),
            DailyErrors = errorRows
                .GroupBy(r => r.Timestamp.Date)
                .OrderBy(g => g.Key)
                .Select(g => new TelemetryDailyCount { DateUtc = g.Key, Count = g.Count() })
                .ToList()
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static TelemetryVersionHealthSummary BuildVersionSummary(string version, List<VersionHealthRow> rows, int top)
    {
        var errorRows = rows.Where(r => r.Type == TelemetryType.Error).ToList();

        return new TelemetryVersionHealthSummary
        {
            Version = version,
            Records = rows.Count,
            Events = rows.Count(r => r.Type == TelemetryType.Event),
            Diagnostics = rows.Count(r => r.Type == TelemetryType.Diagnostic),
            Errors = errorRows.Count,
            UniqueDevices = rows.Select(r => r.HardwareId).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            ErrorRate = rows.Count == 0 ? 0 : Math.Round((double)errorRows.Count / rows.Count, 4),
            FirstSeenUtc = rows.Min(r => r.Timestamp),
            LastSeenUtc = rows.Max(r => r.Timestamp),
            TopEvents = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                .Select(r => r.EventName.Trim()), top),
            ErrorTypes = ToTopCounts(errorRows
                .Select(r => string.IsNullOrWhiteSpace(r.ErrorType) ? "(unknown)" : r.ErrorType!.Trim()), top),
            ErrorEvents = ToTopCounts(errorRows
                .Select(r => string.IsNullOrWhiteSpace(r.EventName) ? "(unknown)" : r.EventName.Trim()), top)
        };
    }

    private static string NormalizeVersion(string? version)
    {
        return string.IsNullOrWhiteSpace(version) ? UnknownVersion : version.Trim();
    }

    private static List<TelemetryToolCount> ToTopCounts(IEnumerable<string> values, int top)
    {
        return values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
            .ToList();
    }

    private sealed record VersionHealthRow(
        DateTime Timestamp,
        string HardwareId,
        string? Version,
        TelemetryType Type,
        string EventName,
        string? ErrorType);
}
