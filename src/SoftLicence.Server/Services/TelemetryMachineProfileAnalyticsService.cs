using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryMachineProfileAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private const int DefaultTake = 25;
    private const int MaxTake = 50;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryMachineProfileAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryMachineProfileResponse?> GetMachineProfileForProductKeyAsync(
        string productKey,
        string hardwareId,
        int days = DefaultDays,
        int top = DefaultTop,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);
        take = Math.Clamp(take, 1, MaxTake);
        hardwareId = hardwareId.Trim();

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var product = await db.Products.AsNoTracking()
            .Where(p => p.ApiSecret == productKey)
            .Select(p => new { p.Id })
            .FirstOrDefaultAsync(cancellationToken);

        if (product == null)
            return null;

        return await GetMachineProfileForProductIdAsync(product.Id, hardwareId, days, top, take, cancellationToken);
    }

    public async Task<TelemetryMachineProfileResponse> GetMachineProfileForProductIdAsync(
        Guid productId,
        string hardwareId,
        int days = DefaultDays,
        int top = DefaultTop,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);
        take = Math.Clamp(take, 1, MaxTake);
        hardwareId = hardwareId.Trim();

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-machine-profile:{productId:N}:{hardwareId.ToLowerInvariant()}:{days}:{top}:{take}";
        if (_cache.TryGetValue(cacheKey, out TelemetryMachineProfileResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.HardwareId == hardwareId
                && r.Timestamp >= since)
            .Select(r => new MachineTelemetryRow(
                r.Timestamp,
                r.Type,
                r.EventName,
                r.AppName,
                r.Version,
                r.EventData != null ? r.EventData.PropertiesJson : null,
                r.ErrorData != null ? r.ErrorData.ErrorType : null,
                r.DiagnosticData != null ? r.DiagnosticData.Score : null))
            .ToListAsync(cancellationToken);

        var recent = rows
            .OrderByDescending(r => r.Timestamp)
            .Take(take)
            .Select(r => new TelemetryMachineProfileRecord
            {
                TimestampUtc = r.Timestamp,
                Type = r.Type.ToString(),
                EventName = r.EventName,
                Family = r.Type == TelemetryType.Event
                    ? TelemetrySchemaRegistry.ClassifyFamily(r.EventName)
                    : r.Type.ToString().ToLowerInvariant(),
                AppName = r.AppName,
                Version = r.Version,
                PropertyKeys = TelemetrySchemaRegistry.ParseKeys(r.PropertiesJson),
                ErrorType = r.ErrorType,
                DiagnosticScore = r.DiagnosticScore
            })
            .ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryMachineProfileResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            HardwareId = hardwareId,
            RecordsAnalyzed = rows.Count,
            RealActivityEvents = rows.Count(r => r.Type == TelemetryType.Event && TelemetrySchemaRegistry.IsRealUserActivityEvent(r.EventName)),
            SystemNoiseEvents = rows.Count(r => r.Type == TelemetryType.Event && TelemetrySchemaRegistry.IsSystemNoiseEvent(r.EventName)),
            FirstActivityUtc = rows.Count == 0 ? null : rows.Min(r => r.Timestamp),
            LastActivityUtc = rows.Count == 0 ? null : rows.Max(r => r.Timestamp),
            TypeCounts = ToTopCounts(rows
                .GroupBy(r => r.Type.ToString())
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            EventFamilies = ToTopCounts(rows
                .Where(r => r.Type == TelemetryType.Event)
                .GroupBy(r => TelemetrySchemaRegistry.ClassifyFamily(r.EventName))
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            TopEvents = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => r.EventName)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            Versions = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.Version))
                .GroupBy(r => r.Version!)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            Apps = ToTopCounts(rows
                .Where(r => !string.IsNullOrWhiteSpace(r.AppName))
                .GroupBy(r => r.AppName)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase), top),
            RecentRecords = recent
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
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

    private sealed record MachineTelemetryRow(
        DateTime Timestamp,
        TelemetryType Type,
        string EventName,
        string AppName,
        string? Version,
        string? PropertiesJson,
        string? ErrorType,
        int? DiagnosticScore);
}
