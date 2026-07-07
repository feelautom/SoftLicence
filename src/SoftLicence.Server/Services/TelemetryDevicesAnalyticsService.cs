using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryDevicesAnalyticsService
{
    private const int DefaultTake = 100;
    private const int MaxTake = 500;
    private const int DefaultTopEvents = 5;
    private const int MaxTopEvents = 20;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryDevicesAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryDevicesResponse> GetDevicesForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        int take = DefaultTake,
        int topEvents = DefaultTopEvents,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);
        topEvents = Math.Clamp(topEvents, 1, MaxTopEvents);

        var cacheKey = $"telemetry-devices:{productId:N}:{period.CacheKey}:{take}:{topEvents}";
        if (_cache.TryGetValue(cacheKey, out TelemetryDevicesResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= period.FromUtc && r.Timestamp < period.ToUtc)
            .Select(r => new DeviceTelemetryRow(
                r.Timestamp,
                r.HardwareId,
                r.ClientIp,
                r.AppName,
                r.Version,
                r.EventName,
                r.Type))
            .ToListAsync(cancellationToken);

        var devices = rows
            .Where(r => !string.IsNullOrWhiteSpace(r.HardwareId))
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .Select(g => BuildDeviceSummary(g.ToList(), topEvents))
            .OrderByDescending(d => d.LastSeenUtc)
            .ThenBy(d => d.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var returned = devices.Take(take).ToList();
        var now = DateTime.UtcNow;
        var response = new TelemetryDevicesResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            RecordsAnalyzed = rows.Count,
            TotalDevices = devices.Count,
            DevicesReturned = returned.Count,
            Devices = returned
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static TelemetryDeviceSummary BuildDeviceSummary(List<DeviceTelemetryRow> rows, int topEvents)
    {
        var latestVersion = rows
            .Where(r => !string.IsNullOrWhiteSpace(r.Version))
            .OrderByDescending(r => r.Timestamp)
            .Select(r => r.Version)
            .FirstOrDefault();
        var latestClientIp = rows
            .Where(r => !string.IsNullOrWhiteSpace(r.ClientIp))
            .OrderByDescending(r => r.Timestamp)
            .Select(r => r.ClientIp)
            .FirstOrDefault();
        var latestAppName = rows
            .Where(r => !string.IsNullOrWhiteSpace(r.AppName))
            .OrderByDescending(r => r.Timestamp)
            .Select(r => r.AppName)
            .FirstOrDefault();

        return new TelemetryDeviceSummary
        {
            HardwareId = rows[0].HardwareId,
            FirstSeenUtc = rows.Min(r => r.Timestamp),
            LastSeenUtc = rows.Max(r => r.Timestamp),
            EventCount = rows.Count,
            LastVersion = latestVersion,
            LastClientIp = latestClientIp,
            AppName = latestAppName,
            TopEvents = rows
                .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => r.EventName)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(topEvents)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            EventFamilies = rows
                .Where(r => r.Type == TelemetryType.Event && !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => TelemetrySchemaRegistry.ClassifyFamily(r.EventName))
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(topEvents)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList()
        };
    }

    private sealed record DeviceTelemetryRow(
        DateTime Timestamp,
        string HardwareId,
        string? ClientIp,
        string AppName,
        string? Version,
        string EventName,
        TelemetryType Type);
}
