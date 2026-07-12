using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryRawSampleAnalyticsService
{
    private const int DefaultTake = 25;
    private const int MaxTake = 50;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryRawSampleAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryRawSampleResponse> GetRawSampleForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        string? hardwareId,
        string? eventName,
        string? eventFamily,
        string? version,
        string? type,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);

        hardwareId = Normalize(hardwareId);
        eventName = Normalize(eventName);
        eventFamily = Normalize(eventFamily);
        version = Normalize(version);
        type = Normalize(type);

        var cacheKey = string.Join(':',
            "telemetry-raw-sample",
            productId.ToString("N"),
            period.CacheKey,
            hardwareId?.ToLowerInvariant() ?? "",
            eventName?.ToLowerInvariant() ?? "",
            eventFamily?.ToLowerInvariant() ?? "",
            version?.ToLowerInvariant() ?? "",
            type?.ToLowerInvariant() ?? "",
            take);

        if (_cache.TryGetValue(cacheKey, out TelemetryRawSampleResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var query = db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= period.FromUtc && r.Timestamp < period.ToUtc);

        query = ApplyHardwareIdFilter(query, hardwareId);

        if (eventName != null)
            query = query.Where(r => r.EventName == eventName);

        if (version != null)
            query = query.Where(r => r.Version == version);

        if (type != null && Enum.TryParse<TelemetryType>(type, ignoreCase: true, out var parsedType))
            query = query.Where(r => r.Type == parsedType);

        var rows = await query
            .OrderByDescending(r => r.Timestamp)
            .Select(r => new RawTelemetryRow(
                r.Timestamp,
                r.HardwareId,
                r.ClientIp,
                r.AppName,
                r.Version,
                r.EventName,
                r.Type,
                r.EventData != null ? r.EventData.PropertiesJson : null,
                r.ErrorData != null ? r.ErrorData.ErrorType : null,
                r.DiagnosticData != null ? r.DiagnosticData.Score : null))
            .Take(500)
            .ToListAsync(cancellationToken);

        if (eventFamily != null)
        {
            rows = rows
                .Where(r => string.Equals(TelemetrySchemaRegistry.ClassifyFamily(r.EventName), eventFamily, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        var records = rows
            .Take(take)
            .Select(r => new TelemetryRawSampleRecord
            {
                TimestampUtc = r.Timestamp,
                HardwareId = r.HardwareId,
                ClientIp = r.ClientIp,
                AppName = r.AppName,
                Version = r.Version,
                EventName = r.EventName,
                Type = r.Type.ToString(),
                Family = TelemetrySchemaRegistry.ClassifyFamily(r.EventName),
                PropertyKeys = TelemetrySchemaRegistry.ParseKeys(r.PropertiesJson),
                Properties = TelemetrySchemaRegistry.ParseProperties(r.PropertiesJson),
                ErrorType = r.ErrorType,
                DiagnosticScore = r.DiagnosticScore
            })
            .ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryRawSampleResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            RecordsMatched = rows.Count,
            RecordsReturned = records.Count,
            Records = records
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static IQueryable<TelemetryRecord> ApplyHardwareIdFilter(IQueryable<TelemetryRecord> query, string? hardwareId)
    {
        if (hardwareId == null)
            return query;

        var normalized = hardwareId.ToUpperInvariant();
        if (normalized.Length < 6)
            return query.Where(r => r.HardwareId.ToUpper() == normalized);

        var prefix = normalized[..Math.Min(8, normalized.Length)];
        return query.Where(r =>
            r.HardwareId.ToUpper() == normalized
            || r.HardwareId.ToUpper().Contains(normalized)
            || r.HardwareId.ToUpper().StartsWith(prefix));
    }

    private sealed record RawTelemetryRow(
        DateTime Timestamp,
        string HardwareId,
        string? ClientIp,
        string AppName,
        string? Version,
        string EventName,
        TelemetryType Type,
        string? PropertiesJson,
        string? ErrorType,
        int? DiagnosticScore);
}
