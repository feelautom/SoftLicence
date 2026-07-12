using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryActivationFailuresAnalyticsService
{
    private const int DefaultTake = 25;
    private const int MaxTake = 50;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryActivationFailuresAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryActivationFailuresResponse> GetActivationFailuresForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        string? hardwareId,
        string? status,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);
        hardwareId = Normalize(hardwareId);
        status = Normalize(status);

        var cacheKey = string.Join(':',
            "telemetry-activation-failures",
            productId.ToString("N"),
            period.CacheKey,
            hardwareId?.ToLowerInvariant() ?? "",
            status?.ToLowerInvariant() ?? "",
            take);

        if (_cache.TryGetValue(cacheKey, out TelemetryActivationFailuresResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var product = await db.Products.AsNoTracking()
            .Where(p => p.Id == productId)
            .Select(p => new { p.Id, p.Name })
            .FirstAsync(cancellationToken);

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, product.Id, cancellationToken);
        var productNames = await db.Products.AsNoTracking()
            .Where(p => productScopeIds.Contains(p.Id))
            .Select(p => p.Name.ToLower())
            .ToListAsync(cancellationToken);
        var query = db.AccessLogs.AsNoTracking()
            .Where(l => l.Timestamp >= period.FromUtc
                && l.Timestamp < period.ToUtc
                && productNames.Contains(l.AppName.ToLower())
                && l.Endpoint == "ACTIVATE"
                && (!l.IsSuccess || l.ResultStatus == "BANNED" || l.ResultStatus == "COMPONENT_BANNED"));

        if (hardwareId != null)
            query = query.Where(l => l.HardwareId == hardwareId);

        if (status != null)
            query = query.Where(l => l.ResultStatus == status);

        var rows = await query
            .OrderByDescending(l => l.Timestamp)
            .Select(l => new ActivationFailureRow(
                l.Timestamp,
                l.HardwareId,
                l.ClientIp,
                l.StatusCode,
                l.ResultStatus,
                l.ErrorDetails))
            .Take(500)
            .ToListAsync(cancellationToken);

        var hardwareIds = rows
            .Select(r => r.HardwareId)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var latestVersionsByHardware = await GetLatestVersionsByHardwareAsync(
            db,
            productScopeIds,
            period,
            hardwareIds,
            cancellationToken);
        var customerEmailsByHardware = await GetCustomerEmailsByHardwareAsync(
            db,
            productScopeIds,
            hardwareIds,
            cancellationToken);

        var failures = rows
            .Take(take)
            .Select(r => new TelemetryActivationFailureRecord
            {
                TimestampUtc = r.Timestamp,
                HardwareId = r.HardwareId,
                CustomerEmail = customerEmailsByHardware.GetValueOrDefault(r.HardwareId),
                ClientIp = Normalize(r.ClientIp),
                StatusCode = r.StatusCode,
                Status = Normalize(r.ResultStatus) ?? "UNKNOWN",
                FailureReason = BuildFailureReason(r),
                ClientVersion = latestVersionsByHardware.GetValueOrDefault(r.HardwareId)
            })
            .ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryActivationFailuresResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            HardwareId = hardwareId,
            Status = status,
            RecordsMatched = rows.Count,
            RecordsReturned = failures.Count,
            FailureStatuses = rows
                .GroupBy(r => Normalize(r.ResultStatus) ?? "UNKNOWN")
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(MaxTop)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            HardwareIds = rows
                .Where(r => !string.IsNullOrWhiteSpace(r.HardwareId))
                .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(MaxTop)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            ClientVersions = failures
                .Where(f => !string.IsNullOrWhiteSpace(f.ClientVersion))
                .GroupBy(f => f.ClientVersion!, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(MaxTop)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            Failures = failures
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static async Task<Dictionary<string, string>> GetLatestVersionsByHardwareAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        TelemetryAnalyticsPeriod period,
        List<string> hardwareIds,
        CancellationToken cancellationToken)
    {
        if (hardwareIds.Count == 0)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Timestamp >= period.FromUtc
                && r.Timestamp < period.ToUtc
                && hardwareIds.Contains(r.HardwareId)
                && r.Version != null
                && r.Version != "")
            .OrderByDescending(r => r.Timestamp)
            .Select(r => new { r.HardwareId, r.Version })
            .ToListAsync(cancellationToken);

        return rows
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => g.First().Version!,
            StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<Dictionary<string, string>> GetCustomerEmailsByHardwareAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        List<string> hardwareIds,
        CancellationToken cancellationToken)
    {
        if (hardwareIds.Count == 0)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var primaryRows = await db.Licenses.AsNoTracking()
            .Where(l => productScopeIds.Contains(l.ProductId)
                && l.Seats.Count == 0
                && l.HardwareId != null
                && hardwareIds.Contains(l.HardwareId)
                && l.CustomerEmail != "")
            .Select(l => new CustomerEmailHardwareRow(
                l.HardwareId!,
                l.CustomerEmail,
                l.ActivationDate ?? l.CreationDate))
            .ToListAsync(cancellationToken);

        var seatRows = await db.LicenseSeats.AsNoTracking()
            .Where(s => s.License != null
                && productScopeIds.Contains(s.License.ProductId)
                && hardwareIds.Contains(s.HardwareId)
                && s.License.CustomerEmail != "")
            .Select(s => new CustomerEmailHardwareRow(
                s.HardwareId,
                s.License!.CustomerEmail,
                s.LastCheckInAt))
            .ToListAsync(cancellationToken);

        return primaryRows
            .Concat(seatRows)
            .Select(r => r with { CustomerEmail = Normalize(r.CustomerEmail) ?? "" })
            .Where(r => !string.IsNullOrWhiteSpace(r.HardwareId) && !string.IsNullOrWhiteSpace(r.CustomerEmail))
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.SortDateUtc).First().CustomerEmail,
                StringComparer.OrdinalIgnoreCase);
    }

    private static string? BuildFailureReason(ActivationFailureRow row)
    {
        var errorDetails = Normalize(row.ErrorDetails);
        if (errorDetails != null)
            return Truncate(errorDetails, 240);

        return Normalize(row.ResultStatus);
    }

    private static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private sealed record ActivationFailureRow(
        DateTime Timestamp,
        string HardwareId,
        string ClientIp,
        int StatusCode,
        string ResultStatus,
        string? ErrorDetails);

    private sealed record CustomerEmailHardwareRow(
        string HardwareId,
        string CustomerEmail,
        DateTime SortDateUtc);
}
