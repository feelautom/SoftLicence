using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryActivationFunnelAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryActivationFunnelAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryActivationFunnelResponse?> GetActivationFunnelForProductKeyAsync(
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
            .Select(p => new { p.Id, p.Name })
            .FirstOrDefaultAsync(cancellationToken);

        if (product == null)
            return null;

        return await GetActivationFunnelForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryActivationFunnelResponse> GetActivationFunnelForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var product = await db.Products.AsNoTracking()
            .Where(p => p.Id == productId)
            .Select(p => new { p.Id, p.Name })
            .FirstAsync(cancellationToken);

        var cacheKey = $"telemetry-activation-funnel:{product.Id:N}:{days}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryActivationFunnelResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, product.Id, cancellationToken);
        var productNames = await db.Products.AsNoTracking()
            .Where(p => productScopeIds.Contains(p.Id))
            .Select(p => p.Name.ToLower())
            .ToListAsync(cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);

        var licenses = await db.Licenses.AsNoTracking()
            .Where(l => productScopeIds.Contains(l.ProductId)
                && (l.CreationDate >= since || (l.ActivationDate != null && l.ActivationDate >= since)))
            .Select(l => new LicenseFunnelRow(l.CreationDate, l.ActivationDate))
            .ToListAsync(cancellationToken);

        var logs = await db.AccessLogs.AsNoTracking()
            .Where(l => l.Timestamp >= since
                && productNames.Contains(l.AppName.ToLower())
                && (l.Endpoint == "ACTIVATE" || l.Endpoint == "TRIAL_AUTO" || l.Endpoint == "CHECK"))
            .Select(l => new AccessLogFunnelRow(
                l.Timestamp,
                l.Endpoint,
                l.IsSuccess,
                l.ResultStatus,
                l.HardwareId,
                l.ClientIp))
            .ToListAsync(cancellationToken);

        var activationLogs = logs.Where(l => l.Endpoint == "ACTIVATE").ToList();
        var trialLogs = logs.Where(l => l.Endpoint == "TRIAL_AUTO").ToList();
        var activationFailures = activationLogs.Where(l => !l.IsSuccess).ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryActivationFunnelResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            LicensesCreated = licenses.Count(l => l.CreationDate >= since),
            LicensesActivated = licenses.Count(l => l.ActivationDate.HasValue && l.ActivationDate.Value >= since),
            LicensesCreatedAndNeverActivated = licenses.Count(l => l.CreationDate >= since && !l.ActivationDate.HasValue),
            ActivationAttempts = activationLogs.Count,
            ActivationSuccesses = activationLogs.Count(l => l.IsSuccess),
            ActivationFailures = activationFailures.Count,
            TrialRequests = trialLogs.Count,
            TrialSuccesses = trialLogs.Count(l => l.IsSuccess),
            TrialFailures = trialLogs.Count(l => !l.IsSuccess),
            CheckRequests = logs.Count(l => l.Endpoint == "CHECK"),
            UniqueActivationDevices = activationLogs
                .Where(l => !string.IsNullOrWhiteSpace(l.HardwareId))
                .Select(l => l.HardwareId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            UniqueActivationIps = activationLogs
                .Where(l => !string.IsNullOrWhiteSpace(l.ClientIp))
                .Select(l => l.ClientIp)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            FailureStatuses = activationFailures
                .Where(l => !string.IsNullOrWhiteSpace(l.ResultStatus))
                .GroupBy(l => l.ResultStatus)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(top)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            DailyFunnel = BuildDailyFunnel(licenses, logs, days)
        };

        response.ActivationSuccessRate = response.ActivationAttempts == 0
            ? 0
            : Math.Round(response.ActivationSuccesses * 100.0 / response.ActivationAttempts, 1);

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static List<TelemetryActivationFunnelDay> BuildDailyFunnel(
        List<LicenseFunnelRow> licenses,
        List<AccessLogFunnelRow> logs,
        int days)
    {
        var start = DateTime.UtcNow.Date.AddDays(-(days - 1));
        var result = new List<TelemetryActivationFunnelDay>(days);

        for (var i = 0; i < days; i++)
        {
            var date = start.AddDays(i);
            var dayLogs = logs.Where(l => l.Timestamp.Date == date).ToList();

            result.Add(new TelemetryActivationFunnelDay
            {
                DateUtc = date,
                LicensesCreated = licenses.Count(l => l.CreationDate.Date == date),
                LicensesActivated = licenses.Count(l => l.ActivationDate.HasValue && l.ActivationDate.Value.Date == date),
                ActivationAttempts = dayLogs.Count(l => l.Endpoint == "ACTIVATE"),
                ActivationSuccesses = dayLogs.Count(l => l.Endpoint == "ACTIVATE" && l.IsSuccess),
                ActivationFailures = dayLogs.Count(l => l.Endpoint == "ACTIVATE" && !l.IsSuccess),
                TrialRequests = dayLogs.Count(l => l.Endpoint == "TRIAL_AUTO")
            });
        }

        return result;
    }

    private sealed record LicenseFunnelRow(DateTime CreationDate, DateTime? ActivationDate);

    private sealed record AccessLogFunnelRow(
        DateTime Timestamp,
        string Endpoint,
        bool IsSuccess,
        string ResultStatus,
        string HardwareId,
        string ClientIp);
}
