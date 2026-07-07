using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryStartupHealthAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private const string StartupEventName = "Startup_AppStarted";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private static readonly string[] FingerprintKeys =
    {
        "FP_CPU",
        "FP_MB",
        "FP_BIOS",
        "FP_DISK",
        "FP_HOST",
        "FP_EXE",
        "FP_DLL",
        "FP_CORE"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryStartupHealthAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryStartupHealthResponse?> GetStartupHealthForProductKeyAsync(
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

        return await GetStartupHealthForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryStartupHealthResponse> GetStartupHealthForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-startup-health:{productId:N}:{days}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryStartupHealthResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Type == TelemetryType.Event
                && r.EventName == StartupEventName
                && r.Timestamp >= since)
            .Select(r => new
            {
                r.HardwareId,
                PropertiesJson = r.EventData != null ? r.EventData.PropertiesJson : null
            })
            .ToListAsync(cancellationToken);

        var overallStatuses = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var selectedVersions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var licenseEditions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var failedChecks = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var warningChecks = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var flags = new TelemetryStartupFlagSummary();
        var checkTotals = new TelemetryStartupCheckTotals();

        foreach (var row in rows)
        {
            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);

            IncrementIfPresent(overallStatuses, props, "OverallStatus");
            IncrementIfPresent(selectedVersions, props, "SelectedVersion");

            if (!IncrementIfPresent(licenseEditions, props, "LicenseEdition"))
                IncrementIfPresent(licenseEditions, props, "LicenseTypeSlug");

            checkTotals.PassCount += ParseInt(props, "PassCount");
            checkTotals.WarningCount += ParseInt(props, "WarningCount");
            checkTotals.FailCount += ParseInt(props, "FailCount");

            TrackBoolFlag(props, "IsAdministrator", () => flags.AdminTrue++, () => flags.AdminFalse++);
            TrackBoolFlag(props, "IsVM", () => flags.VmTrue++, null);
            TrackBoolFlag(props, "IsSandbox", () => flags.SandboxTrue++, null);

            if (FingerprintKeys.Any(props.ContainsKey))
                flags.FingerprintSamples++;

            TrackCheckList(failedChecks, props, "FailedChecks");
            TrackCheckList(warningChecks, props, "WarnChecks");
        }

        var now = DateTime.UtcNow;
        var response = new TelemetryStartupHealthResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            StartupEvents = rows.Count,
            UniqueDevices = rows.Select(r => r.HardwareId).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            OverallStatuses = ToTopCounts(overallStatuses, top),
            SelectedTiaVersions = ToTopCounts(selectedVersions, top),
            LicenseEditions = ToTopCounts(licenseEditions, top),
            Flags = flags,
            CheckTotals = checkTotals,
            FailedChecks = ToTopCounts(failedChecks, top),
            WarningChecks = ToTopCounts(warningChecks, top)
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static bool IncrementIfPresent(
        Dictionary<string, int> counts,
        Dictionary<string, string> props,
        string key)
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

    private static void TrackBoolFlag(
        Dictionary<string, string> props,
        string key,
        Action onTrue,
        Action? onFalse)
    {
        if (!props.TryGetValue(key, out var raw))
            return;

        if (bool.TryParse(raw, out var value))
        {
            if (value)
                onTrue();
            else
                onFalse?.Invoke();
        }
    }

    private static void TrackCheckList(
        Dictionary<string, int> counts,
        Dictionary<string, string> props,
        string key)
    {
        if (!props.TryGetValue(key, out var raw) || string.IsNullOrWhiteSpace(raw))
            return;

        var checks = raw.Split(new[] { ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var check in checks)
        {
            if (!string.IsNullOrWhiteSpace(check))
                Increment(counts, check);
        }
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
