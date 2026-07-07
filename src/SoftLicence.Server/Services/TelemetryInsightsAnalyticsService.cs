using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryInsightsAnalyticsService
{
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly string[] QuotaKeys =
    {
        "Quota_Api_Daily",
        "Quota_Mcp_Daily",
        "Quota_Copilot_Daily"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryInsightsAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryInsightsResponse> GetInsightsForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        top = Math.Clamp(top, 1, MaxTop);

        var cacheKey = $"telemetry-insights:{productId:N}:{period.CacheKey}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryInsightsResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= period.FromUtc && r.Timestamp < period.ToUtc)
            .Select(r => new InsightTelemetryRow(
                r.Timestamp,
                r.HardwareId,
                r.Version,
                r.Type,
                r.EventName,
                r.EventData != null ? r.EventData.PropertiesJson : null,
                r.ErrorData != null ? r.ErrorData.ErrorType : null))
            .ToListAsync(cancellationToken);

        var insights = new List<TelemetryInsightItem>();
        AddAuthFailures(insights, rows, top);
        AddStartupFailures(insights, rows, top);
        AddCertPinningFailures(insights, rows, top);
        AddActivationFailures(insights, rows, top);
        AddQuotaOpportunities(insights, rows, top);
        AddVersionErrorRates(insights, rows, top);

        insights = insights
            .OrderByDescending(i => SeverityRank(i.Severity))
            .ThenByDescending(i => i.Score ?? i.Count)
            .ThenBy(i => i.Category, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryInsightsResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            RecordsAnalyzed = rows.Count,
            CriticalCount = insights.Count(i => string.Equals(i.Severity, "critical", StringComparison.OrdinalIgnoreCase)),
            WarningCount = insights.Count(i => string.Equals(i.Severity, "warning", StringComparison.OrdinalIgnoreCase)),
            OpportunityCount = insights.Count(i => string.Equals(i.Severity, "opportunity", StringComparison.OrdinalIgnoreCase)),
            Insights = insights
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static void AddAuthFailures(List<TelemetryInsightItem> insights, List<InsightTelemetryRow> rows, int top)
    {
        var matched = rows
            .Where(r => r.EventName.Contains("AuthFailed", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matched.Count == 0)
            return;

        insights.Add(BuildInsight(
            "warning",
            "auth",
            "Authentication failures detected",
            $"{matched.Count} authentication failure telemetry events were recorded.",
            matched,
            top,
            matched.Count));
    }

    private static void AddStartupFailures(List<TelemetryInsightItem> insights, List<InsightTelemetryRow> rows, int top)
    {
        var matched = rows
            .Where(r => r.EventName == "Startup_AppStarted")
            .Where(r =>
            {
                var props = TelemetrySchemaRegistry.ParseProperties(r.PropertiesJson);
                return props.TryGetValue("OverallStatus", out var status)
                    && !status.Equals("Pass", StringComparison.OrdinalIgnoreCase)
                    || ParseInt(props, "FailCount") > 0;
            })
            .ToList();

        if (matched.Count == 0)
            return;

        insights.Add(BuildInsight(
            "warning",
            "startup",
            "Startup health failures detected",
            $"{matched.Count} startup events reported a failed or degraded status.",
            matched,
            top,
            matched.Count));
    }

    private static void AddCertPinningFailures(List<TelemetryInsightItem> insights, List<InsightTelemetryRow> rows, int top)
    {
        var matched = rows
            .Where(r => r.EventName.Contains("CertPinning", StringComparison.OrdinalIgnoreCase)
                && r.EventName.Contains("Fail", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matched.Count == 0)
            return;

        insights.Add(BuildInsight(
            "critical",
            "cert-pinning",
            "Certificate pinning failures detected",
            $"{matched.Count} certificate pinning failure events were recorded.",
            matched,
            top,
            matched.Count));
    }

    private static void AddActivationFailures(List<TelemetryInsightItem> insights, List<InsightTelemetryRow> rows, int top)
    {
        var matched = rows
            .Where(r => r.EventName.Contains("Activation", StringComparison.OrdinalIgnoreCase)
                && (r.EventName.Contains("Fail", StringComparison.OrdinalIgnoreCase)
                    || r.EventName.Contains("Error", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (matched.Count == 0)
            return;

        insights.Add(BuildInsight(
            "warning",
            "activation",
            "Activation failures detected",
            $"{matched.Count} activation failure events were recorded.",
            matched,
            top,
            matched.Count));
    }

    private static void AddQuotaOpportunities(List<TelemetryInsightItem> insights, List<InsightTelemetryRow> rows, int top)
    {
        var peaks = new Dictionary<string, (int Used, int? Limit)>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
            foreach (var key in QuotaKeys)
            {
                if (!props.TryGetValue(key, out var raw))
                    continue;

                var parsed = ParseQuota(raw);
                if (parsed == null)
                    continue;

                if (!peaks.TryGetValue(key, out var current) || parsed.Value.Used > current.Used)
                    peaks[key] = parsed.Value;
            }
        }

        foreach (var peak in peaks)
        {
            if (peak.Value.Limit is not > 0)
                continue;

            var percentage = Math.Round(peak.Value.Used * 100.0 / peak.Value.Limit.Value, 1);
            if (percentage < 80)
                continue;

            insights.Add(new TelemetryInsightItem
            {
                Severity = "opportunity",
                Category = "quota",
                Title = $"{peak.Key} usage reached the plan limit",
                Summary = $"{peak.Key} reached {peak.Value.Used}/{peak.Value.Limit} ({percentage}%). Treat this as strong engagement and a potential upgrade/conversion signal, not as an incident unless users report blocking.",
                Count = 1,
                Score = percentage,
                Breakdown = new List<TelemetryToolCount>
                {
                    new() { Name = peak.Key, Count = peak.Value.Used }
                }
            });
        }
    }

    private static void AddVersionErrorRates(List<TelemetryInsightItem> insights, List<InsightTelemetryRow> rows, int top)
    {
        var versions = rows
            .Where(r => !string.IsNullOrWhiteSpace(r.Version))
            .GroupBy(r => r.Version!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new
            {
                Version = g.Key,
                Records = g.Count(),
                Errors = g.Count(r => r.Type == TelemetryType.Error)
            })
            .Where(v => v.Records >= 5 && v.Errors > 0)
            .Select(v => new
            {
                v.Version,
                v.Records,
                v.Errors,
                ErrorRate = Math.Round(v.Errors * 100.0 / v.Records, 1)
            })
            .Where(v => v.ErrorRate >= 5)
            .OrderByDescending(v => v.ErrorRate)
            .Take(top)
            .ToList();

        foreach (var version in versions)
        {
            insights.Add(new TelemetryInsightItem
            {
                Severity = version.ErrorRate >= 20 ? "critical" : "warning",
                Category = "version",
                Title = $"Version {version.Version} has elevated error rate",
                Summary = $"{version.Errors}/{version.Records} records are errors ({version.ErrorRate}%).",
                Count = version.Errors,
                Score = version.ErrorRate,
                Breakdown = new List<TelemetryToolCount> { new() { Name = version.Version, Count = version.Errors } }
            });
        }
    }

    private static TelemetryInsightItem BuildInsight(
        string severity,
        string category,
        string title,
        string summary,
        List<InsightTelemetryRow> rows,
        int top,
        double score)
    {
        return new TelemetryInsightItem
        {
            Severity = severity,
            Category = category,
            Title = title,
            Summary = summary,
            Count = rows.Count,
            Score = score,
            FirstSeenUtc = rows.Min(r => r.Timestamp),
            LastSeenUtc = rows.Max(r => r.Timestamp),
            Breakdown = rows
                .GroupBy(r => r.EventName, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(top)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList()
        };
    }

    private static int SeverityRank(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "critical" => 3,
            "warning" => 2,
            "opportunity" => 1,
            _ => 0
        };
    }

    private static int ParseInt(Dictionary<string, string> props, string key)
    {
        return props.TryGetValue(key, out var raw) && int.TryParse(raw, out var value) ? value : 0;
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

    private sealed record InsightTelemetryRow(
        DateTime Timestamp,
        string HardwareId,
        string? Version,
        TelemetryType Type,
        string EventName,
        string? PropertiesJson,
        string? ErrorType);
}
