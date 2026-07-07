using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryToolUsageAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTop = 20;
    private const int MaxTop = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private static readonly string[] ToolEventNames =
    {
        "Mcp_ToolCall",
        "Copilot_ToolCall"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryToolUsageAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryToolUsageSummaryResponse?> GetToolUsageForProductKeyAsync(
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

        return await GetToolUsageForProductIdAsync(product.Id, days, top, cancellationToken);
    }

    public async Task<TelemetryToolUsageSummaryResponse> GetToolUsageForProductIdAsync(
        Guid productId,
        int days = DefaultDays,
        int top = DefaultTop,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        top = Math.Clamp(top, 1, MaxTop);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var cacheKey = $"telemetry-tool-usage:{productId:N}:{days}:{top}";
        if (_cache.TryGetValue(cacheKey, out TelemetryToolUsageSummaryResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Type == TelemetryType.Event
                && r.Timestamp >= since
                && ToolEventNames.Contains(r.EventName))
            .Select(r => new
            {
                r.EventName,
                PropertiesJson = r.EventData != null ? r.EventData.PropertiesJson : null
            })
            .ToListAsync(cancellationToken);

        var toolCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var providerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var modelCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var sourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var channelCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var quotaPeaks = new Dictionary<string, ParsedQuotaPeak>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows)
        {
            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
            var channel = GetChannel(row.EventName, props);
            Increment(channelCounts, channel);

            if (props.TryGetValue("Tool", out var tool) && !string.IsNullOrWhiteSpace(tool))
                Increment(toolCounts, tool.Trim());

            if (props.TryGetValue("McpTool", out var mcpTool) && !string.IsNullOrWhiteSpace(mcpTool))
                Increment(toolCounts, mcpTool.Trim());

            if (props.TryGetValue("Provider", out var provider) && !string.IsNullOrWhiteSpace(provider))
                Increment(providerCounts, provider.Trim());

            if (props.TryGetValue("Model", out var model) && !string.IsNullOrWhiteSpace(model))
                Increment(modelCounts, model.Trim());

            if (props.TryGetValue("RequestSource", out var source) && !string.IsNullOrWhiteSpace(source))
                Increment(sourceCounts, source.Trim());

            TrackQuotaPeak(quotaPeaks, props, "Quota_Api_Daily");
            TrackQuotaPeak(quotaPeaks, props, "Quota_Mcp_Daily");
            TrackQuotaPeak(quotaPeaks, props, "Quota_Copilot_Daily");
        }

        var now = DateTime.UtcNow;
        var response = new TelemetryToolUsageSummaryResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            RecordsAnalyzed = rows.Count,
            ToolCallEvents = rows.Count,
            Channels = channelCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kv => new TelemetryToolChannelSummary
                {
                    Channel = kv.Key,
                    Count = kv.Value,
                    Percentage = rows.Count == 0 ? 0 : Math.Round(kv.Value * 100.0 / rows.Count, 1)
                })
                .ToList(),
            TopTools = ToTopCounts(toolCounts, top),
            TopProviders = ToTopCounts(providerCounts, top),
            TopModels = ToTopCounts(modelCounts, top),
            RequestSources = ToTopCounts(sourceCounts, top),
            QuotaPeaks = quotaPeaks
                .Values
                .OrderBy(q => q.QuotaKey, StringComparer.OrdinalIgnoreCase)
                .Select(q => new TelemetryQuotaPeak
                {
                    QuotaKey = q.QuotaKey,
                    PeakUsed = q.PeakUsed,
                    Limit = q.Limit,
                    PeakPercentage = q.Limit is > 0
                        ? Math.Round(q.PeakUsed * 100.0 / q.Limit.Value, 1)
                        : null
                })
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

    private static List<TelemetryToolCount> ToTopCounts(Dictionary<string, int> counts, int top)
    {
        return counts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .Select(kv => new TelemetryToolCount { Name = kv.Key, Count = kv.Value })
            .ToList();
    }

    private static void TrackQuotaPeak(
        Dictionary<string, ParsedQuotaPeak> peaks,
        Dictionary<string, string> props,
        string key)
    {
        if (!props.TryGetValue(key, out var raw))
            return;

        var parsed = ParseQuota(raw);
        if (parsed == null)
            return;

        if (!peaks.TryGetValue(key, out var existing) || parsed.Value.Used > existing.PeakUsed)
        {
            peaks[key] = new ParsedQuotaPeak(key, parsed.Value.Used, parsed.Value.Limit);
        }
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

    private sealed record ParsedQuotaPeak(string QuotaKey, int PeakUsed, int? Limit);
}
