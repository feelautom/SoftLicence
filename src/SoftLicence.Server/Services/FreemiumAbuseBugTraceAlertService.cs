using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class FreemiumAbuseBugTraceAlertService
{
    private const string DefaultLicenseType = "TIA-CONNECT-FREEMIUM";
    private const int AlertPolicyLevel = 2;
    private const int AnalysisDays = 7;
    private const int AnalysisTake = 20;
    private const int MaxTicketsPerAnalysis = 3;
    private static readonly ConcurrentDictionary<string, DateTime> CreatedTicketCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<Guid, DateTime> LastAnalysisByProduct = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan ProductAnalysisThrottle = TimeSpan.FromMinutes(15);
    private static readonly SemaphoreSlim AnalysisGate = new(1, 1);

    private static readonly HashSet<string> ProductiveEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "BlockGeneration_Success",
        "Compile_Success",
        "Block_Export",
        "Block_Import",
        "Tag_Create",
        "Tag_Update",
        "Tag_Delete",
        "Tag_Export",
        "Project_Save",
        "ExternalSource_ImportAndGenerate"
    };

    private readonly FreemiumAbuseRiskAnalyticsService _riskAnalytics;
    private readonly IBugTraceProxyService _bugTrace;
    private readonly ILogger<FreemiumAbuseBugTraceAlertService> _logger;
    private readonly bool _autoTicketCreationEnabled;

    public FreemiumAbuseBugTraceAlertService(
        FreemiumAbuseRiskAnalyticsService riskAnalytics,
        IBugTraceProxyService bugTrace,
        ILogger<FreemiumAbuseBugTraceAlertService> logger,
        IConfiguration config)
    {
        _riskAnalytics = riskAnalytics;
        _bugTrace = bugTrace;
        _logger = logger;
        _autoTicketCreationEnabled = config.GetValue("SOFTLICENCE_FREEMIUM_ABUSE_AUTO_TICKETS", false);
    }

    public async Task HandleTelemetryAsync(Guid productId, TelemetryEventRequest request, CancellationToken ct = default)
    {
        if (!_autoTicketCreationEnabled)
            return;

        if (!_bugTrace.IsConfigured)
            return;

        if (!ShouldAnalyze(request))
            return;

        RemoveExpiredCacheEntries();

        var now = DateTime.UtcNow;
        if (LastAnalysisByProduct.TryGetValue(productId, out var lastAnalysis)
            && now - lastAnalysis < ProductAnalysisThrottle)
        {
            _logger.LogDebug(
                "Skipping Freemium abuse analysis for product {ProductId}: throttled for {RemainingSeconds}s",
                productId,
                (int)(ProductAnalysisThrottle - (now - lastAnalysis)).TotalSeconds);
            return;
        }

        if (!await AnalysisGate.WaitAsync(0, ct))
        {
            _logger.LogDebug(
                "Skipping Freemium abuse analysis for product {ProductId}: another analysis is already running",
                productId);
            return;
        }

        try
        {
            LastAnalysisByProduct[productId] = DateTime.UtcNow;

            var period = TelemetryAnalyticsPeriod.Resolve(AnalysisDays, null, null, null);
            var risk = await _riskAnalytics.GetRiskForProductIdAsync(
                productId,
                period,
                DefaultLicenseType,
                AnalysisTake,
                ct);

            var createdInAnalysis = 0;
            foreach (var group in risk.Groups.Where(ShouldCreateTicket))
            {
                if (createdInAnalysis >= MaxTicketsPerAnalysis)
                    break;

                if (!CreatedTicketCache.TryAdd(group.DeduplicationKey, DateTime.UtcNow))
                    continue;

                try
                {
                    var ticket = new
                    {
                        version = "main",
                        type = "IMPROVEMENT",
                        priority = group.PolicyLevel >= 5 || string.Equals(group.RiskBand, "high", StringComparison.OrdinalIgnoreCase)
                            ? "HIGH"
                            : "NORMAL",
                        title = BuildTitle(group),
                        description = BuildDescription(risk, group, request),
                        reporterEmail = "internal@feelautom.local",
                        isInternal = true,
                        tags = new[]
                        {
                            "softlicence",
                            "freemium",
                            "anti-abuse",
                            "risk-scoring",
                            "multi-account",
                            "multi-hwid",
                            "auto-alert",
                            $"dedupe:{ShortHash(group.DeduplicationKey)}"
                        }
                    };

                    var result = await _bugTrace.SubmitTicketAsync(ticket, ct);
                    var ticketNumber = TryGetJsonString(result, "ticketNumber") ?? TryGetJsonString(result, "number") ?? "unknown";
                    _logger.LogWarning(
                        "Created BugTrace ticket {TicketNumber} for Freemium abuse risk dedupe={DedupeKey} score={Score}",
                        ticketNumber,
                        group.DeduplicationKey,
                        group.Score);
                    createdInAnalysis++;
                }
                catch
                {
                    CreatedTicketCache.TryRemove(group.DeduplicationKey, out _);
                    throw;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Failed to create Freemium abuse BugTrace alert for product {ProductId}, HWID {HardwareId}",
                productId,
                request.HardwareId);
        }
        finally
        {
            AnalysisGate.Release();
        }
    }

    private static bool ShouldAnalyze(TelemetryEventRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.EventName))
            return false;

        if (request.EventName.StartsWith("Startup_", StringComparison.OrdinalIgnoreCase))
            return true;

        if (request.EventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase)
            || request.EventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase))
            return true;

        if (ProductiveEvents.Contains(request.EventName))
            return true;

        return request.Properties?.Keys.Any(k => k.StartsWith("Quota_", StringComparison.OrdinalIgnoreCase)) == true;
    }

    private static bool ShouldCreateTicket(FreemiumAbuseRiskGroup group)
    {
        return group.PolicyLevel >= AlertPolicyLevel
            || string.Equals(group.Classification, "security_or_license_signal", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildTitle(FreemiumAbuseRiskGroup group)
    {
        var scope = !string.IsNullOrWhiteSpace(group.EmailDomain)
            ? group.EmailDomain
            : group.HardwareIdHashes.FirstOrDefault() ?? group.GroupType;

        return $"Freemium abuse risk - {group.Classification} - score {group.Score:0.#} - {scope}";
    }

    private static string BuildDescription(
        FreemiumAbuseRiskResponse risk,
        FreemiumAbuseRiskGroup group,
        TelemetryEventRequest trigger)
    {
        var lines = new List<string>
        {
            "## Auto Freemium abuse risk alert",
            "",
            "SoftLicence detected a Freemium usage cluster that should be reviewed manually.",
            "",
            "## Policy",
            "- No automatic revocation was performed.",
            "- No automatic blocking was performed.",
            "- This ticket is an internal review alert only.",
            "",
            "## Trigger",
            $"- EventName: `{trigger.EventName}`",
            $"- AppName: `{trigger.AppName}`",
            $"- Version: `{trigger.Version ?? "unknown"}`",
            $"- HardwareIdHash: `{ShortHash(trigger.HardwareId)}`",
            "",
            "## Group",
            $"- Rank: `{group.Rank}`",
            $"- RiskBand: `{group.RiskBand}`",
            $"- Score: `{group.Score:0.##}`",
            $"- Classification: `{group.Classification}`",
            $"- PolicyLevel: `{group.PolicyLevel}`",
            $"- RecommendedAction: `{group.RecommendedAction}`",
            $"- ReviewCategory: `{group.ReviewCategory}`",
            $"- DeduplicationKey: `{group.DeduplicationKey}`",
            $"- DeduplicationWindow: `{group.DeduplicationWindow}`",
            "",
            "## Scope",
            $"- LicenseType: `{risk.LicenseType}`",
            $"- Period: `{risk.FromUtc:O}` -> `{risk.ToUtc:O}`",
            $"- LicenseCount: `{group.LicenseCount}`",
            $"- ActiveLicenses: `{group.ActiveLicenses}`",
            $"- ExpiredLicenses: `{group.ExpiredLicenses}`",
            $"- RevokedLicenses: `{group.RevokedLicenses}`",
            $"- EmailCount: `{group.EmailCount}`",
            $"- HardwareIdCount: `{group.HardwareIdCount}`",
            $"- ClientIpCount: `{group.ClientIpCount}`",
            $"- TelemetryEvents: `{group.TelemetryEvents}`",
            $"- ProductiveEvents: `{group.ProductiveEvents}`",
            $"- McpCopilotEvents: `{group.McpCopilotEvents}`",
            "",
            "## Redacted identifiers",
            $"- EmailDomain: `{group.EmailDomain ?? "unknown"}`",
            $"- EmailsRedacted: `{string.Join(", ", group.EmailsRedacted)}`",
            $"- CustomerNameHashes: `{string.Join(", ", group.CustomerNameHashes)}`",
            $"- HardwareIdsRedacted: `{string.Join(", ", group.HardwareIdsRedacted)}`",
            $"- HardwareIdHashes: `{string.Join(", ", group.HardwareIdHashes)}`",
            $"- ClientIpsRedacted: `{string.Join(", ", group.ClientIpsRedacted)}`",
            $"- Versions: `{string.Join(", ", group.Versions)}`",
            "",
            "## Signals"
        };

        if (group.Signals.Count == 0)
        {
            lines.Add("- none");
        }
        else
        {
            lines.AddRange(group.Signals.Select(s => $"- `{s.Code}` +{s.Points:0.##}: {s.Detail}"));
        }

        lines.Add("");
        lines.Add("## Top events");
        lines.AddRange(group.TopEvents.Count == 0
            ? new[] { "- none" }
            : group.TopEvents.Select(e => $"- `{e.Name}`: {e.Count}"));

        lines.Add("");
        lines.Add("## Quota peaks");
        lines.AddRange(group.QuotaPeaks.Count == 0
            ? new[] { "- none" }
            : group.QuotaPeaks.Select(q => $"- `{q.QuotaKey}`: {q.PeakUsed}/{q.Limit?.ToString() ?? "unknown"} ({q.PeakPercentage?.ToString("0.#") ?? "unknown"}%)"));

        lines.Add("");
        lines.Add("## Initial recommendation");
        lines.Add("- Review the cluster manually before contacting the customer or changing any license state.");

        return string.Join(Environment.NewLine, lines);
    }

    private static string ShortHash(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "unknown";

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private static string? TryGetJsonString(System.Text.Json.JsonElement element, string propertyName)
    {
        if (element.ValueKind != System.Text.Json.JsonValueKind.Object)
            return null;

        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                return property.Value.ValueKind == System.Text.Json.JsonValueKind.String
                    ? property.Value.GetString()
                    : property.Value.ToString();
        }

        return null;
    }

    private static void RemoveExpiredCacheEntries()
    {
        var cutoff = DateTime.UtcNow - CacheTtl;
        foreach (var entry in CreatedTicketCache)
        {
            if (entry.Value < cutoff)
                CreatedTicketCache.TryRemove(entry.Key, out _);
        }
    }
}
