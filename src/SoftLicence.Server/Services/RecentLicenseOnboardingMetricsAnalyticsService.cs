using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class RecentLicenseOnboardingMetricsAnalyticsService
{
    private const string DefaultLicenseTypeFilter = "paid";
    private const string DefaultStatusFilter = "active";
    private const int DefaultTake = 10;
    private const int MaxTake = 100;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly string[] FreeLicenseMarkers = { "freemium", "free", "trial" };

    private static readonly HashSet<string> ProductiveEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "BlockGeneration_Success",
        "Compile_Success",
        "Block_Export",
        "Block_Import",
        "Tag_Create",
        "Tag_Update",
        "Tag_Export",
        "Project_Open",
        "Project_Save",
        "ExternalSource_ImportAndGenerate"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public RecentLicenseOnboardingMetricsAnalyticsService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<RecentLicenseOnboardingMetricsResponse> GetMetricsForProductIdAsync(
        Guid productId,
        int take = DefaultTake,
        string? licenseType = DefaultLicenseTypeFilter,
        string? status = DefaultStatusFilter,
        int? activationAgeMaxDays = null,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);
        var normalizedLicenseType = NormalizeLicenseTypeFilter(licenseType);
        var normalizedStatus = NormalizeStatus(status);
        activationAgeMaxDays = activationAgeMaxDays.HasValue
            ? Math.Clamp(activationAgeMaxDays.Value, 0, 3650)
            : null;

        var cacheKey = string.Join(':',
            "recent-license-onboarding-metrics",
            productId.ToString("N"),
            take,
            normalizedLicenseType,
            normalizedStatus,
            activationAgeMaxDays?.ToString() ?? "");

        if (_cache.TryGetValue(cacheKey, out RecentLicenseOnboardingMetricsResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var now = DateTime.UtcNow;

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Where(l => productScopeIds.Contains(l.ProductId) && l.Type != null)
            .ToListAsync(cancellationToken);

        var candidates = licenses
            .Where(l => LicenseTypeMatches(l.Type!, normalizedLicenseType))
            .Where(l => StatusMatches(normalizedStatus, ResolveLicenseStatus(l, now)))
            .Select(l => BuildCandidate(l, now))
            .Where(c => !activationAgeMaxDays.HasValue || c.ActivationAgeDays <= activationAgeMaxDays.Value)
            .OrderByDescending(c => c.OnboardingStartUtc)
            .ThenBy(c => c.CustomerEmail, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var selected = candidates.Take(take).ToList();
        var hardwareIds = selected
            .SelectMany(c => c.HardwareIds)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetryRows = hardwareIds.Count == 0
            ? new List<OnboardingTelemetryRow>()
            : await db.TelemetryRecords.AsNoTracking()
                .Include(r => r.EventData)
                .Where(r => r.ProductId.HasValue
                    && productScopeIds.Contains(r.ProductId.Value)
                    && hardwareIds.Contains(r.HardwareId))
                .Select(r => new OnboardingTelemetryRow(
                    r.HardwareId,
                    r.Timestamp,
                    r.EventName,
                    r.Type.ToString(),
                    r.EventData != null ? r.EventData.PropertiesJson : null))
                .ToListAsync(cancellationToken);

        var telemetryByHardware = telemetryRows
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => r.TimestampUtc).ToList(), StringComparer.OrdinalIgnoreCase);

        var items = selected
            .Select(c => BuildItem(c, telemetryByHardware))
            .ToList();

        var response = new RecentLicenseOnboardingMetricsResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            LicenseTypeFilter = normalizedLicenseType,
            StatusFilter = normalizedStatus,
            ActivationAgeMaxDays = activationAgeMaxDays,
            TotalLicensesMatched = candidates.Count,
            LicensesReturned = items.Count,
            Summary = BuildSummary(items),
            OnboardingSegments = ToTopCounts(items.Select(i => i.OnboardingSegment), 10),
            DetectedPaths = ToTopCounts(items.Select(i => i.DetectedPath), 10),
            Licenses = items
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static OnboardingCandidate BuildCandidate(License license, DateTime now)
    {
        var resolvedHardwareIds = LicenseSeatHardwareResolver.ResolveActiveHardwareIds(license);
        var hardwareIds = resolvedHardwareIds.Select(h => h.HardwareId).ToList();
        var firstSeatActivation = resolvedHardwareIds
            .Where(h => h.Seat != null)
            .Select(h => h.FirstActivatedAt)
            .Where(d => d.HasValue)
            .Min();

        var onboardingStart = license.ActivationDate ?? firstSeatActivation ?? license.CreationDate;
        var activationDateSource = license.ActivationDate.HasValue
            ? "license_activation"
            : firstSeatActivation.HasValue
                ? "seat_first_activation"
                : "license_creation";

        return new OnboardingCandidate
        {
            LicenseId = license.Id,
            LicenseTypeSlug = license.Type?.Slug ?? "",
            LicenseTypeName = license.Type?.Name ?? "",
            LicenseStatus = ResolveLicenseStatus(license, now),
            CustomerEmail = license.CustomerEmail,
            ActivationDateUtc = license.ActivationDate,
            OnboardingStartUtc = onboardingStart,
            ActivationDateSource = activationDateSource,
            ActivationAgeDays = (int)Math.Floor((now - onboardingStart).TotalDays),
            ExpirationDateUtc = license.ExpirationDate,
            HardwareIds = hardwareIds
        };
    }

    private static RecentLicenseOnboardingMetricItem BuildItem(
        OnboardingCandidate candidate,
        Dictionary<string, List<OnboardingTelemetryRow>> telemetryByHardware)
    {
        var rows = candidate.HardwareIds
            .SelectMany(h => telemetryByHardware.TryGetValue(h, out var hardwareRows)
                ? hardwareRows
                : Enumerable.Empty<OnboardingTelemetryRow>())
            .Where(r => r.TimestampUtc >= candidate.OnboardingStartUtc)
            .OrderBy(r => r.TimestampUtc)
            .ToList();

        var primaryHardwareId = candidate.HardwareIds.FirstOrDefault() ?? "";
        var firstProductive = FirstMatching(rows, IsProductiveEvent);
        var firstMcpToolCall = FirstMatching(rows, r => IsMcpToolCall(r.EventName));
        var firstCopilotChat = FirstMatching(rows, r => IsCopilotChat(r.EventName));
        var firstCopilotSuccess = FirstMatching(rows, r => IsCopilotChatSuccess(r.EventName));
        var firstWizardCompleted = FirstMatching(rows, r => EventContains(r.EventName, "Wizard") && EventContains(r.EventName, "Completed"));
        var firstWizardMcpSelected = FirstMatching(rows, r => EventContains(r.EventName, "Wizard") && EventContains(r.EventName, "Mcp") && EventContains(r.EventName, "Selected"));

        var item = new RecentLicenseOnboardingMetricItem
        {
            LicenseId = candidate.LicenseId,
            LicenseTypeSlug = candidate.LicenseTypeSlug,
            LicenseTypeName = candidate.LicenseTypeName,
            LicenseStatus = candidate.LicenseStatus,
            CustomerEmailRedacted = RedactEmail(candidate.CustomerEmail),
            ActivationDateUtc = candidate.ActivationDateUtc,
            OnboardingStartUtc = candidate.OnboardingStartUtc,
            ActivationDateSource = candidate.ActivationDateSource,
            ExpirationDateUtc = candidate.ExpirationDateUtc,
            HardwareIdRedacted = RedactHardwareId(primaryHardwareId),
            HardwareIdHash = HashHardwareId(primaryHardwareId),
            HardwareIdsRedacted = candidate.HardwareIds.Select(RedactHardwareId).ToList(),
            HardwareIdHashes = candidate.HardwareIds.Select(HashHardwareId).ToList(),
            FirstTelemetryUtc = rows.FirstOrDefault()?.TimestampUtc,
            FirstWizardOpenedUtc = FirstMatching(rows, r => EventContains(r.EventName, "Wizard") && EventContains(r.EventName, "Opened")),
            FirstWizardCompletedUtc = firstWizardCompleted,
            FirstWizardMcpToolSelectedUtc = firstWizardMcpSelected,
            FirstCopilotChatUtc = firstCopilotChat,
            FirstCopilotChatSuccessUtc = firstCopilotSuccess,
            FirstMcpToolCallUtc = firstMcpToolCall,
            FirstProductiveEventUtc = firstProductive,
            FirstBlockExportUtc = FirstMatching(rows, r => EventEquals(r.EventName, "Block_Export")),
            FirstProjectOpenUtc = FirstMatching(rows, r => EventEquals(r.EventName, "Project_Open") || EventEquals(r.EventName, "Project_Opened")),
            LastTelemetryUtc = rows.LastOrDefault()?.TimestampUtc,
            TotalEvents = rows.Count,
            ProductiveEvents = rows.Count(IsProductiveEvent),
            McpEvents = rows.Count(r => r.EventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase)),
            CopilotEvents = rows.Count(r => r.EventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase)),
            NegativeFlags = BuildNegativeFlags(rows),
            TopEvents = ToTopCounts(rows.Select(r => r.EventName), 10)
        };

        item.MinutesActivationToWizardCompleted = MinutesSince(candidate.OnboardingStartUtc, item.FirstWizardCompletedUtc);
        item.MinutesActivationToMcpSelected = MinutesSince(candidate.OnboardingStartUtc, item.FirstWizardMcpToolSelectedUtc);
        item.MinutesActivationToCopilotChat = MinutesSince(candidate.OnboardingStartUtc, item.FirstCopilotChatUtc);
        item.MinutesActivationToCopilotChatSuccess = MinutesSince(candidate.OnboardingStartUtc, item.FirstCopilotChatSuccessUtc);
        item.MinutesActivationToMcpToolCall = MinutesSince(candidate.OnboardingStartUtc, item.FirstMcpToolCallUtc);
        item.MinutesActivationToProductiveEvent = MinutesSince(candidate.OnboardingStartUtc, item.FirstProductiveEventUtc);
        item.MinutesActivationToLastTelemetry = MinutesSince(candidate.OnboardingStartUtc, item.LastTelemetryUtc);
        item.OnboardingSegment = ResolveOnboardingSegment(item);
        item.DetectedPath = ResolveDetectedPath(rows, item);

        return item;
    }

    private static RecentLicenseOnboardingMetricsSummary BuildSummary(List<RecentLicenseOnboardingMetricItem> items)
    {
        var productiveMinutes = items
            .Select(i => i.MinutesActivationToProductiveEvent)
            .Where(v => v.HasValue)
            .Select(v => v!.Value)
            .OrderBy(v => v)
            .ToList();

        return new RecentLicenseOnboardingMetricsSummary
        {
            WithTelemetry = items.Count(i => i.TotalEvents > 0),
            WithProductiveEvent = items.Count(i => i.ProductiveEvents > 0),
            WithMcpEvents = items.Count(i => i.McpEvents > 0),
            WithCopilotEvents = items.Count(i => i.CopilotEvents > 0),
            MedianMinutesToFirstProductiveEvent = Median(productiveMinutes)
        };
    }

    private static string ResolveOnboardingSegment(RecentLicenseOnboardingMetricItem item)
    {
        if (item.FirstProductiveEventUtc.HasValue)
        {
            var minutes = item.MinutesActivationToProductiveEvent ?? double.MaxValue;
            if (minutes < 15)
                return "fast";
            if (minutes <= 60)
                return "normal";
            return "slow";
        }

        if (item.FirstWizardOpenedUtc.HasValue
            || item.FirstWizardCompletedUtc.HasValue
            || item.FirstWizardMcpToolSelectedUtc.HasValue
            || item.TotalEvents > 0)
        {
            return "setup_only";
        }

        return "stuck";
    }

    private static string ResolveDetectedPath(List<OnboardingTelemetryRow> rows, RecentLicenseOnboardingMetricItem item)
    {
        var hasCopilotViaMcp = rows.Any(r =>
            r.EventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase)
            && (EventContains(r.EventName, "ToolCall")
                || PropertyContains(r.PropertiesJson, "RequestSource", "MCP")
                || PropertyContains(r.PropertiesJson, "RequestSource", "API_Direct")));

        if (hasCopilotViaMcp || (item.CopilotEvents > 0 && item.McpEvents > 0))
            return "copilot_via_mcp";

        if (item.McpEvents > 0)
            return "mcp_direct";

        if (item.CopilotEvents == 0 && item.TotalEvents > 0)
            return "ui_only";

        return "unknown";
    }

    private static List<string> BuildNegativeFlags(List<OnboardingTelemetryRow> rows)
    {
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var eventName = row.EventName;
            if (EventContains(eventName, "Activation") && (EventContains(eventName, "Failed") || EventContains(eventName, "Failure")))
                flags.Add("activation_failed");
            if (EventContains(eventName, "AuthFailed") || EventContains(eventName, "Auth_Failed"))
                flags.Add("auth_failed");
            if (EventContains(eventName, "NoTiaPortal") || EventContains(eventName, "TIA_NotFound"))
                flags.Add("no_tia_portal");
        }

        return flags.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string NormalizeLicenseTypeFilter(string? licenseType)
    {
        var normalized = string.IsNullOrWhiteSpace(licenseType)
            ? DefaultLicenseTypeFilter
            : licenseType.Trim().ToLowerInvariant();

        return normalized switch
        {
            "paid" or "freemium" or "all" => normalized,
            _ => DefaultLicenseTypeFilter
        };
    }

    private static string NormalizeStatus(string? status)
    {
        var normalized = string.IsNullOrWhiteSpace(status)
            ? DefaultStatusFilter
            : status.Trim().ToLowerInvariant();

        return normalized switch
        {
            "active" or "expired" or "revoked" or "not_activated" or "expired_or_revoked" or "all" => normalized,
            _ => DefaultStatusFilter
        };
    }

    private static bool LicenseTypeMatches(LicenseType type, string filter)
    {
        return filter switch
        {
            "all" => true,
            "freemium" => !IsPaidType(type),
            _ => IsPaidType(type)
        };
    }

    private static bool IsPaidType(LicenseType type)
    {
        if (type.IsFree)
            return false;

        var slug = type.Slug ?? "";
        var name = type.Name ?? "";
        return !FreeLicenseMarkers.Any(marker =>
            slug.Contains(marker, StringComparison.OrdinalIgnoreCase)
            || name.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static string ResolveLicenseStatus(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt.HasValue)
            return "revoked";

        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
            return "expired";

        return license.ActivationDate.HasValue || license.Seats.Any(s => s.IsActive)
            ? "active"
            : "not_activated";
    }

    private static bool StatusMatches(string filter, string status)
    {
        return filter switch
        {
            "all" => true,
            "expired_or_revoked" => status is "expired" or "revoked",
            _ => string.Equals(filter, status, StringComparison.OrdinalIgnoreCase)
        };
    }

    private static bool IsProductiveEvent(OnboardingTelemetryRow row)
    {
        return ProductiveEvents.Contains(row.EventName)
            || EventContains(row.EventName, "Success") && (EventContains(row.EventName, "Block") || EventContains(row.EventName, "Compile"));
    }

    private static bool IsMcpToolCall(string eventName)
    {
        return EventEquals(eventName, "Mcp_ToolCall")
            || eventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase) && EventContains(eventName, "ToolCall");
    }

    private static bool IsCopilotChat(string eventName)
    {
        return EventEquals(eventName, "Copilot_Chat")
            || eventName.StartsWith("Copilot_Chat", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCopilotChatSuccess(string eventName)
    {
        return EventEquals(eventName, "Copilot_Chat_Success")
            || EventContains(eventName, "Copilot") && EventContains(eventName, "Chat") && EventContains(eventName, "Success");
    }

    private static DateTime? FirstMatching(List<OnboardingTelemetryRow> rows, Func<OnboardingTelemetryRow, bool> predicate)
    {
        return rows.FirstOrDefault(predicate)?.TimestampUtc;
    }

    private static bool EventEquals(string eventName, string expected)
    {
        return string.Equals(eventName, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static bool EventContains(string eventName, string value)
    {
        return eventName.Contains(value, StringComparison.OrdinalIgnoreCase);
    }

    private static bool PropertyContains(string? propertiesJson, string key, string value)
    {
        var props = TelemetrySchemaRegistry.ParseProperties(propertiesJson);
        return props.TryGetValue(key, out var raw)
            && raw.Contains(value, StringComparison.OrdinalIgnoreCase);
    }

    private static double? MinutesSince(DateTime startUtc, DateTime? endUtc)
    {
        return endUtc.HasValue
            ? Math.Round((endUtc.Value - startUtc).TotalMinutes, 2)
            : null;
    }

    private static double? Median(List<double> values)
    {
        if (values.Count == 0)
            return null;

        var middle = values.Count / 2;
        return values.Count % 2 == 1
            ? values[middle]
            : Math.Round((values[middle - 1] + values[middle]) / 2.0, 2);
    }

    private static List<TelemetryToolCount> ToTopCounts(IEnumerable<string> values, int take)
    {
        return values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .GroupBy(v => v)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Take(take)
            .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
            .ToList();
    }

    private static string RedactEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "";

        var parts = email.Trim().Split('@', 2);
        if (parts.Length != 2)
            return "***";

        var local = parts[0];
        var prefix = local.Length <= 2 ? local[..1] : local[..Math.Min(2, local.Length)];
        return $"{prefix}***@{parts[1]}";
    }

    private static string RedactHardwareId(string hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "";

        if (hardwareId.Length <= 8)
            return "***";

        return $"{hardwareId[..6]}...{hardwareId[^4..]}";
    }

    private static string HashHardwareId(string hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "";

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private sealed class OnboardingCandidate
    {
        public Guid LicenseId { get; set; }
        public string LicenseTypeSlug { get; set; } = "";
        public string LicenseTypeName { get; set; } = "";
        public string LicenseStatus { get; set; } = "";
        public string CustomerEmail { get; set; } = "";
        public DateTime? ActivationDateUtc { get; set; }
        public DateTime OnboardingStartUtc { get; set; }
        public string ActivationDateSource { get; set; } = "";
        public int ActivationAgeDays { get; set; }
        public DateTime? ExpirationDateUtc { get; set; }
        public List<string> HardwareIds { get; set; } = new();
    }

    private sealed record OnboardingTelemetryRow(
        string HardwareId,
        DateTime TimestampUtc,
        string EventName,
        string Type,
        string? PropertiesJson);
}
