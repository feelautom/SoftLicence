using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class LicenseUsageScoringAnalyticsService
{
    private const int DefaultTake = 50;
    private const int MaxTake = 100;
    private const int DefaultActivityWindowDays = 14;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly string[] TrialMarkers = { "trial", "freemium", "free", "essai" };
    private static readonly string[] SubscriptionMarkers = { "subscription", "sub", "monthly", "annual", "yearly", "abonnement" };

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

    public LicenseUsageScoringAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<LicenseUsageScoringResponse> GetScoresForProductIdAsync(
        Guid productId,
        int take = DefaultTake,
        string? licenseType = "paid",
        string? status = "active",
        int? activationAgeMaxDays = null,
        int activityWindowDays = DefaultActivityWindowDays,
        double? minScore = null,
        bool includeInactive = false,
        string? sortBy = "score",
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);
        activityWindowDays = Math.Clamp(activityWindowDays, 1, 90);
        activationAgeMaxDays = activationAgeMaxDays.HasValue ? Math.Clamp(activationAgeMaxDays.Value, 0, 3650) : null;
        minScore = minScore.HasValue ? Math.Clamp(minScore.Value, 0, 100) : null;
        var normalizedLicenseType = NormalizeLicenseType(licenseType);
        var normalizedStatus = NormalizeStatus(status);
        var normalizedSort = NormalizeSort(sortBy);

        var cacheKey = string.Join(':',
            "license-usage-scoring",
            productId.ToString("N"),
            take,
            normalizedLicenseType,
            normalizedStatus,
            activationAgeMaxDays?.ToString() ?? "",
            activityWindowDays,
            minScore?.ToString("0.##") ?? "",
            includeInactive,
            normalizedSort);

        if (_cache.TryGetValue(cacheKey, out LicenseUsageScoringResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var now = DateTime.UtcNow;
        var windowStart = now.AddDays(-activityWindowDays);

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Where(l => productScopeIds.Contains(l.ProductId) && l.Type != null)
            .ToListAsync(cancellationToken);

        var candidates = licenses
            .Select(l => BuildCandidate(l, now))
            .Where(c => LicenseTypeMatches(c.LicenseKind, normalizedLicenseType))
            .Where(c => includeInactive && normalizedStatus == "active"
                || StatusMatches(normalizedStatus, c.LicenseStatus))
            .Where(c => !activationAgeMaxDays.HasValue || c.ActivationAgeDays <= activationAgeMaxDays.Value)
            .ToList();

        var hardwareIds = candidates
            .SelectMany(c => c.HardwareIds)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetryRows = hardwareIds.Count == 0
            ? new List<UsageTelemetryRow>()
            : await db.TelemetryRecords.AsNoTracking()
                .Include(r => r.EventData)
                .Where(r => r.ProductId.HasValue
                    && productScopeIds.Contains(r.ProductId.Value)
                    && hardwareIds.Contains(r.HardwareId))
                .Select(r => new UsageTelemetryRow(
                    r.HardwareId,
                    r.Timestamp,
                    r.EventName,
                    r.Type.ToString(),
                    r.EventData != null ? r.EventData.PropertiesJson : null))
                .ToListAsync(cancellationToken);

        var telemetryByHardware = telemetryRows
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => r.TimestampUtc).ToList(), StringComparer.OrdinalIgnoreCase);

        var scored = candidates
            .Select(c => BuildScoreItem(c, telemetryByHardware, now, windowStart))
            .Where(i => !minScore.HasValue || MaxBusinessScore(i) >= minScore.Value)
            .ToList();

        var ordered = Sort(scored, normalizedSort)
            .Take(take)
            .ToList();

        var response = new LicenseUsageScoringResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            LicenseTypeFilter = normalizedLicenseType,
            StatusFilter = normalizedStatus,
            ActivityWindowDays = activityWindowDays,
            ActivationAgeMaxDays = activationAgeMaxDays,
            IncludeInactive = includeInactive,
            SortBy = normalizedSort,
            MinScore = minScore,
            TotalLicensesMatched = scored.Count,
            LicensesReturned = ordered.Count,
            Summary = BuildSummary(scored),
            Classifications = ToTopCounts(scored.Select(i => i.Classification), 20),
            DetectedPaths = ToTopCounts(scored.Select(i => i.DetectedPath), 20),
            Licenses = ordered
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static UsageCandidate BuildCandidate(License license, DateTime now)
    {
        var activeSeats = license.Seats
            .Where(s => !string.IsNullOrWhiteSpace(s.HardwareId) && s.IsActive)
            .OrderBy(s => s.FirstActivatedAt)
            .ToList();

        var hardwareIds = new List<string>();
        if (!string.IsNullOrWhiteSpace(license.HardwareId))
            hardwareIds.Add(license.HardwareId);
        hardwareIds.AddRange(activeSeats.Select(s => s.HardwareId));
        hardwareIds = hardwareIds.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var firstSeatActivation = activeSeats.Count == 0 ? (DateTime?)null : activeSeats.Min(s => s.FirstActivatedAt);
        var onboardingStart = license.ActivationDate ?? firstSeatActivation ?? license.CreationDate;
        var activationSource = license.ActivationDate.HasValue
            ? "license_activation"
            : firstSeatActivation.HasValue
                ? "seat_first_activation"
                : "license_creation";

        return new UsageCandidate
        {
            LicenseId = license.Id,
            LicenseKind = ResolveLicenseKind(license.Type!),
            LicenseTypeSlug = license.Type?.Slug ?? "",
            LicenseTypeName = license.Type?.Name ?? "",
            LicenseStatus = ResolveLicenseStatus(license, now),
            CustomerEmail = license.CustomerEmail,
            CreationDateUtc = license.CreationDate,
            ActivationDateUtc = license.ActivationDate,
            OnboardingStartUtc = onboardingStart,
            ActivationDateSource = activationSource,
            ActivationAgeDays = (int)Math.Floor((now - onboardingStart).TotalDays),
            ExpirationDateUtc = license.ExpirationDate,
            HardwareIds = hardwareIds
        };
    }

    private static LicenseUsageScoreItem BuildScoreItem(
        UsageCandidate candidate,
        Dictionary<string, List<UsageTelemetryRow>> telemetryByHardware,
        DateTime now,
        DateTime windowStart)
    {
        var rows = candidate.HardwareIds
            .SelectMany(h => telemetryByHardware.TryGetValue(h, out var hardwareRows)
                ? hardwareRows
                : Enumerable.Empty<UsageTelemetryRow>())
            .OrderBy(r => r.TimestampUtc)
            .ToList();

        var recentRows = rows.Where(r => r.TimestampUtc >= windowStart).ToList();
        var firstTelemetry = rows.FirstOrDefault()?.TimestampUtc;
        var lastSeen = rows.LastOrDefault()?.TimestampUtc;
        var firstProductive = rows.FirstOrDefault(IsProductiveEvent)?.TimestampUtc;
        var activeDays = rows.Select(r => r.TimestampUtc.Date).Distinct().Count();
        var activeDaysInWindow = recentRows.Select(r => r.TimestampUtc.Date).Distinct().Count();
        var primaryHardwareId = candidate.HardwareIds.FirstOrDefault() ?? "";
        var negativeEvents = rows.Count(IsNegativeEvent);
        var recentProductiveEvents = recentRows.Count(IsProductiveEvent);
        var mcpEvents = recentRows.Count(r => r.EventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase));
        var copilotEvents = recentRows.Count(r => r.EventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase));
        var onboardingCompleted = rows.Any(r => EventContains(r.EventName, "Wizard") && EventContains(r.EventName, "Completed"));
        var returnedAfterFirstSession = HasReturnAfterFirstSession(rows);

        var item = new LicenseUsageScoreItem
        {
            LicenseId = candidate.LicenseId,
            LicenseKind = candidate.LicenseKind,
            LicenseTypeSlug = candidate.LicenseTypeSlug,
            LicenseTypeName = candidate.LicenseTypeName,
            LicenseStatus = candidate.LicenseStatus,
            CustomerEmailRedacted = RedactEmail(candidate.CustomerEmail),
            CreationDateUtc = candidate.CreationDateUtc,
            ActivationDateUtc = candidate.ActivationDateUtc,
            OnboardingStartUtc = candidate.OnboardingStartUtc,
            ActivationDateSource = candidate.ActivationDateSource,
            ExpirationDateUtc = candidate.ExpirationDateUtc,
            HardwareIdRedacted = RedactHardwareId(primaryHardwareId),
            HardwareIdHash = HashHardwareId(primaryHardwareId),
            FirstTelemetryUtc = firstTelemetry,
            LastSeenAtUtc = lastSeen,
            DaysSinceLastSeen = lastSeen.HasValue ? Math.Max(0, (int)Math.Floor((now - lastSeen.Value).TotalDays)) : null,
            DaysActive = activeDays,
            ActiveDaysInWindow = activeDaysInWindow,
            TotalEvents = rows.Count,
            RecentEvents = recentRows.Count,
            ProductiveEvents = rows.Count(IsProductiveEvent),
            RecentProductiveEvents = recentProductiveEvents,
            McpEvents = mcpEvents,
            CopilotEvents = copilotEvents,
            WizardEvents = recentRows.Count(r => EventContains(r.EventName, "Wizard")),
            ProjectEvents = recentRows.Count(r => EventContains(r.EventName, "Project")),
            BlockEvents = recentRows.Count(r => EventContains(r.EventName, "Block")),
            ExportEvents = recentRows.Count(r => EventContains(r.EventName, "Export")),
            NegativeEvents = negativeEvents,
            OnboardingCompleted = onboardingCompleted,
            ReturnedAfterFirstSession = returnedAfterFirstSession,
            MinutesToFirstProductiveEvent = firstProductive.HasValue
                ? Math.Round((firstProductive.Value - candidate.OnboardingStartUtc).TotalMinutes, 2)
                : null,
            DetectedPath = ResolveDetectedPath(rows),
            OnboardingSegment = ResolveOnboardingSegment(candidate.OnboardingStartUtc, rows, firstProductive),
            TopEvents = ToTopCounts(recentRows.Select(r => r.EventName), 10)
        };

        ApplyScores(item);
        item.Classification = Classify(item);
        item.ReasonCodes = BuildReasonCodes(item);

        return item;
    }

    private static void ApplyScores(LicenseUsageScoreItem item)
    {
        AddBreakdown(item, "usage", "recent_events", Math.Min(25, item.RecentEvents * 1.5));
        AddBreakdown(item, "usage", "recent_productive_events", Math.Min(35, item.RecentProductiveEvents * 10));
        AddBreakdown(item, "usage", "mcp_copilot_depth", Math.Min(20, (item.McpEvents + item.CopilotEvents) * 5));
        AddBreakdown(item, "usage", "active_days", Math.Min(20, item.ActiveDaysInWindow * 5));
        item.UsageScore = ClampScore(SumBreakdown(item, "usage"));

        AddBreakdown(item, "conversion", "productive_depth", Math.Min(35, item.RecentProductiveEvents * 14));
        AddBreakdown(item, "conversion", "multi_day_usage", item.ActiveDaysInWindow >= 2 ? 20 : 0);
        AddBreakdown(item, "conversion", "returned_after_first_session", item.ReturnedAfterFirstSession ? 15 : 0);
        AddBreakdown(item, "conversion", "mcp_copilot_signal", (item.McpEvents + item.CopilotEvents) > 0 ? 15 : 0);
        AddBreakdown(item, "conversion", "onboarding_completed", item.OnboardingCompleted ? 10 : 0);
        AddBreakdown(item, "conversion", "negative_signals", -Math.Min(15, item.NegativeEvents * 5));
        item.ConversionPotentialScore = ClampScore(SumBreakdown(item, "conversion"));

        AddBreakdown(item, "retention", "recency", RecencyRetentionPoints(item.DaysSinceLastSeen));
        AddBreakdown(item, "retention", "active_days", Math.Min(35, item.ActiveDaysInWindow * 8));
        AddBreakdown(item, "retention", "recent_productivity", Math.Min(30, item.RecentProductiveEvents * 10));
        AddBreakdown(item, "retention", "mcp_copilot_depth", Math.Min(20, (item.McpEvents + item.CopilotEvents) * 4));
        AddBreakdown(item, "retention", "negative_signals", -Math.Min(20, item.NegativeEvents * 5));
        item.RetentionConfidenceScore = ClampScore(SumBreakdown(item, "retention"));

        var churn = 100 - item.RetentionConfidenceScore;
        if (item.RecentProductiveEvents == 0)
            churn += 15;
        if (item.OnboardingSegment is "stuck" or "setup_only")
            churn += 10;
        if (item.DaysSinceLastSeen is null)
            churn += 20;
        else if (item.DaysSinceLastSeen >= 14)
            churn += 20;
        else if (item.DaysSinceLastSeen >= 7)
            churn += 10;
        churn += Math.Min(15, item.NegativeEvents * 5);
        item.ChurnRiskScore = ClampScore(churn);
    }

    private static string Classify(LicenseUsageScoreItem item)
    {
        if (item.UsageScore >= 80 && item.RecentProductiveEvents >= 3 && item.McpEvents + item.CopilotEvents >= 2)
            return "power_user";
        if (item.LicenseKind is "trial" or "freemium" && item.ConversionPotentialScore >= 70)
            return "hot_trial";
        if (item.LicenseKind is "subscription" or "paid" && item.RetentionConfidenceScore >= 70 && item.ChurnRiskScore < 45)
            return "engaged_subscriber";
        if (item.ChurnRiskScore >= 75 && (item.DaysSinceLastSeen is >= 7 or null))
            return "dormant";
        if (item.ChurnRiskScore >= 65)
            return "at_risk";
        if (item.ConversionPotentialScore >= 45 || item.ChurnRiskScore >= 50)
            return "needs_followup";
        return "unknown";
    }

    private static List<string> BuildReasonCodes(LicenseUsageScoreItem item)
    {
        var codes = new List<string>();
        if (item.RecentProductiveEvents > 0) codes.Add("recent_productive_usage");
        if (item.ActiveDaysInWindow >= 2) codes.Add("multi_day_usage");
        if (item.ReturnedAfterFirstSession) codes.Add("returned_after_first_session");
        if (item.McpEvents > 0) codes.Add("mcp_usage");
        if (item.CopilotEvents > 0) codes.Add("copilot_usage");
        if (item.OnboardingCompleted) codes.Add("onboarding_completed");
        if (item.DaysSinceLastSeen is null) codes.Add("no_telemetry");
        else if (item.DaysSinceLastSeen >= 7) codes.Add("no_recent_activity");
        if (item.NegativeEvents > 0) codes.Add("negative_signals");
        if (item.OnboardingSegment is "stuck" or "setup_only") codes.Add(item.OnboardingSegment);
        return codes.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static LicenseUsageScoringSummary BuildSummary(List<LicenseUsageScoreItem> items)
    {
        return new LicenseUsageScoringSummary
        {
            WithRecentTelemetry = items.Count(i => i.RecentEvents > 0),
            WithProductiveEvents = items.Count(i => i.RecentProductiveEvents > 0),
            WithMcpOrCopilot = items.Count(i => i.McpEvents + i.CopilotEvents > 0),
            AtRiskOrDormant = items.Count(i => i.Classification is "at_risk" or "dormant"),
            HighConversionPotential = items.Count(i => i.ConversionPotentialScore >= 70),
            EngagedSubscribers = items.Count(i => i.Classification == "engaged_subscriber")
        };
    }

    private static IEnumerable<LicenseUsageScoreItem> Sort(List<LicenseUsageScoreItem> items, string sortBy)
    {
        return sortBy switch
        {
            "conversionPotential" => items.OrderByDescending(i => i.ConversionPotentialScore).ThenByDescending(i => i.UsageScore),
            "retentionConfidence" => items.OrderByDescending(i => i.RetentionConfidenceScore).ThenByDescending(i => i.UsageScore),
            "recentActivity" => items.OrderByDescending(i => i.LastSeenAtUtc ?? DateTime.MinValue).ThenByDescending(i => i.UsageScore),
            _ => items.OrderByDescending(i => MaxBusinessScore(i)).ThenByDescending(i => i.LastSeenAtUtc ?? DateTime.MinValue)
        };
    }

    private static string ResolveLicenseKind(LicenseType type)
    {
        var slug = type.Slug ?? "";
        var name = type.Name ?? "";
        if (ContainsAny(slug, name, TrialMarkers))
            return slug.Contains("trial", StringComparison.OrdinalIgnoreCase) || name.Contains("trial", StringComparison.OrdinalIgnoreCase)
                ? "trial"
                : "freemium";
        if (type.IsRecurring || ContainsAny(slug, name, SubscriptionMarkers))
            return "subscription";
        return "paid";
    }

    private static bool LicenseTypeMatches(string kind, string filter)
    {
        return filter switch
        {
            "all" => true,
            "trial" => kind == "trial",
            _ => string.Equals(kind, filter, StringComparison.OrdinalIgnoreCase)
        };
    }

    private static string ResolveLicenseStatus(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt.HasValue)
            return "revoked";
        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
            return "expired";
        return license.ActivationDate.HasValue || license.Seats.Any(s => s.IsActive) ? "active" : "not_activated";
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

    private static string ResolveDetectedPath(List<UsageTelemetryRow> rows)
    {
        var hasMcp = rows.Any(r => r.EventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase));
        var hasCopilot = rows.Any(r => r.EventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase));
        var hasCopilotViaMcp = rows.Any(r =>
            r.EventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase)
            && (EventContains(r.EventName, "ToolCall")
                || PropertyContains(r.PropertiesJson, "RequestSource", "MCP")
                || PropertyContains(r.PropertiesJson, "RequestSource", "API_Direct")));

        if (hasCopilotViaMcp || hasMcp && hasCopilot)
            return "copilot_via_mcp";
        if (hasMcp)
            return "mcp_direct";
        if (rows.Count > 0)
            return "ui_only";
        return "unknown";
    }

    private static string ResolveOnboardingSegment(DateTime startUtc, List<UsageTelemetryRow> rows, DateTime? firstProductive)
    {
        if (firstProductive.HasValue)
        {
            var minutes = (firstProductive.Value - startUtc).TotalMinutes;
            if (minutes < 15) return "fast";
            if (minutes <= 60) return "normal";
            return "slow";
        }

        if (rows.Any(r => EventContains(r.EventName, "Wizard")) || rows.Count > 0)
            return "setup_only";
        return "stuck";
    }

    private static bool HasReturnAfterFirstSession(List<UsageTelemetryRow> rows)
    {
        if (rows.Count < 2)
            return false;
        var firstDate = rows[0].TimestampUtc.Date;
        return rows.Any(r => r.TimestampUtc.Date > firstDate);
    }

    private static bool IsProductiveEvent(UsageTelemetryRow row)
    {
        return ProductiveEvents.Contains(row.EventName)
            || EventContains(row.EventName, "Success") && (EventContains(row.EventName, "Block") || EventContains(row.EventName, "Compile"));
    }

    private static bool IsNegativeEvent(UsageTelemetryRow row)
    {
        return EventContains(row.EventName, "Failed")
            || EventContains(row.EventName, "Failure")
            || EventContains(row.EventName, "AuthFailed")
            || row.Type.Equals("Error", StringComparison.OrdinalIgnoreCase);
    }

    private static double RecencyRetentionPoints(int? daysSinceLastSeen)
    {
        return daysSinceLastSeen switch
        {
            null => 0,
            <= 1 => 25,
            <= 3 => 18,
            <= 7 => 10,
            _ => 0
        };
    }

    private static void AddBreakdown(LicenseUsageScoreItem item, string score, string code, double points)
    {
        item.ScoreBreakdown.Add(new LicenseUsageScoreBreakdownItem
        {
            Score = score,
            Code = code,
            Points = Math.Round(points, 2)
        });
    }

    private static double SumBreakdown(LicenseUsageScoreItem item, string score)
    {
        return item.ScoreBreakdown.Where(i => i.Score == score).Sum(i => i.Points);
    }

    private static double MaxBusinessScore(LicenseUsageScoreItem item)
    {
        return Math.Max(item.UsageScore, Math.Max(item.ConversionPotentialScore, item.RetentionConfidenceScore));
    }

    private static double ClampScore(double score)
    {
        return Math.Round(Math.Clamp(score, 0, 100), 2);
    }

    private static string NormalizeLicenseType(string? value)
    {
        var normalized = NormalizeOptional(value)?.ToLowerInvariant();
        return normalized switch
        {
            "paid" or "freemium" or "trial" or "subscription" or "all" => normalized,
            _ => "paid"
        };
    }

    private static string NormalizeStatus(string? value)
    {
        var normalized = NormalizeOptional(value)?.ToLowerInvariant();
        return normalized switch
        {
            "active" or "expired" or "revoked" or "not_activated" or "expired_or_revoked" or "all" => normalized,
            _ => "active"
        };
    }

    private static string NormalizeSort(string? value)
    {
        var normalized = NormalizeOptional(value)?.ToLowerInvariant();
        return normalized switch
        {
            "conversionpotential" => "conversionPotential",
            "retentionconfidence" => "retentionConfidence",
            "recentactivity" => "recentActivity",
            _ => "score"
        };
    }

    private static string? NormalizeOptional(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static bool ContainsAny(string slug, string name, string[] markers)
    {
        return markers.Any(marker =>
            slug.Contains(marker, StringComparison.OrdinalIgnoreCase)
            || name.Contains(marker, StringComparison.OrdinalIgnoreCase));
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
        return hardwareId.Length <= 8 ? "***" : $"{hardwareId[..6]}...{hardwareId[^4..]}";
    }

    private static string HashHardwareId(string hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private sealed class UsageCandidate
    {
        public Guid LicenseId { get; set; }
        public string LicenseKind { get; set; } = "unknown";
        public string LicenseTypeSlug { get; set; } = "";
        public string LicenseTypeName { get; set; } = "";
        public string LicenseStatus { get; set; } = "";
        public string CustomerEmail { get; set; } = "";
        public DateTime CreationDateUtc { get; set; }
        public DateTime? ActivationDateUtc { get; set; }
        public DateTime OnboardingStartUtc { get; set; }
        public string ActivationDateSource { get; set; } = "";
        public int ActivationAgeDays { get; set; }
        public DateTime? ExpirationDateUtc { get; set; }
        public List<string> HardwareIds { get; set; } = new();
    }

    private sealed record UsageTelemetryRow(
        string HardwareId,
        DateTime TimestampUtc,
        string EventName,
        string Type,
        string? PropertiesJson);
}
