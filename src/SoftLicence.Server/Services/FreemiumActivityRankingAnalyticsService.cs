using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class FreemiumActivityRankingAnalyticsService
{
    private const string DefaultLicenseType = "TIA-CONNECT-FREEMIUM";
    private const string DefaultStatusFilter = "active";
    private const int DefaultTelemetryDays = 7;
    private const int DefaultTake = 50;
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
        "Project_Save",
        "ExternalSource_ImportAndGenerate"
    };

    private static readonly HashSet<string> McpCopilotEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "Mcp_ToolCall",
        "Copilot_ToolCall",
        "Copilot_Chat_Success"
    };

    private static readonly string[] QuotaKeys =
    {
        "Quota_Api_Daily",
        "Quota_Mcp_Daily",
        "Quota_Copilot_Daily"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public FreemiumActivityRankingAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<FreemiumActivityRankingResponse> GetRankingForProductIdAsync(
        Guid productId,
        string? licenseType = DefaultLicenseType,
        string? status = DefaultStatusFilter,
        int telemetryDays = DefaultTelemetryDays,
        int? activationAgeMinDays = null,
        int? activationAgeMaxDays = null,
        bool includeSamples = false,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        var normalizedLicenseType = string.IsNullOrWhiteSpace(licenseType)
            ? DefaultLicenseType
            : licenseType.Trim();

        var options = NormalizeRankingOptions(
            status,
            telemetryDays,
            activationAgeMinDays,
            activationAgeMaxDays,
            take);

        var cacheKey = string.Join(':',
            "freemium-activity-ranking",
            productId.ToString("N"),
            normalizedLicenseType.ToUpperInvariant(),
            options.Status,
            options.TelemetryDays,
            options.ActivationAgeMinDays?.ToString() ?? "",
            options.ActivationAgeMaxDays?.ToString() ?? "",
            includeSamples,
            options.Take);

        if (_cache.TryGetValue(cacheKey, out FreemiumActivityRankingResponse? cached) && cached != null)
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
            .Where(l => productScopeIds.Contains(l.ProductId)
                && l.Type != null
                && (l.Type.Slug.ToLower() == normalizedLicenseType.ToLower()
                    || l.Type.Name.ToLower() == normalizedLicenseType.ToLower()))
            .ToListAsync(cancellationToken);

        var response = await BuildRankingResponseAsync(
            productId,
            normalizedLicenseType,
            new List<string> { normalizedLicenseType },
            options,
            includeSamples,
            licenses,
            now,
            db,
            productScopeIds,
            cancellationToken);

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    public async Task<FreemiumActivityRankingResponse> GetPaidRankingForProductIdAsync(
        Guid productId,
        string? licenseTypes = null,
        string? status = DefaultStatusFilter,
        int telemetryDays = DefaultTelemetryDays,
        int? activationAgeMinDays = null,
        int? activationAgeMaxDays = null,
        bool includeSamples = false,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        var normalizedTypes = NormalizeLicenseTypes(licenseTypes);
        var options = NormalizeRankingOptions(
            status,
            telemetryDays,
            activationAgeMinDays,
            activationAgeMaxDays,
            take);

        var cacheKey = string.Join(':',
            "paid-activity-ranking",
            productId.ToString("N"),
            normalizedTypes.Count == 0
                ? "ALL_PAID"
                : string.Join(',', normalizedTypes.Select(t => t.ToUpperInvariant()).OrderBy(t => t, StringComparer.Ordinal)),
            options.Status,
            options.TelemetryDays,
            options.ActivationAgeMinDays?.ToString() ?? "",
            options.ActivationAgeMaxDays?.ToString() ?? "",
            includeSamples,
            options.Take);

        if (_cache.TryGetValue(cacheKey, out FreemiumActivityRankingResponse? cached) && cached != null)
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

        licenses = licenses
            .Where(l => l.Type != null && IsPaidType(l.Type))
            .Where(l => normalizedTypes.Count == 0
                || normalizedTypes.Contains(l.Type!.Slug, StringComparer.OrdinalIgnoreCase)
                || normalizedTypes.Contains(l.Type!.Name, StringComparer.OrdinalIgnoreCase))
            .ToList();

        var selectedTypes = normalizedTypes.Count == 0
            ? licenses
                .Select(l => l.Type?.Slug)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList()
            : normalizedTypes;

        var response = await BuildRankingResponseAsync(
            productId,
            normalizedTypes.Count == 0 ? "paid" : string.Join(',', selectedTypes),
            selectedTypes,
            options,
            includeSamples,
            licenses,
            now,
            db,
            productScopeIds,
            cancellationToken);

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    public async Task<LicenseTypesAnalyticsResponse> GetLicenseTypesForProductIdAsync(
        Guid productId,
        bool includeFree = true,
        CancellationToken cancellationToken = default)
    {
        var cacheKey = string.Join(':', "license-types", productId.ToString("N"), includeFree);
        if (_cache.TryGetValue(cacheKey, out LicenseTypesAnalyticsResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var now = DateTime.UtcNow;
        var types = await db.LicenseTypes.AsNoTracking()
            .Include(t => t.Licenses)
            .Where(t => productScopeIds.Contains(t.ProductId))
            .ToListAsync(cancellationToken);

        if (!includeFree)
            types = types.Where(IsPaidType).ToList();

        var items = types
            .Select(t => new LicenseTypeAnalyticsItem
            {
                LicenseTypeId = t.Id,
                Slug = t.Slug,
                Name = t.Name,
                IsFree = !IsPaidType(t),
                DefaultDurationDays = t.DefaultDurationDays,
                TotalLicenses = t.Licenses.Count,
                ActiveLicenses = t.Licenses.Count(l => ResolveLicenseStatus(l, now) == "active"),
                ExpiredLicenses = t.Licenses.Count(l => ResolveLicenseStatus(l, now) == "expired"),
                RevokedLicenses = t.Licenses.Count(l => ResolveLicenseStatus(l, now) == "revoked")
            })
            .OrderByDescending(t => t.ActiveLicenses)
            .ThenByDescending(t => t.TotalLicenses)
            .ThenBy(t => t.Slug, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var response = new LicenseTypesAnalyticsResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            TotalTypes = items.Count,
            TotalLicenses = items.Sum(i => i.TotalLicenses),
            ActiveLicenses = items.Sum(i => i.ActiveLicenses),
            LicenseTypes = items
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static async Task<FreemiumActivityRankingResponse> BuildRankingResponseAsync(
        Guid productId,
        string licenseTypeLabel,
        List<string> selectedLicenseTypes,
        RankingOptions options,
        bool includeSamples,
        List<License> licenses,
        DateTime now,
        LicenseDbContext db,
        List<Guid> productScopeIds,
        CancellationToken cancellationToken)
    {
        var telemetrySince = now.AddDays(-options.TelemetryDays);
        var candidates = BuildCandidates(
            licenses,
            now,
            options.Status,
            options.ActivationAgeMinDays,
            options.ActivationAgeMaxDays);

        var hardwareIds = candidates
            .Select(c => c.HardwareId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetryRows = hardwareIds.Count == 0
            ? new List<RankingTelemetryRow>()
            : await db.TelemetryRecords.AsNoTracking()
                .Include(r => r.EventData)
                .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                    && r.Timestamp >= telemetrySince
                    && hardwareIds.Contains(r.HardwareId))
                .Select(r => new RankingTelemetryRow(
                    r.HardwareId,
                    r.Timestamp,
                    r.EventName,
                    r.Type.ToString(),
                    r.EventData != null ? r.EventData.PropertiesJson : null))
                .ToListAsync(cancellationToken);

        var telemetryByHardware = telemetryRows
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(r => r.TimestampUtc).ToList(), StringComparer.OrdinalIgnoreCase);

        var rankingItems = new List<FreemiumActivityRankingItem>();
        foreach (var candidate in candidates)
        {
            telemetryByHardware.TryGetValue(candidate.HardwareId, out var rows);
            rows ??= new List<RankingTelemetryRow>();

            var item = BuildRankingItem(candidate, rows, now, includeSamples);
            if (item.TotalEvents == 0 && options.Status != "all")
                continue;

            rankingItems.Add(item);
        }

        var ordered = rankingItems
            .OrderByDescending(i => i.Score)
            .ThenByDescending(i => i.LastTelemetryUtc ?? DateTime.MinValue)
            .ThenBy(i => i.CustomerEmailRedacted, StringComparer.OrdinalIgnoreCase)
            .Take(options.Take)
            .ToList();

        for (var i = 0; i < ordered.Count; i++)
            ordered[i].Rank = i + 1;

        return new FreemiumActivityRankingResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            LicenseType = licenseTypeLabel,
            LicenseTypes = selectedLicenseTypes,
            StatusFilter = options.Status,
            TelemetryDays = options.TelemetryDays,
            ActivationAgeMinDays = options.ActivationAgeMinDays,
            ActivationAgeMaxDays = options.ActivationAgeMaxDays,
            Summary = new FreemiumActivityRankingSummary
            {
                TotalLicensesInFilter = candidates.Count,
                RankedMachines = ordered.Count,
                ActiveTelemetry1d = CountActive(candidates, telemetryByHardware, now, 1),
                ActiveTelemetry3d = CountActive(candidates, telemetryByHardware, now, 3),
                ActiveTelemetry7d = CountActive(candidates, telemetryByHardware, now, 7),
                QuotaLimitedMachines = rankingItems.Count(i => i.QuotaFlags.Count > 0),
                MachinesWithNegativeSignals = rankingItems.Count(i => i.NegativeFlags.Count > 0)
            },
            TopSegments = ordered
                .GroupBy(i => i.UserSegment)
                .OrderByDescending(g => g.Count())
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            TopEventFamilies = ordered
                .SelectMany(i => i.TopEventFamilies.Select(f => new { f.Name, f.Count }))
                .GroupBy(f => f.Name)
                .OrderByDescending(g => g.Sum(f => f.Count))
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Sum(f => f.Count) })
                .Take(20)
                .ToList(),
            Rankings = ordered
        };
    }

    private static List<RankingCandidate> BuildCandidates(
        List<License> licenses,
        DateTime now,
        string status,
        int? activationAgeMinDays,
        int? activationAgeMaxDays)
    {
        var candidates = new List<RankingCandidate>();

        foreach (var license in licenses)
        {
            var licenseStatus = ResolveLicenseStatus(license, now);
            if (!StatusMatches(status, licenseStatus))
                continue;

            var hardwareIds = LicenseSeatHardwareResolver.ResolveActiveHardwareIds(license)
                .Select(h => (h.HardwareId, SeatActivation: h.FirstActivatedAt));

            foreach (var seat in hardwareIds
                .GroupBy(h => h.HardwareId, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First()))
            {
                var activationDate = license.ActivationDate ?? seat.SeatActivation;
                var activationAgeDays = activationDate.HasValue
                    ? (int)Math.Floor((now - activationDate.Value).TotalDays)
                    : (int?)null;

                if (activationAgeMinDays.HasValue && (!activationAgeDays.HasValue || activationAgeDays.Value < activationAgeMinDays.Value))
                    continue;
                if (activationAgeMaxDays.HasValue && (!activationAgeDays.HasValue || activationAgeDays.Value > activationAgeMaxDays.Value))
                    continue;

                candidates.Add(new RankingCandidate
                {
                    LicenseId = license.Id,
                    LicenseTypeSlug = license.Type?.Slug ?? "",
                    LicenseTypeName = license.Type?.Name ?? "",
                    LicenseKey = license.LicenseKey,
                    CustomerEmail = license.CustomerEmail,
                    HardwareId = seat.HardwareId,
                    LicenseStatus = licenseStatus,
                    ActivationDateUtc = activationDate,
                    ActivationAgeDays = activationAgeDays,
                    ExpirationDateUtc = license.ExpirationDate
                });
            }
        }

        return candidates;
    }

    private static FreemiumActivityRankingItem BuildRankingItem(
        RankingCandidate candidate,
        List<RankingTelemetryRow> rows,
        DateTime now,
        bool includeSamples)
    {
        var productiveEvents = rows.Count(r => r.EventName != null && ProductiveEvents.Contains(r.EventName));
        var mcpCopilotEvents = rows.Count(r => r.EventName != null && McpCopilotEvents.Contains(r.EventName));
        var quotaFlags = BuildQuotaFlags(rows);
        var negativeFlags = BuildNegativeFlags(rows);
        var userSegment = ResolveUserSegment(rows);

        var score = Math.Round(
            productiveEvents * 8.0
            + mcpCopilotEvents * 3.0
            + Math.Min(rows.Count, 250) * 0.25
            + quotaFlags.Count * 20.0
            - negativeFlags.Count * 2.0,
            2);

        return new FreemiumActivityRankingItem
        {
            LicenseId = candidate.LicenseId,
            LicenseTypeSlug = candidate.LicenseTypeSlug,
            LicenseTypeName = candidate.LicenseTypeName,
            LicenseStatus = candidate.LicenseStatus,
            CustomerEmail = candidate.CustomerEmail,
            CustomerEmailRedacted = RedactEmail(candidate.CustomerEmail),
            LicenseKeyRedacted = RedactKey(candidate.LicenseKey),
            HardwareIdRedacted = RedactHardwareId(candidate.HardwareId),
            HardwareIdHash = HashHardwareId(candidate.HardwareId),
            ActivationDateUtc = candidate.ActivationDateUtc,
            ActivationAgeDays = candidate.ActivationAgeDays,
            ExpirationDateUtc = candidate.ExpirationDateUtc,
            DaysRemaining = candidate.ExpirationDateUtc.HasValue
                ? (int)Math.Ceiling((candidate.ExpirationDateUtc.Value - now).TotalDays)
                : null,
            LastTelemetryUtc = rows.FirstOrDefault()?.TimestampUtc,
            TotalEvents = rows.Count,
            ProductiveEvents = productiveEvents,
            McpCopilotEvents = mcpCopilotEvents,
            Score = score,
            UserSegment = userSegment,
            TopEvents = ToTopCounts(rows.Select(r => r.EventName).Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e!), 10),
            TopEventFamilies = ToTopCounts(rows.Select(r => ClassifyFamily(r.EventName)), 10),
            QuotaFlags = quotaFlags,
            NegativeFlags = negativeFlags,
            RecentEvents = includeSamples
                ? rows.Take(10)
                    .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                    .Select(r => new FreemiumActivityRecentEvent
                    {
                        TimestampUtc = r.TimestampUtc,
                        EventName = r.EventName!,
                        Family = ClassifyFamily(r.EventName)
                    })
                    .ToList()
                : new List<FreemiumActivityRecentEvent>()
        };
    }

    private static RankingOptions NormalizeRankingOptions(
        string? status,
        int telemetryDays,
        int? activationAgeMinDays,
        int? activationAgeMaxDays,
        int take)
    {
        telemetryDays = Math.Clamp(telemetryDays, 1, 30);
        take = Math.Clamp(take, 1, MaxTake);

        if (activationAgeMinDays.HasValue)
            activationAgeMinDays = Math.Clamp(activationAgeMinDays.Value, 0, 3650);
        if (activationAgeMaxDays.HasValue)
            activationAgeMaxDays = Math.Clamp(activationAgeMaxDays.Value, 0, 3650);
        if (activationAgeMinDays.HasValue && activationAgeMaxDays.HasValue && activationAgeMinDays > activationAgeMaxDays)
            (activationAgeMinDays, activationAgeMaxDays) = (activationAgeMaxDays, activationAgeMinDays);

        return new RankingOptions(
            NormalizeStatus(status),
            telemetryDays,
            activationAgeMinDays,
            activationAgeMaxDays,
            take);
    }

    private static List<string> NormalizeLicenseTypes(string? licenseTypes)
    {
        if (string.IsNullOrWhiteSpace(licenseTypes))
            return new List<string>();

        return licenseTypes
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToList();
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

    private static string NormalizeStatus(string? status)
    {
        var normalized = string.IsNullOrWhiteSpace(status)
            ? DefaultStatusFilter
            : status.Trim().ToLowerInvariant();

        return normalized switch
        {
            "active" or "expired" or "revoked" or "expired_or_revoked" or "all" => normalized,
            _ => DefaultStatusFilter
        };
    }

    private static string ResolveLicenseStatus(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt.HasValue)
            return "revoked";

        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
            return "expired";

        return "active";
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

    private static int CountActive(
        List<RankingCandidate> candidates,
        Dictionary<string, List<RankingTelemetryRow>> telemetryByHardware,
        DateTime now,
        int days)
    {
        var since = now.AddDays(-days);
        return candidates.Count(c =>
            telemetryByHardware.TryGetValue(c.HardwareId, out var rows)
            && rows.Any(r => r.TimestampUtc >= since));
    }

    private static List<string> BuildQuotaFlags(List<RankingTelemetryRow> rows)
    {
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var props = ParseProperties(row.PropertiesJson);
            foreach (var key in QuotaKeys)
            {
                if (!props.TryGetValue(key, out var value))
                    continue;

                var parsed = ParseQuota(value);
                if (parsed is not { } quota || quota.Limit <= 0)
                    continue;

                var percentage = quota.Used * 100.0 / quota.Limit;
                if (percentage >= 90)
                    flags.Add($"{key}:{quota.Used}/{quota.Limit}");
            }
        }

        return flags.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> BuildNegativeFlags(List<RankingTelemetryRow> rows)
    {
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var eventName = row.EventName ?? "";
            if (eventName.Contains("AuthFailed", StringComparison.OrdinalIgnoreCase))
                flags.Add("auth_failed");
            if (eventName.Contains("CertPinningFailed", StringComparison.OrdinalIgnoreCase))
                flags.Add("cert_pinning_failed");
            if (eventName.StartsWith("Startup_", StringComparison.OrdinalIgnoreCase)
                && (eventName.Contains("Failed", StringComparison.OrdinalIgnoreCase)
                    || eventName.Contains("Degraded", StringComparison.OrdinalIgnoreCase)))
                flags.Add("startup_degraded");
            if (eventName.Contains("Activation", StringComparison.OrdinalIgnoreCase)
                && eventName.Contains("Failed", StringComparison.OrdinalIgnoreCase))
                flags.Add("activation_failed");
        }

        return flags.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static (int Used, int Limit)? ParseQuota(string value)
    {
        var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
            return null;

        return int.TryParse(parts[0], out var used) && int.TryParse(parts[1], out var limit)
            ? (used, limit)
            : null;
    }

    private static string ResolveUserSegment(List<RankingTelemetryRow> rows)
    {
        foreach (var row in rows)
        {
            var props = ParseProperties(row.PropertiesJson);
            var candidate = ReadFirst(props, "AccountType", "UserType", "Role", "SurveyRole", "LicenseEdition", "Edition");
            if (string.IsNullOrWhiteSpace(candidate))
                continue;

            if (candidate.Contains("pro", StringComparison.OrdinalIgnoreCase)
                || candidate.Contains("company", StringComparison.OrdinalIgnoreCase)
                || candidate.Contains("business", StringComparison.OrdinalIgnoreCase))
                return "professional";

            if (candidate.Contains("personal", StringComparison.OrdinalIgnoreCase)
                || candidate.Contains("student", StringComparison.OrdinalIgnoreCase)
                || candidate.Contains("hobby", StringComparison.OrdinalIgnoreCase))
                return "personal";
        }

        return "unknown";
    }

    private static Dictionary<string, string> ParseProperties(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static string? ReadFirst(Dictionary<string, string> props, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (props.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
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

    private static string ClassifyFamily(string? eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName))
            return "unknown";
        if (eventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase))
            return "mcp";
        if (eventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase))
            return "copilot";
        if (eventName.StartsWith("Block", StringComparison.OrdinalIgnoreCase))
            return "block";
        if (eventName.StartsWith("Compile", StringComparison.OrdinalIgnoreCase))
            return "compile";
        if (eventName.StartsWith("Tag_", StringComparison.OrdinalIgnoreCase))
            return "tag";
        if (eventName.StartsWith("Startup_", StringComparison.OrdinalIgnoreCase))
            return "startup";
        if (eventName.StartsWith("API_", StringComparison.OrdinalIgnoreCase))
            return "api";
        if (eventName.Contains("Quota", StringComparison.OrdinalIgnoreCase))
            return "quota";

        return "other";
    }

    private static string RedactEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "";

        var parts = email.Split('@', 2);
        if (parts.Length != 2)
            return "***";

        var local = parts[0];
        var prefix = local.Length <= 2 ? local[..1] : local[..Math.Min(2, local.Length)];
        return $"{prefix}***@{parts[1]}";
    }

    private static string RedactKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return "";

        var compact = key.Replace("-", "").Replace(" ", "");
        if (compact.Length <= 8)
            return "***";

        return $"{compact[..4]}...{compact[^4..]}";
    }

    private static string RedactHardwareId(string hardwareId)
    {
        if (hardwareId.Length <= 8)
            return "***";

        return $"{hardwareId[..6]}...{hardwareId[^4..]}";
    }

    private static string HashHardwareId(string hardwareId)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private sealed record RankingOptions(
        string Status,
        int TelemetryDays,
        int? ActivationAgeMinDays,
        int? ActivationAgeMaxDays,
        int Take);

    private sealed class RankingCandidate
    {
        public Guid LicenseId { get; set; }
        public string LicenseTypeSlug { get; set; } = "";
        public string LicenseTypeName { get; set; } = "";
        public string LicenseKey { get; set; } = "";
        public string CustomerEmail { get; set; } = "";
        public string HardwareId { get; set; } = "";
        public string LicenseStatus { get; set; } = "";
        public DateTime? ActivationDateUtc { get; set; }
        public int? ActivationAgeDays { get; set; }
        public DateTime? ExpirationDateUtc { get; set; }
    }

    private sealed record RankingTelemetryRow(
        string HardwareId,
        DateTime TimestampUtc,
        string? EventName,
        string Type,
        string? PropertiesJson);
}
