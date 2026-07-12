using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class LicenseDurationMigrationImpactAnalyticsService
{
    private const string DefaultLicenseType = "TIA-CONNECT-FREEMIUM";
    private const int DefaultCurrentDurationDays = 30;
    private const int DefaultTargetDurationDays = 7;
    private const int DefaultTopEvents = 20;
    private const int MaxTopEvents = 100;
    private const int DefaultSampleLimit = 30;
    private const int MaxSampleLimit = 50;
    private static readonly int[] DefaultActivityWindows = { 1, 3, 7 };
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public LicenseDurationMigrationImpactAnalyticsService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<LicenseDurationMigrationImpactResponse> GetImpactForProductIdAsync(
        Guid productId,
        string? licenseType = DefaultLicenseType,
        int currentDurationDays = DefaultCurrentDurationDays,
        int targetDurationDays = DefaultTargetDurationDays,
        string? activityWindowsDays = null,
        bool includeSamples = false,
        int sampleLimit = DefaultSampleLimit,
        int topEvents = DefaultTopEvents,
        CancellationToken cancellationToken = default)
    {
        var normalizedLicenseType = string.IsNullOrWhiteSpace(licenseType)
            ? DefaultLicenseType
            : licenseType.Trim();
        currentDurationDays = Math.Clamp(currentDurationDays, 1, 3650);
        targetDurationDays = Math.Clamp(targetDurationDays, 1, currentDurationDays);
        sampleLimit = Math.Clamp(sampleLimit, 1, MaxSampleLimit);
        topEvents = Math.Clamp(topEvents, 1, MaxTopEvents);
        var windows = ParseActivityWindows(activityWindowsDays);
        var maxWindow = windows.Max();

        var cacheKey = string.Join(':',
            "license-duration-migration-impact",
            productId.ToString("N"),
            normalizedLicenseType.ToUpperInvariant(),
            currentDurationDays,
            targetDurationDays,
            string.Join(',', windows),
            includeSamples,
            sampleLimit,
            topEvents);

        if (_cache.TryGetValue(cacheKey, out LicenseDurationMigrationImpactResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var now = DateTime.UtcNow;
        var today = now.Date;

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Where(l => productScopeIds.Contains(l.ProductId)
                && l.IsActive
                && l.Type != null
                && (l.Type.Slug.ToLower() == normalizedLicenseType.ToLower()
                    || l.Type.Name.ToLower() == normalizedLicenseType.ToLower()))
            .ToListAsync(cancellationToken);

        var deliveredNotActivated = licenses.Count(IsDeliveredNotActivated);
        var candidates = BuildCandidates(licenses, now, currentDurationDays, targetDurationDays);
        var candidateHardwareIds = candidates
            .Select(c => c.HardwareId)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetrySince = now.AddDays(-maxWindow);
        var telemetryRows = candidateHardwareIds.Count == 0
            ? new List<TelemetryImpactRow>()
            : await db.TelemetryRecords.AsNoTracking()
                .Include(r => r.EventData)
                .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                    && r.Timestamp >= telemetrySince
                    && candidateHardwareIds.Contains(r.HardwareId))
                .Select(r => new TelemetryImpactRow(
                    r.HardwareId,
                    r.Timestamp,
                    r.EventName,
                    r.EventData != null ? r.EventData.PropertiesJson : null))
                .ToListAsync(cancellationToken);

        var telemetryByHardware = telemetryRows
            .GroupBy(t => t.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            if (!telemetryByHardware.TryGetValue(candidate.HardwareId, out var rows))
                continue;

            candidate.LastTelemetryUtc = rows.Max(r => r.TimestampUtc);
            candidate.UserSegment = ResolveUserSegment(rows);
        }

        var windowActivity = windows
            .Select(window =>
            {
                var active = candidates.Count(c => c.LastTelemetryUtc.HasValue && c.LastTelemetryUtc.Value >= now.AddDays(-window));
                return new LicenseDurationMigrationWindowActivity
                {
                    WindowDays = window,
                    ActiveCandidates = active,
                    InactiveCandidates = candidates.Count - active
                };
            })
            .ToList();

        var active1d = CountActive(candidates, now, 1);
        var active3d = CountActive(candidates, now, 3);
        var active7d = CountActive(candidates, now, 7);
        var active7dCandidates = candidates
            .Where(c => c.LastTelemetryUtc.HasValue && c.LastTelemetryUtc.Value >= now.AddDays(-7))
            .ToList();

        var response = new LicenseDurationMigrationImpactResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            LicenseType = normalizedLicenseType,
            CurrentDurationDays = currentDurationDays,
            TargetDurationDays = targetDurationDays,
            CandidateDefinition = "active + hardwareId/seat + expiration future + activation age > targetDurationDays and <= currentDurationDays",
            ActivationDateSource = candidates.Any(c => c.ActivationDateWasInferred)
                ? candidates.Any(c => !c.ActivationDateWasInferred) ? "mixed_actual_and_inferred_from_expiration" : "inferred_from_expiration"
                : "actual",
            ActivityWindowsDays = windows,
            Summary = new LicenseDurationMigrationImpactSummary
            {
                TotalCandidates = candidates.Count,
                DeliveredNotActivated = deliveredNotActivated,
                Active1d = active1d,
                Active3d = active3d,
                Active7d = active7d,
                Inactive7d = candidates.Count - active7d,
                ProfessionalActive7d = active7dCandidates.Count(c => string.Equals(c.UserSegment, "professional", StringComparison.OrdinalIgnoreCase)),
                PersonalActive7d = active7dCandidates.Count(c => string.Equals(c.UserSegment, "personal", StringComparison.OrdinalIgnoreCase)),
                UnknownSegmentActive7d = active7dCandidates.Count(c => string.Equals(c.UserSegment, "unknown", StringComparison.OrdinalIgnoreCase))
            },
            WindowActivity = windowActivity,
            ByDaysRemaining = candidates
                .GroupBy(c => Math.Max(0, (int)Math.Ceiling((c.ExpirationDateUtc - now).TotalDays)))
                .OrderBy(g => g.Key)
                .Select(g => new LicenseDurationMigrationDaysRemaining
                {
                    DaysRemaining = g.Key,
                    Total = g.Count(),
                    Active7d = g.Count(c => c.LastTelemetryUtc.HasValue && c.LastTelemetryUtc.Value >= now.AddDays(-7))
                })
                .ToList(),
            TopEvents = telemetryRows
                .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => r.EventName!)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(topEvents)
                .Select(g => new LicenseDurationMigrationTopEvent
                {
                    EventName = g.Key,
                    Count = g.Count(),
                    HardwareIds = g.Select(r => r.HardwareId).Distinct(StringComparer.OrdinalIgnoreCase).Count()
                })
                .ToList(),
            RecommendedSegments = new LicenseDurationMigrationRecommendedSegments(),
            Samples = includeSamples
                ? candidates
                    .OrderByDescending(c => c.LastTelemetryUtc ?? DateTime.MinValue)
                    .ThenBy(c => c.ExpirationDateUtc)
                    .Take(sampleLimit)
                    .Select(c => ToSample(c, now))
                    .ToList()
                : new List<LicenseDurationMigrationSample>()
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static List<MigrationCandidate> BuildCandidates(
        List<License> licenses,
        DateTime now,
        int currentDurationDays,
        int targetDurationDays)
    {
        var candidates = new List<MigrationCandidate>();

        foreach (var license in licenses)
        {
            if (!license.ExpirationDate.HasValue || license.ExpirationDate.Value <= now)
                continue;

            var expirationDate = license.ExpirationDate.Value;
            var hardwareIds = LicenseSeatHardwareResolver.ResolveActiveHardwareIds(license)
                .Select(h => (h.HardwareId, SeatActivation: h.FirstActivatedAt));

            foreach (var seat in hardwareIds
                .GroupBy(h => h.HardwareId, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First()))
            {
                var activationDate = license.ActivationDate ?? seat.SeatActivation;
                var inferred = false;
                if (!activationDate.HasValue)
                {
                    activationDate = expirationDate.AddDays(-currentDurationDays);
                    inferred = true;
                }

                var activationAgeDays = (int)Math.Floor((now - activationDate.Value).TotalDays);
                if (activationAgeDays <= targetDurationDays || activationAgeDays > currentDurationDays)
                    continue;

                candidates.Add(new MigrationCandidate
                {
                    LicenseId = license.Id,
                    LicenseKey = license.LicenseKey,
                    CustomerEmail = license.CustomerEmail,
                    HardwareId = seat.HardwareId,
                    ActivationDateUtc = activationDate.Value,
                    ActivationDateWasInferred = inferred,
                    ExpirationDateUtc = expirationDate,
                    ActivationAgeDays = activationAgeDays
                });
            }
        }

        return candidates;
    }

    private static bool IsDeliveredNotActivated(License license)
    {
        return LicenseSeatHardwareResolver.ResolveActiveHardwareIds(license).Count == 0
            && !license.ActivationDate.HasValue;
    }

    private static int CountActive(List<MigrationCandidate> candidates, DateTime now, int days)
    {
        var since = now.AddDays(-days);
        return candidates.Count(c => c.LastTelemetryUtc.HasValue && c.LastTelemetryUtc.Value >= since);
    }

    private static List<int> ParseActivityWindows(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return DefaultActivityWindows.ToList();

        var windows = value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => int.TryParse(part, out var parsed) ? parsed : 0)
            .Where(day => day > 0 && day <= 30)
            .Distinct()
            .OrderBy(day => day)
            .ToList();

        return windows.Count == 0 ? DefaultActivityWindows.ToList() : windows;
    }

    private static string ResolveUserSegment(List<TelemetryImpactRow> rows)
    {
        foreach (var row in rows.OrderByDescending(r => r.TimestampUtc))
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

    private static LicenseDurationMigrationSample ToSample(MigrationCandidate candidate, DateTime now)
    {
        return new LicenseDurationMigrationSample
        {
            LicenseId = candidate.LicenseId,
            CustomerEmailRedacted = RedactEmail(candidate.CustomerEmail),
            LicenseKeyRedacted = RedactKey(candidate.LicenseKey),
            HardwareIdRedacted = RedactHardwareId(candidate.HardwareId),
            ActivationDateUtc = candidate.ActivationDateUtc,
            ExpirationDateUtc = candidate.ExpirationDateUtc,
            ActivationAgeDays = candidate.ActivationAgeDays,
            DaysRemaining = Math.Max(0, (int)Math.Ceiling((candidate.ExpirationDateUtc - now).TotalDays)),
            LastTelemetryUtc = candidate.LastTelemetryUtc,
            ActivitySegment = candidate.LastTelemetryUtc switch
            {
                DateTime last when last >= now.AddDays(-1) => "active1d",
                DateTime last when last >= now.AddDays(-3) => "active3d",
                DateTime last when last >= now.AddDays(-7) => "active7d",
                _ => "inactive7d"
            },
            UserSegment = candidate.UserSegment
        };
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

    private sealed class MigrationCandidate
    {
        public Guid LicenseId { get; set; }
        public string LicenseKey { get; set; } = "";
        public string CustomerEmail { get; set; } = "";
        public string HardwareId { get; set; } = "";
        public DateTime ActivationDateUtc { get; set; }
        public bool ActivationDateWasInferred { get; set; }
        public DateTime ExpirationDateUtc { get; set; }
        public int ActivationAgeDays { get; set; }
        public DateTime? LastTelemetryUtc { get; set; }
        public string UserSegment { get; set; } = "unknown";
    }

    private sealed record TelemetryImpactRow(
        string HardwareId,
        DateTime TimestampUtc,
        string? EventName,
        string? PropertiesJson);
}
