using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetrySupportProfileAnalyticsService
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;
    private const int DefaultTake = 25;
    private const int MaxTake = 50;
    private const int MaxCandidates = 10;
    private const int MinPartialHardwareIdLength = 6;
    private const int MinEmailFragmentLength = 3;
    private const int MinLicenseFragmentLength = 6;
    private const double SaturationThreshold = 90.0;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly string[] QuotaKeys =
    {
        "Quota_Api_Hourly",
        "Quota_Api_Daily",
        "Quota_Mcp_Hourly",
        "Quota_Mcp_Daily",
        "Quota_Copilot_Hourly",
        "Quota_Copilot_Daily"
    };
    private static readonly string[] UsageKeys =
    {
        "Usage_Api",
        "Usage_Mcp",
        "Usage_Copilot"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;
    private readonly TelemetryMachineProfileAnalyticsService _machineProfileAnalytics;

    public TelemetrySupportProfileAnalyticsService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IMemoryCache cache,
        TelemetryMachineProfileAnalyticsService machineProfileAnalytics)
    {
        _dbFactory = dbFactory;
        _cache = cache;
        _machineProfileAnalytics = machineProfileAnalytics;
    }

    public async Task<TelemetrySupportProfileResponse> GetSupportProfileForProductIdAsync(
        Guid productId,
        string? hardwareId,
        string? email,
        string? emailFragment,
        string? licenseFragment,
        string? clientIp,
        int days = DefaultDays,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, MaxDays);
        take = Math.Clamp(take, 1, MaxTake);

        var criteria = NormalizeCriteria(hardwareId, email, emailFragment, licenseFragment, clientIp);
        ValidateCriteria(criteria);

        var cacheKey = string.Join(':',
            "telemetry-support-profile",
            productId.ToString("N"),
            criteria.HardwareId?.ToLowerInvariant() ?? "",
            criteria.Email?.ToLowerInvariant() ?? "",
            criteria.EmailFragment?.ToLowerInvariant() ?? "",
            criteria.LicenseFragment?.ToUpperInvariant() ?? "",
            criteria.ClientIp?.ToLowerInvariant() ?? "",
            days,
            take);

        if (_cache.TryGetValue(cacheKey, out TelemetrySupportProfileResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);

        var licenseCandidates = await FindLicenseCandidatesAsync(db, productScopeIds, criteria, cancellationToken);
        var telemetryOnlyCandidates = await FindTelemetryOnlyCandidatesAsync(
            db,
            productScopeIds,
            criteria,
            licenseCandidates
                .Select(c => c.HardwareId)
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase),
            days,
            cancellationToken);

        var candidates = licenseCandidates
            .Concat(telemetryOnlyCandidates)
            .GroupBy(c => new
            {
                License = c.LicenseId,
                Hardware = c.HardwareId?.ToLowerInvariant() ?? ""
            })
            .Select(g => MergeCandidateGroup(g.ToList()))
            .OrderByDescending(c => c.LastTelemetryUtc ?? c.SeatLastCheckInAtUtc ?? c.ActivationDateUtc ?? DateTime.MinValue)
            .ThenBy(c => c.CustomerEmailRedacted, StringComparer.OrdinalIgnoreCase)
            .Take(MaxCandidates)
            .ToList();

        await EnrichTelemetryAsync(db, productScopeIds, candidates, days, take, cancellationToken);

        var selectedCandidate = SelectCandidate(candidates, criteria);
        TelemetryMachineProfileResponse? machineProfile = null;
        TelemetrySupportQuotaSummary? quotas = null;
        if (!string.IsNullOrWhiteSpace(selectedCandidate?.HardwareId))
        {
            machineProfile = await _machineProfileAnalytics.GetMachineProfileForProductIdAsync(
                productId,
                selectedCandidate.HardwareId,
                days,
                top: 20,
                take,
                cancellationToken);

            quotas = await BuildQuotaSummaryAsync(
                db,
                productScopeIds,
                selectedCandidate.HardwareId,
                days,
                take,
                cancellationToken);
        }

        var now = DateTime.UtcNow;
        var response = new TelemetrySupportProfileResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = days,
            Query = new TelemetrySupportProfileQuery
            {
                HasHardwareId = !string.IsNullOrWhiteSpace(criteria.HardwareId),
                HardwareIdLength = criteria.HardwareId?.Length,
                HardwareIdPartialLookupEnabled = criteria.IsPartialHardwareIdLookup,
                HasEmail = !string.IsNullOrWhiteSpace(criteria.Email),
                HasEmailFragment = !string.IsNullOrWhiteSpace(criteria.EmailFragment),
                HasLicenseFragment = !string.IsNullOrWhiteSpace(criteria.LicenseFragment),
                HasClientIp = !string.IsNullOrWhiteSpace(criteria.ClientIp),
                EmailFragmentLength = criteria.EmailFragment?.Length,
                LicenseFragmentLength = criteria.LicenseFragment?.Length
            },
            CandidateCount = candidates.Count,
            IsAmbiguous = selectedCandidate == null && candidates.Count > 1,
            SelectedCandidate = selectedCandidate,
            Candidates = candidates,
            MachineProfile = machineProfile,
            Quotas = quotas,
            Insights = BuildSupportInsights(machineProfile, quotas)
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static async Task<List<TelemetrySupportCandidate>> FindLicenseCandidatesAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        SupportSearchCriteria criteria,
        CancellationToken cancellationToken)
    {
        var rawLicenseFragment = criteria.LicenseFragment?.ToUpperInvariant();
        var compactLicenseFragment = CompactKey(criteria.LicenseFragment);

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Product)
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Where(l => productScopeIds.Contains(l.ProductId))
            .Where(l =>
                (criteria.HardwareId != null && (l.HardwareId == criteria.HardwareId || l.Seats.Any(s => s.HardwareId == criteria.HardwareId)))
                || (criteria.IsPartialHardwareIdLookup
                    && ((l.HardwareId != null && l.HardwareId.ToUpper().Contains(criteria.HardwareId!))
                        || l.Seats.Any(s => s.HardwareId != null && s.HardwareId.ToUpper().Contains(criteria.HardwareId!))))
                || (criteria.Email != null && l.CustomerEmail.ToLower().Contains(criteria.Email.ToLower()))
                || (criteria.EmailFragment != null && l.CustomerEmail.ToLower().Contains(criteria.EmailFragment.ToLower()))
                || (rawLicenseFragment != null
                    && (l.LicenseKey.ToUpper().Contains(rawLicenseFragment)
                        || l.LicenseKey.Replace("-", "").Replace(" ", "").ToUpper().Contains(compactLicenseFragment))))
            .Take(50)
            .ToListAsync(cancellationToken);

        if (criteria.IsPartialHardwareIdLookup)
        {
            var exactLicenses = licenses
                .Where(l => l.HardwareId == criteria.HardwareId || l.Seats.Any(s => s.HardwareId == criteria.HardwareId))
                .ToList();

            if (exactLicenses.Count > 0)
                licenses = exactLicenses;
        }

        var candidates = new List<TelemetrySupportCandidate>();
        foreach (var license in licenses)
        {
            var matchingSeats = SelectMatchingSeats(license, criteria);
            if (matchingSeats.Count == 0 && !string.IsNullOrWhiteSpace(license.HardwareId))
            {
                matchingSeats.Add(new LicenseSeat
                {
                    LicenseId = license.Id,
                    HardwareId = license.HardwareId,
                    FirstActivatedAt = license.ActivationDate ?? license.CreationDate,
                    LastCheckInAt = license.ActivationDate ?? license.CreationDate,
                    IsActive = license.IsActive
                });
            }

            if (matchingSeats.Count == 0)
            {
                candidates.Add(BuildCandidate(license, null, criteria));
                continue;
            }

            foreach (var seat in matchingSeats)
                candidates.Add(BuildCandidate(license, seat, criteria));
        }

        return candidates;
    }

    private static async Task<List<TelemetrySupportCandidate>> FindTelemetryOnlyCandidatesAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        SupportSearchCriteria criteria,
        HashSet<string> knownHardwareIds,
        int days,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(criteria.HardwareId)
            && string.IsNullOrWhiteSpace(criteria.ClientIp))
            return new List<TelemetrySupportCandidate>();

        var since = DateTime.UtcNow.AddDays(-days);
        var hardwareId = criteria.HardwareId;
        if (!string.IsNullOrWhiteSpace(hardwareId) && knownHardwareIds.Contains(hardwareId))
            return new List<TelemetrySupportCandidate>();

        var query = db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= since);

        if (!string.IsNullOrWhiteSpace(hardwareId))
        {
            if (criteria.IsPartialHardwareIdLookup)
            {
                var exactTelemetry = await BuildTelemetryOnlyCandidatesAsync(
                    query.Where(r => r.HardwareId == hardwareId),
                    knownHardwareIds,
                    criteria,
                    cancellationToken);

                if (exactTelemetry.Count > 0)
                    return exactTelemetry;

                query = query.Where(r => r.HardwareId.ToUpper().Contains(hardwareId.ToUpper()));
            }
            else
            {
                query = query.Where(r => r.HardwareId == hardwareId);
            }
        }

        if (!string.IsNullOrWhiteSpace(criteria.ClientIp))
            query = query.Where(r => r.ClientIp == criteria.ClientIp);

        return await BuildTelemetryOnlyCandidatesAsync(query, knownHardwareIds, criteria, cancellationToken);
    }

    private static async Task<List<TelemetrySupportCandidate>> BuildTelemetryOnlyCandidatesAsync(
        IQueryable<TelemetryRecord> query,
        HashSet<string> knownHardwareIds,
        SupportSearchCriteria criteria,
        CancellationToken cancellationToken)
    {
        var telemetry = await query
            .Where(r => !knownHardwareIds.Contains(r.HardwareId))
            .GroupBy(r => r.HardwareId)
            .Select(g => new
            {
                HardwareId = g.Key,
                Count = g.Count(),
                First = g.Min(r => r.Timestamp),
                Last = g.Max(r => r.Timestamp)
            })
            .OrderByDescending(g => g.Last)
            .Take(MaxCandidates)
            .ToListAsync(cancellationToken);

        return telemetry
            .Select(t => new TelemetrySupportCandidate
            {
                MatchType = !string.IsNullOrWhiteSpace(criteria.ClientIp)
                    ? "telemetry_client_ip"
                    : criteria.IsPartialHardwareIdLookup
                        ? "telemetry_hardware_fragment"
                        : "telemetry_hardware",
                HardwareId = t.HardwareId,
                TelemetryRecords = t.Count,
                FirstTelemetryUtc = t.First,
                LastTelemetryUtc = t.Last
            })
            .ToList();
    }

    private static List<LicenseSeat> SelectMatchingSeats(License license, SupportSearchCriteria criteria)
    {
        var seats = license.Seats.ToList();
        if (!string.IsNullOrWhiteSpace(criteria.HardwareId))
        {
            return criteria.IsPartialHardwareIdLookup
                ? seats.Where(s => s.HardwareId.Contains(criteria.HardwareId, StringComparison.OrdinalIgnoreCase)).ToList()
                : seats.Where(s => s.HardwareId == criteria.HardwareId).ToList();
        }

        return seats.Count <= 1 ? seats : seats.Where(s => s.IsActive).Take(MaxCandidates).ToList();
    }

    private static TelemetrySupportCandidate BuildCandidate(
        License license,
        LicenseSeat? seat,
        SupportSearchCriteria criteria)
    {
        return new TelemetrySupportCandidate
        {
            MatchType = BuildMatchType(license, seat, criteria),
            LicenseId = license.Id,
            ProductName = license.Product?.Name,
            CustomerName = string.IsNullOrWhiteSpace(license.CustomerName) ? null : license.CustomerName,
            CustomerEmail = NormalizeEmail(license.CustomerEmail),
            CustomerEmailRedacted = RedactEmail(license.CustomerEmail),
            LicenseKeyRedacted = RedactLicenseKey(license.LicenseKey),
            LicenseKeyFirstSegment = GetLicenseKeyFirstSegment(license.LicenseKey),
            LicenseStatus = GetLicenseStatus(license),
            LicenseTypeSlug = license.Type?.Slug,
            LicenseTypeName = license.Type?.Name,
            LicenseValidityDays = license.ValidityDays,
            LicenseTypeDefaultDurationDays = license.Type?.DefaultDurationDays,
            MaxSeats = license.MaxSeats,
            ActivationDateUtc = license.ActivationDate,
            ExpirationDateUtc = license.ExpirationDate,
            HardwareId = seat?.HardwareId ?? license.HardwareId,
            SeatFirstActivatedAtUtc = seat?.FirstActivatedAt,
            SeatLastCheckInAtUtc = seat?.LastCheckInAt
        };
    }

    private static async Task EnrichTelemetryAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        List<TelemetrySupportCandidate> candidates,
        int days,
        int top,
        CancellationToken cancellationToken)
    {
        var hardwareIds = candidates
            .Select(c => c.HardwareId)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (hardwareIds.Count == 0)
            return;

        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && hardwareIds.Contains(r.HardwareId) && r.Timestamp >= since)
            .Select(r => new
            {
                r.HardwareId,
                r.Timestamp,
                r.EventName,
                r.Version,
                r.ClientIp,
                PropertiesJson = r.EventData != null ? r.EventData.PropertiesJson : null
            })
            .ToListAsync(cancellationToken);

        var grouped = rows.GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate.HardwareId) || !grouped.TryGetValue(candidate.HardwareId, out var telemetry))
                continue;

            candidate.TelemetryRecords = telemetry.Count;
            candidate.FirstTelemetryUtc = telemetry.Min(r => r.Timestamp);
            candidate.LastTelemetryUtc = telemetry.Max(r => r.Timestamp);
            candidate.TopEvents = telemetry
                .Where(r => !string.IsNullOrWhiteSpace(r.EventName))
                .GroupBy(r => r.EventName)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(top)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList();
            candidate.Versions = telemetry
                .Where(r => !string.IsNullOrWhiteSpace(r.Version))
                .GroupBy(r => r.Version!)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(top)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList();
            candidate.ClientIps = telemetry
                .Where(r => !string.IsNullOrWhiteSpace(r.ClientIp))
                .GroupBy(r => r.ClientIp!)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Min(top, 10))
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList();
            candidate.LicenseEdition ??= telemetry
                .OrderByDescending(r => r.Timestamp)
                .Select(r => ReadLicenseEdition(r.PropertiesJson))
                .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        }
    }

    private static TelemetrySupportCandidate MergeCandidateGroup(List<TelemetrySupportCandidate> group)
    {
        var first = group[0];
        first.MatchType = string.Join("+", group.Select(c => c.MatchType).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v));
        return first;
    }

    private static TelemetrySupportCandidate? SelectCandidate(
        List<TelemetrySupportCandidate> candidates,
        SupportSearchCriteria criteria)
    {
        if (candidates.Count == 1)
            return candidates[0];

        if (!string.IsNullOrWhiteSpace(criteria.HardwareId))
        {
            var exactHardware = candidates
                .Where(c => string.Equals(c.HardwareId, criteria.HardwareId, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (exactHardware.Count == 1)
                return exactHardware[0];
        }

        return null;
    }

    private static async Task<TelemetrySupportQuotaSummary?> BuildQuotaSummaryAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        string hardwareId,
        int days,
        int top,
        CancellationToken cancellationToken)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.HardwareId == hardwareId
                && r.Type == TelemetryType.Event
                && r.Timestamp >= since)
            .OrderBy(r => r.Timestamp)
            .Select(r => new
            {
                r.Timestamp,
                r.EventName,
                PropertiesJson = r.EventData != null ? r.EventData.PropertiesJson : null
            })
            .ToListAsync(cancellationToken);

        if (rows.Count == 0)
            return null;

        var quotaStats = QuotaKeys.ToDictionary(
            key => key,
            key => new SupportQuotaAccumulator(key),
            StringComparer.OrdinalIgnoreCase);
        var usageStats = UsageKeys.ToDictionary(
            key => key,
            key => new SupportUsageAccumulator(key),
            StringComparer.OrdinalIgnoreCase);
        var channelCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var sourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var recordsWithQuota = 0;

        foreach (var row in rows)
        {
            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
            var hasQuota = false;

            foreach (var key in QuotaKeys)
            {
                if (!props.TryGetValue(key, out var raw))
                    continue;

                var parsed = ParseQuota(raw);
                if (parsed == null)
                    continue;

                quotaStats[key].Add(parsed.Value.Used, parsed.Value.Limit, row.Timestamp);
                hasQuota = true;
            }

            foreach (var key in UsageKeys)
            {
                if (!props.TryGetValue(key, out var raw) || !TryParseDouble(raw, out var value))
                    continue;

                usageStats[key].Add(value, row.Timestamp);
            }

            if (!hasQuota)
                continue;

            recordsWithQuota++;
            Increment(channelCounts, GetChannel(row.EventName, props));

            if (props.TryGetValue("RequestSource", out var source) && !string.IsNullOrWhiteSpace(source))
                Increment(sourceCounts, source.Trim());
        }

        var quotas = quotaStats.Values
            .Where(q => q.Samples > 0)
            .OrderBy(q => q.QuotaKey, StringComparer.OrdinalIgnoreCase)
            .Select(q => q.ToMetric())
            .ToList();

        var usage = usageStats.Values
            .Where(u => u.Samples > 0)
            .OrderBy(u => u.UsageKey, StringComparer.OrdinalIgnoreCase)
            .Select(u => u.ToMetric())
            .ToList();

        var totalPeakUsage = usage.Sum(u => u.PeakValue);
        if (totalPeakUsage > 0)
        {
            foreach (var item in usage)
                item.PercentageOfPeakTotal = Math.Round(item.PeakValue * 100.0 / totalPeakUsage, 1);
        }

        if (quotas.Count == 0 && usage.Count == 0 && recordsWithQuota == 0)
            return null;

        return new TelemetrySupportQuotaSummary
        {
            RecordsAnalyzed = rows.Count,
            RecordsWithQuota = recordsWithQuota,
            HasSaturatedQuota = quotas.Any(q => q.IsSaturated),
            Quotas = quotas,
            Usage = usage,
            Channels = channelCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kv => new TelemetryToolChannelSummary
                {
                    Channel = kv.Key,
                    Count = kv.Value,
                    Percentage = recordsWithQuota == 0 ? 0 : Math.Round(kv.Value * 100.0 / recordsWithQuota, 1)
                })
                .ToList(),
            RequestSources = sourceCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(top)
                .Select(kv => new TelemetryToolCount { Name = kv.Key, Count = kv.Value })
                .ToList()
        };
    }

    private static SupportSearchCriteria NormalizeCriteria(
        string? hardwareId,
        string? email,
        string? emailFragment,
        string? licenseFragment,
        string? clientIp)
    {
        return new SupportSearchCriteria(
            NormalizeHardwareIdLookup(hardwareId),
            NormalizeNullable(email)?.ToLowerInvariant(),
            NormalizeNullable(emailFragment)?.ToLowerInvariant(),
            NormalizeNullable(licenseFragment)?.ToUpperInvariant(),
            NormalizeNullable(clientIp));
    }

    private static void ValidateCriteria(SupportSearchCriteria criteria)
    {
        if (criteria.HardwareId == null
            && criteria.Email == null
            && criteria.EmailFragment == null
            && criteria.LicenseFragment == null
            && criteria.ClientIp == null)
        {
            throw new ArgumentException("At least one query parameter is required: hardwareId, email, emailFragment, licenseFragment, or clientIp.");
        }

        if (criteria.EmailFragment != null && criteria.EmailFragment.Length < MinEmailFragmentLength)
            throw new ArgumentException($"emailFragment must contain at least {MinEmailFragmentLength} characters.");

        if (criteria.LicenseFragment != null && CompactKey(criteria.LicenseFragment).Length < MinLicenseFragmentLength)
            throw new ArgumentException($"licenseFragment must contain at least {MinLicenseFragmentLength} non-separator characters.");
    }

    private static string? NormalizeNullable(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string? NormalizeHardwareIdLookup(string? value)
    {
        var normalized = NormalizeNullable(value);
        if (normalized == null)
            return null;

        var compact = new string(normalized
            .Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '_' && c != ':')
            .ToArray());

        if (compact.Length >= MinPartialHardwareIdLength && compact.All(Uri.IsHexDigit))
            return compact.ToUpperInvariant();

        return normalized.ToUpperInvariant();
    }

    private static string CompactKey(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? ""
            : value.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
    }

    private static string BuildMatchType(License license, LicenseSeat? seat, SupportSearchCriteria criteria)
    {
        var matches = new List<string>();

        if (criteria.HardwareId != null
            && (string.Equals(license.HardwareId, criteria.HardwareId, StringComparison.OrdinalIgnoreCase)
                || string.Equals(seat?.HardwareId, criteria.HardwareId, StringComparison.OrdinalIgnoreCase)))
        {
            matches.Add("hardware");
        }

        if (criteria.IsPartialHardwareIdLookup
            && ((!string.IsNullOrWhiteSpace(license.HardwareId)
                    && license.HardwareId.Contains(criteria.HardwareId!, StringComparison.OrdinalIgnoreCase))
                || (!string.IsNullOrWhiteSpace(seat?.HardwareId)
                    && seat.HardwareId.Contains(criteria.HardwareId!, StringComparison.OrdinalIgnoreCase))))
        {
            matches.Add("hardware_fragment");
        }

        if (criteria.Email != null && license.CustomerEmail.Contains(criteria.Email, StringComparison.OrdinalIgnoreCase))
            matches.Add("email");

        if (criteria.EmailFragment != null && license.CustomerEmail.Contains(criteria.EmailFragment, StringComparison.OrdinalIgnoreCase))
            matches.Add("email_fragment");

        if (criteria.LicenseFragment != null
            && (license.LicenseKey.Contains(criteria.LicenseFragment, StringComparison.OrdinalIgnoreCase)
                || CompactKey(license.LicenseKey).Contains(CompactKey(criteria.LicenseFragment), StringComparison.OrdinalIgnoreCase)))
        {
            matches.Add("license_fragment");
        }

        return matches.Count == 0 ? "license" : string.Join("+", matches);
    }

    private static string GetLicenseStatus(License license)
    {
        if (!license.IsActive || license.RevokedAt != null)
            return "revoked";

        if (license.ExpirationDate != null && license.ExpirationDate < DateTime.UtcNow)
            return "expired";

        return license.ActivationDate == null ? "not_activated" : "active";
    }

    private static List<TelemetryInsightItem> BuildSupportInsights(
        TelemetryMachineProfileResponse? machineProfile,
        TelemetrySupportQuotaSummary? quotas)
    {
        if (machineProfile == null && quotas == null)
            return new List<TelemetryInsightItem>();

        var insights = new List<TelemetryInsightItem>();

        if (machineProfile != null)
        {
            AddTopEventInsight(
                insights,
                machineProfile,
                "auth",
                "warning",
                "Authentication failures on this machine",
                e => e.Name.Contains("AuthFailed", StringComparison.OrdinalIgnoreCase));

            AddTopEventInsight(
                insights,
                machineProfile,
                "compile",
                "warning",
                "Compilation failures on this machine",
                e => e.Name.Contains("Compile", StringComparison.OrdinalIgnoreCase)
                    && e.Name.Contains("Fail", StringComparison.OrdinalIgnoreCase));

            AddTopEventInsight(
                insights,
                machineProfile,
                "activation",
                "warning",
                "Activation failures on this machine",
                e => e.Name.Contains("Activation", StringComparison.OrdinalIgnoreCase)
                    && (e.Name.Contains("Fail", StringComparison.OrdinalIgnoreCase)
                        || e.Name.Contains("Error", StringComparison.OrdinalIgnoreCase)));

            AddTopEventInsight(
                insights,
                machineProfile,
                "cert-pinning",
                "critical",
                "Certificate pinning failures on this machine",
                e => e.Name.Contains("CertPinning", StringComparison.OrdinalIgnoreCase)
                    && e.Name.Contains("Fail", StringComparison.OrdinalIgnoreCase));

            var errorCount = machineProfile.TypeCounts
                .FirstOrDefault(c => c.Name.Equals("Error", StringComparison.OrdinalIgnoreCase))
                ?.Count ?? 0;

            if (errorCount > 0)
            {
                insights.Add(new TelemetryInsightItem
                {
                    Severity = errorCount >= 5 ? "critical" : "warning",
                    Category = "error",
                    Title = "Error telemetry on this machine",
                    Summary = $"{errorCount} error telemetry records were recorded for this machine.",
                    Count = errorCount,
                    Score = errorCount
                });
            }
        }

        if (quotas?.HasSaturatedQuota == true)
        {
            var saturated = quotas.Quotas
                .Where(q => q.IsSaturated)
                .OrderByDescending(q => q.PeakPercentage ?? 0)
                .ToList();

            insights.Add(new TelemetryInsightItem
            {
                Severity = "opportunity",
                Category = "quota",
                Title = "Quota saturation on this machine",
                Summary = $"{saturated.Count} quota(s) reached at least {SaturationThreshold:0}% usage.",
                Count = saturated.Count,
                Score = saturated.Max(q => q.PeakPercentage ?? 0),
                FirstSeenUtc = saturated.Min(q => q.LastSeenUtc),
                LastSeenUtc = saturated.Max(q => q.LastSeenUtc),
                Breakdown = saturated
                    .Select(q => new TelemetryToolCount
                    {
                        Name = $"{q.QuotaKey}:{q.PeakUsed}/{q.PeakLimit}",
                        Count = (int)Math.Round(q.PeakPercentage ?? 0)
                    })
                    .ToList()
            });
        }

        return insights
            .OrderByDescending(i => i.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase) ? 3
                : i.Severity.Equals("warning", StringComparison.OrdinalIgnoreCase) ? 2
                : 1)
            .ThenByDescending(i => i.Count)
            .ToList();
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

    private static bool TryParseDouble(string raw, out double value)
    {
        return double.TryParse(raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out value)
            || double.TryParse(raw, out value);
    }

    private static void AddTopEventInsight(
        List<TelemetryInsightItem> insights,
        TelemetryMachineProfileResponse machineProfile,
        string category,
        string severity,
        string title,
        Func<TelemetryToolCount, bool> predicate)
    {
        var matches = machineProfile.TopEvents.Where(predicate).ToList();
        if (matches.Count == 0)
            return;

        var count = matches.Sum(m => m.Count);
        insights.Add(new TelemetryInsightItem
        {
            Severity = severity,
            Category = category,
            Title = title,
            Summary = $"{count} matching events were found on this machine.",
            Count = count,
            Score = count,
            FirstSeenUtc = machineProfile.FirstActivityUtc,
            LastSeenUtc = machineProfile.LastActivityUtc,
            Breakdown = matches
        });
    }

    private static string? RedactEmail(string? email)
    {
        email = NormalizeEmail(email);
        if (email == null)
            return null;

        var parts = email.Split('@', 2);
        if (parts.Length != 2)
            return "***";

        var local = parts[0];
        var visible = local.Length <= 2 ? local[..1] : local[..Math.Min(2, local.Length)];
        return $"{visible}***@{parts[1]}";
    }

    private static string? NormalizeEmail(string? email)
    {
        var trimmed = email?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string? RedactLicenseKey(string? licenseKey)
    {
        var compact = CompactKey(licenseKey);
        if (compact.Length == 0)
            return null;

        if (compact.Length <= 8)
            return $"{compact[..Math.Min(4, compact.Length)]}***";

        return $"{compact[..4]}****{compact[^4..]}";
    }

    private static string? GetLicenseKeyFirstSegment(string? licenseKey)
    {
        var trimmed = NormalizeNullable(licenseKey);
        if (trimmed == null)
            return null;

        var firstSeparator = trimmed.IndexOf('-', StringComparison.Ordinal);
        var firstSegment = firstSeparator >= 0 ? trimmed[..firstSeparator] : trimmed;
        firstSegment = firstSegment.Trim();

        return string.IsNullOrWhiteSpace(firstSegment) ? null : firstSegment;
    }

    private static string? ReadLicenseEdition(string? propertiesJson)
    {
        var props = TelemetrySchemaRegistry.ParseProperties(propertiesJson);
        foreach (var key in new[] { "LicenseEdition", "LicenseTypeSlug", "Edition", "AccountType" })
        {
            if (props.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                return value.Trim();
        }

        return null;
    }

    private sealed class SupportQuotaAccumulator
    {
        private int _totalUsed;

        public SupportQuotaAccumulator(string quotaKey)
        {
            QuotaKey = quotaKey;
        }

        public string QuotaKey { get; }
        public int Samples { get; private set; }
        public int LastUsed { get; private set; }
        public int? LastLimit { get; private set; }
        public DateTime? LastSeenUtc { get; private set; }
        public int PeakUsed { get; private set; }
        public int? PeakLimit { get; private set; }
        public double? PeakPercentage { get; private set; }

        public void Add(int used, int? limit, DateTime timestampUtc)
        {
            Samples++;
            _totalUsed += used;
            LastUsed = used;
            LastLimit = limit;
            LastSeenUtc = timestampUtc;

            var percentage = limit is > 0 ? Math.Round(used * 100.0 / limit.Value, 1) : (double?)null;
            if (used > PeakUsed || (percentage.HasValue && (!PeakPercentage.HasValue || percentage.Value > PeakPercentage.Value)))
            {
                PeakUsed = used;
                PeakLimit = limit;
                PeakPercentage = percentage;
            }
        }

        public TelemetrySupportQuotaMetric ToMetric()
        {
            return new TelemetrySupportQuotaMetric
            {
                QuotaKey = QuotaKey,
                Samples = Samples,
                LastUsed = LastUsed,
                LastLimit = LastLimit,
                LastPercentage = LastLimit is > 0
                    ? Math.Round(LastUsed * 100.0 / LastLimit.Value, 1)
                    : null,
                LastSeenUtc = LastSeenUtc,
                PeakUsed = PeakUsed,
                PeakLimit = PeakLimit,
                PeakPercentage = PeakPercentage,
                AverageUsed = Samples == 0 ? 0 : Math.Round(_totalUsed * 1.0 / Samples, 1),
                IsSaturated = (PeakPercentage ?? 0) >= SaturationThreshold
            };
        }
    }

    private sealed class SupportUsageAccumulator
    {
        public SupportUsageAccumulator(string usageKey)
        {
            UsageKey = usageKey;
        }

        public string UsageKey { get; }
        public int Samples { get; private set; }
        public double LastValue { get; private set; }
        public DateTime? LastSeenUtc { get; private set; }
        public double PeakValue { get; private set; }

        public void Add(double value, DateTime timestampUtc)
        {
            Samples++;
            LastValue = value;
            LastSeenUtc = timestampUtc;

            if (value > PeakValue)
                PeakValue = value;
        }

        public TelemetrySupportUsageMetric ToMetric()
        {
            return new TelemetrySupportUsageMetric
            {
                UsageKey = UsageKey,
                Channel = UsageKey.Replace("Usage_", "", StringComparison.Ordinal).ToLowerInvariant(),
                Samples = Samples,
                LastValue = LastValue,
                LastSeenUtc = LastSeenUtc,
                PeakValue = PeakValue
            };
        }
    }

    private sealed record SupportSearchCriteria(
        string? HardwareId,
        string? Email,
        string? EmailFragment,
        string? LicenseFragment,
        string? ClientIp)
    {
        public bool IsPartialHardwareIdLookup => HardwareId is { Length: >= MinPartialHardwareIdLength };
    }
}
