using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class FreemiumAbuseRiskAnalyticsService
{
    private const string DefaultLicenseType = "TIA-CONNECT-FREEMIUM";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

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

    private static readonly HashSet<string> McpCopilotEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "Mcp_ToolCall",
        "Copilot_ToolCall",
        "Copilot_Chat_Success"
    };

    private static readonly HashSet<string> FreemailDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "gmail.com",
        "googlemail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com"
    };

    private static readonly string[] QuotaKeys =
    {
        "Quota_Api_Daily",
        "Quota_Mcp_Daily",
        "Quota_Copilot_Daily"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public FreemiumAbuseRiskAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<FreemiumAbuseRiskResponse> GetRiskForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        string? licenseType = DefaultLicenseType,
        int take = 50,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, 100);
        var normalizedLicenseType = string.IsNullOrWhiteSpace(licenseType)
            ? DefaultLicenseType
            : licenseType.Trim();

        var cacheKey = string.Join(':',
            "freemium-abuse-risk",
            productId.ToString("N"),
            normalizedLicenseType.ToUpperInvariant(),
            period.FromUtc.ToString("O"),
            period.ToUtc.ToString("O"),
            take);

        if (_cache.TryGetValue(cacheKey, out FreemiumAbuseRiskResponse? cached) && cached != null)
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

        var candidates = BuildCandidates(licenses, now);
        var hardwareIds = candidates
            .Select(c => c.HardwareId)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetryRows = hardwareIds.Count == 0
            ? new List<RiskTelemetryRow>()
            : await db.TelemetryRecords.AsNoTracking()
                .Include(r => r.EventData)
                .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                    && r.Timestamp >= period.FromUtc
                    && r.Timestamp <= period.ToUtc
                    && hardwareIds.Contains(r.HardwareId))
                .Select(r => new RiskTelemetryRow(
                    r.HardwareId,
                    r.Timestamp,
                    r.EventName,
                    r.ClientIp,
                    r.Version,
                    r.EventData != null ? r.EventData.PropertiesJson : null))
                .ToListAsync(cancellationToken);

        var telemetryByHardware = telemetryRows
            .GroupBy(r => r.HardwareId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(r => r.TimestampUtc).ToList(), StringComparer.OrdinalIgnoreCase);

        var groups = candidates
            .GroupBy(BuildGroupKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => BuildGroup(g.Key, g.ToList(), telemetryByHardware))
            .Where(g => g.LicenseCount > 0)
            .OrderByDescending(g => g.Score)
            .ThenByDescending(g => g.LastTelemetryUtc ?? DateTime.MinValue)
            .ThenBy(g => g.GroupKey, StringComparer.OrdinalIgnoreCase)
            .ToList();

        for (var i = 0; i < groups.Count; i++)
            groups[i].Rank = i + 1;

        var returned = groups.Take(take).ToList();
        var response = new FreemiumAbuseRiskResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            LicenseType = normalizedLicenseType,
            Summary = new FreemiumAbuseRiskSummary
            {
                GroupsAnalyzed = groups.Count,
                GroupsReturned = returned.Count,
                HighRiskGroups = groups.Count(g => g.RiskBand == "high"),
                MediumRiskGroups = groups.Count(g => g.RiskBand == "medium"),
                EnterpriseFreemiumGroups = groups.Count(g => g.Classification == "enterprise_freemium"),
                SecuritySignalGroups = groups.Count(g => g.Classification == "security_or_license_signal"),
                TotalLicenses = groups.Sum(g => g.LicenseCount),
                TotalHardwareIds = groups.Sum(g => g.HardwareIdCount),
                TotalEmails = groups.Sum(g => g.EmailCount),
                TotalTelemetryEvents = groups.Sum(g => g.TelemetryEvents)
            },
            RiskBands = groups
                .GroupBy(g => g.RiskBand)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
                .ToList(),
            Groups = returned
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static List<RiskCandidate> BuildCandidates(List<License> licenses, DateTime now)
    {
        var candidates = new List<RiskCandidate>();
        foreach (var license in licenses)
        {
            var status = ResolveLicenseStatus(license, now);
            var hardwareIds = LicenseSeatHardwareResolver.ResolveActiveHardwareIds(license)
                .Select(h => (h.HardwareId, SeatActivation: h.FirstActivatedAt));

            foreach (var seat in hardwareIds
                .Where(h => !string.IsNullOrWhiteSpace(h.HardwareId))
                .GroupBy(h => h.HardwareId, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First()))
            {
                candidates.Add(new RiskCandidate(
                    license.Id,
                    license.CustomerEmail,
                    NormalizeCustomerName(license.CustomerName),
                    ExtractEmailDomain(license.CustomerEmail),
                    seat.HardwareId,
                    status,
                    license.ActivationDate ?? seat.SeatActivation,
                    license.ExpirationDate));
            }
        }

        return candidates;
    }

    private static string BuildGroupKey(RiskCandidate candidate)
    {
        if (!string.IsNullOrWhiteSpace(candidate.EmailDomain) && !FreemailDomains.Contains(candidate.EmailDomain))
            return $"domain:{candidate.EmailDomain}";

        if (!string.IsNullOrWhiteSpace(candidate.CustomerNameNormalized))
            return $"customer-name:{HashValue(candidate.CustomerNameNormalized)}";

        if (!string.IsNullOrWhiteSpace(candidate.EmailDomain))
            return $"domain:{candidate.EmailDomain}";

        return $"hwid:{HashValue(candidate.HardwareId)}";
    }

    private static FreemiumAbuseRiskGroup BuildGroup(
        string groupKey,
        List<RiskCandidate> candidates,
        Dictionary<string, List<RiskTelemetryRow>> telemetryByHardware)
    {
        var rows = candidates
            .SelectMany(c => telemetryByHardware.TryGetValue(c.HardwareId, out var telemetry)
                ? telemetry
                : Enumerable.Empty<RiskTelemetryRow>())
            .OrderByDescending(r => r.TimestampUtc)
            .ToList();

        var emailDomain = candidates
            .Select(c => c.EmailDomain)
            .FirstOrDefault(d => !string.IsNullOrWhiteSpace(d));

        var emailCount = candidates.Select(c => c.CustomerEmail).Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var customerNameCount = candidates.Select(c => c.CustomerNameNormalized).Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var hasSharedCustomerName = groupKey.StartsWith("customer-name:", StringComparison.OrdinalIgnoreCase)
            && (emailCount >= 2 || candidates.Select(c => c.HardwareId).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2);
        var hardwareCount = candidates.Select(c => c.HardwareId).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var clientIps = rows.Select(r => r.ClientIp).Where(ip => !string.IsNullOrWhiteSpace(ip)).Select(ip => ip!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var productiveEvents = rows.Count(r => ProductiveEvents.Contains(r.EventName));
        var mcpCopilotEvents = rows.Count(r => McpCopilotEvents.Contains(r.EventName));
        var quotaPeaks = BuildQuotaPeaks(rows);

        var signals = BuildSignals(
            candidates,
            rows,
            emailDomain,
            emailCount,
            hasSharedCustomerName,
            hardwareCount,
            clientIps.Count,
            productiveEvents,
            mcpCopilotEvents,
            quotaPeaks);

        var score = Math.Round(signals.Sum(s => s.Points), 2);
        var classification = Classify(candidates, emailDomain, score, hardwareCount, emailCount, hasSharedCustomerName, productiveEvents, mcpCopilotEvents);
        var policy = ResolvePolicy(classification, score, hardwareCount, emailCount, productiveEvents, mcpCopilotEvents, quotaPeaks);

        return new FreemiumAbuseRiskGroup
        {
            GroupKey = groupKey,
            GroupType = groupKey.StartsWith("domain:", StringComparison.OrdinalIgnoreCase)
                ? "email_domain"
                : groupKey.StartsWith("customer-name:", StringComparison.OrdinalIgnoreCase)
                    ? "customer_name"
                    : "hardware",
            EmailDomain = emailDomain,
            RiskBand = score >= 80 ? "high" : score >= 40 ? "medium" : "low",
            Classification = classification,
            PolicyLevel = policy.Level,
            RecommendedAction = policy.Action,
            ReviewCategory = policy.Category,
            DeduplicationKey = BuildDeduplicationKey(groupKey, classification, policy.Level),
            DeduplicationWindow = policy.DeduplicationWindow,
            Score = score,
            Signals = signals,
            LicenseCount = candidates.Select(c => c.LicenseId).Distinct().Count(),
            ActiveLicenses = candidates.Select(c => c.LicenseId).Distinct().Count(id => candidates.Any(c => c.LicenseId == id && c.LicenseStatus == "active")),
            ExpiredLicenses = candidates.Select(c => c.LicenseId).Distinct().Count(id => candidates.Any(c => c.LicenseId == id && c.LicenseStatus == "expired")),
            RevokedLicenses = candidates.Select(c => c.LicenseId).Distinct().Count(id => candidates.Any(c => c.LicenseId == id && c.LicenseStatus == "revoked")),
            EmailCount = emailCount,
            HardwareIdCount = hardwareCount,
            ClientIpCount = clientIps.Count,
            TelemetryEvents = rows.Count,
            ProductiveEvents = productiveEvents,
            McpCopilotEvents = mcpCopilotEvents,
            FirstActivationUtc = candidates.Select(c => c.ActivationDateUtc).Where(d => d.HasValue).Min(),
            LastActivationUtc = candidates.Select(c => c.ActivationDateUtc).Where(d => d.HasValue).Max(),
            LastTelemetryUtc = rows.FirstOrDefault()?.TimestampUtc,
            EmailsRedacted = candidates.Select(c => RedactEmail(c.CustomerEmail)).Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(e => e, StringComparer.OrdinalIgnoreCase).Take(20).ToList(),
            CustomerNameHashes = candidates.Select(c => c.CustomerNameNormalized).Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => HashValue(n!)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(h => h, StringComparer.OrdinalIgnoreCase).Take(20).ToList(),
            HardwareIdsRedacted = candidates.Select(c => RedactHardwareId(c.HardwareId)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(h => h, StringComparer.OrdinalIgnoreCase).Take(20).ToList(),
            HardwareIdHashes = candidates.Select(c => HashValue(c.HardwareId)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(h => h, StringComparer.OrdinalIgnoreCase).Take(20).ToList(),
            ClientIpsRedacted = clientIps.Select(RedactIp).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase).Take(20).ToList(),
            Versions = rows.Select(r => r.Version).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!).Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(v => v, StringComparer.OrdinalIgnoreCase).Take(10).ToList(),
            TopEvents = ToTopCounts(rows.Select(r => r.EventName), 10),
            TopEventFamilies = ToTopCounts(rows.Select(r => ClassifyFamily(r.EventName)), 10),
            QuotaPeaks = quotaPeaks
        };
    }

    private static List<FreemiumAbuseRiskSignal> BuildSignals(
        List<RiskCandidate> candidates,
        List<RiskTelemetryRow> rows,
        string? emailDomain,
        int emailCount,
        bool hasSharedCustomerName,
        int hardwareCount,
        int clientIpCount,
        int productiveEvents,
        int mcpCopilotEvents,
        List<FreemiumAbuseQuotaPeak> quotaPeaks)
    {
        var signals = new List<FreemiumAbuseRiskSignal>();

        AddThresholdSignal(signals, "multi_email", emailCount, 2, 8, "emails distincts");
        if (hasSharedCustomerName)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "shared_customer_name", Points = 18, Detail = "nom client normalise partage par plusieurs emails/HWID" });
        AddThresholdSignal(signals, "multi_hwid", hardwareCount, 2, 12, "HWID distincts");
        AddThresholdSignal(signals, "multi_ip", clientIpCount, 2, 4, "IP clientes distinctes");

        if (!string.IsNullOrWhiteSpace(emailDomain) && !FreemailDomains.Contains(emailDomain) && (emailCount >= 2 || hardwareCount >= 2))
            signals.Add(new FreemiumAbuseRiskSignal { Code = "business_domain", Points = 25, Detail = $"domaine entreprise probable {emailDomain}" });

        var active = candidates.Count(c => c.LicenseStatus == "active");
        var expired = candidates.Count(c => c.LicenseStatus == "expired");
        var revoked = candidates.Count(c => c.LicenseStatus == "revoked");
        if (active > 0)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "active_freemium", Points = Math.Min(active, 10) * 2, Detail = $"{active} licence(s)/poste(s) Freemium actif(s)" });
        if (expired > 0 && rows.Count > 0)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "expired_with_telemetry", Points = Math.Min(expired, 10) * 18, Detail = $"{expired} licence(s)/poste(s) expire(s) avec telemetry recente" });
        if (revoked > 0 && rows.Count > 0)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "revoked_with_telemetry", Points = Math.Min(revoked, 10) * 25, Detail = $"{revoked} licence(s)/poste(s) revoque(s) avec telemetry recente" });

        if (productiveEvents > 0)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "productive_usage", Points = Math.Min(productiveEvents, 50) * 1.2, Detail = $"{productiveEvents} evenement(s) productif(s)" });
        if (mcpCopilotEvents > 0)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "mcp_copilot_usage", Points = Math.Min(mcpCopilotEvents, 100) * 0.6, Detail = $"{mcpCopilotEvents} evenement(s) MCP/Copilot" });
        if (rows.Count >= 100)
            signals.Add(new FreemiumAbuseRiskSignal { Code = "high_event_volume", Points = Math.Min(rows.Count / 10.0, 25), Detail = $"{rows.Count} evenement(s) telemetry" });

        foreach (var quota in quotaPeaks.Where(q => q.PeakPercentage >= 90))
        {
            signals.Add(new FreemiumAbuseRiskSignal
            {
                Code = "quota_saturated",
                Points = quota.PeakPercentage >= 100 ? 20 : 12,
                Detail = $"{quota.QuotaKey}:{quota.PeakUsed}/{quota.Limit}"
            });
        }

        return signals
            .OrderByDescending(s => s.Points)
            .ThenBy(s => s.Code, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void AddThresholdSignal(List<FreemiumAbuseRiskSignal> signals, string code, int count, int threshold, double pointsPerExtra, string label)
    {
        if (count < threshold)
            return;

        signals.Add(new FreemiumAbuseRiskSignal
        {
            Code = code,
            Points = (count - 1) * pointsPerExtra,
            Detail = $"{count} {label}"
        });
    }

    private static string Classify(
        List<RiskCandidate> candidates,
        string? emailDomain,
        double score,
        int hardwareCount,
        int emailCount,
        bool hasSharedCustomerName,
        int productiveEvents,
        int mcpCopilotEvents)
    {
        if (candidates.Any(c => c.LicenseStatus is "expired" or "revoked") && (productiveEvents > 0 || mcpCopilotEvents > 0))
            return "security_or_license_signal";

        if (!string.IsNullOrWhiteSpace(emailDomain) && !FreemailDomains.Contains(emailDomain) && (hardwareCount >= 2 || emailCount >= 2) && score >= 40)
            return "enterprise_freemium";

        if (hardwareCount >= 5 || emailCount >= 5)
            return "probable_multi_account_abuse";

        if (hasSharedCustomerName && (hardwareCount >= 2 || emailCount >= 2))
            return "probable_multi_account_abuse";

        if (hardwareCount >= 2 || emailCount >= 2)
            return "small_team_or_multi_device";

        return "solo_or_low_usage";
    }

    private static FreemiumAbusePolicy ResolvePolicy(
        string classification,
        double score,
        int hardwareCount,
        int emailCount,
        int productiveEvents,
        int mcpCopilotEvents,
        List<FreemiumAbuseQuotaPeak> quotaPeaks)
    {
        if (classification == "security_or_license_signal")
        {
            return new FreemiumAbusePolicy(
                5,
                "route_to_license_security_review",
                "security_or_license_signal",
                "24h");
        }

        var saturatedQuotaCount = quotaPeaks.Count(q => q.PeakPercentage >= 90);
        if (classification == "enterprise_freemium" && (productiveEvents > 0 || mcpCopilotEvents > 0))
        {
            return new FreemiumAbusePolicy(
                4,
                "request_contact_or_conversion",
                "commercial_review",
                "7d");
        }

        if (hardwareCount >= 5 || emailCount >= 5 || score >= 100 || saturatedQuotaCount >= 2)
        {
            return new FreemiumAbusePolicy(
                3,
                "review_soft_limit_or_group_quota",
                "commercial_review",
                "7d");
        }

        if (hardwareCount >= 3 || emailCount >= 3 || score >= 40)
        {
            return new FreemiumAbusePolicy(
                2,
                "create_internal_review_alert",
                "commercial_review",
                "7d");
        }

        return new FreemiumAbusePolicy(
            1,
            "observe",
            "commercial_review",
            "7d");
    }

    private static string BuildDeduplicationKey(string groupKey, string classification, int policyLevel) =>
        $"freemium-abuse:{classification}:L{policyLevel}:{HashValue(groupKey)}";

    private static List<FreemiumAbuseQuotaPeak> BuildQuotaPeaks(List<RiskTelemetryRow> rows)
    {
        var peaks = new Dictionary<string, FreemiumAbuseQuotaPeak>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var props = ParseProperties(row.PropertiesJson);
            foreach (var key in QuotaKeys)
            {
                if (!props.TryGetValue(key, out var raw))
                    continue;

                var parsed = ParseQuota(raw);
                if (parsed == null)
                    continue;

                if (!peaks.TryGetValue(key, out var current) || parsed.Value.Used > current.PeakUsed)
                {
                    peaks[key] = new FreemiumAbuseQuotaPeak
                    {
                        QuotaKey = key,
                        PeakUsed = parsed.Value.Used,
                        Limit = parsed.Value.Limit,
                        PeakPercentage = parsed.Value.Limit > 0
                            ? Math.Round(parsed.Value.Used * 100.0 / parsed.Value.Limit, 1)
                            : null
                    };
                }
            }
        }

        return peaks.Values.OrderBy(q => q.QuotaKey, StringComparer.OrdinalIgnoreCase).ToList();
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

    private static (int Used, int Limit)? ParseQuota(string value)
    {
        var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
            return null;

        return int.TryParse(parts[0], out var used) && int.TryParse(parts[1], out var limit)
            ? (used, limit)
            : null;
    }

    private static string ResolveLicenseStatus(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt.HasValue)
            return "revoked";

        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
            return "expired";

        return "active";
    }

    private static string? ExtractEmailDomain(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        var parts = email.Trim().Split('@', 2);
        return parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1])
            ? parts[1].Trim().ToLowerInvariant()
            : null;
    }

    private static string? NormalizeCustomerName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return null;

        var trimmed = name.Trim();
        if (trimmed.Contains('@') || trimmed.Length < 5)
            return null;

        var normalized = trimmed.Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(normalized.Length);
        foreach (var c in normalized)
        {
            var category = CharUnicodeInfo.GetUnicodeCategory(c);
            if (category == UnicodeCategory.NonSpacingMark)
                continue;

            if (char.IsLetterOrDigit(c))
                builder.Append(char.ToLowerInvariant(c));
        }

        var value = builder.ToString();
        return value.Length >= 5 ? value : null;
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

    private static string RedactHardwareId(string hardwareId)
    {
        if (hardwareId.Length <= 8)
            return "***";

        return $"{hardwareId[..6]}...{hardwareId[^4..]}";
    }

    private static string RedactIp(string ip)
    {
        if (ip.Contains(':'))
        {
            var parts = ip.Split(':', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length <= 2 ? "***" : $"{parts[0]}:{parts[1]}::***";
        }

        var octets = ip.Split('.');
        return octets.Length == 4 ? $"{octets[0]}.{octets[1]}.{octets[2]}.***" : "***";
    }

    private static string HashValue(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private sealed record RiskCandidate(
        Guid LicenseId,
        string CustomerEmail,
        string? CustomerNameNormalized,
        string? EmailDomain,
        string HardwareId,
        string LicenseStatus,
        DateTime? ActivationDateUtc,
        DateTime? ExpirationDateUtc);

    private sealed record RiskTelemetryRow(
        string HardwareId,
        DateTime TimestampUtc,
        string EventName,
        string? ClientIp,
        string? Version,
        string? PropertiesJson);

    private sealed record FreemiumAbusePolicy(
        int Level,
        string Action,
        string Category,
        string DeduplicationWindow);
}
