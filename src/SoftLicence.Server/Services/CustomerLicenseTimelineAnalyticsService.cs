using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class CustomerLicenseTimelineAnalyticsService
{
    private const int DefaultDays = 30;
    private const int MaxDays = 30;
    private const int DefaultTakeTimeline = 150;
    private const int MaxTakeTimeline = 500;
    private const int MaxLicenses = 20;
    private const int MaxHardwareIds = 50;
    private const int MinEmailFragmentLength = 3;
    private const int MinHardwareFragmentLength = 6;
    private const int MinLicenseFragmentLength = 6;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private static readonly HashSet<string> ImportantEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "LicenseActivation_Clicked",
        "LicenseActivation_Started",
        "LicenseActivation_Success",
        "LicenseActivation_Failed",
        "LicenseActivation_ApiError",
        "LicenseActivation_Retry",
        "LicensePrompt_Shown",
        "Startup_NoLicenseDetected",
        "Startup_LicensePromptShown",
        "Update_RevokeLicense",
        "Update_Check",
        "LicenseDeactivation_Started",
        "LicenseDeactivation_Success",
        "LicenseDeactivation_Failed",
        "LicenseCleared",
        "CertPinningFailed",
        "CertPinningRecovered"
    };

    private static readonly HashSet<string> SensitivePropertyKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "LicenseKey",
        "LicenseFile",
        "LicenseContent",
        "Token",
        "AccessToken",
        "RefreshToken",
        "Password",
        "Secret",
        "ApiKey",
        "PrivateKey",
        "RequestBody",
        "ResponseBody",
        "StackTrace"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public CustomerLicenseTimelineAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<CustomerLicenseTimelineResponse> GetTimelineForProductIdAsync(
        Guid productId,
        string? email,
        string? emailFragment,
        string? hardwareId,
        string? licenseId,
        string? licenseFragment,
        TelemetryAnalyticsPeriod period,
        int takeTimeline = DefaultTakeTimeline,
        int offset = 0,
        bool includeAccessLogs = true,
        bool includeNoise = false,
        bool importantOnly = true,
        bool includeProperties = false,
        string? mode = "timeline",
        CancellationToken cancellationToken = default)
    {
        takeTimeline = Math.Clamp(takeTimeline, 1, MaxTakeTimeline);
        offset = Math.Max(0, offset);
        mode = NormalizeMode(mode);

        var criteria = NormalizeCriteria(email, emailFragment, hardwareId, licenseId, licenseFragment);
        ValidateCriteria(criteria);

        var cacheKey = string.Join(':',
            "customer-license-timeline",
            productId.ToString("N"),
            criteria.Email ?? "",
            criteria.EmailFragment ?? "",
            criteria.HardwareId ?? "",
            criteria.LicenseId?.ToString("N") ?? "",
            criteria.LicenseFragment ?? "",
            period.FromUtc.Ticks,
            period.ToUtc.Ticks,
            takeTimeline,
            offset,
            includeAccessLogs,
            includeNoise,
            importantOnly,
            includeProperties,
            mode);

        if (_cache.TryGetValue(cacheKey, out CustomerLicenseTimelineResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);

        var licenses = await ResolveLicensesAsync(db, productScopeIds, criteria, cancellationToken);
        var hardwareIds = ResolveHardwareIds(licenses, criteria);

        await AddTelemetryHardwareIdsAsync(db, productScopeIds, hardwareIds, criteria, period, cancellationToken);
        var boundedHardwareIds = hardwareIds.Take(MaxHardwareIds).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var telemetryRows = await LoadTelemetryRowsAsync(db, productScopeIds, boundedHardwareIds, period, includeNoise, importantOnly, cancellationToken);
        var accessLogs = includeAccessLogs
            ? await LoadAccessLogsAsync(db, productScopeIds, licenses, boundedHardwareIds, period, cancellationToken)
            : new List<AccessLogTimelineRow>();

        var timeline = new List<CustomerLicenseTimelineItem>();
        timeline.AddRange(BuildLicenseEvents(licenses, period));
        timeline.AddRange(BuildSeatEvents(licenses, period));
        timeline.AddRange(telemetryRows.Select(r => BuildTelemetryItem(r, includeProperties)));
        timeline.AddRange(accessLogs.Select(BuildAccessLogItem));

        timeline = timeline
            .OrderBy(i => i.TimestampUtc)
            .ThenBy(i => i.Source, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var returnedTimeline = mode == "summary"
            ? new List<CustomerLicenseTimelineItem>()
            : timeline.Skip(offset).Take(takeTimeline).ToList();

        var hardwareSummaries = BuildHardwareSummaries(licenses, telemetryRows, boundedHardwareIds, includeProperties);
        var response = new CustomerLicenseTimelineResponse
        {
            GeneratedAtUtc = DateTime.UtcNow,
            Cached = false,
            ExpiresAtUtc = DateTime.UtcNow.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            Query = new CustomerLicenseTimelineQuery
            {
                HasEmail = criteria.Email != null,
                HasEmailFragment = criteria.EmailFragment != null,
                HasHardwareId = criteria.HardwareId != null,
                HasLicenseId = criteria.LicenseId.HasValue,
                HasLicenseFragment = criteria.LicenseFragment != null,
                IncludeAccessLogs = includeAccessLogs,
                IncludeNoise = includeNoise,
                IncludeProperties = includeProperties,
                ImportantOnly = importantOnly,
                Mode = mode,
                TakeTimeline = takeTimeline,
                Offset = offset
            },
            Candidates = BuildCandidates(licenses, criteria),
            Licenses = licenses.Select(BuildLicenseSummary).ToList(),
            HardwareIds = hardwareSummaries,
            Timeline = returnedTimeline,
            TimelineTotal = timeline.Count,
            TimelineReturned = returnedTimeline.Count,
            OmittedRecords = Math.Max(0, timeline.Count - returnedTimeline.Count - offset),
            HasMore = offset + returnedTimeline.Count < timeline.Count
        };

        response.Summary = BuildSummary(response, telemetryRows, accessLogs, timeline);

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    public static string? RedactLicenseKeyForTimeline(string? licenseKey) => RedactLicenseKey(licenseKey);

    public static Dictionary<string, string> RedactPropertiesForTimeline(string? propertiesJson, int maxProperties = 12)
    {
        var props = TelemetrySchemaRegistry.ParseProperties(propertiesJson);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var kv in props.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (result.Count >= maxProperties)
                break;
            if (SensitivePropertyKeys.Contains(kv.Key))
                continue;
            if (kv.Key.Contains("Path", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = kv.Value?.Trim();
            if (string.IsNullOrWhiteSpace(value))
                continue;

            result[kv.Key] = value.Length > 160 ? value[..160] : value;
        }

        return result;
    }

    private static async Task<List<License>> ResolveLicensesAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        TimelineCriteria criteria,
        CancellationToken cancellationToken)
    {
        var compactLicenseFragment = CompactKey(criteria.LicenseFragment);

        var query = db.Licenses.AsNoTracking()
            .Include(l => l.Product)
            .Include(l => l.Type)
            .Include(l => l.Seats)
            .Include(l => l.History)
            .Where(l => productScopeIds.Contains(l.ProductId))
            .Where(l =>
                (criteria.LicenseId.HasValue && l.Id == criteria.LicenseId.Value)
                || (criteria.Email != null && l.CustomerEmail.ToLower().Contains(criteria.Email))
                || (criteria.EmailFragment != null && l.CustomerEmail.ToLower().Contains(criteria.EmailFragment))
                || (criteria.HardwareId != null
                    && (l.HardwareId == criteria.HardwareId
                        || l.Seats.Any(s => s.HardwareId == criteria.HardwareId)
                        || (criteria.HardwareIdIsFragment
                            && ((l.HardwareId != null && l.HardwareId.Contains(criteria.HardwareId))
                                || l.Seats.Any(s => s.HardwareId.Contains(criteria.HardwareId))))))
                || (criteria.LicenseFragment != null
                    && (l.LicenseKey.ToUpper().Contains(criteria.LicenseFragment)
                        || l.LicenseKey.Replace("-", "").Replace(" ", "").ToUpper().Contains(compactLicenseFragment))));

        return await query
            .OrderByDescending(l => l.ActivationDate ?? l.CreationDate)
            .Take(MaxLicenses)
            .ToListAsync(cancellationToken);
    }

    private static HashSet<string> ResolveHardwareIds(List<License> licenses, TimelineCriteria criteria)
    {
        var hardwareIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(criteria.HardwareId) && !criteria.HardwareIdIsFragment)
            hardwareIds.Add(criteria.HardwareId);

        foreach (var license in licenses)
        {
            if (!string.IsNullOrWhiteSpace(license.HardwareId))
                hardwareIds.Add(license.HardwareId);

            foreach (var seat in license.Seats)
            {
                if (!string.IsNullOrWhiteSpace(seat.HardwareId))
                    hardwareIds.Add(seat.HardwareId);
            }
        }

        return hardwareIds;
    }

    private static async Task AddTelemetryHardwareIdsAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        HashSet<string> hardwareIds,
        TimelineCriteria criteria,
        TelemetryAnalyticsPeriod period,
        CancellationToken cancellationToken)
    {
        if (criteria.HardwareId == null)
            return;

        var query = db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Timestamp >= period.FromUtc && r.Timestamp <= period.ToUtc);

        query = criteria.HardwareIdIsFragment
            ? query.Where(r => r.HardwareId.ToUpper().Contains(criteria.HardwareId))
            : query.Where(r => r.HardwareId == criteria.HardwareId);

        var telemetryHardwareIds = await query
            .Where(r => r.HardwareId != "")
            .Select(r => r.HardwareId)
            .Distinct()
            .Take(MaxHardwareIds)
            .ToListAsync(cancellationToken);

        foreach (var id in telemetryHardwareIds)
            hardwareIds.Add(id);
    }

    private static async Task<List<TelemetryTimelineRow>> LoadTelemetryRowsAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        HashSet<string> hardwareIds,
        TelemetryAnalyticsPeriod period,
        bool includeNoise,
        bool importantOnly,
        CancellationToken cancellationToken)
    {
        if (hardwareIds.Count == 0)
            return new List<TelemetryTimelineRow>();

        var rows = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && hardwareIds.Contains(r.HardwareId)
                && r.Timestamp >= period.FromUtc && r.Timestamp <= period.ToUtc)
            .Select(r => new TelemetryTimelineRow(
                r.Timestamp,
                r.HardwareId,
                r.ClientIp,
                r.AppName,
                r.Version,
                r.EventName,
                r.Type.ToString(),
                r.EventData != null ? r.EventData.PropertiesJson : null,
                r.ErrorData != null ? r.ErrorData.ErrorType : null,
                r.DiagnosticData != null ? r.DiagnosticData.Score : null))
            .ToListAsync(cancellationToken);

        return rows
            .Where(r => includeNoise || !IsNoiseEvent(r.EventName))
            .Where(r => !importantOnly || IsImportantEvent(r.EventName, r.Type))
            .ToList();
    }

    private static async Task<List<AccessLogTimelineRow>> LoadAccessLogsAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        List<License> licenses,
        HashSet<string> hardwareIds,
        TelemetryAnalyticsPeriod period,
        CancellationToken cancellationToken)
    {
        var licenseKeys = licenses.Select(l => l.LicenseKey).Where(k => !string.IsNullOrWhiteSpace(k)).ToList();
        if (hardwareIds.Count == 0 && licenseKeys.Count == 0)
            return new List<AccessLogTimelineRow>();

        var rows = await db.AccessLogs.AsNoTracking()
            .Where(a => a.Timestamp >= period.FromUtc && a.Timestamp <= period.ToUtc)
            .Where(a => a.Endpoint.Contains("Activation") || a.Path.Contains("/api/activation") || a.Path.Contains("/api/updates"))
            .Where(a => hardwareIds.Contains(a.HardwareId) || licenseKeys.Contains(a.LicenseKey))
            .OrderBy(a => a.Timestamp)
            .Take(1000)
            .Select(a => new AccessLogTimelineRow(
                a.Timestamp,
                a.HardwareId,
                a.ClientIp,
                a.Path,
                a.Endpoint,
                a.StatusCode,
                a.ResultStatus,
                a.ErrorDetails,
                a.IsSuccess))
            .ToListAsync(cancellationToken);

        return rows;
    }

    private static IEnumerable<CustomerLicenseTimelineItem> BuildLicenseEvents(List<License> licenses, TelemetryAnalyticsPeriod period)
    {
        foreach (var license in licenses)
        {
            if (IsInPeriod(license.CreationDate, period))
            {
                yield return new CustomerLicenseTimelineItem
                {
                    TimestampUtc = license.CreationDate,
                    Source = "license",
                    LicenseId = license.Id,
                    Action = "CREATED",
                    Category = "license",
                    Result = "observed",
                    ShortProperties = new Dictionary<string, string>
                    {
                        ["licenseKeyRedacted"] = RedactLicenseKey(license.LicenseKey) ?? "",
                        ["customerEmailRedacted"] = RedactEmail(license.CustomerEmail) ?? "",
                        ["maxSeats"] = license.MaxSeats.ToString()
                    }
                };
            }

            if (license.RevokedAt.HasValue && IsInPeriod(license.RevokedAt.Value, period))
            {
                yield return new CustomerLicenseTimelineItem
                {
                    TimestampUtc = license.RevokedAt.Value,
                    Source = "license",
                    LicenseId = license.Id,
                    Action = "REVOKED",
                    Category = "revoke",
                    Severity = "warning",
                    Result = "observed",
                    ReasonCode = NormalizeReason(license.RevocationReason) ?? "LicenseRevoked",
                    ShortProperties = new Dictionary<string, string>
                    {
                        ["reason"] = RedactFreeText(license.RevocationReason) ?? ""
                    }
                };
            }

            foreach (var history in license.History.Where(h => IsInPeriod(h.Timestamp, period)))
            {
                yield return new CustomerLicenseTimelineItem
                {
                    TimestampUtc = history.Timestamp,
                    Source = "license",
                    LicenseId = license.Id,
                    Action = history.Action,
                    Category = CategorizeAction(history.Action),
                    Result = "observed",
                    ReasonCode = NormalizeReason(history.Action),
                    ShortProperties = new Dictionary<string, string>
                    {
                        ["details"] = RedactFreeText(history.Details) ?? "",
                        ["performedBy"] = RedactFreeText(history.PerformedBy) ?? ""
                    }
                };
            }
        }
    }

    private static IEnumerable<CustomerLicenseTimelineItem> BuildSeatEvents(List<License> licenses, TelemetryAnalyticsPeriod period)
    {
        foreach (var license in licenses)
        {
            foreach (var seat in license.Seats)
            {
                if (IsInPeriod(seat.FirstActivatedAt, period))
                {
                    yield return new CustomerLicenseTimelineItem
                    {
                        TimestampUtc = seat.FirstActivatedAt,
                        Source = "seat",
                        HardwareId = seat.HardwareId,
                        HardwareIdRedacted = RedactHardwareId(seat.HardwareId),
                        LicenseId = license.Id,
                        Action = "SeatActivated",
                        Category = "seat",
                        Result = "success",
                        ReasonCode = "SeatActivated",
                        AppVersion = seat.AppVersion,
                        ShortProperties = new Dictionary<string, string>
                        {
                            ["isActive"] = seat.IsActive.ToString().ToLowerInvariant()
                        }
                    };
                }

                if (seat.UnlinkedAt.HasValue && IsInPeriod(seat.UnlinkedAt.Value, period))
                {
                    yield return new CustomerLicenseTimelineItem
                    {
                        TimestampUtc = seat.UnlinkedAt.Value,
                        Source = "seat",
                        HardwareId = seat.HardwareId,
                        HardwareIdRedacted = RedactHardwareId(seat.HardwareId),
                        LicenseId = license.Id,
                        Action = "SeatUnlinked",
                        Category = "deactivation",
                        Severity = "warning",
                        Result = "observed",
                        ReasonCode = "SeatUnlinked"
                    };
                }
            }
        }
    }

    private static CustomerLicenseTimelineItem BuildTelemetryItem(TelemetryTimelineRow row, bool includeProperties)
    {
        var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
        return new CustomerLicenseTimelineItem
        {
            TimestampUtc = row.TimestampUtc,
            Source = "telemetry",
            HardwareId = row.HardwareId,
            HardwareIdRedacted = RedactHardwareId(row.HardwareId),
            EventName = row.EventName,
            Category = CategorizeTelemetryEvent(row.EventName),
            Severity = row.Type.Equals("Error", StringComparison.OrdinalIgnoreCase) ? "error" : "info",
            Result = ResolveTelemetryResult(row.EventName, row.Type, props),
            ReasonCode = ResolveReasonCode(row.EventName, props),
            ClientIp = row.ClientIp,
            AppVersion = row.Version,
            ShortProperties = includeProperties ? RedactPropertiesForTimeline(row.PropertiesJson) : BuildPropertyKeySummary(props),
            CorrelationId = TryGetProperty(props, "CorrelationId"),
            SessionCorrelationId = TryGetProperty(props, "SessionCorrelationId")
        };
    }

    private static CustomerLicenseTimelineItem BuildAccessLogItem(AccessLogTimelineRow row)
    {
        return new CustomerLicenseTimelineItem
        {
            TimestampUtc = row.TimestampUtc,
            Source = "access_log",
            HardwareId = string.IsNullOrWhiteSpace(row.HardwareId) ? null : row.HardwareId,
            HardwareIdRedacted = string.IsNullOrWhiteSpace(row.HardwareId) ? null : RedactHardwareId(row.HardwareId),
            Action = row.Endpoint,
            Category = row.Path.Contains("/api/updates", StringComparison.OrdinalIgnoreCase) ? "update" : "activation",
            Severity = row.IsSuccess ? "info" : "warning",
            Result = row.IsSuccess ? "success" : "failure",
            ReasonCode = NormalizeReason(row.ResultStatus) ?? NormalizeReason(row.ErrorDetails),
            ClientIp = row.ClientIp,
            ShortProperties = new Dictionary<string, string>
            {
                ["path"] = row.Path,
                ["statusCode"] = row.StatusCode.ToString(),
                ["resultStatus"] = row.ResultStatus,
                ["error"] = RedactFreeText(row.ErrorDetails) ?? ""
            }
        };
    }

    private static List<CustomerLicenseTimelineHardwareId> BuildHardwareSummaries(
        List<License> licenses,
        List<TelemetryTimelineRow> telemetryRows,
        HashSet<string> hardwareIds,
        bool includeProperties)
    {
        return hardwareIds
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .Select(hardwareId =>
            {
                var rows = telemetryRows.Where(r => string.Equals(r.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase)).ToList();
                var seats = licenses.SelectMany(l => l.Seats).Where(s => string.Equals(s.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase)).ToList();
                return new CustomerLicenseTimelineHardwareId
                {
                    HardwareId = hardwareId,
                    HardwareIdRedacted = RedactHardwareId(hardwareId),
                    TelemetryRecords = rows.Count,
                    RealActivityEvents = rows.Count(r => !IsNoiseEvent(r.EventName)),
                    SystemNoiseEvents = rows.Count(r => IsNoiseEvent(r.EventName)),
                    FirstTelemetryUtc = rows.Count == 0 ? null : rows.Min(r => r.TimestampUtc),
                    LastTelemetryUtc = rows.Count == 0 ? null : rows.Max(r => r.TimestampUtc),
                    IsCurrentActiveSeat = seats.Any(s => s.IsActive),
                    SeatFirstActivatedAtUtc = seats.Count == 0 ? null : seats.Min(s => s.FirstActivatedAt),
                    SeatLastCheckInAtUtc = seats.Count == 0 ? null : seats.Max(s => s.LastCheckInAt),
                    SeatDeactivatedAtUtc = seats.Where(s => s.UnlinkedAt.HasValue).Select(s => s.UnlinkedAt).OrderByDescending(d => d).FirstOrDefault(),
                    TopEvents = TopCounts(rows.Select(r => r.EventName), 10),
                    Versions = TopCounts(rows.Select(r => r.Version).Where(v => !string.IsNullOrWhiteSpace(v))!, 10),
                    ClientIps = TopCounts(rows.Select(r => r.ClientIp).Where(v => !string.IsNullOrWhiteSpace(v))!, 10),
                    Environment = BuildEnvironmentSummary(rows),
                    RecentSignificantEvents = rows
                        .Where(r => IsImportantEvent(r.EventName, r.Type))
                        .OrderByDescending(r => r.TimestampUtc)
                        .Take(10)
                        .Select(r => BuildTelemetryItem(r, includeProperties))
                        .ToList()
                };
            })
            .ToList();
    }

    private static CustomerLicenseTimelineSummary BuildSummary(
        CustomerLicenseTimelineResponse response,
        List<TelemetryTimelineRow> telemetryRows,
        List<AccessLogTimelineRow> accessLogs,
        List<CustomerLicenseTimelineItem> timeline)
    {
        var updateRevoke = timeline.Any(i => string.Equals(i.EventName, "Update_RevokeLicense", StringComparison.OrdinalIgnoreCase));
        var serverUnlink = timeline.Any(i => string.Equals(i.Source, "seat", StringComparison.OrdinalIgnoreCase)
            && string.Equals(i.ReasonCode, "SeatUnlinked", StringComparison.OrdinalIgnoreCase));
        var deactivation = timeline.Any(i => (i.EventName ?? i.Action ?? "").StartsWith("LicenseDeactivation_", StringComparison.OrdinalIgnoreCase));

        var verdicts = new List<string>();
        if (response.HardwareIds.Count <= 1)
            verdicts.Add("single_machine");
        if (response.HardwareIds.Count > 1)
            verdicts.Add("multiple_hardware_ids");
        if (response.Licenses.Any(l => l.MaxSeats > 0 && response.HardwareIds.Count > l.MaxSeats))
            verdicts.Add("seat_limit_conflict");
        if (updateRevoke)
            verdicts.Add("update_revoke_license_seen");
        if (deactivation)
            verdicts.Add("license_deactivation_seen");
        verdicts.Add(serverUnlink ? "server_seat_unlink_trace_found" : "no_server_seat_unlink_trace_found");

        return new CustomerLicenseTimelineSummary
        {
            CandidateCount = response.Candidates.Count,
            IsAmbiguous = response.Candidates.Select(c => c.LicenseId).Distinct().Count() > 1,
            LicenseCount = response.Licenses.Count,
            HardwareIdCount = response.HardwareIds.Count,
            ActiveSeatCount = response.Licenses.Sum(l => l.ActiveSeats),
            TelemetryRecords = telemetryRows.Count,
            AccessLogRecords = accessLogs.Count,
            LicenseEvents = timeline.Count(i => i.Source == "license"),
            SeatEvents = timeline.Count(i => i.Source == "seat"),
            RealActivityEvents = telemetryRows.Count(r => !IsNoiseEvent(r.EventName)),
            SystemNoiseEvents = telemetryRows.Count(r => IsNoiseEvent(r.EventName)),
            DiagnosticEvents = telemetryRows.Count(r => r.Type.Equals("Diagnostic", StringComparison.OrdinalIgnoreCase)),
            ErrorEvents = telemetryRows.Count(r => r.Type.Equals("Error", StringComparison.OrdinalIgnoreCase)),
            FirstEventUtc = timeline.Count == 0 ? null : timeline.Min(i => i.TimestampUtc),
            LastEventUtc = timeline.Count == 0 ? null : timeline.Max(i => i.TimestampUtc),
            UpdateRevokeLicenseSeen = updateRevoke,
            ServerSeatUnlinkTraceSeen = serverUnlink,
            LicenseDeactivationTraceSeen = deactivation,
            ServerDeactivationVerdict = serverUnlink ? "server_seat_unlink_trace_found" : "no_server_seat_unlink_trace_found",
            VerdictCodes = verdicts,
            Notes = new List<string>
            {
                "Update_RevokeLicense proves a local desktop clear/revocation decision from update-check; it is not proof that a server seat was unlinked.",
                serverUnlink
                    ? "At least one server-side seat unlink trace was found."
                    : "No server-side seat unlink trace was found in the selected period."
            }
        };
    }

    private static List<CustomerLicenseTimelineCandidate> BuildCandidates(List<License> licenses, TimelineCriteria criteria)
    {
        return licenses.Select(l => new CustomerLicenseTimelineCandidate
        {
            LicenseId = l.Id,
            MatchType = BuildMatchType(l, criteria),
            ProductName = l.Product?.Name,
            CustomerName = string.IsNullOrWhiteSpace(l.CustomerName) ? null : l.CustomerName,
            CustomerEmail = NormalizeEmail(l.CustomerEmail),
            CustomerEmailRedacted = RedactEmail(l.CustomerEmail),
            LicenseKeyRedacted = RedactLicenseKey(l.LicenseKey),
            LicenseKeyFirstSegment = GetLicenseKeyFirstSegment(l.LicenseKey),
            LicenseStatus = GetLicenseStatus(l),
            HardwareId = l.Seats.FirstOrDefault(s => s.IsActive)?.HardwareId ?? l.HardwareId
        }).ToList();
    }

    private static CustomerLicenseTimelineLicense BuildLicenseSummary(License license)
    {
        var hardwareIds = ResolveHardwareIds(new List<License> { license }, new TimelineCriteria(null, null, null, null, null)).ToList();
        return new CustomerLicenseTimelineLicense
        {
            LicenseId = license.Id,
            ProductId = license.ProductId,
            ProductName = license.Product?.Name,
            CustomerName = string.IsNullOrWhiteSpace(license.CustomerName) ? null : license.CustomerName,
            CustomerEmail = NormalizeEmail(license.CustomerEmail),
            CustomerEmailRedacted = RedactEmail(license.CustomerEmail),
            LicenseKeyRedacted = RedactLicenseKey(license.LicenseKey),
            LicenseKeyFirstSegment = GetLicenseKeyFirstSegment(license.LicenseKey),
            LicenseStatus = GetLicenseStatus(license),
            LicenseTypeSlug = license.Type?.Slug,
            LicenseTypeName = license.Type?.Name,
            LicenseEdition = license.Type?.Slug,
            CreationDateUtc = license.CreationDate,
            ActivationDateUtc = license.ActivationDate,
            ExpirationDateUtc = license.ExpirationDate,
            RevokedAtUtc = license.RevokedAt,
            MaxSeats = license.MaxSeats,
            ActiveSeats = license.Seats.Count(s => s.IsActive),
            TotalSeats = license.Seats.Count,
            HardwareIds = hardwareIds
        };
    }

    private static TimelineCriteria NormalizeCriteria(string? email, string? emailFragment, string? hardwareId, string? licenseId, string? licenseFragment)
    {
        Guid? parsedLicenseId = null;
        var normalizedLicenseId = NormalizeNullable(licenseId);
        if (normalizedLicenseId != null && Guid.TryParse(normalizedLicenseId, out var id))
            parsedLicenseId = id;

        return new TimelineCriteria(
            NormalizeNullable(email)?.ToLowerInvariant(),
            NormalizeNullable(emailFragment)?.ToLowerInvariant(),
            NormalizeHardwareIdLookup(hardwareId),
            parsedLicenseId,
            NormalizeNullable(licenseFragment)?.ToUpperInvariant());
    }

    private static void ValidateCriteria(TimelineCriteria criteria)
    {
        if (criteria.Email == null && criteria.EmailFragment == null && criteria.HardwareId == null && !criteria.LicenseId.HasValue && criteria.LicenseFragment == null)
            throw new ArgumentException("At least one query parameter is required: email, emailFragment, hardwareId, licenseId, or licenseFragment.");
        if (criteria.EmailFragment != null && criteria.EmailFragment.Length < MinEmailFragmentLength)
            throw new ArgumentException($"emailFragment must contain at least {MinEmailFragmentLength} characters.");
        if (criteria.HardwareIdIsFragment && criteria.HardwareId!.Length < MinHardwareFragmentLength)
            throw new ArgumentException($"hardwareId fragments must contain at least {MinHardwareFragmentLength} characters.");
        if (criteria.LicenseFragment != null && CompactKey(criteria.LicenseFragment).Length < MinLicenseFragmentLength)
            throw new ArgumentException($"licenseFragment must contain at least {MinLicenseFragmentLength} non-separator characters.");
    }

    private static string NormalizeMode(string? mode)
    {
        var normalized = NormalizeNullable(mode)?.ToLowerInvariant();
        return normalized is "summary" or "timeline" or "full" ? normalized : "timeline";
    }

    private static bool IsImportantEvent(string eventName, string type)
    {
        return ImportantEvents.Contains(eventName)
            || type.Equals("Error", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Activation", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("License", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Revoke", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("CertPinning", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Security", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Update", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNoiseEvent(string eventName)
    {
        return eventName.Contains("Heartbeat", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Tick", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("Mouse", StringComparison.OrdinalIgnoreCase)
            || eventName.Contains("WindowFocus", StringComparison.OrdinalIgnoreCase);
    }

    private static string CategorizeTelemetryEvent(string eventName)
    {
        if (eventName.Contains("Activation", StringComparison.OrdinalIgnoreCase))
            return "activation";
        if (eventName.Contains("Deactivation", StringComparison.OrdinalIgnoreCase) || eventName.Contains("ClearLicense", StringComparison.OrdinalIgnoreCase))
            return "deactivation";
        if (eventName.Contains("Update", StringComparison.OrdinalIgnoreCase))
            return eventName.Contains("Revoke", StringComparison.OrdinalIgnoreCase) ? "revoke" : "update";
        if (eventName.Contains("CertPinning", StringComparison.OrdinalIgnoreCase) || eventName.Contains("Tls", StringComparison.OrdinalIgnoreCase))
            return "tls";
        if (eventName.Contains("Security", StringComparison.OrdinalIgnoreCase) || eventName.Contains("Ban", StringComparison.OrdinalIgnoreCase))
            return "security";
        return IsNoiseEvent(eventName) ? "noise" : "usage";
    }

    private static string CategorizeAction(string action)
    {
        if (action.Contains("REVOK", StringComparison.OrdinalIgnoreCase))
            return "revoke";
        if (action.Contains("UNLINK", StringComparison.OrdinalIgnoreCase) || action.Contains("DEACT", StringComparison.OrdinalIgnoreCase))
            return "deactivation";
        return "license";
    }

    private static string ResolveTelemetryResult(string eventName, string type, Dictionary<string, string> props)
    {
        if (type.Equals("Error", StringComparison.OrdinalIgnoreCase))
            return "failure";
        if (eventName.Contains("Success", StringComparison.OrdinalIgnoreCase))
            return "success";
        if (eventName.Contains("Fail", StringComparison.OrdinalIgnoreCase) || eventName.Contains("Error", StringComparison.OrdinalIgnoreCase))
            return "failure";
        if (props.TryGetValue("Success", out var success))
            return success.Equals("true", StringComparison.OrdinalIgnoreCase) ? "success" : "failure";
        return "observed";
    }

    private static string? ResolveReasonCode(string eventName, Dictionary<string, string> props)
    {
        if (eventName.Equals("Update_RevokeLicense", StringComparison.OrdinalIgnoreCase))
            return "UpdateRevokeLicense";

        foreach (var key in new[] { "ReasonCode", "RevokeCause", "Reason", "Status", "ErrorCode", "FailureReason", "ServerStatus" })
        {
            if (props.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                return NormalizeReason(value);
        }

        if (eventName.Contains("MaxActivations", StringComparison.OrdinalIgnoreCase))
            return "MaxActivationsReached";
        return null;
    }

    private static List<TelemetryToolCount> TopCounts(IEnumerable<string?> values, int top)
    {
        return values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .GroupBy(v => v!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .Select(g => new TelemetryToolCount { Name = g.Key, Count = g.Count() })
            .ToList();
    }

    private static List<TelemetryToolCount> BuildEnvironmentSummary(List<TelemetryTimelineRow> rows)
    {
        var values = new List<string>();
        foreach (var row in rows)
        {
            var props = TelemetrySchemaRegistry.ParseProperties(row.PropertiesJson);
            foreach (var key in new[] { "OS", "OsVersion", "Culture", "RuntimeMode", "UiMode", "RequestSource" })
            {
                if (props.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                    values.Add($"{key}:{value}");
            }
        }

        return TopCounts(values, 12);
    }

    private static Dictionary<string, string> BuildPropertyKeySummary(Dictionary<string, string> props)
    {
        var keys = props.Keys
            .Where(k => !SensitivePropertyKeys.Contains(k))
            .Where(k => !k.Contains("Path", StringComparison.OrdinalIgnoreCase))
            .OrderBy(k => k, StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .ToList();

        return keys.Count == 0
            ? new Dictionary<string, string>()
            : new Dictionary<string, string> { ["propertyKeys"] = string.Join(",", keys) };
    }

    private static bool IsInPeriod(DateTime timestampUtc, TelemetryAnalyticsPeriod period)
    {
        return timestampUtc >= period.FromUtc && timestampUtc <= period.ToUtc;
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

        var compact = new string(normalized.Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '_' && c != ':').ToArray());
        return compact.Length >= MinHardwareFragmentLength && compact.All(Uri.IsHexDigit)
            ? compact.ToUpperInvariant()
            : normalized.ToUpperInvariant();
    }

    private static string CompactKey(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? ""
            : value.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
    }

    private static string? RedactEmail(string? email)
    {
        email = NormalizeEmail(email);
        if (email == null)
            return null;
        var parts = email.Split('@', 2);
        if (parts.Length != 2)
            return "***";
        var visible = parts[0].Length <= 2 ? parts[0][..1] : parts[0][..Math.Min(2, parts[0].Length)];
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

    private static string RedactHardwareId(string hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "";
        return hardwareId.Length <= 8 ? hardwareId : $"{hardwareId[..8]}...";
    }

    private static string? GetLicenseKeyFirstSegment(string? licenseKey)
    {
        var trimmed = NormalizeNullable(licenseKey);
        if (trimmed == null)
            return null;
        var firstSeparator = trimmed.IndexOf('-', StringComparison.Ordinal);
        var firstSegment = firstSeparator >= 0 ? trimmed[..firstSeparator] : trimmed;
        return string.IsNullOrWhiteSpace(firstSegment) ? null : firstSegment.Trim();
    }

    private static string GetLicenseStatus(License license)
    {
        if (!license.IsActive || license.RevokedAt != null)
            return "revoked";
        if (license.ExpirationDate != null && license.ExpirationDate < DateTime.UtcNow)
            return "expired";
        return license.ActivationDate == null ? "not_activated" : "active";
    }

    private static string? NormalizeReason(string? value)
    {
        var normalized = NormalizeNullable(value);
        if (normalized == null)
            return null;
        if (normalized.Contains("ActivationLimit", StringComparison.OrdinalIgnoreCase))
            return "ActivationLimit";
        if (normalized.Contains("MaxActivations", StringComparison.OrdinalIgnoreCase) || normalized.Contains("max activations", StringComparison.OrdinalIgnoreCase))
            return "MaxActivationsReached";
        if (normalized.Contains("Update_RevokeLicense", StringComparison.OrdinalIgnoreCase))
            return "UpdateRevokeLicense";
        if (normalized.Contains("unlinked", StringComparison.OrdinalIgnoreCase))
            return "SeatUnlinked";
        return normalized.Length > 80 ? normalized[..80] : normalized;
    }

    private static string? RedactFreeText(string? value)
    {
        var normalized = NormalizeNullable(value);
        if (normalized == null)
            return null;
        return normalized.Length > 160 ? normalized[..160] : normalized;
    }

    private static string? TryGetProperty(Dictionary<string, string> props, string key)
    {
        return props.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
    }

    private static string BuildMatchType(License license, TimelineCriteria criteria)
    {
        var matches = new List<string>();
        if (criteria.LicenseId == license.Id)
            matches.Add("license_id");
        if (criteria.Email != null && license.CustomerEmail.Contains(criteria.Email, StringComparison.OrdinalIgnoreCase))
            matches.Add("email");
        if (criteria.EmailFragment != null && license.CustomerEmail.Contains(criteria.EmailFragment, StringComparison.OrdinalIgnoreCase))
            matches.Add("email_fragment");
        if (criteria.HardwareId != null && ResolveHardwareIds(new List<License> { license }, criteria).Any(h => h.Contains(criteria.HardwareId, StringComparison.OrdinalIgnoreCase)))
            matches.Add(criteria.HardwareIdIsFragment ? "hardware_fragment" : "hardware");
        if (criteria.LicenseFragment != null && CompactKey(license.LicenseKey).Contains(CompactKey(criteria.LicenseFragment), StringComparison.OrdinalIgnoreCase))
            matches.Add("license_fragment");
        return matches.Count == 0 ? "license" : string.Join("+", matches);
    }

    private sealed record TimelineCriteria(
        string? Email,
        string? EmailFragment,
        string? HardwareId,
        Guid? LicenseId,
        string? LicenseFragment)
    {
        public bool HardwareIdIsFragment => HardwareId is { Length: >= MinHardwareFragmentLength };
    }

    private sealed record TelemetryTimelineRow(
        DateTime TimestampUtc,
        string HardwareId,
        string? ClientIp,
        string AppName,
        string? Version,
        string EventName,
        string Type,
        string? PropertiesJson,
        string? ErrorType,
        int? DiagnosticScore);

    private sealed record AccessLogTimelineRow(
        DateTime TimestampUtc,
        string HardwareId,
        string ClientIp,
        string Path,
        string Endpoint,
        int StatusCode,
        string ResultStatus,
        string? ErrorDetails,
        bool IsSuccess);
}
