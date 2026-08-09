using System.Net;
using System.Net.Http.Json;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SoftLicence.Mcp;

public sealed class SoftLicenceAnalyticsClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private const int MaxTimelineRangeDays = 90;
    private const int MaxTimelineSegmentDays = 30;

    private readonly HttpClient _httpClient;
    private readonly SoftLicenceMcpOptions _options;
    private readonly McpResultStore _resultStore;

    public SoftLicenceAnalyticsClient(
        HttpClient httpClient,
        IOptions<SoftLicenceMcpOptions> options,
        McpResultStore? resultStore = null)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _resultStore = resultStore ?? new McpResultStore(options);
    }

    public async Task<JsonElement> GetCurrentProductAsync(CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("products/current", new Dictionary<string, string?>(), cancellationToken);
    }

    public async Task<JsonElement> ListProductsAsync(CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("products", new Dictionary<string, string?>(), cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryOverviewAsync(
        int days,
        int top,
        string? date,
        string? fromUtc,
        string? toUtc,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/overview", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryDevicesAsync(
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        int take,
        int topEvents,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/devices", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["take"] = take.ToString(),
            ["topEvents"] = topEvents.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetrySchemaSummaryAsync(
        int days,
        int topEvents,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/schema-summary", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["topEvents"] = topEvents.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryToolUsageAsync(
        int days,
        int top,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/tool-usage", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryQuotaSummaryAsync(
        int days,
        int top,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/quota-summary", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryStartupHealthAsync(
        int days,
        int top,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/startup-health", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryCertPinningSummaryAsync(
        int days,
        int top,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/cert-pinning-summary", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryActivationFunnelAsync(
        int days,
        int top,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/activation-funnel", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetActivationFailuresAsync(
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        string? hardwareId,
        string? status,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/activation-failures", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["hardwareId"] = hardwareId,
            ["status"] = status,
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryMachineProfileAsync(
        string hardwareId,
        int days,
        int top,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/machine-profile", new Dictionary<string, string?>
        {
            ["hardwareId"] = hardwareId,
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryVersionHealthAsync(
        int days,
        int top,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/version-health", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetSupportTelemetryProfileAsync(
        string? hardwareId,
        string? email,
        string? emailFragment,
        string? licenseFragment,
        string? clientIp,
        int days,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null,
        bool protectOversized = true)
    {
        return await GetAnalyticsAsync("support/profile", new Dictionary<string, string?>
        {
            ["hardwareId"] = hardwareId,
            ["email"] = email,
            ["emailFragment"] = emailFragment,
            ["licenseFragment"] = licenseFragment,
            ["clientIp"] = clientIp,
            ["days"] = days.ToString(),
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken, protectOversized);
    }

    public async Task<JsonElement> GetCustomerLicenseTimelineAsync(
        string? email,
        string? emailFragment,
        string? hardwareId,
        string? licenseId,
        string? licenseFragment,
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        int takeTimeline,
        int offset,
        bool includeAccessLogs,
        bool includeNoise,
        bool importantOnly,
        bool includeProperties,
        string? mode,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        if (string.IsNullOrWhiteSpace(date)
            && string.IsNullOrWhiteSpace(fromUtc)
            && string.IsNullOrWhiteSpace(toUtc)
            && days > MaxTimelineSegmentDays)
        {
            if (days > MaxTimelineRangeDays)
                return BuildTimelineRangeTooLargeError(days);

            var rollingTo = DateTimeOffset.UtcNow;
            var rollingFrom = rollingTo.AddDays(-days);
            fromUtc = rollingFrom.ToString("O", CultureInfo.InvariantCulture);
            toUtc = rollingTo.ToString("O", CultureInfo.InvariantCulture);
        }

        if (TryParseUtcRange(fromUtc, toUtc, out var rangeFrom, out var rangeTo)
            && rangeTo > rangeFrom)
        {
            var rangeDays = (rangeTo - rangeFrom).TotalDays;
            if (rangeDays > MaxTimelineRangeDays)
                return BuildTimelineRangeTooLargeError(rangeDays);

            if (rangeDays > MaxTimelineSegmentDays)
            {
                return await GetSegmentedCustomerLicenseTimelineAsync(
                    email, emailFragment, hardwareId, licenseId, licenseFragment,
                    rangeFrom, rangeTo, takeTimeline, offset, includeAccessLogs,
                    includeNoise, importantOnly, includeProperties, mode,
                    cancellationToken, productId, productName);
            }
        }

        return await GetCustomerLicenseTimelineSegmentAsync(
            email, emailFragment, hardwareId, licenseId, licenseFragment,
            days, date, fromUtc, toUtc, takeTimeline, offset, includeAccessLogs,
            includeNoise, importantOnly, includeProperties, mode,
            cancellationToken, productId, productName, protectOversized: true);
    }

    private async Task<JsonElement> GetSegmentedCustomerLicenseTimelineAsync(
        string? email,
        string? emailFragment,
        string? hardwareId,
        string? licenseId,
        string? licenseFragment,
        DateTimeOffset rangeFrom,
        DateTimeOffset rangeTo,
        int takeTimeline,
        int offset,
        bool includeAccessLogs,
        bool includeNoise,
        bool importantOnly,
        bool includeProperties,
        string? mode,
        CancellationToken cancellationToken,
        string? productId,
        string? productName)
    {
        var segments = new List<TimelineSegmentResult>();
        var segmentFrom = rangeFrom;

        while (segmentFrom < rangeTo)
        {
            var nextSegmentFrom = segmentFrom.AddDays(MaxTimelineSegmentDays);
            var segmentTo = nextSegmentFrom < rangeTo
                ? nextSegmentFrom.AddTicks(-1)
                : rangeTo;

            var segmentFromText = segmentFrom.ToString("O", CultureInfo.InvariantCulture);
            var segmentToText = segmentTo.ToString("O", CultureInfo.InvariantCulture);
            var result = await GetCustomerLicenseTimelineSegmentAsync(
                email, emailFragment, hardwareId, licenseId, licenseFragment,
                MaxTimelineSegmentDays, date: null, segmentFromText, segmentToText,
                takeTimeline, offset, includeAccessLogs, includeNoise, importantOnly,
                includeProperties, mode, cancellationToken, productId, productName, protectOversized: false);

            if (IsFailedResult(result))
                return result;

            segments.Add(new TimelineSegmentResult(
                segments.Count + 1,
                segmentFromText,
                segmentToText,
                result));
            segmentFrom = segmentTo.AddTicks(1);
        }

        var combined = JsonSerializer.SerializeToElement(new
        {
            ok = true,
            segmented = true,
            maxRangeDays = MaxTimelineRangeDays,
            maxSegmentDays = MaxTimelineSegmentDays,
            requestedFromUtc = rangeFrom,
            requestedToUtc = rangeTo,
            segmentCount = segments.Count,
            segments
        }, JsonOptions);

        return await _resultStore.DeliverAsync(combined, cancellationToken);
    }

    private async Task<JsonElement> GetCustomerLicenseTimelineSegmentAsync(
        string? email,
        string? emailFragment,
        string? hardwareId,
        string? licenseId,
        string? licenseFragment,
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        int takeTimeline,
        int offset,
        bool includeAccessLogs,
        bool includeNoise,
        bool importantOnly,
        bool includeProperties,
        string? mode,
        CancellationToken cancellationToken,
        string? productId,
        string? productName,
        bool protectOversized)
    {
        return await GetAnalyticsAsync("support/customer-license-timeline", new Dictionary<string, string?>
        {
            ["email"] = email,
            ["emailFragment"] = emailFragment,
            ["hardwareId"] = hardwareId,
            ["licenseId"] = licenseId,
            ["licenseFragment"] = licenseFragment,
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["takeTimeline"] = takeTimeline.ToString(),
            ["offset"] = offset.ToString(),
            ["includeAccessLogs"] = includeAccessLogs.ToString().ToLowerInvariant(),
            ["includeNoise"] = includeNoise.ToString().ToLowerInvariant(),
            ["importantOnly"] = importantOnly.ToString().ToLowerInvariant(),
            ["includeProperties"] = includeProperties.ToString().ToLowerInvariant(),
            ["mode"] = mode,
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken, protectOversized);
    }

    private static bool TryParseUtcRange(
        string? fromUtc,
        string? toUtc,
        out DateTimeOffset rangeFrom,
        out DateTimeOffset rangeTo)
    {
        const DateTimeStyles styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
        var hasFrom = DateTimeOffset.TryParse(fromUtc, CultureInfo.InvariantCulture, styles, out rangeFrom);
        var hasTo = DateTimeOffset.TryParse(toUtc, CultureInfo.InvariantCulture, styles, out rangeTo);
        return hasFrom && hasTo;
    }

    private static JsonElement BuildTimelineRangeTooLargeError(double requestedDays)
    {
        return JsonSerializer.SerializeToElement(new
        {
            ok = false,
            errorCode = "TIMELINE_RANGE_TOO_LARGE",
            message = $"Customer license timeline ranges are limited to {MaxTimelineRangeDays} days per MCP call.",
            hint = "Split investigations longer than 90 days into consecutive MCP calls.",
            maxDays = MaxTimelineRangeDays,
            requestedDays = Math.Ceiling(requestedDays)
        }, JsonOptions);
    }

    private static bool IsFailedResult(JsonElement result)
    {
        return result.ValueKind == JsonValueKind.Object
            && result.TryGetProperty("ok", out var ok)
            && ok.ValueKind == JsonValueKind.False;
    }

    public async Task<JsonElement> GetTelemetryRawSampleAsync(
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        string? hardwareId,
        string? eventName,
        string? eventFamily,
        string? version,
        string? type,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/raw-sample", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["hardwareId"] = hardwareId,
            ["eventName"] = eventName,
            ["eventFamily"] = eventFamily,
            ["version"] = version,
            ["type"] = type,
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryFloodSuppressionsAsync(
        int days,
        string? hardwareId,
        string? eventName,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/flood-suppressions", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["hardwareId"] = hardwareId,
            ["eventName"] = eventName,
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryInsightsAsync(
        int days,
        int top,
        string? date,
        string? fromUtc,
        string? toUtc,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("telemetry/insights", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetLicenseDurationMigrationImpactAsync(
        string? licenseType,
        int currentDurationDays,
        int targetDurationDays,
        string? activityWindowsDays,
        bool includeSamples,
        int sampleLimit,
        int topEvents,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/duration-migration-impact", new Dictionary<string, string?>
        {
            ["licenseType"] = licenseType,
            ["currentDurationDays"] = currentDurationDays.ToString(),
            ["targetDurationDays"] = targetDurationDays.ToString(),
            ["activityWindowsDays"] = activityWindowsDays,
            ["includeSamples"] = includeSamples.ToString().ToLowerInvariant(),
            ["sampleLimit"] = sampleLimit.ToString(),
            ["topEvents"] = topEvents.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetFreemiumActivityRankingAsync(
        string? licenseType,
        string? status,
        int telemetryDays,
        int? activationAgeMinDays,
        int? activationAgeMaxDays,
        bool includeSamples,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/freemium-activity-ranking", new Dictionary<string, string?>
        {
            ["licenseType"] = licenseType,
            ["status"] = status,
            ["telemetryDays"] = telemetryDays.ToString(),
            ["activationAgeMinDays"] = activationAgeMinDays?.ToString(),
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString(),
            ["includeSamples"] = includeSamples.ToString().ToLowerInvariant(),
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetPaidActivityRankingAsync(
        string? licenseTypes,
        string? status,
        int telemetryDays,
        int? activationAgeMinDays,
        int? activationAgeMaxDays,
        bool includeSamples,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/paid-activity-ranking", new Dictionary<string, string?>
        {
            ["licenseTypes"] = licenseTypes,
            ["status"] = status,
            ["telemetryDays"] = telemetryDays.ToString(),
            ["activationAgeMinDays"] = activationAgeMinDays?.ToString(),
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString(),
            ["includeSamples"] = includeSamples.ToString().ToLowerInvariant(),
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetLicenseTypesAsync(
        bool includeFree,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/types", new Dictionary<string, string?>
        {
            ["includeFree"] = includeFree.ToString().ToLowerInvariant(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetRecentLicenseOnboardingMetricsAsync(
        int take,
        string? licenseType,
        string? status,
        int? activationAgeMaxDays,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/recent-onboarding-metrics", new Dictionary<string, string?>
        {
            ["take"] = take.ToString(),
            ["licenseType"] = licenseType,
            ["status"] = status,
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetLicenseUsageScoresAsync(
        int take,
        string? licenseType,
        string? status,
        int? activationAgeMaxDays,
        int activityWindowDays,
        double? minScore,
        bool includeInactive,
        string? sortBy,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/usage-scoring", new Dictionary<string, string?>
        {
            ["take"] = take.ToString(),
            ["licenseType"] = licenseType,
            ["status"] = status,
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString(),
            ["activityWindowDays"] = activityWindowDays.ToString(),
            ["minScore"] = minScore?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["includeInactive"] = includeInactive.ToString().ToLowerInvariant(),
            ["sortBy"] = sortBy,
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryLicenseHardwareAuditAsync(
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        string? activityWindowsDays,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/telemetry-hwid-audit", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["activityWindowsDays"] = activityWindowsDays,
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetFreemiumAbuseRiskAsync(
        string? licenseType,
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync("licenses/freemium-abuse-risk", new Dictionary<string, string?>
        {
            ["licenseType"] = licenseType,
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> ListSecurityBansAsync(
        string? hardwareId,
        string? componentHash,
        string? componentType,
        string? clientIp,
        string? emailFragment,
        string? licenseFragment,
        bool includeInactive,
        int take,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null,
        bool includeSourceEvents = false,
        bool protectOversized = true)
    {
        return await GetAnalyticsAsync("security/bans", new Dictionary<string, string?>
        {
            ["hardwareId"] = hardwareId,
            ["componentHash"] = componentHash,
            ["componentType"] = componentType,
            ["clientIp"] = clientIp,
            ["emailFragment"] = emailFragment,
            ["licenseFragment"] = licenseFragment,
            ["includeInactive"] = includeInactive.ToString().ToLowerInvariant(),
            ["includeSourceEvents"] = includeSourceEvents ? "true" : null,
            ["take"] = take.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken, protectOversized);
    }

    public async Task<JsonElement> ListSecurityCanaryAlertsAsync(
        string? fromUtc,
        string? toUtc,
        string? trigger,
        int? severity,
        string? hardwareId,
        string? machine,
        string? user,
        string? clientIp,
        string? version,
        bool? isBanned,
        int take,
        int offset,
        string? productId,
        string? productName,
        CancellationToken cancellationToken,
        bool protectOversized = true)
    {
        return await GetAnalyticsAsync("security/canary-alerts", new Dictionary<string, string?>
        {
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["trigger"] = trigger,
            ["severity"] = severity?.ToString(),
            ["hardwareId"] = hardwareId,
            ["machine"] = machine,
            ["user"] = user,
            ["clientIp"] = clientIp,
            ["version"] = version,
            ["isBanned"] = isBanned?.ToString().ToLowerInvariant(),
            ["take"] = take.ToString(),
            ["offset"] = offset.ToString(),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken, protectOversized);
    }

    public async Task<JsonElement> GetSecurityCanaryAlertDetailsAsync(
        Guid alertId,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync($"security/canary-alerts/{alertId:D}", new Dictionary<string, string?>
        {
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public async Task<JsonElement> GetSecurityCaseSnapshotAsync(
        string? ticketRef,
        string? securityCaseId,
        string? hardwareId,
        string? componentHash,
        string? componentType,
        string? clientIp,
        string? emailFragment,
        string? licenseFragment,
        bool includeInactive,
        int take,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        var bans = await ListSecurityBansAsync(
            hardwareId, componentHash, componentType, clientIp, emailFragment, licenseFragment,
            includeInactive, take, cancellationToken, productId, productName,
            includeSourceEvents: false, protectOversized: false);
        var referenceOnly = string.IsNullOrWhiteSpace(hardwareId)
            && string.IsNullOrWhiteSpace(componentHash)
            && string.IsNullOrWhiteSpace(clientIp)
            && string.IsNullOrWhiteSpace(emailFragment)
            && string.IsNullOrWhiteSpace(licenseFragment)
            && (!string.IsNullOrWhiteSpace(ticketRef) || !string.IsNullOrWhiteSpace(securityCaseId));
        var referenceMatchedBans = new List<JsonElement>();
        if (referenceOnly && bans.TryGetProperty("bans", out var referenceRows) && referenceRows.ValueKind == JsonValueKind.Array)
        {
            foreach (var ban in referenceRows.EnumerateArray())
            {
                var reason = ban.TryGetProperty("reason", out var reasonElement) ? reasonElement.GetString() ?? "" : "";
                var matches = (!string.IsNullOrWhiteSpace(ticketRef) && HasAuditMetadata(reason, "ticket", ticketRef))
                    || (!string.IsNullOrWhiteSpace(securityCaseId) && HasAuditMetadata(reason, "securityCase", securityCaseId));
                if (matches) referenceMatchedBans.Add(ban.Clone());
            }
        }
        var effectiveBans = referenceOnly
            ? JsonSerializer.SerializeToElement(new { recordsMatched = referenceMatchedBans.Count, recordsReturned = referenceMatchedBans.Count, bans = referenceMatchedBans }, JsonOptions)
            : bans;
        var resolvedHwids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (bans.TryGetProperty("resolvedHardwareIds", out var resolvedElement)
            && resolvedElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in resolvedElement.EnumerateArray())
                if (!string.IsNullOrWhiteSpace(item.GetString())) resolvedHwids.Add(item.GetString()!);
        }
        if (resolvedHwids.Count == 0 && !string.IsNullOrWhiteSpace(hardwareId))
            resolvedHwids.Add(hardwareId);
        if (referenceOnly)
        {
            foreach (var ban in referenceMatchedBans)
            {
                var targetHwid = ban.TryGetProperty("hardwareId", out var target) ? target.GetString() : null;
                if (!string.IsNullOrWhiteSpace(targetHwid)) resolvedHwids.Add(targetHwid);
                var hash = ban.TryGetProperty("componentHash", out var hashElement) ? hashElement.GetString() : null;
                var type = ban.TryGetProperty("componentType", out var typeElement) ? typeElement.GetString() : null;
                if (string.IsNullOrWhiteSpace(hash)) continue;
                var related = await ListSecurityBansAsync(null, hash, type, null, null, null, includeInactive, take,
                    cancellationToken, productId, productName,
                    includeSourceEvents: false, protectOversized: false);
                if (related.TryGetProperty("resolvedHardwareIds", out var relatedHwids) && relatedHwids.ValueKind == JsonValueKind.Array)
                    foreach (var item in relatedHwids.EnumerateArray())
                        if (!string.IsNullOrWhiteSpace(item.GetString())) resolvedHwids.Add(item.GetString()!);
            }
        }

        var canaryByMachine = new List<object>();
        var profilesByMachine = new List<object>();
        var nodes = new List<Dictionary<string, object?>>();
        var edges = new List<Dictionary<string, object?>>();
        var nodeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddNode(string id, string type, object? value)
        {
            if (nodeIds.Add(id)) nodes.Add(new() { ["id"] = id, ["type"] = type, ["value"] = value });
        }
        void AddEdge(string from, string to, string relation, string confidence, string evidence) =>
            edges.Add(new() { ["from"] = from, ["to"] = to, ["relation"] = relation, ["confidence"] = confidence, ["evidence"] = evidence });

        foreach (var hwid in resolvedHwids.Take(10))
        {
            var machineNode = $"machine:{hwid}";
            AddNode(machineNode, "machine", hwid);
            var canary = await ListSecurityCanaryAlertsAsync(
                null, null, null, null, hwid, null, null, null, null, null,
                take, 0, productId, productName, cancellationToken, protectOversized: false);
            canaryByMachine.Add(new { hardwareId = hwid, result = canary });
            if (canary.TryGetProperty("alerts", out var alerts) && alerts.ValueKind == JsonValueKind.Array)
            {
                foreach (var alert in alerts.EnumerateArray())
                {
                    var alertId = alert.TryGetProperty("alertId", out var id) ? id.GetString() : null;
                    if (alertId == null) continue;
                    AddNode($"canary:{alertId}", "canary_alert", alertId);
                    AddEdge(machineNode, $"canary:{alertId}", "raised_canary_alert", "exact", "same hardwareId");
                }
            }

            var profile = await GetSupportTelemetryProfileAsync(
                hwid, null, null, null, null, 30, Math.Min(take, 50), cancellationToken, productId, productName,
                protectOversized: false);
            profilesByMachine.Add(new { hardwareId = hwid, result = profile });
            if (profile.TryGetProperty("candidates", out var candidates) && candidates.ValueKind == JsonValueKind.Array)
            {
                foreach (var candidate in candidates.EnumerateArray())
                {
                    var licenseId = candidate.TryGetProperty("licenseId", out var license) ? license.GetString() : null;
                    var email = candidate.TryGetProperty("customerEmail", out var account) ? account.GetString() : null;
                    if (licenseId != null)
                    {
                        AddNode($"license:{licenseId}", "license", licenseId);
                        AddEdge(machineNode, $"license:{licenseId}", "bound_to_license", "exact", "active or historical seat binding");
                    }
                    if (email != null)
                    {
                        AddNode($"account:{email.ToLowerInvariant()}", "account", email);
                        if (licenseId != null) AddEdge($"license:{licenseId}", $"account:{email.ToLowerInvariant()}", "owned_by", "exact", "license customer email");
                    }
                    if (candidate.TryGetProperty("clientIps", out var ips) && ips.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var ipRow in ips.EnumerateArray())
                        {
                            var ip = ipRow.TryGetProperty("name", out var ipName) ? ipName.GetString() : null;
                            if (ip == null) continue;
                            AddNode($"ip:{ip}", "ip", ip);
                            AddEdge(machineNode, $"ip:{ip}", "observed_from_ip", "exact", "telemetry record");
                        }
                    }
                }
            }
        }

        var ticketRefs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var securityCaseRefs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(ticketRef)) ticketRefs.Add(ticketRef);
        if (!string.IsNullOrWhiteSpace(securityCaseId)) securityCaseRefs.Add(securityCaseId);
        if (effectiveBans.TryGetProperty("bans", out var banRows) && banRows.ValueKind == JsonValueKind.Array)
        {
            foreach (var ban in banRows.EnumerateArray())
            {
                var banId = ban.TryGetProperty("banId", out var id) ? id.GetString() : null;
                if (banId == null) continue;
                var banNode = $"ban:{banId}";
                AddNode(banNode, "ban", banId);
                var targetHwid = ban.TryGetProperty("hardwareId", out var target) ? target.GetString() : null;
                var strength = ban.TryGetProperty("componentMatchStrength", out var match) ? match.GetString() : "exact";
                IEnumerable<string> targets = targetHwid == null ? resolvedHwids : new[] { targetHwid };
                foreach (var hwid in targets)
                {
                    var isProbabilistic = strength == "weak"
                        || (targetHwid == null && !string.IsNullOrWhiteSpace(componentHash) && componentHash.Length < 64);
                    AddEdge($"machine:{hwid}", banNode, targetHwid == null ? "matched_component_ban" : "matched_hardware_ban",
                        isProbabilistic ? "probabilistic" : "exact",
                        targetHwid == null ? (isProbabilistic ? "component fingerprint fragment or weak component" : "exact component fingerprint") : "same hardwareId");
                }
                if (ban.TryGetProperty("reason", out var reasonElement))
                {
                    var reason = reasonElement.GetString() ?? "";
                    foreach (var part in reason.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (part.StartsWith("ticket=", StringComparison.OrdinalIgnoreCase)) ticketRefs.Add(part[7..]);
                        else if (part.StartsWith("securityCase=", StringComparison.OrdinalIgnoreCase)) securityCaseRefs.Add(part[13..]);
                    }
                }
            }
        }
        foreach (var ticket in ticketRefs)
            AddNode($"ticket:{ticket}", "bugtrace_ticket", ticket);
        foreach (var securityCase in securityCaseRefs)
            AddNode($"security-case:{securityCase}", "security_case", securityCase);

        var snapshot = JsonSerializer.SerializeToElement(new
        {
            ticketRef,
            securityCaseId,
            generatedAtUtc = DateTime.UtcNow,
            query = new
            {
                hardwareId,
                componentHash,
                componentType,
                clientIp,
                hasEmailFragment = !string.IsNullOrWhiteSpace(emailFragment),
                hasLicenseFragment = !string.IsNullOrWhiteSpace(licenseFragment),
                includeInactive,
                take,
                productId,
                productName
            },
            bans = effectiveBans,
            resolvedHardwareIds = resolvedHwids.OrderBy(v => v).ToList(),
            canaryByMachine,
            profilesByMachine,
            graph = new
            {
                exactEvidence = edges.Count(e => Equals(e["confidence"], "exact")),
                probabilisticEvidence = edges.Count(e => Equals(e["confidence"], "probabilistic")),
                nodes,
                edges
            },
            correlatedTickets = ticketRefs.OrderBy(v => v).ToList(),
            correlatedSecurityCases = securityCaseRefs.OrderBy(v => v).ToList()
        }, JsonOptions);

        return await _resultStore.DeliverAsync(snapshot, cancellationToken);
    }

    public async Task<JsonElement> GetSecurityBanDetailsAsync(
        Guid banId,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null,
        bool protectOversized = true)
    {
        return await GetAnalyticsAsync($"security/bans/{banId:D}", new Dictionary<string, string?>
        {
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken, protectOversized);
    }

    public async Task<JsonElement> GetSecurityBanSourceEventAsync(
        Guid banId,
        CancellationToken cancellationToken,
        string? productId = null,
        string? productName = null)
    {
        return await GetAnalyticsAsync($"security/bans/{banId:D}/source-event", new Dictionary<string, string?>
        {
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    public JsonElement GetSecurityHardwareBanCategories()
    {
        return JsonSerializer.SerializeToElement(new
        {
            categories = new[]
            {
                "manual",
                "piracy",
                "debugger",
                "outdated_version",
                "quota_abuse",
                "dev_canary_quarantine"
            },
            defaultCategory = "manual",
            permanentCategories = new[] { "debugger", "piracy" },
            autoUnbannableCategories = new[] { "quota_abuse", "outdated_version" }
        }, JsonOptions);
    }

    public async Task<JsonElement> CreateSecurityHardwareBanAsync(
        string hardwareId,
        string reason,
        string category,
        string? productId,
        string? productName,
        string? expiresAt,
        int? durationDays,
        string? ticketRef,
        string? securityCaseId,
        string? createdBy,
        string? auditNote,
        CancellationToken cancellationToken)
    {
        const string operation = "create_security_hardware_ban";
        const string endpoint = "/api/admin/banned-hwids";
        if (!_options.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
            return await DeliverAdminCredentialErrorAsync(operation, endpoint, errorCode, errorMessage, cancellationToken);

        var resolvedExpiresAt = ResolveExpiresAt(expiresAt, durationDays);
        var uri = BuildRootedUri("api/admin/banned-hwids", new Dictionary<string, string?>());
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = JsonContent.Create(new
            {
                hardwareId,
                reason = BuildAuditedReason(reason, ticketRef, securityCaseId, createdBy, auditNote),
                productId,
                expiresAt = resolvedExpiresAt,
                banCategory = category
            }, options: JsonOptions)
        };
        request.Headers.Add("X-Admin-Secret", adminSecret);

        var mutation = await SendAdminJsonAsync(request, cancellationToken, returnStructuredError: true);
        var verification = await ListSecurityBansAsync(
            hardwareId,
            componentHash: null,
            componentType: null,
            clientIp: null,
            emailFragment: null,
            licenseFragment: null,
            includeInactive: true,
            take: 25,
            cancellationToken,
            productId,
            string.IsNullOrWhiteSpace(productId) ? productName : null,
            includeSourceEvents: false,
            protectOversized: false);

        var result = JsonSerializer.SerializeToElement(new
        {
            operation,
            mutation,
            verification
        }, JsonOptions);
        return await _resultStore.DeliverAsync(result, cancellationToken);
    }

    public async Task<JsonElement> UnbanSecurityHardwareBanAsync(
        Guid banId,
        string? productId,
        string? productName,
        string reason,
        string? ticketRef,
        string? securityCaseId,
        string? createdBy,
        string? auditNote,
        CancellationToken cancellationToken)
    {
        const string operation = "unban_security_hardware_ban";
        var endpoint = $"/api/admin/banned-hwids/{banId:D}";
        if (!_options.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
            return await DeliverAdminCredentialErrorAsync(operation, endpoint, errorCode, errorMessage, cancellationToken);

        var uri = BuildRootedUri($"api/admin/banned-hwids/{banId:D}", new Dictionary<string, string?>
        {
            ["auditReason"] = BuildAuditedReason(reason, ticketRef, securityCaseId, createdBy, auditNote)
        });
        using var request = new HttpRequestMessage(HttpMethod.Delete, uri);
        request.Headers.Add("X-Admin-Secret", adminSecret);

        var mutation = await SendAdminJsonAsync(request, cancellationToken, returnStructuredError: true);
        var verification = await GetSecurityBanDetailsAsync(
            banId, cancellationToken, productId,
            string.IsNullOrWhiteSpace(productId) ? productName : null,
            protectOversized: false);

        var result = JsonSerializer.SerializeToElement(new
        {
            operation,
            mutation,
            verification
        }, JsonOptions);
        return await _resultStore.DeliverAsync(result, cancellationToken);
    }

    public async Task<JsonElement> CreateSecurityComponentBanAsync(
        string componentType,
        string componentHash,
        string reason,
        string? category,
        string? productId,
        string? productName,
        string? expiresAt,
        int? durationDays,
        string? ticketRef,
        string? securityCaseId,
        string? createdBy,
        string? auditNote,
        CancellationToken cancellationToken)
    {
        const string operation = "create_security_component_ban";
        const string endpoint = "/api/admin/banned-components";
        if (!_options.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
            return await DeliverAdminCredentialErrorAsync(operation, endpoint, errorCode, errorMessage, cancellationToken);

        var resolvedExpiresAt = ResolveExpiresAt(expiresAt, durationDays);
        var uri = BuildRootedUri("api/admin/banned-components", new Dictionary<string, string?>());
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = JsonContent.Create(new
            {
                componentType,
                componentHash,
                reason = BuildAuditedReason(
                    string.IsNullOrWhiteSpace(category) ? reason : $"{reason} | category={Truncate(category.Trim(), 50)}",
                    ticketRef, securityCaseId, createdBy, auditNote),
                productId,
                expiresAt = resolvedExpiresAt
            }, options: JsonOptions)
        };
        request.Headers.Add("X-Admin-Secret", adminSecret);

        var mutation = await SendAdminJsonAsync(request, cancellationToken, returnStructuredError: true);
        var verification = await ListSecurityBansAsync(
            hardwareId: null,
            componentHash,
            componentType,
            clientIp: null,
            emailFragment: null,
            licenseFragment: null,
            includeInactive: true,
            take: 25,
            cancellationToken,
            productId,
            string.IsNullOrWhiteSpace(productId) ? productName : null,
            includeSourceEvents: false,
            protectOversized: false);

        var result = JsonSerializer.SerializeToElement(new
        {
            operation,
            mutation,
            verification
        }, JsonOptions);
        return await _resultStore.DeliverAsync(result, cancellationToken);
    }

    public async Task<JsonElement> UnbanSecurityComponentBanAsync(
        Guid banId,
        string? productId,
        string? productName,
        string reason,
        string? ticketRef,
        string? securityCaseId,
        string? createdBy,
        string? auditNote,
        CancellationToken cancellationToken)
    {
        const string operation = "unban_security_component_ban";
        var endpoint = $"/api/admin/banned-components/{banId:D}";
        if (!_options.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
            return await DeliverAdminCredentialErrorAsync(operation, endpoint, errorCode, errorMessage, cancellationToken);

        var uri = BuildRootedUri($"api/admin/banned-components/{banId:D}", new Dictionary<string, string?>
        {
            ["auditReason"] = BuildAuditedReason(reason, ticketRef, securityCaseId, createdBy, auditNote)
        });
        using var request = new HttpRequestMessage(HttpMethod.Delete, uri);
        request.Headers.Add("X-Admin-Secret", adminSecret);

        var mutation = await SendAdminJsonAsync(request, cancellationToken, returnStructuredError: true);
        var verification = await GetSecurityBanDetailsAsync(
            banId, cancellationToken, productId,
            string.IsNullOrWhiteSpace(productId) ? productName : null,
            protectOversized: false);

        var result = JsonSerializer.SerializeToElement(new
        {
            operation,
            mutation,
            verification
        }, JsonOptions);
        return await _resultStore.DeliverAsync(result, cancellationToken);
    }

    public async Task<JsonElement> ListLlmTipFeedbackAsync(
        string? fromUtc,
        string? toUtc,
        string? productId,
        string? productName,
        string? appVersion,
        string? category,
        string? severity,
        string? reviewStatus,
        string? search,
        int limit,
        int offset,
        string? sortBy,
        string? sortDir,
        CancellationToken cancellationToken)
    {
        return await GetLlmTipFeedbackAsync("admin/tips", new Dictionary<string, string?>
        {
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["productId"] = productId,
            ["productName"] = productName,
            ["appVersion"] = appVersion,
            ["category"] = category,
            ["severity"] = severity,
            ["reviewStatus"] = reviewStatus,
            ["search"] = search,
            ["limit"] = limit.ToString(),
            ["offset"] = offset.ToString(),
            ["sortBy"] = sortBy,
            ["sortDir"] = sortDir
        }, cancellationToken);
    }

    public async Task<JsonElement> GetLlmTipFeedbackDetailAsync(
        string idOrContentHash,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        return await GetLlmTipFeedbackAsync(
            $"admin/tips/{Uri.EscapeDataString(idOrContentHash)}",
            new Dictionary<string, string?>
            {
                ["productId"] = productId,
                ["productName"] = productName
            },
            cancellationToken);
    }

    public async Task<JsonElement> GetLlmTipFeedbackStatsAsync(
        int days,
        string? fromUtc,
        string? toUtc,
        string? productId,
        string? productName,
        string? appVersion,
        string? category,
        string? severity,
        string? reviewStatus,
        string? search,
        CancellationToken cancellationToken)
    {
        return await GetLlmTipFeedbackAsync("admin/stats", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["productId"] = productId,
            ["productName"] = productName,
            ["appVersion"] = appVersion,
            ["category"] = category,
            ["severity"] = severity,
            ["reviewStatus"] = reviewStatus,
            ["search"] = search
        }, cancellationToken);
    }

    public async Task<JsonElement> UpdateLlmTipFeedbackReviewStatusAsync(
        string? id,
        string? contentHash,
        string reviewStatus,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        var uri = BuildRootedUri("api/llm-tips-feedback/admin/tips/review-status", new Dictionary<string, string?>
        {
            ["productId"] = productId,
            ["productName"] = productName
        });
        using var request = new HttpRequestMessage(HttpMethod.Patch, uri)
        {
            Content = JsonContent.Create(new
            {
                id,
                contentHash,
                reviewStatus
            }, options: JsonOptions)
        };
        request.Headers.Add("X-Analytics-Key", _options.GetApiKey());

        return await SendJsonAsync(request, cancellationToken);
    }

    private async Task<JsonElement> GetAnalyticsAsync(
        string path,
        IReadOnlyDictionary<string, string?> query,
        CancellationToken cancellationToken,
        bool protectOversized = true)
    {
        var uri = BuildRootedUri($"api/analytics/{path}", query);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("X-Analytics-Key", _options.GetApiKey());

        return await SendJsonAsync(request, cancellationToken, protectOversized);
    }

    private async Task<JsonElement> GetLlmTipFeedbackAsync(
        string path,
        IReadOnlyDictionary<string, string?> query,
        CancellationToken cancellationToken)
    {
        var uri = BuildRootedUri($"api/llm-tips-feedback/{path}", query);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("X-Analytics-Key", _options.GetApiKey());

        return await SendJsonAsync(request, cancellationToken);
    }

    private async Task<JsonElement> SendJsonAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        bool protectOversized = true)
    {
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            throw new InvalidOperationException("SoftLicence analytics API rejected SOFTLICENCE_API_KEY.");

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
            if (TryGetProductSelectorError(errorBody, out var errorCode, out var message))
            {
                var selectorError = await BuildProductSelectorErrorAsync(
                    request, response, errorCode, message, errorBody, cancellationToken);
                return protectOversized
                    ? await _resultStore.DeliverAsync(selectorError, cancellationToken)
                    : selectorError;
            }

            var analyticsError = BuildAnalyticsError(request, response, errorBody);
            return protectOversized
                ? await _resultStore.DeliverAsync(analyticsError, cancellationToken)
                : analyticsError;
        }

        if (protectOversized)
        {
            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            return await _resultStore.DeliverJsonAsync(json, cancellationToken);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        return document.RootElement.Clone();
    }

    private async Task<JsonElement> SendAdminJsonAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        bool returnStructuredError = false)
    {
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var errorCode = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => "admin_auth_failed",
                HttpStatusCode.Forbidden => "write_forbidden",
                HttpStatusCode.Conflict => "write_conflict",
                HttpStatusCode.NotFound => "target_not_found",
                _ => "admin_write_failed"
            };
            var structuredError = JsonSerializer.SerializeToElement(new
            {
                ok = false,
                errorCode,
                statusCode = (int)response.StatusCode,
                reasonPhrase = response.ReasonPhrase,
                endpoint = request.RequestUri?.AbsolutePath,
                error = TryParseJsonElement(body),
                message = string.IsNullOrWhiteSpace(body)
                    ? "SoftLicence admin API refused the mutation without a response body."
                    : null
            }, JsonOptions);
            if (returnStructuredError)
                return structuredError;

            throw new InvalidOperationException(
                $"{errorCode}: SoftLicence admin API returned HTTP {(int)response.StatusCode} for {request.RequestUri?.AbsolutePath}. "
                + (string.IsNullOrWhiteSpace(body) ? "No response body." : Truncate(body, 500)));
        }

        if (string.IsNullOrWhiteSpace(body))
            return JsonSerializer.SerializeToElement(new { ok = true }, JsonOptions);

        using var document = JsonDocument.Parse(body);
        return document.RootElement.Clone();
    }

    private async Task<JsonElement> DeliverAdminCredentialErrorAsync(
        string operation,
        string endpoint,
        string errorCode,
        string message,
        CancellationToken cancellationToken)
    {
        var result = JsonSerializer.SerializeToElement(new
        {
            operation,
            mutation = new
            {
                ok = false,
                errorCode,
                endpoint,
                requestSent = false,
                message
            },
            verification = (object?)null
        }, JsonOptions);
        return await _resultStore.DeliverAsync(result, cancellationToken);
    }

    private async Task<JsonElement> BuildProductSelectorErrorAsync(
        HttpRequestMessage failedRequest,
        HttpResponseMessage response,
        string errorCode,
        string message,
        string errorBody,
        CancellationToken cancellationToken)
    {
        var availableProducts = await TryFetchAvailableProductsAsync(cancellationToken);
        var originalError = TryParseJsonElement(errorBody);

        return JsonSerializer.SerializeToElement(new
        {
            ok = false,
            errorCode,
            message,
            hint = "This SoftLicence analytics key is global or the product selector is invalid. Call list_products, then retry with an exact productName or productId.",
            endpoint = failedRequest.RequestUri?.AbsolutePath,
            statusCode = (int)response.StatusCode,
            reasonPhrase = response.ReasonPhrase,
            availableProducts,
            originalError
        }, JsonOptions);
    }

    private async Task<JsonElement?> TryFetchAvailableProductsAsync(CancellationToken cancellationToken)
    {
        try
        {
            var uri = BuildRootedUri("api/analytics/products", new Dictionary<string, string?>());
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add("X-Analytics-Key", _options.GetApiKey());

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
                return null;

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return document.RootElement.Clone();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static JsonElement BuildAnalyticsError(
        HttpRequestMessage failedRequest,
        HttpResponseMessage response,
        string errorBody)
    {
        using var document = TryParseJsonDocument(errorBody);
        var mayExposeStructuredDetails = (int)response.StatusCode < 500;
        var errorCode = mayExposeStructuredDetails
            ? TryGetStringProperty(document?.RootElement, "errorCode") ?? "ANALYTICS_API_ERROR"
            : "ANALYTICS_SERVER_ERROR";
        var message = mayExposeStructuredDetails
            ? TryGetStringProperty(document?.RootElement, "message")
                ?? $"SoftLicence analytics API returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase})."
            : "SoftLicence analytics API returned an internal server error.";
        var hint = mayExposeStructuredDetails ? TryGetStringProperty(document?.RootElement, "hint") : null;
        var maxDays = mayExposeStructuredDetails ? TryGetInt32Property(document?.RootElement, "maxDays") : null;

        return JsonSerializer.SerializeToElement(new
        {
            ok = false,
            errorCode,
            message,
            hint,
            maxDays,
            endpoint = failedRequest.RequestUri?.AbsolutePath,
            statusCode = (int)response.StatusCode,
            reasonPhrase = response.ReasonPhrase
        }, JsonOptions);
    }

    private static string? TryGetStringProperty(JsonElement? element, string propertyName)
    {
        if (!element.HasValue || element.Value.ValueKind != JsonValueKind.Object)
            return null;

        if (!element.Value.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return property.GetString();
    }

    private static int? TryGetInt32Property(JsonElement? element, string propertyName)
    {
        if (!element.HasValue || element.Value.ValueKind != JsonValueKind.Object)
            return null;

        if (!element.Value.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.Number
            || !property.TryGetInt32(out var value))
        {
            return null;
        }

        return value;
    }

    private static bool TryGetProductSelectorError(string errorBody, out string errorCode, out string message)
    {
        errorCode = "";
        message = "";

        using var document = TryParseJsonDocument(errorBody);
        if (document == null || document.RootElement.ValueKind != JsonValueKind.Object)
            return false;

        if (!document.RootElement.TryGetProperty("errorCode", out var codeElement))
            return false;

        errorCode = codeElement.GetString() ?? "";
        if (!IsProductSelectorError(errorCode))
            return false;

        if (document.RootElement.TryGetProperty("message", out var messageElement))
            message = messageElement.GetString() ?? "";

        return true;
    }

    private static bool IsProductSelectorError(string errorCode)
    {
        return errorCode is
            "PRODUCT_SELECTOR_REQUIRED" or
            "PRODUCT_SELECTOR_AMBIGUOUS" or
            "PRODUCT_NAME_AMBIGUOUS" or
            "PRODUCT_NOT_FOUND";
    }

    private static JsonDocument? TryParseJsonDocument(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;

        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static JsonElement? TryParseJsonElement(string json)
    {
        using var document = TryParseJsonDocument(json);
        return document?.RootElement.Clone();
    }

    private static DateTime? ResolveExpiresAt(string? expiresAt, int? durationDays)
    {
        if (!string.IsNullOrWhiteSpace(expiresAt))
            return DateTime.Parse(expiresAt, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);

        return durationDays.HasValue ? DateTime.UtcNow.AddDays(Math.Clamp(durationDays.Value, 1, 3650)) : null;
    }

    private static string BuildAuditedReason(string reason, string? ticketRef, string? securityCaseId, string? createdBy, string? auditNote)
    {
        var parts = new List<string> { Truncate(reason.Trim(), 300) };
        if (!string.IsNullOrWhiteSpace(ticketRef))
            parts.Add($"ticket={Truncate(ticketRef.Trim(), 50)}");
        if (!string.IsNullOrWhiteSpace(securityCaseId))
            parts.Add($"securityCase={Truncate(securityCaseId.Trim(), 70)}");
        if (!string.IsNullOrWhiteSpace(createdBy))
            parts.Add($"createdBy={Truncate(createdBy.Trim(), 50)}");
        if (!string.IsNullOrWhiteSpace(auditNote))
            parts.Add($"note={Truncate(auditNote.Trim(), 70)}");

        return string.Join(" | ", parts);
    }

    private static bool HasAuditMetadata(string reason, string key, string expectedValue)
    {
        return reason.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Any(part => part.Equals($"{key}={expectedValue}", StringComparison.OrdinalIgnoreCase));
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private Uri BuildRootedUri(string path, IReadOnlyDictionary<string, string?> query)
    {
        var builder = new UriBuilder($"{_options.GetBaseUrl()}/{path.TrimStart('/')}");
        var encoded = query
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Value))
            .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(NormalizeQueryValue(kv.Key, kv.Value!))}");

        builder.Query = string.Join("&", encoded);
        return builder.Uri;
    }

    private static string NormalizeQueryValue(string key, string value)
    {
        if (!key.Equals("productName", StringComparison.Ordinal))
            return value;

        var trimmed = value.Trim();
        return trimmed.Equals("TIAConnect", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("T-IA Connect", StringComparison.OrdinalIgnoreCase)
                ? "TIAConnect"
                : trimmed;
    }

    private sealed record TimelineSegmentResult(
        int Index,
        string FromUtc,
        string ToUtc,
        JsonElement Result);
}
