using System.Net;
using System.Net.Http.Json;
using System.Globalization;
using System.Text;
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
    private readonly ISoftLicenceCallerCredentials _credentials;
    private readonly McpResultStore _resultStore;

    /// <summary>
    /// Reads a bounded, product-scoped page from the durable pre-download decision registry. Exact
    /// selectors are encoded without text normalization; provider failures and cancellation propagate.
    /// </summary>
    public async Task<JsonElement> GetRuntimeDistributionHardwareDecisionsAsync(
        string? requestId, Guid? licenseId, string? hardwareIdHash, string? outcome,
        DateTime? fromUtc, DateTime? toUtc, int take, int offset,
        string? productId, string? productName, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("support/runtime-distribution-hardware-decisions",
            new Dictionary<string, string?>
            {
                ["requestId"] = requestId,
                ["licenseId"] = licenseId?.ToString("D"),
                ["hardwareIdHash"] = hardwareIdHash,
                ["outcome"] = outcome,
                ["fromUtc"] = fromUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                ["toUtc"] = toUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                ["take"] = take.ToString(CultureInfo.InvariantCulture),
                ["offset"] = offset.ToString(CultureInfo.InvariantCulture),
                ["productId"] = productId,
                ["productName"] = productName
            }, cancellationToken);
    }

    /// <summary>Reads a bounded decision page through existing Analytics credentials without normalizing opaque selectors.</summary>
    /// <remarks>The server enforces product scope and exact target validation. Null query values are omitted; supplied values are percent-encoded unchanged. Existing transport cancellation, provider error projection and oversized-result handling apply. No licensing command is issued.</remarks>
    public async Task<JsonElement> GetLicenseDecisionsAsync(
        Guid? licenseId, string? hardwareId, string? requestId, int take, int offset,
        string? productId, string? productName, CancellationToken cancellationToken)
    {
        return await GetLicenseDecisionsCoreAsync(licenseId, hardwareId, requestId, take, offset,
            productId, productName, cancellationToken, protectOversized: true);
    }

    /// <summary>Reads the decision page with explicit control over final MCP artifact delivery.</summary>
    /// <remarks>Composed diagnostics disable intermediate artifact delivery so they can validate the provider JSON before protecting their own final result.</remarks>
    private async Task<JsonElement> GetLicenseDecisionsCoreAsync(
        Guid? licenseId, string? hardwareId, string? requestId, int take, int offset,
        string? productId, string? productName, CancellationToken cancellationToken,
        bool protectOversized)
    {
        var query = new Dictionary<string, string?>
        {
            ["licenseId"] = licenseId?.ToString("D"), ["hardwareId"] = hardwareId,
            ["requestId"] = requestId, ["take"] = take.ToString(CultureInfo.InvariantCulture),
            ["offset"] = offset.ToString(CultureInfo.InvariantCulture),
            ["productId"] = productId, ["productName"] = productName
        };
        var builder = new UriBuilder($"{_options.GetBaseUrl()}/api/analytics/support/license-decisions")
        {
            Query = string.Join("&", query.Where(item => item.Value != null)
                .Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value!)}"))
        };
        using var request = new HttpRequestMessage(HttpMethod.Get, builder.Uri);
        request.Headers.Add("X-Analytics-Key", _credentials.GetApiKey());
        return await SendJsonAsync(request, cancellationToken, protectOversized);
    }

    /// <summary>Builds one exact request-scoped Runtime authority diagnostic from stored provider evidence.</summary>
    /// <remarks>The decision row supplies the only HWID allowed to seed security correlation. Historical candidate payloads are never reconstructed; absence is reported explicitly. Existing authorization and result-size protection remain in force.</remarks>
    public async Task<JsonElement> GetRuntimeEnrollmentAuthorityDiagnosticAsync(
        string requestId, string? productId, string? productName, CancellationToken cancellationToken)
    {
        var decisions = await GetCompleteLicenseDecisionsAsync(
            requestId, productId, productName, cancellationToken);
        var decisionItems = decisions.GetProperty("items");
        var submittedHardwareIds = new HashSet<string>(StringComparer.Ordinal);
        var storedCandidateSelectionAvailable = decisionItems.GetArrayLength() > 0;
        var decisionEvidenceComplete = decisionItems.GetArrayLength() > 0;
        foreach (var item in decisionItems.EnumerateArray())
        {
            if (!item.TryGetProperty("parseStatus", out var parseStatus)
                || parseStatus.ValueKind != JsonValueKind.String
                || parseStatus.GetString() != "available"
                || !item.TryGetProperty("decision", out var decision)
                || decision.ValueKind != JsonValueKind.Object)
            {
                decisionEvidenceComplete = false;
                continue;
            }
            if (!decision.TryGetProperty("submittedHardwareId", out var hardware)
                || hardware.ValueKind != JsonValueKind.String
                || !ValidExactText(hardware.GetString(), 512))
                decisionEvidenceComplete = false;
            else submittedHardwareIds.Add(hardware.GetString()!);
            if (!decision.TryGetProperty("replacementCandidates", out var candidates)
                || candidates.ValueKind != JsonValueKind.Array)
                storedCandidateSelectionAvailable = false;
        }
        storedCandidateSelectionAvailable = decisionEvidenceComplete && storedCandidateSelectionAvailable;
        var exactHardwareId = decisionEvidenceComplete && submittedHardwareIds.Count == 1
            ? submittedHardwareIds.Single() : null;
        JsonElement? security = exactHardwareId == null ? null : await GetSecurityCaseSnapshotCoreAsync(
            null, null, exactHardwareId, null, null, null, null, null,
            true, 100, productId, productName, cancellationToken,
            protectOversized: false, exactHardwareOnly: true);
        var result = JsonSerializer.SerializeToElement(new
        {
            schema = "runtime-enrollment-authority-diagnostic-v1",
            requestId,
            generatedAtUtc = DateTime.UtcNow,
            decisions,
            exactHardwareId,
            decisionEvidenceComplete,
            security,
            candidateSelection = new
            {
                historicalPayloadAvailable = storedCandidateSelectionAvailable,
                classification = storedCandidateSelectionAvailable ? "stored" : "not_observed",
                limitation = storedCandidateSelectionAvailable ? null
                    : "Historical replacement candidate payloads are not reconstructed from later binding state."
            },
            guarantees = new[]
            {
                "exact_request_id",
                "provider_stored_decision_only",
                "exact_hardware_id_from_decision_only",
                "no_new_licensing_decision"
            },
            readOnly = true
        }, JsonOptions);
        return await _resultStore.DeliverAsync(result, cancellationToken);
    }

    /// <summary>Reads one bounded atomic provider snapshot before deriving a unique hardware identity.</summary>
    private async Task<JsonElement> GetCompleteLicenseDecisionsAsync(
        string requestId, string? productId, string? productName, CancellationToken cancellationToken)
    {
        var snapshot = await GetAnalyticsAsync("support/license-decisions/request-snapshot",
            new Dictionary<string, string?>
            {
                ["requestId"] = requestId, ["productId"] = productId, ["productName"] = productName
            }, cancellationToken, protectOversized: false);
        if (snapshot.ValueKind != JsonValueKind.Object
            || !snapshot.TryGetProperty("complete", out var complete) || complete.ValueKind != JsonValueKind.True
            || !snapshot.TryGetProperty("requestId", out var returnedRequestId)
            || returnedRequestId.ValueKind != JsonValueKind.String
            || !string.Equals(returnedRequestId.GetString(), requestId, StringComparison.Ordinal)
            || !snapshot.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("SoftLicence decision diagnostic returned an incomplete request snapshot.");
        return snapshot;
    }

    /// <summary>
    /// Creates a client for one tool call. <paramref name="credentials"/> defaults to the stdio
    /// environment; the HTTP mode injects the caller's request headers instead (TKT-001169).
    /// </summary>
    public SoftLicenceAnalyticsClient(
        HttpClient httpClient,
        IOptions<SoftLicenceMcpOptions> options,
        McpResultStore? resultStore = null,
        ISoftLicenceCallerCredentials? credentials = null)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _resultStore = resultStore ?? new McpResultStore(options);
        _credentials = credentials ?? new OptionsCallerCredentials(options);
    }

    public async Task<JsonElement> GetCurrentProductAsync(CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("products/current", new Dictionary<string, string?>(), cancellationToken);
    }

    public async Task<JsonElement> ListProductsAsync(CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("products", new Dictionary<string, string?>(), cancellationToken);
    }

    /// <summary>
    /// Gets one ordered Recovery timeline while preserving exact product selector and run identifier bytes in the query contract.
    /// </summary>
    public async Task<JsonElement> GetRecoveryTimelineAsync(
        string recoveryRunId,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        return await GetRecoveryAnalyticsAsync($"runs/{Uri.EscapeDataString(recoveryRunId)}", new Dictionary<string, string?>
        {
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
    }

    /// <summary>
    /// Gets bounded product-scoped Recovery ingestion rejections without raw request data.
    /// </summary>
    public async Task<JsonElement> GetRecoveryRejectionsAsync(
        string? recoveryRunId,
        int take,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        return await GetRecoveryAnalyticsAsync("rejections", new Dictionary<string, string?>
        {
            ["recoveryRunId"] = recoveryRunId,
            ["take"] = take.ToString(CultureInfo.InvariantCulture),
            ["productId"] = productId,
            ["productName"] = productName
        }, cancellationToken);
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
        string? productName = null,
        bool exactSnapshot = false)
    {
        return await GetAnalyticsAsync("telemetry/machine-profile", new Dictionary<string, string?>
        {
            ["hardwareId"] = hardwareId,
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["take"] = take.ToString(),
            ["exactSnapshot"] = exactSnapshot ? "true" : null,
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
        bool protectOversized = true,
        bool exactHardwareId = false)
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
            ["exactHardwareId"] = exactHardwareId ? "true" : null,
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
        bool protectOversized = true,
        bool exactHardwareId = false)
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
            ["exactHardwareId"] = exactHardwareId ? "true" : null,
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
        return await GetSecurityCaseSnapshotCoreAsync(
            ticketRef, securityCaseId, hardwareId, componentHash, componentType, clientIp,
            emailFragment, licenseFragment, includeInactive, take, productId, productName,
            cancellationToken, protectOversized: true, exactHardwareOnly: false);
    }

    /// <summary>Builds a security snapshot while letting composed diagnostics retain the complete provider evidence.</summary>
    /// <remarks>Public calls keep artifact protection. Internal composition requests raw JSON, validates every required source, and applies artifact delivery only to the final diagnostic.</remarks>
    private async Task<JsonElement> GetSecurityCaseSnapshotCoreAsync(
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
        CancellationToken cancellationToken,
        bool protectOversized,
        bool exactHardwareOnly)
    {
        var bans = await ListSecurityBansAsync(
            hardwareId, componentHash, componentType, clientIp, emailFragment, licenseFragment,
            includeInactive, take, cancellationToken, productId, productName,
            includeSourceEvents: false, protectOversized: false, exactHardwareId: exactHardwareOnly);
        EnsureAnalyticsArraySourceAvailable(bans, "security bans", "bans");
        if (exactHardwareOnly)
        {
            EnsureCompleteArraySource(bans, "security bans", "bans", "recordsMatched", "recordsReturned");
            EnsureExactHardwareArray(bans, "security bans", "resolvedHardwareIds", hardwareId!);
        }
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
        var exactBanRows = exactHardwareOnly && hardwareId != null
            ? ExactHardwareRows(bans, "security bans", "bans", hardwareId, ValidateExactBanRow, [
                "banId", "targetType", "isActive", "bannedAtUtc", "expiresAtUtc", "hardwareId",
                "correlatedHardwareIds", "componentType", "componentHashRedacted", "componentMatchType",
                "componentMatchStrength", "isWeakComponentCorrelation", "banCategory", "matchType"])
            : null;
        if (exactBanRows != null && exactBanRows.Count != bans.GetProperty("bans").GetArrayLength())
            throw new InvalidOperationException("SoftLicence exact security bans contain a foreign hardware identity.");
        var effectiveBans = exactBanRows != null
            ? JsonSerializer.SerializeToElement(new
            {
                recordsMatched = exactBanRows.Count,
                recordsReturned = exactBanRows.Count,
                resolvedHardwareIds = new[] { hardwareId },
                bans = exactBanRows
            }, JsonOptions)
            : referenceOnly
            ? JsonSerializer.SerializeToElement(new { recordsMatched = referenceMatchedBans.Count, recordsReturned = referenceMatchedBans.Count, bans = referenceMatchedBans }, JsonOptions)
            : bans;
        var resolvedHwids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (exactHardwareOnly && hardwareId != null)
            resolvedHwids.Add(hardwareId);
        else if (bans.TryGetProperty("resolvedHardwareIds", out var resolvedElement)
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
                EnsureAnalyticsArraySourceAvailable(related, "related security bans", "bans");
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
                exactHardwareOnly ? 200 : take, 0, productId, productName, cancellationToken,
                protectOversized: false, exactHardwareId: exactHardwareOnly);
            EnsureAnalyticsArraySourceAvailable(canary, "security Canary alerts", "alerts");
            if (exactHardwareOnly)
                EnsureCompleteArraySource(canary, "security Canary alerts", "alerts", "groupsMatched", "groupsReturned");
            var exactAlerts = exactHardwareOnly ? ExactHardwareRows(canary, "security Canary alerts", "alerts", hwid, ValidateExactCanaryRow, [
                "alertId", "hardwareId", "trigger", "severity", "evidenceCount", "firstSeenUtc",
                "lastSeenUtc", "isHardwareBanned", "sourceKind"])
                : null;
            if (exactAlerts != null && exactAlerts.Count != canary.GetProperty("alerts").GetArrayLength())
                throw new InvalidOperationException("SoftLicence exact Canary source contains a foreign hardware identity.");
            var effectiveCanary = exactAlerts == null
                ? canary : JsonSerializer.SerializeToElement(new
                {
                    groupsMatched = exactAlerts.Count,
                    groupsReturned = exactAlerts.Count,
                    alerts = exactAlerts
                }, JsonOptions);
            canaryByMachine.Add(new { hardwareId = hwid, result = effectiveCanary });
            if (effectiveCanary.TryGetProperty("alerts", out var alerts) && alerts.ValueKind == JsonValueKind.Array)
            {
                foreach (var alert in alerts.EnumerateArray())
                {
                    var alertId = alert.TryGetProperty("alertId", out var id) ? id.GetString() : null;
                    if (alertId == null) continue;
                    AddNode($"canary:{alertId}", "canary_alert", alertId);
                    AddEdge(machineNode, $"canary:{alertId}", "raised_canary_alert", "exact", "same hardwareId");
                }
            }

            var profile = exactHardwareOnly
                ? await GetTelemetryMachineProfileAsync(hwid, 30, 20, 1000, cancellationToken,
                    productId, productName, exactSnapshot: true)
                : await GetSupportTelemetryProfileAsync(
                    hwid, null, null, null, null, 30, Math.Min(take, 50), cancellationToken,
                    productId, productName, protectOversized: false);
            if (exactHardwareOnly)
            {
                if (profile.ValueKind != JsonValueKind.Object
                    || !profile.TryGetProperty("hardwareId", out var profileHardware)
                    || profileHardware.ValueKind != JsonValueKind.String
                    || !string.Equals(profileHardware.GetString(), hwid, StringComparison.OrdinalIgnoreCase)
                    || !profile.TryGetProperty("complete", out var complete) || complete.ValueKind != JsonValueKind.True
                    || !profile.TryGetProperty("recordsAnalyzed", out var recordsAnalyzed)
                    || recordsAnalyzed.ValueKind != JsonValueKind.Number
                    || !recordsAnalyzed.TryGetInt32(out var analyzedCount)
                    || !profile.TryGetProperty("recentRecords", out var recentRecords)
                    || recentRecords.ValueKind != JsonValueKind.Array
                    || analyzedCount != recentRecords.GetArrayLength()
                    || !ExactInteger(profile, "days", 30)
                    || recentRecords.EnumerateArray().Any(row => !ValidExactProfileRow(row))
                    || !ValidExactProfileInterval(profile, analyzedCount, recentRecords))
                    throw new InvalidOperationException("SoftLicence exact machine profile is unavailable or incomplete.");
            }
            else EnsureAnalyticsArraySourceAvailable(profile, "support telemetry profile", "candidates");
            var effectiveProfile = exactHardwareOnly ? ProjectExactMachineProfile(profile) : profile;
            profilesByMachine.Add(new { hardwareId = hwid, result = effectiveProfile });
            if (effectiveProfile.TryGetProperty("candidates", out var candidates) && candidates.ValueKind == JsonValueKind.Array)
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

        return protectOversized
            ? await _resultStore.DeliverAsync(snapshot, cancellationToken)
            : snapshot;
    }

    /// <summary>Rejects provider errors and contract drift before absence can be interpreted as negative security evidence.</summary>
    private static void EnsureAnalyticsArraySourceAvailable(JsonElement source, string sourceName, string arrayProperty)
    {
        if (source.ValueKind != JsonValueKind.Object
            || source.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False
            || !source.TryGetProperty(arrayProperty, out var rows)
            || rows.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException($"SoftLicence {sourceName} source is unavailable or malformed.");
        }
    }

    /// <summary>Requires exact snapshots to prove that the returned array is the entire matched population.</summary>
    private static void EnsureCompleteArraySource(
        JsonElement source, string sourceName, string arrayProperty,
        string matchedProperty, string returnedProperty)
    {
        var rows = source.GetProperty(arrayProperty);
        if (!source.TryGetProperty(matchedProperty, out var matched)
            || matched.ValueKind != JsonValueKind.Number || !matched.TryGetInt32(out var matchedCount)
            || !source.TryGetProperty(returnedProperty, out var returned)
            || returned.ValueKind != JsonValueKind.Number || !returned.TryGetInt32(out var returnedCount)
            || matchedCount != returnedCount || returnedCount != rows.GetArrayLength())
            throw new InvalidOperationException($"SoftLicence {sourceName} source is incomplete or truncated.");
    }

    /// <summary>Requires an exact identity array to contain the requested HWID and no foreign value.</summary>
    private static void EnsureExactHardwareArray(
        JsonElement source, string sourceName, string arrayProperty, string hardwareId)
    {
        if (!source.TryGetProperty(arrayProperty, out var values)
            || values.ValueKind != JsonValueKind.Array || values.GetArrayLength() == 0
            || values.EnumerateArray().Any(value => value.ValueKind != JsonValueKind.String
                || !string.Equals(value.GetString(), hardwareId, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"SoftLicence {sourceName} source contains a foreign hardware identity.");
    }

    /// <summary>Validates each exact provider row before projecting only its approved evidence fields.</summary>
    private static List<JsonElement> ExactHardwareRows(
        JsonElement source, string sourceName, string arrayProperty, string hardwareId,
        Func<JsonElement, string, bool> validateRow, IReadOnlyCollection<string> allowedProperties)
    {
        var rows = source.GetProperty(arrayProperty).EnumerateArray().ToArray();
        if (rows.Any(row => !validateRow(row, hardwareId)))
            throw new InvalidOperationException($"SoftLicence exact {sourceName} source contains a malformed row.");
        return rows
            .Select(row => JsonSerializer.SerializeToElement(row.EnumerateObject()
                .Where(property => allowedProperties.Contains(property.Name))
                .ToDictionary(property => property.Name, property => property.Value.Clone()), JsonOptions))
            .ToList();
    }

    /// <summary>Requires every exact ban row to carry typed identity, state, timestamp and target-specific evidence.</summary>
    private static bool ValidateExactBanRow(JsonElement row, string hardwareId)
    {
        if (row.ValueKind != JsonValueKind.Object
            || !ValidGuidString(row, "banId")
            || !RequiredString(row, "targetType", 32, out var targetType)
            || !Boolean(row, "isActive")
            || !ValidDateString(row, "bannedAtUtc")
            || !OptionalDateString(row, "expiresAtUtc")
            || !RequiredString(row, "matchType", 128, out _)
            || !OptionalKnownBanCategory(row)) return false;
        if (targetType == "hardware_id")
            return ExactString(row, "hardwareId", hardwareId);
        if (targetType != "component"
            || !RequiredString(row, "componentType", 32, out var componentType)
            || !ValidRedactedComponentHash(row)
            || !RequiredString(row, "componentMatchType", 32, out var componentMatchType)
            || !RequiredString(row, "componentMatchStrength", 16, out var strength)
            || !BooleanValue(row, "isWeakComponentCorrelation", out var isWeak)) return false;
        var expectedWeak = componentType is "CPU" or "MB" or "BIOS" or "DISK" or "HOST";
        var expectedStrength = expectedWeak ? "weak" : "strong";
        return componentType is "FP_EXE" or "FP_DLL" or "FP_CORE" or "CPU" or "MB" or "BIOS" or "DISK" or "HOST"
            && componentMatchType == componentType && strength == expectedStrength && isWeak == expectedWeak
            && ExactStringArray(row, "correlatedHardwareIds", hardwareId);
    }

    /// <summary>Requires every exact Canary summary to carry typed identity, severity, interval, origin and ban state.</summary>
    private static bool ValidateExactCanaryRow(JsonElement row, string hardwareId) =>
        row.ValueKind == JsonValueKind.Object
        && ValidGuidString(row, "alertId")
        && ExactString(row, "hardwareId", hardwareId)
        && RequiredString(row, "trigger", 100, out _)
        && IntegerInRange(row, "severity", 1, 3)
        && NonNegativeInteger(row, "evidenceCount")
        && ValidOrderedDates(row, "firstSeenUtc", "lastSeenUtc")
        && Boolean(row, "isHardwareBanned")
        && RequiredString(row, "sourceKind", 32, out var sourceKind)
        && sourceKind is "client_canary" or "server_incident";

    /// <summary>Requires each counted exact telemetry record to match the provider's non-nullable public contract.</summary>
    private static bool ValidExactProfileRow(JsonElement row) => row.ValueKind == JsonValueKind.Object
        && ValidDateString(row, "timestampUtc")
        && RequiredString(row, "type", 32, out var type)
        && type is "Event" or "Diagnostic" or "Error"
        && RequiredString(row, "eventName", 512, out _)
        && RequiredString(row, "family", 128, out _)
        && RequiredString(row, "appName", 256, out _)
        && (!row.TryGetProperty("version", out var version)
            || version.ValueKind == JsonValueKind.Null
            || version.ValueKind == JsonValueKind.String && ValidExactText(version.GetString(), 128));

    /// <summary>Requires top-level activity dates to equal the extrema of the complete recent-record population.</summary>
    private static bool ValidExactProfileInterval(JsonElement profile, int count, JsonElement records)
    {
        if (count == 0)
            return NullDate(profile, "firstActivityUtc") && NullDate(profile, "lastActivityUtc");
        if (!TryDate(profile, "firstActivityUtc", out var first)
            || !TryDate(profile, "lastActivityUtc", out var last)) return false;
        var timestamps = records.EnumerateArray().Select(row =>
        {
            row.GetProperty("timestampUtc").TryGetDateTimeOffset(out var value);
            return value;
        }).ToArray();
        return first == timestamps.Min() && last == timestamps.Max();
    }

    /// <summary>Accepts only the closed hardware-ban category vocabulary, or absence for component bans.</summary>
    private static bool OptionalKnownBanCategory(JsonElement row)
    {
        if (!row.TryGetProperty("banCategory", out var value) || value.ValueKind == JsonValueKind.Null)
            return true;
        return value.ValueKind == JsonValueKind.String && value.GetString() is
            "quota_abuse" or "outdated_version" or "debugger" or "piracy" or "manual" or "dev_canary_quarantine";
    }

    /// <summary>Accepts only the canonical hexadecimal eight-ellipsis-eight redaction shape.</summary>
    private static bool ValidRedactedComponentHash(JsonElement row)
    {
        if (!RequiredString(row, "componentHashRedacted", 19, out var value)) return false;
        return value!.Length == 19 && value.AsSpan(8, 3).SequenceEqual("...")
            && value.Take(8).Concat(value.Skip(11)).All(Uri.IsHexDigit);
    }

    /// <summary>Reads one bounded nonempty exact string without controls or edge whitespace.</summary>
    private static bool RequiredString(JsonElement row, string property, int maximum, out string? value)
    {
        value = null;
        if (!row.TryGetProperty(property, out var element) || element.ValueKind != JsonValueKind.String)
            return false;
        value = element.GetString();
        return ValidExactText(value, maximum);
    }

    /// <summary>Requires one hardware string to equal the requested identity under the provider's case-insensitive contract.</summary>
    private static bool ExactString(JsonElement row, string property, string expected) =>
        RequiredString(row, property, 512, out var value)
        && string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

    /// <summary>Requires a nonempty hardware identity array containing no value outside the requested identity.</summary>
    private static bool ExactStringArray(JsonElement row, string property, string expected) =>
        row.TryGetProperty(property, out var values) && values.ValueKind == JsonValueKind.Array
        && values.GetArrayLength() > 0 && values.EnumerateArray().All(value =>
            value.ValueKind == JsonValueKind.String
            && string.Equals(value.GetString(), expected, StringComparison.OrdinalIgnoreCase));

    /// <summary>Requires a JSON boolean property without coercion.</summary>
    private static bool Boolean(JsonElement row, string property) =>
        row.TryGetProperty(property, out var value)
        && value.ValueKind is JsonValueKind.True or JsonValueKind.False;

    /// <summary>Reads a JSON boolean property without coercion.</summary>
    private static bool BooleanValue(JsonElement row, string property, out bool value)
    {
        value = false;
        if (!row.TryGetProperty(property, out var element)
            || element.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        value = element.GetBoolean();
        return true;
    }

    /// <summary>Requires one nonnegative Int32 counter.</summary>
    private static bool NonNegativeInteger(JsonElement row, string property) =>
        row.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt32(out var number) && number >= 0;

    /// <summary>Requires one Int32 value inside the closed contract range.</summary>
    private static bool IntegerInRange(JsonElement row, string property, int minimum, int maximum) =>
        row.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt32(out var number) && number >= minimum && number <= maximum;

    /// <summary>Requires one exact Int32 contract value.</summary>
    private static bool ExactInteger(JsonElement row, string property, int expected) =>
        row.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt32(out var number) && number == expected;

    /// <summary>Requires one canonical dashed GUID-shaped string.</summary>
    private static bool ValidGuidString(JsonElement row, string property) =>
        RequiredString(row, property, 36, out var value)
        && Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty
        && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal)
        && value![14] is >= '1' and <= '5'
        && value[19] is '8' or '9' or 'a' or 'b';

    /// <summary>Rejects empty, oversized, controlled or edge-whitespace text without normalizing evidence.</summary>
    private static bool ValidExactText(string? value, int maximum) => value is { Length: > 0 }
        && value.Length <= maximum && !value.Any(char.IsControl)
        && !char.IsWhiteSpace(value[0]) && !char.IsWhiteSpace(value[^1]);

    /// <summary>Requires one parseable JSON date-time string.</summary>
    private static bool ValidDateString(JsonElement row, string property) =>
        row.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
        && value.TryGetDateTimeOffset(out _);

    /// <summary>Reads one required date-time string without coercion.</summary>
    private static bool TryDate(JsonElement row, string property, out DateTimeOffset value)
    {
        value = default;
        return row.TryGetProperty(property, out var element) && element.ValueKind == JsonValueKind.String
            && element.TryGetDateTimeOffset(out value);
    }

    /// <summary>Requires an explicit null date property for an empty complete profile.</summary>
    private static bool NullDate(JsonElement row, string property) =>
        row.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Null;

    /// <summary>Accepts an absent/null date or requires a parseable JSON date-time string.</summary>
    private static bool OptionalDateString(JsonElement row, string property) =>
        !row.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null
        || value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out _);

    /// <summary>Requires a parseable inclusive first/last interval.</summary>
    private static bool ValidOrderedDates(JsonElement row, string firstProperty, string lastProperty) =>
        row.TryGetProperty(firstProperty, out var first) && first.ValueKind == JsonValueKind.String
        && first.TryGetDateTimeOffset(out var firstValue)
        && row.TryGetProperty(lastProperty, out var last) && last.ValueKind == JsonValueKind.String
        && last.TryGetDateTimeOffset(out var lastValue) && firstValue <= lastValue;

    /// <summary>Projects the exact machine profile without forwarding future telemetry fields.</summary>
    private static JsonElement ProjectExactMachineProfile(JsonElement profile)
    {
        var properties = new HashSet<string>([
            "hardwareId", "days", "recordsAnalyzed", "complete", "firstActivityUtc", "lastActivityUtc"
        ], StringComparer.Ordinal);
        var result = profile.EnumerateObject()
            .Where(property => properties.Contains(property.Name))
            .ToDictionary(property => property.Name, property => property.Value.Clone());
        result["recentRecords"] = JsonSerializer.SerializeToElement(profile.GetProperty("recentRecords")
            .EnumerateArray().Where(row => row.ValueKind == JsonValueKind.Object)
            .Select(row => row.EnumerateObject().Where(property => new[]
                { "timestampUtc", "type", "eventName", "family", "appName", "version" }
                .Contains(property.Name, StringComparer.Ordinal))
                .ToDictionary(property => property.Name, property => property.Value.Clone()))
            .ToArray(), JsonOptions);
        return JsonSerializer.SerializeToElement(result, JsonOptions);
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
        if (!_credentials.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
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
        if (!_credentials.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
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
        if (!_credentials.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
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
        if (!_credentials.TryGetAdminSecret(out var adminSecret, out var errorCode, out var errorMessage))
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
        request.Headers.Add("X-Analytics-Key", _credentials.GetApiKey());

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
        request.Headers.Add("X-Analytics-Key", _credentials.GetApiKey());

        return await SendJsonAsync(request, cancellationToken, protectOversized);
    }

    /// <summary>
    /// Calls the Recovery analytics surface without the legacy product-name alias normalization used by generic analytics.
    /// </summary>
    private async Task<JsonElement> GetRecoveryAnalyticsAsync(
        string path,
        IReadOnlyDictionary<string, string?> query,
        CancellationToken cancellationToken)
    {
        var builder = new UriBuilder($"{_options.GetBaseUrl()}/api/analytics/recovery/{path.TrimStart('/')}");
        builder.Query = string.Join("&", query
            .Where(item => item.Value is not null)
            .Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value!)}"));
        using var request = new HttpRequestMessage(HttpMethod.Get, builder.Uri);
        request.Headers.Add("X-Analytics-Key", _credentials.GetApiKey());
        return await SendJsonAsync(request, cancellationToken);
    }

    private async Task<JsonElement> GetLlmTipFeedbackAsync(
        string path,
        IReadOnlyDictionary<string, string?> query,
        CancellationToken cancellationToken)
    {
        var uri = BuildRootedUri($"api/llm-tips-feedback/{path}", query);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("X-Analytics-Key", _credentials.GetApiKey());

        return await SendJsonAsync(request, cancellationToken);
    }

    private async Task<JsonElement> SendJsonAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        bool protectOversized = true)
    {
        using var response = await _httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            // Name the endpoint and relay the server text so the client sees why (TKT-001168).
            // Servers before TKT-001168 also answer 401 when a valid key lacks the endpoint scope.
            var unauthorizedBody = Encoding.UTF8.GetString(
                await ReadBoundedResponseBytesAsync(response.Content, cancellationToken)).Trim();
            throw new InvalidOperationException(
                $"SoftLicence analytics API rejected SOFTLICENCE_API_KEY (HTTP 401 on {request.RequestUri?.AbsolutePath}"
                + (unauthorizedBody.Length == 0 ? ")" : $": {Truncate(unauthorizedBody, 300)})")
                + ". The key is missing, unknown, inactive or expired, or (older servers) lacks the scope required by this "
                + "endpoint, e.g. security:read for security tools.");
        }

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = Encoding.UTF8.GetString(
                await ReadBoundedResponseBytesAsync(response.Content, cancellationToken));
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
            var json = Encoding.UTF8.GetString(
                await ReadBoundedResponseBytesAsync(response.Content, cancellationToken));
            return await _resultStore.DeliverJsonAsync(json, cancellationToken);
        }

        var bytes = await ReadBoundedResponseBytesAsync(response.Content, cancellationToken);
        using var document = JsonDocument.Parse(bytes);
        return document.RootElement.Clone();
    }

    /// <summary>Rejects declared and streamed response bodies before JSON parsing can consume unbounded memory.</summary>
    private async Task<byte[]> ReadBoundedResponseBytesAsync(
        HttpContent content, CancellationToken cancellationToken)
    {
        const int absoluteMaximum = 16 * 1024 * 1024;
        var maximum = Math.Clamp(_options.AnalyticsResponseMaxBytes, 1024, absoluteMaximum);
        if (content.Headers.ContentLength is > 0 and var declared && declared > maximum)
            throw new InvalidOperationException("SoftLicence analytics response exceeds the safe transport byte bound.");

        await using var input = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream(content.Headers.ContentLength is > 0 and var length
            ? checked((int)length) : Math.Min(maximum, 81920));
        var buffer = new byte[81920];
        var total = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            total = checked(total + read);
            if (total > maximum)
                throw new InvalidOperationException("SoftLicence analytics response exceeds the safe transport byte bound.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private async Task<JsonElement> SendAdminJsonAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        bool returnStructuredError = false)
    {
        using var response = await _httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var body = Encoding.UTF8.GetString(
            await ReadBoundedResponseBytesAsync(response.Content, cancellationToken));
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
            request.Headers.Add("X-Analytics-Key", _credentials.GetApiKey());

            using var response = await _httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
                return null;

            var bytes = await ReadBoundedResponseBytesAsync(response.Content, cancellationToken);
            using var document = JsonDocument.Parse(bytes);
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
