using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SoftLicence.Mcp;

public sealed class SoftLicenceAnalyticsClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly SoftLicenceMcpOptions _options;

    public SoftLicenceAnalyticsClient(HttpClient httpClient, IOptions<SoftLicenceMcpOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task<JsonElement> GetTelemetryOverviewAsync(
        int days,
        int top,
        string? date,
        string? fromUtc,
        string? toUtc,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/overview", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryDevicesAsync(
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        int take,
        int topEvents,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/devices", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["take"] = take.ToString(),
            ["topEvents"] = topEvents.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetrySchemaSummaryAsync(int days, int topEvents, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/schema-summary", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["topEvents"] = topEvents.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryToolUsageAsync(int days, int top, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/tool-usage", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryQuotaSummaryAsync(int days, int top, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/quota-summary", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryStartupHealthAsync(int days, int top, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/startup-health", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryCertPinningSummaryAsync(int days, int top, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/cert-pinning-summary", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryActivationFunnelAsync(int days, int top, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/activation-funnel", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString()
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
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/activation-failures", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["hardwareId"] = hardwareId,
            ["status"] = status,
            ["take"] = take.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryMachineProfileAsync(
        string hardwareId,
        int days,
        int top,
        int take,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/machine-profile", new Dictionary<string, string?>
        {
            ["hardwareId"] = hardwareId,
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["take"] = take.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryVersionHealthAsync(int days, int top, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/version-health", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString()
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
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("support/profile", new Dictionary<string, string?>
        {
            ["hardwareId"] = hardwareId,
            ["email"] = email,
            ["emailFragment"] = emailFragment,
            ["licenseFragment"] = licenseFragment,
            ["clientIp"] = clientIp,
            ["days"] = days.ToString(),
            ["take"] = take.ToString()
        }, cancellationToken);
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
        CancellationToken cancellationToken)
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
            ["take"] = take.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryInsightsAsync(
        int days,
        int top,
        string? date,
        string? fromUtc,
        string? toUtc,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("telemetry/insights", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["top"] = top.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc
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
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/duration-migration-impact", new Dictionary<string, string?>
        {
            ["licenseType"] = licenseType,
            ["currentDurationDays"] = currentDurationDays.ToString(),
            ["targetDurationDays"] = targetDurationDays.ToString(),
            ["activityWindowsDays"] = activityWindowsDays,
            ["includeSamples"] = includeSamples.ToString().ToLowerInvariant(),
            ["sampleLimit"] = sampleLimit.ToString(),
            ["topEvents"] = topEvents.ToString()
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
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/freemium-activity-ranking", new Dictionary<string, string?>
        {
            ["licenseType"] = licenseType,
            ["status"] = status,
            ["telemetryDays"] = telemetryDays.ToString(),
            ["activationAgeMinDays"] = activationAgeMinDays?.ToString(),
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString(),
            ["includeSamples"] = includeSamples.ToString().ToLowerInvariant(),
            ["take"] = take.ToString()
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
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/paid-activity-ranking", new Dictionary<string, string?>
        {
            ["licenseTypes"] = licenseTypes,
            ["status"] = status,
            ["telemetryDays"] = telemetryDays.ToString(),
            ["activationAgeMinDays"] = activationAgeMinDays?.ToString(),
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString(),
            ["includeSamples"] = includeSamples.ToString().ToLowerInvariant(),
            ["take"] = take.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetLicenseTypesAsync(bool includeFree, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/types", new Dictionary<string, string?>
        {
            ["includeFree"] = includeFree.ToString().ToLowerInvariant()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetRecentLicenseOnboardingMetricsAsync(
        int take,
        string? licenseType,
        string? status,
        int? activationAgeMaxDays,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/recent-onboarding-metrics", new Dictionary<string, string?>
        {
            ["take"] = take.ToString(),
            ["licenseType"] = licenseType,
            ["status"] = status,
            ["activationAgeMaxDays"] = activationAgeMaxDays?.ToString()
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
        CancellationToken cancellationToken)
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
            ["sortBy"] = sortBy
        }, cancellationToken);
    }

    public async Task<JsonElement> GetTelemetryLicenseHardwareAuditAsync(
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        string? activityWindowsDays,
        int take,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/telemetry-hwid-audit", new Dictionary<string, string?>
        {
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["activityWindowsDays"] = activityWindowsDays,
            ["take"] = take.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetFreemiumAbuseRiskAsync(
        string? licenseType,
        int days,
        string? date,
        string? fromUtc,
        string? toUtc,
        int take,
        CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync("licenses/freemium-abuse-risk", new Dictionary<string, string?>
        {
            ["licenseType"] = licenseType,
            ["days"] = days.ToString(),
            ["date"] = date,
            ["fromUtc"] = fromUtc,
            ["toUtc"] = toUtc,
            ["take"] = take.ToString()
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
        CancellationToken cancellationToken)
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
            ["take"] = take.ToString()
        }, cancellationToken);
    }

    public async Task<JsonElement> GetSecurityBanDetailsAsync(Guid banId, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync($"security/bans/{banId:D}", new Dictionary<string, string?>(), cancellationToken);
    }

    public async Task<JsonElement> GetSecurityBanSourceEventAsync(Guid banId, CancellationToken cancellationToken)
    {
        return await GetAnalyticsAsync($"security/bans/{banId:D}/source-event", new Dictionary<string, string?>(), cancellationToken);
    }

    public async Task<JsonElement> ListLlmTipFeedbackAsync(
        string? fromUtc,
        string? toUtc,
        string? productId,
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

    public async Task<JsonElement> GetLlmTipFeedbackDetailAsync(string idOrContentHash, CancellationToken cancellationToken)
    {
        return await GetLlmTipFeedbackAsync(
            $"admin/tips/{Uri.EscapeDataString(idOrContentHash)}",
            new Dictionary<string, string?>(),
            cancellationToken);
    }

    public async Task<JsonElement> GetLlmTipFeedbackStatsAsync(
        int days,
        string? fromUtc,
        string? toUtc,
        string? productId,
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
        CancellationToken cancellationToken)
    {
        var uri = BuildRootedUri("api/llm-tips-feedback/admin/tips/review-status", new Dictionary<string, string?>());
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
        CancellationToken cancellationToken)
    {
        var uri = BuildRootedUri($"api/analytics/{path}", query);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("X-Analytics-Key", _options.GetApiKey());

        return await SendJsonAsync(request, cancellationToken);
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

    private async Task<JsonElement> SendJsonAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            throw new InvalidOperationException("SoftLicence analytics API rejected SOFTLICENCE_API_KEY.");

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        return document.RootElement.Clone();
    }

    private Uri BuildRootedUri(string path, IReadOnlyDictionary<string, string?> query)
    {
        var builder = new UriBuilder($"{_options.GetBaseUrl()}/{path.TrimStart('/')}");
        var encoded = query
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Value))
            .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}");

        builder.Query = string.Join("&", encoded);
        return builder.Uri;
    }
}
