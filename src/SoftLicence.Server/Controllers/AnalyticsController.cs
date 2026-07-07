using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/analytics")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
public sealed class AnalyticsController : ControllerBase
{
    private readonly TelemetryOverviewAnalyticsService _overviewAnalytics;
    private readonly TelemetryDevicesAnalyticsService _devicesAnalytics;
    private readonly TelemetrySchemaAnalyticsService _schemaAnalytics;
    private readonly TelemetryToolUsageAnalyticsService _toolUsageAnalytics;
    private readonly TelemetryQuotaAnalyticsService _quotaAnalytics;
    private readonly TelemetryCertPinningAnalyticsService _certPinningAnalytics;
    private readonly TelemetryActivationFunnelAnalyticsService _activationFunnelAnalytics;
    private readonly TelemetryActivationFailuresAnalyticsService _activationFailuresAnalytics;
    private readonly TelemetryMachineProfileAnalyticsService _machineProfileAnalytics;
    private readonly TelemetrySupportProfileAnalyticsService _supportProfileAnalytics;
    private readonly TelemetryVersionHealthAnalyticsService _versionHealthAnalytics;
    private readonly TelemetryStartupHealthAnalyticsService _startupHealthAnalytics;
    private readonly TelemetryRawSampleAnalyticsService _rawSampleAnalytics;
    private readonly TelemetryInsightsAnalyticsService _insightsAnalytics;
    private readonly LicenseDurationMigrationImpactAnalyticsService _durationMigrationImpactAnalytics;
    private readonly FreemiumActivityRankingAnalyticsService _freemiumActivityRankingAnalytics;
    private readonly RecentLicenseOnboardingMetricsAnalyticsService _recentLicenseOnboardingMetricsAnalytics;
    private readonly LicenseUsageScoringAnalyticsService _licenseUsageScoringAnalytics;
    private readonly TelemetryLicenseHardwareAuditAnalyticsService _telemetryLicenseHardwareAuditAnalytics;
    private readonly LicenseHardwareVerifierAnalyticsService _licenseHardwareVerifierAnalytics;
    private readonly FreemiumAbuseRiskAnalyticsService _freemiumAbuseRiskAnalytics;
    private readonly SecurityBanAuditAnalyticsService _securityBanAuditAnalytics;
    private readonly AnalyticsApiKeyAuthService _apiKeyAuth;

    public AnalyticsController(
        TelemetryOverviewAnalyticsService overviewAnalytics,
        TelemetryDevicesAnalyticsService devicesAnalytics,
        TelemetrySchemaAnalyticsService schemaAnalytics,
        TelemetryToolUsageAnalyticsService toolUsageAnalytics,
        TelemetryQuotaAnalyticsService quotaAnalytics,
        TelemetryCertPinningAnalyticsService certPinningAnalytics,
        TelemetryActivationFunnelAnalyticsService activationFunnelAnalytics,
        TelemetryActivationFailuresAnalyticsService activationFailuresAnalytics,
        TelemetryMachineProfileAnalyticsService machineProfileAnalytics,
        TelemetrySupportProfileAnalyticsService supportProfileAnalytics,
        TelemetryVersionHealthAnalyticsService versionHealthAnalytics,
        TelemetryStartupHealthAnalyticsService startupHealthAnalytics,
        TelemetryRawSampleAnalyticsService rawSampleAnalytics,
        TelemetryInsightsAnalyticsService insightsAnalytics,
        LicenseDurationMigrationImpactAnalyticsService durationMigrationImpactAnalytics,
        FreemiumActivityRankingAnalyticsService freemiumActivityRankingAnalytics,
        RecentLicenseOnboardingMetricsAnalyticsService recentLicenseOnboardingMetricsAnalytics,
        LicenseUsageScoringAnalyticsService licenseUsageScoringAnalytics,
        TelemetryLicenseHardwareAuditAnalyticsService telemetryLicenseHardwareAuditAnalytics,
        LicenseHardwareVerifierAnalyticsService licenseHardwareVerifierAnalytics,
        FreemiumAbuseRiskAnalyticsService freemiumAbuseRiskAnalytics,
        SecurityBanAuditAnalyticsService securityBanAuditAnalytics,
        AnalyticsApiKeyAuthService apiKeyAuth)
    {
        _overviewAnalytics = overviewAnalytics;
        _devicesAnalytics = devicesAnalytics;
        _schemaAnalytics = schemaAnalytics;
        _toolUsageAnalytics = toolUsageAnalytics;
        _quotaAnalytics = quotaAnalytics;
        _certPinningAnalytics = certPinningAnalytics;
        _activationFunnelAnalytics = activationFunnelAnalytics;
        _activationFailuresAnalytics = activationFailuresAnalytics;
        _machineProfileAnalytics = machineProfileAnalytics;
        _supportProfileAnalytics = supportProfileAnalytics;
        _versionHealthAnalytics = versionHealthAnalytics;
        _startupHealthAnalytics = startupHealthAnalytics;
        _rawSampleAnalytics = rawSampleAnalytics;
        _insightsAnalytics = insightsAnalytics;
        _durationMigrationImpactAnalytics = durationMigrationImpactAnalytics;
        _freemiumActivityRankingAnalytics = freemiumActivityRankingAnalytics;
        _recentLicenseOnboardingMetricsAnalytics = recentLicenseOnboardingMetricsAnalytics;
        _licenseUsageScoringAnalytics = licenseUsageScoringAnalytics;
        _telemetryLicenseHardwareAuditAnalytics = telemetryLicenseHardwareAuditAnalytics;
        _licenseHardwareVerifierAnalytics = licenseHardwareVerifierAnalytics;
        _freemiumAbuseRiskAnalytics = freemiumAbuseRiskAnalytics;
        _securityBanAuditAnalytics = securityBanAuditAnalytics;
        _apiKeyAuth = apiKeyAuth;
    }

    [HttpGet("telemetry/overview")]
    public async Task<IActionResult> GetTelemetryOverview(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _overviewAnalytics.GetOverviewForProductIdAsync(
                auth.ProductId,
                period,
                top,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("telemetry/devices")]
    public async Task<IActionResult> GetTelemetryDevices(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] int take = 100,
        [FromQuery] int topEvents = 5,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _devicesAnalytics.GetDevicesForProductIdAsync(
                auth.ProductId,
                period,
                take,
                topEvents,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("telemetry/schema-summary")]
    public async Task<IActionResult> GetTelemetrySchemaSummary(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int topEvents = 25,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _schemaAnalytics.GetSchemaSummaryForProductIdAsync(
            auth.ProductId,
            days,
            topEvents,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("telemetry/tool-usage")]
    public async Task<IActionResult> GetTelemetryToolUsage(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _toolUsageAnalytics.GetToolUsageForProductIdAsync(
            auth.ProductId,
            days,
            top,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("telemetry/quota-summary")]
    public async Task<IActionResult> GetTelemetryQuotaSummary(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _quotaAnalytics.GetQuotaSummaryForProductIdAsync(
            auth.ProductId,
            days,
            top,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("telemetry/startup-health")]
    public async Task<IActionResult> GetTelemetryStartupHealth(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _startupHealthAnalytics.GetStartupHealthForProductIdAsync(
            auth.ProductId,
            days,
            top,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("telemetry/cert-pinning-summary")]
    public async Task<IActionResult> GetTelemetryCertPinningSummary(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _certPinningAnalytics.GetCertPinningSummaryForProductIdAsync(
            auth.ProductId,
            days,
            top,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("telemetry/activation-funnel")]
    public async Task<IActionResult> GetTelemetryActivationFunnel(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _activationFunnelAnalytics.GetActivationFunnelForProductIdAsync(
            auth.ProductId,
            days,
            top,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("telemetry/activation-failures")]
    public async Task<IActionResult> GetTelemetryActivationFailures(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? status = null,
        [FromQuery] int take = 25,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _activationFailuresAnalytics.GetActivationFailuresForProductIdAsync(
                auth.ProductId,
                period,
                hardwareId,
                status,
                take,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("telemetry/machine-profile")]
    public async Task<IActionResult> GetTelemetryMachineProfile(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? hardwareId,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        [FromQuery] int take = 25,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        if (string.IsNullOrWhiteSpace(hardwareId))
            return BadRequest("Missing hardwareId query parameter.");

        var result = await _machineProfileAnalytics.GetMachineProfileForProductIdAsync(
            auth.ProductId,
            hardwareId,
            days,
            top,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("support/profile")]
    public async Task<IActionResult> GetSupportProfile(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? hardwareId,
        [FromQuery] string? email,
        [FromQuery] string? emailFragment,
        [FromQuery] string? licenseFragment,
        [FromQuery] string? clientIp,
        [FromQuery] int days = 7,
        [FromQuery] int take = 25,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var result = await _supportProfileAnalytics.GetSupportProfileForProductIdAsync(
                auth.ProductId,
                hardwareId,
                email,
                emailFragment,
                licenseFragment,
                clientIp,
                days,
                take,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("telemetry/raw-sample")]
    public async Task<IActionResult> GetTelemetryRawSample(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? eventName = null,
        [FromQuery] string? eventFamily = null,
        [FromQuery] string? version = null,
        [FromQuery] string? type = null,
        [FromQuery] int take = 25,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _rawSampleAnalytics.GetRawSampleForProductIdAsync(
                auth.ProductId,
                period,
                hardwareId,
                eventName,
                eventFamily,
                version,
                type,
                take,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("security/bans")]
    public async Task<IActionResult> ListSecurityBans(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? hardwareId,
        [FromQuery] string? componentHash,
        [FromQuery] string? componentType,
        [FromQuery] string? clientIp,
        [FromQuery] string? emailFragment,
        [FromQuery] string? licenseFragment,
        [FromQuery] bool includeInactive = false,
        [FromQuery] int take = 25,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _securityBanAuditAnalytics.ListBansForProductIdAsync(
            auth.ProductId,
            hardwareId,
            componentHash,
            componentType,
            clientIp,
            emailFragment,
            licenseFragment,
            includeInactive,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("security/bans/{banId:guid}")]
    public async Task<IActionResult> GetSecurityBanDetails(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        Guid banId,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _securityBanAuditAnalytics.GetBanDetailsForProductIdAsync(
            auth.ProductId,
            banId,
            cancellationToken);

        return result.Ban == null ? NotFound(result) : Ok(result);
    }

    [HttpGet("security/bans/{banId:guid}/source-event")]
    public async Task<IActionResult> GetSecurityBanSourceEvent(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        Guid banId,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _securityBanAuditAnalytics.GetBanSourceEventForProductIdAsync(
            auth.ProductId,
            banId,
            cancellationToken);

        return result.Status == "ban_not_found" ? NotFound(result) : Ok(result);
    }

    [HttpGet("telemetry/insights")]
    public async Task<IActionResult> GetTelemetryInsights(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _insightsAnalytics.GetInsightsForProductIdAsync(
                auth.ProductId,
                period,
                top,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("telemetry/version-health")]
    public async Task<IActionResult> GetTelemetryVersionHealth(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _versionHealthAnalytics.GetVersionHealthForProductIdAsync(
            auth.ProductId,
            days,
            top,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/duration-migration-impact")]
    public async Task<IActionResult> GetLicenseDurationMigrationImpact(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? licenseType = "TIA-CONNECT-FREEMIUM",
        [FromQuery] int currentDurationDays = 30,
        [FromQuery] int targetDurationDays = 7,
        [FromQuery] string? activityWindowsDays = null,
        [FromQuery] bool includeSamples = false,
        [FromQuery] int sampleLimit = 30,
        [FromQuery] int topEvents = 20,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _durationMigrationImpactAnalytics.GetImpactForProductIdAsync(
            auth.ProductId,
            licenseType,
            currentDurationDays,
            targetDurationDays,
            activityWindowsDays,
            includeSamples,
            sampleLimit,
            topEvents,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/freemium-activity-ranking")]
    public async Task<IActionResult> GetFreemiumActivityRanking(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? licenseType = "TIA-CONNECT-FREEMIUM",
        [FromQuery] string? status = "active",
        [FromQuery] int telemetryDays = 7,
        [FromQuery] int? activationAgeMinDays = null,
        [FromQuery] int? activationAgeMaxDays = null,
        [FromQuery] bool includeSamples = false,
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _freemiumActivityRankingAnalytics.GetRankingForProductIdAsync(
            auth.ProductId,
            licenseType,
            status,
            telemetryDays,
            activationAgeMinDays,
            activationAgeMaxDays,
            includeSamples,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/paid-activity-ranking")]
    public async Task<IActionResult> GetPaidActivityRanking(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? licenseTypes = null,
        [FromQuery] string? status = "active",
        [FromQuery] int telemetryDays = 7,
        [FromQuery] int? activationAgeMinDays = null,
        [FromQuery] int? activationAgeMaxDays = null,
        [FromQuery] bool includeSamples = false,
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _freemiumActivityRankingAnalytics.GetPaidRankingForProductIdAsync(
            auth.ProductId,
            licenseTypes,
            status,
            telemetryDays,
            activationAgeMinDays,
            activationAgeMaxDays,
            includeSamples,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/types")]
    public async Task<IActionResult> GetLicenseTypes(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] bool includeFree = true,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _freemiumActivityRankingAnalytics.GetLicenseTypesForProductIdAsync(
            auth.ProductId,
            includeFree,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/recent-onboarding-metrics")]
    public async Task<IActionResult> GetRecentLicenseOnboardingMetrics(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int take = 10,
        [FromQuery] string? licenseType = "paid",
        [FromQuery] string? status = "active",
        [FromQuery] int? activationAgeMaxDays = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _recentLicenseOnboardingMetricsAnalytics.GetMetricsForProductIdAsync(
            auth.ProductId,
            take,
            licenseType,
            status,
            activationAgeMaxDays,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/usage-scoring")]
    public async Task<IActionResult> GetLicenseUsageScoring(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int take = 50,
        [FromQuery] string? licenseType = "paid",
        [FromQuery] string? status = "active",
        [FromQuery] int? activationAgeMaxDays = null,
        [FromQuery] int activityWindowDays = 14,
        [FromQuery] double? minScore = null,
        [FromQuery] bool includeInactive = false,
        [FromQuery] string? sortBy = "score",
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var result = await _licenseUsageScoringAnalytics.GetScoresForProductIdAsync(
            auth.ProductId,
            take,
            licenseType,
            status,
            activationAgeMaxDays,
            activityWindowDays,
            minScore,
            includeInactive,
            sortBy,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/telemetry-hwid-audit")]
    public async Task<IActionResult> GetTelemetryLicenseHardwareAudit(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] string? activityWindowsDays = "1,3,7,30",
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _telemetryLicenseHardwareAuditAnalytics.GetAuditForProductIdAsync(
                auth.ProductId,
                period,
                activityWindowsDays,
                take,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("licenses/verify-hwid")]
    public async Task<IActionResult> VerifyLicenseHardwareId(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? hardwareId,
        [FromQuery(Name = "hwid")] string? hwid,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var resolvedHardwareId = !string.IsNullOrWhiteSpace(hardwareId) ? hardwareId : hwid;
        if (string.IsNullOrWhiteSpace(resolvedHardwareId))
            return BadRequest("Missing required hardwareId or hwid query parameter.");

        var result = await _licenseHardwareVerifierAnalytics.VerifyHardwareIdForProductIdAsync(
            auth.ProductId,
            resolvedHardwareId,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/freemium-abuse-risk")]
    public async Task<IActionResult> GetFreemiumAbuseRisk(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? licenseType = "TIA-CONNECT-FREEMIUM",
        [FromQuery] int days = 7,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _freemiumAbuseRiskAnalytics.GetRiskForProductIdAsync(
                auth.ProductId,
                period,
                licenseType,
                take,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    private async Task<AnalyticsApiKeyAuthResult?> AuthenticateAnalyticsAsync(
        string? analyticsKey,
        CancellationToken cancellationToken)
    {
        return await _apiKeyAuth.ValidateAsync(
            analyticsKey ?? "",
            AnalyticsApiKeyScopes.TelemetryRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);
    }
}
