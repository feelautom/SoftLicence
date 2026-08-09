using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
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
    private readonly CustomerLicenseTimelineAnalyticsService _customerLicenseTimelineAnalytics;
    private readonly TelemetryVersionHealthAnalyticsService _versionHealthAnalytics;
    private readonly TelemetryStartupHealthAnalyticsService _startupHealthAnalytics;
    private readonly TelemetryRawSampleAnalyticsService _rawSampleAnalytics;
    private readonly TelemetryInsightsAnalyticsService _insightsAnalytics;
    private readonly LicenseDurationMigrationImpactAnalyticsService _durationMigrationImpactAnalytics;
    private readonly FreemiumActivityRankingAnalyticsService _freemiumActivityRankingAnalytics;
    private readonly RecentLicenseOnboardingMetricsAnalyticsService _recentLicenseOnboardingMetricsAnalytics;
    private readonly LicenseUsageScoringAnalyticsService _licenseUsageScoringAnalytics;
    private readonly TelemetryLicenseHardwareAuditAnalyticsService _telemetryLicenseHardwareAuditAnalytics;
    private readonly LicenseSeatConsistencyCheckService _licenseSeatConsistencyCheck;
    private readonly LicenseHardwareVerifierAnalyticsService _licenseHardwareVerifierAnalytics;
    private readonly FreemiumAbuseRiskAnalyticsService _freemiumAbuseRiskAnalytics;
    private readonly SecurityBanAuditAnalyticsService _securityBanAuditAnalytics;
    private readonly SecurityCanaryAnalyticsService _securityCanaryAnalytics;
    private readonly AnalyticsApiKeyAuthService _apiKeyAuth;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

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
        CustomerLicenseTimelineAnalyticsService customerLicenseTimelineAnalytics,
        TelemetryVersionHealthAnalyticsService versionHealthAnalytics,
        TelemetryStartupHealthAnalyticsService startupHealthAnalytics,
        TelemetryRawSampleAnalyticsService rawSampleAnalytics,
        TelemetryInsightsAnalyticsService insightsAnalytics,
        LicenseDurationMigrationImpactAnalyticsService durationMigrationImpactAnalytics,
        FreemiumActivityRankingAnalyticsService freemiumActivityRankingAnalytics,
        RecentLicenseOnboardingMetricsAnalyticsService recentLicenseOnboardingMetricsAnalytics,
        LicenseUsageScoringAnalyticsService licenseUsageScoringAnalytics,
        TelemetryLicenseHardwareAuditAnalyticsService telemetryLicenseHardwareAuditAnalytics,
        LicenseSeatConsistencyCheckService licenseSeatConsistencyCheck,
        LicenseHardwareVerifierAnalyticsService licenseHardwareVerifierAnalytics,
        FreemiumAbuseRiskAnalyticsService freemiumAbuseRiskAnalytics,
        SecurityBanAuditAnalyticsService securityBanAuditAnalytics,
        SecurityCanaryAnalyticsService securityCanaryAnalytics,
        AnalyticsApiKeyAuthService apiKeyAuth,
        IDbContextFactory<LicenseDbContext> dbFactory)
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
        _customerLicenseTimelineAnalytics = customerLicenseTimelineAnalytics;
        _versionHealthAnalytics = versionHealthAnalytics;
        _startupHealthAnalytics = startupHealthAnalytics;
        _rawSampleAnalytics = rawSampleAnalytics;
        _insightsAnalytics = insightsAnalytics;
        _durationMigrationImpactAnalytics = durationMigrationImpactAnalytics;
        _freemiumActivityRankingAnalytics = freemiumActivityRankingAnalytics;
        _recentLicenseOnboardingMetricsAnalytics = recentLicenseOnboardingMetricsAnalytics;
        _licenseUsageScoringAnalytics = licenseUsageScoringAnalytics;
        _telemetryLicenseHardwareAuditAnalytics = telemetryLicenseHardwareAuditAnalytics;
        _licenseSeatConsistencyCheck = licenseSeatConsistencyCheck;
        _licenseHardwareVerifierAnalytics = licenseHardwareVerifierAnalytics;
        _freemiumAbuseRiskAnalytics = freemiumAbuseRiskAnalytics;
        _securityBanAuditAnalytics = securityBanAuditAnalytics;
        _securityCanaryAnalytics = securityCanaryAnalytics;
        _apiKeyAuth = apiKeyAuth;
        _dbFactory = dbFactory;
    }

    [HttpGet("support/customer-license-timeline")]
    public async Task<IActionResult> GetCustomerLicenseTimeline(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? email = null,
        [FromQuery] string? emailFragment = null,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? licenseId = null,
        [FromQuery] string? licenseFragment = null,
        [FromQuery] int days = 30,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] int takeTimeline = 150,
        [FromQuery] int offset = 0,
        [FromQuery] bool includeAccessLogs = true,
        [FromQuery] bool includeNoise = false,
        [FromQuery] bool importantOnly = true,
        [FromQuery] bool includeProperties = true,
        [FromQuery] string? mode = "timeline",
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        TelemetryAnalyticsPeriod period;
        try
        {
            period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new
            {
                errorCode = "INVALID_TELEMETRY_PERIOD",
                message = ex.Message,
                maxDays = TelemetryAnalyticsPeriod.MaxDays,
                hint = "Use a UTC range of at most 30 days. For longer investigations, split the range into contiguous chunks and merge the timelines."
            });
        }

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var result = await _customerLicenseTimelineAnalytics.GetTimelineForProductIdAsync(
                product.ProductId,
                email,
                emailFragment,
                hardwareId,
                licenseId,
                licenseFragment,
                period,
                takeTimeline,
                offset,
                includeAccessLogs,
                includeNoise,
                importantOnly,
                includeProperties,
                mode,
                cancellationToken);

            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new
            {
                errorCode = "INVALID_ANALYTICS_REQUEST",
                message = ex.Message
            });
        }
    }

    [HttpGet("products/current")]
    public async Task<IActionResult> GetCurrentProduct(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        if (auth.IsGlobal)
        {
            return Ok(new
            {
                generatedAtUtc = DateTime.UtcNow,
                product = (AnalyticsProductSummary?)null,
                scopeKind = AnalyticsApiKeyScopeKinds.Global,
                scopeMode = "global",
                isMultiProduct = true
            });
        }

        if (!auth.ProductId.HasValue)
            return NotFound("Configured product was not found.");

        var product = await GetProductSummaryAsync(auth.ProductId.Value, cancellationToken);
        return product == null ? NotFound("Configured product was not found.") : Ok(new
        {
            generatedAtUtc = DateTime.UtcNow,
            product,
            scopeKind = AnalyticsApiKeyScopeKinds.Product,
            scopeMode = "configured",
            isMultiProduct = IsMultiProduct(auth)
        });
    }

    [HttpGet("products")]
    public async Task<IActionResult> ListProducts(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.Products.AsNoTracking();
        if (!IsMultiProduct(auth))
        {
            if (!auth.ProductId.HasValue)
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    errorCode = "PRODUCT_SCOPE_INVALID",
                    message = "The analytics key is not configured for a product."
                });

            query = query.Where(p => p.Id == auth.ProductId.Value);
        }

        var products = await query
            .OrderBy(p => p.Name)
            .Select(p => new AnalyticsProductSummary(
                p.Id,
                p.Name,
                p.MinimumAllowedVersion,
                p.Licenses.Count,
                p.TelemetryRecords.Count,
                p.AnalyticsApiKeys.Count(k => k.IsActive)))
            .ToListAsync(cancellationToken);

        return Ok(new
        {
            generatedAtUtc = DateTime.UtcNow,
            scopeKind = auth.IsGlobal ? AnalyticsApiKeyScopeKinds.Global : AnalyticsApiKeyScopeKinds.Product,
            scopeMode = IsMultiProduct(auth) ? "multi-product" : "configured",
            productsReturned = products.Count,
            products
        });
    }

    [HttpGet("telemetry/overview")]
    public async Task<IActionResult> GetTelemetryOverview(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] int top = 20,
        [FromQuery] string? date = null,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _overviewAnalytics.GetOverviewForProductIdAsync(
                product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _devicesAnalytics.GetDevicesForProductIdAsync(
                product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _schemaAnalytics.GetSchemaSummaryForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _toolUsageAnalytics.GetToolUsageForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _quotaAnalytics.GetQuotaSummaryForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _startupHealthAnalytics.GetStartupHealthForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _certPinningAnalytics.GetCertPinningSummaryForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _activationFunnelAnalytics.GetActivationFunnelForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _activationFailuresAnalytics.GetActivationFailuresForProductIdAsync(
                product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        if (string.IsNullOrWhiteSpace(hardwareId))
            return BadRequest("Missing hardwareId query parameter.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _machineProfileAnalytics.GetMachineProfileForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var result = await _supportProfileAnalytics.GetSupportProfileForProductIdAsync(
                product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _rawSampleAnalytics.GetRawSampleForProductIdAsync(
                product.ProductId,
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

    [HttpGet("telemetry/flood-suppressions")]
    public async Task<IActionResult> GetTelemetryFloodSuppressions(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int days = 7,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? eventName = null,
        [FromQuery] int take = 25,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var boundedDays = Math.Clamp(days, 1, 30);
        var boundedTake = Math.Clamp(take, 1, 100);
        var sinceUtc = DateTime.UtcNow.AddDays(-boundedDays);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.TelemetryFloodSuppressionCounters
            .AsNoTracking()
            .Where(c => c.ProductId == product.ProductId && c.LastSeenUtc >= sinceUtc);

        if (!string.IsNullOrWhiteSpace(hardwareId))
        {
            var normalizedHardwareId = hardwareId.Trim();
            query = query.Where(c => c.HardwareId == normalizedHardwareId || c.HardwareId.StartsWith(normalizedHardwareId));
        }

        if (!string.IsNullOrWhiteSpace(eventName))
        {
            var normalizedEventName = eventName.Trim();
            query = query.Where(c => c.EventName == normalizedEventName);
        }

        var rows = await query
            .OrderByDescending(c => c.SuppressedCount)
            .ThenByDescending(c => c.LastSeenUtc)
            .Take(boundedTake)
            .Select(c => new
            {
                c.Id,
                c.ProductId,
                c.AppName,
                c.HardwareId,
                c.EventName,
                Type = c.Type.ToString(),
                c.Version,
                c.WindowStartUtc,
                c.WindowEndUtc,
                c.WindowMinutes,
                c.Threshold,
                c.RawStoredCount,
                c.SuppressedCount,
                c.FirstSeenUtc,
                c.LastSeenUtc,
                c.LastClientIp,
                c.LastIsp,
                c.LastPayloadHash
            })
            .ToListAsync(cancellationToken);

        var counters = rows.Select(c => new
        {
            c.Id,
            c.ProductId,
            c.AppName,
            HardwareId = RedactHardwareId(c.HardwareId),
            c.EventName,
            c.Type,
            c.Version,
            c.WindowStartUtc,
            c.WindowEndUtc,
            c.WindowMinutes,
            c.Threshold,
            c.RawStoredCount,
            c.SuppressedCount,
            c.FirstSeenUtc,
            c.LastSeenUtc,
            c.LastClientIp,
            c.LastIsp,
            c.LastPayloadHash
        }).ToList();

        var totalSuppressed = await query.SumAsync(c => (int?)c.SuppressedCount, cancellationToken) ?? 0;
        var groupsMatched = await query.CountAsync(cancellationToken);

        return Ok(new
        {
            generatedAtUtc = DateTime.UtcNow,
            productId = product.ProductId,
            days = boundedDays,
            groupsMatched,
            returned = counters.Count,
            totalSuppressed,
            counters
        });
    }

    [HttpGet("security/canary-alerts")]
    public async Task<IActionResult> ListSecurityCanaryAlerts(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? fromUtc = null,
        [FromQuery] string? toUtc = null,
        [FromQuery] string? trigger = null,
        [FromQuery] int? severity = null,
        [FromQuery] string? hardwareId = null,
        [FromQuery] string? machine = null,
        [FromQuery] string? user = null,
        [FromQuery] string? clientIp = null,
        [FromQuery] string? version = null,
        [FromQuery] bool? isBanned = null,
        [FromQuery] int take = 50,
        [FromQuery] int offset = 0,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        if (!TryParseOptionalUtc(fromUtc, out var parsedFrom) || !TryParseOptionalUtc(toUtc, out var parsedTo))
            return BadRequest(new { errorCode = "INVALID_UTC_RANGE", message = "fromUtc and toUtc must be ISO 8601 timestamps." });
        if (parsedFrom.HasValue && parsedTo.HasValue && parsedFrom > parsedTo)
            return BadRequest(new { errorCode = "INVALID_UTC_RANGE", message = "fromUtc must be before toUtc." });
        if (severity is < 1 or > 3)
            return BadRequest(new { errorCode = "INVALID_SEVERITY", message = "severity must be 1, 2, or 3." });

        var result = await _securityCanaryAnalytics.ListForProductIdAsync(
            product.ProductId, parsedFrom, parsedTo, trigger, severity, hardwareId, machine, user,
            clientIp, version, isBanned, take, offset, cancellationToken);
        return Ok(result);
    }

    [HttpGet("security/canary-alerts/{alertId:guid}")]
    public async Task<IActionResult> GetSecurityCanaryAlertDetails(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        Guid alertId,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _securityCanaryAnalytics.GetDetailsForProductIdAsync(
            product.ProductId, alertId, cancellationToken);
        return result == null ? NotFound() : Ok(result);
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
        [FromQuery] bool includeSourceEvents = false,
        [FromQuery] int take = 25,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _securityBanAuditAnalytics.ListBansForProductIdAsync(
            product.ProductId,
            hardwareId,
            componentHash,
            componentType,
            clientIp,
            emailFragment,
            licenseFragment,
            includeInactive,
            includeSourceEvents,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("security/bans/{banId:guid}")]
    public async Task<IActionResult> GetSecurityBanDetails(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        Guid banId,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _securityBanAuditAnalytics.GetBanDetailsForProductIdAsync(
            product.ProductId,
            banId,
            cancellationToken);

        return result.Ban == null ? NotFound(result) : Ok(result);
    }

    [HttpGet("security/bans/{banId:guid}/source-event")]
    public async Task<IActionResult> GetSecurityBanSourceEvent(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        Guid banId,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateSecurityAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _securityBanAuditAnalytics.GetBanSourceEventForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _insightsAnalytics.GetInsightsForProductIdAsync(
                product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _versionHealthAnalytics.GetVersionHealthForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _durationMigrationImpactAnalytics.GetImpactForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _freemiumActivityRankingAnalytics.GetRankingForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _freemiumActivityRankingAnalytics.GetPaidRankingForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _freemiumActivityRankingAnalytics.GetLicenseTypesForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _recentLicenseOnboardingMetricsAnalytics.GetMetricsForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _licenseUsageScoringAnalytics.GetScoresForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _telemetryLicenseHardwareAuditAnalytics.GetAuditForProductIdAsync(
                product.ProductId,
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

    [HttpGet("licenses/seat-consistency")]
    public async Task<IActionResult> GetLicenseSeatConsistency(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int take = 100,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _licenseSeatConsistencyCheck.CheckProductAsync(
            product.ProductId,
            take,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("licenses/verify-hwid")]
    public async Task<IActionResult> VerifyLicenseHardwareId(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? hardwareId,
        [FromQuery(Name = "hwid")] string? hwid,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        var resolvedHardwareId = !string.IsNullOrWhiteSpace(hardwareId) ? hardwareId : hwid;
        if (string.IsNullOrWhiteSpace(resolvedHardwareId))
            return BadRequest("Missing required hardwareId or hwid query parameter.");

        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null)
            return product.Error;

        var result = await _licenseHardwareVerifierAnalytics.VerifyHardwareIdForProductIdAsync(
            product.ProductId,
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
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        try
        {
            var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
            if (product.Error != null)
                return product.Error;

            var period = TelemetryAnalyticsPeriod.Resolve(days, date, fromUtc, toUtc);
            var result = await _freemiumAbuseRiskAnalytics.GetRiskForProductIdAsync(
                product.ProductId,
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

    private static bool TryParseOptionalUtc(string? value, out DateTime? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(value))
            return true;
        if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp))
            return false;
        parsed = timestamp;
        return true;
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

    private async Task<AnalyticsApiKeyAuthResult?> AuthenticateSecurityAnalyticsAsync(
        string? analyticsKey,
        CancellationToken cancellationToken)
    {
        return await _apiKeyAuth.ValidateAsync(
            analyticsKey ?? "",
            AnalyticsApiKeyScopes.SecurityRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);
    }

    private async Task<ResolvedAnalyticsProduct> ResolveAnalyticsProductAsync(
        AnalyticsApiKeyAuthResult auth,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        var hasProductId = !string.IsNullOrWhiteSpace(productId);
        var hasProductName = !string.IsNullOrWhiteSpace(productName);
        if (hasProductId && hasProductName)
            return ResolvedAnalyticsProduct.BadRequest("Provide either productId or productName, not both.", "PRODUCT_SELECTOR_AMBIGUOUS");

        if (!hasProductId && !hasProductName)
        {
            if (auth.IsGlobal)
            {
                return ResolvedAnalyticsProduct.BadRequest(
                    "Global analytics keys must provide productId or productName for product-scoped endpoints.",
                    "PRODUCT_SELECTOR_REQUIRED");
            }

            if (!auth.ProductId.HasValue)
                return ResolvedAnalyticsProduct.Forbid("The analytics key is not configured for a product.", "PRODUCT_SCOPE_INVALID", new
                {
                    scopeKind = auth.ScopeKind
                });

            SetProductHeaders(auth.ProductId.Value, null, "configured");
            return new ResolvedAnalyticsProduct(auth.ProductId.Value, "configured", null);
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        Product? requestedProduct;
        if (hasProductId)
        {
            if (!Guid.TryParse(productId, out var parsedProductId))
                return ResolvedAnalyticsProduct.BadRequest("productId must be a valid UUID.", "PRODUCT_ID_INVALID");

            requestedProduct = await db.Products
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == parsedProductId, cancellationToken);
        }
        else
        {
            var normalizedProductName = productName!.Trim();
            var matches = await db.Products
                .AsNoTracking()
                .Where(p => p.Name.ToLower() == normalizedProductName.ToLower())
                .Take(2)
                .ToListAsync(cancellationToken);

            if (matches.Count > 1)
                return ResolvedAnalyticsProduct.BadRequest("productName matches multiple products. Use productId.", "PRODUCT_NAME_AMBIGUOUS");

            requestedProduct = matches.SingleOrDefault();
        }

        if (requestedProduct == null)
            return ResolvedAnalyticsProduct.NotFound("Requested product was not found.", "PRODUCT_NOT_FOUND");

        if (!auth.IsGlobal && (!auth.ProductId.HasValue || requestedProduct.Id != auth.ProductId.Value))
        {
            return ResolvedAnalyticsProduct.Forbid("The analytics key is scoped to a different product.", "PRODUCT_SCOPE_FORBIDDEN", new
            {
                configuredProductId = auth.ProductId,
                requestedProductId = requestedProduct.Id
            });
        }

        var scopeMode = auth.IsGlobal
            ? "explicit-global"
            : "explicit";
        SetProductHeaders(requestedProduct.Id, requestedProduct.Name, scopeMode);
        return new ResolvedAnalyticsProduct(requestedProduct.Id, scopeMode, null);
    }

    private async Task<AnalyticsProductSummary?> GetProductSummaryAsync(Guid productId, CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.Products
            .AsNoTracking()
            .Where(p => p.Id == productId)
            .Select(p => new AnalyticsProductSummary(
                p.Id,
                p.Name,
                p.MinimumAllowedVersion,
                p.Licenses.Count,
                p.TelemetryRecords.Count,
                p.AnalyticsApiKeys.Count(k => k.IsActive)))
            .FirstOrDefaultAsync(cancellationToken);
    }

    private static bool IsMultiProduct(AnalyticsApiKeyAuthResult auth)
    {
        return auth.IsGlobal
            && AnalyticsApiKeyAuthService.HasScope(auth.Scopes, AnalyticsApiKeyScopes.MultiProductRead);
    }

    private void SetProductHeaders(Guid productId, string? productName, string scopeMode)
    {
        Response.Headers["X-SoftLicence-Product-Id"] = productId.ToString("D");
        if (!string.IsNullOrWhiteSpace(productName))
            Response.Headers["X-SoftLicence-Product-Name"] = productName;
        Response.Headers["X-SoftLicence-Product-Scope-Mode"] = scopeMode;
    }

    private static string RedactHardwareId(string hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "";

        return hardwareId.Length <= 8
            ? hardwareId
            : hardwareId[..8] + "...";
    }

    private sealed record AnalyticsProductSummary(
        Guid ProductId,
        string Name,
        string? MinimumAllowedVersion,
        int LicenseCount,
        int TelemetryRecordCount,
        int ActiveAnalyticsKeyCount);

    private sealed record ResolvedAnalyticsProduct(Guid ProductId, string ScopeMode, IActionResult? Error)
    {
        public static ResolvedAnalyticsProduct BadRequest(string message, string code)
        {
            return new ResolvedAnalyticsProduct(Guid.Empty, "error", new BadRequestObjectResult(new
            {
                errorCode = code,
                message
            }));
        }

        public static ResolvedAnalyticsProduct NotFound(string message, string code)
        {
            return new ResolvedAnalyticsProduct(Guid.Empty, "error", new NotFoundObjectResult(new
            {
                errorCode = code,
                message
            }));
        }

        public static ResolvedAnalyticsProduct Forbid(string message, string code, object details)
        {
            return new ResolvedAnalyticsProduct(Guid.Empty, "error", new ObjectResult(new
            {
                errorCode = code,
                message,
                details
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            });
        }
    }
}
