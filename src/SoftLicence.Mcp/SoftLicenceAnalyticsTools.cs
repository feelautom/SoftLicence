using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace SoftLicence.Mcp;

[McpServerToolType]
public sealed class SoftLicenceAnalyticsTools
{
    private readonly SoftLicenceAnalyticsClient _client;
    private readonly McpResultStore _resultStore;

    /// <summary>
    /// Returns stored pre-download requests and decisions for one authorized product and exact selectors
    /// or a bounded UTC period. It is read-only and rejects malformed or unbounded queries before transport.
    /// </summary>
    [McpServerTool]
    [Description("Read the durable T-IA Connect pre-download hardware decision registry. Search by exact request ID, licence ID, irreversible HWID digest, closed outcome, or a UTC period up to 90 days. Returns commercial facts, ban categories, decision reason, auto-unban count and replay count without raw hardware observations, licence keys, tokens or customer identity.")]
    public async Task<JsonElement> GetRuntimeDistributionHardwareDecisions(
        [Description("Optional exact canonical request UUID.")] string? requestId = null,
        [Description("Optional exact SoftLicence licence UUID.")] Guid? licenseId = null,
        [Description("Optional lowercase SHA-256 hardware digest.")] string? hardwareIdHash = null,
        [Description("Optional closed outcome: accepted, auto-unbanned or refused.")] string? outcome = null,
        [Description("Optional UTC period start; must be supplied with toUtc.")] DateTime? fromUtc = null,
        [Description("Optional UTC period end, at most 90 days after fromUtc.")] DateTime? toUtc = null,
        [Description("Page size 1..200.")] int take = 100,
        [Description("Page offset 0..10000, newest decisions first.")] int offset = 0,
        [Description("Product UUID selector; required for global keys when productName is absent.")] string? productId = null,
        [Description("Product name selector, mutually exclusive with productId.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (requestId is not null) ValidateCanonicalUuid(requestId, nameof(requestId));
        if (licenseId == Guid.Empty
            || hardwareIdHash is not null && (hardwareIdHash.Length != 64
                || hardwareIdHash.Any(character => character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'f')))
            || outcome is not null and not ("accepted" or "auto-unbanned" or "refused")
            || fromUtc.HasValue != toUtc.HasValue
            || fromUtc is not null && (fromUtc.Value.Kind != DateTimeKind.Utc
                || toUtc!.Value.Kind != DateTimeKind.Utc || fromUtc > toUtc
                || toUtc.Value - fromUtc.Value > TimeSpan.FromDays(90))
            || requestId is null && licenseId is null && hardwareIdHash is null
                && outcome is null && fromUtc is null
            || take is < 1 or > 200 || offset is < 0 or > 10000)
            throw new ArgumentException("Provide valid exact selectors or one bounded UTC period.");
        if (productId is not null) ValidateCanonicalUuid(productId, nameof(productId));
        return await _client.GetRuntimeDistributionHardwareDecisionsAsync(
            requestId, licenseId, hardwareIdHash, outcome, fromUtc, toUtc, take, offset,
            productId, productName, cancellationToken);
    }

    /// <summary>Exposes product-scoped stored decisions through an exact targeted administrator read.</summary>
    /// <remarks>Rejects missing targets, controls, boundary whitespace and invalid page bounds before transport. Identifiers retain casing and Unicode. Null observations are unknown; legacy hardware-lock observations do not prove global quota authority. Existing provider errors propagate through the analytics client.</remarks>
    [McpServerTool]
    [Description("Read stored activation/finalization decisions for one authorized product and at least one exact licenseId, hardwareId or requestId. Targets intersect. No historical reconstruction, Website correlation or new licensing decision. Global keys require productId or productName. Unknown facts remain null; observationGuarantee states the original locking limits.")]
    public async Task<JsonElement> GetLicenseDecisions(
        [Description("Exact licence UUID, optional when another target is supplied.")] Guid? licenseId = null,
        [Description("Exact submitted, resolved or correlated HWID, at most 512 characters; no normalization.")] string? hardwareId = null,
        [Description("Exact operation or first observed HTTP correlation, at most 200 characters.")] string? requestId = null,
        [Description("Page size 1..200.")] int take = 50,
        [Description("Page offset 0..10000, newest events first.")] int offset = 0,
        [Description("Product UUID selector; required for global keys when productName is absent.")] string? productId = null,
        [Description("Existing Analytics product-name selector, mutually exclusive with productId.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        /// <summary>Validates optional exact selector text without changing bytes, case or Unicode; rejects controls and boundary whitespace before transport.</summary>
        static bool Valid(string? value, int maximum) => value == null || (value.Length > 0
            && value.Length <= maximum && !value.Any(char.IsControl)
            && !char.IsWhiteSpace(value[0]) && !char.IsWhiteSpace(value[^1]));
        if (licenseId == Guid.Empty || !Valid(hardwareId, 512) || !Valid(requestId, 200)
            || (licenseId == null && hardwareId == null && requestId == null)
            || take is < 1 or > 200 || offset is < 0 or > 10000)
            throw new ArgumentException("An exact target and valid page bounds are required.");
        return await _client.GetLicenseDecisionsAsync(licenseId, hardwareId, requestId, take, offset,
            productId, productName, cancellationToken);
    }

    /// <summary>Returns a request-scoped Runtime enrollment authority and security diagnostic.</summary>
    /// <remarks>The request identifier is exact and unnormalized. The result distinguishes unavailable historical candidate payloads from an empty candidate set and never changes licensing state.</remarks>
    [McpServerTool]
    [Description("Diagnose one Runtime enrollment/finalization request from exact stored provider decisions, then correlate only its provider-observed HWID with bans, Canary and telemetry. Historical candidate payloads are not reconstructed and remain explicitly unavailable.")]
    public async Task<JsonElement> GetRuntimeEnrollmentAuthorityDiagnostic(
        [Description("Exact canonical Runtime/finalization request UUID in lowercase D form.")] string requestId,
        [Description("Optional product UUID; required for global keys when productName is absent.")] string? productId = null,
        [Description("Optional exact product name, mutually exclusive with productId.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalUuid(requestId, nameof(requestId));
        if (productId is not null) ValidateCanonicalUuid(productId, nameof(productId));
        return await _client.GetRuntimeEnrollmentAuthorityDiagnosticAsync(
            requestId, productId, productName, cancellationToken);
    }

    public SoftLicenceAnalyticsTools(SoftLicenceAnalyticsClient client, McpResultStore resultStore)
    {
        _client = client;
        _resultStore = resultStore;
    }

    [McpServerTool]
    [Description("Get the SoftLicence product currently selected by this MCP analytics key. Use this before product-specific investigations.")]
    public async Task<JsonElement> GetCurrentProduct(CancellationToken cancellationToken = default)
    {
        return await _client.GetCurrentProductAsync(cancellationToken);
    }

    [McpServerTool]
    [Description("List SoftLicence products accessible with this MCP analytics key. Mono-product keys return only their configured product.")]
    public async Task<JsonElement> ListProducts(CancellationToken cancellationToken = default)
    {
        return await _client.ListProductsAsync(cancellationToken);
    }

    /// <summary>
    /// Returns one privacy-safe Recovery v1 timeline under mono-product/global analytics authorization.
    /// </summary>
    [McpServerTool]
    [Description("Get one ordered Recovery v1 support timeline and its derived incomplete/completed/failed/cancelled status. Mono-product keys need no selector; global keys must select one exact product.")]
    public async Task<JsonElement> GetRecoveryTimeline(
        [Description("Canonical lowercase Recovery run UUID in D form.")] string recoveryRunId,
        [Description("Optional exact product UUID. Required for a global key when productName is omitted.")] string? productId = null,
        [Description("Optional exact product name. Required for a global key when productId is omitted.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalUuid(recoveryRunId, nameof(recoveryRunId));
        if (productId is not null) ValidateCanonicalUuid(productId, nameof(productId));
        return await _client.GetRecoveryTimelineAsync(recoveryRunId, productId, productName, cancellationToken);
    }

    /// <summary>
    /// Returns bounded Recovery v1 rejection evidence without payloads, customer identity, machine identity, or free text.
    /// </summary>
    [McpServerTool]
    [Description("List bounded product-scoped Recovery v1 ingestion rejections. Returned rows contain only valid opaque identifiers, a closed code, correlation ID, and server receive time.")]
    public async Task<JsonElement> GetRecoveryRejections(
        [Description("Optional canonical lowercase Recovery run UUID in D form.")] string? recoveryRunId = null,
        [Description("Maximum rows, clamped from 1 to 200.")] int take = 100,
        [Description("Optional exact product UUID. Required for a global key when productName is omitted.")] string? productId = null,
        [Description("Optional exact product name. Required for a global key when productId is omitted.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (recoveryRunId is not null) ValidateCanonicalUuid(recoveryRunId, nameof(recoveryRunId));
        if (productId is not null) ValidateCanonicalUuid(productId, nameof(productId));
        return await _client.GetRecoveryRejectionsAsync(recoveryRunId, Math.Clamp(take, 1, 200), productId, productName, cancellationToken);
    }

    [McpServerTool]
    [Description("Get metadata for a complete oversized MCP result artifact. Artifact IDs are opaque values returned by other SoftLicence MCP tools.")]
    public JsonElement GetMcpResultArtifactInfo(
        [Description("Opaque artifactId returned by an oversized SoftLicence MCP response.")] string artifactId)
    {
        return _resultStore.GetInfo(artifactId);
    }

    [McpServerTool]
    [Description("Read a bounded text chunk from a complete oversized MCP JSON result. Concatenate chunks in offset order to reconstruct the exact original JSON without truncation.")]
    public JsonElement GetMcpResultArtifactChunk(
        [Description("Opaque artifactId returned by an oversized SoftLicence MCP response.")] string artifactId,
        [Description("UTF-16 character offset. Start with 0 and then use nextOffset until hasMore is false.")] int offset = 0,
        [Description("Chunk size from artifact metadata. Omit it or pass 0 to use the default; pass the exact value from metadata to use a fixed chunk size.")] int length = 0)
    {
        return _resultStore.GetChunk(artifactId, offset, length == 0 ? null : length);
    }

    [McpServerTool]
    [Description("Get a compact read-only overview of SoftLicence telemetry activity. Defaults to the configured product; pass productId or productName only when the key is authorized for that product.")]
    public async Task<JsonElement> GetTelemetryOverview(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional. Overrides days when provided.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryOverviewAsync(
            ClampDays(days),
            ClampTop(top),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List unique telemetry devices/HardwareIds for a SoftLicence product over a bounded period.")]
    public async Task<JsonElement> GetTelemetryDevices(
        [Description("Time window in days. Clamped from 1 to 30. Ignored when date or fromUtc/toUtc is provided.")] int days = 7,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("Maximum number of returned devices. Clamped from 1 to 500.")] int take = 100,
        [Description("Maximum number of top events/families per device. Clamped from 1 to 20.")] int topEvents = 5,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryDevicesAsync(
            ClampDays(days),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            Math.Clamp(take, 1, 500),
            Math.Clamp(topEvents, 1, 20),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get telemetry schema drift and property-key summary without exposing raw properties.")]
    public async Task<JsonElement> GetTelemetrySchemaSummary(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of events. Clamped from 1 to 100.")] int topEvents = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetrySchemaSummaryAsync(
            ClampDays(days),
            ClampTop(topEvents),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get MCP/Copilot/API tool usage analytics for the configured product.")]
    public async Task<JsonElement> GetTelemetryToolUsage(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryToolUsageAsync(
            ClampDays(days),
            ClampTop(top),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get quota usage summary for API, MCP, and Copilot telemetry.")]
    public async Task<JsonElement> GetTelemetryQuotaSummary(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryQuotaSummaryAsync(
            ClampDays(days),
            ClampTop(top),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get startup health analytics such as startup status, checks, license editions, and TIA versions.")]
    public async Task<JsonElement> GetTelemetryStartupHealth(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryStartupHealthAsync(
            ClampDays(days),
            ClampTop(top),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get certificate pinning incident analytics without raw secret material.")]
    public async Task<JsonElement> GetTelemetryCertPinningSummary(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryCertPinningSummaryAsync(
            ClampDays(days),
            ClampTop(top),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get activation funnel analytics combining license lifecycle and access logs.")]
    public async Task<JsonElement> GetTelemetryActivationFunnel(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryActivationFunnelAsync(
            ClampDays(days),
            ClampTop(top),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get recent license activation failures with full customer email when a license can be matched, plus status, reason, machine, IP, and inferred client version. License keys are never returned.")]
    public async Task<JsonElement> GetActivationFailures(
        [Description("Time window in days. Clamped from 1 to 30. Ignored when date or fromUtc/toUtc is provided.")] int days = 7,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("Exact HardwareId filter. Optional.")] string? hardwareId = null,
        [Description("Exact failure status filter, such as BAD_REQUEST, INVALID_KEY, REVOKED, or FORBIDDEN. Optional.")] string? status = null,
        [Description("Maximum number of returned failures. Clamped from 1 to 50.")] int take = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetActivationFailuresAsync(
            ClampDays(days),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            NormalizeOptional(hardwareId),
            NormalizeOptional(status),
            Math.Clamp(take, 1, 50),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get a redacted support profile for a single HardwareId, including a short recent telemetry timeline.")]
    public async Task<JsonElement> GetTelemetryMachineProfile(
        [Description("HardwareId to inspect. Required.")] string hardwareId,
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Maximum number of recent records. Clamped from 1 to 50.")] int take = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            throw new ArgumentException("hardwareId is required.", nameof(hardwareId));

        return await _client.GetTelemetryMachineProfileAsync(
            hardwareId.Trim(),
            ClampDays(days),
            ClampTop(top),
            Math.Clamp(take, 1, 50),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get version health and compact errors summary for regression detection.")]
    public async Task<JsonElement> GetTelemetryVersionHealth(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of grouped items. Clamped from 1 to 100.")] int top = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryVersionHealthAsync(
            ClampDays(days),
            ClampTop(top),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Find a read-only support telemetry profile by HardwareId, email/email fragment, license-key fragment, or client IP. Customer emails are returned in full for authenticated analytics calls; license keys remain redacted. HardwareId accepts full IDs and fragments of 6+ characters.")]
    public async Task<JsonElement> GetSupportTelemetryProfile(
        [Description("HardwareId to inspect. Full IDs are exact; values of 6+ characters can also match prefixes/fragments when no exact match exists. Optional when another lookup field is provided.")] string? hardwareId = null,
        [Description("Email or email substring. Optional. Prefer emailFragment for partial searches.")] string? email = null,
        [Description("Email fragment, minimum 3 characters. Optional.")] string? emailFragment = null,
        [Description("License-key fragment, minimum 6 non-separator characters. Optional. Full keys are not returned.")] string? licenseFragment = null,
        [Description("Exact client IP address, IPv4 or IPv6. Optional. IPv6 is URL-encoded and never split on colon.")] string? clientIp = null,
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Maximum number of recent records in the resolved machine profile. Clamped from 1 to 50.")] int take = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hardwareId)
            && string.IsNullOrWhiteSpace(email)
            && string.IsNullOrWhiteSpace(emailFragment)
            && string.IsNullOrWhiteSpace(licenseFragment)
            && string.IsNullOrWhiteSpace(clientIp))
        {
            throw new ArgumentException("At least one lookup field is required.");
        }

        return await _client.GetSupportTelemetryProfileAsync(
            NormalizeOptional(hardwareId),
            NormalizeOptional(email),
            NormalizeOptional(emailFragment),
            NormalizeOptional(licenseFragment),
            NormalizeOptional(clientIp),
            ClampDays(days),
            Math.Clamp(take, 1, 50),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get a global read-only customer/license investigation timeline by email, HardwareId, licenseId, or license-key fragment. Generic for any customer; returns full internal emails/HWIDs, redacted license keys, per-HWID summaries, license/seat/update/access-log events, and explicitly distinguishes Update_RevokeLicense local clears from server-side seat unlink traces.")]
    public async Task<JsonElement> GetCustomerLicenseTimeline(
        [Description("Customer email. Optional when another lookup field is provided.")] string? email = null,
        [Description("Customer email fragment, minimum 3 characters. Optional.")] string? emailFragment = null,
        [Description("HardwareId to inspect. Full IDs are exact; 6+ character hex fragments can match partial HWIDs. Optional.")] string? hardwareId = null,
        [Description("License UUID. Optional.")] string? licenseId = null,
        [Description("License-key fragment or first segment, minimum 6 non-separator characters. Full license keys are never returned. Optional.")] string? licenseFragment = null,
        [Description("Time window in days. Accepted from 1 to 90; windows above 30 days are automatically split into safe server segments. Ignored when date or fromUtc/toUtc is provided.")] int days = 30,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Ranges up to 90 days are automatically split into safe server segments. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Ranges up to 90 days are automatically split into safe server segments. Optional.")] string? toUtc = null,
        [Description("Maximum number of timeline items returned. Clamped from 1 to 500.")] int takeTimeline = 150,
        [Description("Timeline offset for pagination. Minimum 0.")] int offset = 0,
        [Description("Include activation/update HTTP access logs when available.")] bool includeAccessLogs = true,
        [Description("Include noisy heartbeat/UI events. Default false.")] bool includeNoise = false,
        [Description("When true, keep the timeline focused on license/support/security/update events.")] bool importantOnly = true,
        [Description("Include redacted event properties instead of only property-key summaries. Default true for internal investigations.")] bool includeProperties = true,
        [Description("Output mode: summary, timeline, or full.")] string? mode = "timeline",
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email)
            && string.IsNullOrWhiteSpace(emailFragment)
            && string.IsNullOrWhiteSpace(hardwareId)
            && string.IsNullOrWhiteSpace(licenseId)
            && string.IsNullOrWhiteSpace(licenseFragment))
        {
            throw new ArgumentException("At least one lookup field is required.");
        }

        return await _client.GetCustomerLicenseTimelineAsync(
            NormalizeOptional(email),
            NormalizeOptional(emailFragment),
            NormalizeOptional(hardwareId),
            NormalizeOptional(licenseId),
            NormalizeOptional(licenseFragment),
            Math.Max(1, days),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            Math.Clamp(takeTimeline, 1, 500),
            Math.Max(0, offset),
            includeAccessLogs,
            includeNoise,
            importantOnly,
            includeProperties,
            NormalizeTimelineMode(mode),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get a small bounded redacted sample of raw telemetry records for investigation.")]
    public async Task<JsonElement> GetTelemetryRawSample(
        [Description("Time window in days. Clamped from 1 to 30. Ignored when date or fromUtc/toUtc is provided.")] int days = 7,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("HardwareId exact value, prefix, or fragment of 6+ characters. Optional. Full IDs can match legacy/truncated stored values.")] string? hardwareId = null,
        [Description("Exact event name filter. Optional.")] string? eventName = null,
        [Description("Event family filter such as mcp, startup, api, compile, cert-pinning. Optional.")] string? eventFamily = null,
        [Description("Exact app version filter. Optional.")] string? version = null,
        [Description("Telemetry type filter: Event, Diagnostic, or Error. Optional.")] string? type = null,
        [Description("Maximum number of returned records. Clamped from 1 to 50.")] int take = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryRawSampleAsync(
            ClampDays(days),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            NormalizeOptional(hardwareId),
            NormalizeOptional(eventName),
            NormalizeOptional(eventFamily),
            NormalizeOptional(version),
            NormalizeOptional(type),
            Math.Clamp(take, 1, 50),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List deterministic telemetry flood suppressions for a product. Use this to see which repeated event groups are no longer written as raw telemetry rows.")]
    public async Task<JsonElement> GetTelemetryFloodSuppressions(
        [Description("Time window in days. Clamped from 1 to 30.")] int days = 7,
        [Description("Optional HardwareId exact value or prefix filter. Returned HardwareIds are redacted.")] string? hardwareId = null,
        [Description("Optional exact event name filter, for example NativeExtractionFailed.")] string? eventName = null,
        [Description("Maximum number of suppression groups. Clamped from 1 to 100.")] int take = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryFloodSuppressionsAsync(
            ClampDays(days),
            NormalizeOptional(hardwareId),
            NormalizeOptional(eventName),
            Math.Clamp(take, 1, 100),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get compact telemetry alerts and insights such as high quotas, startup failures, auth failures, cert pinning failures, and version regressions.")]
    public async Task<JsonElement> GetTelemetryInsights(
        [Description("Time window in days. Clamped from 1 to 30. Ignored when date or fromUtc/toUtc is provided.")] int days = 7,
        [Description("Maximum number of insights. Clamped from 1 to 100.")] int top = 20,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryInsightsAsync(
            ClampDays(days),
            ClampTop(top),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Analyze read-only impact of shortening a Freemium/Trial license duration by crossing active licenses with recent telemetry. Returns aggregates by default and only redacted bounded samples when requested.")]
    public async Task<JsonElement> GetLicenseDurationMigrationImpact(
        [Description("License type slug or name. Default: TIA-CONNECT-FREEMIUM.")] string? licenseType = "TIA-CONNECT-FREEMIUM",
        [Description("Current duration in days. Default: 30.")] int currentDurationDays = 30,
        [Description("Target duration in days. Default: 7.")] int targetDurationDays = 7,
        [Description("Comma-separated activity windows in days. Default: 1,3,7.")] string? activityWindowsDays = "1,3,7",
        [Description("Return redacted bounded candidate samples. Default: false.")] bool includeSamples = false,
        [Description("Maximum number of returned samples. Clamped from 1 to 50.")] int sampleLimit = 30,
        [Description("Maximum number of top telemetry events. Clamped from 1 to 100.")] int topEvents = 20,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        currentDurationDays = Math.Clamp(currentDurationDays, 1, 3650);
        targetDurationDays = Math.Clamp(targetDurationDays, 1, currentDurationDays);

        return await _client.GetLicenseDurationMigrationImpactAsync(
            NormalizeOptional(licenseType),
            currentDurationDays,
            targetDurationDays,
            NormalizeActivityWindows(activityWindowsDays),
            includeSamples,
            Math.Clamp(sampleLimit, 1, 50),
            ClampTop(topEvents),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Rank Freemium licenses/machines by telemetry activity and conversion potential, with license status filters. Customer emails are returned in full for authenticated analytics calls; license keys and hardware IDs remain redacted/hash-based.")]
    public async Task<JsonElement> GetFreemiumActivityRanking(
        [Description("License type slug or name. Default: TIA-CONNECT-FREEMIUM.")] string? licenseType = "TIA-CONNECT-FREEMIUM",
        [Description("License status filter: active, expired, revoked, expired_or_revoked, or all. Default: active.")] string? status = "active",
        [Description("Telemetry window in days. Clamped from 1 to 30.")] int telemetryDays = 7,
        [Description("Minimum activation age in days. Use 0 for no minimum. Example: 7.")] int activationAgeMinDays = 0,
        [Description("Maximum activation age in days. Use 0 for no maximum. Example: 30.")] int activationAgeMaxDays = 0,
        [Description("Include up to 10 recent redacted event samples per ranked machine. Default: false.")] bool includeSamples = false,
        [Description("Maximum number of ranked machines returned. Clamped from 1 to 100.")] int take = 50,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetFreemiumActivityRankingAsync(
            NormalizeOptional(licenseType),
            NormalizeStatus(status),
            ClampDays(telemetryDays),
            NormalizeAge(activationAgeMinDays),
            NormalizeAge(activationAgeMaxDays),
            includeSamples,
            Math.Clamp(take, 1, 100),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Rank paid/non-Freemium licenses and machines by telemetry activity, engagement, and retention risk. Excludes free/freemium/trial types by default. Customer emails are returned in full for authenticated analytics calls; license keys and hardware IDs remain redacted/hash-based.")]
    public async Task<JsonElement> GetPaidActivityRanking(
        [Description("Optional comma-separated license type slugs or names. Empty means all paid/non-Freemium types. Use get_license_types to discover slugs.")] string? licenseTypes = null,
        [Description("License status filter: active, expired, revoked, expired_or_revoked, or all. Default: active.")] string? status = "active",
        [Description("Telemetry window in days. Clamped from 1 to 30.")] int telemetryDays = 7,
        [Description("Minimum activation age in days. Use 0 for no minimum. Example: 30.")] int activationAgeMinDays = 0,
        [Description("Maximum activation age in days. Use 0 for no maximum. Example: 365.")] int activationAgeMaxDays = 0,
        [Description("Include up to 10 recent redacted event samples per ranked machine. Default: false.")] bool includeSamples = false,
        [Description("Maximum number of ranked machines returned. Clamped from 1 to 100.")] int take = 50,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetPaidActivityRankingAsync(
            NormalizeLicenseTypes(licenseTypes),
            NormalizeStatus(status),
            ClampDays(telemetryDays),
            NormalizeAge(activationAgeMinDays),
            NormalizeAge(activationAgeMaxDays),
            includeSamples,
            Math.Clamp(take, 1, 100),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List available license type slugs for a SoftLicence product with active, expired, revoked, and total license counts.")]
    public async Task<JsonElement> GetLicenseTypes(
        [Description("Include free/Freemium/trial license types. Default: true. Set false to list only paid/non-Freemium types.")] bool includeFree = true,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetLicenseTypesAsync(
            includeFree,
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get read-only onboarding Time-To-Value metrics for the most recent licenses, with redacted emails, hardware IDs, and no license keys.")]
    public async Task<JsonElement> GetLicenseOnboardingMetrics(
        [Description("Maximum number of recent licenses returned. Clamped from 1 to 100. Default: 10.")] int take = 10,
        [Description("License type group: paid, freemium, or all. Default: paid.")] string? licenseType = "paid",
        [Description("License status filter: active, expired, revoked, not_activated, expired_or_revoked, or all. Default: active.")] string? status = "active",
        [Description("Maximum activation/onboarding age in days. Use 0 for no maximum.")] int activationAgeMaxDays = 0,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetRecentLicenseOnboardingMetricsAsync(
            Math.Clamp(take, 1, 100),
            NormalizeOnboardingLicenseType(licenseType),
            NormalizeOnboardingStatus(status),
            NormalizeAge(activationAgeMaxDays),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Score license usage, trial conversion potential, retention confidence, and churn risk. Read-only, bounded, and redacted.")]
    public async Task<JsonElement> GetLicenseUsageScores(
        [Description("Maximum number of licenses returned. Clamped from 1 to 100. Default: 50.")] int take = 50,
        [Description("License type group: paid, freemium, trial, subscription, or all. Default: paid.")] string? licenseType = "paid",
        [Description("License status filter: active, expired, revoked, not_activated, expired_or_revoked, or all. Default: active.")] string? status = "active",
        [Description("Maximum activation/onboarding age in days. Use 0 for no maximum.")] int activationAgeMaxDays = 0,
        [Description("Recent activity window in days. Clamped from 1 to 90. Default: 14.")] int activityWindowDays = 14,
        [Description("Minimum score across usage/conversion/retention. Clamped from 0 to 100. Use 0 for no minimum.")] double minScore = 0,
        [Description("Include inactive licenses in addition to the status filter. Default: false.")] bool includeInactive = false,
        [Description("Sort field: score, conversionPotential, retentionConfidence, or recentActivity. Default: score.")] string? sortBy = "score",
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetLicenseUsageScoresAsync(
            Math.Clamp(take, 1, 100),
            NormalizeUsageLicenseType(licenseType),
            NormalizeOnboardingStatus(status),
            NormalizeAge(activationAgeMaxDays),
            Math.Clamp(activityWindowDays, 1, 90),
            minScore > 0 ? Math.Clamp(minScore, 0, 100) : null,
            includeInactive,
            NormalizeUsageSort(sortBy),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Audit telemetry HardwareIds against effective license validity. Returns aggregate windows and redacted anomalies only.")]
    public async Task<JsonElement> GetTelemetryLicenseHardwareAudit(
        [Description("Telemetry window in days. Clamped from 1 to 30. Ignored when date or fromUtc/toUtc is provided.")] int days = 7,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("Comma-separated activity windows in days. Default: 1,3,7,30.")] string? activityWindowsDays = "1,3,7,30",
        [Description("Maximum number of returned redacted anomalies. Clamped from 1 to 100.")] int take = 50,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetTelemetryLicenseHardwareAuditAsync(
            ClampDays(days),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            NormalizeActivityWindows(activityWindowsDays),
            Math.Clamp(take, 1, 100),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Score probable Freemium abuse groups by email domain, HWID, IP, telemetry volume, productive usage, quotas, and expired/revoked license activity. Read-only and redacted.")]
    public async Task<JsonElement> GetFreemiumAbuseRisk(
        [Description("License type slug or name. Default: TIA-CONNECT-FREEMIUM.")] string? licenseType = "TIA-CONNECT-FREEMIUM",
        [Description("Telemetry window in days. Clamped from 1 to 30. Ignored when date or fromUtc/toUtc is provided.")] int days = 7,
        [Description("Explicit UTC calendar day in YYYY-MM-DD format. Optional.")] string? date = null,
        [Description("Explicit UTC range start. Must be provided with toUtc. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Must be provided with fromUtc. Optional.")] string? toUtc = null,
        [Description("Maximum number of returned groups. Clamped from 1 to 100.")] int take = 50,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetFreemiumAbuseRiskAsync(
            NormalizeOptional(licenseType),
            ClampDays(days),
            NormalizeOptional(date),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            Math.Clamp(take, 1, 100),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List and aggregate the unified SoftLicence security feed: client Canary alerts plus server-side incidents such as BinaryPatched, with repeat counts, first/last detection, machine context, evidence counts and ban status. Results are bounded and require an authorized analytics key.")]
    public async Task<JsonElement> ListSecurityCanaryAlerts(
        [Description("Explicit UTC range start. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Optional.")] string? toUtc = null,
        [Description("Trigger filter, for example IntegrityCheck_Startup or RuntimeCheck_Debugger.")] string? trigger = null,
        [Description("Severity filter: 0=all, 1=Info, 2=Warning, 3=Critical.")] int severity = 0,
        [Description("HardwareId exact value or fragment.")] string? hardwareId = null,
        [Description("Machine-name fragment.")] string? machine = null,
        [Description("Windows user-name fragment.")] string? user = null,
        [Description("Exact client IP.")] string? clientIp = null,
        [Description("Exact app version.")] string? version = null,
        [Description("Filter alerts by active hardware-ban state: empty string for any, 'true' for banned only, 'false' for not banned.")] string isBanFilter = "",
        [Description("Maximum groups returned. Clamped from 1 to 200.")] int take = 50,
        [Description("Pagination offset. Minimum 0.")] int offset = 0,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (severity != 0 && severity is < 1 or > 3)
            throw new ArgumentException("severity must be 0 (all), 1, 2, or 3.", nameof(severity));

        bool? isBanned = isBanFilter.ToLowerInvariant() switch { "true" => true, "false" => false, _ => null };
        return await _client.ListSecurityCanaryAlertsAsync(
            NormalizeOptional(fromUtc), NormalizeOptional(toUtc), NormalizeOptional(trigger), severity == 0 ? null : severity,
            NormalizeOptional(hardwareId), NormalizeOptional(machine), NormalizeOptional(user),
            NormalizeOptional(clientIp), NormalizeOptional(version), isBanned,
            Math.Clamp(take, 1, 200), Math.Max(0, offset),
            NormalizeOptional(productId), NormalizeOptional(productName), cancellationToken);
    }

    [McpServerTool]
    [Description("Get full authorized details for one unified security item, including Canary context or server-incident evidence and associated hardware/component bans.")]
    public async Task<JsonElement> GetSecurityCanaryAlertDetails(
        [Description("Unified security item UUID returned by list_security_canary_alerts.")] string alertId,
        [Description("Optional product UUID. Required with a global analytics key.")] string? productId = null,
        [Description("Optional exact product name. Required with a global analytics key when productId is omitted.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(NormalizeOptional(alertId), out var parsed))
            throw new ArgumentException("alertId must be a valid UUID.", nameof(alertId));
        return await _client.GetSecurityCanaryAlertDetailsAsync(
            parsed, NormalizeOptional(productId), NormalizeOptional(productName), cancellationToken);
    }

    [McpServerTool]
    [Description("Get read-only security ban status for a HWID, component hash/type, client IP, email fragment, or license fragment. Returns redacted bounded ban records.")]
    public async Task<JsonElement> GetSecurityBanStatus(
        [Description("HardwareId or fragment to inspect. Optional when another lookup field is provided.")] string? hardwareId = null,
        [Description("Component hash or hash fragment to inspect. Optional.")] string? componentHash = null,
        [Description("Component type such as FP_EXE, FP_DLL, FP_CORE, FP_MB, FP_CPU, MB, CPU, BIOS, DISK, HOST. Optional.")] string? componentType = null,
        [Description("Exact client IP to resolve to recent HWIDs. Optional.")] string? clientIp = null,
        [Description("Email fragment used to resolve license HWIDs. Optional.")] string? emailFragment = null,
        [Description("License-key fragment used to resolve license HWIDs. Optional. Full keys are not returned.")] string? licenseFragment = null,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        EnsureSecurityBanLookup(hardwareId, componentHash, componentType, clientIp, emailFragment, licenseFragment);
        return await _client.ListSecurityBansAsync(
            NormalizeOptional(hardwareId),
            NormalizeOptional(componentHash),
            NormalizeOptional(componentType),
            NormalizeOptional(clientIp),
            NormalizeOptional(emailFragment),
            NormalizeOptional(licenseFragment),
            includeInactive: false,
            take: 25,
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List read-only security bans with filters. Use includeInactive for historical audit. Results are bounded and redacted.")]
    public async Task<JsonElement> ListSecurityBans(
        [Description("HardwareId or fragment to inspect. Optional.")] string? hardwareId = null,
        [Description("Component hash or hash fragment to inspect. Optional.")] string? componentHash = null,
        [Description("Component type filter. Optional.")] string? componentType = null,
        [Description("Exact client IP to resolve to recent HWIDs. Optional.")] string? clientIp = null,
        [Description("Email fragment used to resolve license HWIDs. Optional.")] string? emailFragment = null,
        [Description("License-key fragment used to resolve license HWIDs. Optional.")] string? licenseFragment = null,
        [Description("Include inactive/expired/unbanned rows. Default: false.")] bool includeInactive = false,
        [Description("Maximum number of records. Clamped from 1 to 100.")] int take = 25,
        [Description("Optional product UUID. Mono-product keys may only request their configured product.")] string? productId = null,
        [Description("Optional exact product name. Use list_products first when unsure.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.ListSecurityBansAsync(
            NormalizeOptional(hardwareId),
            NormalizeOptional(componentHash),
            NormalizeOptional(componentType),
            NormalizeOptional(clientIp),
            NormalizeOptional(emailFragment),
            NormalizeOptional(licenseFragment),
            includeInactive,
            Math.Clamp(take, 1, 100),
            cancellationToken,
            NormalizeOptional(productId),
            NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List the unified security blacklist overview for HWID and component/fingerprint bans, including active and historical entries.")]
    public async Task<JsonElement> ListSecurityBlacklistOverview(
        [Description("HardwareId or fragment.")] string? hardwareId = null,
        [Description("Component hash or fragment.")] string? componentHash = null,
        [Description("Component type such as FP_EXE, FP_DLL, FP_CORE, CPU, MB, BIOS, DISK, HOST.")] string? componentType = null,
        [Description("Include inactive, expired and lifted entries.")] bool includeInactive = true,
        [Description("Maximum rows. Clamped from 1 to 100.")] int take = 100,
        [Description("Optional product UUID.")] string? productId = null,
        [Description("Optional exact product name.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.ListSecurityBansAsync(
            NormalizeOptional(hardwareId), NormalizeOptional(componentHash), NormalizeOptional(componentType),
            clientIp: null, emailFragment: null, licenseFragment: null, includeInactive,
            Math.Clamp(take, 1, 100), cancellationToken,
            NormalizeOptional(productId), NormalizeOptional(productName), includeSourceEvents: true);
    }

    [McpServerTool]
    [Description("Build a bounded read-only security case snapshot combining Canary alerts with HWID and component blacklists. Provide at least one lookup field.")]
    public async Task<JsonElement> GetSecurityCaseSnapshot(
        [Description("Optional BugTrace ticket reference, for example TKT-999610.")] string? ticketRef = null,
        [Description("Optional stable security-case identifier.")] string? securityCaseId = null,
        [Description("HardwareId or fragment to correlate across Canary and ban records.")] string? hardwareId = null,
        [Description("Component hash or fragment.")] string? componentHash = null,
        [Description("Component type such as FP_EXE, FP_DLL, FP_CORE, CPU, MB, BIOS, DISK, or HOST.")] string? componentType = null,
        [Description("Exact client IP.")] string? clientIp = null,
        [Description("Customer email fragment. The returned snapshot does not expose the full license key.")] string? emailFragment = null,
        [Description("License-key fragment. Never provide a full license key unless operationally required.")] string? licenseFragment = null,
        [Description("Include historical inactive bans.")] bool includeInactive = true,
        [Description("Maximum rows per section. Clamped from 1 to 100.")] int take = 50,
        [Description("Optional product UUID.")] string? productId = null,
        [Description("Optional exact product name.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ticketRef) && string.IsNullOrWhiteSpace(securityCaseId))
            EnsureSecurityBanLookup(hardwareId, componentHash, componentType, clientIp, emailFragment, licenseFragment);
        return await _client.GetSecurityCaseSnapshotAsync(
            NormalizeOptional(ticketRef), NormalizeOptional(securityCaseId), NormalizeOptional(hardwareId), NormalizeOptional(componentHash),
            NormalizeOptional(componentType), NormalizeOptional(clientIp), NormalizeOptional(emailFragment),
            NormalizeOptional(licenseFragment), includeInactive, Math.Clamp(take, 1, 100),
            NormalizeOptional(productId), NormalizeOptional(productName), cancellationToken);
    }

    [McpServerTool]
    [Description("Get read-only details for a security ban by ban id, including source-event status when available.")]
    public async Task<JsonElement> GetSecurityBanDetails(
        [Description("Ban UUID returned by list_security_bans/get_security_ban_status.")] string banId,
        [Description("Optional product UUID. Required with a global analytics key.")] string? productId = null,
        [Description("Optional exact product name. Required with a global analytics key when productId is omitted.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(NormalizeOptional(banId), out var parsed))
            throw new ArgumentException("banId must be a valid UUID.", nameof(banId));

        return await _client.GetSecurityBanDetailsAsync(
            parsed, cancellationToken, NormalizeOptional(productId), NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("Get the source telemetry event for a security ban when SoftLicence can infer one from persisted telemetry.")]
    public async Task<JsonElement> GetSecurityBanSourceEvent(
        [Description("Ban UUID returned by list_security_bans/get_security_ban_status.")] string banId,
        [Description("Optional product UUID. Required with a global analytics key.")] string? productId = null,
        [Description("Optional exact product name. Required with a global analytics key when productId is omitted.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(NormalizeOptional(banId), out var parsed))
            throw new ArgumentException("banId must be a valid UUID.", nameof(banId));

        return await _client.GetSecurityBanSourceEventAsync(
            parsed, cancellationToken, NormalizeOptional(productId), NormalizeOptional(productName));
    }

    [McpServerTool]
    [Description("List supported SoftLicence hardware-ban categories for MCP write tools. This does not require write credentials.")]
    public JsonElement GetSecurityHardwareBanCategories()
    {
        return _client.GetSecurityHardwareBanCategories();
    }

    [McpServerTool]
    [Description("Create or reactivate a SoftLicence hardware-id ban through the admin API. Requires SOFTLICENCE_ADMIN_SECRET, separate from the read-only analytics key. Returns mutation result plus post-mutation verification.")]
    public async Task<JsonElement> CreateSecurityHardwareBan(
        [Description("HardwareId to ban. Required.")] string hardwareId,
        [Description("Ban reason. Required and stored in audit history.")] string reason,
        [Description("Ban category: manual, piracy, debugger, outdated_version, quota_abuse, dev_canary_quarantine.")] string? category = "manual",
        [Description("Optional product UUID. Omit to ban for all products.")] string? productId = null,
        [Description("Optional exact product name used only for post-mutation verification with a global analytics key.")] string? productName = null,
        [Description("Optional UTC expiration timestamp. Use either expiresAt or durationDays, not both.")] string? expiresAt = null,
        [Description("Optional duration in days for a temporary ban. Use either expiresAt or durationDays, not both. Use 0 for permanent.")] int durationDays = 0,
        [Description("Optional BugTrace ticket reference for audit, for example TKT-999381.")] string? ticketRef = null,
        [Description("Optional stable security-case identifier.")] string? securityCaseId = null,
        [Description("Optional actor name for audit.")] string? createdBy = "Codex MCP",
        [Description("Optional compact audit note. Do not include secrets.")] string? auditNote = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            throw new ArgumentException("hardwareId is required.", nameof(hardwareId));
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("reason is required.", nameof(reason));
        if (!string.IsNullOrWhiteSpace(expiresAt) && durationDays > 0)
            throw new ArgumentException("Use either expiresAt or durationDays, not both.");

        return await _client.CreateSecurityHardwareBanAsync(
            hardwareId.Trim(),
            reason.Trim(),
            NormalizeHardwareBanCategory(category),
            NormalizeOptional(productId),
            NormalizeOptional(productName),
            NormalizeOptional(expiresAt),
            durationDays > 0 ? Math.Clamp(durationDays, 1, 3650) : null,
            NormalizeOptional(ticketRef),
            NormalizeOptional(securityCaseId),
            NormalizeOptional(createdBy),
            NormalizeOptional(auditNote),
            cancellationToken);
    }

    [McpServerTool]
    [Description("Deactivate a SoftLicence hardware-id ban by banId through the admin API. Requires SOFTLICENCE_ADMIN_SECRET, separate from the read-only analytics key. Returns mutation result plus post-mutation verification.")]
    public async Task<JsonElement> UnbanSecurityHardwareBan(
        [Description("Ban UUID returned by list_security_bans/get_security_ban_status.")] string banId,
        [Description("Explicit operator reason for lifting the ban. Required.")] string reason,
        [Description("Optional product UUID. Required with a global analytics key for post-mutation verification.")] string? productId = null,
        [Description("Optional exact product name. Required with a global analytics key when productId is omitted.")] string? productName = null,
        [Description("Optional BugTrace ticket reference for audit, for example TKT-999381.")] string? ticketRef = null,
        [Description("Optional stable security-case identifier.")] string? securityCaseId = null,
        [Description("Optional actor name for audit.")] string? createdBy = "Codex MCP",
        [Description("Optional compact audit note. Do not include secrets.")] string? auditNote = null,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(NormalizeOptional(banId), out var parsed))
            throw new ArgumentException("banId must be a valid UUID.", nameof(banId));
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("reason is required.", nameof(reason));

        return await _client.UnbanSecurityHardwareBanAsync(
            parsed,
            NormalizeOptional(productId),
            NormalizeOptional(productName),
            reason.Trim(),
            NormalizeOptional(ticketRef),
            NormalizeOptional(securityCaseId),
            NormalizeOptional(createdBy),
            NormalizeOptional(auditNote),
            cancellationToken);
    }

    [McpServerTool]
    [Description("Create or reactivate an enforceable SoftLicence release-binary fingerprint ban through the admin API. Only FP_EXE, FP_DLL and FP_CORE are enforceable. Hardware fingerprints are correlation-only; the server refuses them and returns impact/cardinality details. Requires SOFTLICENCE_ADMIN_SECRET and returns post-mutation verification.")]
    public async Task<JsonElement> CreateSecurityComponentBan(
        [Description("Enforceable component type: FP_EXE, FP_DLL or FP_CORE. CPU, MB, BIOS, DISK and HOST are correlation-only and cannot be globally banned.")] string componentType,
        [Description("Exact component hash.")] string componentHash,
        [Description("Audit reason. Required.")] string reason,
        [Description("Optional audit category, for example integrity, piracy, debugger, or manual.")] string? category = "integrity",
        [Description("Optional product UUID.")] string? productId = null,
        [Description("Optional exact product name used only for post-mutation verification with a global analytics key.")] string? productName = null,
        [Description("Optional UTC expiration timestamp. Use either expiresAt or durationDays.")] string? expiresAt = null,
        [Description("Optional duration in days. Use either expiresAt or durationDays. Use 0 for permanent.")] int durationDays = 0,
        [Description("Optional BugTrace ticket reference.")] string? ticketRef = null,
        [Description("Optional stable security-case identifier.")] string? securityCaseId = null,
        [Description("Optional actor name.")] string? createdBy = "Codex MCP",
        [Description("Optional compact audit note. Do not include secrets.")] string? auditNote = null,
        CancellationToken cancellationToken = default)
    {
        var type = NormalizeComponentType(componentType);
        var hash = NormalizeOptional(componentHash)?.ToLowerInvariant();
        if (hash == null) throw new ArgumentException("componentHash is required.", nameof(componentHash));
        if (hash.Length != 64 || hash.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new ArgumentException("componentHash must be exactly 64 ASCII hexadecimal characters.", nameof(componentHash));
        if (string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("reason is required.", nameof(reason));
        if (!string.IsNullOrWhiteSpace(expiresAt) && durationDays > 0)
            throw new ArgumentException("Use either expiresAt or durationDays, not both.");

        return await _client.CreateSecurityComponentBanAsync(
            type, hash, reason.Trim(), NormalizeOptional(category), NormalizeOptional(productId), NormalizeOptional(productName), NormalizeOptional(expiresAt),
            durationDays > 0 ? Math.Clamp(durationDays, 1, 3650) : null,
            NormalizeOptional(ticketRef), NormalizeOptional(securityCaseId), NormalizeOptional(createdBy), NormalizeOptional(auditNote),
            cancellationToken);
    }

    [McpServerTool]
    [Description("Deactivate a SoftLicence component/fingerprint ban by id. Requires SOFTLICENCE_ADMIN_SECRET and returns post-mutation verification.")]
    public async Task<JsonElement> UnbanSecurityComponentBan(
        [Description("Ban UUID.")] string banId,
        [Description("Explicit operator reason for lifting the ban. Required.")] string reason,
        [Description("Optional product UUID. Required with a global analytics key.")] string? productId = null,
        [Description("Optional exact product name.")] string? productName = null,
        [Description("Optional BugTrace ticket reference.")] string? ticketRef = null,
        [Description("Optional stable security-case identifier.")] string? securityCaseId = null,
        [Description("Optional actor name.")] string? createdBy = "Codex MCP",
        [Description("Optional compact audit note.")] string? auditNote = null,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(NormalizeOptional(banId), out var parsed))
            throw new ArgumentException("banId must be a valid UUID.", nameof(banId));
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("reason is required.", nameof(reason));
        return await _client.UnbanSecurityComponentBanAsync(
            parsed, NormalizeOptional(productId), NormalizeOptional(productName),
            reason.Trim(), NormalizeOptional(ticketRef), NormalizeOptional(securityCaseId), NormalizeOptional(createdBy), NormalizeOptional(auditNote),
            cancellationToken);
    }

    [McpServerTool]
    [Description("List centralized anonymized LLM Tips Feedback for the configured SoftLicence product. Compact, paginated, and separated from standard telemetry.")]
    public async Task<JsonElement> ListLlmTipFeedback(
        [Description("Explicit UTC range start. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Optional.")] string? toUtc = null,
        [Description("Optional product UUID. Global analytics keys must provide productId or productName.")] string? productId = null,
        [Description("Optional exact product name. Global analytics keys must provide productId or productName.")] string? productName = null,
        [Description("App version filter, for example 2.2.501. Optional.")] string? appVersion = null,
        [Description("Tip category filter. Optional.")] string? category = null,
        [Description("Tip severity filter. Optional.")] string? severity = null,
        [Description("Review status filter. Optional.")] string? reviewStatus = null,
        [Description("Search title, description, or contentHash. Optional.")] string? search = null,
        [Description("Maximum returned tips. Clamped from 1 to 200.")] int limit = 50,
        [Description("Pagination offset. Minimum 0.")] int offset = 0,
        [Description("Sort field: occurrenceCount, lastSeenAtUtc, createdAtUtc, firstSeenAtUtc, upvotes, title. Default occurrenceCount.")] string? sortBy = "occurrenceCount",
        [Description("Sort direction: desc or asc. Default desc.")] string? sortDir = "desc",
        CancellationToken cancellationToken = default)
    {
        return await _client.ListLlmTipFeedbackAsync(
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            NormalizeOptional(productId),
            NormalizeOptional(productName),
            NormalizeOptional(appVersion),
            NormalizeOptional(category),
            NormalizeOptional(severity),
            NormalizeReviewStatus(reviewStatus),
            NormalizeOptional(search),
            Math.Clamp(limit, 1, 200),
            Math.Max(0, offset),
            NormalizeLlmTipSortBy(sortBy),
            NormalizeSortDir(sortDir),
            cancellationToken);
    }

    [McpServerTool]
    [Description("Get anonymized detail for one centralized LLM Tips Feedback item by id or contentHash.")]
    public async Task<JsonElement> GetLlmTipFeedbackDetail(
        [Description("Tip UUID or contentHash returned by list_llm_tip_feedback.")] string idOrContentHash,
        [Description("Optional product UUID. Global analytics keys must provide productId or productName.")] string? productId = null,
        [Description("Optional exact product name. Global analytics keys must provide productId or productName.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(idOrContentHash))
            throw new ArgumentException("idOrContentHash is required.", nameof(idOrContentHash));

        return await _client.GetLlmTipFeedbackDetailAsync(
            idOrContentHash.Trim(),
            NormalizeOptional(productId),
            NormalizeOptional(productName),
            cancellationToken);
    }

    [McpServerTool]
    [Description("Get compact centralized LLM Tips Feedback stats for the configured product, including occurrences, approved tips, upvotes, review status, top categories, versions, severities, and upvote usage events.")]
    public async Task<JsonElement> GetLlmTipFeedbackStats(
        [Description("Time window in days. Clamped from 1 to 365. Ignored when fromUtc/toUtc is provided.")] int days = 30,
        [Description("Explicit UTC range start. Optional.")] string? fromUtc = null,
        [Description("Explicit UTC range end. Optional.")] string? toUtc = null,
        [Description("Optional product UUID. Global analytics keys must provide productId or productName.")] string? productId = null,
        [Description("Optional exact product name. Global analytics keys must provide productId or productName.")] string? productName = null,
        [Description("App version filter, for example 2.2.501. Optional.")] string? appVersion = null,
        [Description("Tip category filter. Optional.")] string? category = null,
        [Description("Tip severity filter. Optional.")] string? severity = null,
        [Description("Review status filter. Optional.")] string? reviewStatus = null,
        [Description("Search title, description, or contentHash. Optional.")] string? search = null,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetLlmTipFeedbackStatsAsync(
            Math.Clamp(days, 1, 365),
            NormalizeOptional(fromUtc),
            NormalizeOptional(toUtc),
            NormalizeOptional(productId),
            NormalizeOptional(productName),
            NormalizeOptional(appVersion),
            NormalizeOptional(category),
            NormalizeOptional(severity),
            NormalizeReviewStatus(reviewStatus),
            NormalizeOptional(search),
            cancellationToken);
    }

    [McpServerTool]
    [Description("Update review status for one centralized LLM Tips Feedback item by id or contentHash.")]
    public async Task<JsonElement> UpdateLlmTipFeedbackReviewStatus(
        [Description("Tip UUID. Optional when contentHash is provided.")] string? id = null,
        [Description("Tip contentHash. Optional when id is provided.")] string? contentHash = null,
        [Description("Allowed status: new, ignored, needs-product-fix, needs-doc, needs-mcp-guide, needs-regression-test, converted-to-bugtrace, fixed-in-product.")] string reviewStatus = "new",
        [Description("Optional product UUID. Global analytics keys must provide productId or productName.")] string? productId = null,
        [Description("Optional exact product name. Global analytics keys must provide productId or productName.")] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id) && string.IsNullOrWhiteSpace(contentHash))
            throw new ArgumentException("id or contentHash is required.");

        return await _client.UpdateLlmTipFeedbackReviewStatusAsync(
            NormalizeOptional(id),
            NormalizeOptional(contentHash),
            NormalizeReviewStatus(reviewStatus) ?? "new",
            NormalizeOptional(productId),
            NormalizeOptional(productName),
            cancellationToken);
    }

    private static int ClampDays(int days)
    {
        return Math.Clamp(days, 1, 30);
    }

    private static int ClampTop(int top)
    {
        return Math.Clamp(top, 1, 100);
    }

    private static string? NormalizeOptional(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string? NormalizeReviewStatus(string? status)
    {
        var normalized = NormalizeOptional(status)?.ToLowerInvariant();
        return normalized switch
        {
            "new"
            or "ignored"
            or "needs-product-fix"
            or "needs-doc"
            or "needs-mcp-guide"
            or "needs-regression-test"
            or "converted-to-bugtrace"
            or "fixed-in-product" => normalized,
            null => null,
            _ => throw new ArgumentException("Unsupported reviewStatus.")
        };
    }

    private static string NormalizeHardwareBanCategory(string? category)
    {
        var normalized = NormalizeOptional(category)?.ToLowerInvariant().Replace('-', '_');
        return normalized switch
        {
            "manual" => "manual",
            "piracy" => "piracy",
            "debugger" or "reverseengineering" or "reverse_engineering" => "debugger",
            "outdated_version" or "outdatedversion" => "outdated_version",
            "quota_abuse" or "quotaabuse" => "quota_abuse",
            "dev_canary_quarantine" or "devcanaryquarantine" => "dev_canary_quarantine",
            null => "manual",
            _ => throw new ArgumentException("Unsupported hardware ban category. Use get_security_hardware_ban_categories.")
        };
    }

    private static string NormalizeComponentType(string value)
    {
        var normalized = NormalizeOptional(value)?.ToUpperInvariant();
        return normalized switch
        {
            "FP_CPU" => "CPU",
            "FP_MB" => "MB",
            "FP_BIOS" => "BIOS",
            "FP_DISK" => "DISK",
            "FP_HOST" => "HOST",
            "CPU" or "MB" or "BIOS" or "DISK" or "HOST" or "FP_EXE" or "FP_DLL" or "FP_CORE" => normalized,
            _ => throw new ArgumentException("Unsupported componentType.", nameof(value))
        };
    }

    private static string NormalizeLlmTipSortBy(string? sortBy)
    {
        var normalized = NormalizeOptional(sortBy)?.ToLowerInvariant();
        return normalized switch
        {
            "occurrencecount" or "occurrences" => "occurrenceCount",
            "lastseen" or "lastseenatutc" => "lastSeenAtUtc",
            "firstseen" or "firstseenatutc" => "firstSeenAtUtc",
            "created" or "createdat" or "createdatutc" => "createdAtUtc",
            "upvotes" => "upvotes",
            "title" => "title",
            _ => "occurrenceCount"
        };
    }

    private static string NormalizeSortDir(string? sortDir)
    {
        return string.Equals(NormalizeOptional(sortDir), "asc", StringComparison.OrdinalIgnoreCase) ? "asc" : "desc";
    }

    private static string NormalizeTimelineMode(string? mode)
    {
        var normalized = NormalizeOptional(mode)?.ToLowerInvariant();
        return normalized switch
        {
            "summary" or "timeline" or "full" => normalized,
            _ => "timeline"
        };
    }

    private static void EnsureSecurityBanLookup(
        string? hardwareId,
        string? componentHash,
        string? componentType,
        string? clientIp,
        string? emailFragment,
        string? licenseFragment)
    {
        if (string.IsNullOrWhiteSpace(hardwareId)
            && string.IsNullOrWhiteSpace(componentHash)
            && string.IsNullOrWhiteSpace(componentType)
            && string.IsNullOrWhiteSpace(clientIp)
            && string.IsNullOrWhiteSpace(emailFragment)
            && string.IsNullOrWhiteSpace(licenseFragment))
        {
            throw new ArgumentException("At least one security ban lookup field is required.");
        }
    }

    private static string? NormalizeActivityWindows(string? value)
    {
        var normalized = NormalizeOptional(value);
        if (normalized == null)
            return null;

        var windows = normalized
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => int.TryParse(part, out var parsed) ? parsed : 0)
            .Where(day => day > 0 && day <= 30)
            .Distinct()
            .OrderBy(day => day)
            .ToList();

        return windows.Count == 0 ? null : string.Join(',', windows);
    }

    private static string? NormalizeLicenseTypes(string? value)
    {
        var normalized = NormalizeOptional(value);
        if (normalized == null)
            return null;

        var types = normalized
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(type => !string.IsNullOrWhiteSpace(type))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToList();

        return types.Count == 0 ? null : string.Join(',', types);
    }

    private static string NormalizeStatus(string? status)
    {
        var normalized = NormalizeOptional(status)?.ToLowerInvariant();
        return normalized switch
        {
            "active" or "expired" or "revoked" or "expired_or_revoked" or "all" => normalized,
            _ => "active"
        };
    }

    private static string NormalizeOnboardingLicenseType(string? licenseType)
    {
        var normalized = NormalizeOptional(licenseType)?.ToLowerInvariant();
        return normalized switch
        {
            "paid" or "freemium" or "all" => normalized,
            _ => "paid"
        };
    }

    private static string NormalizeOnboardingStatus(string? status)
    {
        var normalized = NormalizeOptional(status)?.ToLowerInvariant();
        return normalized switch
        {
            "active" or "expired" or "revoked" or "not_activated" or "expired_or_revoked" or "all" => normalized,
            _ => "active"
        };
    }

    private static string NormalizeUsageLicenseType(string? licenseType)
    {
        var normalized = NormalizeOptional(licenseType)?.ToLowerInvariant();
        return normalized switch
        {
            "paid" or "freemium" or "trial" or "subscription" or "all" => normalized,
            _ => "paid"
        };
    }

    private static string NormalizeUsageSort(string? sortBy)
    {
        var normalized = NormalizeOptional(sortBy)?.ToLowerInvariant();
        return normalized switch
        {
            "conversionpotential" => "conversionPotential",
            "retentionconfidence" => "retentionConfidence",
            "recentactivity" => "recentActivity",
            _ => "score"
        };
    }

    private static int? NormalizeAge(int days)
    {
        return days > 0 ? Math.Clamp(days, 0, 3650) : null;
    }

    /// <summary>
    /// Rejects non-canonical UUID text before it can become a support lookup selector.
    /// </summary>
    private static void ValidateCanonicalUuid(string value, string parameterName)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed) || value != parsed.ToString("D"))
            throw new ArgumentException("The value must be a canonical lowercase UUID in D form.", parameterName);
    }
}
