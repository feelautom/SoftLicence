using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class CertPinningBugTraceAlertService
{
    private const string SecurityTrigger = "Telemetry.CertPinningFailed";
    private static readonly ConcurrentDictionary<string, DateTime> CreatedTicketCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan CacheTtl = TimeSpan.FromDays(2);

    private readonly IBugTraceProxyService _bugTrace;
    private readonly ILogger<CertPinningBugTraceAlertService> _logger;

    public CertPinningBugTraceAlertService(
        IBugTraceProxyService bugTrace,
        ILogger<CertPinningBugTraceAlertService> logger)
    {
        _bugTrace = bugTrace;
        _logger = logger;
    }

    public async Task HandleAsync(TelemetryEventRequest request, string? ip, string? isp, Guid? productId = null, CancellationToken ct = default)
    {
        if (!_bugTrace.IsConfigured)
            return;

        if (!string.Equals(request.EventName, "CertPinningFailed", StringComparison.OrdinalIgnoreCase))
            return;

        var host = GetProperty(request, "Host") ?? "unknown-host";
        var day = DateTime.UtcNow.ToString("yyyy-MM-dd");
        var dedupeKey = BuildDedupeKey(request.AppName, request.HardwareId, host, request.Version, day);
        RemoveExpiredCacheEntries();

        if (!CreatedTicketCache.TryAdd(dedupeKey, DateTime.UtcNow))
            return;

        try
        {
            var isCritical = IsCritical(request);
            var securityCaseId = SecurityCaseContextService.BuildSecurityCaseId(productId, request.HardwareId, SecurityTrigger);
            var ticket = new
            {
                version = "main",
                type = "BUG",
                priority = isCritical ? "CRITICAL" : "HIGH",
                title = $"CertPinningFailed detected - {request.AppName} {request.Version ?? "unknown"} - {RedactHardwareId(request.HardwareId)}",
                description = BuildDescription(request, ip, isp, host, dedupeKey, isCritical, securityCaseId, productId),
                reporterEmail = "internal@feelautom.local",
                isInternal = true,
                securityCaseId,
                trigger = SecurityTrigger,
                hardwareId = request.HardwareId,
                incidentIp = ip,
                productId,
                productName = request.AppName,
                tags = new[]
                {
                    "softlicence",
                    "telemetry",
                    "cert-pinning",
                    "security",
                    "security-alert",
                    "runtime-validation",
                    "tia-connect",
                    "auto-alert",
                    $"dedupe:{ShortHash(dedupeKey)}"
                }
            };

            var result = await _bugTrace.SubmitTicketAsync(ticket, ct);
            var ticketNumber = TryGetJsonString(result, "ticketNumber") ?? TryGetJsonString(result, "number") ?? "unknown";
            _logger.LogWarning(
                "Created BugTrace ticket {TicketNumber} for CertPinningFailed dedupe={DedupeKey}",
                ticketNumber,
                dedupeKey);
        }
        catch (Exception ex)
        {
            CreatedTicketCache.TryRemove(dedupeKey, out _);
            _logger.LogWarning(ex, "Failed to create BugTrace ticket for CertPinningFailed dedupe={DedupeKey}", dedupeKey);
        }
    }

    private static bool IsCritical(TelemetryEventRequest request)
    {
        var source = GetProperty(request, "RequestSource");
        var interactive = GetProperty(request, "IsInteractive");

        return string.Equals(source, "API_Direct", StringComparison.OrdinalIgnoreCase)
            || string.Equals(interactive, "False", StringComparison.OrdinalIgnoreCase)
            || string.Equals(interactive, "false", StringComparison.Ordinal);
    }

    private static string BuildDescription(
        TelemetryEventRequest request,
        string? ip,
        string? isp,
        string host,
        string dedupeKey,
        bool isCritical,
        string securityCaseId,
        Guid? productId)
    {
        var lines = new List<string>
        {
            "## Auto security telemetry alert",
            "",
            "SoftLicence received a `CertPinningFailed` telemetry event from TIAConnect.",
            "",
            "## Severity",
            $"- Priority: {(isCritical ? "CRITICAL" : "HIGH")}",
            $"- Reason: {(isCritical ? "`API_Direct` and/or non-interactive context" : "interactive cert pinning failure")}",
            "",
            "## Event",
            $"- SecurityCaseId: `{securityCaseId}`",
            $"- Trigger: `{SecurityTrigger}`",
            $"- EventName: `{request.EventName}`",
            $"- AppName: `{request.AppName}`",
            $"- ProductId: `{productId?.ToString() ?? "unknown"}`",
            $"- Version: `{request.Version ?? "unknown"}`",
            $"- HardwareId: `{request.HardwareId}`",
            $"- HardwareIdHash: `{ShortHash(request.HardwareId)}`",
            $"- ClientIp: `{ip ?? "unknown"}`",
            $"- ISP: `{isp ?? "unknown"}`",
            $"- Host: `{host}`",
            $"- RequestSource: `{GetProperty(request, "RequestSource") ?? "unknown"}`",
            $"- IsInteractive: `{GetProperty(request, "IsInteractive") ?? "unknown"}`",
            $"- OS: `{GetProperty(request, "OS") ?? "unknown"}`",
            $"- Culture: `{GetProperty(request, "Culture") ?? "unknown"}`",
            "",
            "## Certificate details",
            $"- FailureReason: `{GetProperty(request, "FailureReason") ?? "unknown"}`",
            $"- ExpectedPinsCount: `{GetProperty(request, "ExpectedPinsCount") ?? "unknown"}`",
            $"- ObservedChainCount: `{GetProperty(request, "ObservedChainCount") ?? "unknown"}`",
            $"- SuppressedCount: `{GetProperty(request, "SuppressedCount") ?? "unknown"}`",
            $"- CertificateIssuer: `{GetProperty(request, "CertificateIssuer") ?? "unknown"}`",
            $"- CertificateSubject: `{GetProperty(request, "CertificateSubject") ?? "unknown"}`",
            $"- CertificateThumbprint: `{GetProperty(request, "CertificateThumbprint") ?? "unknown"}`",
            $"- CertificateNotBeforeUtc: `{GetProperty(request, "CertificateNotBeforeUtc") ?? "unknown"}`",
            $"- CertificateNotAfterUtc: `{GetProperty(request, "CertificateNotAfterUtc") ?? "unknown"}`",
            $"- FirstFailureAt: `{GetProperty(request, "FirstFailureAt") ?? "unknown"}`",
            $"- LastFailureAt: `{GetProperty(request, "LastFailureAt") ?? "unknown"}`",
            "",
            "## Deduplication",
            $"- DedupeKey: `{dedupeKey}`",
            $"- DedupeHash: `{ShortHash(dedupeKey)}`",
            "- Current implementation deduplicates in-memory for the current server process. If a duplicate is emitted after process restart, merge it manually or extend BugTrace search-based dedupe.",
            "",
            "## Initial interpretation",
            "- A pin mismatch can indicate TLS interception, proxy inspection, MITM, replaced certificate chain, or a non-standard network environment.",
            "- This ticket is internal and should be reviewed before taking customer-facing action."
        };

        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildDedupeKey(string appName, string hardwareId, string host, string? version, string day) =>
        $"cert-pinning:{Normalize(appName)}:{Normalize(hardwareId)}:{Normalize(host)}:{Normalize(version ?? "unknown")}:{day}";

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();

    private static string? GetProperty(TelemetryEventRequest request, string key)
    {
        if (request.Properties == null)
            return null;

        return request.Properties.TryGetValue(key, out var value) ? value : null;
    }

    private static string RedactHardwareId(string hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return "unknown";

        return hardwareId.Length <= 10
            ? "***"
            : $"{hardwareId[..6]}...{hardwareId[^4..]}";
    }

    private static string ShortHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    private static string? TryGetJsonString(System.Text.Json.JsonElement element, string propertyName)
    {
        if (element.ValueKind != System.Text.Json.JsonValueKind.Object)
            return null;

        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                return property.Value.ValueKind == System.Text.Json.JsonValueKind.String
                    ? property.Value.GetString()
                    : property.Value.ToString();
        }

        return null;
    }

    private static void RemoveExpiredCacheEntries()
    {
        var cutoff = DateTime.UtcNow - CacheTtl;
        foreach (var entry in CreatedTicketCache)
        {
            if (entry.Value < cutoff)
                CreatedTicketCache.TryRemove(entry.Key, out _);
        }
    }
}
