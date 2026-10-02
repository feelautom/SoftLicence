using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SoftLicence.Mcp;

/// <summary>
/// Access control in front of the online MCP endpoint (TKT-001169). Every MCP request must:
/// 1. come from an allowed network (the WireGuard VPN, 10.10.0.0/24 by default) — otherwise 403;
/// 2. carry an X-Analytics-Key header — otherwise 401;
/// 3. carry a key that the SoftLicence server accepts — otherwise 401 (403 if it lacks telemetry:read).
/// Valid keys are cached briefly by fingerprint; repeated failures from one address are throttled.
/// The container port is also published only on the VPN address, so this is defense in depth.
/// </summary>
public sealed class McpHttpAccessGate
{
    private static readonly TimeSpan ValidKeyCacheDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(5);
    private const int MaxFailuresPerWindow = 10;

    private readonly IReadOnlyList<IPNetwork> _allowedNetworks;
    private readonly HttpClient _httpClient;
    private readonly SoftLicenceMcpOptions _options;
    private readonly ILogger<McpHttpAccessGate> _logger;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _validKeys = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, FailureCounter> _failures = new(StringComparer.Ordinal);

    /// <summary>Creates the gate from the configured allowed networks and SoftLicence base URL.</summary>
    /// <exception cref="InvalidOperationException">No allowed network is configured, or a network is unrestricted.</exception>
    public McpHttpAccessGate(
        IOptions<SoftLicenceMcpOptions> options,
        HttpClient httpClient,
        ILogger<McpHttpAccessGate> logger,
        TimeProvider? time = null)
    {
        _options = options.Value;
        _httpClient = httpClient;
        _logger = logger;
        _time = time ?? TimeProvider.System;
        _allowedNetworks = ParseAllowedNetworks(_options.AllowedCidrs);
    }

    /// <summary>
    /// Parses a comma-separated CIDR list. An empty list or an unrestricted network (prefix 0) is
    /// refused so that the online MCP can never start open to everyone by mistake.
    /// </summary>
    public static IReadOnlyList<IPNetwork> ParseAllowedNetworks(string? cidrs)
    {
        var networks = (cidrs ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(IPNetwork.Parse)
            .ToList();
        if (networks.Count == 0)
            throw new InvalidOperationException("SOFTLICENCE_MCP_ALLOWED_CIDRS must list at least one network (e.g. 10.10.0.0/24).");
        if (networks.Any(network => network.PrefixLength == 0))
            throw new InvalidOperationException("SOFTLICENCE_MCP_ALLOWED_CIDRS must not contain an unrestricted network.");
        return networks;
    }

    /// <summary>Returns whether a remote address belongs to an allowed network (IPv4-mapped IPv6 included).</summary>
    public bool IsAllowedAddress(IPAddress? address)
    {
        if (address == null)
            return false;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        return _allowedNetworks.Any(network => network.Contains(address));
    }

    /// <summary>ASP.NET Core middleware entry point: rejects the request or passes it to <paramref name="next"/>.</summary>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var remote = context.Connection.RemoteIpAddress;
        var remoteText = remote?.ToString() ?? "unknown";
        if (!IsAllowedAddress(remote))
        {
            _logger.LogWarning("[MCP_GATE] Refused request from non-allowed address {Address}.", remoteText);
            await WriteRefusalAsync(context, StatusCodes.Status403Forbidden, "MCP_NETWORK_NOT_ALLOWED",
                "This MCP endpoint is reachable only through the VPN.");
            return;
        }

        if (IsThrottled(remoteText))
        {
            await WriteRefusalAsync(context, StatusCodes.Status429TooManyRequests, "MCP_TOO_MANY_FAILURES",
                "Too many rejected analytics keys from this address; retry later.");
            return;
        }

        var keyFingerprint = HttpRequestCallerCredentials.GetKeyFingerprint(context);
        if (keyFingerprint == null)
        {
            RecordFailure(remoteText);
            await WriteRefusalAsync(context, StatusCodes.Status401Unauthorized, "MCP_ANALYTICS_KEY_REQUIRED",
                $"Send exactly one {HttpRequestCallerCredentials.AnalyticsKeyHeader} header.");
            return;
        }

        var now = _time.GetUtcNow();
        if (!_validKeys.TryGetValue(keyFingerprint, out var validUntil) || validUntil <= now)
        {
            var verdict = await VerifyKeyWithServerAsync(context, context.RequestAborted);
            if (verdict != StatusCodes.Status200OK)
            {
                if (verdict is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
                    RecordFailure(remoteText);
                _logger.LogWarning("[MCP_GATE] Refused analytics key from {Address}; status={Status}.", remoteText, verdict);
                await WriteRefusalAsync(context, verdict, verdict switch
                {
                    StatusCodes.Status401Unauthorized => "MCP_ANALYTICS_KEY_INVALID",
                    StatusCodes.Status403Forbidden => "MCP_ANALYTICS_KEY_SCOPE_MISSING",
                    _ => "MCP_SOFTLICENCE_UNAVAILABLE",
                }, verdict switch
                {
                    StatusCodes.Status401Unauthorized => "The analytics key is unknown, inactive or expired.",
                    StatusCodes.Status403Forbidden => "The analytics key lacks the telemetry:read scope.",
                    _ => "SoftLicence could not verify the analytics key; retry later.",
                });
                return;
            }

            _validKeys[keyFingerprint] = now.Add(ValidKeyCacheDuration);
        }

        await next(context);
    }

    /// <summary>
    /// Asks the SoftLicence server whether the caller key is usable. 200, or 400 because a global key
    /// must name a product, both prove a valid telemetry key.
    /// </summary>
    /// <returns>200 when valid, 401/403 when refused by the server, 503 when the server is unreachable.</returns>
    private async Task<int> VerifyKeyWithServerAsync(HttpContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get, $"{_options.GetBaseUrl()}/api/analytics/products/current");
            request.Headers.Add(HttpRequestCallerCredentials.AnalyticsKeyHeader,
                context.Request.Headers[HttpRequestCallerCredentials.AnalyticsKeyHeader].ToString().Trim());
            using var response = await _httpClient.SendAsync(request, cancellationToken);
            return response.StatusCode switch
            {
                HttpStatusCode.OK or HttpStatusCode.BadRequest => StatusCodes.Status200OK,
                HttpStatusCode.Unauthorized => StatusCodes.Status401Unauthorized,
                HttpStatusCode.Forbidden => StatusCodes.Status403Forbidden,
                _ => StatusCodes.Status503ServiceUnavailable,
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "[MCP_GATE] SoftLicence key verification failed.");
            return StatusCodes.Status503ServiceUnavailable;
        }
    }

    private bool IsThrottled(string address)
    {
        return _failures.TryGetValue(address, out var counter)
            && counter.WindowEndsAt > _time.GetUtcNow()
            && counter.Count >= MaxFailuresPerWindow;
    }

    private void RecordFailure(string address)
    {
        var now = _time.GetUtcNow();
        _failures.AddOrUpdate(
            address,
            _ => new FailureCounter(1, now.Add(FailureWindow)),
            (_, existing) => existing.WindowEndsAt <= now
                ? new FailureCounter(1, now.Add(FailureWindow))
                : existing with { Count = existing.Count + 1 });
    }

    private static Task WriteRefusalAsync(HttpContext context, int status, string errorCode, string message)
    {
        context.Response.StatusCode = status;
        return context.Response.WriteAsJsonAsync(new { errorCode, message });
    }

    private sealed record FailureCounter(int Count, DateTimeOffset WindowEndsAt);
}
