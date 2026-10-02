using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace SoftLicence.Mcp;

/// <summary>
/// Credentials used by <see cref="SoftLicenceAnalyticsClient"/> for one tool call.
/// In stdio mode they come from the local process configuration; in HTTP mode (TKT-001169) they come
/// from the headers of the caller's MCP request and are never stored by the online container.
/// </summary>
public interface ISoftLicenceCallerCredentials
{
    /// <summary>Returns the analytics key sent as X-Analytics-Key.</summary>
    /// <exception cref="InvalidOperationException">No key is available.</exception>
    string GetApiKey();

    /// <summary>Returns the admin secret required by ban/unban mutations, with a stable refusal reason.</summary>
    bool TryGetAdminSecret(out string value, out string errorCode, out string errorMessage);
}

/// <summary>Stdio-mode credentials read from <see cref="SoftLicenceMcpOptions"/> (environment).</summary>
public sealed class OptionsCallerCredentials : ISoftLicenceCallerCredentials
{
    private readonly SoftLicenceMcpOptions _options;

    /// <summary>Creates credentials bound to the configured options.</summary>
    public OptionsCallerCredentials(IOptions<SoftLicenceMcpOptions> options)
    {
        _options = options.Value;
    }

    /// <inheritdoc />
    public string GetApiKey() => _options.GetApiKey();

    /// <inheritdoc />
    public bool TryGetAdminSecret(out string value, out string errorCode, out string errorMessage) =>
        _options.TryGetAdminSecret(out value, out errorCode, out errorMessage);
}

/// <summary>
/// HTTP-mode credentials read from the current MCP request: X-Analytics-Key (required, checked by
/// <see cref="McpHttpAccessGate"/>) and X-Admin-Secret (only needed by ban/unban tools).
/// </summary>
public sealed class HttpRequestCallerCredentials : ISoftLicenceCallerCredentials
{
    /// <summary>Header carrying the caller's analytics key.</summary>
    public const string AnalyticsKeyHeader = "X-Analytics-Key";

    /// <summary>Header carrying the caller's admin secret for mutations.</summary>
    public const string AdminSecretHeader = "X-Admin-Secret";

    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>Creates credentials that read the current request headers.</summary>
    public HttpRequestCallerCredentials(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc />
    public string GetApiKey()
    {
        var key = ReadSingleHeader(AnalyticsKeyHeader);
        if (string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException($"Missing {AnalyticsKeyHeader} header on the MCP request.");
        return key.Trim();
    }

    /// <inheritdoc />
    public bool TryGetAdminSecret(out string value, out string errorCode, out string errorMessage) =>
        SoftLicenceMcpOptions.ValidateAdminSecret(
            ReadSingleHeader(AdminSecretHeader),
            $"Missing {AdminSecretHeader} header on the MCP request (required for ban/unban tools).",
            out value,
            out errorCode,
            out errorMessage);

    /// <summary>
    /// Returns a short fingerprint of the caller's analytics key, used to bind stored result artifacts
    /// to the caller. Returns null outside an HTTP request or without a key.
    /// </summary>
    public static string? GetKeyFingerprint(HttpContext? httpContext)
    {
        if (httpContext == null)
            return null;
        var values = httpContext.Request.Headers[AnalyticsKeyHeader];
        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
            return null;
        return Fingerprint(values[0]!.Trim());
    }

    /// <summary>Returns the first 32 hex characters of the SHA-256 of a key; never reversible.</summary>
    public static string Fingerprint(string key) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..32];

    /// <summary>Reads a header that must appear at most once; a repeated header is treated as absent.</summary>
    private string? ReadSingleHeader(string name)
    {
        var values = _httpContextAccessor.HttpContext?.Request.Headers[name] ?? default;
        return values.Count == 1 ? values[0] : null;
    }
}
