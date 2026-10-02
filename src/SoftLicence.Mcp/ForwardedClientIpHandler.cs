using Microsoft.AspNetCore.Http;

namespace SoftLicence.Mcp;

/// <summary>
/// HTTP mode only (TKT-001169): tells the SoftLicence server which VPN client is really calling, by
/// sending the MCP caller address as X-Forwarded-For on every outgoing analytics/admin request.
/// The server trusts this header only from its Docker network, so audit logs and threat scoring
/// attribute calls to the caller instead of the shared MCP container.
/// </summary>
public sealed class ForwardedClientIpHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>Creates the handler; the inner handler is set by the HTTP client factory registration.</summary>
    public ForwardedClientIpHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var address = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress;
        if (address != null)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();
            request.Headers.Remove("X-Forwarded-For");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", address.ToString());
        }

        return base.SendAsync(request, cancellationToken);
    }
}
