namespace SoftLicence.Mcp;

/// <summary>
/// Carries a refused analytics request so the MCP client sees a tool error instead of a result.
/// A refusal is never data: this exception is raised for a non-success answer from the SoftLicence server,
/// where <see cref="StatusCode"/> is the provider status and <see cref="ErrorCode"/> is the stable code the
/// provider published or the client derived from it (for example PRODUCT_SELECTOR_REQUIRED,
/// ANALYTICS_AUTH_FAILED, ANALYTICS_API_ERROR or ANALYTICS_SERVER_ERROR). A status of 0 is reserved for a
/// future local pre-flight refusal and is not produced today.
/// It derives from <see cref="InvalidOperationException"/> so <see cref="McpToolErrorFilter"/>
/// keeps the bounded, secret-free message and the MCP SDK reports IsError=true.
/// </summary>
public sealed class SoftLicenceProviderRefusalException : InvalidOperationException
{
    /// <summary>Creates a refusal with its stable code, provider status and bounded description.</summary>
    /// <param name="errorCode">Stable code, either published by SoftLicence or produced by the local pre-flight.</param>
    /// <param name="statusCode">HTTP status of the refused request, or 0 when no request was sent.</param>
    /// <param name="message">Bounded, secret-free description forwarded to the MCP client.</param>
    public SoftLicenceProviderRefusalException(string errorCode, int statusCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
        StatusCode = statusCode;
    }

    /// <summary>Stable refusal code the MCP client can branch on.</summary>
    public string ErrorCode { get; }

    /// <summary>HTTP status of the refused provider request, or 0 for a local pre-flight refusal.</summary>
    public int StatusCode { get; }
}
