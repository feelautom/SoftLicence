using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace SoftLicence.Mcp;

/// <summary>
/// Call-tool filter that makes expected tool failures readable by MCP clients.
/// The MCP SDK replaces the message of every exception that is not an <see cref="McpException"/>
/// with "An error occurred invoking '&lt;tool&gt;'.", which hid causes such as an HTTP 401 on a missing
/// analytics scope (TKT-001168). This filter rethrows those failures as <see cref="McpException"/>
/// carrying a bounded, secret-free description. Tool code keeps its specific exception types.
/// </summary>
public static class McpToolErrorFilter
{
    /// <summary>Longest message forwarded to the client.</summary>
    private const int MaxMessageLength = 1500;

    /// <summary>Wraps the next call-tool handler; registered through <c>AddCallToolFilter</c>.</summary>
    public static McpRequestHandler<CallToolRequestParams, CallToolResult> Wrap(
        McpRequestHandler<CallToolRequestParams, CallToolResult> next)
    {
        return async (request, cancellationToken) =>
        {
            try
            {
                return await next(request, cancellationToken);
            }
            catch (Exception ex) when (ShouldExpose(ex, cancellationToken))
            {
                throw new McpException(Describe(ex), ex);
            }
        };
    }

    /// <summary>
    /// Returns whether a failure must be converted. MCP exceptions already reach the client, and a
    /// cancellation requested by the client must keep flowing as a cancellation.
    /// </summary>
    public static bool ShouldExpose(Exception exception, CancellationToken cancellationToken) => exception switch
    {
        McpException => false,
        OperationCanceledException when cancellationToken.IsCancellationRequested => false,
        _ => true,
    };

    /// <summary>
    /// Describes a failure for the MCP client. Messages written by this MCP and by the SoftLicence
    /// server are kept (they never contain the analytics key or the admin secret); unexpected
    /// exception types expose only their type name.
    /// </summary>
    public static string Describe(Exception exception)
    {
        var message = exception switch
        {
            ArgumentException or InvalidOperationException or KeyNotFoundException or IOException or FormatException
                => exception.Message,
            HttpRequestException http
                => $"SoftLicence server unreachable{(http.StatusCode is { } status ? $" (HTTP {(int)status})" : string.Empty)}: {http.Message}",
            TimeoutException or OperationCanceledException
                => "SoftLicence request timed out before a response was received.",
            JsonException json
                => $"SoftLicence returned an unreadable JSON response: {json.Message}",
            _ => $"Unexpected {exception.GetType().Name} in the SoftLicence MCP.",
        };
        return message.Length <= MaxMessageLength ? message : message[..MaxMessageLength] + "…";
    }
}
