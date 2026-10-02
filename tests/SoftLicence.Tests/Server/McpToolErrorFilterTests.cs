using System.Net;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001168: expected tool failures must reach MCP clients with their real cause instead of the
/// SDK's generic "An error occurred invoking" text.
/// </summary>
public sealed class McpToolErrorFilterTests
{
    private static McpRequestHandler<CallToolRequestParams, CallToolResult> Throwing(Exception exception) =>
        (_, _) => throw exception;

    [Fact]
    public async Task Wrap_ConvertsExpectedFailureToMcpExceptionWithOriginalMessage()
    {
        var original = new InvalidOperationException(
            "SoftLicence analytics API rejected SOFTLICENCE_API_KEY (HTTP 401 on /api/analytics/security/bans).");
        var wrapped = McpToolErrorFilter.Wrap(Throwing(original));

        var ex = await Assert.ThrowsAsync<McpException>(async () => await wrapped(null!, CancellationToken.None));

        Assert.Equal(original.Message, ex.Message);
        Assert.Same(original, ex.InnerException);
    }

    [Fact]
    public async Task Wrap_KeepsMcpExceptionUnchanged()
    {
        var original = new McpException("already readable");
        var wrapped = McpToolErrorFilter.Wrap(Throwing(original));

        var ex = await Assert.ThrowsAsync<McpException>(async () => await wrapped(null!, CancellationToken.None));

        Assert.Same(original, ex);
    }

    [Fact]
    public async Task Wrap_LetsClientRequestedCancellationFlow()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var wrapped = McpToolErrorFilter.Wrap(Throwing(new OperationCanceledException(cancellation.Token)));

        await Assert.ThrowsAsync<OperationCanceledException>(async () => await wrapped(null!, cancellation.Token));
    }

    [Fact]
    public async Task Wrap_ReturnsSuccessfulResultUntouched()
    {
        var expected = new CallToolResult();
        var wrapped = McpToolErrorFilter.Wrap((_, _) => ValueTask.FromResult(expected));

        Assert.Same(expected, await wrapped(null!, CancellationToken.None));
    }

    [Fact]
    public void Describe_ReportsHttpStatusForTransportFailures()
    {
        var message = McpToolErrorFilter.Describe(
            new HttpRequestException("Connection refused", null, HttpStatusCode.BadGateway));

        Assert.Contains("HTTP 502", message);
        Assert.Contains("Connection refused", message);
    }

    [Fact]
    public void Describe_ReportsTimeoutWhenCancellationWasNotRequestedByClient()
    {
        Assert.True(McpToolErrorFilter.ShouldExpose(new TaskCanceledException(), CancellationToken.None));
        Assert.Contains("timed out", McpToolErrorFilter.Describe(new TaskCanceledException()));
    }

    [Fact]
    public void Describe_ExposesOnlyTheTypeNameOfUnexpectedExceptions()
    {
        var message = McpToolErrorFilter.Describe(new NullReferenceException("internal detail"));

        Assert.Contains(nameof(NullReferenceException), message);
        Assert.DoesNotContain("internal detail", message);
    }

    [Fact]
    public void Describe_BoundsVeryLongMessages()
    {
        var message = McpToolErrorFilter.Describe(new ArgumentException(new string('x', 5000)));

        Assert.True(message.Length <= 1501);
        Assert.EndsWith("…", message);
    }
}
