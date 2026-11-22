using System.Reflection;
using ModelContextProtocol.Server;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003574 MCP tool surface: the published tool exists and refuses locally, without any request, a retraction
/// without reason or a call without selector. The HTTP request the client sends is covered in
/// <see cref="SoftLicenceMcpClientTests"/>, which owns every client construction so that no second class builds the
/// per-process result store concurrently.
/// </summary>
public sealed class Tkt003574LlmTipSharingMcpTests
{
    [Fact]
    public void SharingTool_UsesThePublishedName()
    {
        var names = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .Select(method => method.Name)
            .ToArray();

        Assert.Contains(nameof(SoftLicenceAnalyticsTools.SetLlmTipFeedbackSharing), names);
    }

    /// <summary>
    /// A retraction without a reason and a call without selector are refused by the tool itself; the null client
    /// proves no request could have been sent.
    /// </summary>
    [Fact]
    public async Task SharingTool_RefusesLocallyWithoutReasonOrSelector()
    {
        var tools = new SoftLicenceAnalyticsTools(null!, null!);

        await Assert.ThrowsAsync<ArgumentException>(() => tools.SetLlmTipFeedbackSharing(false, id: Guid.NewGuid().ToString(), reason: "  "));
        await Assert.ThrowsAsync<ArgumentException>(() => tools.SetLlmTipFeedbackSharing(true));
    }
}
