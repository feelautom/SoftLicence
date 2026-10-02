using System.ComponentModel;
using System.Net;
using System.Text;
using System.Reflection;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies that Recovery support operations are exposed as bounded MCP tools with strict identifier validation.</summary>
public sealed class RecoveryTelemetryMcpTests
{
    /// <summary>Proves both Recovery read operations are discoverable in the MCP tool catalog.</summary>
    [Fact]
    public void RecoveryTools_AreCataloguedAndDescribed()
    {
        foreach (var name in new[] { nameof(SoftLicenceAnalyticsTools.GetRecoveryTimeline), nameof(SoftLicenceAnalyticsTools.GetRecoveryRejections) })
        {
            var method = typeof(SoftLicenceAnalyticsTools).GetMethod(name, BindingFlags.Instance | BindingFlags.Public);
            Assert.NotNull(method);
            Assert.NotNull(method!.GetCustomAttribute<McpServerToolAttribute>());
            Assert.False(string.IsNullOrWhiteSpace(method.GetCustomAttribute<DescriptionAttribute>()?.Description));
        }
    }

    /// <summary>Proves the MCP boundary refuses uppercase UUID text instead of silently normalizing lookup authority.</summary>
    [Fact]
    public async Task RecoveryTimeline_RejectsNonCanonicalUuid()
    {
        var tools = new SoftLicenceAnalyticsTools(null!, null!);
        await Assert.ThrowsAsync<ArgumentException>(() => tools.GetRecoveryTimeline("10000000-0000-4000-8000-00000000000A"));
    }

    /// <summary>Proves the MCP client preserves exact product-name casing and addresses the dedicated Recovery route.</summary>
    [Fact]
    public async Task RecoveryClient_PreservesExactSelectorAndDedicatedRoute()
    {
        Uri? capturedUri = null;
        var handler = new DelegateHandler(request =>
        {
            capturedUri = request.RequestUri;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"status\":\"incomplete\"}", Encoding.UTF8, "application/json")
            };
        });
        var options = Options.Create(new SoftLicenceMcpOptions
        {
            SoftLicenceBaseUrl = "https://softlicence.test",
            SoftLicenceApiKey = "analytics-key"
        });
        var client = new SoftLicenceAnalyticsClient(new HttpClient(handler), options);

        await client.GetRecoveryTimelineAsync("10000000-0000-4000-8000-000000000001", null, "tiaconnect", CancellationToken.None);

        Assert.Equal("https://softlicence.test/api/analytics/recovery/runs/10000000-0000-4000-8000-000000000001?productName=tiaconnect", capturedUri!.AbsoluteUri);
    }

    /// <summary>Provides a deterministic in-memory HTTP transport for MCP route assertions.</summary>
    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        /// <inheritdoc />
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}
