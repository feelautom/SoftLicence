using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001169: online SoftLicence MCP over Streamable HTTP, reachable only from the VPN and only with
/// an analytics key accepted by SoftLicence; credentials come from each caller's request headers.
/// </summary>
public sealed class McpHttpModeTests : IAsyncLifetime
{
    private const string GoodKey = "sla_http_mode_good_key";
    private const string VpnAddress = "10.10.0.3";
    private const string TestRemoteIpHeader = "X-Test-Remote-Ip";

    private readonly StubSoftLicence _softLicence = new();
    private readonly string _resultDirectory = Path.Combine(Path.GetTempPath(), $"sl-mcp-http-{Guid.NewGuid():N}");
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _app = McpHosting.BuildHttpApp([], builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SOFTLICENCE_BASE_URL"] = "https://softlicence.test",
                ["SOFTLICENCE_MCP_RESULT_DIRECTORY"] = _resultDirectory,
                ["SOFTLICENCE_MCP_ALLOWED_CIDRS"] = "10.10.0.0/24",
            });
            // Real forwarding handler in front of the stubbed SoftLicence server.
            builder.Services.AddSingleton(provider => new HttpClient(
                new ForwardedClientIpHandler(provider.GetRequiredService<IHttpContextAccessor>())
                {
                    InnerHandler = _softLicence,
                }));
            // TestServer has no remote address: the test sets it before the access gate runs.
            builder.Services.AddTransient<IStartupFilter, TestRemoteIpStartupFilter>();
        });
        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        if (Directory.Exists(_resultDirectory))
            Directory.Delete(_resultDirectory, recursive: true);
    }

    [Fact]
    public async Task Health_IsAvailableWithoutCredentials()
    {
        var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Mcp_FromOutsideTheVpn_IsForbiddenEvenWithAValidKey()
    {
        var response = await PostRpcAsync("tools/list", remoteIp: "203.0.113.5", key: GoodKey);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("MCP_NETWORK_NOT_ALLOWED", await response.Content.ReadAsStringAsync());
        Assert.Empty(_softLicence.Requests);
    }

    [Fact]
    public async Task Mcp_WithoutKey_IsUnauthorized()
    {
        var response = await PostRpcAsync("tools/list", remoteIp: VpnAddress, key: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("MCP_ANALYTICS_KEY_REQUIRED", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Mcp_WithKeyRejectedBySoftLicence_IsUnauthorized()
    {
        var response = await PostRpcAsync("tools/list", remoteIp: VpnAddress, key: "sla_unknown_key");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("MCP_ANALYTICS_KEY_INVALID", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Mcp_RepeatedInvalidKeys_AreThrottled()
    {
        HttpResponseMessage? last = null;
        for (var attempt = 0; attempt < 11; attempt++)
            last = await PostRpcAsync("tools/list", remoteIp: "10.10.0.7", key: $"sla_wrong_{attempt}");

        Assert.Equal(HttpStatusCode.TooManyRequests, last!.StatusCode);
    }

    [Fact]
    public async Task ToolsList_WithValidKeyFromVpn_ExposesReadAndBanTools()
    {
        var result = await CallRpcAsync("tools/list", new { });

        var names = result.GetProperty("tools").EnumerateArray().Select(tool => tool.GetProperty("name").GetString()).ToList();
        Assert.Contains("list_security_bans", names);
        Assert.Contains("create_security_hardware_ban", names);
        Assert.Contains("unban_security_hardware_ban", names);
    }

    [Fact]
    public async Task ToolCall_ForwardsCallerKeyAndVpnAddressToSoftLicence()
    {
        var result = await CallRpcAsync("tools/call", new { name = "list_security_bans", arguments = new { take = 1 } });

        Assert.False(result.TryGetProperty("isError", out var isError) && isError.GetBoolean());
        var call = Assert.Single(_softLicence.Requests, request => request.Path == "/api/analytics/security/bans");
        Assert.Equal(GoodKey, call.AnalyticsKey);
        Assert.Equal(VpnAddress, call.ForwardedFor);
    }

    [Fact]
    public async Task BanTool_WithoutAdminSecretHeader_RefusesWithoutCallingSoftLicence()
    {
        var result = await CallRpcAsync("tools/call", new
        {
            name = "create_security_hardware_ban",
            arguments = new { hardwareId = "ABCDEF0123456789", reason = "test" },
        });

        Assert.Contains("write_credentials_missing", result.GetRawText());
        Assert.DoesNotContain(_softLicence.Requests, request => request.Path.StartsWith("/api/admin/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BanTool_WithAdminSecretHeader_SendsItToSoftLicence()
    {
        await CallRpcAsync("tools/call", new
        {
            name = "create_security_hardware_ban",
            arguments = new { hardwareId = "ABCDEF0123456789", reason = "test" },
        }, adminSecret: "admin-secret-for-test");

        var call = Assert.Single(_softLicence.Requests, request => request.Path == "/api/admin/banned-hwids");
        Assert.Equal("admin-secret-for-test", call.AdminSecret);
        Assert.Equal(VpnAddress, call.ForwardedFor);
    }

    [Fact]
    public void AllowedNetworks_RejectEmptyAndUnrestrictedLists()
    {
        Assert.Throws<InvalidOperationException>(() => McpHttpAccessGate.ParseAllowedNetworks(""));
        Assert.Throws<InvalidOperationException>(() => McpHttpAccessGate.ParseAllowedNetworks("0.0.0.0/0"));
        Assert.Single(McpHttpAccessGate.ParseAllowedNetworks(" 10.10.0.0/24 "));
    }

    [Fact]
    public async Task ResultArtifacts_AreReadableOnlyByTheCallerThatProducedThem()
    {
        var owner = "caller-a";
        var store = new McpResultStore(
            Options.Create(new SoftLicenceMcpOptions
            {
                ResultDirectory = _resultDirectory,
                MaxInlineResultCharacters = 16_384,
            }),
            () => owner);
        var large = JsonSerializer.Serialize(new { rows = Enumerable.Range(0, 5000).Select(i => new { i, text = "0123456789" }) });

        var envelope = await store.DeliverJsonAsync(large);
        var artifactId = envelope.GetRawText().Split('"').SkipWhile(part => part != "artifactId").Skip(2).First();

        store.GetInfo(artifactId);
        owner = "caller-b";
        Assert.Throws<KeyNotFoundException>(() => store.GetInfo(artifactId));
    }

    private async Task<JsonElement> CallRpcAsync(string method, object parameters, string? adminSecret = null)
    {
        var response = await PostRpcAsync(method, VpnAddress, GoodKey, parameters, adminSecret);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        // Streamable HTTP may answer as JSON or as a single server-sent event.
        var json = body.TrimStart().StartsWith('{')
            ? body
            : string.Join('\n', body.Split('\n').Where(line => line.StartsWith("data:", StringComparison.Ordinal)).Select(line => line[5..].Trim()));
        using var document = JsonDocument.Parse(json);
        Assert.False(document.RootElement.TryGetProperty("error", out _), json);
        return document.RootElement.GetProperty("result").Clone();
    }

    private Task<HttpResponseMessage> PostRpcAsync(
        string method,
        string remoteIp,
        string? key,
        object? parameters = null,
        string? adminSecret = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method, @params = parameters ?? new { } }),
                Encoding.UTF8,
                "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.Add(TestRemoteIpHeader, remoteIp);
        if (key != null)
            request.Headers.Add(HttpRequestCallerCredentials.AnalyticsKeyHeader, key);
        if (adminSecret != null)
            request.Headers.Add(HttpRequestCallerCredentials.AdminSecretHeader, adminSecret);
        return _client.SendAsync(request);
    }

    /// <summary>Sets the connection address from a test header before any application middleware.</summary>
    private sealed class TestRemoteIpStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                if (IPAddress.TryParse(context.Request.Headers[TestRemoteIpHeader], out var address))
                    context.Connection.RemoteIpAddress = address;
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    /// <summary>Minimal SoftLicence server: accepts only <see cref="GoodKey"/> and records every request.</summary>
    private sealed class StubSoftLicence : HttpMessageHandler
    {
        public ConcurrentBag<RecordedRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string? Header(string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : null;
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add(new RecordedRequest(path, Header("X-Analytics-Key"), Header("X-Admin-Secret"), Header("X-Forwarded-For")));

            if (path.StartsWith("/api/analytics/", StringComparison.Ordinal) && Header("X-Analytics-Key") != GoodKey)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));

            var body = path switch
            {
                "/api/analytics/products/current" => """{"product":{"name":"TIAConnect"}}""",
                "/api/analytics/security/bans" => """{"complete":true,"recordsMatched":0,"recordsReturned":0,"bans":[]}""",
                "/api/admin/banned-hwids" => """{"ok":true}""",
                _ => "{}",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed record RecordedRequest(string Path, string? AnalyticsKey, string? AdminSecret, string? ForwardedFor);
}
