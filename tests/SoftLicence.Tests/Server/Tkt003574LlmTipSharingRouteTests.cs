using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003574 HTTP contract: the sharing decision route (internal network, then the dedicated key scope) and the
/// public read route consumed by T-IA Connect. End to end over HTTP: a tip ingested by a client is invisible to other
/// clients until an administrator shares it through the API, then visible, then gone after a reasoned retraction.
/// </summary>
public sealed class Tkt003574LlmTipSharingRouteTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string ReadOnlyKey = "sla_test_tip_sharing_readonly_001";
    private const string ShareKey = "sla_test_tip_sharing_writer_0001";
    private const string SharingRoute = "/api/llm-tips-feedback/admin/tips/sharing";
    private const string PublicRoute = "/api/llm-tips-feedback/shared?appName=tiaconnect";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    /// <summary>Shared in-memory root so every factory of one test instance reads the same catalogue.</summary>
    private readonly Microsoft.EntityFrameworkCore.Storage.InMemoryDatabaseRoot _dbRoot = new();

    /// <summary>Builds an isolated server; <paramref name="factory"/> is the shared xUnit fixture.</summary>
    public Tkt003574LlmTipSharingRouteTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// From a public address, a key holding the sharing scope is still refused with INTERNAL_NETWORK_REQUIRED and the
    /// tip stays unshared.
    /// </summary>
    [Fact]
    public async Task Sharing_FromOutsideTheInternalNetwork_IsRefusedEvenWithTheScope()
    {
        // 203.0.113.0/24 is reserved for documentation (RFC 5737): a public address that can never be a real caller.
        var factory = CreateFactory(IPAddress.Parse("203.0.113.9"));
        var tipId = await SeedAsync(factory);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ShareKey);

        var response = await client.PostAsJsonAsync(SharingRoute, new { id = tipId, shared = true, productName = "TIAConnect" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("INTERNAL_NETWORK_REQUIRED", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.False(await IsSharedAsync(factory, tipId));
    }

    /// <summary>From the loopback address, a key without the scope gets 403 ANALYTICS_SCOPE_REQUIRED naming it.</summary>
    [Fact]
    public async Task Sharing_WithAReadOnlyKey_IsRefusedWithTheMissingScope()
    {
        var factory = CreateFactory(IPAddress.Loopback);
        var tipId = await SeedAsync(factory);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ReadOnlyKey);

        var response = await client.PostAsJsonAsync(SharingRoute, new { id = tipId, shared = true, productName = "TIAConnect" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("ANALYTICS_SCOPE_REQUIRED", body, StringComparison.Ordinal);
        Assert.Contains(AnalyticsApiKeyScopes.LlmTipsShare, body, StringComparison.Ordinal);
        Assert.False(await IsSharedAsync(factory, tipId));
    }

    /// <summary>
    /// End to end: not shared, so absent from the public snapshot; shared by the API, so present with only the public
    /// fields and an ETag that answers 304; a retraction without a reason is refused (400) and leaves it shared; a
    /// reasoned retraction removes it from the snapshot. The public reads come from a public address without any key.
    /// </summary>
    [Fact]
    public async Task ShareThenRetract_IsVisibleThenInvisibleOnThePublicRoute()
    {
        var adminFactory = CreateFactory(IPAddress.Loopback);
        var tipId = await SeedAsync(adminFactory);
        var admin = adminFactory.CreateClient();
        admin.DefaultRequestHeaders.Add("X-Analytics-Key", ShareKey);
        var publicClient = CreateFactory(IPAddress.Parse("203.0.113.10")).CreateClient();

        Assert.Equal(0, (await ReadSnapshotAsync(publicClient)).GetProperty("count").GetInt32());

        var share = await admin.PostAsJsonAsync(SharingRoute, new { id = tipId, shared = true, reason = "Real TIA tip", source = "mcp", productName = "TIAConnect" });
        Assert.Equal(HttpStatusCode.OK, share.StatusCode);
        var shareBody = JsonDocument.Parse(await share.Content.ReadAsStringAsync()).RootElement;
        Assert.True(shareBody.GetProperty("changed").GetBoolean());
        Assert.StartsWith("analytics-key:", shareBody.GetProperty("sharingChangedBy").GetString(), StringComparison.Ordinal);

        var response = await publicClient.GetAsync(PublicRoute);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("public, max-age=300", response.Headers.CacheControl?.ToString());
        var etag = response.Headers.ETag?.Tag;
        Assert.False(string.IsNullOrEmpty(etag));
        var snapshot = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("1", snapshot.GetProperty("schemaVersion").GetString());
        var item = Assert.Single(snapshot.GetProperty("items").EnumerateArray());
        Assert.Equal("hash-3574-route", item.GetProperty("contentHash").GetString());
        Assert.Equal(
            new[] { "category", "confidence", "contentHash", "description", "severity", "sharedAtUtc", "title" },
            item.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());

        using (var conditional = new HttpRequestMessage(HttpMethod.Get, PublicRoute))
        {
            conditional.Headers.TryAddWithoutValidation("If-None-Match", etag);
            var notModified = await publicClient.SendAsync(conditional);
            Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);
            Assert.Empty(await notModified.Content.ReadAsByteArrayAsync());
        }

        var refused = await admin.PostAsJsonAsync(SharingRoute, new { id = tipId, shared = false, productName = "TIAConnect" });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.True(await IsSharedAsync(adminFactory, tipId));

        var retract = await admin.PostAsJsonAsync(SharingRoute, new { id = tipId, shared = false, reason = "Bug report, not a tip", productName = "TIAConnect" });
        Assert.Equal(HttpStatusCode.OK, retract.StatusCode);
        Assert.Equal(0, (await ReadSnapshotAsync(publicClient)).GetProperty("count").GetInt32());

        using var scope = adminFactory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var channels = await db.LlmTipFeedbackSharingDecisions.OrderBy(d => d.DecidedAtUtc).Select(d => d.Channel).ToListAsync();
        Assert.Equal(new[] { "mcp", "api" }, channels);
    }

    [Theory]
    [InlineData("/api/llm-tips-feedback/shared")]
    [InlineData("/api/llm-tips-feedback/shared?appName=%20")]
    public async Task PublicRoute_WithoutAppName_Returns400InvalidAppName(string path)
    {
        var client = CreateFactory(IPAddress.Parse("203.0.113.11")).CreateClient();

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_app_name", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    /// <summary>
    /// Reads the key screen source: creating a global key never grants the sharing scope, and the screen exposes the
    /// per-key grant button instead.
    /// </summary>
    [Fact]
    public void NewGlobalKeys_NeverReceiveTheSharingScopeByDefault()
    {
        var page = File.ReadAllText(FindRepositoryFile("src", "SoftLicence.Server", "Components", "Pages", "GlobalAnalyticsKeys.razor"));
        var creation = page[page.IndexOf("private async Task CreateGlobalAnalyticsApiKey()", StringComparison.Ordinal)..];
        creation = creation[..creation.IndexOf("private async Task RevokeAnalyticsApiKey", StringComparison.Ordinal)];
        Assert.DoesNotContain("LlmTipsShare", creation, StringComparison.Ordinal);
        Assert.Contains("SetLlmTipsShare(key, !canShareTips)", page, StringComparison.Ordinal);
    }

    /// <summary>Reads the public snapshot and fails unless it answers 200.</summary>
    /// <param name="client">Client of a server whose requests come from a public address.</param>
    /// <returns>The parsed response body.</returns>
    private static async Task<JsonElement> ReadSnapshotAsync(HttpClient client)
    {
        var response = await client.GetAsync(PublicRoute);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    }

    /// <summary>
    /// Server on this test's in-memory catalogue, whose requests come from <paramref name="remoteIp"/>. Several
    /// factories of one test share the catalogue by name, so a public client sees what the admin client wrote.
    /// </summary>
    private WebApplicationFactory<Program> CreateFactory(IPAddress remoteIp) => _factory.WithWebHostBuilder(builder =>
    {
        builder.UseSetting("IsIntegrationTest", "true");
        builder.UseSetting("AdminSettings:ApiSecret", "admin-secret");
        builder.UseSetting("AdminSettings:AllowedIps", "");
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<LicenseDbContext>>();
            services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
            services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName, _dbRoot));
            services.AddSingleton<IStartupFilter>(new RemoteIpStartupFilter(remoteIp));
        });
    });

    /// <summary>
    /// Seeds the product, a read-only global key, a key holding only the sharing scope, and one tip ingested through
    /// the production service with the client's local approval set (so it must not be public yet).
    /// </summary>
    /// <returns>The identifier of the seeded tip.</returns>
    private static async Task<Guid> SeedAsync(WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        db.Products.Add(new Product { Name = "TIAConnect", PrivateKeyXml = "k", PublicKeyXml = "k" });
        db.AnalyticsApiKeys.AddRange(
            NewKey(ReadOnlyKey, $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.SecurityRead} {AnalyticsApiKeyScopes.MultiProductRead}"),
            NewKey(ShareKey, AnalyticsApiKeyScopes.LlmTipsShare));
        await db.SaveChangesAsync();

        var service = scope.ServiceProvider.GetRequiredService<LlmTipFeedbackService>();
        var created = await service.SaveTipAsync(Tkt003574LlmTipSharingTests.BuildClientTip("hash-3574-route", clientApproved: true));
        return created.Id;
    }

    /// <summary>Reads the sharing state of one tip from the server's catalogue.</summary>
    private static async Task<bool> IsSharedAsync(WebApplicationFactory<Program> factory, Guid tipId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        return (await db.LlmTipFeedbackTips.AsNoTracking().SingleAsync(t => t.Id == tipId)).SharedWithClients;
    }

    /// <summary>Creates an active global key with <paramref name="scopes"/>.</summary>
    private static AnalyticsApiKey NewKey(string rawKey, string scopes) => new()
    {
        Name = "Tip sharing test key",
        Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
        KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
        Scopes = scopes,
        ScopeKind = AnalyticsApiKeyScopeKinds.Global,
        IsActive = true
    };

    /// <summary>Finds a repository file from the test output directory.</summary>
    private static string FindRepositoryFile(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }

    /// <summary>Sets the connection address before the pipeline, as the reverse proxy would.</summary>
    private sealed class RemoteIpStartupFilter(IPAddress remoteIp) : IStartupFilter
    {
        /// <inheritdoc />
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = remoteIp;
                await nextMiddleware();
            });
            next(app);
        };
    }
}
