using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002781: barriers of the licence-type write routes before any database work. The routes are under
/// <c>/api/analytics</c>, which the Internet can reach, so writing needs the internal network (the MCP), like the
/// administration routes of types, and the dedicated scope that no key receives by default.
/// </summary>
public sealed class LicenseTypeChangeRouteTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string ReadOnlyKey = "sla_test_type_changes_readonly_001";
    private const string WriterKey = "sla_test_type_changes_writer_001";
    private const string Preview = "/api/analytics/license-types/changes/preview";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    /// <summary>Builds an isolated server; <paramref name="factory"/> is the shared xUnit fixture.</summary>
    public LicenseTypeChangeRouteTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// The startup filter sets a public address on every request; a key holding the write scope is still refused with
    /// INTERNAL_NETWORK_REQUIRED before any key or database work.
    /// </summary>
    [Fact]
    public async Task Preview_FromOutsideTheInternalNetwork_IsRefusedEvenWithTheWriteScope()
    {
        // 203.0.113.0/24 is reserved for documentation (RFC 5737): a public address that can never be a real caller.
        var factory = CreateFactory(remoteIp: IPAddress.Parse("203.0.113.9"));
        await SeedAsync(factory);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", WriterKey);

        var response = await client.PostAsJsonAsync(Preview, new { productName = "Product A", operations = new[] { new { kind = "updateType", slug = "PLAIN", isFree = true } } });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("INTERNAL_NETWORK_REQUIRED", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    /// <summary>
    /// From the loopback address, a global key with only the read scopes gets 403 ANALYTICS_SCOPE_REQUIRED naming
    /// license-types:write.
    /// </summary>
    [Fact]
    public async Task Preview_WithAReadOnlyKey_IsRefusedWithTheMissingScope()
    {
        var factory = CreateFactory(remoteIp: IPAddress.Loopback);
        await SeedAsync(factory);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ReadOnlyKey);

        var response = await client.PostAsJsonAsync(Preview, new { productName = "Product A", operations = new[] { new { kind = "updateType", slug = "PLAIN", isFree = true } } });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("ANALYTICS_SCOPE_REQUIRED", body, StringComparison.Ordinal);
        Assert.Contains(AnalyticsApiKeyScopes.LicenseTypesWrite, body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Adding the scope keeps the other scopes and their order, adding it again under another case does not duplicate
    /// it, and removing it restores the original list.
    /// </summary>
    [Fact]
    public void WithScope_AddsOnceAndRemoves_KeepingTheOtherScopes()
    {
        var granted = AnalyticsApiKeyScopes.WithScope("telemetry:read security:read", AnalyticsApiKeyScopes.LicenseTypesWrite, true);
        Assert.Equal("telemetry:read security:read license-types:write", granted);
        Assert.Equal(granted, AnalyticsApiKeyScopes.WithScope(granted.Replace("license-types:write", "LICENSE-TYPES:WRITE"), AnalyticsApiKeyScopes.LicenseTypesWrite, true));
        Assert.Equal("telemetry:read security:read", AnalyticsApiKeyScopes.WithScope(granted, AnalyticsApiKeyScopes.LicenseTypesWrite, false));
        Assert.True(AnalyticsApiKeyAuthService.HasScope(granted, AnalyticsApiKeyScopes.LicenseTypesWrite));
    }

    /// <summary>
    /// Reads the key screen source: the creation method of a global key never mentions the write scope, and the screen
    /// exposes the per-key grant button instead.
    /// </summary>
    [Fact]
    public void NewGlobalKeys_NeverReceiveTheWriteScopeByDefault()
    {
        var page = File.ReadAllText(FindRepositoryFile("src", "SoftLicence.Server", "Components", "Pages", "GlobalAnalyticsKeys.razor"));
        var creation = page[page.IndexOf("private async Task CreateGlobalAnalyticsApiKey()", StringComparison.Ordinal)..];
        creation = creation[..creation.IndexOf("private async Task RevokeAnalyticsApiKey", StringComparison.Ordinal)];
        Assert.DoesNotContain("LicenseTypesWrite", creation, StringComparison.Ordinal);
        Assert.Contains("SetLicenseTypesWrite(key, !canWriteTypes)", page, StringComparison.Ordinal);
    }

    /// <summary>Server on an in-memory catalogue, whose requests come from <paramref name="remoteIp"/>.</summary>
    private WebApplicationFactory<Program> CreateFactory(IPAddress? remoteIp) => _factory.WithWebHostBuilder(builder =>
    {
        builder.UseSetting("IsIntegrationTest", "true");
        builder.UseSetting("AdminSettings:ApiSecret", "admin-secret");
        builder.UseSetting("AdminSettings:AllowedIps", "");
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<LicenseDbContext>>();
            services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
            services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
            services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new RemoteIpStartupFilter(remoteIp));
        });
    });

    /// <summary>Seeds one product, one type, a read-only global key and a key holding only the write scope.</summary>
    private static async Task SeedAsync(WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        if (await db.AnalyticsApiKeys.AnyAsync()) return;
        var product = new Product { Name = "Product A", PrivateKeyXml = "k", PublicKeyXml = "k" };
        db.Products.Add(product);
        db.LicenseTypes.Add(new LicenseType { ProductId = product.Id, Name = "Plain", Slug = "PLAIN" });
        db.AnalyticsApiKeys.AddRange(
            NewKey(ReadOnlyKey, $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.SecurityRead} {AnalyticsApiKeyScopes.MultiProductRead}"),
            NewKey(WriterKey, AnalyticsApiKeyScopes.LicenseTypesWrite));
        await db.SaveChangesAsync();
    }

    /// <summary>Creates an active global key.</summary>
    private static AnalyticsApiKey NewKey(string rawKey, string scopes) => new()
    {
        Name = "Type changes test key",
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
    private sealed class RemoteIpStartupFilter(IPAddress? remoteIp) : Microsoft.AspNetCore.Hosting.IStartupFilter
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
