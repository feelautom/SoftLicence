using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002469 (audit finding C6): the seven licence-type administration routes must require the
/// admin secret and the product scope, not only a private network address. Every request here comes
/// from a Docker-network address, which is exactly what any compromised application on the server has.
/// </summary>
public sealed class LicenseTypeAdminAuthorizationPostgreSqlTests
{
    /// <summary>Synthetic global admin credential used only by the isolated in-process host.</summary>
    private const string GlobalSecret = "tkt2469-global-fixture-secret";
    /// <summary>Synthetic product secret of <see cref="Fixture.AlphaName"/>.</summary>
    private const string AlphaSecret = "tkt2469-alpha-product-secret";
    /// <summary>Synthetic product secret of <see cref="Fixture.BetaName"/>.</summary>
    private const string BetaSecret = "tkt2469-beta-product-secret";
    /// <summary>Address of the SoftLicence container on the shared Docker network (audit C6).</summary>
    private const string DockerNetworkAddress = "10.0.1.60";
    /// <summary>Public documentation address (RFC 5737), never internal.</summary>
    private const string PublicAddress = "203.0.113.10";
    /// <summary>Test-only header read by the startup filter to choose the connection address.</summary>
    private const string TestRemoteIpHeader = "X-Tkt2469-Test-Remote-Ip";
    /// <summary>Custom parameter seeded on both fixture types.</summary>
    private const string SeededParamKey = "maxAccounts";

    /// <summary>The seven routes that only checked the private address before TKT-002469.</summary>
    public static TheoryData<string> Routes() => new()
    {
        "create", "list", "update", "delete", "add-param", "update-param", "delete-param"
    };

    /// <summary>The same routes, plus the product-name routes called with a different name casing.</summary>
    public static TheoryData<string> ScopeRoutes()
    {
        var routes = Routes();
        routes.Add("create-lowercase-name");
        routes.Add("list-lowercase-name");
        return routes;
    }

    /// <summary>An internal address without any secret is refused with 401 and changes nothing.</summary>
    [Theory]
    [MemberData(nameof(Routes))]
    public async Task InternalAddressWithoutSecret_IsRefused(string route)
    {
        await using var fixture = await Fixture.CreateAsync();
        var before = await fixture.SnapshotAsync();
        using var response = await fixture.SendAsync(route, Target.Alpha, secret: null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, await fixture.SnapshotAsync());
    }

    /// <summary>An internal address with an unknown or empty secret is refused with 401 and changes nothing.</summary>
    [Theory]
    [MemberData(nameof(Routes))]
    public async Task InternalAddressWithWrongSecret_IsRefused(string route)
    {
        await using var fixture = await Fixture.CreateAsync();
        var before = await fixture.SnapshotAsync();
        using var wrong = await fixture.SendAsync(route, Target.Alpha, secret: "tkt2469-unknown-secret");
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        using var empty = await fixture.SendAsync(route, Target.Alpha, secret: string.Empty);
        Assert.Equal(HttpStatusCode.Unauthorized, empty.StatusCode);
        Assert.Equal(before, await fixture.SnapshotAsync());
    }

    /// <summary>
    /// A product secret cannot reach another product: by product name (any casing) for the catalogue
    /// routes, or by the identifier of a type that belongs to the other product for the routes by id.
    /// </summary>
    [Theory]
    [MemberData(nameof(ScopeRoutes))]
    public async Task ProductSecretOfAnotherProduct_IsRefused(string route)
    {
        await using var fixture = await Fixture.CreateAsync();
        var before = await fixture.SnapshotAsync();
        using var response = await fixture.SendAsync(route, Target.Beta, AlphaSecret);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(before, await fixture.SnapshotAsync());
    }

    /// <summary>A valid global secret from a public address stays refused by the private-address check.</summary>
    [Theory]
    [MemberData(nameof(Routes))]
    public async Task PublicAddressWithGlobalSecret_StaysRefused(string route)
    {
        await using var fixture = await Fixture.CreateAsync();
        var before = await fixture.SnapshotAsync();
        using var response = await fixture.SendAsync(route, Target.Alpha, GlobalSecret, PublicAddress);
        Assert.False(response.IsSuccessStatusCode, $"{route} accepted a public address: {(int)response.StatusCode}");
        Assert.Equal(before, await fixture.SnapshotAsync());
    }

    /// <summary>
    /// The legitimate callers keep working: the product's own secret (the website) and the global
    /// secret manage the types of the product, including the public trial opt-in.
    /// </summary>
    [Theory]
    [InlineData(AlphaSecret)]
    [InlineData(GlobalSecret)]
    public async Task OwnProductSecretAndGlobalSecret_ManageTypes(string secret)
    {
        await using var fixture = await Fixture.CreateAsync();
        foreach (var route in new[] { "list", "create", "update", "add-param", "update-param", "delete-param" })
        {
            using var response = await fixture.SendAsync(route, Target.Alpha, secret);
            Assert.True(response.IsSuccessStatusCode, $"{route}: {(int)response.StatusCode}");
        }

        await using (var db = fixture.Db())
        {
            var alpha = await db.LicenseTypes.Include(t => t.CustomParams).AsNoTracking()
                .SingleAsync(t => t.Id == fixture.AlphaTypeId);
            Assert.True(alpha.AllowPublicTrial);
            Assert.DoesNotContain(alpha.CustomParams, p => p.Key == SeededParamKey);
            Assert.Contains(alpha.CustomParams, p => p.Key == "injected" && p.Value == "1");
            Assert.True(await db.LicenseTypes.AnyAsync(t => t.ProductId == fixture.AlphaProductId && t.Slug == "TKT2469-INJECTED"));
            var beta = await db.LicenseTypes.Include(t => t.CustomParams).AsNoTracking()
                .SingleAsync(t => t.Id == fixture.BetaTypeId);
            Assert.False(beta.AllowPublicTrial);
            Assert.Contains(beta.CustomParams, p => p.Key == SeededParamKey && p.Value == "5");
        }

        using var deleted = await fixture.SendAsync("delete", Target.Alpha, secret);
        Assert.True(deleted.IsSuccessStatusCode, $"delete: {(int)deleted.StatusCode}");
        await using var check = fixture.Db();
        Assert.False(await check.LicenseTypes.AnyAsync(t => t.Id == fixture.AlphaTypeId));
        Assert.True(await check.LicenseTypes.AnyAsync(t => t.Id == fixture.BetaTypeId));
    }

    /// <summary>Which seeded product a request aims at.</summary>
    private enum Target { Alpha, Beta }

    /// <summary>Isolated PostgreSQL database and in-process server with two products and one type each.</summary>
    private sealed class Fixture : IAsyncDisposable
    {
        /// <summary>Exact name of the product owning <see cref="AlphaSecret"/>.</summary>
        public const string AlphaName = "TKT2469-ALPHA";
        /// <summary>Exact name of the product owning <see cref="BetaSecret"/>.</summary>
        public const string BetaName = "TKT2469-BETA";

        /// <summary>Loopback maintenance connection used only to remove the owned database.</summary>
        private readonly string maintenance;
        /// <summary>Generated ASCII database identifier.</summary>
        private readonly string database;
        /// <summary>Private fixture connection; never logged.</summary>
        private readonly string connection;
        /// <summary>Owned in-process HTTP server, disposed before database removal.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Client without default credentials and without redirect following.</summary>
        private readonly HttpClient client;

        /// <summary>Creates an isolated host bound only to the owned database.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance;
            this.database = database;
            this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", GlobalSecret);
                builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                    services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                    services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                    services.RemoveAll<LicenseDbContext>();
                    services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connection));
                    services.AddTransient<IStartupFilter, RemoteAddressStartupFilter>();
                });
            });
            client = host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        }

        /// <summary>Product identifier of <see cref="AlphaName"/>.</summary>
        public Guid AlphaProductId { get; private set; }
        /// <summary>Type identifier owned by <see cref="AlphaName"/>.</summary>
        public Guid AlphaTypeId { get; private set; }
        /// <summary>Type identifier owned by <see cref="BetaName"/>.</summary>
        public Guid BetaTypeId { get; private set; }

        /// <summary>Clones the current schema and seeds two products, each with a closed type and one parameter.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("tkt2469types");
            var fixture = new Fixture(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                var alpha = new Product { Name = AlphaName, ApiSecret = AlphaSecret };
                var beta = new Product { Name = BetaName, ApiSecret = BetaSecret };
                var alphaType = new LicenseType { Product = alpha, Name = "Alpha Pro", Slug = "TKT2469-PRO" };
                var betaType = new LicenseType { Product = beta, Name = "Beta Pro", Slug = "TKT2469-PRO" };
                alphaType.CustomParams.Add(new LicenseTypeCustomParam { Key = SeededParamKey, Name = "Comptes", Value = "5" });
                betaType.CustomParams.Add(new LicenseTypeCustomParam { Key = SeededParamKey, Name = "Comptes", Value = "5" });
                db.AddRange(alpha, beta, alphaType, betaType);
                await db.SaveChangesAsync();
                fixture.AlphaProductId = alpha.Id;
                fixture.AlphaTypeId = alphaType.Id;
                fixture.BetaTypeId = betaType.Id;
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        /// <summary>Creates a fresh context for observing committed state.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);

        /// <summary>Serializes every product, type and parameter so any write becomes visible.</summary>
        public async Task<string> SnapshotAsync()
        {
            await using var db = Db();
            var types = await db.LicenseTypes.AsNoTracking().Include(t => t.CustomParams)
                .OrderBy(t => t.Id).ToListAsync();
            var products = await db.Products.AsNoTracking().OrderBy(p => p.Id)
                .Select(p => p.Id + ":" + p.Name).ToListAsync();
            return string.Join('|', products) + "#" + string.Join('|', types.Select(t =>
                $"{t.Id}:{t.ProductId}:{t.Name}:{t.Slug}:{t.AllowPublicTrial}:{t.IsFree}:{t.DefaultDurationDays}:"
                + string.Join(',', t.CustomParams.OrderBy(p => p.Key, StringComparer.Ordinal)
                    .Select(p => $"{p.Key}={p.Name}={p.Value}"))));
        }

        /// <summary>Sends one of the seven routes against the chosen product, from the chosen address.</summary>
        public async Task<HttpResponseMessage> SendAsync(string route, Target target, string? secret, string address = DockerNetworkAddress)
        {
            var productName = target == Target.Alpha ? AlphaName : BetaName;
            var typeId = target == Target.Alpha ? AlphaTypeId : BetaTypeId;
            var products = $"/api/admin/products/{Uri.EscapeDataString(productName)}/license-types";
            var types = $"/api/admin/license-types/{typeId}";
            var param = new { key = SeededParamKey, name = "Comptes", value = "999" };
            using var request = route switch
            {
                "create" => Json(HttpMethod.Post, products, new { name = "Injected", slug = "TKT2469-INJECTED", allowPublicTrial = true }),
                "create-lowercase-name" => Json(HttpMethod.Post,
                    $"/api/admin/products/{Uri.EscapeDataString(productName.ToLowerInvariant())}/license-types",
                    new { name = "Injected", slug = "TKT2469-INJECTED", allowPublicTrial = true }),
                "list" => new HttpRequestMessage(HttpMethod.Get, products),
                "list-lowercase-name" => new HttpRequestMessage(HttpMethod.Get,
                    $"/api/admin/products/{Uri.EscapeDataString(productName.ToLowerInvariant())}/license-types"),
                "update" => Json(HttpMethod.Put, types, new { allowPublicTrial = true }),
                "delete" => new HttpRequestMessage(HttpMethod.Delete, types),
                "add-param" => Json(HttpMethod.Post, $"{types}/params", new { key = "injected", name = "Injected", value = "1" }),
                "update-param" => Json(HttpMethod.Put, $"{types}/params/{SeededParamKey}", param),
                "delete-param" => new HttpRequestMessage(HttpMethod.Delete, $"{types}/params/{SeededParamKey}"),
                _ => throw new ArgumentOutOfRangeException(nameof(route), route, "Unknown licence-type route.")
            };
            request.Headers.Add(TestRemoteIpHeader, address);
            if (secret != null) request.Headers.TryAddWithoutValidation("X-Admin-Secret", secret);
            return await client.SendAsync(request);
        }

        /// <summary>Builds a JSON request for the given method and path.</summary>
        private static HttpRequestMessage Json(HttpMethod method, string path, object body) =>
            new(method, path) { Content = JsonContent.Create(body) };

        /// <summary>Stops the server, then removes the owned database.</summary>
        public async ValueTask DisposeAsync()
        {
            client.Dispose();
            await host.DisposeAsync();
            await PostgreSqlModelDatabase.DropAsync(maintenance, database);
        }
    }

    /// <summary>Sets the connection address from the test header before any application middleware.</summary>
    private sealed class RemoteAddressStartupFilter : IStartupFilter
    {
        /// <summary>Prepends the address assignment so audit, security and controllers see the same caller.</summary>
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
}
