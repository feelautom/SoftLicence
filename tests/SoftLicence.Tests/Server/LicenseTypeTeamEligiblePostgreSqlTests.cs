using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
/// TKT-002717: the <c>TeamEligible</c> licence-type setting is stored and exposed, never interpreted. These tests
/// prove the admin write routes, every licence-type read route and the licence detail read by the website
/// (<c>GET /api/admin/licenses/{key}</c>) carry the exact JSON field <c>teamEligible</c>, false by default.
/// </summary>
public sealed class LicenseTypeTeamEligiblePostgreSqlTests
{
    /// <summary>Synthetic global admin credential used only by the isolated in-process host.</summary>
    private const string GlobalSecret = "tkt2717-global-fixture-secret";
    /// <summary>Private Docker-network address required by the licence-type routes.</summary>
    private const string InternalAddress = "10.0.1.60";
    /// <summary>Test-only header read by the startup filter to choose the connection address.</summary>
    private const string TestRemoteIpHeader = "X-Tkt2717-Test-Remote-Ip";
    /// <summary>Exact name of the seeded product.</summary>
    private const string ProductName = "TKT2717-PRODUCT";

    /// <summary>A type created without the field is not team eligible; an explicit true is stored and returned.</summary>
    [Fact]
    public async Task Create_DefaultsToFalse_AndStoresExplicitTrue()
    {
        await using var fixture = await Fixture.CreateAsync();

        using var plain = await fixture.SendAsync(HttpMethod.Post, fixture.TypesPath, new { name = "Plain", slug = "TKT2717-PLAIN" });
        Assert.Equal(HttpStatusCode.OK, plain.StatusCode);
        Assert.False(await ReadTeamEligibleAsync(plain));

        using var team = await fixture.SendAsync(HttpMethod.Post, fixture.TypesPath, new { name = "Team", slug = "TKT2717-NEWTEAM", teamEligible = true });
        Assert.Equal(HttpStatusCode.OK, team.StatusCode);
        Assert.True(await ReadTeamEligibleAsync(team));

        await using var db = fixture.Db();
        Assert.False((await db.LicenseTypes.AsNoTracking().SingleAsync(t => t.Slug == "TKT2717-PLAIN")).TeamEligible);
        Assert.True((await db.LicenseTypes.AsNoTracking().SingleAsync(t => t.Slug == "TKT2717-NEWTEAM")).TeamEligible);
    }

    /// <summary>The update route changes the field when provided and leaves it unchanged when omitted.</summary>
    [Fact]
    public async Task Update_ChangesOnlyWhenProvided()
    {
        await using var fixture = await Fixture.CreateAsync();
        var path = $"/api/admin/license-types/{fixture.StandardTypeId}";

        using var enabled = await fixture.SendAsync(HttpMethod.Put, path, new { teamEligible = true });
        Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        Assert.True(await ReadTeamEligibleAsync(enabled));

        using var untouched = await fixture.SendAsync(HttpMethod.Put, path, new { name = "Renamed" });
        Assert.Equal(HttpStatusCode.OK, untouched.StatusCode);
        Assert.True(await ReadTeamEligibleAsync(untouched));

        using var disabled = await fixture.SendAsync(HttpMethod.Put, path, new { teamEligible = false });
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        Assert.False(await ReadTeamEligibleAsync(disabled));

        await using var db = fixture.Db();
        var type = await db.LicenseTypes.AsNoTracking().SingleAsync(t => t.Id == fixture.StandardTypeId);
        Assert.False(type.TeamEligible);
        Assert.Equal("Renamed", type.Name);
    }

    /// <summary>The catalogue, by-slug and by-id reads all carry the stored value of each type.</summary>
    [Fact]
    public async Task TypeReads_ExposeTeamEligible()
    {
        await using var fixture = await Fixture.CreateAsync();

        using var list = await fixture.SendAsync(HttpMethod.Get, fixture.TypesPath);
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        using (var document = JsonDocument.Parse(await list.Content.ReadAsStringAsync()))
        {
            var bySlug = document.RootElement.EnumerateArray()
                .ToDictionary(t => t.GetProperty("slug").GetString()!, t => t.GetProperty("teamEligible").GetBoolean(), StringComparer.Ordinal);
            Assert.True(bySlug["TKT2717-TEAM"]);
            Assert.False(bySlug["TKT2717-STANDARD"]);
        }

        using var slug = await fixture.SendAsync(HttpMethod.Get, $"{fixture.TypesPath}/by-slug/TKT2717-TEAM");
        Assert.Equal(HttpStatusCode.OK, slug.StatusCode);
        Assert.True(await ReadTeamEligibleAsync(slug));

        using var id = await fixture.SendAsync(HttpMethod.Get, $"{fixture.TypesPath}/by-id/{fixture.StandardTypeId}");
        Assert.Equal(HttpStatusCode.OK, id.StatusCode);
        Assert.False(await ReadTeamEligibleAsync(id));
    }

    /// <summary>The licence detail read by the website carries the value of the licence's own type.</summary>
    [Fact]
    public async Task LicenseDetail_ExposesTheTypeValue()
    {
        await using var fixture = await Fixture.CreateAsync();

        using var team = await fixture.SendAsync(HttpMethod.Get, $"/api/admin/licenses/{fixture.TeamLicenseKey}");
        Assert.Equal(HttpStatusCode.OK, team.StatusCode);
        Assert.True(await ReadTeamEligibleAsync(team));

        using var standard = await fixture.SendAsync(HttpMethod.Get, $"/api/admin/licenses/{fixture.StandardLicenseKey}");
        Assert.Equal(HttpStatusCode.OK, standard.StatusCode);
        Assert.False(await ReadTeamEligibleAsync(standard));
    }

    /// <summary>Reads the exact camelCase <c>teamEligible</c> boolean of a JSON object response.</summary>
    /// <param name="response">Successful response whose body is one JSON object.</param>
    /// <returns>The boolean value; the test fails when the property is missing or not a boolean.</returns>
    private static async Task<bool> ReadTeamEligibleAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("teamEligible").GetBoolean();
    }

    /// <summary>Isolated PostgreSQL database and in-process server with one team type, one standard type and one licence each.</summary>
    private sealed class Fixture : IAsyncDisposable
    {
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

        /// <summary>Catalogue route of the seeded product.</summary>
        public string TypesPath => $"/api/admin/products/{Uri.EscapeDataString(ProductName)}/license-types";
        /// <summary>Identifier of the seeded type that is not team eligible.</summary>
        public Guid StandardTypeId { get; private set; }
        /// <summary>Key of the licence whose type is team eligible.</summary>
        public string TeamLicenseKey { get; private set; } = string.Empty;
        /// <summary>Key of the licence whose type is not team eligible.</summary>
        public string StandardLicenseKey { get; private set; } = string.Empty;

        /// <summary>Clones the current schema and seeds one product with a team type and a standard type, each holding one licence.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("tkt2717team");
            var fixture = new Fixture(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                var product = new Product { Name = ProductName, ApiSecret = "tkt2717-product-secret" };
                var team = new LicenseType { Product = product, Name = "Team", Slug = "TKT2717-TEAM", TeamEligible = true };
                var standard = new LicenseType { Product = product, Name = "Standard", Slug = "TKT2717-STANDARD" };
                var teamLicense = NewLicense(product, team, "TKT2717-TEAM-KEY");
                var standardLicense = NewLicense(product, standard, "TKT2717-STANDARD-KEY");
                db.AddRange(product, team, standard, teamLicense, standardLicense);
                await db.SaveChangesAsync();
                fixture.StandardTypeId = standard.Id;
                fixture.TeamLicenseKey = teamLicense.LicenseKey;
                fixture.StandardLicenseKey = standardLicense.LicenseKey;
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        /// <summary>Builds one synthetic licence of the given type.</summary>
        private static License NewLicense(Product product, LicenseType type, string key) => new()
        {
            Product = product, Type = type, LicenseKey = key,
            CustomerName = "Synthetic buyer", CustomerEmail = "buyer@example.test",
            MaxSeats = 1, ExpirationDate = DateTime.UtcNow.AddDays(30)
        };

        /// <summary>Creates a fresh context for observing committed state.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);

        /// <summary>Sends an authenticated request from the internal address, with an optional JSON body.</summary>
        public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            using var request = new HttpRequestMessage(method, path);
            if (body != null) request.Content = JsonContent.Create(body);
            request.Headers.Add(TestRemoteIpHeader, InternalAddress);
            request.Headers.TryAddWithoutValidation("X-Admin-Secret", GlobalSecret);
            return await client.SendAsync(request);
        }

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
