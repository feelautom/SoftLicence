using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TargetedLicenseResolutionPostgreSqlTests
{
    private const string GlobalSecret = "targeted-postgres-global-secret";

    [Fact]
    public async Task Resolve_EnforcesExactCanonicalSelectorsScopeAndAuthoritativeStatuses()
    {
        var provision = await PostgreSqlProvision.CreateAsync();
        try
        {
            using var factory = CreateFactory(provision.ConnectionString);
            var fixture = await SeedAsync(factory.Services);
            using var global = CreateClient(factory, GlobalSecret);

            Assert.Equal("active_license_found", await ResolveReasonAsync(global, fixture.ProductA,
                "licenseKey", fixture.ActiveKey, HttpStatusCode.OK));
            Assert.Equal("active_license_found", await ResolveReasonAsync(global, fixture.ProductA,
                "hardwareId", fixture.ActiveHardware, HttpStatusCode.OK));
            Assert.Equal("license_revoked", await ResolveReasonAsync(global, fixture.ProductA,
                "licenseKey", fixture.RevokedKey, HttpStatusCode.OK));
            Assert.Equal("license_expired", await ResolveReasonAsync(global, fixture.ProductA,
                "licenseKey", fixture.ExpiredKey, HttpStatusCode.OK));
            Assert.Equal("seat_inactive", await ResolveReasonAsync(global, fixture.ProductA,
                "hardwareId", fixture.InactiveHardware, HttpStatusCode.OK));
            Assert.Equal("license_not_found", await ResolveReasonAsync(global, fixture.ProductA,
                "licenseKey", "UNKNOWN-KEY-0001", HttpStatusCode.OK));

            foreach (var invalid in new[]
            {
                fixture.ActiveKey.ToLowerInvariant(),
                " " + fixture.ActiveKey,
                fixture.ActiveKey + " ",
                "É" + fixture.ActiveKey,
                "",
                "   "
            })
            {
                await ResolveReasonAsync(global, fixture.ProductA, "licenseKey", invalid, HttpStatusCode.BadRequest);
            }

            using var productScoped = CreateClient(factory, fixture.ProductASecret);
            Assert.Equal("active_license_found", await ResolveReasonAsync(productScoped, fixture.ProductA,
                "licenseKey", fixture.ActiveKey, HttpStatusCode.OK));
            await ResolveReasonAsync(productScoped, fixture.ProductB,
                "licenseKey", fixture.ProductBKey, HttpStatusCode.BadRequest);

            using var ambiguous = await global.PostAsJsonAsync("/api/admin/licenses/resolve", new
            {
                schema = "targeted-license-resolution-v1",
                productId = fixture.ProductA,
                licenseKey = fixture.ActiveKey,
                hardwareId = fixture.ActiveHardware
            });
            Assert.Equal(HttpStatusCode.BadRequest, ambiguous.StatusCode);

            using var extension = await global.PostAsJsonAsync("/api/admin/licenses/resolve", new
            {
                schema = "targeted-license-resolution-v1",
                productId = fixture.ProductA,
                licenseKey = fixture.ActiveKey,
                unexpected = "rejected"
            });
            Assert.Equal(HttpStatusCode.BadRequest, extension.StatusCode);
        }
        finally
        {
            await provision.DisposeAsync();
        }
    }

    private static WebApplicationFactory<Program> CreateFactory(string connectionString) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", GlobalSecret);
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connectionString));
            });
        });

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory, string secret)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", secret);
        return client;
    }

    private static async Task<string?> ResolveReasonAsync(HttpClient client, Guid productId,
        string selectorName, string selector, HttpStatusCode expectedStatus)
    {
        var body = new Dictionary<string, object?>
        {
            ["schema"] = "targeted-license-resolution-v1",
            ["productId"] = productId,
            [selectorName] = selector
        };
        using var response = await client.PostAsJsonAsync("/api/admin/licenses/resolve", body);
        Assert.Equal(expectedStatus, response.StatusCode);
        if (response.StatusCode != HttpStatusCode.OK) return null;
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("reasonCode").GetString();
    }

    private static async Task<Fixture> SeedAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        var productA = new Product { Name = "Targeted PostgreSQL A", ApiSecret = "PRODUCT-A-TARGETED-SECRET" };
        var productB = new Product { Name = "Targeted PostgreSQL B", ApiSecret = "PRODUCT-B-TARGETED-SECRET" };
        var typeA = new LicenseType { Product = productA, Name = "Pro A", Slug = "PRO-A", DefaultDurationDays = 30 };
        var typeB = new LicenseType { Product = productB, Name = "Pro B", Slug = "PRO-B", DefaultDurationDays = 30 };
        var active = NewLicense(productA, typeA, "EXACT-KEY-0001", true, DateTime.UtcNow.AddDays(30));
        var revoked = NewLicense(productA, typeA, "REVOKED-KEY-0001", false, DateTime.UtcNow.AddDays(30));
        var expired = NewLicense(productA, typeA, "EXPIRED-KEY-0001", true, DateTime.UtcNow.AddDays(-1));
        var inactive = NewLicense(productA, typeA, "INACTIVE-KEY-0001", true, DateTime.UtcNow.AddDays(30));
        var other = NewLicense(productB, typeB, "OTHER-PRODUCT-KEY-0001", true, DateTime.UtcNow.AddDays(30));
        active.Seats.Add(new LicenseSeat { HardwareId = "EXACT-HWID-0001", IsActive = true, FirstActivatedAt = DateTime.UtcNow });
        inactive.Seats.Add(new LicenseSeat { HardwareId = "INACTIVE-HWID-0001", IsActive = false, FirstActivatedAt = DateTime.UtcNow.AddDays(-1) });
        db.AddRange(productA, productB, typeA, typeB, active, revoked, expired, inactive, other);
        await db.SaveChangesAsync();
        return new(productA.Id, productB.Id, productA.ApiSecret, active.LicenseKey,
            active.Seats.Single().HardwareId, revoked.LicenseKey, expired.LicenseKey,
            inactive.Seats.Single().HardwareId, other.LicenseKey);
    }

    private static License NewLicense(Product product, LicenseType type, string key, bool active, DateTime expiration) => new()
    {
        Product = product,
        Type = type,
        LicenseKey = key,
        IsActive = active,
        ExpirationDate = expiration,
        MaxSeats = 1
    };

    private sealed record Fixture(Guid ProductA, Guid ProductB, string ProductASecret, string ActiveKey,
        string ActiveHardware, string RevokedKey, string ExpiredKey, string InactiveHardware, string ProductBKey);

    private sealed class PostgreSqlProvision(string maintenanceConnectionString, string connectionString, string database)
        : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");
            var database = "targeted_resolution_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }
            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
            await using (var db = new LicenseDbContext(options)) await db.Database.MigrateAsync();
            return new PostgreSqlProvision(maintenance, target, database);
        }

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync();
        }
    }
}
