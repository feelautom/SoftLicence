using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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

public sealed class TargetedLicenseResolutionTests
{
    private const string AdminSecret = "targeted-resolution-test-secret";

    [Fact]
    public async Task Resolve_ProtectedInfrastructureIpWithoutSecretStillReturnsUnauthorized()
    {
        const string protectedIp = "91.134.136.142";
        using var factory = CreateFactory(protectedIp);
        await using var scope = factory.Services.CreateAsyncScope();
        var authentication = scope.ServiceProvider.GetRequiredService<AdminSecretAuthenticationService>();
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(protectedIp);

        var authenticationResult = await authentication.AuthenticateAsync(context);

        Assert.False(authenticationResult.Authorized);
        Assert.Null(authenticationResult.ScopedProductId);

        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync("/api/admin/licenses/resolve", new
        {
            schema = "targeted-license-resolution-v1",
            productId = Guid.NewGuid(),
            licenseKey = "TARGETED-KEY-0001"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Resolve_ReturnsOneMinimalAuthoritativeResultWithoutPii(bool resolveByKey)
    {
        using var factory = CreateFactory();
        var fixture = await SeedAsync(factory.Services);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", AdminSecret);
        var request = new Dictionary<string, object?>
        {
            ["schema"] = "targeted-license-resolution-v1",
            ["productId"] = fixture.ProductId,
            [resolveByKey ? "licenseKey" : "hardwareId"] = resolveByKey ? fixture.LicenseKey : fixture.HardwareId
        };

        using var response = await client.PostAsJsonAsync("/api/admin/licenses/resolve", request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(body);
        Assert.Equal("Active", json.RootElement.GetProperty("status").GetString());
        Assert.Equal("active_license_found", json.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(fixture.LicenseId, json.RootElement.GetProperty("licenseId").GetGuid());
        Assert.False(json.RootElement.TryGetProperty("licenseKey", out _));
        Assert.False(json.RootElement.TryGetProperty("hardwareId", out _));
        Assert.DoesNotContain(fixture.Email, body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(fixture.CustomerName, body, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.LicenseKey, body, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.HardwareId, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Resolve_RejectsAmbiguousOrAdditionalInput()
    {
        using var factory = CreateFactory();
        var fixture = await SeedAsync(factory.Services);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", AdminSecret);

        using var response = await client.PostAsJsonAsync("/api/admin/licenses/resolve", new
        {
            schema = "targeted-license-resolution-v1",
            productId = fixture.ProductId,
            licenseKey = fixture.LicenseKey,
            hardwareId = fixture.HardwareId,
            unexpected = "must-fail"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("targeted-key-0001")]
    [InlineData(" TARGETED-KEY-0001")]
    [InlineData("TARGETED-KEY-0001 ")]
    [InlineData("TARGÉTED-KEY-0001")]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Resolve_RejectsNonCanonicalSelectorWithoutNormalization(string selector)
    {
        using var factory = CreateFactory();
        var fixture = await SeedAsync(factory.Services);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", AdminSecret);
        using var response = await client.PostAsJsonAsync("/api/admin/licenses/resolve", new
        {
            schema = "targeted-license-resolution-v1",
            productId = fixture.ProductId,
            licenseKey = selector
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static WebApplicationFactory<Program> CreateFactory(string protectedInfrastructureIps = "")
    {
        var databaseName = $"targeted-resolution-{Guid.NewGuid():N}";
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", AdminSecret);
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.UseSetting("SecuritySettings:ProtectedInfrastructureIps", protectedInfrastructureIps);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
            });
        });
    }

    private static async Task<Fixture> SeedAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        var product = new Product { Name = "T-IA Connect", ApiSecret = "product-secret" };
        var type = new LicenseType
        {
            Product = product,
            Name = "Professional",
            Slug = "TIA-PRO",
            DefaultDurationDays = 365
        };
        var license = new License
        {
            Product = product,
            Type = type,
            LicenseKey = "TARGETED-KEY-0001",
            CustomerEmail = "private@example.test",
            CustomerName = "Private Customer",
            Reference = "website-entitlement-ref",
            IsActive = true,
            ExpirationDate = DateTime.UtcNow.AddDays(30),
            MaxSeats = 1
        };
        var seat = new LicenseSeat
        {
            License = license,
            HardwareId = "TARGETED-HWID-0001",
            IsActive = true,
            FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
            LastCheckInAt = DateTime.UtcNow
        };
        db.AddRange(product, type, license, seat);
        await db.SaveChangesAsync();
        return new(product.Id, license.Id, license.LicenseKey, seat.HardwareId,
            license.CustomerEmail, license.CustomerName);
    }

    private sealed record Fixture(
        Guid ProductId,
        Guid LicenseId,
        string LicenseKey,
        string HardwareId,
        string Email,
        string CustomerName);
}
