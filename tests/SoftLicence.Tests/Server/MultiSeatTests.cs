using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using Xunit;
using SoftLicence.Server.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SoftLicence.Tests.Server;

public class MultiSeatTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public MultiSeatTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                // On force une base unique pour cette série de tests
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    private async Task<License> CreateLicenseAsync(IServiceProvider services, int maxSeats)
    {
        var db = services.GetRequiredService<LicenseDbContext>();
        var encryption = services.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        var prod = new Product { 
            Id = Guid.NewGuid(), 
            Name = "MultiApp", 
            PrivateKeyXml = encryption.Encrypt(LicenseService.GenerateKeys().PrivateKey), 
            PublicKeyXml = "k",
            ApiSecret = "secret"
        };
        var type = new LicenseType { Id = Guid.NewGuid(), Name = "T", Slug = "T" };
        var license = new License {
            Id = Guid.NewGuid(),
            LicenseKey = Guid.NewGuid().ToString().ToUpper(),
            ProductId = prod.Id,
            LicenseTypeId = type.Id,
            MaxSeats = maxSeats,
            IsActive = true,
            CustomerName = "Test",
            AllowedVersions = "*"
        };
        db.Products.Add(prod);
        db.LicenseTypes.Add(type);
        db.Licenses.Add(license);
        await db.SaveChangesAsync();
        return license;
    }

    [Fact]
    public async Task Activate_ShouldRejectSecondPc_WhenMaxSeatsIsOne()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        
        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
        }

        // PC 1 : OK
        await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "PC-1", AppName = "MultiApp" });

        // PC 2 : Rejeté
        var response = await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "PC-2", AppName = "MultiApp" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("maximum d'activations", content);
    }

    [Fact]
    public async Task Activate_ShouldAllowMultiplePcs_WhenMaxSeatsIsGreater()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        
        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 2);
            licenseKey = lic.LicenseKey;
        }

        var res1 = await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "PC-A", AppName = "MultiApp" });
        var res2 = await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "PC-B", AppName = "MultiApp" });

        Assert.Equal(HttpStatusCode.OK, res1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, res2.StatusCode);
    }
}