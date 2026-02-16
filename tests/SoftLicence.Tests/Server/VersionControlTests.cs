using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;
using SoftLicence.Server.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SoftLicence.Tests.Server;

public class VersionControlTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public VersionControlTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                var dbName = Guid.NewGuid().ToString();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(dbName));
            });
        });
    }

    [Fact]
    public async Task Activate_WithWrongVersion_ShouldReturnBadRequest()
    {
        // Arrange
        var licenseKey = "V1-ONLY-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();
            
            var prod = new Product { Id = Guid.NewGuid(), Name = "YOUR_APP_NAME", PrivateKeyXml = encryption.Encrypt("k"), PublicKeyXml = "k" };
            var type = new LicenseType { Id = Guid.NewGuid(), Name = "T", Slug = "T" };
            db.Products.Add(prod);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(new License {
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                AllowedVersions = "1.*", // Uniquement v1
                IsActive = true,
                CustomerName = "Test"
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var request = new { 
            LicenseKey = licenseKey, 
            HardwareId = "HW1", 
            AppName = "YOUR_APP_NAME",
            AppVersion = "2.0.0" // Tentative en v2
        };

        // Act
        var response = await client.PostAsJsonAsync("/api/activation", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.True(content.Contains("pas valide pour la version 2.0.0") || content.Contains("not valid for version 2.0.0"));
    }

    [Fact]
    public async Task Activate_WithCorrectVersion_ShouldSucceed()
    {
        // Arrange
        var licenseKey = "V1-OK-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

            var prod = new Product { Id = Guid.NewGuid(), Name = "YOUR_APP_NAME", PrivateKeyXml = encryption.Encrypt(LicenseService.GenerateKeys().PrivateKey), PublicKeyXml = "k" };
            var type = new LicenseType { Id = Guid.NewGuid(), Name = "T", Slug = "T" };
            db.Products.Add(prod);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(new License {
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                AllowedVersions = "1.*",
                IsActive = true,
                CustomerName = "Test"
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var request = new { 
            LicenseKey = licenseKey, 
            HardwareId = "HW1", 
            AppName = "YOUR_APP_NAME",
            AppVersion = "1.2.3" // Version compatible v1.*
        };

        // Act
        var response = await client.PostAsJsonAsync("/api/activation", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
