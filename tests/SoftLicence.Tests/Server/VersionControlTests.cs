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
            HardwareId = "A000000000000001",
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
            HardwareId = "A000000000000001",
            AppName = "YOUR_APP_NAME",
            AppVersion = "1.2.3" // Version compatible v1.*
        };

        // Act
        var response = await client.PostAsJsonAsync("/api/activation", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CheckStatus_WithExpiredLicense_ShouldReturnExpiredWithoutLicenseFile()
    {
        // Arrange
        var licenseKey = "EXPIRED-CHECK-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

            var prod = new Product { Id = Guid.NewGuid(), Name = "ExpiredApp", PrivateKeyXml = encryption.Encrypt("k"), PublicKeyXml = "k" };
            var type = new LicenseType { Id = Guid.NewGuid(), Name = "T", Slug = "T" };
            db.Products.Add(prod);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                AllowedVersions = "*",
                IsActive = true,
                CustomerName = "Test",
                ExpirationDate = DateTime.UtcNow.AddDays(-1)
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var request = new
        {
            LicenseKey = licenseKey,
            HardwareId = "A000000000000002",
            AppName = "ExpiredApp",
            AppVersion = "2.1.781"
        };

        // Act
        var response = await client.PostAsJsonAsync("/api/activation/check", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("EXPIRED", GetString(json.RootElement, "status"));
        Assert.Null(GetString(json.RootElement, "licenseFile"));
    }

    [Fact]
    public async Task CheckStatus_WithRevokedLicense_ShouldReturnRevokedWithoutLicenseFile()
    {
        // Arrange
        var licenseKey = "REVOKED-CHECK-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

            var prod = new Product { Id = Guid.NewGuid(), Name = "RevokedApp", PrivateKeyXml = encryption.Encrypt("k"), PublicKeyXml = "k" };
            var type = new LicenseType { Id = Guid.NewGuid(), Name = "T", Slug = "T" };
            db.Products.Add(prod);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                AllowedVersions = "*",
                IsActive = false,
                CustomerName = "Test",
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var request = new
        {
            LicenseKey = licenseKey,
            HardwareId = "A000000000000003",
            AppName = "RevokedApp",
            AppVersion = "2.1.781"
        };

        // Act
        var response = await client.PostAsJsonAsync("/api/activation/check", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("REVOKED", GetString(json.RootElement, "status"));
        Assert.Null(GetString(json.RootElement, "licenseFile"));
    }

    [Fact]
    public async Task CheckStatus_WithActiveLicenseBelowMinimumVersion_ShouldReturnUpdateRequiredWithoutRevokingLicense()
    {
        var licenseKey = "MIN-VERSION-CHECK-KEY";
        Guid licenseId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

            var prod = new Product
            {
                Id = Guid.NewGuid(),
                Name = "MinVersionApp",
                PrivateKeyXml = encryption.Encrypt("k"),
                PublicKeyXml = "k",
                MinimumAllowedVersion = "2.2.0"
            };
            var type = new LicenseType { Id = Guid.NewGuid(), ProductId = prod.Id, Name = "Pro", Slug = "PRO", IsFree = false };
            licenseId = Guid.NewGuid();
            db.Products.Add(prod);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(new License
            {
                Id = licenseId,
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                AllowedVersions = "*",
                HardwareId = "A000000000000004",
                IsActive = true,
                CustomerName = "Test",
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "A000000000000004",
            AppName = "MinVersionApp",
            AppVersion = "2.1.736"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("UPDATE_REQUIRED", GetString(json.RootElement, "status"));
        Assert.Equal("Update required by server", GetString(json.RootElement, "errorMessage"));
        Assert.Null(GetString(json.RootElement, "licenseFile"));

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await verifyDb.Licenses.SingleAsync(l => l.Id == licenseId);
        Assert.True(license.IsActive);
        Assert.Null(license.RevokedAt);
    }

    [Fact]
    public async Task CheckStatus_WithRevokedLicenseBelowMinimumVersion_ShouldReturnRevoked()
    {
        var licenseKey = "REVOKED-MIN-VERSION-CHECK-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

            var prod = new Product
            {
                Id = Guid.NewGuid(),
                Name = "RevokedMinVersionApp",
                PrivateKeyXml = encryption.Encrypt("k"),
                PublicKeyXml = "k",
                MinimumAllowedVersion = "2.2.0"
            };
            var type = new LicenseType { Id = Guid.NewGuid(), ProductId = prod.Id, Name = "Pro", Slug = "PRO", IsFree = false };
            db.Products.Add(prod);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(new License
            {
                Id = Guid.NewGuid(),
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                AllowedVersions = "*",
                HardwareId = "A000000000000005",
                IsActive = false,
                RevokedAt = DateTime.UtcNow.AddDays(-1),
                CustomerName = "Test",
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "A000000000000005",
            AppName = "RevokedMinVersionApp",
            AppVersion = "2.1.736"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("REVOKED", GetString(json.RootElement, "status"));
        Assert.Null(GetString(json.RootElement, "licenseFile"));
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                return property.Value.ValueKind == JsonValueKind.Null ? null : property.Value.GetString();
        }

        return null;
    }
}
