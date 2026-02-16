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

public class ApiIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public ApiIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "CHANGE_ME_RANDOM_SECRET");
            builder.UseSetting("AdminSettings:AllowedIps", ""); 
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    private async Task SeedDataAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<LicenseDbContext>();
        var encryption = services.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        if (await db.Products.AnyAsync(p => p.Name == "YOUR_APP_NAME")) return;

        var keys = LicenseService.GenerateKeys();
        var product = new Product 
        { 
            Id = Guid.NewGuid(),
            Name = "YOUR_APP_NAME", 
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey), 
            PublicKeyXml = keys.PublicKey,
            ApiSecret = "CHANGE_ME_RANDOM_SECRET"
        };
        db.Products.Add(product);

        var trialType = new LicenseType 
        { 
            Id = Guid.NewGuid(),
            Name = "Trial", 
            Slug = "TRIAL", 
            DefaultDurationDays = 7,
            IsRecurring = true,
            DefaultMaxSeats = 1
        };
        db.LicenseTypes.Add(trialType);

        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task PostActivation_WithInvalidKey_ShouldReturnBadRequest()
    {
        var client = _factory.CreateClient();
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedDataAsync(scope.ServiceProvider);
        }

        var request = new { LicenseKey = "INVALID", HardwareId = "HW1", AppName = "YOUR_APP_NAME" };
        var response = await client.PostAsJsonAsync("/api/activation", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PostActivation_WithAutoTrial_ShouldGenerateNewLicense()
    {
        var client = _factory.CreateClient();
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedDataAsync(scope.ServiceProvider);
        }

        var request = new { LicenseKey = "YOUR_APP_NAME-FREE-TRIAL", HardwareId = "NEW-PC-123", AppName = "YOUR_APP_NAME" };
        var response = await client.PostAsJsonAsync("/api/activation", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(result.TryGetProperty("licenseFile", out _));
    }

    [Fact]
    public async Task AdminRenew_WithSecret_ShouldExtendLicense()
    {
        string licenseKey = "RENEW-ME-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var prod = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");
            
            db.Licenses.Add(new License {
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                HardwareId = "HW-RENEW",
                ExpirationDate = DateTime.UtcNow.AddDays(1),
                CustomerName = "Test",
                CustomerEmail = "test@test.com",
                IsActive = true,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        
        var request = new { TransactionId = "STRIPE_SUCCESS_UNIQUE", Reference = "INV-001" };
        var response = await client.PostAsJsonAsync($"/api/admin/licenses/{licenseKey}/renew", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
