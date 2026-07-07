using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public class LicenseStateTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Endpoint = "/api/auth/license-state";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public LicenseStateTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    [Fact]
    public async Task LicenseState_WhenAccountDoesNotExist_ReturnsNoAccount()
    {
        var response = await PostAsync("missing@example.com", "anything");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<LicenseStateDto>();
        Assert.Equal("no_account", state!.Status);
        Assert.False(state.HasAccount);
        Assert.False(state.HasActiveLicense);
    }

    [Fact]
    public async Task LicenseState_WhenPasswordDoesNotMatchKnownEmail_ReturnsInvalidCredentials()
    {
        await SeedLicenseAsync("known@example.com", "KNOWN-LICENSE-001", "TIA-CONNECT-PRO", isActive: true);

        var response = await PostAsync("known@example.com", "wrong-secret");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<LicenseStateDto>();
        Assert.Equal("invalid_credentials", state!.Status);
        Assert.True(state.HasAccount);
        Assert.False(state.HasActiveLicense);
    }

    [Fact]
    public async Task LicenseState_WhenTiaLicenseIsActive_ReturnsActiveLicense()
    {
        await SeedLicenseAsync("active@example.com", "ACTIVE-LICENSE-001", "TIA-CONNECT-PRO", isActive: true,
            expiresAt: DateTime.UtcNow.AddDays(10));

        var response = await PostAsync("active@example.com", "ACTIVE-LICENSE-001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<LicenseStateDto>();
        Assert.Equal("active_license", state!.Status);
        Assert.True(state.HasAccount);
        Assert.True(state.HasActiveLicense);
        Assert.Equal("TIA-CONNECT-PRO", state.LastLicenseTypeSlug);
        Assert.Equal("ACTIVE", state.LastLicenseStatus);
        Assert.Null(state.LicenseKey);
    }

    [Fact]
    public async Task LicenseState_WhenFreemiumExpired_ReturnsFreemiumExpired()
    {
        await SeedLicenseAsync("freemium@example.com", "FREEMIUM-LICENSE-001", "TIA-CONNECT-FREEMIUM",
            isActive: true, expiresAt: DateTime.UtcNow.AddDays(-1));

        var response = await PostAsync("freemium@example.com", "FREEMIUM-LICENSE-001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<LicenseStateDto>();
        Assert.Equal("freemium_expired", state!.Status);
        Assert.False(state.HasActiveLicense);
        Assert.Equal("TIA-CONNECT-FREEMIUM", state.LastLicenseTypeSlug);
        Assert.Equal("EXPIRED", state.LastLicenseStatus);
    }

    [Fact]
    public async Task LicenseState_WhenNonFreemiumRevoked_ReturnsLicenseRevoked()
    {
        await SeedLicenseAsync("revoked@example.com", "REVOKED-LICENSE-001", "TIA-CONNECT-PRO",
            isActive: false, revokedAt: DateTime.UtcNow, revocationReason: "payment_failed");

        var response = await PostAsync("revoked@example.com", "REVOKED-LICENSE-001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<LicenseStateDto>();
        Assert.Equal("license_revoked", state!.Status);
        Assert.Equal("TIA-CONNECT-PRO", state.LastLicenseTypeSlug);
        Assert.Equal("REVOKED", state.LastLicenseStatus);
    }

    [Fact]
    public async Task LicenseState_WhenAccountSuspended_ReturnsAccountSuspended()
    {
        await SeedLicenseAsync("suspended@example.com", "SUSPENDED-LICENSE-001", "TIA-CONNECT-PRO",
            isActive: false, revokedAt: DateTime.UtcNow, revocationReason: "account_suspended");

        var response = await PostAsync("suspended@example.com", "SUSPENDED-LICENSE-001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<LicenseStateDto>();
        Assert.Equal("account_suspended", state!.Status);
        Assert.False(state.HasActiveLicense);
        Assert.Equal("REVOKED", state.LastLicenseStatus);
    }

    private async Task<HttpResponseMessage> PostAsync(string email, string password)
    {
        var client = _factory.CreateClient();
        return await client.PostAsJsonAsync(Endpoint, new { email, password });
    }

    private async Task SeedLicenseAsync(
        string email,
        string licenseKey,
        string typeSlug,
        bool isActive,
        DateTime? expiresAt = null,
        DateTime? revokedAt = null,
        string? revocationReason = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        var product = await db.Products.FirstOrDefaultAsync(p => p.Name == "T-IA Connect");
        if (product == null)
        {
            var keys = LicenseService.GenerateKeys();
            product = new Product
            {
                Id = Guid.NewGuid(),
                Name = "T-IA Connect",
                PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
                PublicKeyXml = keys.PublicKey,
                ApiSecret = "CHANGE_ME_RANDOM_SECRET"
            };
            db.Products.Add(product);
            await db.SaveChangesAsync();
        }

        var type = await db.LicenseTypes.FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug == typeSlug);
        if (type == null)
        {
            type = new LicenseType
            {
                Id = Guid.NewGuid(),
                Name = typeSlug,
                Slug = typeSlug,
                ProductId = product.Id,
                IsFree = typeSlug.EndsWith("FREEMIUM", StringComparison.OrdinalIgnoreCase)
            };
            db.LicenseTypes.Add(type);
            await db.SaveChangesAsync();
        }

        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            LicenseKey = licenseKey,
            ProductId = product.Id,
            LicenseTypeId = type.Id,
            CustomerEmail = email,
            CustomerName = "T-IA User",
            IsActive = isActive,
            ExpirationDate = expiresAt,
            RevokedAt = revokedAt,
            RevocationReason = revocationReason,
            CreationDate = DateTime.UtcNow.AddDays(-30),
            MaxSeats = 1
        });
        await db.SaveChangesAsync();
    }

    private sealed class LicenseStateDto
    {
        public string Status { get; set; } = "";
        public string Email { get; set; } = "";
        public bool HasAccount { get; set; }
        public bool HasActiveLicense { get; set; }
        public string? LastLicenseTypeSlug { get; set; }
        public string? LastLicenseStatus { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public string DashboardUrl { get; set; } = "";
        public string Message { get; set; } = "";
        public string? LicenseKey { get; set; }
    }
}
