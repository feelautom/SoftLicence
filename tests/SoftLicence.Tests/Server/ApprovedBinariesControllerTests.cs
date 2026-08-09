using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ApprovedBinariesControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string GlobalSecret = "approved-binaries-global-secret";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = $"approved-binaries-{Guid.NewGuid():N}";

    public ApprovedBinariesControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", GlobalSecret);
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    [Fact]
    public async Task PutThenGet_WithGlobalSecret_RegistersAndVerifiesAuthoritativeBaseline()
    {
        var product = await SeedProductAsync("product-secret");
        var client = CreateClient(GlobalSecret);

        var first = await PutAsync(client, product.Id, "release-first", Hash('a'));
        var retry = await PutAsync(client, product.Id, "release-first", Hash('a'));
        var get = await client.GetAsync(Route(product.Id));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.False((await ReadJsonAsync(first)).GetProperty("idempotent").GetBoolean());
        Assert.True((await ReadJsonAsync(retry)).GetProperty("idempotent").GetBoolean());
        var body = await ReadJsonAsync(get);
        Assert.Equal("Approved", body.GetProperty("verdict").GetString());
        Assert.True(body.GetProperty("authoritative").GetBoolean());
        Assert.Equal("release-first", body.GetProperty("registrationId").GetString());
        Assert.Equal(Hash('d'), body.GetProperty("manifestDigestSha256").GetString());
        Assert.Equal(64, body.GetProperty("baselineDigestSha256").GetString()!.Length);
        Assert.Equal(3, body.GetProperty("artifacts").GetArrayLength());
    }

    [Fact]
    public async Task Put_WithDifferentExistingHash_ReturnsConflictAndDoesNotOverwrite()
    {
        var product = await SeedProductAsync("product-secret");
        var client = CreateClient(GlobalSecret);
        Assert.Equal(HttpStatusCode.Created, (await PutAsync(client, product.Id, "release-first", Hash('a'))).StatusCode);

        var conflict = await PutAsync(client, product.Id, "release-conflict", Hash('f'));

        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal("baseline_registration_conflict", (await ReadJsonAsync(conflict)).GetProperty("error").GetString());
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.Equal(Hash('a'), (await db.ApprovedBinaries.SingleAsync(row => row.Key == "FP_EXE")).Hash);
    }

    [Fact]
    public async Task Put_WithProductScopedSecretForAnotherProduct_IsForbidden()
    {
        var requestedProduct = await SeedProductAsync("requested-secret");
        var otherProduct = await SeedProductAsync("other-secret");

        var response = await PutAsync(CreateClient(otherProduct.ApiSecret), requestedProduct.Id, "release-scope", Hash('a'));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.False(await db.ApprovedBinaries.AnyAsync());
    }

    [Fact]
    public async Task Put_WithPartialPayload_ReturnsBadRequestAndWritesNothing()
    {
        var product = await SeedProductAsync("product-secret");
        var client = CreateClient(GlobalSecret);

        var response = await client.PutAsJsonAsync(Route(product.Id), new
        {
            registrationId = "release-partial",
            manifestDigestSha256 = Hash('d'),
            artifacts = new[] { new { key = "FP_EXE", sha256 = Hash('a') } }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("required_key_missing", (await ReadJsonAsync(response)).GetProperty("error").GetString());
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.False(await db.ApprovedBinaries.AnyAsync());
    }

    [Fact]
    public async Task Get_WithLegacyAutoRows_ReturnsSourceConflict()
    {
        var product = await SeedProductAsync("product-secret");
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            db.ApprovedBinaries.AddRange(BuildArtifacts(Hash('a')).Select(artifact => new ApprovedBinary
            {
                ProductId = product.Id,
                Version = "2.2.844",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = "auto"
            }));
            await db.SaveChangesAsync();
        }

        var response = await CreateClient(GlobalSecret).GetAsync(Route(product.Id));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var body = await ReadJsonAsync(response);
        Assert.Equal("baseline_source_conflict", body.GetProperty("error").GetString());
        Assert.Equal("BaselineMissing", body.GetProperty("verdict").GetString());
    }

    [Fact]
    public async Task LegacyAdoption_ExactTiaConnect2362_ReturnsCreatedThenAuthoritativeGet()
    {
        var product = await SeedProductAsync("product-secret", ApprovedBinaryService.TiaConnectLegacyAdoptionProductId);
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            db.ApprovedBinaries.AddRange(BuildArtifacts(Hash('a')).Select(artifact => new ApprovedBinary
            {
                ProductId = product.Id,
                Version = "2.3.62",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = ApprovedBinaryService.ReleaseSource
            }));
            await db.SaveChangesAsync();
        }
        var client = CreateClient(GlobalSecret);
        var payload = new
        {
            registrationId = "legacy-tia-2.3.62",
            manifestDigestSha256 = Hash('d'),
            artifacts = BuildArtifacts(Hash('a'))
        };

        var legacyRoute = $"/api/admin/products/{product.Id:D}/approved-binaries/2.3.62";
        var adopted = await client.PutAsJsonAsync($"{legacyRoute}/legacy-adoption", payload);
        var replay = await client.PutAsJsonAsync($"{legacyRoute}/legacy-adoption", payload);
        var readback = await client.GetAsync(legacyRoute);

        Assert.Equal(HttpStatusCode.Created, adopted.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(HttpStatusCode.OK, readback.StatusCode);
        Assert.True((await ReadJsonAsync(replay)).GetProperty("idempotent").GetBoolean());
    }

    [Fact]
    public async Task LegacyAdoption_WithProductScopedSecret_IsForbiddenWithoutMutation()
    {
        var product = await SeedProductAsync("product-secret", ApprovedBinaryService.TiaConnectLegacyAdoptionProductId);
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            db.ApprovedBinaries.AddRange(BuildArtifacts(Hash('a')).Select(artifact => new ApprovedBinary
            {
                ProductId = product.Id,
                Version = "2.3.62",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = ApprovedBinaryService.ReleaseSource
            }));
            await db.SaveChangesAsync();
        }

        var response = await CreateClient(product.ApiSecret).PutAsJsonAsync(
            $"/api/admin/products/{product.Id:D}/approved-binaries/2.3.62/legacy-adoption",
            new
            {
                registrationId = "legacy-tia-2.3.62",
                manifestDigestSha256 = Hash('d'),
                artifacts = BuildArtifacts(Hash('a'))
            });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("global_admin_required", (await ReadJsonAsync(response)).GetProperty("error").GetString());
        using var verificationScope = _factory.Services.CreateScope();
        var verification = verificationScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.Empty(await verification.ApprovedBinaryRegistrations.ToListAsync());
    }

    private async Task<Product> SeedProductAsync(string apiSecret, Guid? productId = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var product = new Product
        {
            Id = productId ?? Guid.NewGuid(),
            Name = $"Product-{Guid.NewGuid():N}",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = apiSecret
        };
        db.Products.Add(product);
        await db.SaveChangesAsync();
        return product;
    }

    private HttpClient CreateClient(string secret)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", secret);
        return client;
    }

    private static Task<HttpResponseMessage> PutAsync(
        HttpClient client,
        Guid productId,
        string registrationId,
        string exeHash) =>
        client.PutAsJsonAsync(Route(productId), new
        {
            registrationId,
            manifestDigestSha256 = Hash('d'),
            artifacts = BuildArtifacts(exeHash)
        });

    private static ApprovedBinaryArtifactPayload[] BuildArtifacts(string exeHash) =>
    [
        new("FP_EXE", exeHash),
        new("FP_DLL", Hash('b')),
        new("FP_CORE", Hash('c'))
    ];

    private static string Route(Guid productId) =>
        $"/api/admin/products/{productId:D}/approved-binaries/2.2.844";

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();

    private static string Hash(char value) => new(value, 64);

    private sealed record ApprovedBinaryArtifactPayload(string Key, string Sha256);
}
