using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Configuration;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ExtraParamsOfflineActivationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string GlobalSecret = "test-global-admin-secret";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = $"extra-params-{Guid.NewGuid():N}";

    public ExtraParamsOfflineActivationTests(WebApplicationFactory<Program> factory)
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

    public static TheoryData<Dictionary<string, string>> RejectedExtraParams => new()
    {
        new Dictionary<string, string>(),
        new Dictionary<string, string> { ["premiumFeature"] = "true" },
        new Dictionary<string, string> { ["maxProjects"] = "999999" },
        new Dictionary<string, string> { ["unknownEntitlement"] = "enabled" },
        new Dictionary<string, string> { [" ALLOWOFFLINE "] = "true" },
        Enumerable.Range(0, 5_000).ToDictionary(i => $"clientKey{i}", _ => new string('x', 64))
    };

    [Theory]
    [MemberData(nameof(RejectedExtraParams))]
    public async Task PublicActivation_WithAnyExtraParams_IsRejectedBeforeBusinessSideEffects(
        Dictionary<string, string> extraParams)
    {
        var fixture = await SeedLicenseAsync();
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            fixture.LicenseKey,
            HardwareId = "HW-EXTRA-PARAMS",
            AppName = fixture.ProductName,
            ExtraParams = extraParams,
            ComponentFingerprints = new Dictionary<string, string> { ["disk"] = "CLIENT-FINGERPRINT" }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("extra_params_not_allowed", await ReadErrorAsync(response));

        await Task.Delay(150);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.False(await db.LicenseSeats.AnyAsync(s => s.LicenseId == fixture.LicenseId));
        Assert.False(await db.LicenseHistories.AnyAsync(h => h.LicenseId == fixture.LicenseId));
        Assert.False(await db.HardwareFingerprints.AnyAsync());
        var license = await db.Licenses.SingleAsync(l => l.Id == fixture.LicenseId);
        Assert.Null(license.HardwareId);
        Assert.Null(license.ActivationDate);
    }

    [Fact]
    public async Task PublicActivation_WithoutExtraParams_RemainsCompatible()
    {
        var fixture = await SeedLicenseAsync();
        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation", new
        {
            fixture.LicenseKey,
            HardwareId = "HW-NORMAL",
            AppName = fixture.ProductName
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var licenseFile = await ReadLicenseFileAsync(response);
        var validation = LicenseService.ValidateLicenseDetailed(licenseFile, fixture.PublicKey, "HW-NORMAL");
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.Equal("false", validation.License!.Features["premiumFeature"]);
        Assert.Equal("5", validation.License.Features["maxProjects"]);
        Assert.DoesNotContain("offlineMode", validation.License.Features.Keys);
        Assert.DoesNotContain("offlineRequestCode", validation.License.Features.Keys);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid-secret")]
    public async Task OfflineActivation_WithoutValidSecret_FailsClosed(string? suppliedSecret)
    {
        var fixture = await SeedLicenseAsync();
        var client = _factory.CreateClient();
        if (suppliedSecret != null)
            client.DefaultRequestHeaders.Add("X-Admin-Secret", suppliedSecret);

        var response = await PostOfflineAsync(client, fixture, "HW-AUTH", "abcd-ef01-2345-6789");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("unauthorized", await ReadErrorAsync(response));
    }

    [Fact]
    public async Task OfflineActivation_WithAnotherProductSecret_IsDenied()
    {
        var fixture = await SeedLicenseAsync();
        var other = await SeedLicenseAsync(productSecret: "other-product-secret");
        var client = CreateAdminClient(other.ProductSecret);

        var response = await PostOfflineAsync(client, fixture, "HW-SCOPE", "abcd-ef01-2345-6789");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("offline_activation_denied", await ReadErrorAsync(response));
    }

    [Fact]
    public async Task OfflineActivation_WithGlobalSecret_IsAuthorized()
    {
        var fixture = await SeedLicenseAsync();
        var response = await PostOfflineAsync(
            CreateAdminClient(GlobalSecret),
            fixture,
            "HW-GLOBAL",
            "ABCD-EF01-2345-6789");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AdminSecretAuthentication_OutsideConfiguredIpWhitelist_IsRejected()
    {
        using var scope = _factory.Services.CreateScope();
        var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
        var previousAllowedIps = configuration["AdminSettings:AllowedIps"];
        configuration["AdminSettings:AllowedIps"] = "198.51.100.10";
        try
        {
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10");
            context.Request.Path = "/api/activation/offline";
            context.Request.Headers["X-Admin-Secret"] = GlobalSecret;
            var authentication = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.AdminSecretAuthenticationService>();

            var result = await authentication.AuthenticateAsync(context);

            Assert.False(result.Authorized);
            Assert.Null(result.ScopedProductId);
        }
        finally
        {
            configuration["AdminSettings:AllowedIps"] = previousAllowedIps;
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ABCD-EF01-2345")]
    [InlineData("ABCD-EF01-2345-678!")]
    [InlineData(" ABCD-EF01-2345-6789")]
    public async Task OfflineActivation_WithMissingOrInvalidRequestCode_IsRejected(string? requestCode)
    {
        var fixture = await SeedLicenseAsync();
        var client = CreateAdminClient(fixture.ProductSecret);
        var response = await client.PostAsJsonAsync("/api/activation/offline", new
        {
            fixture.LicenseKey,
            HardwareId = "HW-CODE",
            OfflineRequestCode = requestCode
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await ReadErrorAsync(response));
    }

    [Fact]
    public async Task OfflineActivation_WithLetterOutsideHexadecimalRange_IsRejected()
    {
        var fixture = await SeedLicenseAsync();
        var response = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            "HW-NON-HEX-CODE",
            "ABCG-EF01-2345-6789");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await ReadErrorAsync(response));
    }

    [Fact]
    public async Task OfflineActivation_WithUnknownInputProperty_IsRejected()
    {
        var fixture = await SeedLicenseAsync();
        var client = CreateAdminClient(fixture.ProductSecret);
        var response = await client.PostAsJsonAsync("/api/activation/offline", new
        {
            fixture.LicenseKey,
            HardwareId = "HW-UNKNOWN",
            OfflineRequestCode = "ABCD-EF01-2345-6789",
            ExtraParams = new { premiumFeature = true }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await ReadErrorAsync(response));
    }

    [Theory]
    [InlineData(false, false, false, true, false)]
    [InlineData(true, true, false, true, false)]
    [InlineData(true, false, true, true, false)]
    [InlineData(true, false, false, false, false)]
    [InlineData(true, false, false, true, true)]
    public async Task OfflineActivation_WithIneligibleLicense_IsDenied(
        bool isActive,
        bool expired,
        bool isFree,
        bool allowOffline,
        bool addReservedCollision = false)
    {
        var fixture = await SeedLicenseAsync(
            isActive: isActive,
            expired: expired,
            isFree: isFree,
            allowOffline: allowOffline,
            addReservedCollision: addReservedCollision);
        var response = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            "HW-INELIGIBLE",
            "ABCD-EF01-2345-6789");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("offline_activation_denied", await ReadErrorAsync(response));
    }

    [Fact]
    public async Task OfflineActivation_WithoutAllowOfflineFeature_IsDenied()
    {
        var fixture = await SeedLicenseAsync(includeAllowOffline: false);
        var response = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            "HW-NO-ENTITLEMENT",
            "ABCD-EF01-2345-6789");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("offline_activation_denied", await ReadErrorAsync(response));
    }

    [Fact]
    public async Task OfflineActivation_PreservesSeatAndHardwareControls()
    {
        var fixture = await SeedLicenseAsync(maxSeats: 1, existingSeatHardwareId: "HW-BOUND");
        var response = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            "HW-WRONG",
            "ABCD-EF01-2345-6789");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var activeSeats = await db.LicenseSeats.Where(s => s.LicenseId == fixture.LicenseId && s.IsActive).ToListAsync();
        Assert.Single(activeSeats);
        Assert.Equal("HW-BOUND", activeSeats[0].HardwareId);
    }

    [Fact]
    public async Task OfflineActivation_WithLowercaseHexRequestCode_NormalizesAndProducesSdkCompatibleLicense()
    {
        var fixture = await SeedLicenseAsync();
        var response = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            "HW-OFFLINE",
            "abcd-ef01-2345-6789");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var licenseFile = await ReadLicenseFileAsync(response);
        var validation = LicenseService.ValidateLicenseDetailed(licenseFile, fixture.PublicKey, "HW-OFFLINE");
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.Equal("false", validation.License!.Features["premiumFeature"]);
        Assert.Equal("5", validation.License.Features["maxProjects"]);
        Assert.Equal("true", validation.License.Features["allowOffline"], ignoreCase: true);
        Assert.Equal("True", validation.License.Features["offlineMode"]);
        Assert.Equal("ABCD-EF01-2345-6789", validation.License.Features["offlineRequestCode"]);
    }

    [Fact]
    public async Task CheckStatus_WithExtraParams_UsesOnlyServerFeatures()
    {
        var fixture = await SeedLicenseAsync();
        var client = _factory.CreateClient();
        var activation = await client.PostAsJsonAsync("/api/activation", new
        {
            fixture.LicenseKey,
            HardwareId = "HW-CHECK",
            AppName = fixture.ProductName
        });
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);

        var check = await client.PostAsJsonAsync("/api/activation/check", new
        {
            fixture.LicenseKey,
            HardwareId = "HW-CHECK",
            AppName = fixture.ProductName,
            ExtraParams = new Dictionary<string, string>
            {
                ["premiumFeature"] = "true",
                ["maxProjects"] = "999999",
                ["offlineMode"] = "true"
            }
        });

        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        using var responseJson = JsonDocument.Parse(await check.Content.ReadAsStringAsync());
        var licenseFile = responseJson.RootElement.GetProperty("licenseFile").GetString()!;
        var validation = LicenseService.ValidateLicenseDetailed(licenseFile, fixture.PublicKey, "HW-CHECK");
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.Equal("false", validation.License!.Features["premiumFeature"]);
        Assert.Equal("5", validation.License.Features["maxProjects"]);
        Assert.DoesNotContain("offlineMode", validation.License.Features.Keys);
    }

    [Fact]
    public async Task SensitiveActivationRoutes_AreRedactedInAccessLogAndErrors()
    {
        var fixture = await SeedLicenseAsync();
        const string hardwareId = "HW-SENSITIVE-LOG";
        const string requestCode = "ABCD-EF01-2345-6789";

        var activationResponse = await _factory.CreateClient().PostAsJsonAsync("/api/activation", new
        {
            fixture.LicenseKey,
            HardwareId = hardwareId,
            AppName = fixture.ProductName
        });
        Assert.Equal(HttpStatusCode.OK, activationResponse.StatusCode);
        using (var activationJson = JsonDocument.Parse(await activationResponse.Content.ReadAsStringAsync()))
            Assert.False(string.IsNullOrWhiteSpace(activationJson.RootElement.GetProperty("licenseFile").GetString()));

        var activationLog = await WaitForLogAsync("ACTIVATE");
        AssertRedactedStructuredLog(activationLog, fixture.LicenseKey, hardwareId);

        var checkResponse = await _factory.CreateClient().PostAsJsonAsync("/api/activation/check", new
        {
            fixture.LicenseKey,
            HardwareId = hardwareId,
            AppName = fixture.ProductName
        });
        Assert.Equal(HttpStatusCode.OK, checkResponse.StatusCode);
        using (var checkJson = JsonDocument.Parse(await checkResponse.Content.ReadAsStringAsync()))
            Assert.False(string.IsNullOrWhiteSpace(checkJson.RootElement.GetProperty("licenseFile").GetString()));

        var checkLog = await WaitForLogAsync("CHECK");
        AssertRedactedStructuredLog(checkLog, fixture.LicenseKey, hardwareId);

        var offlineResponse = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            hardwareId,
            requestCode);

        Assert.Equal(HttpStatusCode.OK, offlineResponse.StatusCode);
        var offlineLog = await WaitForLogAsync("OFFLINE_ACTIVATE");
        AssertRedactedStructuredLog(offlineLog, fixture.LicenseKey, hardwareId);

        var redactedBodies = string.Join('|', offlineLog.RequestBody, offlineLog.ErrorDetails);
        Assert.DoesNotContain(fixture.LicenseKey, redactedBodies, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hardwareId, redactedBodies, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(requestCode, redactedBodies, StringComparison.OrdinalIgnoreCase);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var searchableLog = await db.AccessLogs.AsNoTracking().SingleAsync(entry =>
                entry.Endpoint == "OFFLINE_ACTIVATE"
                && entry.LicenseKey == fixture.LicenseKey
                && entry.HardwareId == hardwareId);
            Assert.Equal(offlineLog.Id, searchableLog.Id);
        }

        var invalidResponse = await PostOfflineAsync(
            CreateAdminClient(fixture.ProductSecret),
            fixture,
            hardwareId,
            "INVALID-CODE");
        var errorBody = await invalidResponse.Content.ReadAsStringAsync();
        Assert.DoesNotContain(fixture.LicenseKey, errorBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hardwareId, errorBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("INVALID-CODE", errorBody, StringComparison.OrdinalIgnoreCase);
    }

    private static void AssertRedactedStructuredLog(AccessLog log, string licenseKey, string hardwareId)
    {
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.Null(log.ErrorDetails);
        Assert.Equal(licenseKey, log.LicenseKey);
        Assert.Equal(hardwareId, log.HardwareId);
    }

    private HttpClient CreateAdminClient(string secret)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", secret);
        return client;
    }

    private static Task<HttpResponseMessage> PostOfflineAsync(
        HttpClient client,
        LicenseFixture fixture,
        string hardwareId,
        string requestCode) =>
        client.PostAsJsonAsync("/api/activation/offline", new
        {
            fixture.LicenseKey,
            HardwareId = hardwareId,
            OfflineRequestCode = requestCode
        });

    private async Task<LicenseFixture> SeedLicenseAsync(
        string? productSecret = null,
        bool isActive = true,
        bool expired = false,
        bool isFree = false,
        bool allowOffline = true,
        bool includeAllowOffline = true,
        bool addReservedCollision = false,
        int maxSeats = 1,
        string? existingSeatHardwareId = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();
        var keys = LicenseService.GenerateKeys();
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var productName = $"OfflineProduct-{Guid.NewGuid():N}";
        var secret = productSecret ?? $"product-secret-{Guid.NewGuid():N}";
        var licenseKey = $"LIC-{Guid.NewGuid():N}".ToUpperInvariant();

        db.Products.Add(new Product
        {
            Id = productId,
            Name = productName,
            ApiSecret = secret,
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
            PublicKeyXml = keys.PublicKey
        });

        var type = new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Offline Commercial",
            Slug = "OFFLINE-COMMERCIAL",
            IsFree = isFree
        };
        type.CustomParams.Add(new LicenseTypeCustomParam { LicenseTypeId = typeId, Key = "premiumFeature", Name = "Premium", Value = "false" });
        type.CustomParams.Add(new LicenseTypeCustomParam { LicenseTypeId = typeId, Key = "maxProjects", Name = "Projects", Value = "5" });
        if (includeAllowOffline)
            type.CustomParams.Add(new LicenseTypeCustomParam { LicenseTypeId = typeId, Key = "allowOffline", Name = "Offline", Value = allowOffline.ToString() });
        if (addReservedCollision)
            type.CustomParams.Add(new LicenseTypeCustomParam { LicenseTypeId = typeId, Key = " OfflineMode ", Name = "Collision", Value = "false" });
        db.LicenseTypes.Add(type);

        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = licenseKey,
            CustomerName = "Artificial Test Customer",
            CustomerEmail = "artificial@example.test",
            IsActive = isActive,
            ExpirationDate = expired ? DateTime.UtcNow.AddMinutes(-1) : DateTime.UtcNow.AddDays(30),
            MaxSeats = maxSeats,
            AllowedVersions = "*"
        });

        if (existingSeatHardwareId != null)
        {
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId,
                HardwareId = existingSeatHardwareId,
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-1),
                IsActive = true
            });
        }

        await db.SaveChangesAsync();
        return new LicenseFixture(licenseId, licenseKey, productName, productId, secret, keys.PublicKey);
    }

    private async Task<AccessLog> WaitForLogAsync(string endpoint)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var log = await db.AccessLogs.AsNoTracking()
                .Where(l => l.Endpoint == endpoint)
                .OrderByDescending(l => l.Timestamp)
                .FirstOrDefaultAsync();
            if (log != null)
                return log;
            await Task.Delay(100);
        }

        throw new TimeoutException("Expected redacted access log was not written.");
    }

    private static async Task<string> ReadErrorAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("error").GetString()!;
    }

    private static async Task<string> ReadLicenseFileAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("licenseFile").GetString()!;
    }

    private sealed record LicenseFixture(
        Guid LicenseId,
        string LicenseKey,
        string ProductName,
        Guid ProductId,
        string ProductSecret,
        string PublicKey);
}
