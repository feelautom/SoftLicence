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

public sealed class LeadOpsSnapshotControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string ValidAnalyticsKey = "sla_test_leadops_snapshot_key_001";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public LeadOpsSnapshotControllerTests(WebApplicationFactory<Program> factory)
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
    public async Task Snapshot_WithLimitOne_ExposesTotalReturnedAndHasMore()
    {
        await SeedLeadOpsSnapshotAsync(3);
        var client = CreateAnalyticsClient();

        var response = await client.GetAsync("/api/analytics/leadops/snapshot?limit=1&telemetryDays=30");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal(3, GetInt(json, "totalAvailable"));
        Assert.Equal(3, GetInt(json, "totalLicensesAvailable"));
        Assert.Equal(1, GetInt(json, "returned"));
        Assert.Equal(1, GetInt(json, "limit"));
        Assert.Equal(1, GetInt(json, "pageSize"));
        Assert.Equal(1, GetInt(json, "page"));
        Assert.Equal(0, GetInt(json, "offset"));
        Assert.True(GetBool(json, "hasMore"));
        Assert.Equal(1, GetInt(json, "nextOffset"));
        Assert.Equal(2, GetInt(json, "nextPage"));
        Assert.Equal("1", GetString(json, "nextCursor"));
        Assert.Equal(1, GetInt(GetProperty(json, "counts"), "licenses"));
        var licenses = GetArray(json, "licenses");
        Assert.Single(licenses);
        Assert.False(GetBool(licenses[0], "hasUninstallEvent"));
        Assert.Equal(JsonValueKind.Null, GetProperty(licenses[0], "lastUninstallAtUtc").ValueKind);

        var coverage = GetProperty(json, "coverage");
        var licensesCoverage = GetProperty(coverage, "licenses");
        Assert.Equal(3, GetInt(licensesCoverage, "totalAvailable"));
        Assert.Equal(1, GetInt(licensesCoverage, "returned"));
        Assert.True(GetBool(licensesCoverage, "hasMore"));
        Assert.Equal("all_product_licenses", GetString(licensesCoverage, "scope"));
    }

    [Fact]
    public async Task Snapshot_WithLimitOverMax_DoesNotHideRealCoverage()
    {
        await SeedLeadOpsSnapshotAsync(1002);
        var client = CreateAnalyticsClient();

        var cappedResponse = await client.GetAsync("/api/analytics/leadops/snapshot?limit=1000&telemetryDays=30");
        var response = await client.GetAsync("/api/analytics/leadops/snapshot?limit=1001&telemetryDays=30");

        Assert.Equal(HttpStatusCode.OK, cappedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var cappedJson = await ReadJsonAsync(cappedResponse);
        Assert.Equal(1002, GetInt(cappedJson, "totalAvailable"));
        Assert.Equal(1000, GetInt(cappedJson, "returned"));
        Assert.True(GetBool(cappedJson, "hasMore"));

        var json = await ReadJsonAsync(response);
        Assert.Equal(1002, GetInt(json, "totalAvailable"));
        Assert.Equal(1002, GetInt(json, "totalLicensesAvailable"));
        Assert.Equal(1000, GetInt(json, "returned"));
        Assert.Equal(1000, GetInt(json, "limit"));
        Assert.Equal(1000, GetInt(json, "pageSize"));
        Assert.True(GetBool(json, "hasMore"));
        Assert.Equal(1000, GetInt(json, "nextOffset"));
        Assert.Equal(2, GetInt(json, "nextPage"));
        Assert.Equal(1000, GetInt(GetProperty(json, "counts"), "licenses"));
        Assert.Equal(1000, GetArray(json, "licenses").Length);
    }

    [Fact]
    public async Task Snapshot_WithOffsetAndCursor_ReturnsStablePages()
    {
        await SeedLeadOpsSnapshotAsync(5);
        var client = CreateAnalyticsClient();

        var firstResponse = await client.GetAsync("/api/analytics/leadops/snapshot?limit=2");
        var pageResponse = await client.GetAsync("/api/analytics/leadops/snapshot?limit=2&page=2");
        var secondResponse = await client.GetAsync("/api/analytics/leadops/snapshot?limit=2&offset=2");
        var cursorResponse = await client.GetAsync("/api/analytics/leadops/snapshot?limit=2&cursor=4");

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, pageResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, cursorResponse.StatusCode);

        var first = await ReadJsonAsync(firstResponse);
        var page = await ReadJsonAsync(pageResponse);
        var second = await ReadJsonAsync(secondResponse);
        var cursor = await ReadJsonAsync(cursorResponse);

        Assert.Equal(1, GetInt(first, "page"));
        Assert.Equal(2, GetInt(page, "page"));
        Assert.Equal(2, GetInt(second, "page"));
        Assert.Equal(3, GetInt(cursor, "page"));
        Assert.Equal(0, GetInt(first, "offset"));
        Assert.Equal(2, GetInt(page, "offset"));
        Assert.Equal(2, GetInt(second, "offset"));
        Assert.Equal(4, GetInt(cursor, "offset"));
        Assert.True(GetBool(first, "hasMore"));
        Assert.True(GetBool(page, "hasMore"));
        Assert.True(GetBool(second, "hasMore"));
        Assert.False(GetBool(cursor, "hasMore"));

        var firstIds = GetArray(first, "licenses").Select(x => GetString(x, "id")).ToArray();
        var pageIds = GetArray(page, "licenses").Select(x => GetString(x, "id")).ToArray();
        var secondIds = GetArray(second, "licenses").Select(x => GetString(x, "id")).ToArray();
        var cursorIds = GetArray(cursor, "licenses").Select(x => GetString(x, "id")).ToArray();

        Assert.Equal(pageIds, secondIds);
        Assert.Empty(firstIds.Intersect(secondIds));
        Assert.Empty(firstIds.Intersect(cursorIds));
        Assert.Empty(secondIds.Intersect(cursorIds));
        Assert.Single(cursorIds);
    }

    [Fact]
    public async Task Snapshot_KeepsExistingTopLevelCollectionsAndRedactedKeys()
    {
        await SeedLeadOpsSnapshotAsync(2, includeTelemetryAndBans: true);
        var client = CreateAnalyticsClient();

        var response = await client.GetAsync("/api/analytics/leadops/snapshot?limit=10&telemetryDays=30");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SECRET-LEADOPS-LICENSE", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        var json = doc.RootElement;
        Assert.Equal(2, GetArray(json, "licenses").Length);
        Assert.NotEmpty(GetArray(json, "telemetry"));
        Assert.NotEmpty(GetArray(json, "bannedHardware"));
        Assert.NotEmpty(GetArray(json, "bannedComponents"));
        Assert.Equal(2, GetInt(GetProperty(json, "counts"), "licenses"));
        Assert.False(GetBool(json, "hasMore"));
    }

    [Fact]
    public async Task Snapshot_WithGlobalKeyWithoutProductSelector_ReturnsSelectorRequired()
    {
        await SeedLeadOpsSnapshotAsync(2);
        const string globalKey = "sla_test_leadops_global_key_001";
        await SeedGlobalAnalyticsKeyAsync(globalKey);
        var client = CreateAnalyticsClient(globalKey);

        var response = await client.GetAsync("/api/analytics/leadops/snapshot?limit=1");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("PRODUCT_SELECTOR_REQUIRED", GetString(json, "errorCode"));
    }

    [Fact]
    public async Task Snapshot_WithGlobalKeyAndProductName_ReturnsRequestedProduct()
    {
        await SeedLeadOpsSnapshotAsync(2);
        const string globalKey = "sla_test_leadops_global_key_002";
        await SeedGlobalAnalyticsKeyAsync(globalKey);
        var client = CreateAnalyticsClient(globalKey);

        var response = await client.GetAsync("/api/analytics/leadops/snapshot?limit=1&productName=T-IA%20Connect");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-SoftLicence-Product-Scope-Mode", out var scopeModes));
        Assert.Equal("explicit-global", Assert.Single(scopeModes));
        var json = await ReadJsonAsync(response);
        Assert.Equal(2, GetInt(json, "totalAvailable"));
        Assert.Equal(1, GetInt(json, "returned"));
        Assert.True(GetBool(json, "hasMore"));
    }

    private HttpClient CreateAnalyticsClient()
    {
        return CreateAnalyticsClient(ValidAnalyticsKey);
    }

    private HttpClient CreateAnalyticsClient(string analyticsKey)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", analyticsKey);
        return client;
    }

    private async Task SeedLeadOpsSnapshotAsync(int licenseCount, bool includeTelemetryAndBans = false)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        db.Products.Add(new Product
        {
            Id = productId,
            Name = "T-IA Connect",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = "legacy-product-secret"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "TIA Connect Pro",
            Slug = "TIA-CONNECT-PRO",
            IsFree = false
        });
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = productId,
            Name = "LeadOps snapshot test key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(ValidAnalyticsKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(ValidAnalyticsKey),
            Scopes = AnalyticsApiKeyScopes.TelemetryRead,
            IsActive = true
        });

        for (var i = 0; i < licenseCount; i++)
        {
            var hardwareId = $"HW-LEADOPS-{i:0000}";
            var license = new License
            {
                Id = DeterministicGuid(i),
                ProductId = productId,
                LicenseTypeId = typeId,
                LicenseKey = $"SECRET-LEADOPS-LICENSE-{i:0000}",
                CustomerName = $"LeadOps Customer {i:0000}",
                CustomerEmail = $"leadops{i:0000}@example.test",
                HardwareId = hardwareId,
                ActivationDate = now.AddDays(-i),
                CreationDate = now.AddMinutes(-i),
                ExpirationDate = now.AddDays(30),
                IsActive = true,
                HasUninstallEvent = i == 0,
                LastUninstallAt = i == 0 ? now.AddHours(-2) : null
            };
            license.Seats.Add(new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = hardwareId,
                FirstActivatedAt = now.AddDays(-i),
                LastCheckInAt = now.AddHours(-1),
                IsActive = true
            });
            db.Licenses.Add(license);
        }

        if (includeTelemetryAndBans)
        {
            db.TelemetryRecords.Add(new TelemetryRecord
            {
                ProductId = productId,
                Timestamp = now.AddMinutes(-5),
                HardwareId = "HW-LEADOPS-0000",
                AppName = "TIAConnect",
                Version = "2.2.900",
                EventName = "Startup_AppStarted",
                Type = TelemetryType.Event,
                EventData = new TelemetryEvent { PropertiesJson = "{}" }
            });
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                ProductId = productId,
                HardwareId = "HW-LEADOPS-0000",
                BanCategory = "test",
                Reason = "test ban",
                BannedAt = now.AddMinutes(-4),
                IsActive = true
            });
            db.BannedComponents.Add(new BannedComponent
            {
                ProductId = productId,
                ComponentType = "CPU",
                ComponentHash = "HASH-LEADOPS-CPU",
                Reason = "test component ban",
                BannedAt = now.AddMinutes(-3),
                IsActive = true
            });
        }

        await db.SaveChangesAsync();
    }

    private async Task SeedGlobalAnalyticsKeyAsync(string rawKey)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = null,
            Name = "Global LeadOps analytics test key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
            Scopes = $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.MultiProductRead}",
            ScopeKind = AnalyticsApiKeyScopeKinds.Global,
            IsActive = true
        });

        await db.SaveChangesAsync();
    }

    private static Guid DeterministicGuid(int value)
    {
        var bytes = new byte[16];
        BitConverter.GetBytes(value).CopyTo(bytes, 0);
        return new Guid(bytes);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return json;
    }

    private static JsonElement[] GetArray(JsonElement element, string propertyName)
    {
        return element.GetProperty(propertyName).EnumerateArray().ToArray();
    }

    private static int GetInt(JsonElement element, string propertyName)
    {
        return element.GetProperty(propertyName).GetInt32();
    }

    private static bool GetBool(JsonElement element, string propertyName)
    {
        return element.GetProperty(propertyName).GetBoolean();
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        return element.GetProperty(propertyName).GetString();
    }

    private static JsonElement GetProperty(JsonElement element, string propertyName)
    {
        return element.GetProperty(propertyName);
    }
}
