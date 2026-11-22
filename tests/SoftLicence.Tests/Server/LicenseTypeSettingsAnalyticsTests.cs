using System.Net;
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

/// <summary>
/// Covers the read-only license type settings route used by the MCP (TKT-002776): direct settings and
/// custom parameters, the slug and parameter key filters, the exposed field set, and the analytics key scope boundaries.
/// </summary>
public sealed class LicenseTypeSettingsAnalyticsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string GlobalKey = "sla_test_type_settings_global_001";
    private const string TelemetryOnlyKey = "sla_test_type_settings_product_001";
    private const string ScopedMultiProductKey = "sla_test_type_settings_scoped_001";
    private const string Route = "/api/analytics/licenses/types/settings";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    /// <summary>Builds an isolated server with an in-memory catalogue per test class instance.</summary>
    public LicenseTypeSettingsAnalyticsTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "admin-secret");
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
    public async Task GlobalKey_ReturnsDirectSettingsAndCustomParameters()
    {
        await SeedAsync();
        var json = await GetOkAsync(GlobalKey, $"{Route}?productName=Product%20A");

        var types = json.EnumerateArray().ToArray();
        Assert.Equal(3, types.Length);
        var teacher = types.Single(t => t.GetProperty("slug").GetString() == "CLASSROOM-TEACHER");
        Assert.Equal(7, teacher.GetProperty("defaultDurationDays").GetInt32());
        Assert.Equal(1, teacher.GetProperty("defaultMaxSeats").GetInt32());
        Assert.Equal("true", ParamValue(teacher, "hasClassroomTeacher"));
        Assert.Equal("Rôle enseignant", teacher.GetProperty("params").EnumerateArray()
            .Single(p => p.GetProperty("key").GetString() == "hasClassroomTeacher").GetProperty("name").GetString());
    }

    [Fact]
    public async Task ParameterKeyFilter_ReturnsOnlyTypesCarryingThatKey()
    {
        await SeedAsync();
        var json = await GetOkAsync(GlobalKey, $"{Route}?productName=Product%20A&parameterKey=hasClassroomTeacher");

        var slugs = json.EnumerateArray().Select(t => t.GetProperty("slug").GetString()).OrderBy(s => s).ToArray();
        Assert.Equal(new[] { "CLASSROOM-STUDENT", "CLASSROOM-TEACHER" }, slugs);
    }

    [Fact]
    public async Task SlugFilter_IsCaseInsensitiveLikeOtherSlugLookups()
    {
        await SeedAsync();
        var json = await GetOkAsync(GlobalKey, $"{Route}?productName=Product%20A&slug=classroom-student");

        var type = Assert.Single(json.EnumerateArray());
        Assert.Equal("CLASSROOM-STUDENT", type.GetProperty("slug").GetString());
        Assert.Equal("false", ParamValue(type, "hasClassroomTeacher"));
    }

    [Fact]
    public async Task TypesOfAnotherProduct_AreNeverReturned()
    {
        await SeedAsync();
        var json = await GetOkAsync(GlobalKey, $"{Route}?productName=Product%20B");

        var type = Assert.Single(json.EnumerateArray());
        Assert.Equal("OTHER-TYPE", type.GetProperty("slug").GetString());
    }

    [Fact]
    public async Task KeyWithoutMultiProductScope_IsRefused()
    {
        await SeedAsync();
        var client = CreateClient(TelemetryOnlyKey);

        var response = await client.GetAsync($"{Route}?productName=Product%20A");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ProductScopedKey_CannotReadAnotherProduct()
    {
        await SeedAsync();
        var client = CreateClient(ScopedMultiProductKey);

        var response = await client.GetAsync($"{Route}?productName=Product%20B");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ProductScopedKey_ReadsItsOwnProduct()
    {
        await SeedAsync();
        var json = await GetOkAsync(ScopedMultiProductKey, $"{Route}?productName=Product%20A");

        var slugs = json.EnumerateArray().Select(t => t.GetProperty("slug").GetString()).OrderBy(s => s).ToArray();
        Assert.Equal(new[] { "CLASSROOM-STUDENT", "CLASSROOM-TEACHER", "PLAIN" }, slugs);
    }

    /// <summary>
    /// The projection is shared with AdminController (TKT-003097): any field added there must be reviewed before
    /// it reaches analytics keys, so the exact field sets are pinned and the product secret never appears.
    /// </summary>
    [Fact]
    public async Task Response_ExposesOnlyTheTypeContract()
    {
        await SeedAsync();
        var response = await CreateClient(GlobalKey).GetAsync($"{Route}?productName=Product%20A");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("secret-a", body, StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(body);
        var expectedTypeFields = new[]
        {
            "allowAnonymous", "allowPublicTrial", "defaultAllowedVersions", "defaultDurationDays", "defaultMaxSeats",
            "description", "disableNewActivations", "enforceSingleUsePerHardwareId", "id", "isFree", "isRecurring",
            "maxActivationsPerDay", "name", "params", "slug", "teamEligible"
        };
        foreach (var type in doc.RootElement.EnumerateArray())
        {
            Assert.Equal(expectedTypeFields, type.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
            foreach (var param in type.GetProperty("params").EnumerateArray())
                Assert.Equal(new[] { "key", "name", "value" }, param.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        }
    }

    [Fact]
    public async Task UnknownProduct_ReturnsNotFound()
    {
        await SeedAsync();
        var client = CreateClient(GlobalKey);

        var response = await client.GetAsync($"{Route}?productName=Missing");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>Seeds two products, three typed catalogue entries for the first one, and three keys.</summary>
    private async Task SeedAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var productA = new Product { Id = Guid.NewGuid(), Name = "Product A", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-a" };
        var productB = new Product { Id = Guid.NewGuid(), Name = "Product B", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "secret-b" };
        db.Products.AddRange(productA, productB);

        var teacher = new LicenseType { Id = Guid.NewGuid(), ProductId = productA.Id, Name = "Classroom Teacher", Slug = "CLASSROOM-TEACHER", DefaultDurationDays = 7, DefaultMaxSeats = 1 };
        teacher.CustomParams.Add(new LicenseTypeCustomParam { Key = "hasClassroomTeacher", Name = "Rôle enseignant", Value = "true" });
        teacher.CustomParams.Add(new LicenseTypeCustomParam { Key = "hasClassroomStudent", Name = "Rôle élève", Value = "true" });
        var student = new LicenseType { Id = Guid.NewGuid(), ProductId = productA.Id, Name = "Classroom Student", Slug = "CLASSROOM-STUDENT", DefaultDurationDays = 365, DefaultMaxSeats = 1 };
        student.CustomParams.Add(new LicenseTypeCustomParam { Key = "hasClassroomTeacher", Name = "Rôle enseignant", Value = "false" });
        student.CustomParams.Add(new LicenseTypeCustomParam { Key = "hasClassroomStudent", Name = "Rôle élève", Value = "true" });
        var plain = new LicenseType { Id = Guid.NewGuid(), ProductId = productA.Id, Name = "Plain", Slug = "PLAIN" };
        var other = new LicenseType { Id = Guid.NewGuid(), ProductId = productB.Id, Name = "Other", Slug = "OTHER-TYPE" };
        other.CustomParams.Add(new LicenseTypeCustomParam { Key = "hasClassroomTeacher", Name = "Rôle enseignant", Value = "true" });
        db.LicenseTypes.AddRange(teacher, student, plain, other);

        db.AnalyticsApiKeys.AddRange(
            NewKey(GlobalKey, null, AnalyticsApiKeyScopeKinds.Global,
                $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.SecurityRead} {AnalyticsApiKeyScopes.MultiProductRead}"),
            NewKey(TelemetryOnlyKey, productA.Id, AnalyticsApiKeyScopeKinds.Product, AnalyticsApiKeyScopes.TelemetryRead),
            NewKey(ScopedMultiProductKey, productA.Id, AnalyticsApiKeyScopeKinds.Product,
                $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.MultiProductRead}"));

        await db.SaveChangesAsync();
    }

    /// <summary>Creates an active analytics key row for the given raw secret and scope.</summary>
    private static AnalyticsApiKey NewKey(string rawKey, Guid? productId, string scopeKind, string scopes) => new()
    {
        ProductId = productId,
        Name = "Type settings test key",
        Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
        KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
        Scopes = scopes,
        ScopeKind = scopeKind,
        IsActive = true
    };

    /// <summary>Creates a client that sends the given analytics key.</summary>
    private HttpClient CreateClient(string key)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", key);
        return client;
    }

    /// <summary>Calls the route, asserts 200 and returns the parsed body.</summary>
    private async Task<JsonElement> GetOkAsync(string key, string url)
    {
        var response = await CreateClient(key).GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var stream = await response.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);
        return doc.RootElement.Clone();
    }

    /// <summary>Returns the value of one custom parameter of a projected type.</summary>
    private static string? ParamValue(JsonElement type, string key) => type.GetProperty("params").EnumerateArray()
        .Single(p => p.GetProperty("key").GetString() == key).GetProperty("value").GetString();
}
