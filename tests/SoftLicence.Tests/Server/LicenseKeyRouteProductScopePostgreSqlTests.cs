using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002551: on every admin route that resolves one licence by its key, a product admin secret covers the
/// licences of that product and of its descendants (sub-products, walked up through
/// <see cref="Product.ParentProductId"/>), exactly as <c>POST /api/admin/licenses</c> already accepts the
/// parent secret for a plugin. It never covers a parent, a sibling or an unrelated product, a corrupt
/// (cyclic or too deep) hierarchy is refused, the global secret is unchanged, and every refusal keeps the
/// route's historical 401 without any write. Runs through real HTTP on PostgreSQL.
/// </summary>
public sealed class LicenseKeyRouteProductScopePostgreSqlTests
{
    /// <summary>Synthetic global admin secret of the in-process host.</summary>
    private const string GlobalSecret = "tkt2551-global-fixture-secret";
    /// <summary>Synthetic secret of the parent product.</summary>
    private const string ParentSecret = "tkt2551-parent-product-secret";
    /// <summary>Synthetic secret of the sub-product of the parent.</summary>
    private const string ChildSecret = "tkt2551-child-product-secret";
    /// <summary>Synthetic secret of the sub-product of the child.</summary>
    private const string GrandchildSecret = "tkt2551-grandchild-product-secret";
    /// <summary>Synthetic secret of another sub-product of the same parent.</summary>
    private const string SiblingSecret = "tkt2551-sibling-product-secret";
    /// <summary>Synthetic secret of a product without any hierarchy link.</summary>
    private const string UnrelatedSecret = "tkt2551-unrelated-product-secret";
    /// <summary>Canonical 16-character uppercase hexadecimal identifier of the seeded active seat.</summary>
    private const string SeatHardwareId = "A1B2C3D4E5F60718";

    /// <summary>Every admin route that loads one licence by its key and compares its product with the secret scope.</summary>
    public static TheoryData<string> KeyRoutes() => new()
    {
        "get", "update", "revoke", "unrevoke", "renew", "hardware-authority", "deactivate-seat",
        "key-activation-disable", "key-activation-lift", "exclusions-list", "exclusions-lift"
    };

    /// <summary>
    /// The reported production case: the parent secret reaches the licence of its direct sub-product on every
    /// route by key, as it already does at creation.
    /// </summary>
    [Theory]
    [MemberData(nameof(KeyRoutes))]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ParentSecret_OnSubProductLicence_IsAccepted(string route)
    {
        await using var f = await Fixture.CreateAsync();
        using var response = await f.SendAsync(route, f.ChildKey, ParentSecret);
        AssertAccepted(route, response);
    }

    /// <summary>The descendant walk is not limited to one level: the parent secret covers a grandchild licence.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ParentSecret_OnGrandchildLicence_UpdateIsAccepted()
    {
        await using var f = await Fixture.CreateAsync();
        using var response = await f.SendAsync("update", f.GrandchildKey, ParentSecret);
        AssertAccepted("update", response);
        await using var db = f.Db();
        Assert.Equal(3, (await db.Licenses.AsNoTracking().SingleAsync(l => l.LicenseKey == f.GrandchildKey)).MaxSeats);
    }

    /// <summary>The own secret of the licence product and the global secret keep working on every route by key.</summary>
    [Theory]
    [MemberData(nameof(KeyRoutes))]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task OwnProductSecretAndGlobalSecret_StayAccepted(string route)
    {
        await using (var own = await Fixture.CreateAsync())
        {
            using var response = await own.SendAsync(route, own.ChildKey, ChildSecret);
            AssertAccepted(route, response);
        }

        await using var global = await Fixture.CreateAsync();
        using var globalResponse = await global.SendAsync(route, global.ChildKey, GlobalSecret);
        AssertAccepted(route, globalResponse);
    }

    /// <summary>A sub-product secret never covers its parent's licence: 401, nothing written.</summary>
    [Theory]
    [MemberData(nameof(KeyRoutes))]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SubProductSecret_OnParentLicence_IsRefusedWithoutWrite(string route)
    {
        await using var f = await Fixture.CreateAsync();
        await AssertRefusedWithoutWriteAsync(f, route, f.ParentKey, ChildSecret);
    }

    /// <summary>
    /// A secret never covers a sibling, an unrelated product, or an ancestor's licence from a deeper descendant.
    /// </summary>
    [Theory]
    [MemberData(nameof(KeyRoutes))]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SiblingUnrelatedAndDescendantSecrets_AreRefusedWithoutWrite(string route)
    {
        await using var f = await Fixture.CreateAsync();
        await AssertRefusedWithoutWriteAsync(f, route, f.ChildKey, SiblingSecret);
        await AssertRefusedWithoutWriteAsync(f, route, f.ChildKey, UnrelatedSecret);
        await AssertRefusedWithoutWriteAsync(f, route, f.ChildKey, GrandchildSecret);
    }

    /// <summary>
    /// A cyclic hierarchy is refused instead of being walked forever, even for a product that appears in the
    /// cycle above the licence; the licence product's own secret keeps its exact-match access.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task CyclicHierarchy_IsRefusedWithoutWrite()
    {
        await using var f = await Fixture.CreateAsync();
        await f.CreateCycleBetweenChildAndGrandchildAsync();

        await AssertRefusedWithoutWriteAsync(f, "update", f.ChildKey, GrandchildSecret);
        await AssertRefusedWithoutWriteAsync(f, "update", f.ChildKey, ParentSecret);
        using var own = await f.SendAsync("get", f.ChildKey, ChildSecret);
        AssertAccepted("get", own);
    }

    /// <summary>A hierarchy deeper than the bounded walk is refused even when the secret's product is its root.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task HierarchyDeeperThanBound_IsRefusedWithoutWrite()
    {
        await using var f = await Fixture.CreateAsync();
        var deepKey = await f.SeedDeepChainLicenceAsync(depth: 20);
        await AssertRefusedWithoutWriteAsync(f, "update", deepKey, ParentSecret);
    }

    /// <summary>
    /// The production flow end to end: the parent secret creates a plugin licence through
    /// <c>POST /api/admin/licenses</c>, then sets its end date through <c>PUT /api/admin/licenses/{key}</c>.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ParentSecret_CreatesPluginLicenceThenUpdatesIt()
    {
        await using var f = await Fixture.CreateAsync();
        using var created = await f.CreatePluginLicenceAsync(ParentSecret, f.GrandchildProductId);
        Assert.True(created.IsSuccessStatusCode, $"create: {(int)created.StatusCode}");
        var key = await f.FindOtherLicenceKeyAsync(f.GrandchildProductId, f.GrandchildKey);

        var end = DateTime.UtcNow.Date.AddDays(14);
        using var updated = await f.SendAsync(key, ParentSecret, new { ExpirationDate = end });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        await using var db = f.Db();
        Assert.Equal(end, (await db.Licenses.AsNoTracking().SingleAsync(l => l.LicenseKey == key)).ExpirationDate);
    }

    /// <summary>
    /// Creation shares the bounded walk: a plugin inside a cyclic hierarchy is refused with the historical 400
    /// instead of looping forever, and no licence is written.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Creation_PluginInCyclicHierarchy_IsRefusedWithoutWrite()
    {
        await using var f = await Fixture.CreateAsync();
        await f.CreateCycleBetweenChildAndGrandchildAsync();
        var before = await f.SnapshotAsync();
        using var response = await f.CreatePluginLicenceAsync(ParentSecret, f.GrandchildProductId);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await f.SnapshotAsync());
    }

    /// <summary>Requires the route to have passed the scope check and produced its normal outcome.</summary>
    private static void AssertAccepted(string route, HttpResponseMessage response)
    {
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
        if (route == "exclusions-lift")
        {
            // No exclusion is seeded: the service answers with its own closed refusal, after the scope check.
            Assert.True((int)response.StatusCode < 500, $"{route}: {(int)response.StatusCode}");
            return;
        }

        Assert.True(response.IsSuccessStatusCode, $"{route}: {(int)response.StatusCode}");
    }

    /// <summary>Requires the historical 401 and a byte-identical snapshot of every licence-owned table.</summary>
    private static async Task AssertRefusedWithoutWriteAsync(Fixture f, string route, string key, string secret)
    {
        var before = await f.SnapshotAsync();
        using var response = await f.SendAsync(route, key, secret);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, await f.SnapshotAsync());
    }

    /// <summary>
    /// Isolated PostgreSQL database and in-process server with a parent, a child, a grandchild, a sibling and an
    /// unrelated product; one recurring licence with one active seat on the parent, the child and the grandchild.
    /// </summary>
    private sealed class Fixture : IAsyncDisposable
    {
        /// <summary>Loopback maintenance connection used only to remove the owned database.</summary>
        private readonly string maintenance;
        /// <summary>Generated ASCII database identifier.</summary>
        private readonly string database;
        /// <summary>Private fixture connection; never logged.</summary>
        private readonly string connection;
        /// <summary>Owned in-process HTTP server, disposed before database removal.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Client without default credentials.</summary>
        private readonly HttpClient client;
        /// <summary>Product identifiers by role, filled during seeding.</summary>
        private Guid parentId, childId, grandchildId;

        /// <summary>Creates an isolated host bound only to the owned database.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance; this.database = database; this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", GlobalSecret);
                builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<IHostedService>();
                    services.RemoveAll<IDataProtectionProvider>();
                    services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                    services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                    services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                    services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                    services.RemoveAll<LicenseDbContext>();
                    services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connection));
                });
            });
            client = host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        }

        /// <summary>Key of the licence owned by the parent product.</summary>
        public string ParentKey { get; private set; } = string.Empty;
        /// <summary>Key of the licence owned by the child (sub-product of the parent).</summary>
        public string ChildKey { get; private set; } = string.Empty;
        /// <summary>Key of the licence owned by the grandchild (sub-product of the child).</summary>
        public string GrandchildKey { get; private set; } = string.Empty;

        /// <summary>Creates a fresh untracked context for observing committed state.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);

        /// <summary>Clones the current schema and seeds the product hierarchy and the three licences.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("tkt2551scope");
            var fixture = new Fixture(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
            try
            {
                using var scope = fixture.host.Services.CreateScope();
                var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
                await using var db = fixture.Db();
                var parent = fixture.NewProduct(encryption, "PARENT", ParentSecret, null);
                var child = fixture.NewProduct(encryption, "CHILD", ChildSecret, parent);
                var grandchild = fixture.NewProduct(encryption, "GRANDCHILD", GrandchildSecret, child);
                var sibling = fixture.NewProduct(encryption, "SIBLING", SiblingSecret, parent);
                var unrelated = fixture.NewProduct(encryption, "UNRELATED", UnrelatedSecret, null);
                db.Products.AddRange(parent, child, grandchild, sibling, unrelated);
                await db.SaveChangesAsync();
                fixture.parentId = parent.Id; fixture.childId = child.Id; fixture.grandchildId = grandchild.Id;
                fixture.ParentKey = await SeedLicenceAsync(db, parent.Id);
                fixture.ChildKey = await SeedLicenceAsync(db, child.Id);
                fixture.GrandchildKey = await SeedLicenceAsync(db, grandchild.Id);
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        /// <summary>Builds one product with a fresh signing key pair and an optional parent.</summary>
        private Product NewProduct(EncryptionService encryption, string role, string secret, Product? parent)
        {
            using var rsa = RSA.Create(2048);
            return new Product
            {
                Name = $"{database}-{role}", ApiSecret = secret, ParentProduct = parent,
                PrivateKeyXml = encryption.Encrypt(rsa.ToXmlString(true)), PublicKeyXml = rsa.ToXmlString(false)
            };
        }

        /// <summary>Seeds one recurring type and one active licence with one active seat for a product.</summary>
        private static async Task<string> SeedLicenceAsync(LicenseDbContext db, Guid productId)
        {
            var type = new LicenseType
            {
                ProductId = productId, Name = "Synthetic recurring", Slug = "TKT2551-PRO", DefaultDurationDays = 30,
                DefaultMaxSeats = 2, IsRecurring = true
            };
            db.LicenseTypes.Add(type);
            var license = new License
            {
                ProductId = productId, Type = type,
                LicenseKey = "TKT2551-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
                CustomerName = "Synthetic buyer", CustomerEmail = "buyer@example.test", MaxSeats = 2,
                HardwareId = SeatHardwareId, ExpirationDate = DateTime.UtcNow.AddDays(30)
            };
            db.Licenses.Add(license);
            db.LicenseSeats.Add(new LicenseSeat { License = license, HardwareId = SeatHardwareId, IsActive = true });
            await db.SaveChangesAsync();
            return license.LicenseKey;
        }

        /// <summary>Corrupts the hierarchy into child → grandchild → child, as a direct database edit could.</summary>
        public async Task CreateCycleBetweenChildAndGrandchildAsync()
        {
            await using var db = Db();
            var child = await db.Products.SingleAsync(p => p.Id == childId);
            child.ParentProductId = grandchildId;
            await db.SaveChangesAsync();
        }

        /// <summary>Seeds a linear chain of sub-products below the parent and one licence on its deepest product.</summary>
        public async Task<string> SeedDeepChainLicenceAsync(int depth)
        {
            using var scope = host.Services.CreateScope();
            var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
            await using var db = Db();
            var current = await db.Products.SingleAsync(p => p.Id == parentId);
            for (var level = 0; level < depth; level++)
            {
                var next = NewProduct(encryption, $"DEEP{level}", $"tkt2551-deep-{level}-secret", current);
                db.Products.Add(next);
                current = next;
            }

            await db.SaveChangesAsync();
            return await SeedLicenceAsync(db, current.Id);
        }

        /// <summary>Serializes every licence-owned table and the hierarchy so that any write becomes visible.</summary>
        public async Task<string> SnapshotAsync()
        {
            await using var db = Db();
            var options = new JsonSerializerOptions { ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles };
            var parts = new object[]
            {
                await db.Products.AsNoTracking().OrderBy(p => p.Id).Select(p => new { p.Id, p.ParentProductId }).ToListAsync(),
                await db.Licenses.AsNoTracking().OrderBy(l => l.Id).ToListAsync(),
                await db.LicenseSeats.AsNoTracking().OrderBy(s => s.Id).ToListAsync(),
                await db.LicenseHistories.AsNoTracking().CountAsync(),
                await db.LicenseRenewals.AsNoTracking().CountAsync(),
                await db.LicenseKeyActivationSettings.AsNoTracking().CountAsync(),
                await db.LicenseKeyActivationOperations.AsNoTracking().CountAsync(),
                await db.LicenseHardwareExclusions.AsNoTracking().CountAsync()
            };
            return JsonSerializer.Serialize(parts, options);
        }

        /// <summary>Sends one route by key with the chosen admin secret.</summary>
        public async Task<HttpResponseMessage> SendAsync(string route, string key, string secret)
        {
            var path = $"/api/admin/licenses/{Uri.EscapeDataString(key)}";
            using var request = route switch
            {
                "get" => new HttpRequestMessage(HttpMethod.Get, path),
                "update" => Json(HttpMethod.Put, path, new { MaxSeats = 3 }),
                "revoke" => Json(HttpMethod.Post, $"{path}/revoke", new { Reason = "tkt2551" }),
                "unrevoke" => new HttpRequestMessage(HttpMethod.Post, $"{path}/unrevoke"),
                "renew" => Json(HttpMethod.Post, $"{path}/renew", new { TransactionId = "tkt2551-" + Guid.NewGuid().ToString("N"), DaysToAdd = 5 }),
                "hardware-authority" => Json(HttpMethod.Post, $"{path}/hardware-authority", new { HardwareId = SeatHardwareId }),
                "deactivate-seat" => new HttpRequestMessage(HttpMethod.Delete, $"{path}/seats/{SeatHardwareId}"),
                "key-activation-disable" => Json(HttpMethod.Post, $"{path}/key-activation-settings", new { RequestId = Guid.NewGuid() }),
                "key-activation-lift" => Json(HttpMethod.Post, $"{path}/key-activation-settings/lift", new { RequestId = Guid.NewGuid() }),
                "exclusions-list" => new HttpRequestMessage(HttpMethod.Get, $"{path}/hardware-exclusions"),
                "exclusions-lift" => Json(HttpMethod.Post, $"{path}/hardware-exclusions/lift", new { RequestId = Guid.NewGuid(), HardwareId = SeatHardwareId }),
                _ => throw new ArgumentOutOfRangeException(nameof(route), route, "Unknown licence route.")
            };
            request.Headers.TryAddWithoutValidation("X-Admin-Secret", secret);
            return await client.SendAsync(request);
        }

        /// <summary>Identifier of the grandchild product (sub-product of the child).</summary>
        public Guid GrandchildProductId => grandchildId;

        /// <summary>Sends <c>PUT /api/admin/licenses/{key}</c> with an explicit body and the chosen secret.</summary>
        public async Task<HttpResponseMessage> SendAsync(string key, string secret, object updateBody)
        {
            using var request = Json(HttpMethod.Put, $"/api/admin/licenses/{Uri.EscapeDataString(key)}", updateBody);
            request.Headers.TryAddWithoutValidation("X-Admin-Secret", secret);
            return await client.SendAsync(request);
        }

        /// <summary>
        /// Creates one licence of <paramref name="pluginId"/> through <c>POST /api/admin/licenses</c>, naming the
        /// parent product as the site does.
        /// </summary>
        public async Task<HttpResponseMessage> CreatePluginLicenceAsync(string secret, Guid pluginId)
        {
            using var request = Json(HttpMethod.Post, "/api/admin/licenses", new
            {
                ProductName = $"{database}-PARENT", CustomerName = "Synthetic buyer", CustomerEmail = "buyer@example.test",
                TypeSlug = "TKT2551-PRO", PluginId = pluginId, CommercialSubjectId = Guid.NewGuid(),
                Reference = "tkt2551-" + Guid.NewGuid().ToString("N")
            });
            request.Headers.TryAddWithoutValidation("X-Admin-Secret", secret);
            return await client.SendAsync(request);
        }

        /// <summary>Returns the key of the single licence of a product other than the seeded one.</summary>
        public async Task<string> FindOtherLicenceKeyAsync(Guid productId, string seededKey)
        {
            await using var db = Db();
            return await db.Licenses.AsNoTracking()
                .Where(l => l.ProductId == productId && l.LicenseKey != seededKey)
                .Select(l => l.LicenseKey).SingleAsync();
        }

        /// <summary>Builds a JSON request for the given method and path.</summary>
        private static HttpRequestMessage Json(HttpMethod method, string path, object body) =>
            new(method, path) { Content = JsonContent.Create(body) };

        /// <summary>Stops the server, then drops exactly this generated database.</summary>
        public async ValueTask DisposeAsync()
        {
            client.Dispose(); await host.DisposeAsync();
            await PostgreSqlModelDatabase.DropAsync(maintenance, database);
        }
    }
}
