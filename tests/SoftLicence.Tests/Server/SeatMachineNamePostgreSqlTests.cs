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
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003404: proves through real HTTP on PostgreSQL that the PC name sent in <c>MachineEvidence</c> is stored
/// on the seat at activation and trial, refreshed by <c>POST /api/activation/check</c> when it changes, never
/// erased by a request without a usable name, never written on another machine's seat, and exposed to the
/// website in <c>GET /api/admin/licenses/{key}</c>.
/// </summary>
public sealed class SeatMachineNamePostgreSqlTests
{
    /// <summary>Synthetic paid type slug.</summary>
    private const string PaidSlug = "SYN-NAME-PRO";
    /// <summary>Synthetic public trial type slug.</summary>
    private const string TrialSlug = "SYN-NAME-TRIAL";
    /// <summary>Synthetic admin secret of the in-process host.</summary>
    private const string AdminSecret = "tkt3404-local-synthetic";

    /// <summary>
    /// Activation stores the cleaned name and the admin read exposes it; a check with a new name refreshes it;
    /// checks without evidence, with a blank name or without the property keep it.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ActivationThenCheck_StoresRefreshesAndNeverErasesTheName()
    {
        await using var f = await Fixture.CreateAsync();
        var machine = Machine.Create();
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 2);

        var activated = await f.PostAsync("/api/activation", f.ActivationBody(license.LicenseKey, machine, "  PC-ATELIER\u200B "));
        Assert.Equal(HttpStatusCode.OK, activated);
        Assert.Equal("PC-ATELIER", await f.SeatNameAsync(license.Id, machine));
        Assert.Equal("PC-ATELIER", await f.AdminExposedNameAsync(license.LicenseKey, machine));

        Assert.Equal(HttpStatusCode.OK, await f.PostAsync("/api/activation/check",
            f.ActivationBody(license.LicenseKey, machine, "pc-bureau")));
        Assert.Equal("pc-bureau", await f.SeatNameAsync(license.Id, machine));

        Assert.Equal(HttpStatusCode.OK, await f.PostAsync("/api/activation/check",
            f.ActivationBody(license.LicenseKey, machine, name: null, withEvidence: false)));
        Assert.Equal(HttpStatusCode.OK, await f.PostAsync("/api/activation/check",
            f.ActivationBody(license.LicenseKey, machine, "   ")));
        Assert.Equal(HttpStatusCode.OK, await f.PostAsync("/api/activation/check",
            f.ActivationBody(license.LicenseKey, machine, name: null)));
        Assert.Equal("pc-bureau", await f.SeatNameAsync(license.Id, machine));
        Assert.Equal("pc-bureau", await f.AdminExposedNameAsync(license.LicenseKey, machine));
    }

    /// <summary>
    /// A check from a machine without an active seat on the licence renames nothing: the other machine's seat
    /// keeps its name and no seat is created. A seat that never received a name is exposed as null.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Check_FromAnotherMachine_RenamesNothingAndUnnamedSeatIsNull()
    {
        await using var f = await Fixture.CreateAsync();
        var seated = Machine.Create();
        var stranger = Machine.Create();
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 2, activeSeat: seated, seatName: "PC-HISTO");
        var unnamed = Machine.Create();
        await f.AddActiveSeatAsync(license.Id, unnamed);

        Assert.Equal(HttpStatusCode.OK, await f.PostAsync("/api/activation/check",
            f.ActivationBody(license.LicenseKey, stranger, "PC-INTRUS")));

        Assert.Equal("PC-HISTO", await f.SeatNameAsync(license.Id, seated));
        Assert.Null(await f.SeatNameAsync(license.Id, unnamed));
        Assert.Null(await f.AdminExposedNameAsync(license.LicenseKey, unnamed));
        await using var db = f.Db();
        Assert.False(await db.LicenseSeats.AnyAsync(row => row.LicenseId == license.Id && row.HardwareId == stranger.HardwareId));
    }

    /// <summary>A public trial creates its seat with the reported name, bounded to 64 characters.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Trial_CreatesSeatWithBoundedName()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(TrialSlug, isFree: true, allowPublicTrial: true);
        var machine = Machine.Create();

        var status = await f.PostAsync("/api/activation/trial", new
        {
            AppName = f.ProductName, TypeSlug = TrialSlug, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
            AppVersion = "1.0.0", MachineEvidence = Fixture.Evidence(new string('N', 100))
        });

        Assert.Equal(HttpStatusCode.OK, status);
        await using var db = f.Db();
        var seat = await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.HardwareId == machine.HardwareId);
        Assert.Equal(new string('N', SeatMachineName.MaxLength), seat.MachineName);
    }

    /// <summary>Synthetic machine identity accepted by the UUID-based identity rule.</summary>
    private sealed record Machine(string SystemUuid, string HardwareId)
    {
        /// <summary>Creates a fresh accepted identity from a random UUID.</summary>
        public static Machine Create()
        {
            var uuid = Guid.NewGuid().ToString("D").ToUpperInvariant();
            var identity = MachineIdentity.FromUuid(uuid);
            Assert.True(identity.IsAccepted);
            return new Machine(uuid, identity.HardwareId!);
        }
    }

    /// <summary>Seeded license identity.</summary>
    private sealed record SeededLicense(Guid Id, string LicenseKey);

    /// <summary>Owns one cloned PostgreSQL database, one synthetic product and one in-process host.</summary>
    private sealed class Fixture : IAsyncDisposable
    {
        private readonly string maintenance;
        private readonly string database;
        private readonly string connection;
        private readonly WebApplicationFactory<Program> host;
        private Guid productId;

        /// <summary>Anonymous client; admin calls add the secret per request.</summary>
        private HttpClient Client { get; }

        /// <summary>Synthetic product name (the cloned database name, unique per test).</summary>
        public string ProductName => database;

        /// <summary>Builds the in-process host bound to the cloned database, without hosted services.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance; this.database = database; this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", AdminSecret);
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
            Client = host.CreateClient();
        }

        /// <summary>Creates a fresh untracked context.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);

        /// <summary>Adds one license type to the synthetic product.</summary>
        public async Task<Guid> AddTypeAsync(string slug, bool isFree = false, bool allowPublicTrial = false)
        {
            await using var db = Db();
            var type = new LicenseType
            {
                ProductId = productId, Name = "Synthetic " + slug, Slug = slug, DefaultDurationDays = 30,
                DefaultMaxSeats = 1, IsFree = isFree, AllowPublicTrial = allowPublicTrial
            };
            db.LicenseTypes.Add(type);
            await db.SaveChangesAsync();
            return type.Id;
        }

        /// <summary>Seeds one license of a new type, with an optional active seat carrying a stored name.</summary>
        public async Task<SeededLicense> SeedLicenseAsync(string slug, int maxSeats, Machine? activeSeat = null,
            string? seatName = null)
        {
            var typeId = await AddTypeAsync(slug);
            await using var db = Db();
            var license = new License
            {
                ProductId = productId, LicenseTypeId = typeId,
                LicenseKey = "TKT3404-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
                CustomerName = "Synthetic buyer", CustomerEmail = "buyer@example.test",
                MaxSeats = maxSeats, HardwareId = activeSeat?.HardwareId,
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            };
            db.Licenses.Add(license);
            if (activeSeat != null)
                db.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = license.Id, HardwareId = activeSeat.HardwareId, IsActive = true, MachineName = seatName
                });
            await db.SaveChangesAsync();
            return new SeededLicense(license.Id, license.LicenseKey);
        }

        /// <summary>Adds an active seat that never received a name (historical row).</summary>
        public async Task AddActiveSeatAsync(Guid licenseId, Machine machine)
        {
            await using var db = Db();
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = licenseId, HardwareId = machine.HardwareId, IsActive = true });
            await db.SaveChangesAsync();
        }

        /// <summary>Builds an activation or check body; <paramref name="name"/> null omits the property.</summary>
        public object ActivationBody(string key, Machine machine, string? name, bool withEvidence = true) => new
        {
            AppName = ProductName, LicenseKey = key, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
            AppVersion = "1.0.0", CustomerEmail = "buyer@example.test",
            MachineEvidence = withEvidence ? Evidence(name) : (JsonElement?)null
        };

        /// <summary>Posts one anonymous public request and returns its status, refusing a rate-limited answer.</summary>
        public async Task<HttpStatusCode> PostAsync(string path, object body)
        {
            using var response = await Client.PostAsJsonAsync(path, body);
            Assert.True(response.StatusCode != HttpStatusCode.TooManyRequests,
                "Appel limit\u00E9 en d\u00E9bit (429) : le test ne prouve rien.");
            return response.StatusCode;
        }

        /// <summary>Reads the stored name of the machine's seat on the licence, straight from PostgreSQL.</summary>
        public async Task<string?> SeatNameAsync(Guid licenseId, Machine machine)
        {
            await using var db = Db();
            return (await db.LicenseSeats.AsNoTracking()
                .SingleAsync(row => row.LicenseId == licenseId && row.HardwareId == machine.HardwareId)).MachineName;
        }

        /// <summary>Reads the name the website sees for the machine in <c>GET /api/admin/licenses/{key}</c>.</summary>
        public async Task<string?> AdminExposedNameAsync(string key, Machine machine)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/licenses/" + key);
            request.Headers.Add("X-Admin-Secret", AdminSecret);
            using var response = await Client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var activation = json.RootElement.GetProperty("activations").EnumerateArray()
                .Single(item => item.GetProperty("hardwareId").GetString() == machine.HardwareId);
            var name = activation.GetProperty("machineName");
            return name.ValueKind == JsonValueKind.Null ? null : name.GetString();
        }

        /// <summary>Physical-machine evidence, with the SDK <c>MachineName</c> property when a name is given.</summary>
        public static JsonElement Evidence(string? name)
        {
            var physical = new Dictionary<string, object?>
            {
                ["SystemManufacturer"] = new { Status = "Present", Values = new[] { "Dell Inc." }, Error = (string?)null },
                ["SystemModel"] = new { Status = "Present", Values = new[] { "Precision 7680" }, Error = (string?)null }
            };
            if (name != null)
                physical["MachineName"] = name;
            return JsonSerializer.SerializeToElement(physical);
        }

        /// <summary>Clones the current-schema model database and seeds one synthetic product with fresh keys.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("seat_name");
            var fixture = new Fixture(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                using var rsa = RSA.Create(2048);
                using var scope = fixture.host.Services.CreateScope();
                var product = new Product
                {
                    Name = clone.DatabaseName, ApiSecret = "tkt3404-fixture-product",
                    PrivateKeyXml = scope.ServiceProvider.GetRequiredService<EncryptionService>().Encrypt(rsa.ToXmlString(true)),
                    PublicKeyXml = rsa.ToXmlString(false)
                };
                db.Products.Add(product);
                await db.SaveChangesAsync();
                fixture.productId = product.Id;
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        /// <summary>Closes HTTP, then drops exactly this generated database.</summary>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose(); await host.DisposeAsync();
            await PostgreSqlModelDatabase.DropAsync(maintenance, database);
        }
    }
}
