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
/// TKT-002475: proves through real HTTP on PostgreSQL that a license whose key activation is disabled refuses
/// every new seat admission by key (<c>POST /api/activation</c>, <c>POST /api/activation/trial</c> and the
/// AUTO-TRIAL interception) with the closed 409 <c>key_activation_disabled</c> contract, never revokes the
/// license, writes no seat, and keeps the recovery of an already-active seat. The admin routes are exercised
/// for the pose, the exact key lookup and the idempotency conflict.
/// </summary>
public sealed class LicenseKeyActivationHttpPostgreSqlTests
{
    /// <summary>Synthetic type slug of the guarded license.</summary>
    private const string PaidSlug = "SYN-KEY-PRO";
    /// <summary>Synthetic free type slug accepted by the AUTO-TRIAL interception.</summary>
    private const string AutoTrialSlug = "SYN-KEY-FREE-TRIAL";
    /// <summary>Synthetic admin secret of the in-process host.</summary>
    private const string AdminSecret = "tkt2475-local-synthetic";

    /// <summary>
    /// Bloquant PR #422: a new machine is refused with 409 and the closed code, the license stays active and
    /// unrevoked, no seat is written, and the machine already holding an active seat still recovers.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Activation_DisabledLicense_RefusesNewMachineWithoutRevocationAndKeepsRecovery()
    {
        await using var f = await Fixture.CreateAsync();
        var seated = Machine.Create();
        var newcomer = Machine.Create();
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 2, activeSeat: seated);
        await f.DisableByAdminAsync(license.LicenseKey);
        var seatsBefore = await f.SeatSnapshotAsync(license.Id);

        var refused = await f.ActivateAsync(license.LicenseKey, newcomer);

        AssertKeyActivationDisabled(refused);
        await f.AssertLicenseUntouchedAsync(license.Id, seatsBefore);

        var recovered = await f.ActivateAsync(license.LicenseKey, seated);
        Assert.Equal(HttpStatusCode.OK, recovered.Status);
        Assert.Contains("licenseFile", recovered.Body, StringComparison.Ordinal);
        await using var db = f.Db();
        Assert.True((await db.Licenses.AsNoTracking().SingleAsync(row => row.Id == license.Id)).IsActive);
        Assert.False(await db.LicenseSeats.AnyAsync(row => row.LicenseId == license.Id && row.HardwareId == newcomer.HardwareId));
    }

    /// <summary>Without the setting, the same new machine is admitted: the default behavior is unchanged.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Activation_WithoutSetting_AdmitsNewMachine()
    {
        await using var f = await Fixture.CreateAsync();
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 2, activeSeat: Machine.Create());
        var newcomer = Machine.Create();

        var admitted = await f.ActivateAsync(license.LicenseKey, newcomer);

        Assert.Equal(HttpStatusCode.OK, admitted.Status);
        Assert.Contains("licenseFile", admitted.Body, StringComparison.Ordinal);
        await using var db = f.Db();
        Assert.True(await db.LicenseSeats.AnyAsync(row =>
            row.LicenseId == license.Id && row.HardwareId == newcomer.HardwareId && row.IsActive));
    }

    /// <summary>
    /// The trial route refuses to create a new seat on the disabled license for a machine whose seat is
    /// inactive, without revocation, while the machine holding an active seat still recovers its file.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Trial_DisabledLicense_RefusesNewSeatAndKeepsActiveSeatRecovery()
    {
        await using var f = await Fixture.CreateAsync();
        var seated = Machine.Create();
        var released = Machine.Create();
        // TKT-002468: the trial route only processes a held licence of the requested, opted-in type.
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 2, activeSeat: seated, inactiveSeat: released,
            allowPublicTrial: true);
        await f.DisableByAdminAsync(license.LicenseKey);
        var seatsBefore = await f.SeatSnapshotAsync(license.Id);

        var refused = await f.TrialAsync(PaidSlug, released);

        AssertKeyActivationDisabled(refused);
        await f.AssertLicenseUntouchedAsync(license.Id, seatsBefore);

        var recovered = await f.TrialAsync(PaidSlug, seated);
        Assert.Equal(HttpStatusCode.OK, recovered.Status);
        Assert.Contains("licenseFile", recovered.Body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Point 7: an expired disabled license requested with another type falls through to a brand-new license
    /// (TKT-002468 selection), so the guard does not apply and the disabled license is left untouched.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Trial_ExpiredDisabledLicense_OtherType_CreatesAnotherLicense()
    {
        await using var f = await Fixture.CreateAsync();
        var released = Machine.Create();
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 1, inactiveSeat: released, expired: true);
        await f.AddTypeAsync(AutoTrialSlug, isFree: true, allowPublicTrial: true);
        await f.DisableByAdminAsync(license.LicenseKey);
        var seatsBefore = await f.SeatSnapshotAsync(license.Id);

        var outcome = await f.TrialAsync(AutoTrialSlug, released);

        Assert.Equal(HttpStatusCode.OK, outcome.Status);
        Assert.Contains("licenseFile", outcome.Body, StringComparison.Ordinal);
        await f.AssertLicenseUntouchedAsync(license.Id, seatsBefore);
        await using var db = f.Db();
        Assert.Equal(2, await db.Licenses.CountAsync());
    }

    /// <summary>Point 2: AUTO-TRIAL refuses to recreate a seat on the disabled license found by this machine.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task AutoTrial_DisabledLicense_RefusesNewSeatWithoutRevocation()
    {
        await using var f = await Fixture.CreateAsync();
        var released = Machine.Create();
        var license = await f.SeedLicenseAsync(AutoTrialSlug, maxSeats: 1, inactiveSeat: released,
            isFree: true, allowPublicTrial: true);
        await f.DisableByAdminAsync(license.LicenseKey);
        var seatsBefore = await f.SeatSnapshotAsync(license.Id);

        var refused = await f.ActivateAsync(AutoTrialSlug, released);

        AssertKeyActivationDisabled(refused);
        await f.AssertLicenseUntouchedAsync(license.Id, seatsBefore);
    }

    /// <summary>
    /// Point 4 and 8: the admin routes resolve the exact key only, and a request UUID reused with the other
    /// intent is answered 409 <c>idempotency_conflict</c> instead of 500.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Admin_ExactKeyAndIdempotencyConflict()
    {
        await using var f = await Fixture.CreateAsync();
        var license = await f.SeedLicenseAsync(PaidSlug, maxSeats: 1);
        var requestId = Guid.NewGuid();

        using (var lowered = await f.AdminPostAsync($"licenses/{license.LicenseKey.ToLowerInvariant()}/key-activation-settings", requestId))
            Assert.Equal(HttpStatusCode.NotFound, lowered.StatusCode);

        using (var disabled = await f.AdminPostAsync($"licenses/{license.LicenseKey}/key-activation-settings", requestId))
        {
            Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
            using var json = JsonDocument.Parse(await disabled.Content.ReadAsStringAsync());
            Assert.Equal(LicenseKeyActivationSettingService.DisabledOutcome, json.RootElement.GetProperty("outcome").GetString());
        }

        using var conflict = await f.AdminPostAsync($"licenses/{license.LicenseKey}/key-activation-settings/lift", requestId);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        using var error = JsonDocument.Parse(await conflict.Content.ReadAsStringAsync());
        Assert.Equal("idempotency_conflict", error.RootElement.GetProperty("error").GetString());
        await using var db = f.Db();
        Assert.True(await LicenseKeyActivationChecker.IsDisabledAsync(db, license.Id));
    }

    /// <summary>Asserts the closed refusal contract: 409, header code, JSON envelope and generic message.</summary>
    private static void AssertKeyActivationDisabled(CallOutcome outcome)
    {
        Assert.Equal(HttpStatusCode.Conflict, outcome.Status);
        Assert.Equal(LicenseKeyActivationChecker.RefusalCode, outcome.ErrorCodeHeader);
        using var json = JsonDocument.Parse(outcome.Body);
        Assert.False(json.RootElement.GetProperty("isSuccess").GetBoolean());
        Assert.Equal(LicenseKeyActivationChecker.RefusalCode, json.RootElement.GetProperty("errorCode").GetString());
        Assert.Equal(
            SoftLicence.Server.Controllers.ActivationController.KeyActivationDisabledMessage,
            json.RootElement.GetProperty("errorMessage").GetString());
        Assert.Equal(1, json.RootElement.GetProperty("contractVersion").GetInt32());
        Assert.DoesNotContain("licenseFile", outcome.Body, StringComparison.Ordinal);
    }

    /// <summary>One observed HTTP call.</summary>
    private sealed record CallOutcome(HttpStatusCode Status, string Body, string? ErrorCodeHeader);

    /// <summary>Synthetic, internally consistent machine identity (UUID and its derived canonical HWID).</summary>
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
        public HttpClient Client { get; }

        /// <summary>Synthetic product name.</summary>
        public string ProductName => database;

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

        /// <summary>Seeds one license of a new type, with optional active and inactive seats.</summary>
        public async Task<SeededLicense> SeedLicenseAsync(string slug, int maxSeats, Machine? activeSeat = null,
            Machine? inactiveSeat = null, bool expired = false, bool isFree = false, bool allowPublicTrial = false)
        {
            var typeId = await AddTypeAsync(slug, isFree, allowPublicTrial);
            await using var db = Db();
            var license = new License
            {
                ProductId = productId, LicenseTypeId = typeId,
                LicenseKey = "TKT2475-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
                CustomerName = "Synthetic buyer", CustomerEmail = "buyer@example.test",
                MaxSeats = maxSeats, HardwareId = activeSeat?.HardwareId,
                ExpirationDate = expired ? DateTime.UtcNow.AddDays(-1) : DateTime.UtcNow.AddDays(30)
            };
            db.Licenses.Add(license);
            if (activeSeat != null)
                db.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = activeSeat.HardwareId, IsActive = true });
            if (inactiveSeat != null)
                db.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = license.Id, HardwareId = inactiveSeat.HardwareId, IsActive = false,
                    UnlinkedAt = DateTime.UtcNow.AddDays(-2)
                });
            await db.SaveChangesAsync();
            return new SeededLicense(license.Id, license.LicenseKey);
        }

        /// <summary>Poses the setting through the admin route and requires the <c>disabled</c> terminal.</summary>
        public async Task DisableByAdminAsync(string licenseKey)
        {
            using var response = await AdminPostAsync($"licenses/{licenseKey}/key-activation-settings", Guid.NewGuid());
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        /// <summary>Posts one admin key-activation request with the synthetic admin secret.</summary>
        public Task<HttpResponseMessage> AdminPostAsync(string relativePath, Guid requestId)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/" + relativePath)
            {
                Content = JsonContent.Create(new { RequestId = requestId })
            };
            request.Headers.Add("X-Admin-Secret", AdminSecret);
            return Client.SendAsync(request);
        }

        /// <summary>Serializes the seats of one license for unchanged-state assertions.</summary>
        public async Task<string> SeatSnapshotAsync(Guid licenseId)
        {
            await using var db = Db();
            return JsonSerializer.Serialize(await db.LicenseSeats.AsNoTracking()
                .Where(row => row.LicenseId == licenseId).OrderBy(row => row.Id).ToListAsync());
        }

        /// <summary>Asserts the license is still active, unrevoked, and its seats are byte-identical.</summary>
        public async Task AssertLicenseUntouchedAsync(Guid licenseId, string seatsBefore)
        {
            await using var db = Db();
            var license = await db.Licenses.AsNoTracking().SingleAsync(row => row.Id == licenseId);
            Assert.True(license.IsActive);
            Assert.Null(license.RevokedAt);
            Assert.Null(license.RevocationReason);
            Assert.Equal(seatsBefore, await SeatSnapshotAsync(licenseId));
            Assert.False(await db.LicenseHistories.AnyAsync(row => row.Action == "FIRST_ORDER_FREE_REVOKED"));
        }

        /// <summary>Anonymous <c>POST /api/activation</c> with physical-machine evidence.</summary>
        public async Task<CallOutcome> ActivateAsync(string key, Machine machine)
        {
            using var response = await Client.PostAsJsonAsync("/api/activation", new
            {
                AppName = ProductName, LicenseKey = key, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
                AppVersion = "1.0.0", CustomerEmail = "buyer@example.test", MachineEvidence = PhysicalEvidence()
            });
            return await ReadAsync(response);
        }

        /// <summary>Anonymous <c>POST /api/activation/trial</c> with physical-machine evidence.</summary>
        public async Task<CallOutcome> TrialAsync(string slug, Machine machine)
        {
            using var response = await Client.PostAsJsonAsync("/api/activation/trial", new
            {
                AppName = ProductName, TypeSlug = slug, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
                AppVersion = "1.0.0", MachineEvidence = PhysicalEvidence()
            });
            return await ReadAsync(response);
        }

        private static async Task<CallOutcome> ReadAsync(HttpResponseMessage response)
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.True(response.StatusCode != HttpStatusCode.TooManyRequests,
                "Appel limité en débit (429) : le test ne prouve rien.");
            var errorCode = response.Headers.TryGetValues("X-SoftLicence-Error-Code", out var values) ? values.SingleOrDefault() : null;
            return new CallOutcome(response.StatusCode, body, errorCode);
        }

        private static JsonElement PhysicalEvidence() => JsonSerializer.SerializeToElement(new
        {
            SystemManufacturer = new { Status = "Present", Values = new[] { "Dell Inc." }, Error = (string?)null },
            SystemModel = new { Status = "Present", Values = new[] { "Precision 7680" }, Error = (string?)null }
        });

        /// <summary>Clones the current-schema model database and seeds one synthetic product with fresh keys.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("keyact_http");
            var fixture = new Fixture(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                using var rsa = RSA.Create(2048);
                using var scope = fixture.host.Services.CreateScope();
                var product = new Product
                {
                    Name = clone.DatabaseName, ApiSecret = "tkt2475-fixture-product",
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
