using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>Seeds only synthetic licensing data, using real signing for trial paths and a compliant historical seat.</summary>
    protected static async Task<License> Tkt1469_SeedAsync(TestDbFactory factory, IServiceProvider services,
        bool free, bool seat, string productName = "TIAConnect", string? minimum = "2.4.300", string mask = "*")
    {
        using var scope = services.CreateScope();
        var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
        var product = new Product { Name = productName, MinimumAllowedVersion = minimum,
            PrivateKeyXml = encryption.Encrypt(LicenseService.GenerateKeys().PrivateKey), PublicKeyXml = "synthetic",
            ApiSecret = "tkt1469-synthetic-admin" };
        var type = new LicenseType { ProductId = product.Id, Name = "Synthetic", Slug = "TRIAL", IsFree = free, AllowPublicTrial = true };
        var license = new License { ProductId = product.Id, Product = product, Type = type, LicenseTypeId = type.Id,
            LicenseKey = "TKT1469-SYNTHETIC", CustomerName = "Synthetic", AllowedVersions = mask,
            ValidityDays = 1, HardwareId = seat ? "A146900000000001" : null };
        await using var db = await factory.CreateDbContextAsync();
        db.Licenses.Add(license);
        if (seat) db.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id,
            HardwareId = license.HardwareId!, AppVersion = "99.0.0", FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
            LastCheckInAt = DateTime.UtcNow.AddHours(-1) });
        await db.SaveChangesAsync();
        return license;
    }

    /// <summary>Uses the public JSON contract, including omitted versus explicit-null version declarations.</summary>
    /// <remarks>New trials provide paired UUID/HWID and synthetic physical observations. Existing-seat and non-trial requests retain their legacy identity contract.</remarks>
    protected static Task<HttpResponseMessage> Tkt1469_SendAsync(HttpClient client, string route, string? version, License license)
    {
        var payload = new Dictionary<string, object?>
        {
            ["licenseKey"] = route == "auto-trial" ? "FREE-TRIAL" : license.LicenseKey,
            ["hardwareId"] = "A146900000000001",
            ["appName"] = license.Product!.Name
        };
        if (version != "#omitted") payload["appVersion"] = version;
        if (route == "trial") payload["typeSlug"] = "TRIAL";
        if (license.HardwareId is null && route is "trial" or "auto-trial")
        {
            const string uuid = "E42A9458-12C9-4759-B0E2-345AB6451290";
            payload["systemUuid"] = uuid;
            payload["hardwareId"] = MachineIdentity.FromUuid(uuid).HardwareId;
            payload["machineEvidence"] = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680");
        }
        return client.PostAsJsonAsync(route is "activate" or "auto-trial" ? "/api/activation" : "/api/activation/" + route, payload);
    }

    /// <summary>Excludes HTTP access and independently asserted machine observations; every business/authority table remains in the comparison.</summary>
    protected static async Task<string[]> Tkt1469_AuthorityFingerprintAsync(string connection) =>
        (await Tkt976_BusinessFingerprintAsync(connection))
            .Where(line => !line.StartsWith("AccessLogs", StringComparison.Ordinal)
                && !line.StartsWith("MachineEvidenceObservations:", StringComparison.Ordinal)).ToArray();

}

/// <summary>Runs the tests from LegacyMinimumVersionPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class LegacyMinimumVersionPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>Exercises compliant emission on online activation/status/trial routes and malformed server configuration.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1469_EmissionAndConfigurationContract")]
    [InlineData("trial", "2.4.300", true)]
    [InlineData("auto-trial", "2.4.300", true)]
    [InlineData("activate", "bad-minimum", false)]
    [InlineData("check", "bad-minimum", false)]
    public async Task Tkt1469_EmissionAndConfigurationContract(string route, string minimum, bool accepted)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.App);
        using var host = Tkt976_CreateLegacyHost(factory);
        using var client = host.CreateClient();
        var license = await Tkt1469_SeedAsync(factory, host.Services, false, true, minimum: minimum);
        using var response = await Tkt1469_SendAsync(client, route, "2.4.300", license);
        Assert.Equal(accepted ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (accepted)
            Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("licenseFile").GetString()));
        else
            Assert.Equal("MINIMUM_VERSION_CONFIGURATION_INVALID", body.RootElement.GetProperty("reasonCode").GetString());
    }

    /// <summary>A parent-product lookup cannot bypass the resolved TIAConnect licence's minimum.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1469_ParentLookup_RetainsLicenseProductPolicy")]
    public async Task Tkt1469_ParentLookup_RetainsLicenseProductPolicy()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.App);
        using var host = Tkt976_CreateLegacyHost(factory);
        using var client = host.CreateClient();
        var license = await Tkt1469_SeedAsync(factory, host.Services, false, true);
        await using (var db = await factory.CreateDbContextAsync())
        {
            var parent = new Product
            {
                Name = "SyntheticParent",
                PrivateKeyXml = "synthetic",
                PublicKeyXml = "synthetic"
            };
            db.Products.Add(parent);
            (await db.Products.SingleAsync(row => row.Id == license.ProductId)).ParentProductId = parent.Id;
            await db.SaveChangesAsync();
        }

        license.Product!.Name = "SyntheticParent";
        foreach (var route in new[]
        {
            "activate",
            "check"
        }

        )
        {
            using var response = await Tkt1469_SendAsync(client, route, null, license);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("APP_VERSION_REQUIRED", body.RootElement.GetProperty("reasonCode").GetString());
        }
    }

    /// <summary>Exercises actual HTTP binding and PostgreSQL rollback without any telemetry or historical-version fallback.</summary>
    /// <remarks>Fresh trial requests use a coherent UUID and physical observations to reach version policy. Their separately asserted observation is diagnostic; every authority table must remain unchanged.</remarks>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1469_MinimumRefusal_PreservesPostgreSqlAuthority")]
    [InlineData("activate", null, false, false, "APP_VERSION_REQUIRED")]
    [InlineData("activate", "#omitted", false, false, "APP_VERSION_REQUIRED")]
    [InlineData("activate", "", true, false, "APP_VERSION_REQUIRED")]
    [InlineData("activate", " \t", false, true, "APP_VERSION_REQUIRED")]
    [InlineData("activate", "2.1.357", false, false, "APP_VERSION_BELOW_MINIMUM")]
    [InlineData("activate", "2.1.357", true, true, "APP_VERSION_BELOW_MINIMUM")]
    [InlineData("activate", "99.0-preview", false, true, "APP_VERSION_INVALID")]
    [InlineData("check", null, false, true, "APP_VERSION_REQUIRED")]
    [InlineData("check", "#omitted", false, true, "APP_VERSION_REQUIRED")]
    [InlineData("check", " ", true, true, "APP_VERSION_REQUIRED")]
    [InlineData("check", "2.1.357", false, true, "APP_VERSION_BELOW_MINIMUM")]
    [InlineData("check", "bad", true, true, "APP_VERSION_INVALID")]
    [InlineData("trial", null, true, false, "APP_VERSION_REQUIRED")]
    [InlineData("trial", "2.1.357", true, true, "APP_VERSION_BELOW_MINIMUM")]
    [InlineData("auto-trial", null, true, false, "APP_VERSION_REQUIRED")]
    [InlineData("auto-trial", "2.1.357", true, true, "APP_VERSION_BELOW_MINIMUM")]
    public async Task Tkt1469_MinimumRefusal_PreservesPostgreSqlAuthority(string route, string? version, bool free, bool seat, string reason)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.App);
        using var host = Tkt976_CreateLegacyHost(factory);
        using var client = host.CreateClient();
        var license = await Tkt1469_SeedAsync(factory, host.Services, free, seat);
        var before = await Tkt1469_AuthorityFingerprintAsync(database.App);
        using var response = await Tkt1469_SendAsync(client, route, version, license);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("UPDATE_REQUIRED", body.RootElement.GetProperty("status").GetString());
        Assert.Equal(reason, body.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal("UPDATE_REQUIRED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        Assert.False(body.RootElement.TryGetProperty("licenseFile", out _));
        Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("correlationId").GetString()));
        Assert.Equal(before, await Tkt1469_AuthorityFingerprintAsync(database.App));
        if (!seat && route is "trial" or "auto-trial")
        {
            await using var observed = await factory.CreateDbContextAsync();
            var observation = Assert.Single(await observed.MachineEvidenceObservations.ToListAsync());
            Assert.Null(observation.RefusalCode);
            Assert.Equal("E42A9458-12C9-4759-B0E2-345AB6451290", observation.SystemUuidCanonical);
            Assert.Equal(MachineIdentity.FromUuid(observation.SystemUuidCanonical).HardwareId, observation.HardwareId);
            Assert.Equal(1, observation.ObservationCount);
        }

        if (route == "activate" || seat && route is "trial" or "auto-trial")
        {
            await using var observed = await factory.CreateDbContextAsync();
            var history = await observed.LicenseHistories.SingleAsync(row => row.LicenseId == license.Id && row.Action == "ACTIVATION_DECISION_V1");
            Assert.Contains(reason, history.Details);
        }
    }

    /// <summary>Proves version acceptance, recovery, product isolation and restrictive licence masks over HTTP.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1469_ActivationAndRecovery_PreserveCompatibility")]
    [InlineData("TIAConnect", "2.4.300", "2.4.300", "*", false, true)]
    [InlineData("TIAConnect", "2.4.300", "2.4.300.0", "*", true, true)]
    [InlineData("TIAConnect", "2.4.300", "2.10.0", "*", false, true)]
    [InlineData("TIAConnect", "2.4.300", "2.4.300", "1.*", false, false)]
    [InlineData("TIAConnect", null, null, "*", false, true)]
    [InlineData("YOUR_APP_NAME", "2.4.300", null, "*", false, true)]
    public async Task Tkt1469_ActivationAndRecovery_PreserveCompatibility(string productName, string? minimum, string? version, string mask, bool seat, bool allowed)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.App);
        using var host = Tkt976_CreateLegacyHost(factory);
        using var client = host.CreateClient();
        var license = await Tkt1469_SeedAsync(factory, host.Services, false, seat, productName, minimum, mask);
        using var response = await Tkt1469_SendAsync(client, "activate", version, license);
        Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.BadRequest, response.StatusCode);
        if (!allowed)
            return;
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("licenseFile").GetString()));
        using var check = await Tkt1469_SendAsync(client, "check", version, license);
        using var checkedBody = JsonDocument.Parse(await check.Content.ReadAsStringAsync());
        Assert.Equal("VALID", checkedBody.RootElement.GetProperty("status").GetString());
        Assert.False(string.IsNullOrEmpty(checkedBody.RootElement.GetProperty("licenseFile").GetString()));
    }

    /// <summary>Preserves real revocation, expiry and hardware bans ahead of an invalid declaration.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1469_SecurityPriority_IsPreserved")]
    [InlineData("revoked", "REVOKED", "LICENSE_DISABLED")]
    [InlineData("expired", "EXPIRED", "LICENSE_EXPIRED")]
    [InlineData("piracy", "REVOKED", "BANNED")]
    public async Task Tkt1469_SecurityPriority_IsPreserved(string state, string checkStatus, string activationCode)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.App);
        using var host = Tkt976_CreateLegacyHost(factory);
        using var client = host.CreateClient();
        var license = await Tkt1469_SeedAsync(factory, host.Services, false, true);
        await using (var db = await factory.CreateDbContextAsync())
        {
            var stored = await db.Licenses.SingleAsync(row => row.Id == license.Id);
            if (state == "revoked")
                stored.RevokedAt = DateTime.UtcNow;
            if (state == "expired")
                stored.ExpirationDate = DateTime.UtcNow.AddDays(-1);
            if (state == "piracy")
                db.BannedHardwareIds.Add(new BannedHardwareId { HardwareId = license.HardwareId!, ProductId = license.ProductId, BanCategory = BannedHardwareId.Categories.Piracy });
            await db.SaveChangesAsync();
        }

        var before = await Tkt1469_AuthorityFingerprintAsync(database.App);
        using var check = await Tkt1469_SendAsync(client, "check", null, license);
        using var checkBody = JsonDocument.Parse(await check.Content.ReadAsStringAsync());
        Assert.Equal(checkStatus, checkBody.RootElement.GetProperty("status").GetString());
        using var activate = await Tkt1469_SendAsync(client, "activate", null, license);
        Assert.Equal(activationCode, activate.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        Assert.Equal(before, await Tkt1469_AuthorityFingerprintAsync(database.App));
    }
}
