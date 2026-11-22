using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;
using SdkLicenseService = SoftLicence.SDK.LicenseService;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002466, part 2: the licence journey a client application really follows, proven end to end with the SDK.
/// The website issues the 30-day trial through the administrator API (a key, then a normal activation) on a type that
/// stays closed to public trials; the application then switches to Community through the public trial route when its
/// trial, its paid plan or its Community licence has expired. Every other public request (paid type, foreign product,
/// slug or product-name variant) must deliver nothing.
/// </summary>
/// <remarks>
/// Products, slugs and hardware identities are synthetic. The only real slug is the Community slug the trial route
/// still hard-codes for its renewal (TKT-001889). "No write" is asserted on the rights tables (licences, seats,
/// licence history including decision rows, renewals); request audit and machine observation traces are technical
/// logs written for every public call and are not rights. Each case keeps fewer than ten public calls so the
/// per-host rate limiter cannot turn a call into a misleading refusal; a 429 fails the test.
/// </remarks>
public sealed partial class PublicTrialTypeExposurePostgreSqlTests
{
    /// <summary>Synthetic slug of the website's 30-day trial type, issued only through the administrator API.</summary>
    private const string SiteTrialSlug = "SYN-TRIAL-30";
    /// <summary>Second synthetic paid slug, containing the letter I for the Turkish dotted and dotless variants.</summary>
    private const string PaidEliteSlug = "SYN-ELITE";
    /// <summary>Fallback slug the AUTO-TRIAL interception looks up when the key matches no type.</summary>
    private const string AutoTrialFallbackSlug = "TRIAL";
    /// <summary>Opted-in Community slug of the second, unrelated synthetic product.</summary>
    private const string ForeignCommunitySlug = "SYN-B-COMMUNITY";
    /// <summary>Opted-in AUTO-TRIAL slug of the second, unrelated synthetic product.</summary>
    private const string ForeignAutoTrialSlug = "SYN-B-FREE-TRIAL";

    /// <summary>Signed parameters of the website trial.</summary>
    private static readonly IReadOnlyDictionary<string, string> SiteTrialParams =
        new Dictionary<string, string>(StringComparer.Ordinal) { ["tier"] = "trial", ["maxLines"] = "20" };

    /// <summary>Licence the machine holds before it asks for Community.</summary>
    public enum HeldLicence
    {
        /// <summary>A website trial (administrator key, then activation) that has expired.</summary>
        ExpiredSiteTrial,
        /// <summary>A paid plan (administrator key, then activation) that has expired.</summary>
        ExpiredPaidPlan,
        /// <summary>A Community licence obtained from the public route that has expired.</summary>
        ExpiredCommunity
    }

    /// <summary>
    /// (a) The website trial path still works on a type closed to public trials: the administrator API issues the key,
    /// a normal activation signs a usable file, while the same slug stays refused on the anonymous route.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_SiteTrial_AdminKeyOnClosedType_ActivatesAsBefore()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(SiteTrialSlug, durationDays: 30, SiteTrialParams, isFree: true);
        var machine = Machine.Create();

        var key = await f.AdminCreateLicenseAsync(SiteTrialSlug);
        var activation = await f.AutoTrialAsync(key, machine);

        Assert.True(activation.LicenseFile is not null, activation.Body);
        var validation = SdkLicenseService.ValidateLicenseDetailed(activation.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        var model = validation.License!;
        Assert.Equal(SiteTrialSlug, model.TypeSlug);
        Assert.Equal(key, model.LicenseKey);
        Assert.Equal(machine.HardwareId, model.HardwareId);
        Assert.Equal("trial", model.Features["tier"]);
        Assert.Equal("20", model.Features["maxLines"]);
        Assert.InRange(model.ExpirationDate!.Value, DateTime.UtcNow.AddDays(29), DateTime.UtcNow.AddDays(31));
        Assert.Equal(LicenseValidationErrorCode.HardwareIdMismatch,
            SdkLicenseService.ValidateLicenseDetailed(activation.LicenseFile!, f.PublicKeyXml, Machine.Create().HardwareId).ErrorCode);
        Assert.False(SdkLicenseService.ValidateLicenseDetailed(activation.LicenseFile!, Fixture.ForeignPublicKeyXml, machine.HardwareId).IsValid);

        var anonymous = await f.TrialAsync(SiteTrialSlug, Machine.Create());
        Assert.Null(anonymous.LicenseFile);
        Assert.Equal(PublicTrialNotAllowed, anonymous.ErrorCodeHeader);
        await using var db = f.Db();
        Assert.Equal(1, await db.Licenses.CountAsync());
    }

    /// <summary>
    /// (b) and (c) The three Community switches of a client application through <c>POST /api/activation/trial</c>.
    /// Opted in: a valid Community licence is delivered (renewed for an expired Community, new otherwise) and the held
    /// trial or paid plan is never extended. Not opted in: a switch from a trial or paid plan is a typed refusal with no
    /// write on the rights tables; an expired Community gets the same typed refusal (TKT-002468; previously an
    /// accidental 503 authority_unavailable) with no write either.
    /// </summary>
    /// <param name="held">Licence the machine holds, expired, before the request.</param>
    /// <param name="allowPublicTrial">Opt-in of the Community type at request time.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(HeldLicence.ExpiredSiteTrial, true)]
    [InlineData(HeldLicence.ExpiredPaidPlan, true)]
    [InlineData(HeldLicence.ExpiredCommunity, true)]
    [InlineData(HeldLicence.ExpiredSiteTrial, false)]
    [InlineData(HeldLicence.ExpiredPaidPlan, false)]
    [InlineData(HeldLicence.ExpiredCommunity, false)]
    public async Task Tkt2466_CommunitySwitch_FromExpiredLicence(HeldLicence held, bool allowPublicTrial)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(HardCodedCommunitySlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
        await f.AddTypeAsync(SiteTrialSlug, durationDays: 30, SiteTrialParams, isFree: true);
        await f.AddTypeAsync(PaidSlug, durationDays: 365, PaidParams);
        var machine = Machine.Create();

        Guid heldId;
        if (held == HeldLicence.ExpiredCommunity)
        {
            var first = await f.TrialAsync(HardCodedCommunitySlug, machine);
            Assert.True(first.LicenseFile is not null, first.Body);
            heldId = SdkLicenseService.ValidateLicenseDetailed(first.LicenseFile!, f.PublicKeyXml, machine.HardwareId).License!.Id;
        }
        else
        {
            var key = await f.AdminCreateLicenseAsync(held == HeldLicence.ExpiredSiteTrial ? SiteTrialSlug : PaidSlug);
            var activation = await f.AutoTrialAsync(key, machine);
            Assert.True(activation.LicenseFile is not null, activation.Body);
            heldId = SdkLicenseService.ValidateLicenseDetailed(activation.LicenseFile!, f.PublicKeyXml, machine.HardwareId).License!.Id;
        }

        var expiredAt = await f.ExpireLicenseAsync(heldId);
        await f.SetOptInAsync(HardCodedCommunitySlug, allowPublicTrial);
        var before = await f.RightsSnapshotAsync();

        var outcome = await f.TrialAsync(HardCodedCommunitySlug, machine);

        if (!allowPublicTrial)
        {
            Assert.Null(outcome.LicenseFile);
            Assert.Equal(HttpStatusCode.OK, outcome.Status);
            Assert.Equal(PublicTrialNotAllowed, outcome.ErrorCodeHeader);
            using var json = JsonDocument.Parse(outcome.Body);
            Assert.False(json.RootElement.GetProperty("isSuccess").GetBoolean());
            Assert.Equal(PublicTrialNotAllowed, json.RootElement.GetProperty("errorCode").GetString());
            Assert.Equal(before, await f.RightsSnapshotAsync());
            return;
        }

        Assert.True(outcome.LicenseFile is not null, outcome.Body);
        var validation = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        var community = validation.License!;
        Assert.Equal(HardCodedCommunitySlug, community.TypeSlug);
        Assert.Equal(machine.HardwareId, community.HardwareId);
        Assert.Equal("community", community.Features["tier"]);
        Assert.False(community.Features.ContainsKey("maxLines"));
        Assert.InRange(community.ExpirationDate!.Value, DateTime.UtcNow.AddDays(29), DateTime.UtcNow.AddDays(31));

        await using (var db = f.Db())
        {
            var heldRow = await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == heldId);
            var heldRenewals = await db.LicenseHistories.AsNoTracking()
                .CountAsync(h => h.LicenseId == heldId && h.Action == HistoryActions.Renewed);
            if (held == HeldLicence.ExpiredCommunity)
            {
                Assert.Equal(heldId, community.Id);
                Assert.Equal(1, heldRenewals);
                Assert.Equal(1, await db.Licenses.CountAsync());
            }
            else
            {
                // The held trial or paid plan is not extended: same expiration, no renewal, and a distinct Community row.
                Assert.NotEqual(heldId, community.Id);
                Assert.Equal(expiredAt, heldRow.ExpirationDate);
                Assert.Equal(0, heldRenewals);
                Assert.Equal(2, await db.Licenses.CountAsync());
                Assert.Equal("FREE", (await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == community.Id)).CommercialNature);
            }
        }

        // The next periodic check returns the same Community licence instead of creating another one.
        var again = await f.TrialAsync(HardCodedCommunitySlug, machine);
        Assert.True(again.LicenseFile is not null, again.Body);
        Assert.Equal(community.Id, SdkLicenseService.ValidateLicenseDetailed(again.LicenseFile!, f.PublicKeyXml, machine.HardwareId).License!.Id);
    }

    /// <summary>
    /// (d) Paid types, types of another product, and slug or product-name variants (case, surrounding spaces, control
    /// and invisible characters, look-alike Unicode) never deliver a licence on either public route.
    /// </summary>
    /// <param name="route"><c>trial</c> for <c>POST /api/activation/trial</c>, <c>auto</c> for AUTO-TRIAL.</param>
    /// <param name="slug">Slug or key sent verbatim.</param>
    /// <param name="product">How the product is designated (see <see cref="ProductDesignation"/>).</param>
    /// <param name="canonicalSlug">Stored slug the variant imitates, for the failure report.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData("trial", "syn-pro", "main", PaidSlug)]
    [InlineData("trial", " SYN-PRO ", "main", PaidSlug)]
    [InlineData("trial", "Syn-Pro\t", "main", PaidSlug)]
    [InlineData("trial", "SYN‐PRO", "main", PaidSlug)]
    [InlineData("trial", "SYN-PRO​", "main", PaidSlug)]
    [InlineData("trial", "ＳＹＮ-ＰＲＯ", "main", PaidSlug)]
    [InlineData("trial", "SYN-ELİTE", "main", PaidEliteSlug)]
    [InlineData("trial", "syn-elıte", "main", PaidEliteSlug)]
    [InlineData("trial", "SYN-ELITE", "main", PaidEliteSlug)]
    [InlineData("trial", ForeignCommunitySlug, "main", ForeignCommunitySlug)]
    [InlineData("trial", PaidSlug, "upper", PaidSlug)]
    [InlineData("trial", PaidSlug, "spaces", PaidSlug)]
    [InlineData("trial", PaidSlug, "invisible", PaidSlug)]
    [InlineData("trial", PaidSlug, "dotless", PaidSlug)]
    [InlineData("trial", PaidSlug, "foreign-id", PaidSlug)]
    [InlineData("trial", ForeignCommunitySlug, "main-id-foreign-name", ForeignCommunitySlug)]
    [InlineData("trial", PaidSlug, "foreign", PaidSlug)]
    [InlineData("auto", "syn-pro-free-trial", "main", PaidAutoTrialSlug)]
    [InlineData("auto", " SYN-PRO-FREE-TRIAL ", "main", PaidAutoTrialSlug)]
    [InlineData("auto", "SYN-PRO-FREE-TRİAL", "main", PaidAutoTrialSlug)]
    [InlineData("auto", "SYN-PRO‐FREE-TRIAL", "main", PaidAutoTrialSlug)]
    [InlineData("auto", "FREE-TRIAL", "main", AutoTrialFallbackSlug)]
    [InlineData("auto", ForeignAutoTrialSlug, "main", AutoTrialFallbackSlug)]
    [InlineData("auto", PaidAutoTrialSlug, "upper", PaidAutoTrialSlug)]
    [InlineData("auto", PaidAutoTrialSlug, "foreign", PaidAutoTrialSlug)]
    public async Task Tkt2466_PublicRoutes_VariantsAndForeignTypes_DeliverNothing(string route, string slug, string product, string canonicalSlug)
    {
        await using var f = await Fixture.CreateAsync();
        await SeedVariantCatalogueAsync(f);
        var foreign = await f.AddProductAsync();
        await f.AddTypeAsync(ForeignCommunitySlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true, product: foreign.Id);
        await f.AddTypeAsync(ForeignAutoTrialSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, product: foreign.Id);
        var machine = Machine.Create();
        var (appName, appId) = ProductDesignation(product, f, foreign);

        var outcome = route == "auto"
            ? await f.AutoTrialAsync(slug, machine, appName)
            : await f.TrialAsync(slug, machine, appName: appName, appId: appId);

        await AssertRefusedOrFailWithEvidenceAsync(f, $"variante {route} slug=« {slug} » produit={product}", canonicalSlug, machine, [outcome]);
        Assert.True(outcome.LicenseFile is null, outcome.Body);
        Assert.True((int)outcome.Status < 500, outcome.Body);
        await using var db = f.Db();
        Assert.False(await db.Licenses.AnyAsync());
        Assert.False(await db.LicenseSeats.AnyAsync());
    }

    /// <summary>
    /// Control for the variant matrix: the same catalogue does deliver the foreign product's opted-in type when that
    /// product is named, so the refusals above are decisions, not a broken request. Slug lookup is case-insensitive by
    /// design: a lower-case slug designates the same stored type, and the file carries the stored slug.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_PublicRoutes_VariantControl_ForeignOptedInTypeIsDeliveredUnderItsOwnProduct()
    {
        await using var f = await Fixture.CreateAsync();
        await SeedVariantCatalogueAsync(f);
        var foreign = await f.AddProductAsync();
        await f.AddTypeAsync(ForeignCommunitySlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true, product: foreign.Id);
        var machine = Machine.Create();

        var outcome = await f.TrialAsync(ForeignCommunitySlug.ToLowerInvariant(), machine, appName: foreign.Name);

        Assert.True(outcome.LicenseFile is not null, outcome.Body);
        var validation = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile!, foreign.PublicKeyXml, machine.HardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.Equal(ForeignCommunitySlug, validation.License!.TypeSlug);
        Assert.False(SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile!, f.PublicKeyXml, machine.HardwareId).IsValid);
        await using var db = f.Db();
        Assert.Equal(foreign.Id, (await db.Licenses.AsNoTracking().SingleAsync()).ProductId);
    }

    /// <summary>Main-product catalogue of the variant matrix: every type is closed to public trials.</summary>
    /// <param name="f">Fixture owning the main product.</param>
    private static async Task SeedVariantCatalogueAsync(Fixture f)
    {
        await f.AddTypeAsync(PaidSlug, durationDays: 365, PaidParams);
        await f.AddTypeAsync(PaidEliteSlug, durationDays: 365, PaidParams);
        await f.AddTypeAsync(PaidAutoTrialSlug, durationDays: 365, PaidParams);
        await f.AddTypeAsync(AutoTrialFallbackSlug, durationDays: 30, SiteTrialParams, isFree: true);
    }

    /// <summary>Maps a product designation of the variant matrix to the exact <c>AppName</c> and <c>AppId</c> sent.</summary>
    /// <param name="designation">Designation label.</param>
    /// <param name="f">Fixture owning the main product.</param>
    /// <param name="foreign">Second synthetic product.</param>
    /// <returns>The name and optional identifier sent verbatim.</returns>
    private static (string AppName, string? AppId) ProductDesignation(string designation, Fixture f, SyntheticProduct foreign) => designation switch
    {
        "main" => (f.ProductName, null),
        "upper" => (f.ProductName.ToUpperInvariant(), null),
        "spaces" => ("  " + f.ProductName + " ", null),
        "invisible" => (f.ProductName + "​", null),
        "dotless" => (f.ProductName.Replace('i', 'ı'), null),
        "foreign-id" => (f.ProductName, foreign.Id.ToString("D")),
        "main-id-foreign-name" => (foreign.Name, f.ProductId.ToString("D")),
        "foreign" => (foreign.Name, null),
        _ => throw new ArgumentOutOfRangeException(nameof(designation), designation, null)
    };

    /// <summary>A second synthetic product with its own key pair.</summary>
    /// <param name="Id">Product identifier.</param>
    /// <param name="Name">Product name.</param>
    /// <param name="PublicKeyXml">Product public key.</param>
    private sealed record SyntheticProduct(Guid Id, string Name, string PublicKeyXml);

    /// <summary>Journey helpers of the fixture: administrator issuance, expiry, second product and rights snapshot.</summary>
    private sealed partial class Fixture
    {
        /// <summary>Global administrator secret configured on the in-process host only.</summary>
        private const string AdminSecret = "tkt2466-local-synthetic";

        /// <summary>
        /// Issues one key through <c>POST /api/admin/licenses</c>, the path the website uses for its trial and its paid
        /// plans, with a synthetic commercial subject and provisioning reference.
        /// </summary>
        /// <param name="slug">Type slug of the main product.</param>
        /// <returns>The issued licence key.</returns>
        public async Task<string> AdminCreateLicenseAsync(string slug)
        {
            using var admin = host.CreateClient();
            admin.DefaultRequestHeaders.Add("X-Admin-Secret", AdminSecret);
            using var response = await admin.PostAsJsonAsync("/api/admin/licenses", new
            {
                ProductName, CustomerName = "Synthetic Site Customer", CustomerEmail = "site-customer@example.test",
                TypeSlug = slug, Reference = "TKT2466-SITE-" + Guid.NewGuid().ToString("N"), CommercialSubjectId = Guid.NewGuid()
            });
            var body = await response.Content.ReadAsStringAsync();
            Assert.True(response.StatusCode == HttpStatusCode.OK, body);
            using var json = JsonDocument.Parse(body);
            return json.RootElement.GetProperty("licenseKey").GetString()!;
        }

        /// <summary>Moves one licence one day into the past, at millisecond precision so equality survives PostgreSQL.</summary>
        /// <param name="licenseId">Licence to expire.</param>
        /// <returns>The exact expiration written.</returns>
        public async Task<DateTime> ExpireLicenseAsync(Guid licenseId)
        {
            await using var db = Db();
            var license = await db.Licenses.SingleAsync(l => l.Id == licenseId);
            var expiredAt = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds()).UtcDateTime;
            license.ExpirationDate = expiredAt;
            await db.SaveChangesAsync();
            return expiredAt;
        }

        /// <summary>Adds a second synthetic product with fresh keys, unrelated to the main one.</summary>
        /// <returns>The new product.</returns>
        public async Task<SyntheticProduct> AddProductAsync()
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            using var scope = host.Services.CreateScope();
            var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
            var product = new Product
            {
                Name = ProductName + "_foreign", ApiSecret = "tkt2466-fixture-foreign-product",
                PrivateKeyXml = encryption.Encrypt(rsa.ToXmlString(true)), PublicKeyXml = rsa.ToXmlString(false)
            };
            await using var db = Db();
            db.Products.Add(product);
            await db.SaveChangesAsync();
            return new SyntheticProduct(product.Id, product.Name, product.PublicKeyXml);
        }

        /// <summary>
        /// Serializes every rights row (licences, seats, licence history including decision rows, renewals) in a stable
        /// order, so a refusal can be proven to have written nothing.
        /// </summary>
        /// <returns>A deterministic textual snapshot.</returns>
        public async Task<string> RightsSnapshotAsync()
        {
            await using var db = Db();
            var licenses = await db.Licenses.AsNoTracking().OrderBy(l => l.Id)
                .Select(l => new { l.Id, l.LicenseTypeId, l.HardwareId, l.ExpirationDate, l.IsActive, l.CommercialNature, l.CustomerEmail })
                .ToListAsync();
            var seats = await db.LicenseSeats.AsNoTracking().OrderBy(s => s.Id)
                .Select(s => new { s.Id, s.LicenseId, s.HardwareId, s.IsActive, s.LastCheckInAt })
                .ToListAsync();
            var history = await db.LicenseHistories.AsNoTracking().OrderBy(h => h.Id)
                .Select(h => new { h.Id, h.LicenseId, h.Action })
                .ToListAsync();
            var renewals = await db.LicenseRenewals.AsNoTracking().OrderBy(r => r.Id).Select(r => r.Id).ToListAsync();
            return JsonSerializer.Serialize(new { licenses, seats, history, renewals });
        }
    }
}
