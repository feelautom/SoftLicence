using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
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
using SdkLicenseService = SoftLicence.SDK.LicenseService;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002466: the anonymous public trial routes (<c>POST /api/activation/trial</c> and the AUTO-TRIAL interception of
/// <c>POST /api/activation</c>) may create or automatically renew a licence only for a type whose
/// <see cref="LicenseType.AllowPublicTrial"/> opt-in is set. These tests first proved the defect (paid and plugin
/// types delivered to anyone) and now pin the closed behaviour end to end.
/// </summary>
/// <remarks>
/// A refusal test that ever receives a licence file fails with the full evidence (SDK signature validation with the
/// synthetic product public key, hardware binding, type, expiration, signed features, persisted commercial nature).
/// Products, slugs and hardware identities are synthetic, except the slug the trial route still hard-codes for its
/// Community renewal (tracked by TKT-001889); nothing contacts a production server. Slug lookup is case-insensitive on
/// the server (SQL <c>UPPER</c> on both sides) and unchanged by this ticket; the new decision reads only a stored
/// boolean. HWIDs are canonical 16-character uppercase hexadecimal and the SDK compares them ordinally.
/// </remarks>
public sealed partial class PublicTrialTypeExposurePostgreSqlTests
{
    /// <summary>Synthetic paid type slug: not free, not anonymous, one year, with signed custom parameters.</summary>
    private const string PaidSlug = "SYN-PRO";
    /// <summary>Synthetic plugin type slug with a zero default duration, as plugin types are configured.</summary>
    private const string PluginSlug = "SYN.PLUGIN.ALPHA";
    /// <summary>Paid type whose slug satisfies the AUTO-TRIAL interception suffix.</summary>
    private const string PaidAutoTrialSlug = "SYN-PRO-FREE-TRIAL";
    /// <summary>Synthetic free trial slug accepted by the AUTO-TRIAL interception.</summary>
    private const string FreeAutoTrialSlug = "SYN-FREE-TRIAL";
    /// <summary>The only slug the trial route renews automatically today (hard-coded, TKT-001889, out of scope).</summary>
    private const string HardCodedCommunitySlug = "YOUR_APP_NAME-COMMUNITY";
    /// <summary>Public refusal code shared with the controller.</summary>
    private const string PublicTrialNotAllowed = SoftLicence.Server.Controllers.ActivationController.PublicTrialNotAllowedCode;

    /// <summary>Signed parameters a client application would apply for the paid tier.</summary>
    private static readonly IReadOnlyDictionary<string, string> PaidParams =
        new Dictionary<string, string>(StringComparer.Ordinal) { ["tier"] = "pro", ["maxLines"] = "50" };
    /// <summary>Signed parameters a client application would apply for the plugin.</summary>
    private static readonly IReadOnlyDictionary<string, string> PluginParams =
        new Dictionary<string, string>(StringComparer.Ordinal) { ["pluginVersion"] = "1.0.0", ["feature.alpha"] = "true" };
    /// <summary>Signed parameters of a legitimate free trial type.</summary>
    private static readonly IReadOnlyDictionary<string, string> TrialParams =
        new Dictionary<string, string>(StringComparer.Ordinal) { ["tier"] = "community" };

    /// <summary>An anonymous trial request for a paid type that is not opted in is refused before any write.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_PublicTrial_PaidType_IsRefused()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(PaidSlug, durationDays: 365, PaidParams);
        var machine = Machine.Create();

        // Lower-case slug on purpose: the server lookup is case-insensitive, so casing is not a barrier.
        var outcome = await f.TrialAsync(PaidSlug.ToLowerInvariant(), machine);

        await AssertRefusedOrFailWithEvidenceAsync(f, "POST /api/activation/trial type payant", PaidSlug, machine, [outcome]);
        await AssertPublicTrialNotAllowedAsync(f, outcome);
    }

    /// <summary>For an opted-in type the remaining barrier is declarative machine evidence supplied by the caller (not attestation).</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_PublicTrial_AllowedType_WithoutMachineEvidence_IsRefusedByMachinePolicy()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 14, TrialParams, isFree: true, allowPublicTrial: true);
        var machine = Machine.Create();

        var outcome = await f.TrialAsync(FreeAutoTrialSlug, machine, includeEvidence: false);

        Assert.Null(outcome.LicenseFile);
        Assert.Contains(VirtualMachinePolicy.EvidenceRequiredCode, outcome.Body, StringComparison.Ordinal);
        await using var db = f.Db();
        Assert.False(await db.Licenses.AnyAsync());
    }

    /// <summary>A zero-duration plugin type is refused by the opt-in before the incidental expired-winner 503 can occur.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_PublicTrial_PluginType_IsRefused()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(PluginSlug, durationDays: 0, PluginParams);
        var machine = Machine.Create();

        var outcome = await f.TrialAsync(PluginSlug, machine);

        await AssertRefusedOrFailWithEvidenceAsync(f, "POST /api/activation/trial type plugin (durée 0)", PluginSlug, machine, [outcome]);
        await AssertPublicTrialNotAllowedAsync(f, outcome);
    }

    /// <summary>Repeated requests (same machine, then another machine) are all refused, with or without single use per hardware.</summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2466_PublicTrial_PaidType_RepeatedRequests_AreRefused(bool enforceSingleUsePerHardwareId)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(PaidSlug, durationDays: 365, PaidParams, enforceSingleUse: enforceSingleUsePerHardwareId);
        var first = Machine.Create();
        var second = Machine.Create();

        var outcomes = new List<CallOutcome>
        {
            await f.TrialAsync(PaidSlug, first) with { Label = "1er appel, machine A" },
            await f.TrialAsync(PaidSlug, first) with { Label = "2e appel, même machine A" },
            await f.TrialAsync(PaidSlug, second) with { Label = "3e appel, machine B", Machine = second }
        };

        await AssertRefusedOrFailWithEvidenceAsync(f,
            $"POST /api/activation/trial répété (EnforceSingleUsePerHardwareId={enforceSingleUsePerHardwareId})",
            PaidSlug, first, outcomes);
        foreach (var outcome in outcomes)
            await AssertPublicTrialNotAllowedAsync(f, outcome);
    }

    /// <summary>DisableNewActivations still refuses a new public trial of an opted-in type on the trial route.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_PublicTrial_DisableNewActivations_IsRefused()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 14, TrialParams, isFree: true, allowPublicTrial: true, disableNewActivations: true);
        var machine = Machine.Create();

        var outcome = await f.TrialAsync(FreeAutoTrialSlug, machine);

        await AssertRefusedOrFailWithEvidenceAsync(f, "POST /api/activation/trial avec DisableNewActivations", FreeAutoTrialSlug, machine, [outcome]);
        Assert.Contains("New activations are no longer available", outcome.Body, StringComparison.Ordinal);
    }

    /// <summary>
    /// AUTO-TRIAL: a licence key equal to a paid slug never issues that type. A key without the <c>-FREE-TRIAL</c>
    /// suffix is not intercepted (unknown key); a paid slug carrying the suffix is refused by the opt-in.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(PaidSlug, false)]
    [InlineData(PaidAutoTrialSlug, true)]
    public async Task Tkt2466_AutoTrial_KeyEqualToPaidSlug_IsRefused(string slug, bool intercepted)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(slug, durationDays: 365, PaidParams);
        var machine = Machine.Create();

        var outcome = await f.AutoTrialAsync(slug, machine);

        await AssertRefusedOrFailWithEvidenceAsync(f, $"POST /api/activation AUTO-TRIAL clé = slug payant {slug}", slug, machine, [outcome]);
        if (intercepted)
            await AssertPublicTrialNotAllowedAsync(f, outcome);
    }

    /// <summary>AUTO-TRIAL refuses a zero-duration plugin type through the opt-in, before any licence row exists.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_AutoTrial_PluginType_IsRefused()
    {
        const string slug = PluginSlug + "-FREE-TRIAL";
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(slug, durationDays: 0, PluginParams);
        var machine = Machine.Create();

        var outcome = await f.AutoTrialAsync(slug, machine);

        await AssertRefusedOrFailWithEvidenceAsync(f, $"POST /api/activation AUTO-TRIAL type plugin {slug}", slug, machine, [outcome]);
        await AssertPublicTrialNotAllowedAsync(f, outcome);
    }

    /// <summary>An opted-in but closed type (DisableNewActivations) is now also refused by AUTO-TRIAL, as by the trial route.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2466_AutoTrial_DisableNewActivations_IsRefused()
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 14, TrialParams, isFree: true, allowPublicTrial: true, disableNewActivations: true);
        var machine = Machine.Create();

        var outcome = await f.AutoTrialAsync(FreeAutoTrialSlug, machine);

        await AssertRefusedOrFailWithEvidenceAsync(f, $"POST /api/activation AUTO-TRIAL type fermé (DisableNewActivations) {FreeAutoTrialSlug}", FreeAutoTrialSlug, machine, [outcome]);
        Assert.Equal(HttpStatusCode.BadRequest, outcome.Status);
        Assert.Contains("New activations are no longer available", outcome.Body, StringComparison.Ordinal);
    }

    /// <summary>An opted-in type is still delivered by both routes, and the file is usable end to end by the SDK.</summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2466_AllowedType_IsDeliveredAndUsable(bool automatic)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 14, TrialParams, isFree: true, allowPublicTrial: true);
        var machine = Machine.Create();

        var outcome = automatic ? await f.AutoTrialAsync(FreeAutoTrialSlug, machine) : await f.TrialAsync(FreeAutoTrialSlug, machine);

        Assert.True(outcome.LicenseFile is not null, outcome.Body);
        var validation = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        var model = validation.License!;
        Assert.Equal(FreeAutoTrialSlug, model.TypeSlug);
        Assert.Equal(machine.HardwareId, model.HardwareId);
        Assert.Equal("community", model.Features["tier"]);
        Assert.InRange(model.ExpirationDate!.Value, DateTime.UtcNow.AddDays(13), DateTime.UtcNow.AddDays(15));
        await using var db = f.Db();
        Assert.Equal("FREE", (await db.Licenses.AsNoTracking().SingleAsync()).CommercialNature);
    }

    /// <summary>
    /// Automatic renewal of an expired recurring licence creates new rights: AUTO-TRIAL renews only when the held type
    /// is opted in. Without it the licence keeps its expiration and no renewal is recorded.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2466_AutoTrial_ExpiredRecurringRenewal_RequiresAllowPublicTrial(bool allowPublicTrial)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
        var machine = Machine.Create();
        Assert.NotNull((await f.AutoTrialAsync(FreeAutoTrialSlug, machine)).LicenseFile);
        var expiredAt = await f.ExpireOnlyLicenseAndSetOptInAsync(FreeAutoTrialSlug, allowPublicTrial);

        var outcome = await f.AutoTrialAsync(FreeAutoTrialSlug, machine);

        await AssertRenewalOutcomeAsync(f, outcome, machine, expiredAt, allowPublicTrial);
    }

    /// <summary>The trial route's Community renewal (slug still hard-coded, TKT-001889) also requires the opt-in on the held type.</summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2466_PublicTrial_ExpiredCommunityRenewal_RequiresAllowPublicTrial(bool allowPublicTrial)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(HardCodedCommunitySlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
        var machine = Machine.Create();
        Assert.NotNull((await f.TrialAsync(HardCodedCommunitySlug, machine)).LicenseFile);
        var expiredAt = await f.ExpireOnlyLicenseAndSetOptInAsync(HardCodedCommunitySlug, allowPublicTrial);

        var outcome = await f.TrialAsync(HardCodedCommunitySlug, machine);

        await AssertRenewalOutcomeAsync(f, outcome, machine, expiredAt, allowPublicTrial);
    }

    /// <summary>Asserts the typed opt-in refusal and that no licence or seat was written.</summary>
    /// <param name="f">Fixture owning the database.</param>
    /// <param name="outcome">Observed call.</param>
    private static async Task AssertPublicTrialNotAllowedAsync(Fixture f, CallOutcome outcome)
    {
        Assert.Equal(HttpStatusCode.OK, outcome.Status);
        Assert.Equal(PublicTrialNotAllowed, outcome.ErrorCodeHeader);
        using var json = JsonDocument.Parse(outcome.Body);
        Assert.False(json.RootElement.GetProperty("isSuccess").GetBoolean());
        Assert.Equal(PublicTrialNotAllowed, json.RootElement.GetProperty("errorCode").GetString());
        await using var db = f.Db();
        Assert.False(await db.Licenses.AnyAsync());
        Assert.False(await db.LicenseSeats.AnyAsync());
    }

    /// <summary>Asserts a renewal (opt-in) or an unchanged expiration without renewal history (no opt-in).</summary>
    /// <param name="f">Fixture owning the key and database.</param>
    /// <param name="outcome">Observed renewal call.</param>
    /// <param name="machine">Machine holding the licence.</param>
    /// <param name="expiredAt">Expiration written before the call.</param>
    /// <param name="renewed">Whether a renewal is expected.</param>
    private static async Task AssertRenewalOutcomeAsync(Fixture f, CallOutcome outcome, Machine machine, DateTime expiredAt, bool renewed)
    {
        await using var db = f.Db();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        var renewals = await db.LicenseHistories.AsNoTracking()
            .CountAsync(h => h.LicenseId == license.Id && h.Action == HistoryActions.Renewed);
        if (renewed)
        {
            Assert.True(outcome.LicenseFile is not null, outcome.Body);
            var validation = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
            Assert.True(validation.IsValid, validation.ErrorMessage);
            Assert.True(license.ExpirationDate > DateTime.UtcNow.AddDays(29));
            Assert.Equal(1, renewals);
        }
        else
        {
            // No new rights: either a refusal or the same expired file, never a valid one.
            if (outcome.LicenseFile is not null)
                Assert.Equal(LicenseValidationErrorCode.Expired,
                    SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile, f.PublicKeyXml, machine.HardwareId).ErrorCode);
            Assert.Equal(expiredAt, license.ExpirationDate);
            Assert.Equal(0, renewals);
        }
    }

    /// <summary>
    /// Passes when no call delivered a licence file. Otherwise validates every delivered file with the SDK and fails
    /// with the full evidence, so the red output itself documents what an attacker obtains.
    /// </summary>
    /// <param name="f">Fixture owning the product public key and the database.</param>
    /// <param name="scenario">Human-readable scenario label for the failure message.</param>
    /// <param name="slug">Requested type slug.</param>
    /// <param name="defaultMachine">Machine of the calls that carry no explicit machine.</param>
    /// <param name="outcomes">Observed calls in order.</param>
    private static async Task AssertRefusedOrFailWithEvidenceAsync(Fixture f, string scenario, string slug,
        Machine defaultMachine, IReadOnlyList<CallOutcome> outcomes)
    {
        if (outcomes.All(outcome => outcome.LicenseFile is null))
            return;

        var report = new StringBuilder();
        report.AppendLine($"FAILLE TKT-002466 PROUVÉE : {scenario}. Type demandé : {slug}.");
        await using var db = f.Db();
        var type = await db.LicenseTypes.AsNoTracking().SingleAsync(t => t.Slug == slug);
        report.AppendLine($"Réglages du type : IsFree={type.IsFree}, AllowAnonymous={type.AllowAnonymous}, DefaultDurationDays={type.DefaultDurationDays}, "
            + $"EnforceSingleUsePerHardwareId={type.EnforceSingleUsePerHardwareId}, DisableNewActivations={type.DisableNewActivations}.");
        var licenseIds = new HashSet<Guid>();
        foreach (var outcome in outcomes)
        {
            var machine = outcome.Machine ?? defaultMachine;
            report.Append($"- {outcome.Label ?? "appel"} : HTTP {(int)outcome.Status}");
            if (outcome.LicenseFile is null)
            {
                report.AppendLine($", refus : {Truncate(outcome.Body)}");
                continue;
            }

            var validation = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile, f.PublicKeyXml, machine.HardwareId);
            var otherMachine = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile, f.PublicKeyXml, Machine.Create().HardwareId);
            var wrongKey = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile, Fixture.ForeignPublicKeyXml, machine.HardwareId);
            var model = validation.License;
            report.AppendLine($", licence signée délivrée.");
            report.AppendLine($"    SDK ValidateLicenseDetailed (clé publique du produit, HWID demandé) : IsValid={validation.IsValid}, ErrorCode={validation.ErrorCode}.");
            report.AppendLine($"    Même fichier sur un autre HWID : {otherMachine.ErrorCode} ; avec une autre clé publique : {wrongKey.ErrorCode}.");
            if (model is not null)
            {
                if (!validation.IsValid)
                {
                    // An expired-at-issuance file was still validly signed at its own creation instant.
                    var atCreation = SdkLicenseService.ValidateLicenseDetailed(outcome.LicenseFile, f.PublicKeyXml, machine.HardwareId, model.CreationDate);
                    report.AppendLine($"    Validation SDK à l'instant de création : IsValid={atCreation.IsValid}, ErrorCode={atCreation.ErrorCode}.");
                }

                licenseIds.Add(model.Id);
                var features = string.Join(", ", model.Features.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}={p.Value}"));
                report.AppendLine($"    Contenu signé : TypeSlug={model.TypeSlug}, HardwareId={model.HardwareId} (demandé {machine.HardwareId}), "
                    + $"CreationDate={model.CreationDate:O}, ExpirationDate={model.ExpirationDate:O}, Features=[{features}], "
                    + $"PluginId={model.PluginId ?? "null"}, LicenseKey={model.LicenseKey}, Id={model.Id}.");
                var row = await db.Licenses.AsNoTracking().SingleOrDefaultAsync(l => l.Id == model.Id);
                report.AppendLine(row is null
                    ? "    Aucune ligne License persistée pour cet Id."
                    : $"    Ligne persistée : CommercialNature={row.CommercialNature}, IsActive={row.IsActive}, CustomerEmail={row.CustomerEmail}, HardwareId={row.HardwareId}.");
            }
        }

        report.AppendLine($"Licences distinctes délivrées : {licenseIds.Count} ; lignes License en base : {await db.Licenses.CountAsync()}.");
        Assert.Fail(report.ToString());
    }

    /// <summary>Bounds a refusal body in the failure message.</summary>
    private static string Truncate(string value) => value.Length <= 300 ? value : value[..300] + "…";

    /// <summary>One observed HTTP call: status, raw body and the extracted signed licence, if any.</summary>
    private sealed record CallOutcome(HttpStatusCode Status, string Body, string? LicenseFile, string? ErrorCodeHeader = null)
    {
        /// <summary>Optional scenario label.</summary>
        public string? Label { get; init; }
        /// <summary>Machine used for this call when different from the scenario default.</summary>
        public Machine? Machine { get; init; }
    }

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

    /// <summary>Owns one cloned PostgreSQL database, one synthetic product with in-memory RSA keys and one in-process host.</summary>
    private sealed partial class Fixture : IAsyncDisposable
    {
        /// <summary>Public key of an unrelated key pair, used to prove the signature is product-specific.</summary>
        public static readonly string ForeignPublicKeyXml = CreateForeignPublicKey();
        /// <summary>Loopback maintenance connection supplied by the disposable container runner.</summary>
        private readonly string maintenance;
        /// <summary>Generated database name, also used as the synthetic product name.</summary>
        private readonly string database;
        /// <summary>Isolated connection shared by HTTP and assertion contexts.</summary>
        private readonly string connection;
        /// <summary>In-process host; hosted workers are removed so nothing is sent outside.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Synthetic product identifier.</summary>
        private Guid productId;
        /// <summary>Synthetic product identifier, for scope assertions.</summary>
        public Guid ProductId => productId;
        /// <summary>Anonymous client: no admin secret, as an attacker would call.</summary>
        public HttpClient Client { get; }
        /// <summary>Synthetic product name.</summary>
        public string ProductName => database;
        /// <summary>Product public key a client application would embed.</summary>
        public string PublicKeyXml { get; private set; } = string.Empty;

        /// <summary>Builds the host with test-owned database registrations and no hosted service.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance; this.database = database; this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", "tkt2466-local-synthetic");
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

        /// <summary>Adds one license type with its signed custom parameters to the synthetic product.</summary>
        /// <param name="slug">Exact stored slug.</param>
        /// <param name="durationDays">Default duration of a new licence of this type.</param>
        /// <param name="parameters">Signed custom parameters.</param>
        /// <param name="isFree">Free flag of the type.</param>
        /// <param name="enforceSingleUse">Single use per hardware.</param>
        /// <param name="disableNewActivations">Closure switch for new activations.</param>
        /// <param name="allowPublicTrial">Public trial opt-in (TKT-002466).</param>
        /// <param name="isRecurring">Recurring flag (automatic renewal candidate).</param>
        /// <param name="product">Owning product; the main synthetic product when omitted.</param>
        /// <returns>The new type identifier.</returns>
        public async Task<Guid> AddTypeAsync(string slug, int durationDays, IReadOnlyDictionary<string, string> parameters,
            bool isFree = false, bool enforceSingleUse = false, bool disableNewActivations = false,
            bool allowPublicTrial = false, bool isRecurring = false, Guid? product = null)
        {
            await using var db = Db();
            var type = new LicenseType
            {
                ProductId = product ?? productId, Name = "Synthetic " + slug, Slug = slug, DefaultDurationDays = durationDays,
                DefaultMaxSeats = 1, IsFree = isFree, AllowAnonymous = false,
                EnforceSingleUsePerHardwareId = enforceSingleUse, DisableNewActivations = disableNewActivations,
                AllowPublicTrial = allowPublicTrial, IsRecurring = isRecurring
            };
            foreach (var pair in parameters)
                type.CustomParams.Add(new LicenseTypeCustomParam { Key = pair.Key, Name = pair.Key, Value = pair.Value });
            db.LicenseTypes.Add(type);
            await db.SaveChangesAsync();
            return type.Id;
        }

        /// <summary>Sets the public trial opt-in of one type of the synthetic product.</summary>
        /// <param name="slug">Exact stored slug.</param>
        /// <param name="allowPublicTrial">New opt-in value.</param>
        public async Task SetOptInAsync(string slug, bool allowPublicTrial)
        {
            await using var db = Db();
            var type = await db.LicenseTypes.SingleAsync(t => t.ProductId == productId && t.Slug == slug);
            type.AllowPublicTrial = allowPublicTrial;
            await db.SaveChangesAsync();
        }

        /// <summary>Moves the only licence one day into the past, then sets the opt-in of its type.</summary>
        /// <param name="slug">Exact stored slug of the licence type.</param>
        /// <param name="allowPublicTrial">Opt-in value for the renewal call.</param>
        /// <returns>The exact expiration written, for unchanged-expiration assertions.</returns>
        public async Task<DateTime> ExpireOnlyLicenseAndSetOptInAsync(string slug, bool allowPublicTrial)
        {
            await using (var db = Db())
            {
                var license = await db.Licenses.SingleAsync();
                var expiredAt = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds()).UtcDateTime;
                license.ExpirationDate = expiredAt;
                await db.SaveChangesAsync();
                await SetOptInAsync(slug, allowPublicTrial);
                return expiredAt;
            }
        }

        /// <summary>Anonymous <c>POST /api/activation/trial</c> with declarative physical-machine evidence.</summary>
        /// <param name="slug">Requested type slug, sent verbatim.</param>
        /// <param name="machine">Calling machine.</param>
        /// <param name="includeEvidence">Whether physical-machine evidence is declared.</param>
        /// <param name="appName">Product name sent verbatim; the main synthetic product when omitted.</param>
        /// <param name="appId">Optional product identifier, which the server resolves before the name.</param>
        public async Task<CallOutcome> TrialAsync(string slug, Machine machine, bool includeEvidence = true,
            string? appName = null, string? appId = null)
        {
            using var response = await Client.PostAsJsonAsync("/api/activation/trial", new
            {
                AppName = appName ?? ProductName, AppId = appId, TypeSlug = slug, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
                AppVersion = "1.0.0",
                MachineEvidence = includeEvidence ? PhysicalEvidence() : (JsonElement?)null
            });
            return await ReadAsync(response);
        }

        /// <summary>Anonymous <c>POST /api/activation</c>: AUTO-TRIAL when the key is a type slug, otherwise a normal key activation.</summary>
        /// <param name="key">Licence key sent verbatim.</param>
        /// <param name="machine">Calling machine.</param>
        /// <param name="appName">Product name sent verbatim; the main synthetic product when omitted.</param>
        public async Task<CallOutcome> AutoTrialAsync(string key, Machine machine, string? appName = null)
        {
            using var response = await Client.PostAsJsonAsync("/api/activation", new
            {
                AppName = appName ?? ProductName, LicenseKey = key, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
                AppVersion = "1.0.0", MachineEvidence = PhysicalEvidence()
            });
            return await ReadAsync(response);
        }

        /// <summary>Extracts the signed licence when the body is a success object carrying <c>licenseFile</c>.</summary>
        private static async Task<CallOutcome> ReadAsync(HttpResponseMessage response)
        {
            var body = await response.Content.ReadAsStringAsync();
            // A rate-limited call proves nothing about the licence decision: it must never count as a refusal.
            Assert.True(response.StatusCode != HttpStatusCode.TooManyRequests,
                "Appel limité en débit (429) : le test ne prouve rien, réduire le nombre d'appels publics par cas.");
            string? file = null;
            try
            {
                using var json = JsonDocument.Parse(body);
                if (json.RootElement.ValueKind == JsonValueKind.Object
                    && json.RootElement.TryGetProperty("licenseFile", out var value)
                    && value.ValueKind == JsonValueKind.String)
                    file = value.GetString();
            }
            catch (JsonException)
            {
                // Plain-text refusals carry no licence.
            }
            var errorCode = response.Headers.TryGetValues("X-SoftLicence-Error-Code", out var values) ? values.SingleOrDefault() : null;
            return new CallOutcome(response.StatusCode, body, file, errorCode);
        }

        /// <summary>SDK-shaped declarative evidence of a physical computer; the server cannot verify it.</summary>
        private static JsonElement PhysicalEvidence() => JsonSerializer.SerializeToElement(new
        {
            SystemManufacturer = new { Status = "Present", Values = new[] { "Dell Inc." }, Error = (string?)null },
            SystemModel = new { Status = "Present", Values = new[] { "Precision 7680" }, Error = (string?)null }
        });

        /// <summary>Generates an unrelated public key.</summary>
        private static string CreateForeignPublicKey()
        {
            using var rsa = RSA.Create(2048);
            return rsa.ToXmlString(false);
        }

        /// <summary>Clones the current-schema model database and seeds one synthetic product with fresh keys.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("public_trial");
            var fixture = new Fixture(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                using var rsa = RSA.Create(2048);
                using var scope = fixture.host.Services.CreateScope();
                var product = new Product
                {
                    Name = clone.DatabaseName, ApiSecret = "tkt2466-fixture-product",
                    PrivateKeyXml = scope.ServiceProvider.GetRequiredService<EncryptionService>().Encrypt(rsa.ToXmlString(true)),
                    PublicKeyXml = rsa.ToXmlString(false)
                };
                db.Products.Add(product);
                await db.SaveChangesAsync();
                fixture.productId = product.Id;
                fixture.PublicKeyXml = product.PublicKeyXml;
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
