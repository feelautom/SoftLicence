using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Xunit;
using SdkLicenseService = SoftLicence.SDK.LicenseService;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002468 (audit finding C5): the anonymous public trial routes must never hand a licence the hardware already
/// holds to someone who only knows that hardware identifier, unless the licence is of the requested type, that type is
/// opted in to public trials and the licence is not of a paid commercial nature. The routes never overwrite the stored
/// customer e-mail or name, and an expired licence that cannot be renewed is refused explicitly.
/// </summary>
/// <remarks>
/// The attacker request carries only the product name, an opted-in slug and the victim HWID, plus another e-mail and
/// name: no system UUID and no machine evidence. A request that declares evidence without a valid UUID is refused by
/// the machine-identity rule (TKT-001277) before any licence decision, so the realistic attacker sends neither. The
/// return case replays the legitimate machine's own identity with foreign customer data, as a compromised client or
/// mistyped form would. HWIDs are canonical 16-character uppercase hexadecimal; the server compares them exactly in
/// SQL and the type decision compares type identifiers, so no string normalization is involved in the new checks.
/// "No write" is asserted on the rights tables through <see cref="Fixture.RightsSnapshotAsync"/>.
/// </remarks>
public sealed partial class PublicTrialTypeExposurePostgreSqlTests
{
    /// <summary>Public refusal code when the hardware holds a licence the anonymous route must not return.</summary>
    private const string HardwareAlreadyLicensed = SoftLicence.Server.Controllers.ActivationController.HardwareAlreadyLicensedCode;
    /// <summary>Public refusal code when the held licence of the requested type has expired and cannot be renewed.</summary>
    private const string LicenceExpired = SoftLicence.Server.Controllers.ActivationController.PublicTrialLicenceExpiredCode;
    /// <summary>E-mail an attacker sends to take the licence over.</summary>
    private const string AttackerEmail = "autre@exemple.test";
    /// <summary>Name an attacker sends.</summary>
    private const string AttackerName = "Inconnu";

    /// <summary>
    /// Case 1: a paid licence activated by key on a machine is neither returned nor modified when someone asks either
    /// public route for an opted-in type with that machine's HWID and another e-mail. The victim's seat stays active.
    /// </summary>
    /// <param name="automatic">True for AUTO-TRIAL, false for <c>POST /api/activation/trial</c>.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2468_PaidLicenceOnKnownHwid_IsNeitherReturnedNorModified(bool automatic)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
        await f.AddTypeAsync(PaidSlug, durationDays: 365, PaidParams, isRecurring: true);
        var victim = Machine.Create();
        var key = await f.AdminCreateLicenseAsync(PaidSlug);
        Assert.True((await f.AutoTrialAsync(key, victim)).LicenseFile is not null);
        var before = await f.RightsSnapshotAsync();
        var nameBefore = await f.OnlyLicenceNameAsync();

        var outcome = await f.AttackerAsync(automatic, FreeAutoTrialSlug, victim.HardwareId);

        AssertTypedRefusal(outcome, HardwareAlreadyLicensed);
        Assert.DoesNotContain(key, outcome.Body, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before, await f.RightsSnapshotAsync());
        Assert.Equal(nameBefore, await f.OnlyLicenceNameAsync());
        await using var db = f.Db();
        var seat = await db.LicenseSeats.AsNoTracking().SingleAsync();
        Assert.True(seat.IsActive);
        Assert.Equal(victim.HardwareId, seat.HardwareId);
    }

    /// <summary>
    /// Case 3: a still-valid licence of the requested opted-in type is returned, but the request's e-mail and name
    /// never replace the stored ones, neither in the database nor in the signed file. The caller is the machine that
    /// holds the licence, with its own UUID and evidence, submitting foreign customer data like a compromised client.
    /// </summary>
    /// <param name="automatic">True for AUTO-TRIAL, false for <c>POST /api/activation/trial</c>.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2468_OpenTypeHeldLicence_IsReturnedWithoutCustomerOverwrite(bool automatic)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true);
        var machine = Machine.Create();
        var first = automatic ? await f.AutoTrialAsync(FreeAutoTrialSlug, machine) : await f.TrialAsync(FreeAutoTrialSlug, machine);
        Assert.True(first.LicenseFile is not null, first.Body);
        string emailBefore;
        await using (var db = f.Db()) emailBefore = (await db.Licenses.AsNoTracking().SingleAsync()).CustomerEmail;
        var nameBefore = await f.OnlyLicenceNameAsync();

        var again = await f.RecoveryWithForeignCustomerAsync(automatic, FreeAutoTrialSlug, machine);

        Assert.True(again.LicenseFile is not null, again.Body);
        var validation = SdkLicenseService.ValidateLicenseDetailed(again.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.Equal(emailBefore, validation.License!.CustomerEmail);
        Assert.Equal(nameBefore, validation.License.CustomerName);
        await using var after = f.Db();
        var row = await after.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(emailBefore, row.CustomerEmail);
        Assert.Equal(nameBefore, row.CustomerName);
    }

    /// <summary>
    /// Q1: a licence of the requested opted-in type whose commercial nature is paid (PAID or PAID_TRIAL) is never
    /// returned by an anonymous route; UNKNOWN stays returnable because the website issues Community keys without
    /// commercial evidence.
    /// </summary>
    /// <param name="automatic">True for AUTO-TRIAL, false for <c>POST /api/activation/trial</c>.</param>
    /// <param name="nature">Stored commercial nature of the held licence.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false, "PAID")]
    [InlineData(true, "PAID")]
    [InlineData(false, "PAID_TRIAL")]
    [InlineData(true, "PAID_TRIAL")]
    public async Task Tkt2468_PaidNatureOnOpenType_IsNotReturned(bool automatic, string nature)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true);
        var machine = Machine.Create();
        Assert.True((await f.TrialAsync(FreeAutoTrialSlug, machine)).LicenseFile is not null);
        await using (var db = f.Db())
        {
            var license = await db.Licenses.SingleAsync();
            license.CommercialNature = nature;
            await db.SaveChangesAsync();
        }
        var before = await f.RightsSnapshotAsync();

        var outcome = await f.AttackerAsync(automatic, FreeAutoTrialSlug, machine.HardwareId);

        AssertTypedRefusal(outcome, HardwareAlreadyLicensed);
        Assert.Equal(before, await f.RightsSnapshotAsync());
    }

    /// <summary>
    /// Case 5: an expired licence of the requested opted-in type that the route cannot renew is refused with an
    /// explicit LICENSE_EXPIRED code (previously an accidental 503) and nothing is written. The trial route renews only
    /// its hard-coded Community slug (TKT-001889); AUTO-TRIAL renews only recurring types, so a fixed-term type is used.
    /// </summary>
    /// <param name="automatic">True for AUTO-TRIAL, false for <c>POST /api/activation/trial</c>.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2468_ExpiredNonRenewableHeldLicence_IsRefusedExplicitly(bool automatic)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: !automatic);
        var machine = Machine.Create();
        var first = automatic ? await f.AutoTrialAsync(FreeAutoTrialSlug, machine) : await f.TrialAsync(FreeAutoTrialSlug, machine);
        Assert.True(first.LicenseFile is not null, first.Body);
        var expiredAt = await f.ExpireOnlyLicenseAndSetOptInAsync(FreeAutoTrialSlug, allowPublicTrial: true);
        var before = await f.RightsSnapshotAsync();

        var outcome = automatic ? await f.AutoTrialAsync(FreeAutoTrialSlug, machine) : await f.TrialAsync(FreeAutoTrialSlug, machine);

        AssertTypedRefusal(outcome, LicenceExpired);
        Assert.Equal(before, await f.RightsSnapshotAsync());
        await using var db = f.Db();
        Assert.Equal(expiredAt, (await db.Licenses.AsNoTracking().SingleAsync()).ExpirationDate);
    }

    /// <summary>
    /// Case 2: once its type is closed to public trials, a held licence is no longer returned by an anonymous route;
    /// the typed opt-in refusal comes first and nothing is written. (TKT-002466 kept this recovery; TKT-002468 closes it.)
    /// </summary>
    /// <param name="automatic">True for AUTO-TRIAL, false for <c>POST /api/activation/trial</c>.</param>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt2468_HeldLicenceOfClosedType_IsNotReturned(bool automatic)
    {
        await using var f = await Fixture.CreateAsync();
        await f.AddTypeAsync(FreeAutoTrialSlug, durationDays: 14, TrialParams, isFree: true, allowPublicTrial: true);
        var machine = Machine.Create();
        var first = automatic ? await f.AutoTrialAsync(FreeAutoTrialSlug, machine) : await f.TrialAsync(FreeAutoTrialSlug, machine);
        Assert.True(first.LicenseFile is not null, first.Body);
        await f.SetOptInAsync(FreeAutoTrialSlug, allowPublicTrial: false);
        var before = await f.RightsSnapshotAsync();

        var again = automatic ? await f.AutoTrialAsync(FreeAutoTrialSlug, machine) : await f.TrialAsync(FreeAutoTrialSlug, machine);

        AssertTypedRefusal(again, PublicTrialNotAllowed);
        Assert.Equal(before, await f.RightsSnapshotAsync());
    }

    /// <summary>Asserts a typed JSON refusal (HTTP 200, isSuccess=false, error header and body code) without any licence file.</summary>
    /// <param name="outcome">Observed call.</param>
    /// <param name="code">Expected public error code.</param>
    private static void AssertTypedRefusal(CallOutcome outcome, string code)
    {
        Assert.True(outcome.LicenseFile is null, "Licence délivrée alors qu'un refus était attendu : " + Truncate(outcome.Body));
        Assert.True(outcome.Status == HttpStatusCode.OK, $"HTTP {(int)outcome.Status} : {Truncate(outcome.Body)}");
        Assert.Equal(code, outcome.ErrorCodeHeader);
        using var json = JsonDocument.Parse(outcome.Body);
        Assert.False(json.RootElement.GetProperty("isSuccess").GetBoolean());
        Assert.Equal(code, json.RootElement.GetProperty("errorCode").GetString());
    }

    /// <summary>Attacker helpers: requests built from a bare HWID with foreign customer data.</summary>
    private sealed partial class Fixture
    {
        /// <summary>
        /// Sends what someone who only knows a HWID can send: product name, an opted-in slug (or AUTO-TRIAL key), the
        /// HWID, another e-mail and name. No system UUID and no machine evidence: since TKT-001277 a request carrying
        /// evidence without a valid UUID is refused before any licence decision, so the bare request is the strongest
        /// realistic attacker.
        /// </summary>
        /// <param name="automatic">True for AUTO-TRIAL, false for the trial route.</param>
        /// <param name="slug">Requested slug, or AUTO-TRIAL key.</param>
        /// <param name="hardwareId">The victim's HWID.</param>
        public async Task<CallOutcome> AttackerAsync(bool automatic, string slug, string hardwareId)
        {
            using var response = automatic
                ? await Client.PostAsJsonAsync("/api/activation", new
                {
                    AppName = ProductName, LicenseKey = slug, HardwareId = hardwareId, AppVersion = "1.0.0",
                    CustomerEmail = AttackerEmail, CustomerName = AttackerName
                })
                : await Client.PostAsJsonAsync("/api/activation/trial", new
                {
                    AppName = ProductName, TypeSlug = slug, HardwareId = hardwareId, AppVersion = "1.0.0",
                    CustomerEmail = AttackerEmail, CustomerName = AttackerName
                });
            return await ReadAsync(response);
        }

        /// <summary>
        /// Replays the machine that holds the licence, with its own system UUID and physical evidence, submitting
        /// foreign customer e-mail and name: the recovery path of a client that sends customer data.
        /// </summary>
        /// <param name="automatic">True for AUTO-TRIAL, false for the trial route.</param>
        /// <param name="slug">Requested slug, or AUTO-TRIAL key.</param>
        /// <param name="machine">The machine that holds the licence.</param>
        public async Task<CallOutcome> RecoveryWithForeignCustomerAsync(bool automatic, string slug, Machine machine)
        {
            using var response = automatic
                ? await Client.PostAsJsonAsync("/api/activation", new
                {
                    AppName = ProductName, LicenseKey = slug, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
                    AppVersion = "1.0.0", CustomerEmail = AttackerEmail, CustomerName = AttackerName, MachineEvidence = PhysicalEvidence()
                })
                : await Client.PostAsJsonAsync("/api/activation/trial", new
                {
                    AppName = ProductName, TypeSlug = slug, HardwareId = machine.HardwareId, SystemUuid = machine.SystemUuid,
                    AppVersion = "1.0.0", CustomerEmail = AttackerEmail, CustomerName = AttackerName, MachineEvidence = PhysicalEvidence()
                });
            return await ReadAsync(response);
        }

        /// <summary>Reads the stored customer name of the only licence (the rights snapshot does not include it).</summary>
        public async Task<string> OnlyLicenceNameAsync()
        {
            await using var db = Db();
            return (await db.Licenses.AsNoTracking().SingleAsync()).CustomerName;
        }
    }
}
