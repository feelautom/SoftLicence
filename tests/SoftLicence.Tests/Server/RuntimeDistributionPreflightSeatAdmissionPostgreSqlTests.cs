using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>Builds an active, already checked-in seat for one licence.</summary>
    /// <param name="licenseId">Owning licence.</param>
    /// <param name="hardwareId">Exact seat identifier.</param>
    /// <returns>An unsaved active seat.</returns>
    protected static LicenseSeat Tkt1720_ActiveSeat(Guid licenseId, string hardwareId) => new()
    {
        LicenseId = licenseId,
        HardwareId = hardwareId,
        IsActive = true,
        FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
        LastCheckInAt = DateTime.UtcNow.AddDays(-1)
    };

    /// <summary>Sets the seat limit of a licence and adds one active seat per supplied identifier.</summary>
    /// <param name="factory">Context factory allowed to write the licence and its seats.</param>
    /// <param name="licenseId">Licence to fill.</param>
    /// <param name="maxSeats">New seat limit.</param>
    /// <param name="hardwareIds">Exact identifiers of the active seats to add.</param>
    protected static async Task Tkt1720_FillLicenseAsync(
        TestDbFactory factory, Guid licenseId, int maxSeats, IReadOnlyList<string> hardwareIds)
    {
        await using var db = await factory.CreateDbContextAsync();
        (await db.Licenses.SingleAsync(row => row.Id == licenseId)).MaxSeats = maxSeats;
        foreach (var hardwareId in hardwareIds)
            db.LicenseSeats.Add(Tkt1720_ActiveSeat(licenseId, hardwareId));
        await db.SaveChangesAsync();
    }

    /// <summary>Derives a deterministic canonical 16-character uppercase hexadecimal identifier.</summary>
    /// <param name="label">Test-local label; distinct labels give distinct machines.</param>
    /// <returns>An identifier accepted by finalize's canonical hardware format.</returns>
    protected static string Tkt1720_HardwareId(string label) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("tkt1720-machine-" + label)))[..16];

    /// <summary>Builds a digest-revalidation preflight that asks for the initial seat-admission prediction.</summary>
    /// <param name="productId">Product of the entitlement.</param>
    /// <param name="licenseId">Licence of the entitlement.</param>
    /// <param name="grantRef">Raw grant reference whose SHA-256 identifies the issued entitlement.</param>
    /// <param name="hardwareId">Identifier finalize will receive; only its digest is sent.</param>
    /// <returns>A closed preflight request with a fresh request identifier.</returns>
    protected static RuntimeDistributionPreflightRequest Tkt1720_DigestPreflightRequest(
        Guid productId, Guid licenseId, string grantRef, string hardwareId) => new()
        {
            Schema = "runtime-distribution-hardware-authority",
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = productId.ToString("D"),
            SoftLicenceLicenseId = licenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(grantRef),
            HardwareIdHash = Sha256(hardwareId),
            SeatAdmission = "initial"
        };
}

/// <summary>Runs the tests from RuntimeDistributionPreflightSeatAdmissionPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeDistributionPreflightSeatAdmissionPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// TKT-001720: the pre-download preflight predicts the seat-capacity refusal of finalize only when
    /// it is certain, and only when the Website asked for it. Every other shape keeps the historical
    /// acceptance and leaves the decision to finalize.
    /// </summary>
    /// <param name = "scenarioName">Closed scenario selector.</param>
    /// <param name = "expectRefusal">Whether the preflight must answer the public seat refusal.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Preflight_PredictsSeatLimitOnlyWhenCertain")]
    [InlineData("full-unknown-machine", true)]
    [InlineData("full-without-request", false)]
    [InlineData("full-machine-holds-active-seat", false)]
    [InlineData("one-free-seat", false)]
    [InlineData("single-seat-licence-full", false)]
    [InlineData("full-new-activations-disabled", false)]
    public async Task Tkt1720_Preflight_PredictsSeatLimitOnlyWhenCertain(string scenarioName, bool expectRefusal)
    {
        const string machine = "TKT1720-NEW-MACHINE";
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        scenario.Request.HardwareIdHash = Sha256(machine);
        scenario.Request.SeatAdmission = scenarioName == "full-without-request" ? null : "initial";
        var maxSeats = scenarioName == "single-seat-licence-full" ? 1 : 3;
        var activeSeats = scenarioName == "one-free-seat" ? 2 : maxSeats;
        await using (var seed = await admin.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == scenario.LicenseId);
            license.MaxSeats = maxSeats;
            if (scenarioName == "full-new-activations-disabled")
                license.Type!.DisableNewActivations = true;
            for (var index = 0; index < activeSeats; index++)
            {
                var holdsThisMachine = scenarioName == "full-machine-holds-active-seat" && index == 0;
                seed.LicenseSeats.Add(new LicenseSeat { LicenseId = scenario.LicenseId, HardwareId = holdsThisMachine ? machine : "TKT1720-OTHER-" + index, IsActive = true, FirstActivatedAt = DateTime.UtcNow.AddDays(-2), LastCheckInAt = DateTime.UtcNow.AddDays(-1) });
            }

            await seed.SaveChangesAsync();
        }

        var service = new RuntimeDistributionPreflightService(app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var digest = Sha256("tkt1720-" + scenarioName);
        await using var verification = await admin.CreateDbContextAsync();
        if (!expectRefusal)
        {
            var accepted = await service.EvaluateAsync("tia-connect-website", digest, scenario.Request, CancellationToken.None);
            Assert.Equal("accepted", accepted.Decision);
            Assert.Equal("accepted", (await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync()).Outcome);
            return;
        }

        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("tia-connect-website", digest, scenario.Request, CancellationToken.None));
        Assert.Equal(StatusCodes.Status403Forbidden, refusal.StatusCode);
        Assert.Equal("seat_limit_reached", refusal.ErrorCode);
        Assert.Null(refusal.ReasonCode);
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal("seat_limit_predicted", decision.ReasonCode);
        // A prediction allocates nothing: the licence keeps exactly its seeded seats.
        Assert.Equal(activeSeats, await verification.LicenseSeats.AsNoTracking().CountAsync(row => row.LicenseId == scenario.LicenseId && row.IsActive));
    }

    /// <summary>TKT-001720: the seat-admission field is a closed contract; any other value is malformed.</summary>
    /// <param name = "value">Non-canonical field value.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Preflight_RejectsNonCanonicalSeatAdmission")]
    [InlineData("Initial")]
    [InlineData("initial ")]
    [InlineData("reinstall")]
    [InlineData("")]
    public async Task Tkt1720_Preflight_RejectsNonCanonicalSeatAdmission(string value)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        scenario.Request.SeatAdmission = value;
        var service = new RuntimeDistributionPreflightService(app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("tia-connect-website", Sha256("tkt1720-invalid-" + value), scenario.Request, CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, refusal.StatusCode);
        Assert.Equal("invalid_request", refusal.ErrorCode);
        await using var verification = await admin.CreateDbContextAsync();
        Assert.False(await verification.RuntimeDistributionHardwareDecisions.AnyAsync());
    }

    /// <summary>
    /// TKT-001720: a signed migration alias of the licence that names the machine, through either digest
    /// column, makes the preflight abstain on a full multi-seat licence even though that machine holds no
    /// active seat. An unrelated machine on the same licence is refused, proving capacity is exhausted.
    /// For the legacy column, the real finalize then accepts by resolving the alias to the active canonical
    /// seat, which is exactly the acceptance a prediction must never pre-empt.
    /// </summary>
    /// <param name = "column">Alias digest column expected to reference the requesting machine.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Preflight_AbstainsWhenLicenceAliasReferencesMachine")]
    [InlineData("legacy-column")]
    [InlineData("canonical-column")]
    public async Task Tkt1720_Preflight_AbstainsWhenLicenceAliasReferencesMachine(string column)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes("tkt1720-alias-subject-" + column)));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);
        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, LegacyHardwareId);
        // The helper forces a one-seat licence; turn it into a full two-seat licence afterwards.
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await seed.Licenses.SingleAsync(row => row.Id == prepared.LicenseId);
            license.MaxSeats = 2;
            var canonicalSeat = await seed.LicenseSeats.SingleAsync(row => row.LicenseId == prepared.LicenseId && row.HardwareId == StableHardwareId);
            Assert.True(canonicalSeat.IsActive);
            if (column == "canonical-column")
            {
                canonicalSeat.IsActive = false;
                canonicalSeat.UnlinkedAt = DateTime.UtcNow.AddMinutes(-5);
            }

            var fillers = column == "canonical-column" ? 2 : 1;
            for (var index = 0; index < fillers; index++)
                seed.LicenseSeats.Add(Tkt1720_ActiveSeat(prepared.LicenseId, Tkt1720_HardwareId("alias-filler-" + column + "-" + index)));
            await seed.SaveChangesAsync();
        }

        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
            Assert.Equal(prepared.LicenseId, alias.LicenseId);
            Assert.Equal(Sha256(LegacyHardwareId), alias.LegacyHardwareIdSha256);
            Assert.Equal(Sha256(StableHardwareId), alias.CanonicalHardwareIdSha256);
            Assert.Equal(2, await check.LicenseSeats.CountAsync(row => row.LicenseId == prepared.LicenseId && row.IsActive));
            Assert.False(await check.LicenseSeats.AnyAsync(row => row.LicenseId == prepared.LicenseId && row.IsActive && row.HardwareId == (column == "legacy-column" ? LegacyHardwareId : StableHardwareId)));
        }

        var service = new RuntimeDistributionPreflightService(scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var control = Tkt1720_DigestPreflightRequest(scenario.Fixture.ProductId, prepared.LicenseId, prepared.Request.GrantRef!, Tkt1720_HardwareId("alias-control-" + column));
        var controlRefusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("website-step1", Sha256("tkt1720-alias-control-" + column), control, CancellationToken.None));
        Assert.Equal("seat_limit_reached", controlRefusal.ErrorCode);
        var machine = column == "legacy-column" ? LegacyHardwareId : StableHardwareId;
        var request = Tkt1720_DigestPreflightRequest(scenario.Fixture.ProductId, prepared.LicenseId, prepared.Request.GrantRef!, machine);
        var accepted = await service.EvaluateAsync("website-step1", Sha256("tkt1720-alias-" + column), request, CancellationToken.None);
        Assert.Equal("accepted", accepted.Decision);
        Assert.Equal(Sha256(machine), accepted.HardwareIdHash);
        if (column != "legacy-column")
            return;
        var finalized = await prepared.Service.FinalizeAsync("website-step1", Sha256("tkt1720-alias-finalize-" + Guid.NewGuid().ToString("D")), prepared.Request);
        Assert.Equal(Sha256(StableHardwareId), finalized.Response.HardwareIdHash);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(2, await verification.LicenseSeats.CountAsync(row => row.LicenseId == prepared.LicenseId && row.IsActive));
    }

    /// <summary>
    /// TKT-001720: in server-derived mode the prediction uses the identifier derived from the submitted
    /// system UUID. A full licence refuses an unknown machine and accepts the machine whose derived
    /// identifier already holds an active seat.
    /// </summary>
    /// <param name = "machineHoldsSeat">Whether the UUID-derived identifier is one of the active seats.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Preflight_ServerDerivedMode_PredictsOnUuidDerivedIdentifier")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt1720_Preflight_ServerDerivedMode_PredictsOnUuidDerivedIdentifier(bool machineHoldsSeat)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        var identity = MachineIdentity.FromUuid(TestSystemUuid);
        Assert.True(identity.IsAccepted);
        var derived = identity.HardwareId!;
        scenario.Request.HardwareIdHash = null;
        scenario.Request.InstallationId = Guid.NewGuid().ToString("D");
        scenario.Request.KeyThumbprint = new string ('A', 43);
        scenario.Request.HardwareEvidence = new RuntimeDistributionHardwareEvidence
        {
            SystemUuid = TestSystemUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680")
        };
        scenario.Request.SeatAdmission = "initial";
        await Tkt1720_FillLicenseAsync(admin, scenario.LicenseId, 3, new[] { machineHoldsSeat ? derived : "TKT1720-OTHER-0", "TKT1720-OTHER-1", "TKT1720-OTHER-2" });
        var service = new RuntimeDistributionPreflightService(app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var digest = Sha256("tkt1720-server-derived-" + machineHoldsSeat);
        await using var verification = await admin.CreateDbContextAsync();
        if (machineHoldsSeat)
        {
            var accepted = await service.EvaluateAsync("tia-connect-website", digest, scenario.Request, CancellationToken.None);
            Assert.Equal("accepted", accepted.Decision);
            Assert.Equal("server-derived", accepted.AuthorityMode);
            Assert.Equal(Sha256(derived), accepted.HardwareIdHash);
            return;
        }

        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("tia-connect-website", digest, scenario.Request, CancellationToken.None));
        Assert.Equal(StatusCodes.Status403Forbidden, refusal.StatusCode);
        Assert.Equal("seat_limit_reached", refusal.ErrorCode);
        Assert.Null(refusal.ReasonCode);
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal("seat_limit_predicted", decision.ReasonCode);
        Assert.Equal("server-derived", decision.AuthorityMode);
        Assert.Equal(3, await verification.LicenseSeats.CountAsync(row => row.LicenseId == scenario.LicenseId && row.IsActive));
    }

    /// <summary>
    /// TKT-001720: a known enrollment is never an initial installation. On a full multi-seat licence the
    /// request with the seat-admission field gets exactly the decision obtained without it.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Preflight_KnownEnrollment_IgnoresSeatAdmissionOnFullLicence")]
    public async Task Tkt1720_Preflight_KnownEnrollment_IgnoresSeatAdmissionOnFullLicence()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: PairMachine.Stable);
        await ActivateCanonicalScenarioAsync(scenario, PairMachine.Stable);
        var(clientId, request) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        request.HardwareEvidence = new RuntimeDistributionHardwareEvidence
        {
            SystemUuid = PairMachine.SystemUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680")
        };
        var licenseId = Guid.Parse(request.SoftLicenceLicenseId!);
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            (await seed.Licenses.SingleAsync(row => row.Id == licenseId)).MaxSeats = 2;
            seed.LicenseSeats.Add(Tkt1720_ActiveSeat(licenseId, Tkt1720_HardwareId("known-filler")));
            await seed.SaveChangesAsync();
            Assert.Equal(2, await seed.LicenseSeats.CountAsync(row => row.LicenseId == licenseId && row.IsActive));
        }

        var service = new RuntimeDistributionPreflightService(scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var withoutField = await service.EvaluateAsync(clientId, Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None);
        request.RequestId = Guid.NewGuid().ToString("D");
        request.SeatAdmission = "initial";
        var withField = await service.EvaluateAsync(clientId, Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None);
        Assert.Equal("accepted", withoutField.Decision);
        Assert.Equal("known-enrollment", withoutField.AuthorityMode);
        Assert.Equal(withoutField.Decision, withField.Decision);
        Assert.Equal(withoutField.HardwareIdHash, withField.HardwareIdHash);
        Assert.Equal(withoutField.AuthorityMode, withField.AuthorityMode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var decisions = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().ToListAsync();
        Assert.Equal(2, decisions.Count);
        Assert.All(decisions, decision => Assert.Equal("accepted", decision.Outcome));
        Assert.Equal(2, await verification.LicenseSeats.CountAsync(row => row.LicenseId == licenseId && row.IsActive));
    }

    /// <summary>
    /// TKT-001720: an earlier refusal keeps its priority. A permanent ban stays a hardware_banned refusal
    /// on a full licence, and an auto-unbannable ban on a paid licence is not lifted by a predicted seat
    /// refusal, because the prediction answers before the auto-unban mutation pass.
    /// </summary>
    /// <param name = "autoUnbannable">Whether the seeded ban category is eligible for paid auto-unban.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Preflight_BanRefusalKeepsPriorityAndPredictionNeverLiftsBan")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt1720_Preflight_BanRefusalKeepsPriorityAndPredictionNeverLiftsBan(bool autoUnbannable)
    {
        const string machine = "TKT1720-BANNED-MACHINE";
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(machine);
        scenario.Request.SeatAdmission = "initial";
        await Tkt1720_FillLicenseAsync(admin, scenario.LicenseId, 3, ["TKT1720-OTHER-0", "TKT1720-OTHER-1", "TKT1720-OTHER-2"]);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, machine, autoUnbannable ? BannedHardwareId.Categories.OutdatedVersion : BannedHardwareId.Categories.Piracy);
        var service = new RuntimeDistributionPreflightService(app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("tia-connect-website", Sha256("tkt1720-ban-" + autoUnbannable), scenario.Request, CancellationToken.None));
        Assert.Equal(StatusCodes.Status403Forbidden, refusal.StatusCode);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal(0, decision.AutoUnbannedCount);
        if (autoUnbannable)
        {
            Assert.Equal("seat_limit_reached", refusal.ErrorCode);
            Assert.Null(refusal.ReasonCode);
            Assert.Equal("seat_limit_predicted", decision.ReasonCode);
        }
        else
        {
            Assert.Equal("hardware_banned", refusal.ReasonCode);
            Assert.Equal("hardware_banned", decision.ReasonCode);
        }

        Assert.True((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }
}
