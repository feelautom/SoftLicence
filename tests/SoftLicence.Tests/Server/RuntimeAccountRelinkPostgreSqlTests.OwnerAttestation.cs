using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003753 on PostgreSQL 17: an account relink onto another licence of the same account when no commercial
/// registry owner exists (TEST-PRO, Classroom and older keys). The website, authenticated as the dedicated relink
/// identity, attests with <c>ownerAttestation = website_same_account_v1</c> that the signed-in account owns both
/// licences; SoftLicence decides nothing commercial and applies its usual seat rules. Owner rule: a customer may
/// switch between every key they paid for on one PC as often as they like.
/// </summary>
public sealed partial class RuntimeAccountRelinkPostgreSqlTests
{
    /// <summary>
    /// The installation licence was signed out; the account chooses another licence of the same product with no
    /// registry owner. With the attestation the relink returns 200 onto that licence, records the attestation in the
    /// ledger and the history, and leaves exactly one active seat of the product on the machine.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_NullOwnerAttested_OtherLicenseOfSameAccount_Returns200")]
    public async Task AccountRelink_NullOwnerAttested_OtherLicenseOfSameAccount_Returns200()
    {
        using var scenario = await ActivatedScenarioAsync();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await ReleaseAsync(scenario, "client");
        var (otherLicenseId, _) = await AddLicenseWithSeatAsync(
            scenario, Guid.NewGuid(), OtherCanonicalHardwareId, seatActive: false);

        await RelinkAsync(scenario, await BuildAsync(scenario, otherLicenseId, owner: null,
            ownerAttestation: RuntimeAccountRelinkContract.WebsiteSameAccountAttestation));

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(otherLicenseId, active.LicenseId);
        var seat = await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == active.LicenseSeatId);
        Assert.Equal(LegacyHardwareId, seat.HardwareId);
        Assert.True(seat.IsActive);
        Assert.Equal([otherLicenseId], await ActiveLicencesOnMachineAsync(db, scenario));
        var ledger = await db.RuntimeAccountRelinkRequests.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "COMPLETED");
        Assert.Null(ledger.OwnerSubjectId);
        Assert.Equal(RuntimeAccountRelinkContract.WebsiteSameAccountAttestation, ledger.OwnerAttestation);
        var history = await db.LicenseHistories.AsNoTracking().SingleAsync(row =>
            row.LicenseId == otherLicenseId && row.Action == RuntimeEnrollmentService.AccountRelinkHistoryAction);
        Assert.Contains(RuntimeAccountRelinkContract.WebsiteSameAccountAttestation, history.Details);
        Assert.NotEqual(installationLicenseId, otherLicenseId);
    }

    /// <summary>
    /// Owner sequence on one PC with N = 1 on both licence types: installation licence (Pro), relink to another
    /// licence of the same account (Classroom, attested), sign out, relink back to Pro (its own licence, no owner).
    /// Every step succeeds, nothing is ever refused by the quota, and the machine never holds two active seats.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_ProClassroomPro_SamePc_NeverBlocked")]
    public async Task AccountRelink_ProClassroomPro_SamePc_NeverBlocked()
    {
        using var scenario = await ActivatedScenarioAsync();
        var proLicenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, proLicenseId, 1);
        await ReleaseAsync(scenario, "client");
        var (classroomLicenseId, _) = await AddLicenseWithSeatAsync(
            scenario, Guid.NewGuid(), OtherCanonicalHardwareId, seatActive: false);
        await SetActivationsPerDayAsync(scenario, classroomLicenseId, 1);

        await RelinkAsync(scenario, await BuildAsync(scenario, classroomLicenseId, owner: null,
            ownerAttestation: RuntimeAccountRelinkContract.WebsiteSameAccountAttestation));
        await using (var db = await scenario.Factory.CreateDbContextAsync())
            Assert.Equal([classroomLicenseId], await ActiveLicencesOnMachineAsync(db, scenario));

        await SignOutOnPortalAsync(scenario, classroomLicenseId);
        await RelinkAsync(scenario, await BuildAsync(scenario, proLicenseId, owner: null));

        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal([proLicenseId], await ActiveLicencesOnMachineAsync(check, scenario));
        var active = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(proLicenseId, active.LicenseId);
        Assert.Equal(1, (await SeatChangeQuotaAsync(scenario, proLicenseId)).UsedToday);
        Assert.Equal(1, (await SeatChangeQuotaAsync(scenario, classroomLicenseId)).UsedToday);
    }

    /// <summary>
    /// TKT-001428 (c): after a relink the commercial right moves to the seat of the new licence while the installation
    /// keeps its original <c>LicenseSeatId</c> (its Runtime identity never changes). With the assignment switch
    /// closed, signing out of the new licence from the website must still release that seat: the release finds the
    /// live installation through its ACTIVE right on the seat. It was refused with
    /// <c>seat_release_assignment_without_runtime</c> before the fix. The switch is closed explicitly so the result
    /// never depends on another test of the class having opened it.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_ThenPortalSignOut_ReleasesWithSwitchClosed")]
    public async Task AccountRelink_ThenPortalSignOut_ReleasesWithSwitchClosed()
    {
        using var scenario = await ActivatedScenarioAsync();
        await using (var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await SetAssignmentSwitchAsync(admin, AssignmentEnforcementSetting.Closed);
        await ReleaseAsync(scenario, "client");
        var (classroomLicenseId, _) = await AddLicenseWithSeatAsync(
            scenario, Guid.NewGuid(), OtherCanonicalHardwareId, seatActive: false);
        await RelinkAsync(scenario, await BuildAsync(scenario, classroomLicenseId, owner: null,
            ownerAttestation: RuntimeAccountRelinkContract.WebsiteSameAccountAttestation));
        Guid classroomSeatId;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var right = await db.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
            Assert.Equal(classroomLicenseId, right.LicenseId);
            // The precondition that made the release refuse: the right and the installation name different seats.
            Assert.NotEqual(enrollment.LicenseSeatId, right.LicenseSeatId);
            classroomSeatId = right.LicenseSeatId;
        }

        await SignOutOnPortalAsync(scenario, classroomLicenseId);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.False((await check.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == classroomSeatId)).IsActive);
        Assert.Empty(await check.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.LicenseSeatId == classroomSeatId && row.State == "ACTIVE").ToListAsync());
        await using var switchCheck = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.Empty(await switchCheck.AssignmentEnforcementEvents.AsNoTracking().ToListAsync());
        Assert.Equal(AssignmentEnforcementSetting.Closed,
            (await switchCheck.AssignmentEnforcementSettings.AsNoTracking().SingleAsync()).Mode);
    }

    /// <summary>Licences of the scenario product that hold an active seat on the scenario machine, ordered.</summary>
    /// <param name="db">Caller-owned context.</param>
    /// <param name="scenario">Prepared PostgreSQL scenario.</param>
    /// <returns>Distinct licence identifiers, ordered for an exact comparison.</returns>
    private static async Task<List<Guid>> ActiveLicencesOnMachineAsync(LicenseDbContext db, PreparedBootstrapScenario scenario) =>
        await db.LicenseSeats.AsNoTracking()
            .Where(row => row.HardwareId == LegacyHardwareId && row.IsActive
                && row.License!.ProductId == scenario.Fixture.ProductId)
            .Select(row => row.LicenseId)
            .Distinct()
            .OrderBy(row => row)
            .ToListAsync();

    /// <summary>
    /// Signs the scenario machine out of one licence through the real dashboard release path
    /// (<see cref="PortalDeactivationService"/>, reason <c>settings_button</c>, which bypasses the five-minute guard).
    /// </summary>
    /// <param name="scenario">Prepared PostgreSQL scenario.</param>
    /// <param name="licenseId">Licence whose seat on the machine is released.</param>
    private static async Task SignOutOnPortalAsync(PreparedBootstrapScenario scenario, Guid licenseId)
    {
        var portal = new PortalDeactivationService(
            scenario.Factory, TimeProvider.System, NullLogger<PortalDeactivationService>.Instance);
        var released = await portal.DeactivateAsync(
            "website-step1",
            Sha256("tkt-003753-release-" + Guid.NewGuid().ToString("D")),
            new PortalDeactivationRequest(
                PortalDeactivationService.RequestSchema,
                Guid.NewGuid().ToString("D"),
                scenario.Fixture.ProductId.ToString("D"),
                licenseId.ToString("D"),
                LegacyHardwareId,
                "settings_button"));
        Assert.Equal("deactivated", released.Response.Outcome);
    }
}
