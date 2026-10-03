using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001277 lot 2d: the open position of the assignment switch. The rest of this suite runs with the switch
/// closed and proves the original blocking behaviour; these tests open it and prove that each would-be block is
/// recorded and the operation passes, with the right produced as if the operation were valid.
/// </summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Case 1 (diverging enrollment copy): recorded, write passes, the binding keeps the single right.</summary>
    [Fact]
    public async Task AssignmentSwitchOpen_DivergingEnrollment_IsRecordedAndPasses()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Open);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"InstallationId\" = {Guid.NewGuid().ToString("D")} WHERE \"Id\" = {scenario.EnrollmentId}");

        db.ChangeTracker.Clear();
        Assert.Single(await db.EnrollmentLicenseAssignments.Where(row => row.State == "ACTIVE").ToListAsync());
        Assert.Empty(await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
        var recorded = Assert.Single(await db.AssignmentEnforcementEvents.ToListAsync());
        Assert.Equal("database", recorded.Source);
        Assert.Equal("assignment_trigger", recorded.Control);
        Assert.Equal(1, recorded.CaseNumber);
        Assert.Equal("binding_mismatch", recorded.Reason);
        Assert.Equal("granted_from_binding", recorded.Action);
        Assert.Equal(scenario.EnrollmentId, recorded.EnrollmentId);
    }

    /// <summary>Case 6 (competing live claimant): recorded, write passes, the latest claimant takes the seat.</summary>
    [Fact]
    public async Task AssignmentSwitchOpen_CompetingClaimant_TakesTheSeatAndIsRecorded()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Open);
        var original = await db.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync();
        var secondBindingId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();

        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            await StageSecondClaimantAsync(db, scenario, secondBindingId, secondEnrollmentId);
            await transaction.CommitAsync();
        }

        db.ChangeTracker.Clear();
        var rights = await db.EnrollmentLicenseAssignments.AsNoTracking().ToListAsync();
        var active = Assert.Single(rights, row => row.State == "ACTIVE");
        Assert.Equal(secondEnrollmentId, active.EnrollmentId);
        Assert.Equal(original.LicenseSeatId, active.LicenseSeatId);
        var superseded = Assert.Single(rights, row => row.Id == original.Id);
        Assert.Equal("ENDED", superseded.State);
        Assert.Equal("fail_open_superseded", superseded.EndReason);
        Assert.Contains(await db.AssignmentEnforcementEvents.ToListAsync(), row =>
            row.CaseNumber == 6 && row.Reason == "live_seat_ambiguous"
            && row.Action == "seat_taken_by_latest_claimant" && row.EnrollmentId == secondEnrollmentId);
    }

    /// <summary>Case 6 with the switch closed keeps the original retryable refusal and leaves nothing.</summary>
    [Fact]
    public async Task AssignmentSwitchClosed_CompetingClaimant_KeepsOriginalRefusal()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Closed);

        await using var transaction = await db.Database.BeginTransactionAsync();
        await StageSecondClaimantAsync(db, scenario, Guid.NewGuid(), Guid.NewGuid());
        var conflict = await Assert.ThrowsAsync<PostgresException>(() => transaction.CommitAsync());

        Assert.Equal(PostgresErrorCodes.SerializationFailure, conflict.SqlState);
        Assert.Equal("concurrent commercial seat claimant", conflict.MessageText);
        db.ChangeTracker.Clear();
        Assert.Empty(await db.AssignmentEnforcementEvents.ToListAsync());
    }

    /// <summary>Case 8 (unexpected error): recorded with SQLSTATE and message, write passes, no partial change.</summary>
    [Fact]
    public async Task AssignmentSwitchOpen_UnexpectedError_IsRecordedWithoutPartialChange()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Open);
        await InstallFailingAssignmentWriteAsync(db);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {DateTime.UtcNow}, \"InvalidationReason\" = 'case8_probe' WHERE \"Id\" = {scenario.EnrollmentId}");

        db.ChangeTracker.Clear();
        Assert.Equal("INVALIDATED", (await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.Equal("ACTIVE", (await db.EnrollmentLicenseAssignments.SingleAsync()).State);
        var recorded = Assert.Single(await db.AssignmentEnforcementEvents.ToListAsync());
        Assert.Equal(8, recorded.CaseNumber);
        Assert.Equal("unexpected_error", recorded.Reason);
        Assert.Contains("sqlstate=P0001", recorded.Detail, StringComparison.Ordinal);
        Assert.Contains("simulated assignment failure", recorded.Detail, StringComparison.Ordinal);
    }

    /// <summary>Case 8 with the switch closed re-raises the original error unchanged.</summary>
    [Fact]
    public async Task AssignmentSwitchClosed_UnexpectedError_IsRaisedUnchanged()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Closed);
        await InstallFailingAssignmentWriteAsync(db);

        var failure = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {DateTime.UtcNow}, \"InvalidationReason\" = 'case8_probe' WHERE \"Id\" = {scenario.EnrollmentId}"));

        Assert.Equal("P0001", failure.SqlState);
        Assert.Equal("simulated assignment failure", failure.MessageText);
    }

    /// <summary>Seat release with a missing right: open records and releases, closed keeps the original 503.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AssignmentSwitch_SeatReleaseWithoutRight_FollowsTheSwitch(bool open)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var right = await admin.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync();
        await admin.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM public.\"EnrollmentLicenseAssignments\" WHERE \"Id\" = {right.Id}");
        await SetAssignmentSwitchAsync(admin, open ? AssignmentEnforcementSetting.Open : AssignmentEnforcementSetting.Closed);

        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db);
        var license = await db.Licenses.SingleAsync(row => row.Id == right.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == right.LicenseSeatId);

        if (!open)
        {
            var refused = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                SeatRuntimeReleaseAuthority.PrepareAsync(db, license.ProductId, license, [seat], DateTime.UtcNow));
            Assert.Equal("seat_release_assignment_missing", refused.ReasonCode);
            return;
        }

        var scope = await SeatRuntimeReleaseAuthority.PrepareAsync(db, license.ProductId, license, [seat], DateTime.UtcNow);
        Assert.Empty(scope.Assignments);
        seat.IsActive = false;
        seat.UnlinkedAt = scope.ObservedAtUtc;
        await SeatRuntimeReleaseAuthority.CompleteAsync(db, scope, [seat]);
        await transaction!.CommitAsync();

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == seat.Id)).IsActive);
        Assert.Contains(await check.AssignmentEnforcementEvents.ToListAsync(), row =>
            row.Source == "application" && row.Control == "seat_release"
            && row.Reason == "seat_release_assignment_missing" && row.LicenseSeatId == seat.Id);
    }

    /// <summary>Writes the switch value directly, as the startup synchronizer does.</summary>
    private static Task SetAssignmentSwitchAsync(LicenseDbContext db, string mode) =>
        db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"AssignmentEnforcementSettings\" SET \"Mode\" = {mode}, \"UpdatedBy\" = 'test' WHERE \"Id\" = 1");

    /// <summary>Makes every assignment write fail, to exercise the unexpected-error branch.</summary>
    private static Task InstallFailingAssignmentWriteAsync(LicenseDbContext db) =>
        db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION public.tkt001277_fail_assignment_write() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated assignment failure'; END $$;
            CREATE TRIGGER tkt001277_fail_assignment_write
            BEFORE INSERT OR UPDATE ON public."EnrollmentLicenseAssignments"
            FOR EACH ROW EXECUTE FUNCTION public.tkt001277_fail_assignment_write();
            """);

    /// <summary>Stages a second live binding and enrollment on the scenario seat, as Codex's competing-claim test.</summary>
    private static Task StageSecondClaimantAsync(
        LicenseDbContext db, PreparedBootstrapScenario scenario, Guid secondBindingId, Guid secondEnrollmentId) =>
        db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DistributionInstallationBindings"
            SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                to_jsonb(binding) || jsonb_build_object(
                    'Id', {secondBindingId.ToString("D")},
                    'GrantRef', {Guid.NewGuid().ToString("D")},
                    'GrantRefDigestSha256', {new string('b', 64)},
                    'HandoffDigestSha256', {new string('c', 64)},
                    'HardwareIdHash', {new string('d', 64)},
                    'InstallationId', {Guid.NewGuid().ToString("D")}))).*
            FROM public."DistributionInstallationBindings" binding
            WHERE binding."Id" = {scenario.Fixture.BindingId};

            INSERT INTO public."RuntimeEnrollments"
            SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                to_jsonb(enrollment) || jsonb_build_object(
                    'Id', {secondEnrollmentId.ToString("D")},
                    'BindingId', {secondBindingId.ToString("D")},
                    'InstallationId', (SELECT "InstallationId"
                                       FROM public."DistributionInstallationBindings"
                                       WHERE "Id" = {secondBindingId}),
                    'HandoffDigestSha256', {new string('c', 64)},
                    'KeyThumbprint', {new string('e', 43)}))).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = {scenario.EnrollmentId};
            """);
}
