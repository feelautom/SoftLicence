using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;
using PreparedBootstrapScenario = SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTestBase.PreparedBootstrapScenario;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001277 lot 2d: the open position of the assignment switch. The rest of this suite runs with the switch
/// closed and proves the original blocking behaviour; these tests open it and prove that each would-be block is
/// recorded and the operation passes, with the right produced as if the operation were valid.
/// </summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed class AssignmentEnforcementSwitchPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>Case 1 (diverging enrollment copy): recorded, write passes, the binding keeps the single right.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.AssignmentSwitchOpen_DivergingEnrollment_IsRecordedAndPasses")]
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
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.AssignmentSwitchOpen_CompetingClaimant_TakesTheSeatAndIsRecorded")]
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
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.AssignmentSwitchClosed_CompetingClaimant_KeepsOriginalRefusal")]
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
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.AssignmentSwitchOpen_UnexpectedError_IsRecordedWithoutPartialChange")]
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
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.AssignmentSwitchClosed_UnexpectedError_IsRaisedUnchanged")]
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
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.AssignmentSwitch_SeatReleaseWithoutRight_FollowsTheSwitch")]
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

    /// <summary>
    /// TKT-001428, production events 1 to 3 (automatic seat switch, two portal deactivations): the seat's only
    /// installation was invalidated, so its right is ENDED and nothing is live. With the switch closed the release
    /// must succeed without snapshot and without any "would have blocked" event; it was refused before the fix.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.SeatReleaseClosed_EndedHistoryWithoutRuntime_Releases")]
    public async Task SeatReleaseClosed_EndedHistoryWithoutRuntime_Releases()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(admin, AssignmentEnforcementSetting.Closed);
        await InvalidateEnrollmentAsync(admin, scenario.EnrollmentId);
        var right = await admin.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync();
        Assert.Equal("ENDED", right.State);
        Assert.Equal("enrollment_invalidated", right.EndReason);

        await ReleaseSeatAsync(scenario, right.LicenseId, right.LicenseSeatId, expectedSnapshots: 0);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == right.LicenseSeatId)).IsActive);
        Assert.Empty(await check.AssignmentEnforcementEvents.ToListAsync());
    }

    /// <summary>
    /// TKT-001428, production seat 59606347: the live installation lost its right through a licence revocation, and
    /// an earlier invalidated installation of the same seat left an ENDED row. With the switch closed the release
    /// must judge only the live installation's right and succeed; the earlier row made it refuse before the fix.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.SeatReleaseClosed_RevokedLiveInstallationWithEarlierHistory_Releases")]
    public async Task SeatReleaseClosed_RevokedLiveInstallationWithEarlierHistory_Releases()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(admin, AssignmentEnforcementSetting.Closed);
        await InvalidateEnrollmentAsync(admin, scenario.EnrollmentId);
        var liveEnrollmentId = Guid.NewGuid();
        // The reinstall arrives after the invalidation, as in production, so the trigger grants it the free seat
        // instead of refusing a second live claimant.
        await StageSecondClaimantAsync(admin, scenario, Guid.NewGuid(), liveEnrollmentId, live: true);
        admin.ChangeTracker.Clear();
        var liveRight = await admin.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == liveEnrollmentId);
        Assert.Equal("ACTIVE", liveRight.State);
        await admin.Database.ExecuteSqlInterpolatedAsync(
            $"""UPDATE public."Licenses" SET "IsActive" = false WHERE "Id" = {liveRight.LicenseId}""");
        admin.ChangeTracker.Clear();
        var rights = await admin.EnrollmentLicenseAssignments.AsNoTracking().ToListAsync();
        Assert.Equal(2, rights.Count);
        Assert.All(rights, row => Assert.Equal("ENDED", row.State));
        Assert.Equal("license_revoked", rights.Single(row => row.EnrollmentId == liveEnrollmentId).EndReason);

        await ReleaseSeatAsync(scenario, liveRight.LicenseId, liveRight.LicenseSeatId, expectedSnapshots: 1);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == liveRight.LicenseSeatId)).IsActive);
        Assert.Empty(await check.AssignmentEnforcementEvents.ToListAsync());
    }

    /// <summary>
    /// TKT-001428 real case that must stay blocked: an ACTIVE right whose installation is no longer live is an
    /// inconsistent graph. With the switch closed the release keeps refusing it with the original reason and records
    /// nothing. The trigger is bypassed (replica role) only to build this state, which the product never writes.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.SeatReleaseClosed_ActiveRightWithoutRuntime_StaysRefused")]
    public async Task SeatReleaseClosed_ActiveRightWithoutRuntime_StaysRefused()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(admin, AssignmentEnforcementSetting.Closed);
        await using (var seed = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await seed.OpenAsync();
            await using var transaction = await seed.BeginTransactionAsync();
            await using var command = new NpgsqlCommand("""
                SET LOCAL session_replication_role = replica;
                UPDATE public."RuntimeEnrollments"
                SET "State" = 'INVALIDATED', "InvalidatedAtUtc" = pg_catalog.clock_timestamp(),
                    "InvalidationReason" = 'tkt001428_probe'
                WHERE "Id" = @enrollment;
                """, seed, transaction);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            await command.ExecuteNonQueryAsync();
            await transaction.CommitAsync();
        }
        var right = await admin.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync();
        Assert.Equal("ACTIVE", right.State);

        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await using var releaseTransaction = await SeatRuntimeReleaseAuthority.BeginAsync(db);
        var license = await db.Licenses.SingleAsync(row => row.Id == right.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == right.LicenseSeatId);
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            SeatRuntimeReleaseAuthority.PrepareAsync(db, license.ProductId, license, [seat], DateTime.UtcNow));

        Assert.Equal("seat_release_assignment_without_runtime", refused.ReasonCode);
        Assert.Empty(await admin.AssignmentEnforcementEvents.ToListAsync());
    }

    /// <summary>
    /// Invalidates one enrollment through the product path (plain UPDATE), so the assignment trigger ends its right
    /// with <c>enrollment_invalidated</c> exactly as in production.
    /// </summary>
    private static Task InvalidateEnrollmentAsync(LicenseDbContext db, Guid enrollmentId) =>
        db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE public."RuntimeEnrollments"
            SET "State" = 'INVALIDATED', "InvalidatedAtUtc" = {DateTime.UtcNow}, "InvalidationReason" = 'tkt001428_reinstall'
            WHERE "Id" = {enrollmentId}
            """);

    /// <summary>
    /// Releases one seat through <see cref="SeatRuntimeReleaseAuthority"/> in its own transaction, as every product
    /// caller does (prepare, deactivate, complete, commit), and checks the number of captured right snapshots.
    /// Throws the control's <see cref="DistributionOperationException"/> when the release is refused.
    /// </summary>
    private static async Task ReleaseSeatAsync(
        PreparedBootstrapScenario scenario, Guid licenseId, Guid seatId, int expectedSnapshots)
    {
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db);
        var license = await db.Licenses.SingleAsync(row => row.Id == licenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == seatId);
        var scope = await SeatRuntimeReleaseAuthority.PrepareAsync(db, license.ProductId, license, [seat], DateTime.UtcNow);
        Assert.Equal(expectedSnapshots, scope.Assignments.Count);
        seat.IsActive = false;
        seat.UnlinkedAt = scope.ObservedAtUtc;
        await SeatRuntimeReleaseAuthority.CompleteAsync(db, scope, [seat]);
        await transaction!.CommitAsync();
    }

    /// <summary>Makes every assignment write fail, to exercise the unexpected-error branch.</summary>
    private static Task InstallFailingAssignmentWriteAsync(LicenseDbContext db) =>
        db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION public.tkt001277_fail_assignment_write() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated assignment failure'; END $$;
            CREATE TRIGGER tkt001277_fail_assignment_write
            BEFORE INSERT OR UPDATE ON public."EnrollmentLicenseAssignments"
            FOR EACH ROW EXECUTE FUNCTION public.tkt001277_fail_assignment_write();
            """);

    /// <summary>
    /// Stages a second live binding and enrollment on the scenario seat, as Codex's competing-claim test. With
    /// <paramref name="live"/> the copied enrollment is forced ACTIVE without invalidation evidence, so the copy stays
    /// live even when the scenario enrollment was invalidated first (TKT-001428 reinstall after invalidation).
    /// </summary>
    private static Task StageSecondClaimantAsync(
        LicenseDbContext db, PreparedBootstrapScenario scenario, Guid secondBindingId, Guid secondEnrollmentId,
        bool live = false) =>
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
                    'KeyThumbprint', {new string('e', 43)})
                || CASE WHEN {live} THEN jsonb_build_object(
                       'State', 'ACTIVE', 'InvalidatedAtUtc', NULL, 'InvalidationReason', NULL)
                   ELSE jsonb_build_object() END)).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = {scenario.EnrollmentId};
            """);
}
