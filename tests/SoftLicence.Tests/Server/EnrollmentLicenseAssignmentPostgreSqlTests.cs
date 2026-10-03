using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Last migration before the additive assignment and quarantine tables.</summary>
    private const string BeforeEnrollmentAssignmentMigration =
        "20260922113036_AddTkt001296AliasRecognizedAuthorityMode";
    /// <summary>The item-1 schema and transient grants, before item-2 revokes direct writes.</summary>
    private const string EnrollmentAssignmentMigration =
        "20260922203000_AddEnrollmentLicenseAssignment";

    /// <summary>
    /// Proves the migration maps one coherent pending enrollment through its exact
    /// binding and seat, without importing hardware identity into the assignment.
    /// </summary>
    [Fact]
    public async Task AssignmentBackfill_CoherentPendingGraph_CreatesOneActiveAssignment()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await RewindAssignmentMigrationsAsync(scenario.AdminConnectionString);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var legacyEnrollment = await mutate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            legacyEnrollment.HardwareIdHash = new string('a', 64);
            await mutate.SaveChangesAsync();
        }
        await using (var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await migration.Database.MigrateAsync(EnrollmentAssignmentMigration);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await check.DistributionInstallationBindings.SingleAsync(row => row.Id == enrollment.BindingId);
        var assignment = await check.EnrollmentLicenseAssignments.SingleAsync();
        Assert.Equal(enrollment.Id, assignment.EnrollmentId);
        Assert.Equal(binding.LicenseId, assignment.LicenseId);
        Assert.Equal(binding.LicenseSeatId, assignment.LicenseSeatId);
        Assert.Equal("ACTIVE", assignment.State);
        Assert.Equal(binding.BoundAtUtc, assignment.ActivatedAtUtc);
        Assert.Null(assignment.EndedAtUtc);
        Assert.Equal(1, assignment.Revision);
        Assert.Empty(await check.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
        Assert.DoesNotContain(typeof(EnrollmentLicenseAssignment).GetProperties(),
            property => property.Name.Contains("Hardware", StringComparison.OrdinalIgnoreCase));

        await using var privileges = new NpgsqlConnection(scenario.AdminConnectionString);
        await privileges.OpenAsync();
        await using var permissions = new NpgsqlCommand("""
            SELECT has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'SELECT')
               AND has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'INSERT')
               AND has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'UPDATE')
               AND NOT has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'DELETE')
               AND has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignmentQuarantines"', 'SELECT')
               AND NOT has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignmentQuarantines"', 'INSERT');
            """, privileges);
        Assert.True((bool)(await permissions.ExecuteScalarAsync())!);

        await using var duplicate = new NpgsqlCommand("""
            INSERT INTO "EnrollmentLicenseAssignments"
                ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                 "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
            SELECT gen_random_uuid(), "EnrollmentId", "LicenseId", "LicenseSeatId",
                   'ACTIVE', "ActivatedAtUtc", NULL, 2, NULL
            FROM "EnrollmentLicenseAssignments" WHERE "Id" = @assignment;
            """, privileges);
        duplicate.Parameters.AddWithValue("assignment", assignment.Id);
        var conflict = await Assert.ThrowsAsync<PostgresException>(() => duplicate.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.UniqueViolation, conflict.SqlState);

        await using var rollback = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var blockedRollback = await Assert.ThrowsAsync<PostgresException>(() =>
            rollback.Database.MigrateAsync(BeforeEnrollmentAssignmentMigration));
        Assert.Contains("requires explicit data reconciliation", blockedRollback.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Proves a conflicting enrollment-to-binding seat is quarantined instead of
    /// silently inheriting the binding's commercial right.
    /// </summary>
    [Fact]
    public async Task AssignmentBackfill_SeatMismatch_QuarantinesWithoutAssignment()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await RewindAssignmentMigrationsAsync(scenario.AdminConnectionString);

        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            enrollment.LicenseSeatId = Guid.NewGuid();
            await mutate.SaveChangesAsync();
        }

        await using (var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await migration.Database.MigrateAsync(EnrollmentAssignmentMigration);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.Empty(await check.EnrollmentLicenseAssignments.ToListAsync());
        var quarantine = await check.EnrollmentLicenseAssignmentQuarantines.SingleAsync();
        Assert.Equal(scenario.EnrollmentId, quarantine.EnrollmentId);
        Assert.Equal("binding_mismatch", quarantine.Reason);
    }

    /// <summary>
    /// Proves the historical installation reference is compared byte-for-byte:
    /// changing only UUID letter case cannot silently select a commercial seat.
    /// </summary>
    [Fact]
    public async Task AssignmentBackfill_InstallationCaseDivergence_Quarantines()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await RewindAssignmentMigrationsAsync(scenario.AdminConnectionString);

        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            await mutate.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"DistributionInstallationBindings\" SET \"InstallationId\" = {scenario.Fixture.InstallationId.ToUpperInvariant()} WHERE \"Id\" = {scenario.Fixture.BindingId}");
        }
        await using (var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await migration.Database.MigrateAsync(EnrollmentAssignmentMigration);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.Empty(await check.EnrollmentLicenseAssignments.ToListAsync());
        Assert.Equal("binding_mismatch",
            (await check.EnrollmentLicenseAssignmentQuarantines.SingleAsync()).Reason);
    }

    /// <summary>
    /// Proves two live enrollments naming the same seat cannot be ordered by a
    /// migration guess: both are quarantined even when their bindings are distinct.
    /// </summary>
    [Fact]
    public async Task AssignmentBackfill_TwoLiveClaimantsForSeat_QuarantinesBoth()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await RewindAssignmentMigrationsAsync(scenario.AdminConnectionString);

        var secondBindingId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();
        await using (var connection = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await connection.OpenAsync();
            await using var clone = new NpgsqlCommand("""
                INSERT INTO "DistributionInstallationBindings"
                SELECT (jsonb_populate_record(NULL::"DistributionInstallationBindings",
                    to_jsonb(b) || jsonb_build_object(
                        'Id', @new_binding, 'GrantRef', @new_grant,
                        'GrantRefDigestSha256', @grant_digest,
                        'HandoffDigestSha256', @handoff_digest,
                        'HardwareIdHash', @hardware_digest,
                        'InstallationId', @installation))).*
                FROM "DistributionInstallationBindings" b WHERE b."Id" = @source_binding;

                INSERT INTO "RuntimeEnrollments"
                SELECT (jsonb_populate_record(NULL::"RuntimeEnrollments",
                    to_jsonb(e) || jsonb_build_object(
                        'Id', @new_enrollment, 'BindingId', @new_binding,
                        'InstallationId', @installation,
                        'HandoffDigestSha256', @handoff_digest,
                        'KeyThumbprint', @thumbprint))).*
                FROM "RuntimeEnrollments" e WHERE e."Id" = @source_enrollment;
                """, connection);
            clone.Parameters.AddWithValue("source_binding", scenario.Fixture.BindingId);
            clone.Parameters.AddWithValue("source_enrollment", scenario.EnrollmentId);
            clone.Parameters.AddWithValue("new_binding", secondBindingId.ToString("D"));
            clone.Parameters.AddWithValue("new_enrollment", secondEnrollmentId.ToString("D"));
            clone.Parameters.AddWithValue("new_grant", Guid.NewGuid().ToString("D"));
            clone.Parameters.AddWithValue("installation", Guid.NewGuid().ToString("D"));
            clone.Parameters.AddWithValue("grant_digest", new string('b', 64));
            clone.Parameters.AddWithValue("handoff_digest", new string('c', 64));
            clone.Parameters.AddWithValue("hardware_digest", new string('d', 64));
            clone.Parameters.AddWithValue("thumbprint", new string('e', 43));
            await clone.ExecuteNonQueryAsync();
        }

        await using (var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await migration.Database.MigrateAsync(EnrollmentAssignmentMigration);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.Empty(await check.EnrollmentLicenseAssignments.ToListAsync());
        var quarantines = await check.EnrollmentLicenseAssignmentQuarantines
            .OrderBy(row => row.EnrollmentId).ToListAsync();
        Assert.Equal(2, quarantines.Count);
        Assert.All(quarantines, row => Assert.Equal("live_seat_ambiguous", row.Reason));
        Assert.Contains(quarantines, row => row.EnrollmentId == scenario.EnrollmentId);
        Assert.Contains(quarantines, row => row.EnrollmentId == secondEnrollmentId);
    }

    /// <summary>
    /// Proves a genuine terminal enrollment receives history only and cannot keep
    /// a live commercial assignment after migration.
    /// </summary>
    [Fact]
    public async Task AssignmentBackfill_TerminalEnrollment_CreatesEndedHistory()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await RewindAssignmentMigrationsAsync(scenario.AdminConnectionString);

        var endedAtUtc = DateTime.UtcNow;
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = endedAtUtc;
            enrollment.InvalidationReason = "seat_released";
            await mutate.SaveChangesAsync();
        }

        await using (var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await migration.Database.MigrateAsync(EnrollmentAssignmentMigration);

        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var persistedEnrollment = await check.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignment = await check.EnrollmentLicenseAssignments.SingleAsync();
        Assert.Equal("ENDED", assignment.State);
        Assert.Equal(persistedEnrollment.InvalidatedAtUtc, assignment.EndedAtUtc);
        Assert.Equal("legacy_enrollment_invalidated", assignment.EndReason);
        Assert.Empty(await check.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
    }

    /// <summary>
    /// Uses the migration administrator connection so a rollback/reapply test does
    /// not depend on the fixture's separate application-role grants for new tables.
    /// </summary>
    private static LicenseDbContext CreateEnrollmentAssignmentMigrationContext(string connectionString) =>
        new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    /// <summary>
    /// Removes only the disposable fixture's trigger-generated assignment before
    /// exercising the preceding migration's historical backfill from its own baseline.
    /// No application-role or production data is modified by this test helper.
    /// </summary>
    private static async Task RewindAssignmentMigrationsAsync(string adminConnectionString)
    {
        await using var migration = CreateEnrollmentAssignmentMigrationContext(adminConnectionString);
        await migration.Database.ExecuteSqlRawAsync(
            "DELETE FROM public.\"EnrollmentLicenseAssignments\"; DELETE FROM public.\"EnrollmentLicenseAssignmentQuarantines\";");
        await migration.Database.MigrateAsync(BeforeEnrollmentAssignmentMigration);
    }
}
