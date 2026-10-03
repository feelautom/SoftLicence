using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// The dual-write target has no hardware, crypto, replay, epoch or release
    /// columns; changing those independent domains cannot revise this ledger.
    /// </summary>
    [Fact]
    public void AssignmentDualWrite_ModelRemainsCommercialOnly()
    {
        var forbidden = new[]
        {
            "Hardware", "Epoch", "Thumbprint", "Digest", "Release",
            "Binary", "Alias", "Ciphertext", "Challenge"
        };
        Assert.DoesNotContain(typeof(EnrollmentLicenseAssignment).GetProperties(),
            property => forbidden.Any(term =>
                property.Name.Contains(term, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Item 2 removes the temporary item-1 DML grant. The production application
    /// role can read assignment history but only the definer trigger can write it.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_ProductionRole_CannotWriteLedgerDirectly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var builder = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only"
        };
        await using var app = new NpgsqlConnection(builder.ConnectionString);
        await app.OpenAsync();
        await using (var read = new NpgsqlCommand(
            "SELECT count(*) FROM public.\"EnrollmentLicenseAssignments\"", app))
            Assert.Equal(1L, await read.ExecuteScalarAsync());

        foreach (var statement in new[]
        {
            "INSERT INTO public.\"EnrollmentLicenseAssignments\" SELECT * FROM public.\"EnrollmentLicenseAssignments\" WHERE false",
            "UPDATE public.\"EnrollmentLicenseAssignments\" SET \"State\" = \"State\" WHERE false",
            "DELETE FROM public.\"EnrollmentLicenseAssignments\" WHERE false"
        })
        {
            await using var forbidden = new NpgsqlCommand(statement, app);
            var denied = await Assert.ThrowsAsync<PostgresException>(
                () => forbidden.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
        }
    }

    /// <summary>
    /// An explicitly allowed empty item-2 rollback restores the complete item-1
    /// temporary application grant while still refusing DELETE.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_EmptyRollback_RestoresItemOnePrivileges()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        Assert.Equal(1, await migration.EnrollmentLicenseAssignments.ExecuteDeleteAsync());
        Assert.Empty(await migration.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
        await migration.Database.MigrateAsync("20260922203000_AddEnrollmentLicenseAssignment");

        await using var admin = new NpgsqlConnection(scenario.AdminConnectionString);
        await admin.OpenAsync();
        await using var permissions = new NpgsqlCommand("""
            SELECT has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'SELECT')
               AND has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'INSERT')
               AND has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'UPDATE')
               AND NOT has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignments"', 'DELETE')
               AND has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignmentQuarantines"', 'SELECT')
               AND NOT has_table_privilege('softlicence_app', 'public."EnrollmentLicenseAssignmentQuarantines"', 'INSERT');
            """, admin);
        Assert.True((bool)(await permissions.ExecuteScalarAsync())!);
    }

    /// <summary>
    /// A malformed historical terminal enrollment is recorded for reconciliation
    /// without inventing assignment history or granting commercial authority.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_MalformedHistoricalTerminal_QuarantinesWithoutGrant()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var historicalId = Guid.NewGuid();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeEnrollments"
            SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                to_jsonb(enrollment) || jsonb_build_object(
                    'Id', {historicalId.ToString("D")},
                    'InstallationId', {Guid.NewGuid().ToString("D")},
                    'KeyThumbprint', {"sl-" + Guid.NewGuid().ToString("N")},
                    'State', 'INVALIDATED',
                    'InvalidatedAtUtc', {DateTime.UtcNow},
                    'InvalidationReason', 'historical_alias'))).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = {scenario.EnrollmentId};
            """);

        db.ChangeTracker.Clear();
        Assert.True(await db.RuntimeEnrollments.AnyAsync(row => row.Id == historicalId));
        Assert.False(await db.EnrollmentLicenseAssignments
            .AnyAsync(row => row.EnrollmentId == historicalId));
        Assert.Equal("binding_mismatch", (await db.EnrollmentLicenseAssignmentQuarantines
            .SingleAsync(row => row.EnrollmentId == historicalId)).Reason);
        Assert.Single(await db.EnrollmentLicenseAssignments
            .Where(row => row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>A malformed live enrollment refuses the whole update and leaves no diagnostic fragment.</summary>
    [Fact]
    public async Task AssignmentDualWrite_MalformedLiveWrite_RefusesWithoutFragment()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var originalInstallation = (await db.RuntimeEnrollments
            .SingleAsync(row => row.Id == scenario.EnrollmentId)).InstallationId;
        var refusal = await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE public.\"RuntimeEnrollments\" SET \"InstallationId\" = {Guid.NewGuid().ToString("D")} WHERE \"Id\" = {scenario.EnrollmentId}"));
        Assert.Equal(PostgresErrorCodes.CheckViolation, refusal.SqlState);
        Assert.Equal("unresolved commercial assignment graph: binding_mismatch", refusal.MessageText);

        db.ChangeTracker.Clear();
        Assert.Equal(originalInstallation, (await db.RuntimeEnrollments
            .SingleAsync(row => row.Id == scenario.EnrollmentId)).InstallationId);
        Assert.Single(await db.EnrollmentLicenseAssignments
            .Where(row => row.State == "ACTIVE").ToListAsync());
        Assert.Empty(await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
    }

    /// <summary>
    /// A terminal transition with a divergent copied commercial field still
    /// revokes an existing assignment atomically and quarantines the graph.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_DivergentTerminalTransition_EndsKnownRightAndQuarantines()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {DateTime.UtcNow}, \"InvalidationReason\" = 'divergent_revocation', \"InstallationId\" = {Guid.NewGuid().ToString("D")} WHERE \"Id\" = {scenario.EnrollmentId}");

        db.ChangeTracker.Clear();
        var assignment = await db.EnrollmentLicenseAssignments.SingleAsync();
        Assert.Equal("ENDED", assignment.State);
        Assert.Equal("terminal_graph_diverged", assignment.EndReason);
        Assert.NotNull(assignment.EndedAtUtc);
        Assert.False(await db.EnrollmentLicenseAssignments
            .AnyAsync(row => row.State == "ACTIVE"));
        Assert.Equal("binding_mismatch", (await db.EnrollmentLicenseAssignmentQuarantines
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId)).Reason);
        Assert.Single(await db.RuntimeEnrollments.ToListAsync());
    }

    /// <summary>
    /// A legacy application update after trigger installation ends commercial
    /// authority in its own transaction. Replaying it does not revise history.
    /// A hardware-only update does not touch assignment or enrollment epochs.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_LegacyTerminalAndHardwareRetry_AreAtomicAndIdempotent()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var before = await db.EnrollmentLicenseAssignments.SingleAsync();
        var original = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);

        await using (var legacyApp = new NpgsqlConnection(scenario.AppConnectionString))
        {
            await legacyApp.OpenAsync();
            await using var oldBinaryWrite = new NpgsqlCommand(
                "UPDATE public.\"RuntimeEnrollments\" SET \"HardwareIdHash\" = @hash WHERE \"Id\" = @enrollment",
                legacyApp);
            oldBinaryWrite.Parameters.AddWithValue("hash", new string('f', 64));
            oldBinaryWrite.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await oldBinaryWrite.ExecuteNonQueryAsync());

            await using var forbiddenDirectCall = new NpgsqlCommand(
                "SELECT public.sync_enrollment_license_assignment(@enrollment, false)",
                legacyApp);
            forbiddenDirectCall.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            var denied = await Assert.ThrowsAsync<PostgresException>(
                () => forbiddenDirectCall.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
        }
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"DistributionInstallationBindings\" SET \"HardwareIdHash\" = {new string('f', 64)} WHERE \"Id\" = {scenario.Fixture.BindingId}");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"LicenseSeats\" SET \"HardwareId\" = {Guid.NewGuid().ToString("D")} WHERE \"Id\" = {before.LicenseSeatId}");
        db.ChangeTracker.Clear();
        var afterHardware = await db.EnrollmentLicenseAssignments.SingleAsync();
        var enrollmentAfterHardware = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal(before.Id, afterHardware.Id);
        Assert.Equal(before.Revision, afterHardware.Revision);
        Assert.Equal(before.State, afterHardware.State);
        Assert.Equal(before.ActivatedAtUtc, afterHardware.ActivatedAtUtc);
        Assert.Equal(original.Epoch, enrollmentAfterHardware.Epoch);
        Assert.Equal(original.SecurityEpoch, enrollmentAfterHardware.SecurityEpoch);
        Assert.Equal(original.AuthorityEpoch, enrollmentAfterHardware.AuthorityEpoch);

        await using (var aborted = await db.Database.BeginTransactionAsync())
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {DateTime.UtcNow}, \"InvalidationReason\" = 'rolled_back' WHERE \"Id\" = {scenario.EnrollmentId}");
            await aborted.RollbackAsync();
        }
        db.ChangeTracker.Clear();
        Assert.Equal("PENDING",
            (await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.Equal("ACTIVE", (await db.EnrollmentLicenseAssignments.SingleAsync()).State);

        var terminalTime = DateTime.UtcNow;
        await using (var legacyApp = new NpgsqlConnection(scenario.AppConnectionString))
        {
            await legacyApp.OpenAsync();
            await using var oldBinaryWrite = new NpgsqlCommand(
                "UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = @at, \"InvalidationReason\" = 'test_terminal' WHERE \"Id\" = @enrollment",
                legacyApp);
            oldBinaryWrite.Parameters.AddWithValue("at", terminalTime);
            oldBinaryWrite.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await oldBinaryWrite.ExecuteNonQueryAsync());
        }
        db.ChangeTracker.Clear();
        var ended = await db.EnrollmentLicenseAssignments.SingleAsync();
        Assert.Equal("ENDED", ended.State);
        Assert.Equal("enrollment_invalidated", ended.EndReason);
        Assert.Equal(
            (await db.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId)).InvalidatedAtUtc,
            ended.EndedAtUtc);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED' WHERE \"Id\" = {scenario.EnrollmentId}");
        db.ChangeTracker.Clear();
        Assert.Equal(1, await db.EnrollmentLicenseAssignments.CountAsync());
        Assert.Equal(ended.EndedAtUtc,
            (await db.EnrollmentLicenseAssignments.SingleAsync()).EndedAtUtc);
    }

    /// <summary>
    /// The migration catches a legacy terminal written after item-1 backfill and
    /// before the trigger exists. A later application update is covered by the
    /// trigger in the same database transaction.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_CatchupClosesGap_AndRollbackPreservesPriorState()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await db.Database.ExecuteSqlRawAsync(
            "DELETE FROM public.\"EnrollmentLicenseAssignments\";");
        await db.Database.MigrateAsync("20260922203000_AddEnrollmentLicenseAssignment");

        var terminalTime = DateTime.UtcNow;
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {terminalTime}, \"InvalidationReason\" = 'legacy_gap' WHERE \"Id\" = {scenario.EnrollmentId}");
        Assert.Empty(await db.EnrollmentLicenseAssignments.ToListAsync());
        await db.Database.MigrateAsync();
        db.ChangeTracker.Clear();
        var caughtUp = await db.EnrollmentLicenseAssignments.SingleAsync();
        Assert.Equal("ENDED", caughtUp.State);
        Assert.Equal(
            (await db.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId)).InvalidatedAtUtc,
            caughtUp.EndedAtUtc);
        Assert.Empty(await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync());

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"HardwareIdHash\" = {new string('b', 64)} WHERE \"Id\" = {scenario.EnrollmentId}");
        db.ChangeTracker.Clear();
        Assert.Equal(1, await db.EnrollmentLicenseAssignments.CountAsync());
        Assert.Equal(caughtUp.EndedAtUtc,
            (await db.EnrollmentLicenseAssignments.SingleAsync()).EndedAtUtc);
    }

    /// <summary>
    /// A new binding and seat transfer close the old right before the new one
    /// becomes active. Replaying the same commercial update does not add a revision.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_AtomicSeatTransfer_RevisesOnce()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var originalSeatId = (await db.EnrollmentLicenseAssignments.SingleAsync()).LicenseSeatId;
        var newSeatId = Guid.NewGuid();
        var newBindingId = Guid.NewGuid();
        var installationId = Guid.NewGuid().ToString("D");
        var handoffDigest = new string('c', 64);
        await using (var transfer = await db.Database.BeginTransactionAsync())
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO public."LicenseSeats"
                SELECT (jsonb_populate_record(NULL::public."LicenseSeats",
                    to_jsonb(seat) || jsonb_build_object(
                        'Id', {newSeatId.ToString("D")},
                        'HardwareId', {Guid.NewGuid().ToString("D")}))).*
                FROM public."LicenseSeats" seat WHERE seat."Id" = {originalSeatId};

                INSERT INTO public."DistributionInstallationBindings"
                SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                    to_jsonb(binding) || jsonb_build_object(
                        'Id', {newBindingId.ToString("D")},
                        'LicenseSeatId', {newSeatId.ToString("D")},
                        'InstallationId', {installationId},
                        'GrantRef', {Guid.NewGuid().ToString("D")},
                        'GrantRefDigestSha256', {new string('d', 64)},
                        'HandoffDigestSha256', {handoffDigest},
                        'HardwareIdHash', {new string('e', 64)}))).*
                FROM public."DistributionInstallationBindings" binding
                WHERE binding."Id" = {scenario.Fixture.BindingId};

                UPDATE public."RuntimeEnrollments"
                SET "BindingId" = {newBindingId},
                    "LicenseSeatId" = {newSeatId},
                    "InstallationId" = {installationId},
                    "HandoffDigestSha256" = {handoffDigest},
                    "HardwareIdHash" = {new string('e', 64)}
                WHERE "Id" = {scenario.EnrollmentId};
                """);
            await transfer.CommitAsync();
        }

        db.ChangeTracker.Clear();
        var history = await db.EnrollmentLicenseAssignments
            .OrderBy(row => row.Revision).ToListAsync();
        Assert.Equal(2, history.Count);
        Assert.Equal("ENDED", history[0].State);
        Assert.Equal("commercial_transfer", history[0].EndReason);
        Assert.Equal("ACTIVE", history[1].State);
        Assert.Equal(newSeatId, history[1].LicenseSeatId);
        Assert.Equal(2, history[1].Revision);
        Assert.Single(history, row => row.State == "ACTIVE");

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"BindingId\" = {newBindingId} WHERE \"Id\" = {scenario.EnrollmentId}");
        db.ChangeTracker.Clear();
        Assert.Equal(2, await db.EnrollmentLicenseAssignments.CountAsync());
        Assert.Equal("ACTIVE",
            (await db.EnrollmentLicenseAssignments.SingleAsync(row => row.Revision == 2)).State);
    }

    /// <summary>
    /// A competing live claimant cannot win a seat by row order. Its transaction
    /// fails with a retryable serialization code and leaves the original right intact.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_CompetingSeatClaim_FailsWithoutQuarantine()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var secondBindingId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
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
        var conflict = await Assert.ThrowsAsync<PostgresException>(
            () => transaction.CommitAsync());
        Assert.Equal(PostgresErrorCodes.SerializationFailure, conflict.SqlState);
        db.ChangeTracker.Clear();
        Assert.Single(await db.EnrollmentLicenseAssignments.ToListAsync());
        Assert.Empty(await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
        Assert.False(await db.RuntimeEnrollments.AnyAsync(row => row.Id == secondEnrollmentId));
    }

    /// <summary>
    /// Two independent connections stage different new keys against the same
    /// released seat, then commit concurrently under a bounded timeout. Exactly
    /// one transaction and one ACTIVE assignment survive; the loser retries from
    /// SQLSTATE 40001 and leaves no binding, enrollment or ledger fragment.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_ConcurrentSeatClaims_HaveOneAtomicWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var check = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var seatId = (await check.EnrollmentLicenseAssignments.SingleAsync()).LicenseSeatId;
        await check.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {DateTime.UtcNow}, \"InvalidationReason\" = 'concurrent_transfer' WHERE \"Id\" = {scenario.EnrollmentId}");
        check.ChangeTracker.Clear();
        Assert.Empty(await check.EnrollmentLicenseAssignments
            .Where(row => row.State == "ACTIVE").ToListAsync());

        var firstBindingId = Guid.NewGuid();
        var secondBindingId = Guid.NewGuid();
        var firstEnrollmentId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var firstConnection = new NpgsqlConnection(scenario.AdminConnectionString);
        await using var secondConnection = new NpgsqlConnection(scenario.AdminConnectionString);
        await firstConnection.OpenAsync(timeout.Token);
        await secondConnection.OpenAsync(timeout.Token);
        await using var first = await firstConnection.BeginTransactionAsync(timeout.Token);
        await using var second = await secondConnection.BeginTransactionAsync(timeout.Token);

        await StageSeatClaimAsync(firstConnection, first, scenario.Fixture.BindingId,
            scenario.EnrollmentId, firstBindingId, firstEnrollmentId, 'b', 'e', timeout.Token);
        var secondStage = StageSeatClaimAsync(secondConnection, second, scenario.Fixture.BindingId,
            scenario.EnrollmentId, secondBindingId, secondEnrollmentId, 'c', 'f', timeout.Token);
        var firstOutcome = await CommitSeatClaimAsync(first, timeout.Token);
        Assert.Null(firstOutcome);
        string? secondOutcome;
        try
        {
            await secondStage;
            secondOutcome = await CommitSeatClaimAsync(second, timeout.Token);
        }
        catch (PostgresException exception)
        {
            secondOutcome = exception.SqlState;
            await second.RollbackAsync(CancellationToken.None);
        }
        Assert.Equal(PostgresErrorCodes.SerializationFailure, secondOutcome);

        check.ChangeTracker.Clear();
        Assert.Single(await check.EnrollmentLicenseAssignments
            .Where(row => row.State == "ACTIVE" && row.LicenseSeatId == seatId).ToListAsync());
        Assert.Equal(1, await check.RuntimeEnrollments.CountAsync(row =>
            row.Id == firstEnrollmentId || row.Id == secondEnrollmentId));
        Assert.Equal(1, await check.DistributionInstallationBindings.CountAsync(row =>
            row.Id == firstBindingId || row.Id == secondBindingId));
        Assert.Empty(await check.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
    }

    /// <summary>Stages one independent binding and enrollment inside its owning transaction.</summary>
    private static async Task StageSeatClaimAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid sourceBindingId, Guid sourceEnrollmentId,
        Guid bindingId, Guid enrollmentId,
        char digestCharacter, char thumbprintCharacter,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO public."DistributionInstallationBindings"
            SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                to_jsonb(binding) || jsonb_build_object(
                    'Id', @binding_id, 'GrantRef', @grant_ref,
                    'GrantRefDigestSha256', @grant_digest,
                    'HandoffDigestSha256', @handoff_digest,
                    'HardwareIdHash', @hardware_digest,
                    'InstallationId', @installation))).*
            FROM public."DistributionInstallationBindings" binding
            WHERE binding."Id" = @source_binding;

            INSERT INTO public."RuntimeEnrollments"
            SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                to_jsonb(enrollment) || jsonb_build_object(
                    'Id', @enrollment_id, 'BindingId', @binding_id,
                    'InstallationId', @installation,
                    'HandoffDigestSha256', @handoff_digest,
                    'HardwareIdHash', @hardware_digest,
                    'KeyThumbprint', @thumbprint,
                    'State', 'PENDING',
                    'InvalidatedAtUtc', NULL,
                    'InvalidationReason', NULL))).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = @source_enrollment;
            """, connection, transaction)
        {
            CommandTimeout = 15
        };
        command.Parameters.AddWithValue("source_binding", sourceBindingId);
        command.Parameters.AddWithValue("source_enrollment", sourceEnrollmentId);
        command.Parameters.AddWithValue("binding_id", bindingId.ToString("D"));
        command.Parameters.AddWithValue("enrollment_id", enrollmentId.ToString("D"));
        command.Parameters.AddWithValue("grant_ref", Guid.NewGuid().ToString("D"));
        command.Parameters.AddWithValue("installation", Guid.NewGuid().ToString("D"));
        command.Parameters.AddWithValue("grant_digest", new string(digestCharacter, 64));
        command.Parameters.AddWithValue("handoff_digest", new string(digestCharacter, 64));
        command.Parameters.AddWithValue("hardware_digest", new string(digestCharacter, 64));
        command.Parameters.AddWithValue("thumbprint", new string(thumbprintCharacter, 43));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Returns only the controlled database refusal code for one competing commit.</summary>
    private static async Task<string?> CommitSeatClaimAsync(
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        try
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }
        catch (PostgresException exception)
        {
            return exception.SqlState;
        }
    }

    /// <summary>
    /// A replacement key on the same commercial seat is granted only when the
    /// predecessor is terminal in that very transaction. Deferred triggers may
    /// execute in either enrollment order without exposing two ACTIVE rights.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_NewKeyTransfer_EndsPredecessorBeforeSuccessor()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var secondBindingId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();
        var installationId = Guid.NewGuid().ToString("D");
        var handoffDigest = new string('c', 64);
        await using (var transfer = await db.Database.BeginTransactionAsync())
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO public."DistributionInstallationBindings"
                SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                    to_jsonb(binding) || jsonb_build_object(
                        'Id', {secondBindingId.ToString("D")},
                        'GrantRef', {Guid.NewGuid().ToString("D")},
                        'GrantRefDigestSha256', {new string('b', 64)},
                        'HandoffDigestSha256', {handoffDigest},
                        'HardwareIdHash', {new string('d', 64)},
                        'InstallationId', {installationId}))).*
                FROM public."DistributionInstallationBindings" binding
                WHERE binding."Id" = {scenario.Fixture.BindingId};

                INSERT INTO public."RuntimeEnrollments"
                SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                    to_jsonb(enrollment) || jsonb_build_object(
                        'Id', {secondEnrollmentId.ToString("D")},
                        'BindingId', {secondBindingId.ToString("D")},
                        'InstallationId', {installationId},
                        'HandoffDigestSha256', {handoffDigest},
                        'HardwareIdHash', {new string('d', 64)},
                        'KeyThumbprint', {new string('e', 43)}))).*
                FROM public."RuntimeEnrollments" enrollment
                WHERE enrollment."Id" = {scenario.EnrollmentId};

                UPDATE public."RuntimeEnrollments"
                SET "State" = 'INVALIDATED',
                    "InvalidatedAtUtc" = now(),
                    "InvalidationReason" = 'new_key_transfer'
                WHERE "Id" = {scenario.EnrollmentId};
                """);
            await transfer.CommitAsync();
        }

        db.ChangeTracker.Clear();
        var predecessor = await db.EnrollmentLicenseAssignments
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        var successor = await db.EnrollmentLicenseAssignments
            .SingleAsync(row => row.EnrollmentId == secondEnrollmentId);
        Assert.Equal("ENDED", predecessor.State);
        Assert.Equal("ACTIVE", successor.State);
        Assert.Equal(predecessor.LicenseSeatId, successor.LicenseSeatId);
        Assert.Equal(1, successor.Revision);
        Assert.Empty(await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
    }

    /// <summary>
    /// The successor's deferred trigger executes before the source's terminal
    /// trigger because its binding and enrollment are inserted first. An absent or
    /// backdated source terminal instant must abort without clamping history.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AssignmentDualWrite_SuccessorBeforeInvalidPredecessor_RejectsAtomically(
        bool missingTerminalTime)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var diagnosticConnectionString = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            IncludeErrorDetail = true
        }.ConnectionString;
        await using var db = CreateEnrollmentAssignmentMigrationContext(diagnosticConnectionString);
        var original = await db.EnrollmentLicenseAssignments.SingleAsync();
        var successorBindingId = Guid.NewGuid();
        var successorEnrollmentId = Guid.NewGuid();
        var installationId = Guid.NewGuid().ToString("D");
        var handoffDigest = new string('c', 64);
        await using var transfer = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DistributionInstallationBindings"
            SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                to_jsonb(binding) || jsonb_build_object(
                    'Id', {successorBindingId.ToString("D")},
                    'GrantRef', {Guid.NewGuid().ToString("D")},
                    'GrantRefDigestSha256', {new string('b', 64)},
                    'HandoffDigestSha256', {handoffDigest},
                    'HardwareIdHash', {new string('d', 64)},
                    'InstallationId', {installationId}))).*
            FROM public."DistributionInstallationBindings" binding
            WHERE binding."Id" = {scenario.Fixture.BindingId};

            INSERT INTO public."RuntimeEnrollments"
            SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                to_jsonb(enrollment) || jsonb_build_object(
                    'Id', {successorEnrollmentId.ToString("D")},
                    'BindingId', {successorBindingId.ToString("D")},
                    'InstallationId', {installationId},
                    'HandoffDigestSha256', {handoffDigest},
                    'HardwareIdHash', {new string('d', 64)},
                    'KeyThumbprint', {new string('e', 43)}))).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = {scenario.EnrollmentId};
            """);
        if (missingTerminalTime)
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = NULL, \"InvalidationReason\" = 'invalid_transfer' WHERE \"Id\" = {scenario.EnrollmentId}");
        }
        else
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE public.\"RuntimeEnrollments\" SET \"State\" = 'INVALIDATED', \"InvalidatedAtUtc\" = {original.ActivatedAtUtc.AddMinutes(-1)}, \"InvalidationReason\" = 'invalid_transfer' WHERE \"Id\" = {scenario.EnrollmentId}");
        }
        var refusal = await Assert.ThrowsAsync<PostgresException>(
            () => transfer.CommitAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, refusal.SqlState);
        Assert.Equal("predecessor terminal time is invalid", refusal.MessageText);
        Assert.Contains($"enrollment={successorEnrollmentId:D}", refusal.Detail, StringComparison.Ordinal);
        Assert.Contains($"seat={original.LicenseSeatId:D}", refusal.Detail, StringComparison.Ordinal);
        Assert.Contains("reason=predecessor_terminal_time_invalid", refusal.Detail, StringComparison.Ordinal);

        db.ChangeTracker.Clear();
        Assert.Equal("ACTIVE",
            (await db.EnrollmentLicenseAssignments.SingleAsync()).State);
        Assert.Equal("PENDING",
            (await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.False(await db.RuntimeEnrollments.AnyAsync(row => row.Id == successorEnrollmentId));
        Assert.Empty(await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
    }

    /// <summary>
    /// Two live legacy claimants created after the initial backfill are not
    /// ordered by the catch-up loop. Both receive durable quarantine diagnostics.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_CatchupAmbiguity_QuarantinesBothWithoutGrant()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await db.Database.ExecuteSqlRawAsync(
            "DELETE FROM public.\"EnrollmentLicenseAssignments\";");
        await db.Database.MigrateAsync("20260922203000_AddEnrollmentLicenseAssignment");

        var secondBindingId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();
        var installationId = Guid.NewGuid().ToString("D");
        var handoffDigest = new string('c', 64);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DistributionInstallationBindings"
            SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                to_jsonb(binding) || jsonb_build_object(
                    'Id', {secondBindingId.ToString("D")},
                    'GrantRef', {Guid.NewGuid().ToString("D")},
                    'GrantRefDigestSha256', {new string('b', 64)},
                    'HandoffDigestSha256', {handoffDigest},
                    'HardwareIdHash', {new string('d', 64)},
                    'InstallationId', {installationId}))).*
            FROM public."DistributionInstallationBindings" binding
            WHERE binding."Id" = {scenario.Fixture.BindingId};

            INSERT INTO public."RuntimeEnrollments"
            SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                to_jsonb(enrollment) || jsonb_build_object(
                    'Id', {secondEnrollmentId.ToString("D")},
                    'BindingId', {secondBindingId.ToString("D")},
                    'InstallationId', {installationId},
                    'HandoffDigestSha256', {handoffDigest},
                    'HardwareIdHash', {new string('d', 64)},
                    'KeyThumbprint', {new string('e', 43)}))).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = {scenario.EnrollmentId};
            """);
        await db.Database.MigrateAsync("20260922213000_AddEnrollmentAssignmentDualWrite");

        db.ChangeTracker.Clear();
        Assert.Empty(await db.EnrollmentLicenseAssignments.ToListAsync());
        var quarantines = await db.EnrollmentLicenseAssignmentQuarantines.ToListAsync();
        Assert.Equal(2, quarantines.Count);
        Assert.All(quarantines, row => Assert.Equal("live_seat_ambiguous", row.Reason));
        Assert.Contains(quarantines, row => row.EnrollmentId == scenario.EnrollmentId);
        Assert.Contains(quarantines, row => row.EnrollmentId == secondEnrollmentId);

        // TKT-001277 lot 2d: the switch migration seeds the switch open and gives the quarantined live claimants a
        // right, the latest claimant keeping the seat; every would-be block is recorded.
        await db.Database.MigrateAsync();
        db.ChangeTracker.Clear();
        var active = Assert.Single(await db.EnrollmentLicenseAssignments.Where(row => row.State == "ACTIVE").ToListAsync());
        Assert.Contains(active.EnrollmentId, new[] { scenario.EnrollmentId, secondEnrollmentId });
        var recorded = await db.AssignmentEnforcementEvents.ToListAsync();
        Assert.Contains(recorded, row => row.CaseNumber == 2 && row.Reason == "enrollment_quarantined");
        Assert.Contains(recorded, row => row.CaseNumber == 6 && row.Reason == "live_seat_ambiguous");
    }

    /// <summary>
    /// Commercial sources can change without an enrollment UPDATE. Each source
    /// transition terminates or restores one assignment revision while leaving the
    /// cryptographic enrollment state and epochs untouched.
    /// </summary>
    [Fact]
    public async Task AssignmentDualWrite_BindingSeatAndLicenseMutations_TrackAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"LicenseSeats\" SET \"IsActive\" = false WHERE \"Id\" = {enrollment.LicenseSeatId}");
        db.ChangeTracker.Clear();
        Assert.Equal("seat_released",
            (await db.EnrollmentLicenseAssignments.SingleAsync()).EndReason);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"LicenseSeats\" SET \"IsActive\" = true WHERE \"Id\" = {enrollment.LicenseSeatId}");
        db.ChangeTracker.Clear();
        Assert.Equal(2,
            (await db.EnrollmentLicenseAssignments.SingleAsync(row => row.State == "ACTIVE")).Revision);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"DistributionInstallationBindings\" SET \"State\" = 'invalidated' WHERE \"Id\" = {enrollment.BindingId}");
        db.ChangeTracker.Clear();
        Assert.Equal("binding_invalidated",
            (await db.EnrollmentLicenseAssignments.SingleAsync(row => row.Revision == 2)).EndReason);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"DistributionInstallationBindings\" SET \"State\" = 'active' WHERE \"Id\" = {enrollment.BindingId}");
        db.ChangeTracker.Clear();
        Assert.Equal(3,
            (await db.EnrollmentLicenseAssignments.SingleAsync(row => row.State == "ACTIVE")).Revision);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Licenses\" SET \"CustomerName\" = 'Tkt001312-Unrelated-Edit' WHERE \"Id\" = {enrollment.LicenseId}");
        db.ChangeTracker.Clear();
        Assert.Equal(3,
            (await db.EnrollmentLicenseAssignments.SingleAsync(row => row.State == "ACTIVE")).Revision);

        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Licenses\" SET \"IsActive\" = false WHERE \"Id\" = {enrollment.LicenseId}");
        db.ChangeTracker.Clear();
        Assert.Equal("license_revoked",
            (await db.EnrollmentLicenseAssignments.SingleAsync(row => row.Revision == 3)).EndReason);
        Assert.Empty(await db.EnrollmentLicenseAssignments
            .Where(row => row.State == "ACTIVE").ToListAsync());
        var unchangedEnrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal(enrollment.State, unchangedEnrollment.State);
        Assert.Equal(enrollment.Epoch, unchangedEnrollment.Epoch);
        Assert.Equal(enrollment.SecurityEpoch, unchangedEnrollment.SecurityEpoch);
        Assert.Equal(enrollment.AuthorityEpoch, unchangedEnrollment.AuthorityEpoch);
    }
}
