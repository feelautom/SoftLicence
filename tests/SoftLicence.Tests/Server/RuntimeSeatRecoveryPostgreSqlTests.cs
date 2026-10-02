using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Options;
using Npgsql;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Proves PostgreSQL 17 applies, removes, and reapplies the F2 composite seat relation exactly,
    /// restoring the predecessor single-column relation during Down without leaving schema debris.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivationMigration_FreshUpDownUp_PreservesExactSeatRelation()
    {
        const string previousMigration = "20260829200000_AddTkt000773RuntimeSeatRecoveryKeyProof";
        const string activationMigration = "20260829214251_AddTkt000767RuntimeSeatRecoveryActivation";
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt767_f2_parity_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, database);
        var admin = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
        try
        {
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
            await using (var db = new LicenseDbContext(options))
            {
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(previousMigration);
                await migrator.MigrateAsync(activationMigration);
            }
            await using (var connection = new NpgsqlConnection(admin))
            {
                await connection.OpenAsync();
                Assert.Equal(2L, await ScalarAsync<long>(connection, """
                    SELECT count(*)::bigint AS "Value"
                    FROM pg_catalog.pg_constraint
                    WHERE conname IN (
                        'AK_RuntimeSeatRecoveryReservations_ReservationRef_LicenseSeatId',
                        'FK_RSRAuthorities_RSRReservations_ReservationRef_LicenseSeatId')
                      AND convalidated;
                    """));
            }
            await using (var db = new LicenseDbContext(options))
                await db.GetService<IMigrator>().MigrateAsync(previousMigration);
            await using (var connection = new NpgsqlConnection(admin))
            {
                await connection.OpenAsync();
                Assert.Equal(0L, await ScalarAsync<long>(connection, """
                    SELECT count(*)::bigint AS "Value"
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'RuntimeSeatRecoveryAuthorities'
                      AND column_name = 'LicenseSeatId';
                    """));
                Assert.Equal(1L, await ScalarAsync<long>(connection, """
                    SELECT count(*)::bigint AS "Value"
                    FROM pg_catalog.pg_constraint
                    WHERE conname = 'FK_RuntimeSeatRecoveryAuthorities_RuntimeSeatRecoveryReservati~'
                      AND contype = 'f' AND convalidated;
                    """));
            }
            await using (var db = new LicenseDbContext(options))
                await db.GetService<IMigrator>().MigrateAsync(activationMigration);
            await using (var connection = new NpgsqlConnection(admin))
            {
                await connection.OpenAsync();
                Assert.Equal(2L, await ScalarAsync<long>(connection, """
                    SELECT count(*)::bigint AS "Value"
                    FROM pg_catalog.pg_constraint
                    WHERE conname IN (
                        'AK_RuntimeSeatRecoveryReservations_ReservationRef_LicenseSeatId',
                        'FK_RSRAuthorities_RSRReservations_ReservationRef_LicenseSeatId')
                      AND convalidated;
                    """));
            }
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, database);
        }
    }

    /// <summary>
    /// Proves both recovery-authority generation references are lineage-qualified by real PostgreSQL
    /// foreign keys, so neither the new nor previous generation can be paired with another lineage.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryAuthority_CompositeGenerationForeignKeysRejectCrossLineagePairs()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var parsed = ParseRecoveryRequest(Guid.NewGuid(), Guid.NewGuid(), provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);
        Assert.Equal(StatusCodes.Status200OK, (await provider.Service.AuthorizeAsync(
            "website-recovery", parsed, CancellationToken.None)).StatusCode);

        await AssertRecoveryAuthorityCompositeForeignKeyAsync(connections.Admin,
            "AuthorityLineageId", provider.PreviousAuthorityLineageId,
            "FK_RSRAuthorities_REAuthorityGenerations_New");
        await using var read = await provider.Factory.CreateDbContextAsync();
        var prepared = await read.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
            item.PreviousAuthorityGenerationId == provider.PreviousAuthorityGenerationId);
        await AssertRecoveryAuthorityCompositeForeignKeyAsync(connections.Admin,
            "PreviousAuthorityLineageId", prepared.AuthorityLineageId,
            "FK_RSRAuthorities_REAuthorityGenerations_Previous");
    }

    /// <summary>
    /// Runs the real F6 migration from its populated predecessor twice: one coherent row must be
    /// backfilled and protected by both composite foreign keys, while one orphan predecessor must
    /// fail with 23503 and leave the complete pre-migration schema and row byte-for-byte observable.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryF6Migration_PopulatedPreviousSchemaBackfillsOrphanFailsAtomically()
    {
        const string previousMigration = "20260829100000_AddTkt000763RuntimeSeatRecoveryAuthorization";
        const string f6Migration = "20260829110137_CloseTkt000763F6RecoveryAuthorityIntegrity";
        var shared = await ProvisionAsync();
        var coherentDatabase = "softlicence_tkt763_f6_coherent_" + Guid.NewGuid().ToString("N");
        var orphanDatabase = "softlicence_tkt763_f6_orphan_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, coherentDatabase);
        await CreateDatabaseAsync(shared.Admin, orphanDatabase);
        try
        {
            var coherent = await SeedPreviousF6RecoveryAuthorityAsync(
                shared.Admin, coherentDatabase, previousMigration, orphanPreviousGeneration: false);
            var coherentOptions = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(coherent.Admin).Options;
            await using (var db = new LicenseDbContext(coherentOptions))
                await db.GetService<IMigrator>().MigrateAsync(f6Migration);
            await using (var connection = new NpgsqlConnection(coherent.Admin))
            {
                await connection.OpenAsync();
                Assert.Equal(coherent.PreviousLineageId, await ScalarAsync<Guid>(connection, $$"""
                    SELECT "PreviousAuthorityLineageId" AS "Value"
                    FROM public."RuntimeSeatRecoveryAuthorities"
                    WHERE "ReservationRef" = '{{coherent.ReservationRef:D}}'::uuid;
                    """));
                Assert.Equal(2L, await ScalarAsync<long>(connection, """
                    SELECT count(*)::bigint AS "Value"
                    FROM pg_catalog.pg_constraint
                    WHERE conname IN (
                        'FK_RSRAuthorities_REAuthorityGenerations_New',
                        'FK_RSRAuthorities_REAuthorityGenerations_Previous')
                      AND contype = 'f' AND convalidated AND confdeltype = 'a';
                    """));
                var definitions = await QueryStringsAsync(connection, """
                    SELECT pg_catalog.pg_get_constraintdef(oid)
                    FROM pg_catalog.pg_constraint
                    WHERE conname IN (
                        'FK_RSRAuthorities_REAuthorityGenerations_New',
                        'FK_RSRAuthorities_REAuthorityGenerations_Previous')
                    ORDER BY conname;
                    """);
                Assert.Contains(definitions, value => value.Contains(
                    "FOREIGN KEY (\"AuthorityLineageId\", \"AuthorityGenerationId\")",
                    StringComparison.Ordinal));
                Assert.Contains(definitions, value => value.Contains(
                    "FOREIGN KEY (\"PreviousAuthorityLineageId\", \"PreviousAuthorityGenerationId\")",
                    StringComparison.Ordinal));
            }

            var orphan = await SeedPreviousF6RecoveryAuthorityAsync(
                shared.Admin, orphanDatabase, previousMigration, orphanPreviousGeneration: true);
            await using var orphanConnection = new NpgsqlConnection(orphan.Admin);
            await orphanConnection.OpenAsync();
            var before = await ReadF6PreMigrationSnapshotAsync(orphanConnection, orphan.ReservationRef);
            var orphanOptions = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(orphan.Admin).Options;
            await using (var db = new LicenseDbContext(orphanOptions))
            {
                var failure = await Record.ExceptionAsync(() =>
                    db.GetService<IMigrator>().MigrateAsync(f6Migration));
                Assert.NotNull(failure);
                var postgres = Assert.IsType<PostgresException>(failure.GetBaseException());
                Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, postgres.SqlState);
                Assert.Contains("previous lineage backfill is incomplete", postgres.MessageText,
                    StringComparison.Ordinal);
            }
            var after = await ReadF6PreMigrationSnapshotAsync(orphanConnection, orphan.ReservationRef);
            Assert.Equal(before, after);
            Assert.DoesNotContain("PreviousAuthorityLineageId", after.Columns, StringComparison.Ordinal);
            Assert.Equal(previousMigration, after.LastMigration);
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, coherentDatabase);
            await DropDatabaseAsync(shared.Admin, orphanDatabase);
        }
    }

    /// <summary>
    /// Proves request expiration is decided from a fresh PostgreSQL instant obtained only after the
    /// license row lock is acquired, rather than from a stale application clock captured before waiting.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryAuthorization_ExpirationWhileWaitingForLockUsesPostLockDatabaseTime()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var databaseNow = await ReadDatabaseClockAsync(connections.Admin);
        var expiry = databaseNow.AddSeconds(1);
        var parsed = ParseRecoveryRequest(Guid.NewGuid(), Guid.NewGuid(), provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, expiry,
            new string('b', 64), provider.ArtifactDigest);
        var baseline = await ReadRecoveryCountsAsync(provider.Factory);

        await using var blocker = new NpgsqlConnection(connections.Admin);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var lockLicense = new NpgsqlCommand(
            "SELECT 1 FROM public.\"Licenses\" WHERE \"Id\" = @license FOR UPDATE;",
            blocker, blockerTransaction))
        {
            lockLicense.Parameters.AddWithValue("license", provider.LicenseId);
            await lockLicense.ExecuteNonQueryAsync();
        }
        var pending = provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);
        await WaitForBlockedRecoveryQueryAsync(blocker, blockerTransaction, "Licenses");
        var remaining = expiry - await ReadDatabaseClockAsync(blocker, blockerTransaction);
        if (remaining > TimeSpan.Zero)
            await Task.Delay(remaining + TimeSpan.FromMilliseconds(250));
        await blockerTransaction.CommitAsync();

        var result = await pending;
        Assert.Equal(StatusCodes.Status410Gone, result.StatusCode);
        var after = await ReadRecoveryCountsAsync(provider.Factory);
        Assert.Equal(baseline.Terminals + 1, after.Terminals);
        Assert.Equal(baseline with { Terminals = after.Terminals }, after);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        var terminal = await verify.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery"
            && item.RequestId == Guid.Parse(parsed.Request!.RequestId));
        Assert.True(terminal.CompletedAtUtc >= expiry);
    }

    /// <summary>
    /// Proves real PostgreSQL lock and statement timeout exhaustion is retried only to the bounded
    /// limit, then returned as a non-terminal 503 after every attempted transaction is rolled back.
    /// </summary>
    [Theory]
    [InlineData(100, 15000)]
    [InlineData(5000, 500)]
    public async Task RuntimeSeatRecoveryAuthorization_PostgresTimeoutExhaustionReturnsNonTerminal503(
        int lockTimeoutMilliseconds,
        int statementTimeoutMilliseconds)
    {
        var connections = await ProvisionAsync();
        // Distinct backend PIDs are the proof of distinct retry attempts, so this oracle must not
        // permit either the observer or the application factory to reuse a pooled connection.
        var adminConnection = new NpgsqlConnectionStringBuilder(connections.Admin)
        {
            Pooling = false
        }.ConnectionString;
        var appConnection = new NpgsqlConnectionStringBuilder(connections.App)
        {
            Pooling = false
        }.ConnectionString;
        var provider = await PrepareRecoveryProviderAsync(adminConnection, appConnection,
            lockTimeoutMilliseconds: lockTimeoutMilliseconds,
            statementTimeoutMilliseconds: statementTimeoutMilliseconds);
        var parsed = ParseRecoveryRequest(Guid.NewGuid(), Guid.NewGuid(), provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('c', 64), provider.ArtifactDigest);
        var baseline = await ReadRecoveryCountsAsync(provider.Factory);

        await using var blocker = new NpgsqlConnection(adminConnection);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);", blocker, blockerTransaction))
            await lockCommand.ExecuteNonQueryAsync();

        var pending = provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);
        var observedAttempts = await ObserveRecoveryAdvisoryLockAttemptsAsync(
            blocker, blockerTransaction, pending);
        var result = await pending;

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        Assert.Equal(3, observedAttempts);
        Assert.Contains("\"errorCode\":\"provider_unavailable\"", Encoding.UTF8.GetString(result.ExactBodyUtf8),
            StringComparison.Ordinal);
        Assert.Equal(baseline, await ReadRecoveryCountsAsync(provider.Factory));
        await blockerTransaction.RollbackAsync();
    }

    /// <summary>
    /// Proves PostgreSQL serialization and deadlock SQLSTATE exhaustion reaches the same bounded,
    /// non-terminal 503 path after every transaction-local write has been rolled back.
    /// </summary>
    [Theory]
    [InlineData("40001")]
    [InlineData("40P01")]
    public async Task RuntimeSeatRecoveryAuthorization_PostgresTransactionFailureExhaustionReturnsNonTerminal503(
        string sqlState)
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var parsed = ParseRecoveryRequest(Guid.NewGuid(), Guid.NewGuid(), provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('e', 64), provider.ArtifactDigest);
        var baseline = await ReadRecoveryCountsAsync(provider.Factory);
        var raiseSql = sqlState switch
        {
            "40001" => "RAISE EXCEPTION 'forced F6 serialization failure' USING ERRCODE = '40001';",
            "40P01" => "RAISE EXCEPTION 'forced F6 deadlock failure' USING ERRCODE = '40P01';",
            _ => throw new ArgumentOutOfRangeException(nameof(sqlState))
        };

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        try
        {
            await using (var install = new NpgsqlCommand($$"""
                CREATE SEQUENCE public.tkt763_f6_retry_attempts START WITH 1;
                GRANT USAGE, SELECT ON SEQUENCE public.tkt763_f6_retry_attempts
                    TO softlicence_runtime_test_app;
                CREATE OR REPLACE FUNCTION public.tkt763_f6_raise_transient()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $f6$
                BEGIN
                    PERFORM nextval('public.tkt763_f6_retry_attempts');
                    {{raiseSql}}
                END
                $f6$;
                CREATE TRIGGER trg_tkt763_f6_raise_transient
                BEFORE INSERT ON public."RuntimeSeatRecoveryAuthorizations"
                FOR EACH ROW EXECUTE FUNCTION public.tkt763_f6_raise_transient();
                """, admin))
                await install.ExecuteNonQueryAsync();

            var result = await provider.Service.AuthorizeAsync(
                "website-recovery", parsed, CancellationToken.None);

            Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
            Assert.Contains("\"errorCode\":\"provider_unavailable\"",
                Encoding.UTF8.GetString(result.ExactBodyUtf8), StringComparison.Ordinal);
            await using var attempts = new NpgsqlCommand(
                "SELECT last_value FROM public.tkt763_f6_retry_attempts;", admin);
            Assert.Equal(3L, Convert.ToInt64(await attempts.ExecuteScalarAsync(), CultureInfo.InvariantCulture));
            Assert.Equal(baseline, await ReadRecoveryCountsAsync(provider.Factory));
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("""
                DROP TRIGGER IF EXISTS trg_tkt763_f6_raise_transient
                    ON public."RuntimeSeatRecoveryAuthorizations";
                DROP FUNCTION IF EXISTS public.tkt763_f6_raise_transient();
                DROP SEQUENCE IF EXISTS public.tkt763_f6_retry_attempts;
                """, admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// Proves caller cancellation remains observable and is never translated into provider_unavailable
    /// while a PostgreSQL advisory lock blocks the command before any persistent effect.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryAuthorization_ExplicitCancellationIsPropagatedWithoutEffect()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App,
            lockTimeoutMilliseconds: 5000, statementTimeoutMilliseconds: 15000);
        var parsed = ParseRecoveryRequest(Guid.NewGuid(), Guid.NewGuid(), provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('d', 64), provider.ArtifactDigest);
        var baseline = await ReadRecoveryCountsAsync(provider.Factory);
        await using var blocker = new NpgsqlConnection(connections.Admin);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);", blocker, blockerTransaction))
            await lockCommand.ExecuteNonQueryAsync();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.Service.AuthorizeAsync(
            "website-recovery", parsed, cancellation.Token));

        Assert.Equal(baseline, await ReadRecoveryCountsAsync(provider.Factory));
        await blockerTransaction.RollbackAsync();
    }

    /// <summary>Proves the retry allowlist includes only the four F6 transient PostgreSQL SQLSTATEs.</summary>
    [Theory]
    [InlineData("55P03", true)]
    [InlineData("57014", true)]
    [InlineData("40001", true)]
    [InlineData("40P01", true)]
    [InlineData("23505", false)]
    [InlineData("42501", false)]
    public void RuntimeSeatRecoveryAuthorization_TransientRetryClassifierIsClosed(
        string sqlState,
        bool expected)
    {
        var classifier = typeof(RuntimeSeatRecoveryAuthorizationService).GetMethod(
            "IsRetryableTransientSqlState", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(classifier);
        Assert.Equal(expected, classifier.Invoke(null, [sqlState]));
    }

    /// <summary>
    /// Proves an EF-wrapped 57014 can never enter the transient retry catch once the caller token is
    /// canceled: cancellation classification wins and the retry classifier explicitly excludes it.
    /// </summary>
    [Fact]
    public void RuntimeSeatRecoveryAuthorization_Wrapped57014WithCanceledTokenPrioritizesCancellation()
    {
        var postgres = new PostgresException(
            "forced wrapped cancellation", "ERROR", "ERROR", PostgresErrorCodes.QueryCanceled);
        var wrapped = new InvalidOperationException("execution strategy wrapper",
            new DbUpdateException("save wrapper", postgres));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var cancellationClassifier = typeof(RuntimeSeatRecoveryAuthorizationService).GetMethod(
            "IsCallerCancellationDatabaseFailure", BindingFlags.NonPublic | BindingFlags.Static);
        var retryClassifier = typeof(RuntimeSeatRecoveryAuthorizationService).GetMethod(
            "IsRetryableTransientDatabaseFailure", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(cancellationClassifier);
        Assert.NotNull(retryClassifier);
        Assert.True((bool)cancellationClassifier.Invoke(null, [wrapped, cancellation.Token])!);
        Assert.False((bool)retryClassifier.Invoke(null, [wrapped, cancellation.Token])!);
    }

    /// <summary>Proves one provider transaction freezes exact replay and creates only RESERVED/PREPARED state.</summary>
    [Fact]
    public async Task RuntimeSeatRecoveryAuthorization_ExactReplayDoesNotActivateOrCommit()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);

        var first = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);
        var replay = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);
        var divergent = await provider.Service.AuthorizeAsync("website-recovery",
            ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
                provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
                new string('b', 64), provider.ArtifactDigest),
            CancellationToken.None);

        Assert.Equal(200, first.StatusCode);
        Assert.Equal(first.ExactBodyUtf8, replay.ExactBodyUtf8);
        Assert.Equal(409, divergent.StatusCode);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        var terminal = await verify.RuntimeSeatRecoveryAuthorizations.SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
        var reservation = await verify.RuntimeSeatRecoveryReservations.SingleAsync(item =>
            item.ReservationRef == terminal.ReservationRef);
        var prepared = await verify.RuntimeSeatRecoveryAuthorities.SingleAsync(item =>
            item.ReservationRef == terminal.ReservationRef);
        var generation = await verify.RuntimeEnrollmentAuthorityGenerations.SingleAsync(item =>
            item.AuthorityGenerationId == prepared.AuthorityGenerationId);
        Assert.Equal("RESERVED", reservation.State);
        Assert.Equal("PREPARED", prepared.State);
        Assert.Equal(provider.PreviousAuthorityLineageId, prepared.PreviousAuthorityLineageId);
        Assert.Equal(provider.PreviousAuthorityGenerationId, prepared.PreviousAuthorityGenerationId);
        Assert.Equal(0, generation.Sequence);
        Assert.Null(generation.PreviousGenerationId);
        Assert.Contains("RECOVERY_AUTHORIZED", Encoding.UTF8.GetString(generation.CanonicalPayloadUtf8),
            StringComparison.Ordinal);
        Assert.False(await verify.DistributionInstallationBindings.AnyAsync(item => item.Id == prepared.BindingId));
        Assert.False(await verify.RuntimeEnrollments.AnyAsync(item => item.Id == prepared.EnrollmentId));
    }

    /// <summary>
    /// Proves a newly authorized grant persists the exact current ownership version and remains admissible
    /// while that version is still ACTIVE, without creating any additional recovery lifecycle rows.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryReadback_CurrentOwnershipVersionRemainsAdmissible()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);
        var authorization = await provider.Service.AuthorizeAsync(
            "website-recovery", parsed, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, authorization.StatusCode);

        RuntimeSeatRecoveryAuthorization terminal;
        await using (var verify = await provider.Factory.CreateDbContextAsync())
        {
            terminal = await verify.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
            var owner = await verify.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
                && item.State == "ACTIVE");
            var grant = await verify.RuntimeRecoveryGrantOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.RecoveryOperationRef == recoveryRef);
            Assert.Equal(owner.Id, grant.CommercialOwnershipId);
        }

        var beforeReadback = await ReadRecoveryCountsAsync(provider.Factory);
        var readback = await provider.Service.ReadCurrentAsync("website-recovery",
            CurrentReadbackRequest(provider, parsed, terminal, requestId, recoveryRef),
            CancellationToken.None);

        Assert.Equal(StatusCodes.Status200OK, readback.StatusCode);
        Assert.Equal(beforeReadback, await ReadRecoveryCountsAsync(provider.Factory));
    }

    /// <summary>
    /// Proves both a transfer and an ownership-only revocation invalidate current readback by changing
    /// the ACTIVE ownership version, while the already frozen exact authorization replay remains unchanged.
    /// </summary>
    /// <param name="operation">Exact provider operation applied after the recovery grant was prepared.</param>
    [Theory]
    [InlineData("TRANSFER_OWNERSHIP")]
    [InlineData("REVOKE_OWNERSHIP")]
    public async Task RuntimeSeatRecoveryReadback_OwnershipVersionChangeRejectsButExactReplayRemainsFrozen(
        string operation)
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);
        var authorization = await provider.Service.AuthorizeAsync(
            "website-recovery", parsed, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, authorization.StatusCode);

        RuntimeSeatRecoveryAuthorization terminal;
        RuntimeRecoveryCommercialOwnership initialOwnership;
        Guid? targetSubjectId = null;
        await using (var arrange = await provider.Factory.CreateDbContextAsync())
        {
            terminal = await arrange.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
            initialOwnership = await arrange.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
                && item.State == "ACTIVE");
            if (operation == "TRANSFER_OWNERSHIP")
            {
                targetSubjectId = Guid.NewGuid();
                arrange.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
                {
                    Id = targetSubjectId.Value,
                    ProductId = provider.ProductId,
                    CreatedAtUtc = provider.Now
                });
                await arrange.SaveChangesAsync();
            }
        }

        var commands = new RuntimeRecoveryCommercialOwnershipCommandService(provider.Factory);
        await commands.ExecuteAsync(provider.ProductId,
            new RuntimeRecoveryCommercialOwnershipCommandRequest(
                Guid.NewGuid(), operation, provider.LicenseId, initialOwnership.Id, targetSubjectId),
            CancellationToken.None);

        var afterCommand = await ReadRecoveryCountsAsync(provider.Factory);
        var replay = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);
        Assert.Equal(authorization.StatusCode, replay.StatusCode);
        Assert.Equal(authorization.ContentType, replay.ContentType);
        Assert.Equal(authorization.ExactBodyUtf8, replay.ExactBodyUtf8);
        Assert.Equal(afterCommand, await ReadRecoveryCountsAsync(provider.Factory));

        var readback = await provider.Service.ReadCurrentAsync("website-recovery",
            CurrentReadbackRequest(provider, parsed, terminal, requestId, recoveryRef),
            CancellationToken.None);
        Assert.Equal(StatusCodes.Status403Forbidden, readback.StatusCode);
        Assert.Contains("\"errorCode\":\"recovery_not_authorized\"",
            Encoding.UTF8.GetString(readback.ExactBodyUtf8), StringComparison.Ordinal);
        Assert.Equal(afterCommand, await ReadRecoveryCountsAsync(provider.Factory));
    }

    /// <summary>
    /// Proves a pre-migration-style grant with no ownership-version UUID is rejected rather than inferred
    /// from its matching product, license, subject UUID, or digests, and creates no recovery resources.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryAuthorization_HistoricalNullOwnershipVersionFailsClosed()
    {
        const string previousMigration = "20260829160000_AddTkt000783CommercialOwnershipRetention";
        const string currentMigration = "20260829190000_BindTkt000784RecoveryGrantOwnershipVersion";
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt784_null_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
            var admin = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
            var app = new NpgsqlConnectionStringBuilder(admin)
            {
                Username = "softlicence_runtime_test_app",
                Password = "runtime-test-only"
            }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
            await using (var migration = new LicenseDbContext(options))
                await migration.GetService<IMigrator>().MigrateAsync(previousMigration);
            await using (var privilegeConnection = new NpgsqlConnection(admin))
            {
                await privilegeConnection.OpenAsync();
                await GrantApplicationRuntimePrivilegesAsync(privilegeConnection);
            }

            var provider = await PrepareRecoveryProviderAsync(admin, app);
            var requestId = Guid.NewGuid();
            var recoveryRef = Guid.NewGuid();
            var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
                provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
                new string('a', 64), provider.ArtifactDigest);
            var grantDigest = Convert.ToHexStringLower(SHA256.HashData(
                Encoding.UTF8.GetBytes(parsed.Request!.ProviderGrantRef)));
            await using (var arrange = await provider.Factory.CreateDbContextAsync())
            {
                var owner = await arrange.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
                    item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
                    && item.State == "ACTIVE");
                await arrange.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO public."RuntimeRecoveryGrantOwnerships"
                        ("ProductId","ProviderGrantRefDigestSha256","AuthenticatedClientId","LicenseId",
                         "OwnerSubjectId","RecoveryOperationRef","RecoveryDigestSha256","RequestId","CreatedAtUtc")
                    VALUES
                        ({provider.ProductId},{grantDigest},{"website-recovery"},{provider.LicenseId},
                         {owner.OwnerSubjectId},{recoveryRef},{parsed.Request.RecoveryDigestSha256},{requestId},
                         {provider.Now})
                    """);
            }

            await using (var migration = new LicenseDbContext(options))
                await migration.GetService<IMigrator>().MigrateAsync(currentMigration);
            await using (var verifyMigration = await provider.Factory.CreateDbContextAsync())
            {
                var historical = await verifyMigration.RuntimeRecoveryGrantOwnerships.AsNoTracking().SingleAsync(
                    item => item.ProductId == provider.ProductId && item.RecoveryOperationRef == recoveryRef);
                Assert.Null(historical.CommercialOwnershipId);
            }
            var baseline = await ReadRecoveryCountsAsync(provider.Factory);

            var result = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);

            Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
            Assert.Contains("\"errorCode\":\"recovery_not_authorized\"",
                Encoding.UTF8.GetString(result.ExactBodyUtf8), StringComparison.Ordinal);
            var observed = await ReadRecoveryCountsAsync(provider.Factory);
            Assert.Equal(baseline.Terminals + 1, observed.Terminals);
            Assert.Equal(baseline with { Terminals = observed.Terminals }, observed);
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, database);
        }
    }

    /// <summary>
    /// Proves current readback must bind the exact ownership version rather than accepting a later
    /// A→B→A lineage solely because the opaque subject UUID and its digest match the prepared grant.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryReadback_OwnershipAtoBtoSameSubjectAMustRejectPreparedGrant()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);
        var authorization = await provider.Service.AuthorizeAsync(
            "website-recovery", parsed, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, authorization.StatusCode);

        RuntimeSeatRecoveryAuthorization terminal;
        RuntimeRecoveryCommercialOwnership firstOwnershipA;
        var subjectB = Guid.NewGuid();
        await using (var arrange = await provider.Factory.CreateDbContextAsync())
        {
            terminal = await arrange.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
            firstOwnershipA = await arrange.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
                && item.State == "ACTIVE");
            arrange.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
            {
                Id = subjectB,
                ProductId = provider.ProductId,
                CreatedAtUtc = provider.Now
            });
            await arrange.SaveChangesAsync();
        }

        var commands = new RuntimeRecoveryCommercialOwnershipCommandService(provider.Factory);
        await commands.ExecuteAsync(provider.ProductId,
            new RuntimeRecoveryCommercialOwnershipCommandRequest(
                Guid.NewGuid(), "TRANSFER_OWNERSHIP", provider.LicenseId, firstOwnershipA.Id, subjectB),
            CancellationToken.None);
        RuntimeRecoveryCommercialOwnership ownershipB;
        await using (var readB = await provider.Factory.CreateDbContextAsync())
        {
            ownershipB = await readB.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
                && item.State == "ACTIVE");
        }

        await commands.ExecuteAsync(provider.ProductId,
            new RuntimeRecoveryCommercialOwnershipCommandRequest(
                Guid.NewGuid(), "TRANSFER_OWNERSHIP", provider.LicenseId, ownershipB.Id,
                firstOwnershipA.OwnerSubjectId), CancellationToken.None);
        RuntimeRecoveryCommercialOwnership secondOwnershipA;
        await using (var readA = await provider.Factory.CreateDbContextAsync())
        {
            secondOwnershipA = await readA.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
                && item.State == "ACTIVE");
            var grant = await readA.RuntimeRecoveryGrantOwnerships.AsNoTracking().SingleAsync(item =>
                item.ProductId == provider.ProductId && item.RecoveryOperationRef == recoveryRef);
            var prepared = await readA.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
                item.ReservationRef == terminal.ReservationRef);
            Assert.NotEqual(firstOwnershipA.Id, secondOwnershipA.Id);
            Assert.Equal(ownershipB.Id, secondOwnershipA.PreviousOwnershipId);
            Assert.Equal(firstOwnershipA.OwnerSubjectId, secondOwnershipA.OwnerSubjectId);
            Assert.Equal(firstOwnershipA.Id, grant.CommercialOwnershipId);
            Assert.Equal(grant.OwnerSubjectId, secondOwnershipA.OwnerSubjectId);
            Assert.Equal(prepared.SubjectRefDigestSha256,
                RecoveryOwnerSubjectDigest(secondOwnershipA.OwnerSubjectId));
        }

        var beforeReadback = await ReadRecoveryCountsAsync(provider.Factory);
        var replay = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);
        Assert.Equal(authorization.StatusCode, replay.StatusCode);
        Assert.Equal(authorization.ContentType, replay.ContentType);
        Assert.Equal(authorization.ExactBodyUtf8, replay.ExactBodyUtf8);
        Assert.Equal(beforeReadback, await ReadRecoveryCountsAsync(provider.Factory));
        var readback = await provider.Service.ReadCurrentAsync("website-recovery",
            CurrentReadbackRequest(provider, parsed, terminal, requestId, recoveryRef),
            CancellationToken.None);

        Assert.Equal(StatusCodes.Status403Forbidden, readback.StatusCode);
        Assert.Contains("\"errorCode\":\"recovery_not_authorized\"",
            Encoding.UTF8.GetString(readback.ExactBodyUtf8), StringComparison.Ordinal);
        Assert.Equal(beforeReadback, await ReadRecoveryCountsAsync(provider.Factory));
    }

    /// <summary>
    /// Reproduces the provider's canonical domain-separated digest over the lowercase D-format
    /// opaque owner UUID so the regression proves subject equality without exposing that UUID.
    /// </summary>
    /// <param name="ownerSubjectId">Exact provider-owned commercial-subject UUID.</param>
    /// <returns>The lowercase SHA-256 digest compared by current recovery readback.</returns>
    private static string RecoveryOwnerSubjectDigest(Guid ownerSubjectId)
    {
        ReadOnlySpan<byte> domain = "SOFTLICENCE\0RUNTIME-RECOVERY-OWNER\0V1"u8;
        var owner = Encoding.ASCII.GetBytes(ownerSubjectId.ToString("D"));
        var input = new byte[domain.Length + 1 + owner.Length];
        domain.CopyTo(input);
        input[domain.Length] = 0x0a;
        owner.CopyTo(input, domain.Length + 1);
        try
        {
            return Convert.ToHexStringLower(SHA256.HashData(input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    /// <summary>
    /// Creates the canonical current-readback request for an already frozen authorization terminal without
    /// changing UUID, digest, or reservation text. The caller remains responsible for invoking the service.
    /// </summary>
    /// <param name="provider">The exact isolated provider scope that produced the terminal.</param>
    /// <param name="parsed">The canonical authorization parse result whose digest is replayed verbatim.</param>
    /// <param name="terminal">The frozen authorization terminal owning the reservation reference.</param>
    /// <param name="requestId">The exact request UUID from the authorization namespace.</param>
    /// <param name="recoveryRef">The exact recovery-operation UUID bound to the grant.</param>
    /// <returns>A byte-contract-equivalent readback DTO using lowercase D-format UUID text.</returns>
    private static RuntimeSeatRecoveryCurrentReadbackRequest CurrentReadbackRequest(
        RecoveryProviderScenario provider,
        RuntimeSeatRecoveryContractCodec.AuthorizationParseResult parsed,
        RuntimeSeatRecoveryAuthorization terminal,
        Guid requestId,
        Guid recoveryRef) => new()
        {
            Schema = "runtime-seat-recovery-current-readback-v1",
            ContractVersion = 1,
            ProductId = provider.ProductId.ToString("D"),
            RequestId = requestId.ToString("D"),
            RequestDigestSha256 = parsed.RequestDigestSha256!,
            RecoveryOperationRef = recoveryRef.ToString("D"),
            ReservationRef = terminal.ReservationRef!.Value.ToString("D")
        };

    /// <summary>
    /// Proves the PG-F4-1..10 matrix isolates terminal idempotency by authenticated client while
    /// preserving globally unique authorized resources, frozen exact replay, and the first winner.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryAuthorization_InterClientNamespaceFreezesSecondClientWithoutChangingWinner()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);

        // PG-F4-1: client A owns the authorized resource tuple.
        var authorizedA = await provider.Service.AuthorizeAsync("website-recovery-a", parsed, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, authorizedA.StatusCode);
        var countsAfterA = await ReadRecoveryCountsAsync(provider.Factory);
        RuntimeSeatRecoveryAuthorization frozenA;
        await using (var readA = await provider.Factory.CreateDbContextAsync())
        {
            frozenA = await readA.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery-a" && item.RequestId == requestId);
        }

        // PG-F4-2: A's exact retry is byte-for-byte stable and creates no row.
        var replayA = await provider.Service.AuthorizeAsync("website-recovery-a", parsed, CancellationToken.None);
        Assert.Equal(authorizedA.ContentType, replayA.ContentType);
        Assert.Equal(authorizedA.ExactBodyUtf8, replayA.ExactBodyUtf8);
        Assert.Equal(countsAfterA, await ReadRecoveryCountsAsync(provider.Factory));

        // PG-F4-3: B receives its own frozen 403 for the same request and operation references.
        var refusedB = await provider.Service.AuthorizeAsync("website-recovery-b", parsed, CancellationToken.None);
        Assert.Equal(StatusCodes.Status403Forbidden, refusedB.StatusCode);
        Assert.Contains("\"errorCode\":\"recovery_not_authorized\"", Encoding.UTF8.GetString(refusedB.ExactBodyUtf8),
            StringComparison.Ordinal);
        var countsAfterB = await ReadRecoveryCountsAsync(provider.Factory);
        Assert.Equal(countsAfterA.Terminals + 1, countsAfterB.Terminals);
        Assert.Equal(countsAfterA with { Terminals = countsAfterB.Terminals }, countsAfterB);
        RuntimeSeatRecoveryAuthorization frozenB;
        await using (var readB = await provider.Factory.CreateDbContextAsync())
        {
            frozenB = await readB.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery-b" && item.RequestId == requestId);
        }
        Assert.Equal(frozenB.ExactResponseUtf8, refusedB.ExactBodyUtf8);

        // PG-F4-4: B's exact retry preserves status, media type, bytes, and completed time.
        var replayB = await provider.Service.AuthorizeAsync("website-recovery-b", parsed, CancellationToken.None);
        Assert.Equal(refusedB.StatusCode, replayB.StatusCode);
        Assert.Equal(refusedB.ContentType, replayB.ContentType);
        Assert.Equal(refusedB.ExactBodyUtf8, replayB.ExactBodyUtf8);
        Assert.Equal(countsAfterB, await ReadRecoveryCountsAsync(provider.Factory));
        await using (var replayRead = await provider.Factory.CreateDbContextAsync())
        {
            var replayedB = await replayRead.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery-b" && item.RequestId == requestId);
            Assert.Equal(frozenB.CompletedAtUtc, replayedB.CompletedAtUtc);
        }

        // PG-F4-5: B cannot alter A's frozen winner or its exact replay.
        var replayAAfterB = await provider.Service.AuthorizeAsync("website-recovery-a", parsed, CancellationToken.None);
        Assert.Equal(authorizedA.ExactBodyUtf8, replayAAfterB.ExactBodyUtf8);
        await using (var winnerRead = await provider.Factory.CreateDbContextAsync())
        {
            var winner = await winnerRead.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery-a" && item.RequestId == requestId);
            Assert.Equal(frozenA.ExactResponseUtf8, winner.ExactResponseUtf8);
            Assert.Equal(frozenA.CompletedAtUtc, winner.CompletedAtUtc);
        }

        var divergentProvider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var divergentRequestId = Guid.NewGuid();
        var divergentRecoveryRef = Guid.NewGuid();
        var divergentA = ParseRecoveryRequest(divergentRequestId, divergentRecoveryRef,
            divergentProvider.ProductId, divergentProvider.LicenseId, divergentProvider.InstallationId,
            divergentProvider.HardwareDigest, divergentProvider.Now.AddMinutes(10), new string('2', 64),
            divergentProvider.ArtifactDigest);
        Assert.Equal(StatusCodes.Status200OK, (await divergentProvider.Service.AuthorizeAsync(
            "website-recovery-a", divergentA, CancellationToken.None)).StatusCode);
        var divergentB = ParseRecoveryRequest(divergentRequestId, divergentRecoveryRef,
            divergentProvider.ProductId, divergentProvider.LicenseId, divergentProvider.InstallationId,
            divergentProvider.HardwareDigest, divergentProvider.Now.AddMinutes(10), new string('3', 64),
            divergentProvider.ArtifactDigest);
        var divergentBaseline = await ReadRecoveryCountsAsync(divergentProvider.Factory);

        // PG-F4-6: B's divergent tuple is a frozen 403, never a cross-namespace 409.
        var divergentRefusal = await divergentProvider.Service.AuthorizeAsync(
            "website-recovery-b", divergentB, CancellationToken.None);
        Assert.Equal(StatusCodes.Status403Forbidden, divergentRefusal.StatusCode);
        var divergentFrozen = await ReadRecoveryCountsAsync(divergentProvider.Factory);
        Assert.Equal(divergentBaseline.Terminals + 1, divergentFrozen.Terminals);
        Assert.Equal(divergentBaseline with { Terminals = divergentFrozen.Terminals }, divergentFrozen);

        // PG-F4-7: the divergent B refusal is itself an exact replay.
        var divergentReplay = await divergentProvider.Service.AuthorizeAsync(
            "website-recovery-b", divergentB, CancellationToken.None);
        Assert.Equal(divergentRefusal.ExactBodyUtf8, divergentReplay.ExactBodyUtf8);
        Assert.Equal(divergentFrozen, await ReadRecoveryCountsAsync(divergentProvider.Factory));

        var crossGrantProvider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var crossGrantRequestId = Guid.NewGuid();
        var crossGrantRecoveryRef = Guid.NewGuid();
        var crossGrantA = ParseRecoveryRequest(crossGrantRequestId, crossGrantRecoveryRef,
            crossGrantProvider.ProductId, crossGrantProvider.LicenseId, crossGrantProvider.InstallationId,
            crossGrantProvider.HardwareDigest, crossGrantProvider.Now.AddMinutes(10), new string('4', 64),
            crossGrantProvider.ArtifactDigest);
        Assert.Equal(StatusCodes.Status200OK, (await crossGrantProvider.Service.AuthorizeAsync(
            "website-recovery-a", crossGrantA, CancellationToken.None)).StatusCode);
        await using (var addSeat = await crossGrantProvider.Factory.CreateDbContextAsync())
        {
            addSeat.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = crossGrantProvider.LicenseId,
                HardwareId = "PG-F4-second-available-seat",
                FirstActivatedAt = crossGrantProvider.Now,
                LastCheckInAt = crossGrantProvider.Now,
                IsActive = true
            });
            await addSeat.SaveChangesAsync();
        }
        var crossGrantB = ParseRecoveryRequest(crossGrantRequestId, crossGrantRecoveryRef,
            crossGrantProvider.ProductId, crossGrantProvider.LicenseId, crossGrantProvider.InstallationId,
            crossGrantProvider.HardwareDigest, crossGrantProvider.Now.AddMinutes(10), new string('4', 64),
            crossGrantProvider.ArtifactDigest, "provider-recovery-grant-b");
        var crossGrantBaseline = await ReadRecoveryCountsAsync(crossGrantProvider.Factory);

        // PG-F4-8: a second available seat cannot bypass the operation-to-grant cross-link refusal.
        var crossGrantRefusal = await crossGrantProvider.Service.AuthorizeAsync(
            "website-recovery-b", crossGrantB, CancellationToken.None);
        Assert.Equal(StatusCodes.Status403Forbidden, crossGrantRefusal.StatusCode);
        var crossGrantFrozen = await ReadRecoveryCountsAsync(crossGrantProvider.Factory);
        Assert.Equal(crossGrantBaseline.Terminals + 1, crossGrantFrozen.Terminals);
        Assert.Equal(crossGrantBaseline with { Terminals = crossGrantFrozen.Terminals }, crossGrantFrozen);

        var concurrentProvider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var concurrentRequestId = Guid.NewGuid();
        var concurrentRecoveryRef = Guid.NewGuid();
        var concurrentParsed = ParseRecoveryRequest(concurrentRequestId, concurrentRecoveryRef,
            concurrentProvider.ProductId, concurrentProvider.LicenseId, concurrentProvider.InstallationId,
            concurrentProvider.HardwareDigest, concurrentProvider.Now.AddMinutes(10), new string('5', 64),
            concurrentProvider.ArtifactDigest);
        await using var blocker = new NpgsqlConnection(connections.Admin);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);", blocker, blockerTransaction))
            await lockCommand.ExecuteNonQueryAsync();
        var concurrentA = concurrentProvider.Service.AuthorizeAsync(
            "website-recovery-a", concurrentParsed, CancellationToken.None);
        await WaitForRecoveryAdvisoryWaitersAsync(blocker, blockerTransaction, 1);
        var concurrentB = concurrentProvider.Service.AuthorizeAsync(
            "website-recovery-b", concurrentParsed, CancellationToken.None);
        await WaitForRecoveryAdvisoryWaitersAsync(blocker, blockerTransaction, 2);
        await blockerTransaction.CommitAsync();

        // PG-F4-9: ordered concurrent clients expose no 23505/500; A wins and B freezes 403.
        var concurrentResults = await Task.WhenAll(concurrentA, concurrentB);
        Assert.Equal(StatusCodes.Status200OK, concurrentResults[0].StatusCode);
        Assert.Equal(StatusCodes.Status403Forbidden, concurrentResults[1].StatusCode);

        // PG-F4-10: a later body change conflicts only with B's own frozen command namespace.
        var changedB = ParseRecoveryRequest(concurrentRequestId, concurrentRecoveryRef,
            concurrentProvider.ProductId, concurrentProvider.LicenseId, concurrentProvider.InstallationId,
            concurrentProvider.HardwareDigest, concurrentProvider.Now.AddMinutes(10), new string('6', 64),
            concurrentProvider.ArtifactDigest);
        var beforeConflict = await ReadRecoveryCountsAsync(concurrentProvider.Factory);
        var conflictB = await concurrentProvider.Service.AuthorizeAsync(
            "website-recovery-b", changedB, CancellationToken.None);
        Assert.Equal(StatusCodes.Status409Conflict, conflictB.StatusCode);
        Assert.Equal(beforeConflict, await ReadRecoveryCountsAsync(concurrentProvider.Factory));
        var finalReplayA = await concurrentProvider.Service.AuthorizeAsync(
            "website-recovery-a", concurrentParsed, CancellationToken.None);
        Assert.Equal(concurrentResults[0].ExactBodyUtf8, finalReplayA.ExactBodyUtf8);
    }

    /// <summary>
    /// Proves recovery never projects an ACTIVE predecessor from a superseded, pending, divergent,
    /// historical, or cross-grant provider tuple and creates no recovery side effect on refusal.
    /// </summary>
    [Theory]
    [InlineData("binding_superseded")]
    [InlineData("enrollment_pending")]
    [InlineData("payload_divergent")]
    [InlineData("historical_head")]
    [InlineData("grant_divergent")]
    public async Task RuntimeSeatRecoveryAuthorization_PreviousAuthorityMustBeExactActiveHead(
        string failure)
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App, failure);
        int reservationCount;
        int authorityCount;
        int generationCount;
        await using (var baseline = await provider.Factory.CreateDbContextAsync())
        {
            reservationCount = await baseline.RuntimeSeatRecoveryReservations.CountAsync();
            authorityCount = await baseline.RuntimeSeatRecoveryAuthorities.CountAsync();
            generationCount = await baseline.RuntimeEnrollmentAuthorityGenerations.CountAsync();
        }
        var requestId = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, Guid.NewGuid(), provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10), new string('a', 64),
            provider.ArtifactDigest);

        var result = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);

        Assert.Equal(409, result.StatusCode);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        var terminal = await verify.RuntimeSeatRecoveryAuthorizations.SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
        Assert.Equal("REFUSED", terminal.Decision);
        Assert.Equal("authority_state_conflict", terminal.ErrorCode);
        Assert.Equal(reservationCount, await verify.RuntimeSeatRecoveryReservations.CountAsync());
        Assert.Equal(authorityCount, await verify.RuntimeSeatRecoveryAuthorities.CountAsync());
        Assert.Equal(generationCount, await verify.RuntimeEnrollmentAuthorityGenerations.CountAsync());
    }

    /// <summary>
    /// Proves current readback revalidates the persisted previous-authority head instead of replaying
    /// the projected ACTIVE scalar after its durable binding ceases to be active.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryReadback_PreviousAuthorityConflictIsRevalidatedWithoutSideEffects()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId, provider.LicenseId,
            provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest);
        var authorization = await provider.Service.AuthorizeAsync(
            "website-recovery", parsed, CancellationToken.None);
        Assert.Equal(200, authorization.StatusCode);

        RuntimeSeatRecoveryAuthorization terminal;
        int reservationCount;
        int authorityCount;
        int generationCount;
        await using (var mutate = await provider.Factory.CreateDbContextAsync())
        {
            terminal = await mutate.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
            var previousBinding = await mutate.DistributionInstallationBindings.SingleAsync(item =>
                item.Id == provider.PreviousAuthorityBindingId);
            previousBinding.State = "superseded";
            await mutate.SaveChangesAsync();
            reservationCount = await mutate.RuntimeSeatRecoveryReservations.CountAsync();
            authorityCount = await mutate.RuntimeSeatRecoveryAuthorities.CountAsync();
            generationCount = await mutate.RuntimeEnrollmentAuthorityGenerations.CountAsync();
        }

        var readback = await provider.Service.ReadCurrentAsync("website-recovery",
            new RuntimeSeatRecoveryCurrentReadbackRequest
            {
                Schema = "runtime-seat-recovery-current-readback-v1",
                ContractVersion = 1,
                ProductId = provider.ProductId.ToString("D"),
                RequestId = requestId.ToString("D"),
                RequestDigestSha256 = parsed.RequestDigestSha256!,
                RecoveryOperationRef = recoveryRef.ToString("D"),
                ReservationRef = terminal.ReservationRef!.Value.ToString("D")
            }, CancellationToken.None);

        Assert.Equal(200, readback.StatusCode);
        using var body = JsonDocument.Parse(readback.ExactBodyUtf8);
        Assert.Equal("conflict", body.RootElement.GetProperty("status").GetString());
        Assert.Equal("conflict", body.RootElement.GetProperty("previousAuthority")
            .GetProperty("state").GetString());
        await using var verify = await provider.Factory.CreateDbContextAsync();
        Assert.Equal(reservationCount, await verify.RuntimeSeatRecoveryReservations.CountAsync());
        Assert.Equal(authorityCount, await verify.RuntimeSeatRecoveryAuthorities.CountAsync());
        Assert.Equal(generationCount, await verify.RuntimeEnrollmentAuthorityGenerations.CountAsync());
    }

    /// <summary>
    /// Proves every provider-authority mismatch is refused before reservation, recovery authority,
    /// or generation creation while the refusal itself remains a frozen PostgreSQL terminal.
    /// </summary>
    [Theory]
    [InlineData("hardware")]
    [InlineData("release")]
    [InlineData("approved_binaries")]
    [InlineData("hardware_ban")]
    [InlineData("component_ban")]
    [InlineData("key_commitment")]
    public async Task RuntimeSeatRecoveryAuthorization_ProviderRevalidationRejectsWithoutSideEffects(
        string failure)
    {
        // These negative cases intentionally persist provider bans and authority mutations. An owned
        // database prevents that evidence from contaminating unrelated shared-harness validators.
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (isolated.Admin, isolated.App);
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        await using (var mutate = await provider.Factory.CreateDbContextAsync())
        {
            switch (failure)
            {
                case "release":
                    (await mutate.Licenses.SingleAsync(item => item.Id == provider.LicenseId)).AllowedVersions = "9.*";
                    break;
                case "approved_binaries":
                    (await mutate.ApprovedBinaries.SingleAsync(item => item.ProductId == provider.ProductId
                        && item.Version == "2.3.445" && item.Key == "FP_EXE")).Hash = new string('9', 64);
                    break;
                case "hardware_ban":
                    mutate.BannedHardwareIds.Add(new BannedHardwareId
                    {
                        HardwareId = provider.HardwareId,
                        ProductId = provider.ProductId,
                        IsActive = true,
                        BannedAt = provider.Now,
                        Reason = "TKT-000763 F1 PostgreSQL negative"
                    });
                    break;
                case "component_ban":
                    var executableHash = await mutate.ApprovedBinaries.AsNoTracking().Where(item =>
                            item.ProductId == provider.ProductId && item.Version == "2.3.445"
                            && item.Key == "FP_EXE")
                        .Select(item => item.Hash).SingleAsync();
                    mutate.BannedComponents.Add(new BannedComponent
                    {
                        ComponentType = "FP_EXE",
                        ComponentHash = executableHash,
                        ProductId = provider.ProductId,
                        IsActive = true,
                        BannedAt = provider.Now,
                        Reason = "TKT-000763 F1 PostgreSQL negative"
                    });
                    break;
            }
            await mutate.SaveChangesAsync();
        }

        int reservationCount;
        int authorityCount;
        int generationCount;
        await using (var baseline = await provider.Factory.CreateDbContextAsync())
        {
            reservationCount = await baseline.RuntimeSeatRecoveryReservations.CountAsync();
            authorityCount = await baseline.RuntimeSeatRecoveryAuthorities.CountAsync();
            generationCount = await baseline.RuntimeEnrollmentAuthorityGenerations.CountAsync();
        }
        var hardwareDigest = failure == "hardware" ? new string('8', 64) : provider.HardwareDigest;
        var requestId = Guid.NewGuid();
        var parsed = ParseRecoveryRequest(requestId, Guid.NewGuid(), provider.ProductId, provider.LicenseId,
            provider.InstallationId, hardwareDigest, provider.Now.AddMinutes(10), new string('a', 64),
            provider.ArtifactDigest);
        if (failure == "key_commitment")
            parsed.Request!.NewKeyCommitment.KeyThumbprint = Base64Url(Enumerable.Repeat((byte)0x7a, 32).ToArray());

        var result = await provider.Service.AuthorizeAsync("website-recovery", parsed, CancellationToken.None);

        Assert.Equal(403, result.StatusCode);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        var terminal = await verify.RuntimeSeatRecoveryAuthorizations.SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery" && item.RequestId == requestId);
        Assert.Equal("REFUSED", terminal.Decision);
        Assert.Equal("recovery_not_authorized", terminal.ErrorCode);
        Assert.Equal(reservationCount, await verify.RuntimeSeatRecoveryReservations.CountAsync());
        Assert.Equal(authorityCount, await verify.RuntimeSeatRecoveryAuthorities.CountAsync());
        Assert.Equal(generationCount, await verify.RuntimeEnrollmentAuthorityGenerations.CountAsync());
    }

    /// <summary>
    /// Proves the complete W10.2 provider ceremony on PostgreSQL: preparation is idempotent, cross-product
    /// attempts have no one-shot effect, one concurrent confirmation wins, every reader gets frozen bytes,
    /// W10 and W10.2 equal the immutable signed-generation epoch, and the resulting receipt stops at PROVED
    /// with the exact minimum expiry.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryKeyProof_W10Point2_IsAtomicByteExactAndInert()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        using var runtimeKey = RSA.Create(3072);
        var spki = runtimeKey.ExportSubjectPublicKeyInfo();
        var spkiDigest = Convert.ToHexStringLower(SHA256.HashData(spki));
        var thumbprint = Base64Url(SHA256.HashData(spki));
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var authorizationRequest = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest, publicKeySpkiSha256: spkiDigest,
            keyThumbprint: thumbprint);
        Assert.Equal(200, (await provider.Service.AuthorizeAsync(
            "website-recovery", authorizationRequest, CancellationToken.None)).StatusCode);

        RuntimeSeatRecoveryReservation reservation;
        RuntimeSeatRecoveryAuthority authority;
        await using (var scope = await provider.Factory.CreateDbContextAsync())
        {
            reservation = await scope.RuntimeSeatRecoveryReservations.AsNoTracking()
                .SingleAsync(item => item.RequestId == requestId);
            authority = await scope.RuntimeSeatRecoveryAuthorities.AsNoTracking()
                .SingleAsync(item => item.ReservationRef == reservation.ReservationRef);
        }
        var preparationBody = BuildKeyPreparationBody(provider.ProductId, requestId,
            authorizationRequest.RequestDigestSha256!, recoveryRef, reservation.ReservationRef,
            authority.EnrollmentId, authority.AuthorityGenerationId, Convert.ToBase64String(spki));
        var preparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(
            Encoding.UTF8.GetBytes(preparationBody));
        Assert.True(preparation.IsSuccess, preparation.ErrorCode);
        Assert.Equal(1078, preparation.CanonicalUtf8.Length);

        var prepareAttempts = await Task.WhenAll(
            provider.Service.PrepareKeyAsync("website-recovery", requestId.ToString("D"), preparation,
                CancellationToken.None),
            provider.Service.PrepareKeyAsync("website-recovery", requestId.ToString("D"), preparation,
                CancellationToken.None));
        Assert.All(prepareAttempts, result => Assert.Equal(200, result.StatusCode));
        Assert.Equal(prepareAttempts[0].ExactBodyUtf8, prepareAttempts[1].ExactBodyUtf8);
        using var preparationResponse = JsonDocument.Parse(prepareAttempts[0].ExactBodyUtf8);
        var prepareRef = Guid.Parse(preparationResponse.RootElement.GetProperty("prepareRef").GetString()!);
        var challenge = preparationResponse.RootElement.GetProperty("challenge").GetString()!;
        Assert.Equal(1, preparationResponse.RootElement.GetProperty("securityEpoch").GetInt32());
        Assert.Contains(
            $"\"authorityGenerationId\":\"{authority.AuthorityGenerationId:D}\",\"securityEpoch\":1,\"challenge\"",
            Encoding.UTF8.GetString(prepareAttempts[0].ExactBodyUtf8), StringComparison.Ordinal);

        var otherProduct = Guid.NewGuid();
        var crossProductPreparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(
            Encoding.UTF8.GetBytes(preparationBody.Replace(provider.ProductId.ToString("D"),
                otherProduct.ToString("D"), StringComparison.Ordinal)));
        Assert.True(crossProductPreparation.IsSuccess);
        Assert.Equal(403, (await provider.Service.PrepareKeyAsync("website-recovery", requestId.ToString("D"),
            crossProductPreparation, CancellationToken.None)).StatusCode);

        var statement = BuildKeyConfirmationStatement(prepareRef, requestId,
            authorizationRequest.RequestDigestSha256!, recoveryRef, reservation.ReservationRef,
            authority.EnrollmentId, authority.AuthorityGenerationId, challenge);
        Assert.Equal(628, Encoding.UTF8.GetByteCount(statement));
        var signatureInput = RuntimeSeatRecoveryContractCodec.BuildConfirmationSignatureInput(
            Encoding.UTF8.GetBytes(statement));
        var signature = Base64Url(runtimeKey.SignData(signatureInput, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
        var confirmationBody = BuildKeyConfirmationBody(provider.ProductId, requestId,
            authorizationRequest.RequestDigestSha256!, recoveryRef, reservation.ReservationRef, prepareRef,
            authority.EnrollmentId, authority.AuthorityGenerationId, spkiDigest, statement, signature);
        var confirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(confirmationBody));
        Assert.True(confirmation.IsSuccess, confirmation.ErrorCode);
        Assert.Equal(1873, confirmation.CanonicalUtf8.Length);

        var crossProductConfirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(confirmationBody.Replace(provider.ProductId.ToString("D"),
                otherProduct.ToString("D"), StringComparison.Ordinal)));
        Assert.True(crossProductConfirmation.IsSuccess);
        Assert.Equal(403, (await provider.Service.ConfirmKeyAsync("website-recovery", requestId.ToString("D"),
            crossProductConfirmation, CancellationToken.None)).StatusCode);
        await using (var untouched = await provider.Factory.CreateDbContextAsync())
            Assert.Null((await untouched.RuntimeSeatRecoveryKeyPreparations.AsNoTracking()
                .SingleAsync(item => item.RequestId == requestId)).ChallengeConsumedAtUtc);

        var confirmationAttempts = await Task.WhenAll(
            provider.Service.ConfirmKeyAsync("website-recovery", requestId.ToString("D"), confirmation,
                CancellationToken.None),
            provider.Service.ConfirmKeyAsync("website-recovery", requestId.ToString("D"), confirmation,
                CancellationToken.None));
        Assert.All(confirmationAttempts, result => Assert.Equal(200, result.StatusCode));
        Assert.Equal(confirmationAttempts[0].ExactBodyUtf8, confirmationAttempts[1].ExactBodyUtf8);
        Assert.Equal(872, confirmationAttempts[0].ExactBodyUtf8.Length);
        Assert.Contains("\"provedAtUtc\":", Encoding.UTF8.GetString(confirmationAttempts[0].ExactBodyUtf8),
            StringComparison.Ordinal);
        using var proofResponse = JsonDocument.Parse(confirmationAttempts[0].ExactBodyUtf8);
        Assert.Equal(1, proofResponse.RootElement.GetProperty("securityEpoch").GetInt32());
        Assert.Contains(
            $"\"authorityGenerationId\":\"{authority.AuthorityGenerationId:D}\",\"securityEpoch\":1,\"publicKeySpkiSha256\"",
            Encoding.UTF8.GetString(confirmationAttempts[0].ExactBodyUtf8), StringComparison.Ordinal);

        const string signaturePrefix = "\"confirmationSignature\":\"";
        var signatureOffset = confirmationBody.IndexOf(signaturePrefix, StringComparison.Ordinal)
            + signaturePrefix.Length;
        var replacement = confirmationBody[signatureOffset] == 'A' ? 'B' : 'A';
        var divergentBody = confirmationBody[..signatureOffset] + replacement
            + confirmationBody[(signatureOffset + 1)..];
        var divergent = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(divergentBody));
        Assert.True(divergent.IsSuccess, divergent.ErrorCode);
        Assert.Equal(409, (await provider.Service.ConfirmKeyAsync("website-recovery", requestId.ToString("D"),
            divergent, CancellationToken.None)).StatusCode);

        await using var verify = await provider.Factory.CreateDbContextAsync();
        var storedPreparation = await verify.RuntimeSeatRecoveryKeyPreparations.AsNoTracking()
            .SingleAsync(item => item.RequestId == requestId);
        var storedConfirmation = await verify.RuntimeSeatRecoveryKeyConfirmations.AsNoTracking()
            .SingleAsync(item => item.PrepareRef == prepareRef);
        var receipt = await verify.RuntimeSeatRecoveryProofReceipts.AsNoTracking()
            .SingleAsync(item => item.PrepareRef == prepareRef);
        var signedGeneration = await verify.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleAsync(item => item.AuthorityGenerationId == authority.AuthorityGenerationId);
        var signedPayload = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
            signedGeneration.CanonicalPayloadUtf8)!;
        var unchangedReservation = await verify.RuntimeSeatRecoveryReservations.AsNoTracking()
            .SingleAsync(item => item.ReservationRef == reservation.ReservationRef);
        var unchangedAuthority = await verify.RuntimeSeatRecoveryAuthorities.AsNoTracking()
            .SingleAsync(item => item.ReservationRef == reservation.ReservationRef);
        Assert.NotNull(storedPreparation.ChallengeConsumedAtUtc);
        Assert.Equal("PROVED", storedConfirmation.State);
        Assert.Equal("PROVED", receipt.State);
        Assert.Equal(storedPreparation.ExpiresAtUtc <= unchangedReservation.ExpiresAtUtc
            ? storedPreparation.ExpiresAtUtc : unchangedReservation.ExpiresAtUtc, receipt.ExpiresAtUtc);
        Assert.Equal(confirmationAttempts[0].ExactBodyUtf8, storedConfirmation.ExactResponseUtf8);
        Assert.Equal(signedPayload.Key.SecurityEpoch,
            preparationResponse.RootElement.GetProperty("securityEpoch").GetInt32());
        Assert.Equal(signedPayload.Key.SecurityEpoch,
            proofResponse.RootElement.GetProperty("securityEpoch").GetInt32());
        Assert.Equal("RESERVED", unchangedReservation.State);
        Assert.Equal("PREPARED", unchangedAuthority.State);
        Assert.Equal("ACTIVE", unchangedAuthority.PreviousAuthorityState);

        await using var immutableConnection = new NpgsqlConnection(connections.Admin);
        await immutableConnection.OpenAsync();
        var immutableFailure = await Record.ExceptionAsync(() => ExecuteAsync(immutableConnection, $$"""
            DELETE FROM public."RuntimeSeatRecoveryProofReceipts"
            WHERE "AuthenticatedClientId" = 'website-recovery'
              AND "PrepareRef" = '{{prepareRef:D}}'::uuid;
            """));
        Assert.NotNull(immutableFailure);
        Assert.Equal("55000", Assert.IsType<PostgresException>(immutableFailure.GetBaseException()).SqlState);
        Assert.Equal(0L, await ScalarAsync<long>(immutableConnection, """
            SELECT count(*)::bigint AS "Value"
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name IN (
                'RuntimeSeatRecoveryKeyPreparations',
                'RuntimeSeatRecoveryKeyConfirmations',
                'RuntimeSeatRecoveryProofReceipts')
              AND lower(column_name) = 'jti';
            """));
    }

    /// <summary>
    /// Proves a real PostgreSQL cutover consumes only the durable PROVED receipt, commits all three
    /// lifecycle transitions with one immutable receipt, and gives exact concurrent replay/readback.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_ProvedReceipt_CommitsTripleCasAndExactReplay()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var proofInput = await ArrangeKeyProofRaceAsync(provider, "confirm");
        var proofResult = await provider.Service.ConfirmKeyAsync("website-recovery",
            proofInput.RequestId.ToString("D"), proofInput.Confirmation!, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, proofResult.StatusCode);

        RuntimeSeatRecoveryAuthorization ledger;
        RuntimeSeatRecoveryReservation reservation;
        RuntimeSeatRecoveryAuthority authority;
        RuntimeSeatRecoveryProofReceipt proof;
        await using (var arrange = await provider.Factory.CreateDbContextAsync())
        {
            ledger = await arrange.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.RequestId == proofInput.RequestId);
            reservation = await arrange.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
                item.RequestId == proofInput.RequestId);
            authority = await arrange.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
                item.ReservationRef == reservation.ReservationRef);
            proof = await arrange.RuntimeSeatRecoveryProofReceipts.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.PrepareRef == proofInput.PrepareRef);
        }
        var body = BuildActivationBody(provider.ProductId, proofInput.RequestId, ledger.RequestDigestSha256,
            reservation.RecoveryOperationRef, reservation.ReservationRef, proofInput.PrepareRef,
            proof.ConfirmationRequestSha256);
        var parsed = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(Encoding.UTF8.GetBytes(body));
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);

        var attempts = await Task.WhenAll(
            provider.Service.ActivateAsync("website-recovery", proofInput.RequestId.ToString("D"), parsed,
                CancellationToken.None),
            provider.Service.ActivateAsync("website-recovery", proofInput.RequestId.ToString("D"), parsed,
                CancellationToken.None));
        Assert.All(attempts, result => Assert.Equal(StatusCodes.Status200OK, result.StatusCode));
        Assert.Equal(attempts[0].ExactBodyUtf8, attempts[1].ExactBodyUtf8);
        Assert.Equal(1215, attempts[0].ExactBodyUtf8.Length);

        var readbackRequest = RuntimeSeatRecoveryContractCodec.ParseActivationReadbackRequest(
            Encoding.UTF8.GetBytes(BuildActivationReadbackBody(provider.ProductId, proofInput.RequestId,
                parsed.ActivationRequestDigestSha256!)));
        Assert.True(readbackRequest.IsSuccess, readbackRequest.ErrorCode);
        var readback = await provider.Service.ReadActivationAsync("website-recovery",
            proofInput.RequestId.ToString("D"), readbackRequest.Request!, CancellationToken.None);
        Assert.Equal(attempts[0].ExactBodyUtf8, readback.ExactBodyUtf8);

        var divergentBody = body.Replace(proof.ConfirmationRequestSha256, new string('f', 64),
            StringComparison.Ordinal);
        var divergent = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(Encoding.UTF8.GetBytes(divergentBody));
        Assert.True(divergent.IsSuccess, divergent.ErrorCode);
        Assert.Equal(StatusCodes.Status403Forbidden, (await provider.Service.ActivateAsync(
            "website-recovery", proofInput.RequestId.ToString("D"), divergent, CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status403Forbidden, (await provider.Service.ActivateAsync(
            "website-b", proofInput.RequestId.ToString("D"), parsed, CancellationToken.None)).StatusCode);

        await using (var verify = await provider.Factory.CreateDbContextAsync())
        {
            var committedReservation = await verify.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
                item.ReservationRef == reservation.ReservationRef);
            var activeAuthority = await verify.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
                item.ReservationRef == reservation.ReservationRef);
            var receipt = await verify.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().SingleAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.RequestId == proofInput.RequestId);
            Assert.Equal("COMMITTED", committedReservation.State);
            Assert.Equal("ACTIVE", activeAuthority.State);
            Assert.Equal("SUPERSEDED", activeAuthority.PreviousAuthorityState);
            Assert.Equal(reservation.LicenseSeatId, activeAuthority.LicenseSeatId);
            var previousBinding = await verify.DistributionInstallationBindings.AsNoTracking().SingleAsync(item =>
                item.Id == provider.PreviousAuthorityBindingId);
            var previousEnrollment = await verify.RuntimeEnrollments.AsNoTracking().SingleAsync(item =>
                item.BindingId == provider.PreviousAuthorityBindingId);
            Assert.Equal("invalidated", previousBinding.State);
            Assert.Equal("installation_superseded", previousBinding.InvalidationReason);
            Assert.NotNull(previousBinding.InvalidatedAtUtc);
            Assert.Equal("INVALIDATED", previousEnrollment.State);
            Assert.Equal("binding_superseded", previousEnrollment.InvalidationReason);
            Assert.Equal(previousBinding.InvalidatedAtUtc, previousEnrollment.InvalidatedAtUtc);
            Assert.Equal("COMMITTED", receipt.State);
            Assert.Equal(attempts[0].ExactBodyUtf8, receipt.ExactResponseUtf8);
            Assert.Equal(1, await verify.RuntimeSeatRecoveryKeyConfirmations.AsNoTracking().CountAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.PrepareRef == proofInput.PrepareRef));
            Assert.Equal(1, await verify.RuntimeSeatRecoveryProofReceipts.AsNoTracking().CountAsync(item =>
                item.AuthenticatedClientId == "website-recovery" && item.PrepareRef == proofInput.PrepareRef));
        }

        await using var immutable = new NpgsqlConnection(connections.Admin);
        await immutable.OpenAsync();
        var failure = await Record.ExceptionAsync(() => ExecuteAsync(immutable, $$"""
            DELETE FROM public."RuntimeSeatRecoveryActivationReceipts"
            WHERE "AuthenticatedClientId" = 'website-recovery'
              AND "RequestId" = '{{proofInput.RequestId:D}}'::uuid;
            """));
        Assert.NotNull(failure);
        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState,
            Assert.IsType<PostgresException>(failure.GetBaseException()).SqlState);
    }

    /// <summary>
    /// Proves PostgreSQL rejects an authority whose seat differs from the exact referenced reservation,
    /// even when the lifecycle guard is disabled to isolate the relational invariant.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_AuthoritySeatMustEqualReservationSeat_InPostgreSql()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var input = await ArrangeProvedActivationAsync(provider);
        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await ExecuteAsync(admin, """
            ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                DISABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;
            """);
        try
        {
            var mismatch = await Record.ExceptionAsync(() => ExecuteAsync(admin, $$"""
                UPDATE public."RuntimeSeatRecoveryAuthorities"
                SET "LicenseSeatId" = '{{Guid.NewGuid():D}}'::uuid
                WHERE "ReservationRef" = '{{input.ReservationRef:D}}'::uuid;
                """));
            Assert.NotNull(mismatch);
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.GetBaseException()).SqlState);
        }
        finally
        {
            await ExecuteAsync(admin, """
                ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                    ENABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;
                """);
        }
    }

    /// <summary>Proves an absent provider receipt cannot squat request identity or change any lifecycle state.</summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_AbsentProof_IsNonTerminal403WithZeroEffect()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        using var runtimeKey = RSA.Create(2048);
        var spkiDigest = Convert.ToHexStringLower(SHA256.HashData(runtimeKey.ExportSubjectPublicKeyInfo()));
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var authorization = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddMinutes(10),
            new string('a', 64), provider.ArtifactDigest, publicKeySpkiSha256: spkiDigest,
            keyThumbprint: Base64Url(Convert.FromHexString(spkiDigest)));
        Assert.Equal(StatusCodes.Status200OK, (await provider.Service.AuthorizeAsync(
            "website-recovery", authorization, CancellationToken.None)).StatusCode);
        await using var db = await provider.Factory.CreateDbContextAsync();
        var reservation = await db.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
            item.RequestId == requestId);
        var body = BuildActivationBody(provider.ProductId, requestId, authorization.RequestDigestSha256!,
            recoveryRef, reservation.ReservationRef, Guid.NewGuid(), new string('c', 64));
        var activation = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(Encoding.UTF8.GetBytes(body));
        Assert.True(activation.IsSuccess, activation.ErrorCode);

        var result = await provider.Service.ActivateAsync(
            "website-recovery", requestId.ToString("D"), activation, CancellationToken.None);

        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        db.ChangeTracker.Clear();
        Assert.Equal("RESERVED", (await db.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == reservation.ReservationRef)).State);
        var authority = await db.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == reservation.ReservationRef);
        Assert.Equal("PREPARED", authority.State);
        Assert.Equal("ACTIVE", authority.PreviousAuthorityState);
        Assert.False(await db.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().AnyAsync(item =>
            item.RequestId == requestId));
    }

    /// <summary>Proves exact post-PROVED expiry and ownership divergence freeze terminal errors without cutover.</summary>
    [Theory]
    [InlineData("expired", StatusCodes.Status410Gone, "activation_expired", 375)]
    [InlineData("ownership", StatusCodes.Status409Conflict, "activation_conflict", 376)]
    public async Task RuntimeSeatRecoveryActivation_PostProofClosedFailure_FreezesExactReplayWithoutCas(
        string failure,
        int expectedStatus,
        string expectedError,
        int expectedLength)
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var input = await ArrangeProvedActivationAsync(provider,
            failure == "expired" ? provider.Now.AddSeconds(8) : null);
        if (failure == "expired")
        {
            var remaining = input.ExpiresAtUtc - DateTime.UtcNow + TimeSpan.FromMilliseconds(750);
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining);
        }
        else
        {
            var command = await ArrangeOwnershipCommandAsync(provider, "REVOKE_OWNERSHIP");
            var writer = new RuntimeRecoveryCommercialOwnershipCommandService(provider.Factory);
            _ = await writer.ExecuteAsync(provider.ProductId, command.Request, CancellationToken.None);
        }

        var first = await provider.Service.ActivateAsync("website-recovery", input.RequestId.ToString("D"),
            input.Activation, CancellationToken.None);
        var replay = await provider.Service.ActivateAsync("website-recovery", input.RequestId.ToString("D"),
            input.Activation, CancellationToken.None);

        Assert.Equal(expectedStatus, first.StatusCode);
        Assert.Equal(expectedLength, first.ExactBodyUtf8.Length);
        Assert.Contains($"\"errorCode\":\"{expectedError}\"", Encoding.UTF8.GetString(first.ExactBodyUtf8),
            StringComparison.Ordinal);
        Assert.Equal(first.ExactBodyUtf8, replay.ExactBodyUtf8);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        var reservation = await verify.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == input.ReservationRef);
        var authority = await verify.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == input.ReservationRef);
        var receipt = await verify.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery" && item.RequestId == input.RequestId);
        Assert.Equal("RESERVED", reservation.State);
        Assert.Equal("PREPARED", authority.State);
        Assert.Equal("ACTIVE", authority.PreviousAuthorityState);
        Assert.Equal("REFUSED", receipt.State);
        Assert.Equal(expectedError, receipt.ErrorCode);
        Assert.Equal(first.ExactBodyUtf8, receipt.ExactResponseUtf8);
    }

    /// <summary>Proves a committed positive receipt remains byte-exact after its PROVED prerequisite expires.</summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_CommittedReplayAfterProofExpiry_IsReadOnlyAndByteExact()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var input = await ArrangeProvedActivationAsync(provider, provider.Now.AddSeconds(8));
        var committed = await provider.Service.ActivateAsync("website-recovery", input.RequestId.ToString("D"),
            input.Activation, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, committed.StatusCode);
        await using var audit = new NpgsqlConnection(connections.Admin);
        await audit.OpenAsync();
        await InstallComposition10MutationAuditAsync(audit);
        try
        {
            var before = await ReadComposition10SnapshotSha256Async(audit);
            var remaining = input.ExpiresAtUtc - DateTime.UtcNow + TimeSpan.FromMilliseconds(750);
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining);

            var replay = await provider.Service.ActivateAsync("website-recovery", input.RequestId.ToString("D"),
                input.Activation, CancellationToken.None);
            var readbackBody = BuildActivationReadbackBody(provider.ProductId, input.RequestId,
                input.Activation.ActivationRequestDigestSha256!);
            var readbackRequest = RuntimeSeatRecoveryContractCodec.ParseActivationReadbackRequest(
                Encoding.UTF8.GetBytes(readbackBody));
            var readback = await provider.Service.ReadActivationAsync(
                "website-recovery", input.RequestId.ToString("D"), readbackRequest.Request!,
                CancellationToken.None);

            Assert.Equal(committed.ExactBodyUtf8, replay.ExactBodyUtf8);
            Assert.Equal(committed.ExactBodyUtf8, readback.ExactBodyUtf8);
            Assert.Equal(before, await ReadComposition10SnapshotSha256Async(audit));
            Assert.Equal(0L, await ScalarAsync<long>(audit,
                "SELECT count(*)::bigint AS \"Value\" FROM public.tkt730_composition10_mutations;"));
        }
        finally
        {
            await RemoveComposition10MutationAuditAsync(audit);
        }
    }

    /// <summary>Proves failure while inserting the receipt rolls back both authority states and the reservation.</summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_ReceiptInsertFailure_RollsBackWholeTripleCas()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var input = await ArrangeProvedActivationAsync(provider);
        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await ExecuteAsync(admin, """
            CREATE FUNCTION public.tkt767_activation_receipt_failure()
            RETURNS trigger LANGUAGE plpgsql AS $failure$
            BEGIN
                RAISE EXCEPTION 'test receipt failure' USING ERRCODE = '55000';
            END;
            $failure$;
            CREATE TRIGGER trg_tkt767_activation_receipt_failure
            BEFORE INSERT ON public."RuntimeSeatRecoveryActivationReceipts"
            FOR EACH ROW EXECUTE FUNCTION public.tkt767_activation_receipt_failure();
            """);
        try
        {
            var failure = await Record.ExceptionAsync(() => provider.Service.ActivateAsync(
                "website-recovery", input.RequestId.ToString("D"), input.Activation, CancellationToken.None));
            Assert.NotNull(failure);
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState,
                Assert.IsType<PostgresException>(failure.GetBaseException()).SqlState);
        }
        finally
        {
            await ExecuteAsync(admin, """
                DROP TRIGGER IF EXISTS trg_tkt767_activation_receipt_failure
                    ON public."RuntimeSeatRecoveryActivationReceipts";
                DROP FUNCTION IF EXISTS public.tkt767_activation_receipt_failure();
                """);
        }

        await using (var verify = await provider.Factory.CreateDbContextAsync())
        {
            var reservation = await verify.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
                item.ReservationRef == input.ReservationRef);
            var authority = await verify.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
                item.ReservationRef == input.ReservationRef);
            Assert.Equal("RESERVED", reservation.State);
            Assert.Equal("PREPARED", authority.State);
            Assert.Equal("ACTIVE", authority.PreviousAuthorityState);
            var previousBinding = await verify.DistributionInstallationBindings.AsNoTracking().SingleAsync(item =>
                item.Id == provider.PreviousAuthorityBindingId);
            var previousEnrollment = await verify.RuntimeEnrollments.AsNoTracking().SingleAsync(item =>
                item.BindingId == provider.PreviousAuthorityBindingId);
            Assert.Equal("active", previousBinding.State);
            Assert.Null(previousBinding.InvalidatedAtUtc);
            Assert.Null(previousBinding.InvalidationReason);
            Assert.Equal("ACTIVE", previousEnrollment.State);
            Assert.Null(previousEnrollment.InvalidatedAtUtc);
            Assert.Null(previousEnrollment.InvalidationReason);
            Assert.False(await verify.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().AnyAsync(item =>
                item.RequestId == input.RequestId));
        }
        Assert.Equal(StatusCodes.Status200OK, (await provider.Service.ActivateAsync(
            "website-recovery", input.RequestId.ToString("D"), input.Activation, CancellationToken.None)).StatusCode);
    }

    /// <summary>
    /// Proves an exact zero-row previous-authority CAS rolls back every recovery transition and leaves
    /// no terminal receipt, rather than accepting the projection-only cutover.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_PreviousAuthorityCasMiss_RollsBackWithoutReceipt()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var input = await ArrangeProvedActivationAsync(provider);
        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await ExecuteAsync(admin, $$"""
            CREATE FUNCTION public.tkt767_skip_previous_binding_cas()
            RETURNS trigger LANGUAGE plpgsql AS $failure$
            BEGIN
                IF OLD."Id" = '{{provider.PreviousAuthorityBindingId:D}}'::uuid THEN
                    RETURN NULL;
                END IF;
                RETURN NEW;
            END;
            $failure$;
            CREATE TRIGGER trg_tkt767_skip_previous_binding_cas
            BEFORE UPDATE ON public."DistributionInstallationBindings"
            FOR EACH ROW EXECUTE FUNCTION public.tkt767_skip_previous_binding_cas();
            """);
        RuntimeSeatRecoveryHttpResult result;
        try
        {
            result = await provider.Service.ActivateAsync("website-recovery", input.RequestId.ToString("D"),
                input.Activation, CancellationToken.None);
        }
        finally
        {
            await ExecuteAsync(admin, """
                DROP TRIGGER IF EXISTS trg_tkt767_skip_previous_binding_cas
                    ON public."DistributionInstallationBindings";
                DROP FUNCTION IF EXISTS public.tkt767_skip_previous_binding_cas();
                """);
        }

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        Assert.Equal("RESERVED", (await verify.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == input.ReservationRef)).State);
        var authority = await verify.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == input.ReservationRef);
        Assert.Equal("PREPARED", authority.State);
        Assert.Equal("ACTIVE", authority.PreviousAuthorityState);
        Assert.Equal("active", (await verify.DistributionInstallationBindings.AsNoTracking().SingleAsync(item =>
            item.Id == provider.PreviousAuthorityBindingId)).State);
        Assert.Equal("ACTIVE", (await verify.RuntimeEnrollments.AsNoTracking().SingleAsync(item =>
            item.BindingId == provider.PreviousAuthorityBindingId)).State);
        Assert.False(await verify.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().AnyAsync(item =>
            item.RequestId == input.RequestId));
    }

    /// <summary>
    /// Proves a legitimate previous-authority writer holding both real rows wins the PostgreSQL race;
    /// activation waits, then closes without committing its reservation or prepared recovery authority.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryActivation_PreviousAuthorityWriterWinsRace_LeavesCutoverUntouched()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        var input = await ArrangeProvedActivationAsync(provider);
        await using var writer = new NpgsqlConnection(connections.Admin);
        await writer.OpenAsync();
        await using var writerTransaction = await writer.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand("""
            SELECT binding."Id", enrollment."Id"
            FROM public."DistributionInstallationBindings" binding
            JOIN public."RuntimeEnrollments" enrollment ON enrollment."BindingId" = binding."Id"
            WHERE binding."Id" = @binding
              AND binding."State" = 'active'
              AND enrollment."State" = 'ACTIVE'
            FOR UPDATE OF binding, enrollment;
            """, writer, writerTransaction))
        {
            lockCommand.Parameters.AddWithValue("binding", provider.PreviousAuthorityBindingId);
            await using var reader = await lockCommand.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.False(await reader.ReadAsync());
        }

        var activation = provider.Service.ActivateAsync("website-recovery", input.RequestId.ToString("D"),
            input.Activation, CancellationToken.None);
        await Task.Delay(300);
        Assert.False(activation.IsCompleted);
        await using (var supersede = new NpgsqlCommand("""
            UPDATE public."RuntimeEnrollments"
            SET "State" = 'INVALIDATED',
                "InvalidatedAtUtc" = clock_timestamp(),
                "InvalidationReason" = 'binding_superseded'
            WHERE "BindingId" = @binding AND "State" = 'ACTIVE';
            UPDATE public."DistributionInstallationBindings"
            SET "State" = 'invalidated',
                "InvalidatedAtUtc" = clock_timestamp(),
                "InvalidationReason" = 'installation_superseded'
            WHERE "Id" = @binding AND "State" = 'active';
            """, writer, writerTransaction))
        {
            supersede.Parameters.AddWithValue("binding", provider.PreviousAuthorityBindingId);
            Assert.Equal(2, await supersede.ExecuteNonQueryAsync());
        }
        await writerTransaction.CommitAsync();

        var result = await activation;
        Assert.Equal(StatusCodes.Status409Conflict, result.StatusCode);
        Assert.Contains("\"errorCode\":\"activation_conflict\"", Encoding.UTF8.GetString(result.ExactBodyUtf8),
            StringComparison.Ordinal);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        Assert.Equal("RESERVED", (await verify.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == input.ReservationRef)).State);
        var authority = await verify.RuntimeSeatRecoveryAuthorities.AsNoTracking().SingleAsync(item =>
            item.ReservationRef == input.ReservationRef);
        Assert.Equal("PREPARED", authority.State);
        Assert.Equal("ACTIVE", authority.PreviousAuthorityState);
        var receipt = await verify.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().SingleAsync(item =>
            item.RequestId == input.RequestId);
        Assert.Equal("REFUSED", receipt.State);
        Assert.Equal("activation_conflict", receipt.ErrorCode);
    }

    /// <summary>
    /// Proves the database-clock expiry consumes the prepareRef into one frozen 410 terminal and
    /// never creates a PROVED receipt, even when the syntactic confirmation is replayed after loss.
    /// </summary>
    [Fact]
    public async Task RuntimeSeatRecoveryKeyProof_ExpiredPreparationFreezesExact410WithoutReceipt()
    {
        var connections = await ProvisionAsync();
        var provider = await PrepareRecoveryProviderAsync(connections.Admin, connections.App);
        using var runtimeKey = RSA.Create(3072);
        var spki = runtimeKey.ExportSubjectPublicKeyInfo();
        var spkiDigest = Convert.ToHexStringLower(SHA256.HashData(spki));
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var authorizationRequest = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest, provider.Now.AddSeconds(6),
            new string('a', 64), provider.ArtifactDigest, publicKeySpkiSha256: spkiDigest,
            keyThumbprint: Base64Url(SHA256.HashData(spki)));
        Assert.Equal(200, (await provider.Service.AuthorizeAsync(
            "website-recovery", authorizationRequest, CancellationToken.None)).StatusCode);

        RuntimeSeatRecoveryReservation reservation;
        RuntimeSeatRecoveryAuthority authority;
        await using (var scope = await provider.Factory.CreateDbContextAsync())
        {
            reservation = await scope.RuntimeSeatRecoveryReservations.AsNoTracking()
                .SingleAsync(item => item.RequestId == requestId);
            authority = await scope.RuntimeSeatRecoveryAuthorities.AsNoTracking()
                .SingleAsync(item => item.ReservationRef == reservation.ReservationRef);
        }
        var preparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(Encoding.UTF8.GetBytes(
            BuildKeyPreparationBody(provider.ProductId, requestId, authorizationRequest.RequestDigestSha256!,
                recoveryRef, reservation.ReservationRef, authority.EnrollmentId,
                authority.AuthorityGenerationId, Convert.ToBase64String(spki))));
        var prepared = await provider.Service.PrepareKeyAsync(
            "website-recovery", requestId.ToString("D"), preparation, CancellationToken.None);
        Assert.Equal(200, prepared.StatusCode);
        using var preparationResponse = JsonDocument.Parse(prepared.ExactBodyUtf8);
        var prepareRef = Guid.Parse(preparationResponse.RootElement.GetProperty("prepareRef").GetString()!);
        var challenge = preparationResponse.RootElement.GetProperty("challenge").GetString()!;
        var expiresAt = preparationResponse.RootElement.GetProperty("expiresAtUtc").GetDateTime().ToUniversalTime();

        var statement = BuildKeyConfirmationStatement(prepareRef, requestId,
            authorizationRequest.RequestDigestSha256!, recoveryRef, reservation.ReservationRef,
            authority.EnrollmentId, authority.AuthorityGenerationId, challenge);
        var confirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(Encoding.UTF8.GetBytes(
            BuildKeyConfirmationBody(provider.ProductId, requestId, authorizationRequest.RequestDigestSha256!,
                recoveryRef, reservation.ReservationRef, prepareRef, authority.EnrollmentId,
                authority.AuthorityGenerationId, spkiDigest, statement, new string('A', 512))));
        Assert.True(confirmation.IsSuccess, confirmation.ErrorCode);
        var remaining = expiresAt - DateTime.UtcNow + TimeSpan.FromMilliseconds(750);
        if (remaining > TimeSpan.Zero) await Task.Delay(remaining);

        var first = await provider.Service.ConfirmKeyAsync(
            "website-recovery", requestId.ToString("D"), confirmation, CancellationToken.None);
        var replay = await provider.Service.ConfirmKeyAsync(
            "website-recovery", requestId.ToString("D"), confirmation, CancellationToken.None);

        Assert.Equal(410, first.StatusCode);
        Assert.Equal(first.ExactBodyUtf8, replay.ExactBodyUtf8);
        await using var verify = await provider.Factory.CreateDbContextAsync();
        Assert.Equal("REFUSED", (await verify.RuntimeSeatRecoveryKeyConfirmations.AsNoTracking()
            .SingleAsync(item => item.PrepareRef == prepareRef)).State);
        Assert.NotNull((await verify.RuntimeSeatRecoveryKeyPreparations.AsNoTracking()
            .SingleAsync(item => item.RequestId == requestId)).ChallengeConsumedAtUtc);
        Assert.False(await verify.RuntimeSeatRecoveryProofReceipts.AsNoTracking()
            .AnyAsync(item => item.PrepareRef == prepareRef));
    }

    /// <summary>
    /// Proves preparation and confirmation serialize with the TKT-000782 license/ownership writer for
    /// both transfer and revoke. The test-owned trigger pauses the proof only after its decisive reads,
    /// so the ownership command must wait until the proof transaction commits.
    /// </summary>
    /// <param name="proofStage">Exact proof stage paused after authority revalidation.</param>
    /// <param name="ownershipOperation">Exact TKT-000782 ownership transition raced against the proof.</param>
    [Theory]
    [InlineData("prepare", "TRANSFER_OWNERSHIP")]
    [InlineData("prepare", "REVOKE_OWNERSHIP")]
    [InlineData("confirm", "TRANSFER_OWNERSHIP")]
    [InlineData("confirm", "REVOKE_OWNERSHIP")]
    public async Task RuntimeSeatRecoveryKeyProof_OwnershipWriterRaceSerializesBothLegitimateOrders(
        string proofStage,
        string ownershipOperation)
    {
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt773_f1_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
            var admin = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
            var proofApplicationName = "tkt773-f1-proof-" + Guid.NewGuid().ToString("N");
            var app = new NpgsqlConnectionStringBuilder(admin)
            {
                Username = "softlicence_runtime_test_app",
                Password = "runtime-test-only",
                Pooling = false,
                ApplicationName = proofApplicationName
            }.ConnectionString;
            var writerApplicationName = "tkt773-f1-writer-" + Guid.NewGuid().ToString("N");
            var writerConnection = new NpgsqlConnectionStringBuilder(app)
            {
                ApplicationName = writerApplicationName
            }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
            await using (var migration = new LicenseDbContext(options))
                await migration.Database.MigrateAsync();
            await using (var privileges = new NpgsqlConnection(admin))
            {
                await privileges.OpenAsync();
                await GrantApplicationRuntimePrivilegesAsync(privileges);
            }

            const int raceGateTimeoutMilliseconds = 60_000;
            var proofWinsProvider = await PrepareRecoveryProviderAsync(
                admin, app, lockTimeoutMilliseconds: raceGateTimeoutMilliseconds,
                statementTimeoutMilliseconds: raceGateTimeoutMilliseconds);
            var proofWins = await ArrangeKeyProofRaceAsync(proofWinsProvider, proofStage);
            var proofWinsCommand = await ArrangeOwnershipCommandAsync(
                proofWinsProvider, ownershipOperation);
            var raceGateKey = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            await InstallKeyProofRaceGateAsync(admin, proofStage, raceGateKey);
            await using var gateConnection = new NpgsqlConnection(admin);
            await gateConnection.OpenAsync();
            await using var gateTransaction = await gateConnection.BeginTransactionAsync();
            await ExecuteAsync(gateConnection,
                $"SELECT pg_catalog.pg_advisory_xact_lock(773001, {raceGateKey});", gateTransaction);
            await using var observerConnection = new NpgsqlConnection(admin);
            await observerConnection.OpenAsync();

            var proofTask = ExecuteKeyProofAsync(proofWinsProvider, proofWins, proofStage);
            var proofBackendPid = await WaitForTkt773RaceGateAsync(
                observerConnection, proofApplicationName, gateConnection.ProcessID);
            var writerFactory = new TestDbFactory(writerConnection);
            var commandService = new RuntimeRecoveryCommercialOwnershipCommandService(writerFactory);
            var ownershipTask = commandService.ExecuteAsync(
                proofWinsProvider.ProductId, proofWinsCommand.Request, CancellationToken.None);
            await WaitForOwnershipWriterLockAsync(observerConnection,
                proofApplicationName, writerApplicationName, proofBackendPid,
                gateConnection.ProcessID, ownershipTask);
            await gateTransaction.RollbackAsync();

            await Task.WhenAll(new Task[] { proofTask, ownershipTask }).WaitAsync(TimeSpan.FromSeconds(15));
            var proofResult = await proofTask;
            var ownershipResult = await ownershipTask;
            Assert.Equal(StatusCodes.Status200OK, proofResult.StatusCode);
            Assert.False(string.IsNullOrEmpty(ownershipResult.ResponseJson));
            var proofReplay = await ExecuteKeyProofAsync(proofWinsProvider, proofWins, proofStage);
            Assert.Equal(proofResult.StatusCode, proofReplay.StatusCode);
            Assert.Equal(proofResult.ContentType, proofReplay.ContentType);
            Assert.Equal(proofResult.ExactBodyUtf8, proofReplay.ExactBodyUtf8);
            await using (var verifyProofWins = await proofWinsProvider.Factory.CreateDbContextAsync())
            {
                var previous = await verifyProofWins.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
                    .SingleAsync(item => item.Id == proofWinsCommand.Request.ExpectedOwnershipId);
                Assert.Equal(ownershipOperation == "TRANSFER_OWNERSHIP" ? "TRANSFERRED" : "REVOKED",
                    previous.State);
                Assert.True(await verifyProofWins.RuntimeSeatRecoveryKeyPreparations.AsNoTracking()
                    .AnyAsync(item => item.RequestId == proofWins.RequestId));
                Assert.Equal(proofStage == "confirm",
                    await verifyProofWins.RuntimeSeatRecoveryProofReceipts.AsNoTracking()
                        .AnyAsync(item => item.PrepareRef == proofWins.PrepareRef));
            }

            var writerWinsProvider = await PrepareRecoveryProviderAsync(admin, app);
            var writerWins = await ArrangeKeyProofRaceAsync(writerWinsProvider, proofStage);
            var writerWinsCommand = await ArrangeOwnershipCommandAsync(
                writerWinsProvider, ownershipOperation);
            var writerService = new RuntimeRecoveryCommercialOwnershipCommandService(writerWinsProvider.Factory);
            await writerService.ExecuteAsync(
                writerWinsProvider.ProductId, writerWinsCommand.Request, CancellationToken.None);

            var refused = await ExecuteKeyProofAsync(writerWinsProvider, writerWins, proofStage);
            var refusalReplay = await ExecuteKeyProofAsync(writerWinsProvider, writerWins, proofStage);
            Assert.Contains(refused.StatusCode,
                new[] { StatusCodes.Status403Forbidden, StatusCodes.Status409Conflict });
            Assert.NotEqual(StatusCodes.Status500InternalServerError, refused.StatusCode);
            Assert.Equal(refused.StatusCode, refusalReplay.StatusCode);
            Assert.Equal(refused.ContentType, refusalReplay.ContentType);
            Assert.Equal(refused.ExactBodyUtf8, refusalReplay.ExactBodyUtf8);
            await using var verify = await writerWinsProvider.Factory.CreateDbContextAsync();
            Assert.False(await verify.RuntimeSeatRecoveryProofReceipts.AsNoTracking()
                .AnyAsync(item => item.PrepareRef == writerWins.PrepareRef));
            if (proofStage == "prepare")
            {
                Assert.False(await verify.RuntimeSeatRecoveryKeyPreparations.AsNoTracking()
                    .AnyAsync(item => item.RequestId == writerWins.RequestId));
            }
            else
            {
                var stored = await verify.RuntimeSeatRecoveryKeyPreparations.AsNoTracking()
                    .SingleAsync(item => item.PrepareRef == writerWins.PrepareRef);
                Assert.Null(stored.ChallengeConsumedAtUtc);
                Assert.False(await verify.RuntimeSeatRecoveryKeyConfirmations.AsNoTracking()
                    .AnyAsync(item => item.PrepareRef == writerWins.PrepareRef));
            }
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, database);
        }
    }

    /// <summary>Proves composite idempotency, one live reservation per seat, and frozen terminal bytes on PostgreSQL.</summary>
    [Fact]
    public async Task RuntimeSeatRecoverySchema_EnforcesCompositeIdentityReservationAndFrozenResult()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.3.445", "*");
        Guid licenseId;
        Guid seatId;
        await using (var lookup = await factory.CreateDbContextAsync())
        {
            var binding = await lookup.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(item => item.Id == fixture.BindingId);
            licenseId = binding.LicenseId;
            seatId = binding.LicenseSeatId;
        }

        var requestId = Guid.NewGuid();
        var firstReservation = Guid.NewGuid();
        var firstOperation = Guid.NewGuid();
        await using (var first = await factory.CreateDbContextAsync())
        {
            first.RuntimeSeatRecoveryAuthorizations.Add(AuthorizedTerminal(
                "website-a", requestId, firstReservation, firstOperation));
            await first.SaveChangesAsync();
            first.RuntimeSeatRecoveryReservations.Add(Reservation(
                firstReservation, "website-a", requestId, firstOperation, fixture.ProductId, licenseId, seatId));
            await first.SaveChangesAsync();
        }

        await using (var secondClient = await factory.CreateDbContextAsync())
        {
            secondClient.RuntimeSeatRecoveryAuthorizations.Add(RefusedTerminal(
                "website-b", requestId, firstOperation));
            await secondClient.SaveChangesAsync();
        }
        await using (var duplicateClient = await factory.CreateDbContextAsync())
        {
            duplicateClient.RuntimeSeatRecoveryAuthorizations.Add(RefusedTerminal("website-a", requestId));
            var duplicate = await Assert.ThrowsAsync<DbUpdateException>(() => duplicateClient.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.UniqueViolation, ((PostgresException)duplicate.InnerException!).SqlState);
        }

        var competingRequest = Guid.NewGuid();
        var competingReservation = Guid.NewGuid();
        var competingOperation = Guid.NewGuid();
        await using (var competing = await factory.CreateDbContextAsync())
        {
            competing.RuntimeSeatRecoveryAuthorizations.Add(AuthorizedTerminal(
                "website-b", competingRequest, competingReservation, competingOperation));
            await competing.SaveChangesAsync();
            competing.RuntimeSeatRecoveryReservations.Add(Reservation(competingReservation,
                "website-b", competingRequest, competingOperation, fixture.ProductId, licenseId, seatId));
            var collision = await Assert.ThrowsAsync<DbUpdateException>(() => competing.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.UniqueViolation, ((PostgresException)collision.InnerException!).SqlState);
        }

        await using var connection = new NpgsqlConnection(connections.App);
        await connection.OpenAsync();
        await using var mutate = new NpgsqlCommand("""
            UPDATE public."RuntimeSeatRecoveryAuthorizations"
            SET "ExactResponseUtf8" = decode('7b7d','hex')
            WHERE "AuthenticatedClientId" = 'website-a' AND "RequestId" = @request;
            """, connection);
        mutate.Parameters.AddWithValue("request", requestId);
        var frozen = await Assert.ThrowsAsync<PostgresException>(() => mutate.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, frozen.SqlState);
    }

    private static string BuildKeyPreparationBody(
        Guid productId, Guid requestId, string requestDigest, Guid recoveryRef, Guid reservationRef,
        Guid enrollmentId, Guid generationId, string publicKeySpki) =>
        $"{{\"schema\":\"runtime-seat-recovery-key-prepare-v1\",\"contractVersion\":1,\"productId\":\"{productId:D}\",\"requestId\":\"{requestId:D}\",\"requestDigestSha256\":\"{requestDigest}\",\"recoveryOperationRef\":\"{recoveryRef:D}\",\"reservationRef\":\"{reservationRef:D}\",\"enrollmentId\":\"{enrollmentId:D}\",\"authorityGenerationId\":\"{generationId:D}\",\"publicKeySpki\":\"{publicKeySpki}\"}}";

    private static string BuildKeyConfirmationStatement(
        Guid prepareRef, Guid requestId, string requestDigest, Guid recoveryRef, Guid reservationRef,
        Guid enrollmentId, Guid generationId, string challenge) =>
        $"{{\"schema\":\"runtime-seat-recovery-key-confirmation-v1\",\"contractVersion\":1,\"prepareRef\":\"{prepareRef:D}\",\"requestId\":\"{requestId:D}\",\"requestDigestSha256\":\"{requestDigest}\",\"recoveryOperationRef\":\"{recoveryRef:D}\",\"reservationRef\":\"{reservationRef:D}\",\"enrollmentId\":\"{enrollmentId:D}\",\"authorityGenerationId\":\"{generationId:D}\",\"challenge\":\"{challenge}\",\"confirmAudience\":\"softlicence:runtime-identity-recovery:confirm:v1\"}}";

    private static string BuildKeyConfirmationBody(
        Guid productId, Guid requestId, string requestDigest, Guid recoveryRef, Guid reservationRef,
        Guid prepareRef, Guid enrollmentId, Guid generationId, string spkiDigest, string statement,
        string signature) =>
        $"{{\"schema\":\"runtime-seat-recovery-key-confirmation-request-v1\",\"contractVersion\":1,\"productId\":\"{productId:D}\",\"requestId\":\"{requestId:D}\",\"requestDigestSha256\":\"{requestDigest}\",\"recoveryOperationRef\":\"{recoveryRef:D}\",\"reservationRef\":\"{reservationRef:D}\",\"prepareRef\":\"{prepareRef:D}\",\"enrollmentId\":\"{enrollmentId:D}\",\"authorityGenerationId\":\"{generationId:D}\",\"publicKeySpkiSha256\":\"{spkiDigest}\",\"confirmationStatement\":{statement},\"confirmationAlgorithm\":\"PS256\",\"confirmationSignature\":\"{signature}\"}}";

    /// <summary>Builds the exact closed activation command without any client-asserted provider resource.</summary>
    private static string BuildActivationBody(
        Guid productId,
        Guid requestId,
        string requestDigest,
        Guid recoveryRef,
        Guid reservationRef,
        Guid prepareRef,
        string confirmationRequestSha256) =>
        $"{{\"schema\":\"runtime-seat-recovery-activation-v1\",\"contractVersion\":1,\"productId\":\"{productId:D}\",\"requestId\":\"{requestId:D}\",\"requestDigestSha256\":\"{requestDigest}\",\"recoveryOperationRef\":\"{recoveryRef:D}\",\"reservationRef\":\"{reservationRef:D}\",\"prepareRef\":\"{prepareRef:D}\",\"confirmationRequestSha256\":\"{confirmationRequestSha256}\"}}";

    /// <summary>Builds the exact readback identity for one immutable activation terminal.</summary>
    private static string BuildActivationReadbackBody(
        Guid productId,
        Guid requestId,
        string activationRequestDigestSha256) =>
        $"{{\"schema\":\"runtime-seat-recovery-activation-readback-v1\",\"contractVersion\":1,\"productId\":\"{productId:D}\",\"requestId\":\"{requestId:D}\",\"activationRequestDigestSha256\":\"{activationRequestDigestSha256}\"}}";

    /// <summary>Creates one complete key-proof input without retaining the ephemeral private key.</summary>
    private static async Task<KeyProofRaceInput> ArrangeKeyProofRaceAsync(
        RecoveryProviderScenario provider,
        string proofStage,
        DateTime? authorizationExpiresAtUtc = null)
    {
        using var runtimeKey = RSA.Create(3072);
        var spki = runtimeKey.ExportSubjectPublicKeyInfo();
        var spkiDigest = Convert.ToHexStringLower(SHA256.HashData(spki));
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var authorization = ParseRecoveryRequest(requestId, recoveryRef, provider.ProductId,
            provider.LicenseId, provider.InstallationId, provider.HardwareDigest,
            authorizationExpiresAtUtc ?? provider.Now.AddMinutes(10), new string('a', 64), provider.ArtifactDigest,
            publicKeySpkiSha256: spkiDigest, keyThumbprint: Base64Url(SHA256.HashData(spki)));
        Assert.Equal(StatusCodes.Status200OK, (await provider.Service.AuthorizeAsync(
            "website-recovery", authorization, CancellationToken.None)).StatusCode);

        RuntimeSeatRecoveryReservation reservation;
        RuntimeSeatRecoveryAuthority authority;
        await using (var scope = await provider.Factory.CreateDbContextAsync())
        {
            reservation = await scope.RuntimeSeatRecoveryReservations.AsNoTracking()
                .SingleAsync(item => item.RequestId == requestId);
            authority = await scope.RuntimeSeatRecoveryAuthorities.AsNoTracking()
                .SingleAsync(item => item.ReservationRef == reservation.ReservationRef);
        }
        var preparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(Encoding.UTF8.GetBytes(
            BuildKeyPreparationBody(provider.ProductId, requestId, authorization.RequestDigestSha256!,
                recoveryRef, reservation.ReservationRef, authority.EnrollmentId,
                authority.AuthorityGenerationId, Convert.ToBase64String(spki))));
        Assert.True(preparation.IsSuccess, preparation.ErrorCode);
        if (proofStage == "prepare")
            return new(requestId, Guid.Empty, preparation, null);

        var prepared = await provider.Service.PrepareKeyAsync(
            "website-recovery", requestId.ToString("D"), preparation, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, prepared.StatusCode);
        using var preparationResponse = JsonDocument.Parse(prepared.ExactBodyUtf8);
        var prepareRef = preparationResponse.RootElement.GetProperty("prepareRef").GetGuid();
        var challenge = preparationResponse.RootElement.GetProperty("challenge").GetString()!;
        var statement = BuildKeyConfirmationStatement(prepareRef, requestId,
            authorization.RequestDigestSha256!, recoveryRef, reservation.ReservationRef,
            authority.EnrollmentId, authority.AuthorityGenerationId, challenge);
        var signatureInput = RuntimeSeatRecoveryContractCodec.BuildConfirmationSignatureInput(
            Encoding.UTF8.GetBytes(statement));
        var signature = Base64Url(runtimeKey.SignData(
            signatureInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var confirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(Encoding.UTF8.GetBytes(
            BuildKeyConfirmationBody(provider.ProductId, requestId, authorization.RequestDigestSha256!,
                recoveryRef, reservation.ReservationRef, prepareRef, authority.EnrollmentId,
                authority.AuthorityGenerationId, spkiDigest, statement, signature)));
        Assert.True(confirmation.IsSuccess, confirmation.ErrorCode);
        return new(requestId, prepareRef, preparation, confirmation);
    }

    /// <summary>Produces one durable PROVED receipt and its exact canonical activation command.</summary>
    private static async Task<ProvedActivationInput> ArrangeProvedActivationAsync(
        RecoveryProviderScenario provider,
        DateTime? authorizationExpiresAtUtc = null)
    {
        var proofInput = await ArrangeKeyProofRaceAsync(provider, "confirm", authorizationExpiresAtUtc);
        var proofResult = await provider.Service.ConfirmKeyAsync("website-recovery",
            proofInput.RequestId.ToString("D"), proofInput.Confirmation!, CancellationToken.None);
        Assert.Equal(StatusCodes.Status200OK, proofResult.StatusCode);
        await using var db = await provider.Factory.CreateDbContextAsync();
        var ledger = await db.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery" && item.RequestId == proofInput.RequestId);
        var reservation = await db.RuntimeSeatRecoveryReservations.AsNoTracking().SingleAsync(item =>
            item.RequestId == proofInput.RequestId);
        var proof = await db.RuntimeSeatRecoveryProofReceipts.AsNoTracking().SingleAsync(item =>
            item.AuthenticatedClientId == "website-recovery" && item.PrepareRef == proofInput.PrepareRef);
        var body = BuildActivationBody(provider.ProductId, proofInput.RequestId, ledger.RequestDigestSha256,
            reservation.RecoveryOperationRef, reservation.ReservationRef, proofInput.PrepareRef,
            proof.ConfirmationRequestSha256);
        var parsed = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(Encoding.UTF8.GetBytes(body));
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        return new(proofInput.RequestId, reservation.ReservationRef, proofInput.PrepareRef, proof.ExpiresAtUtc,
            parsed);
    }

    /// <summary>Builds one exact TKT-000782 command against the currently active ownership version.</summary>
    private static async Task<OwnershipRaceCommand> ArrangeOwnershipCommandAsync(
        RecoveryProviderScenario provider,
        string operation)
    {
        await using var db = await provider.Factory.CreateDbContextAsync();
        var active = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync(item =>
            item.ProductId == provider.ProductId && item.LicenseId == provider.LicenseId
            && item.State == "ACTIVE");
        Guid? target = null;
        if (operation == "TRANSFER_OWNERSHIP")
        {
            target = Guid.NewGuid();
            db.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
            {
                Id = target.Value,
                ProductId = provider.ProductId,
                CreatedAtUtc = provider.Now
            });
            await db.SaveChangesAsync();
        }
        return new(new RuntimeRecoveryCommercialOwnershipCommandRequest(
            Guid.NewGuid(), operation, provider.LicenseId, active.Id, target));
    }

    /// <summary>Runs exactly the selected proof stage through the production provider service.</summary>
    private static Task<RuntimeSeatRecoveryHttpResult> ExecuteKeyProofAsync(
        RecoveryProviderScenario provider,
        KeyProofRaceInput input,
        string proofStage) => proofStage == "prepare"
        ? provider.Service.PrepareKeyAsync(
            "website-recovery", input.RequestId.ToString("D"), input.Preparation, CancellationToken.None)
        : provider.Service.ConfirmKeyAsync(
            "website-recovery", input.RequestId.ToString("D"), input.Confirmation!, CancellationToken.None);

    /// <summary>
    /// Installs an isolated-database trigger that pauses only the selected proof insert on a test-owned
    /// advisory lock, after all production authority reads and before the transaction can commit.
    /// </summary>
    private static async Task InstallKeyProofRaceGateAsync(
        string adminConnection,
        string proofStage,
        int raceGateKey)
    {
        var table = proofStage == "prepare"
            ? "RuntimeSeatRecoveryKeyPreparations"
            : "RuntimeSeatRecoveryKeyConfirmations";
        await using var connection = new NpgsqlConnection(adminConnection);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $$"""
            CREATE OR REPLACE FUNCTION public.tkt773_f1_key_proof_race_gate()
            RETURNS trigger LANGUAGE plpgsql AS $gate$
            BEGIN
                PERFORM pg_catalog.pg_advisory_xact_lock(773001, {{raceGateKey}});
                RETURN NEW;
            END;
            $gate$;
            CREATE TRIGGER trg_tkt773_f1_key_proof_race_gate
            BEFORE INSERT ON public."{{table}}"
            FOR EACH ROW EXECUTE FUNCTION public.tkt773_f1_key_proof_race_gate();
            """);
    }

    /// <summary>Waits until the proof insert is blocked inside the isolated test trigger.</summary>
    private static async Task<int> WaitForTkt773RaceGateAsync(
        NpgsqlConnection observer,
        string proofApplicationName,
        int gateBackendPid)
    {
        for (var attempt = 0; attempt < 400; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT activity.pid,
                       activity.wait_event_type,
                       activity.wait_event,
                       pg_catalog.pg_blocking_pids(activity.pid)
                FROM pg_catalog.pg_stat_activity AS activity
                WHERE activity.datname = pg_catalog.current_database()
                  AND activity.application_name = @application_name
                ORDER BY activity.pid;
                """, observer);
            command.Parameters.AddWithValue("application_name", proofApplicationName);
            await using var reader = await command.ExecuteReaderAsync();
            int? proofBackendPid = null;
            string? waitEventType = null;
            string? waitEvent = null;
            int[] blockingBackendPids = [];
            while (await reader.ReadAsync())
            {
                Assert.Null(proofBackendPid);
                proofBackendPid = reader.GetInt32(0);
                waitEventType = reader.IsDBNull(1) ? null : reader.GetString(1);
                waitEvent = reader.IsDBNull(2) ? null : reader.GetString(2);
                blockingBackendPids = reader.GetFieldValue<int[]>(3);
            }
            if (proofBackendPid is not null
                && string.Equals(waitEventType, "Lock", StringComparison.Ordinal)
                && string.Equals(waitEvent, "advisory", StringComparison.Ordinal)
                && blockingBackendPids.Contains(gateBackendPid))
                return proofBackendPid.Value;
            await Task.Delay(10);
        }
        throw new TimeoutException(
            $"Proof backend '{proofApplicationName}' did not wait on gate backend {gateBackendPid}.");
    }

    /// <summary>
    /// Observes one simultaneous PostgreSQL snapshot where the original proof backend is still active on
    /// the test advisory gate and the exact writer backend is waiting on that proof while locking the license.
    /// </summary>
    private static async Task WaitForOwnershipWriterLockAsync(
        NpgsqlConnection observer,
        string proofApplicationName,
        string writerApplicationName,
        int proofBackendPid,
        int gateBackendPid,
        Task<RuntimeRecoveryCommercialOwnershipCommandResult> writer)
    {
        string lastObservation = "proof and writer backends absent";
        for (var attempt = 0; attempt < 400; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT activity.pid,
                       activity.application_name,
                       activity.state,
                       activity.wait_event_type,
                       activity.wait_event,
                       pg_catalog.pg_blocking_pids(activity.pid),
                       activity.query
                FROM pg_catalog.pg_stat_activity AS activity
                WHERE activity.datname = pg_catalog.current_database()
                  AND activity.application_name IN (@proof_application_name, @writer_application_name)
                ORDER BY activity.pid;
                """, observer);
            command.Parameters.AddWithValue("proof_application_name", proofApplicationName);
            command.Parameters.AddWithValue("writer_application_name", writerApplicationName);
            await using var reader = await command.ExecuteReaderAsync();
            string? proofState = null;
            string? proofWaitEventType = null;
            string? proofWaitEvent = null;
            int[] proofBlockingBackendPids = [];
            int? writerBackendPid = null;
            string? writerState = null;
            string? writerWaitEventType = null;
            string? writerWaitEvent = null;
            int[] writerBlockingBackendPids = [];
            string? writerQuery = null;
            while (await reader.ReadAsync())
            {
                var applicationName = reader.GetString(1);
                if (string.Equals(applicationName, proofApplicationName, StringComparison.Ordinal))
                {
                    Assert.Equal(proofBackendPid, reader.GetInt32(0));
                    proofState = reader.IsDBNull(2) ? null : reader.GetString(2);
                    proofWaitEventType = reader.IsDBNull(3) ? null : reader.GetString(3);
                    proofWaitEvent = reader.IsDBNull(4) ? null : reader.GetString(4);
                    proofBlockingBackendPids = reader.GetFieldValue<int[]>(5);
                }
                else
                {
                    Assert.Equal(writerApplicationName, applicationName);
                    Assert.Null(writerBackendPid);
                    writerBackendPid = reader.GetInt32(0);
                    writerState = reader.IsDBNull(2) ? null : reader.GetString(2);
                    writerWaitEventType = reader.IsDBNull(3) ? null : reader.GetString(3);
                    writerWaitEvent = reader.IsDBNull(4) ? null : reader.GetString(4);
                    writerBlockingBackendPids = reader.GetFieldValue<int[]>(5);
                    writerQuery = reader.IsDBNull(6) ? null : reader.GetString(6);
                }
            }
            var proofStillOwnsGate = string.Equals(proofState, "active", StringComparison.Ordinal)
                && string.Equals(proofWaitEventType, "Lock", StringComparison.Ordinal)
                && string.Equals(proofWaitEvent, "advisory", StringComparison.Ordinal)
                && proofBlockingBackendPids.Contains(gateBackendPid);
            var writerWaitsAtLicense = writerBackendPid is not null
                && string.Equals(writerState, "active", StringComparison.Ordinal)
                && string.Equals(writerWaitEventType, "Lock", StringComparison.Ordinal)
                && writerBlockingBackendPids.Contains(proofBackendPid)
                && writerQuery?.Contains("FROM public.\"Licenses\"", StringComparison.Ordinal) == true;
            lastObservation = $"proof pid={proofBackendPid}, state={proofState}, "
                + $"wait={proofWaitEventType}/{proofWaitEvent}, blockers=[{string.Join(',', proofBlockingBackendPids)}]; "
                + (writerBackendPid is null
                    ? "writer backend absent"
                    : $"writer pid={writerBackendPid}, state={writerState}, wait={writerWaitEventType}/{writerWaitEvent}, "
                        + $"blockers=[{string.Join(',', writerBlockingBackendPids)}], query={writerQuery}");
            if (proofStillOwnsGate && writerWaitsAtLicense)
                return;
            if (proofStillOwnsGate && writer.IsCompleted)
                throw new InvalidOperationException(
                    $"Writer '{writerApplicationName}' completed while proof backend {proofBackendPid} still owned "
                    + $"the gated license-lock transaction; {lastObservation}.");
            await Task.Delay(10);
        }
        throw new TimeoutException(
            $"Writer backend '{writerApplicationName}' was not observed waiting on proof backend {proofBackendPid}; "
            + $"last observation: {lastObservation}; task status: {writer.Status}.");
    }

    /// <summary>Creates one minimal valid authorized terminal used only to exercise database invariants.</summary>
    private static RuntimeSeatRecoveryAuthorization AuthorizedTerminal(
        string clientId, Guid requestId, Guid reservationRef, Guid recoveryOperationRef) => new()
    {
        AuthenticatedClientId = clientId, RequestId = requestId,
        RequestDigestSha256 = new('a', 64), RecoveryOperationRef = recoveryOperationRef,
        RecoveryDigestSha256 = new('b', 64), CanonicalRequestUtf8 = "{}"u8.ToArray(),
        ReservationRef = reservationRef, Decision = "AUTHORIZED", HttpStatusCode = 200,
        ContentType = "application/json; charset=utf-8", ExactResponseUtf8 = "{}"u8.ToArray(),
        CompletedAtUtc = ExactUtcNow()
    };

    /// <summary>
    /// Creates one minimal valid refused terminal in a selected client namespace, optionally sharing
    /// an opaque operation reference with another client's terminal ledger.
    /// </summary>
    private static RuntimeSeatRecoveryAuthorization RefusedTerminal(
        string clientId,
        Guid requestId,
        Guid? recoveryOperationRef = null) => new()
    {
        AuthenticatedClientId = clientId, RequestId = requestId,
        RequestDigestSha256 = new('c', 64), RecoveryOperationRef = recoveryOperationRef ?? Guid.NewGuid(),
        RecoveryDigestSha256 = new('d', 64), CanonicalRequestUtf8 = "{}"u8.ToArray(),
        Decision = "REFUSED", HttpStatusCode = 403, ErrorCode = "recovery_not_authorized",
        ContentType = "application/json; charset=utf-8", ExactResponseUtf8 = "{}"u8.ToArray(),
        CompletedAtUtc = ExactUtcNow()
    };

    /// <summary>Creates one live reservation whose uniqueness is owned by PostgreSQL.</summary>
    private static RuntimeSeatRecoveryReservation Reservation(
        Guid reservationRef, string clientId, Guid requestId, Guid recoveryOperationRef,
        Guid productId, Guid licenseId, Guid seatId) => new()
    {
        ReservationRef = reservationRef, AuthenticatedClientId = clientId, RequestId = requestId,
        ProductId = productId, LicenseId = licenseId, LicenseSeatId = seatId,
        RecoveryOperationRef = recoveryOperationRef, ProviderGrantRef = "provider-grant",
        State = "RESERVED", CreatedAtUtc = ExactUtcNow(), ExpiresAtUtc = ExactUtcNow().AddMinutes(10)
    };

    /// <summary>
    /// Seeds the complete provider authority required before one recovery decision, including an exact
    /// release registration whose child rows own the digest supplied by the request.
    /// </summary>
    private static async Task<RecoveryProviderScenario> PrepareRecoveryProviderAsync(
        string adminConnection,
        string appConnection,
        string? previousAuthorityFailure = null,
        int? lockTimeoutMilliseconds = null,
        int? statementTimeoutMilliseconds = null)
    {
        // Historical migration fixtures reuse this seeding on databases stopped before later columns
        // (for example Licenses.AuthorityVersion); the factory must match the schema actually present.
        var factory = await TestDbFactory.ForExistingSchemaAsync(adminConnection, appConnection);
        var fixture = await SeedAuthorityAsync(factory, "2.3.445", "*");
        Guid licenseId;
        Guid seatId;
        string hardwareId;
        string hardwareDigest;
        string artifactDigest;
        await using (var setup = await factory.CreateDbContextAsync())
        {
            var binding = await setup.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(item => item.Id == fixture.BindingId);
            var seat = await setup.LicenseSeats.AsNoTracking()
                .SingleAsync(item => item.Id == binding.LicenseSeatId);
            licenseId = binding.LicenseId;
            seatId = binding.LicenseSeatId;
            hardwareId = seat.HardwareId;
            hardwareDigest = binding.HardwareIdHash;

            var binaries = await setup.ApprovedBinaries
                .Where(item => item.ProductId == fixture.ProductId && item.Version == fixture.Version)
                .ToListAsync();
            var exact = binaries.ToDictionary(item => item.Key, item => item.Hash, StringComparer.Ordinal);
            var artifacts = new[] { "FP_EXE", "FP_DLL", "FP_CORE" }
                .Select(key => new ApprovedBinaryArtifact(key, exact[key]))
                .ToList();
            artifactDigest = ApprovedBinaryService.ComputeBaselineDigestSha256(artifacts);
            var registration = new ApprovedBinaryRegistration
            {
                ProductId = fixture.ProductId,
                Version = fixture.Version,
                RegistrationKey = "tkt-000763-f1-" + Guid.NewGuid().ToString("N"),
                ManifestDigestSha256 = new string('7', 64),
                BaselineDigestSha256 = artifactDigest,
                Source = ApprovedBinaryService.ReleaseSource,
                RegisteredAtUtc = ExactUtcNow()
            };
            setup.ApprovedBinaryRegistrations.Add(registration);
            foreach (var binary in binaries)
                binary.ApprovedBinaryRegistrationId = registration.Id;
            await setup.SaveChangesAsync();
        }

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var operationalAuthority = RSA.Create(2048);
        using var recoveryAuthority = RSA.Create(2048);
        using var registryAuthority = RSA.Create(2048);
        var authorityNow = new DateTimeOffset(ExactUtcNow());
        var requestNow = await ReadDatabaseClockAsync(adminConnection);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        if (lockTimeoutMilliseconds is { } lockTimeout)
            runtimeOptions.LockTimeoutMilliseconds = lockTimeout;
        if (statementTimeoutMilliseconds is { } statementTimeout)
            runtimeOptions.StatementTimeoutMilliseconds = statementTimeout;
        var authoritySigning = AuthoritySigningOptions(authorityNow, operationalAuthority, recoveryAuthority);
        var registryCryptography = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(authorityNow), registryAuthority.ExportSubjectPublicKeyInfo());
        var registryInput = registryCryptography.GetRegistrySnapshotAuthenticationInput(
            authoritySigning, authorityNow).Value!;
        runtimeOptions.AuthorityGenerationSigning = authoritySigning;
        runtimeOptions.AuthorityGenerationV2 = new RuntimeAuthorityGenerationV2Options
        {
            Mode = "enabled",
            RegistryAuthoritySpkiBase64 = Convert.ToBase64String(registryAuthority.ExportSubjectPublicKeyInfo()),
            RegistryObservedAtUtc = authorityNow.ToString("O"),
            RegistrySnapshotSignatureBase64Url = Base64Url(registryAuthority.SignData(
                registryInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        };
        await UpsertKeyRegistryAsync(adminConnection, runtimeOptions);
        var previousAuthority = await SeedActivePreviousAuthorityAsync(
            appConnection, factory, fixture.ProductId, fixture.BindingId, licenseId, seatId,
            artifactDigest, previousAuthorityFailure);
        await using (var ownership = await factory.CreateDbContextAsync())
        {
            var ownerSubjectId = Guid.NewGuid();
            // Historical migration fixtures deliberately stop before TKT-000779 and therefore have
            // no subject table. Current-schema fixtures must persist the explicit subject first.
            if (await Tkt779CommercialSubjectTableExistsAsync(adminConnection))
            {
                ownership.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
                {
                    Id = ownerSubjectId,
                    ProductId = fixture.ProductId,
                    CreatedAtUtc = ExactUtcNow()
                });
            }

            var ownershipId = Guid.NewGuid();
            var ownershipCreatedAtUtc = ExactUtcNow();
            if (await Tkt782OwnershipPreviousColumnExistsAsync(adminConnection))
            {
                ownership.RuntimeRecoveryCommercialOwnerships.Add(new RuntimeRecoveryCommercialOwnership
                {
                    Id = ownershipId, ProductId = fixture.ProductId, LicenseId = licenseId,
                    OwnerSubjectId = ownerSubjectId, State = "ACTIVE", CreatedAtUtc = ownershipCreatedAtUtc
                });
                await ownership.SaveChangesAsync();
            }
            else
            {
                // The historical migration oracle deliberately runs the current test assembly against
                // a pre-TKT-000782 table. Persist the subject first, then emit only columns in that schema.
                await ownership.SaveChangesAsync();
                await ownership.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO public."RuntimeRecoveryCommercialOwnerships"
                        ("Id","ProductId","LicenseId","OwnerSubjectId","State","CreatedAtUtc","EndedAtUtc")
                    VALUES
                        ({ownershipId},{fixture.ProductId},{licenseId},{ownerSubjectId},'ACTIVE',
                         {ownershipCreatedAtUtc},NULL)
                    """);
            }
        }

        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(runtimeOptions));
        var seatClaimCrypto = new RuntimeSeatRecoverySeatClaimCryptography(
            (_, _, _, _) => Task.FromResult(true), destination => destination.Fill(0x42));
        var runtimeCrypto = new RuntimeEnrollmentCryptoService(Options.Create(runtimeOptions));
        var service = new RuntimeSeatRecoveryAuthorizationService(factory, authority, seatClaimCrypto,
            runtimeCrypto, Options.Create(runtimeOptions), new FixedTimeProvider(authorityNow));
        return new(factory, fixture.ProductId, fixture.InstallationId, licenseId, seatId, fixture.BindingId, hardwareId,
            hardwareDigest, artifactDigest, previousAuthority.LineageId, previousAuthority.GenerationId,
            service, runtimeCrypto, requestNow);
    }

    /// <summary>
    /// Detects whether an isolated fixture database has crossed the TKT-000779 migration boundary.
    /// The check does not infer ownership and exists only to keep exact historical migration recipes runnable.
    /// </summary>
    /// <param name="connectionString">Connection to the exact current or historical fixture schema.</param>
    /// <returns>True only when PostgreSQL resolves the canonical CommercialSubject table.</returns>
    private static async Task<bool> Tkt779CommercialSubjectTableExistsAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return await ScalarAsync<bool>(connection, """
            SELECT to_regclass('public."RuntimeRecoveryCommercialSubjects"') IS NOT NULL AS "Value";
            """);
    }

    /// <summary>
    /// Detects whether an isolated fixture database has crossed the TKT-000782 ownership-lineage boundary.
    /// </summary>
    /// <param name="connectionString">Connection to the exact current or historical fixture schema.</param>
    /// <returns>True only when PostgreSQL exposes the nullable predecessor column.</returns>
    private static async Task<bool> Tkt782OwnershipPreviousColumnExistsAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return await ScalarAsync<bool>(connection, """
            SELECT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_attribute
                WHERE attrelid = 'public."RuntimeRecoveryCommercialOwnerships"'::regclass
                  AND attname = 'PreviousOwnershipId'
                  AND attnum > 0
                  AND NOT attisdropped
            ) AS "Value";
            """);
    }

    /// <summary>
    /// Seeds one relationally complete previous Runtime authority. Optional corruptions remain valid
    /// database rows but violate exactly one provider tuple invariant so the production resolver must fail closed.
    /// The caller's factory is reused so historical-schema fixtures keep the model matching their database.
    /// </summary>
    private static async Task<(Guid LineageId, Guid GenerationId)> SeedActivePreviousAuthorityAsync(
        string connectionString,
        TestDbFactory factory,
        Guid productId,
        Guid bindingId,
        Guid licenseId,
        Guid seatId,
        string artifactDigest,
        string? failure)
    {
        var lineageId = Guid.NewGuid();
        var generationId = Guid.NewGuid();
        var payloadGenerationId = failure == "historical_head" ? Guid.NewGuid() : generationId;
        var enrollmentId = Guid.NewGuid();
        var authorityRequestId = Guid.NewGuid();
        var createdAt = ExactUtcNow();
        string grantRef;
        string installationId;
        string hardwareDigest;
        string releaseVersion;
        DateTime licenseIssuedAt;
        DateTime? licenseExpiresAt;
        await using (var db = await factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(item => item.Id == bindingId);
            var license = await db.Licenses.AsNoTracking().SingleAsync(item => item.Id == licenseId);
            grantRef = binding.GrantRef;
            installationId = binding.InstallationId;
            hardwareDigest = binding.HardwareIdHash;
            releaseVersion = binding.Version;
            licenseIssuedAt = license.ActivationDate ?? license.CreationDate;
            licenseExpiresAt = license.ExpirationDate;
            if (failure == "binding_superseded")
                binding.State = "superseded";
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = "website-step1",
                BindingId = bindingId,
                ProductId = productId,
                LicenseId = licenseId,
                LicenseSeatId = seatId,
                InstallationId = installationId,
                HardwareIdHash = hardwareDigest,
                ReleaseVersion = releaseVersion,
                HandoffDigestSha256 = binding.HandoffDigestSha256,
                SubjectRefDigestSha256 = new string('5', 64),
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = "enc-2026-01",
                PublicKeySpkiSha256 = new string('6', 64),
                KeyThumbprint = Base64Url(SHA256.HashData(enrollmentId.ToByteArray())),
                ChallengeCiphertext = "test",
                ChallengeKeyId = "enc-2026-01",
                ChallengeDigestSha256 = new string('7', 64),
                State = failure == "enrollment_pending" ? "PENDING" : "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 1,
                AuthorityEpoch = 1,
                ChallengeExpiresAtUtc = createdAt.AddMinutes(10),
                CreatedAtUtc = createdAt,
                ActivatedAtUtc = failure == "enrollment_pending" ? null : createdAt
            });
            await db.SaveChangesAsync();
        }

        var lineageGrant = failure == "grant_divergent" ? "different-historical-grant" : grantRef;
        var payload = new RuntimeEnrollmentAuthorityGenerationPayloadV2
        {
            Schema = "runtime-enrollment-authority-generation-v2",
            ContractVersion = 2,
            AuthorityLineageId = lineageId.ToString("D"),
            AuthorityGenerationId = payloadGenerationId.ToString("D"),
            PreviousGenerationId = null,
            Sequence = 0,
            Provider = "softlicence",
            ProductId = productId.ToString("D"),
            ProviderGrantRef = lineageGrant,
            Release = new RuntimeEnrollmentAuthorityReleaseV2
            {
                Version = releaseVersion,
                ArtifactSetDigest = artifactDigest
            },
            Binding = new RuntimeEnrollmentAuthorityBindingV2
            {
                BindingId = failure == "payload_divergent" ? Guid.NewGuid().ToString("D") : bindingId.ToString("D"),
                HardwareIdDigest = hardwareDigest
            },
            Enrollment = new RuntimeEnrollmentAuthorityEnrollmentV2
            {
                EnrollmentId = enrollmentId.ToString("D"),
                State = failure == "enrollment_pending" ? "pending" : "active",
                IssuedAtUtc = licenseIssuedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"),
                ExpiresAtUtc = licenseExpiresAt?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
            },
            Key = new RuntimeEnrollmentAuthorityKeyV2
            {
                AuthorityKeyId = "previous-active-key",
                SecurityEpoch = 1
            },
            Installation = new RuntimeEnrollmentAuthorityInstallationV2
            {
                InstallationId = installationId,
                SeatId = seatId.ToString("D")
            },
            Transition = new RuntimeEnrollmentAuthorityGenerationTransitionV2
            {
                Kind = "genesis",
                ReasonCode = "INITIAL_ENROLLMENT",
                RequestId = authorityRequestId.ToString("D"),
                OccurredAtUtc = createdAt.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
            }
        };
        var canonicalPayload = JsonSerializer.SerializeToUtf8Bytes(
            payload, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SET CONSTRAINTS ALL DEFERRED;
            INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                ("AuthorityLineageId","Provider","ProductId","LicenseSeatId","ProviderGrantRef",
                 "ProviderGrantRefScalarCount","CreatedAtUtc","HeadGenerationId","HeadSequence")
            VALUES (@lineage,'softlicence',@product,@seat,@grant,@grantScalars,@created,@generation,0);
            INSERT INTO public."RuntimeEnrollmentAuthorityGenerations"
                ("AuthorityGenerationId","AuthorityLineageId","Sequence","PreviousGenerationId",
                 "RequestId","CanonicalPayloadUtf8","SignedStatementUtf8","AuthorityDigest",
                 "SignatureAlgorithm","SignatureKeyId","SignatureValue","OccurredAtUtc","CreatedAtUtc")
            VALUES (@generation,@lineage,0,NULL,@request,@payload,decode('01','hex'),@digest,
                    'PS256','previous-active-key',repeat('A',342),@created,@created);
            """;
        command.Parameters.AddWithValue("lineage", lineageId);
        command.Parameters.AddWithValue("product", productId);
        command.Parameters.AddWithValue("seat", seatId);
        command.Parameters.AddWithValue("grant", lineageGrant);
        command.Parameters.AddWithValue("grantScalars", lineageGrant.EnumerateRunes().Count());
        command.Parameters.AddWithValue("created", createdAt);
        command.Parameters.AddWithValue("generation", generationId);
        command.Parameters.AddWithValue("request", authorityRequestId);
        command.Parameters.AddWithValue("payload", canonicalPayload);
        command.Parameters.AddWithValue("digest", Sha256(Encoding.UTF8.GetString(canonicalPayload)));
        await command.ExecuteNonQueryAsync();
        await transaction.CommitAsync();
        return (lineageId, generationId);
    }

    /// <summary>
    /// Builds and strictly reparses one canonical recovery request for provider integration tests.
    /// The provider grant is inserted literally so cross-grant tests retain exact opaque string semantics.
    /// </summary>
    private static RuntimeSeatRecoveryContractCodec.AuthorizationParseResult ParseRecoveryRequest(
        Guid requestId, Guid recoveryRef, Guid productId, Guid licenseId, string installationId,
        string hardwareDigest, DateTime expiresAtUtc, string recoveryDigest,
        string? artifactDigest = null,
        string providerGrantRef = "provider-recovery-grant",
        string? publicKeySpkiSha256 = null,
        string? keyThumbprint = null)
    {
        var spkiDigest = Enumerable.Repeat((byte)0xc6, 32).ToArray();
        var spkiHex = publicKeySpkiSha256 ?? Convert.ToHexStringLower(spkiDigest);
        var thumbprint = keyThumbprint
            ?? Convert.ToBase64String(spkiDigest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var json = $"{{\"schema\":\"runtime-seat-recovery-authorization-v1\",\"contractVersion\":1,"
            + $"\"requestId\":\"{requestId:D}\",\"recoveryOperationRef\":\"{recoveryRef:D}\","
            + $"\"recoveryDigestSha256\":\"{recoveryDigest}\",\"provider\":\"softlicence\","
            + $"\"providerGrantRef\":\"{providerGrantRef}\",\"productId\":\"{productId:D}\","
            + $"\"licenseId\":\"{licenseId:D}\",\"seatClaim\":null,\"installation\":{{"
            + $"\"installationId\":\"{installationId}\",\"hardwareIdDigestSha256\":\"{hardwareDigest}\"}},"
            + "\"release\":{\"version\":\"2.3.445\",\"artifactSetDigestSha256\":"
            + $"\"{artifactDigest ?? new string('1', 64)}\"}},\"newKeyCommitment\":{{\"algorithm\":\"PS256\","
            + $"\"publicKeySpkiSha256\":\"{spkiHex}\",\"keyThumbprint\":\"{thumbprint}\"}},"
            + $"\"expiresAtUtc\":\"{expiresAtUtc:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'}\"}}";
        var parsed = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(Encoding.UTF8.GetBytes(json));
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        return parsed;
    }

    /// <summary>
    /// Migrates one isolated PostgreSQL database to the exact F6 predecessor, seeds a relationally
    /// complete provider scenario, and adds one legacy prepared recovery authority. The negative
    /// variant uses a predecessor generation that the old schema deliberately did not constrain.
    /// </summary>
    private static async Task<F6MigrationScenario> SeedPreviousF6RecoveryAuthorityAsync(
        string sharedAdminConnection,
        string database,
        string previousMigration,
        bool orphanPreviousGeneration)
    {
        var admin = new NpgsqlConnectionStringBuilder(sharedAdminConnection)
            { Database = database }.ConnectionString;
        var app = new NpgsqlConnectionStringBuilder(admin)
        {
            Username = "softlicence_runtime_test_app",
            Password = "runtime-test-only"
        }.ConnectionString;
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
        await using (var db = new LicenseDbContext(options))
            await db.GetService<IMigrator>().MigrateAsync(previousMigration);
        await using (var privilegeConnection = new NpgsqlConnection(admin))
        {
            await privilegeConnection.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(privilegeConnection);
        }
        var provider = await PrepareRecoveryProviderAsync(admin, app);
        var reservationRef = Guid.NewGuid();
        var requestId = Guid.NewGuid();
        var recoveryOperationRef = Guid.NewGuid();
        var previousGenerationId = orphanPreviousGeneration
            ? Guid.NewGuid()
            : provider.PreviousAuthorityGenerationId;
        await using var connection = new NpgsqlConnection(admin);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public."RuntimeSeatRecoveryAuthorizations"
                ("AuthenticatedClientId","RequestId","RequestDigestSha256","RecoveryOperationRef",
                 "RecoveryDigestSha256","CanonicalRequestUtf8","ReservationRef","Decision",
                 "HttpStatusCode","ContentType","ErrorCode","ExactResponseUtf8","CompletedAtUtc")
            VALUES
                ('website-recovery-migration',@request,repeat('1',64),@operation,repeat('2',64),
                 decode('7b7d','hex'),@reservation,'AUTHORIZED',200,'application/json',NULL,
                 decode('7b7d','hex'),clock_timestamp());

            INSERT INTO public."RuntimeSeatRecoveryReservations"
                ("ReservationRef","AuthenticatedClientId","RequestId","ProductId","LicenseId",
                 "LicenseSeatId","RecoveryOperationRef","ProviderGrantRef","State","CreatedAtUtc",
                 "ExpiresAtUtc")
            VALUES
                (@reservation,'website-recovery-migration',@request,@product,@license,@seat,@operation,
                 'historical-provider-grant','RESERVED',clock_timestamp(),clock_timestamp()+interval '10 minutes');

            INSERT INTO public."RuntimeSeatRecoveryAuthorities"
                ("ReservationRef","AuthorityLineageId","AuthorityGenerationId",
                 "PreviousAuthorityGenerationId","BindingId","EnrollmentId","InstallationId",
                 "HardwareIdDigestSha256","ReleaseVersion","ArtifactSetDigestSha256",
                 "PublicKeySpkiSha256","KeyThumbprint","State","IsCurrentHead",
                 "PreviousAuthorityState","SubjectRefDigestSha256","CreatedAtUtc")
            VALUES
                (@reservation,@lineage,@generation,@previous,@binding,@enrollment,@installation,
                 @hardware,'2.3.445',@artifact,repeat('3',64),repeat('A',43),'PREPARED',true,
                 'ACTIVE',repeat('4',64),clock_timestamp());
            """, connection, transaction);
        command.Parameters.AddWithValue("request", requestId);
        command.Parameters.AddWithValue("operation", recoveryOperationRef);
        command.Parameters.AddWithValue("reservation", reservationRef);
        command.Parameters.AddWithValue("product", provider.ProductId);
        command.Parameters.AddWithValue("license", provider.LicenseId);
        command.Parameters.AddWithValue("seat", provider.SeatId);
        command.Parameters.AddWithValue("lineage", provider.PreviousAuthorityLineageId);
        command.Parameters.AddWithValue("generation", provider.PreviousAuthorityGenerationId);
        command.Parameters.AddWithValue("previous", previousGenerationId);
        command.Parameters.AddWithValue("binding", Guid.NewGuid());
        command.Parameters.AddWithValue("enrollment", Guid.NewGuid());
        command.Parameters.AddWithValue("installation", Guid.Parse(provider.InstallationId));
        command.Parameters.AddWithValue("hardware", provider.HardwareDigest);
        command.Parameters.AddWithValue("artifact", provider.ArtifactDigest);
        Assert.Equal(3, await command.ExecuteNonQueryAsync());
        await transaction.CommitAsync();
        return new(admin, reservationRef, provider.PreviousAuthorityLineageId);
    }

    /// <summary>
    /// Captures the exact legacy authority row, ordered schema columns, constraints, and migration
    /// head so an expected 23503 can prove the transactional migration left no partial schema or data.
    /// </summary>
    private static async Task<F6PreMigrationSnapshot> ReadF6PreMigrationSnapshotAsync(
        NpgsqlConnection connection,
        Guid reservationRef)
    {
        await using var command = new NpgsqlCommand("""
            SELECT
                (SELECT row_to_json(authority)::text
                 FROM public."RuntimeSeatRecoveryAuthorities" AS authority
                 WHERE authority."ReservationRef" = @reservation),
                (SELECT string_agg(column_name || ':' || data_type || ':' || is_nullable, ',' ORDER BY ordinal_position)
                 FROM information_schema.columns
                 WHERE table_schema = 'public' AND table_name = 'RuntimeSeatRecoveryAuthorities'),
                (SELECT string_agg(conname || ':' || pg_catalog.pg_get_constraintdef(oid), E'\n' ORDER BY conname)
                 FROM pg_catalog.pg_constraint
                 WHERE conrelid = 'public."RuntimeSeatRecoveryAuthorities"'::regclass),
                (SELECT string_agg(tgname || ':' || tgenabled::text || ':' || pg_catalog.pg_get_triggerdef(oid), E'\n' ORDER BY tgname)
                 FROM pg_catalog.pg_trigger
                 WHERE tgrelid = 'public."RuntimeSeatRecoveryAuthorities"'::regclass
                   AND NOT tgisinternal),
                (SELECT "MigrationId" FROM public."__EFMigrationsHistory" ORDER BY "MigrationId" DESC LIMIT 1);
            """, connection);
        command.Parameters.AddWithValue("reservation", reservationRef);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
            reader.GetString(4));
    }

    /// <summary>
    /// Temporarily disables only the recovery-authority lifecycle guard inside a rollback-only
    /// transaction, then proves the named composite foreign key rejects one cross-lineage pairing.
    /// </summary>
    private static async Task AssertRecoveryAuthorityCompositeForeignKeyAsync(
        string connectionString,
        string lineageColumn,
        Guid mismatchedLineageId,
        string expectedConstraint)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        try
        {
            await using (var disableGuard = new NpgsqlCommand("""
                ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                DISABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;
                """, connection, transaction))
                await disableGuard.ExecuteNonQueryAsync();
            var updateSql = lineageColumn switch
            {
                "AuthorityLineageId" => """
                    UPDATE public."RuntimeSeatRecoveryAuthorities"
                    SET "AuthorityLineageId" = @lineage;
                    """,
                "PreviousAuthorityLineageId" => """
                    UPDATE public."RuntimeSeatRecoveryAuthorities"
                    SET "PreviousAuthorityLineageId" = @lineage;
                    """,
                _ => throw new ArgumentOutOfRangeException(nameof(lineageColumn))
            };
            await using var mismatch = new NpgsqlCommand(updateSql, connection, transaction);
            mismatch.Parameters.AddWithValue("lineage", mismatchedLineageId);

            var exception = await Assert.ThrowsAsync<PostgresException>(() => mismatch.ExecuteNonQueryAsync());

            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, exception.SqlState);
            Assert.Equal(expectedConstraint, exception.ConstraintName);
        }
        finally
        {
            await transaction.RollbackAsync();
        }
    }

    /// <summary>Reads PostgreSQL clock_timestamp as the authoritative wall-clock instant.</summary>
    private static async Task<DateTime> ReadDatabaseClockAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return await ReadDatabaseClockAsync(connection, null);
    }

    /// <summary>Reads PostgreSQL clock_timestamp on an existing connection and optional transaction.</summary>
    private static async Task<DateTime> ReadDatabaseClockAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction)
    {
        await using var command = new NpgsqlCommand(
            "SELECT pg_catalog.clock_timestamp() AT TIME ZONE 'UTC';", connection, transaction);
        return DateTime.SpecifyKind((DateTime)(await command.ExecuteScalarAsync())!, DateTimeKind.Utc);
    }

    /// <summary>
    /// Waits until the application connection is blocked on the named recovery query, proving the
    /// tested delay occurs after command entry and before the decisive row lock is acquired.
    /// </summary>
    private static async Task WaitForBlockedRecoveryQueryAsync(
        NpgsqlConnection observer,
        NpgsqlTransaction observerTransaction,
        string queryFragment)
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            await using (var clearSnapshot = new NpgsqlCommand(
                "SELECT pg_catalog.pg_stat_clear_snapshot();", observer, observerTransaction))
                await clearSnapshot.ExecuteNonQueryAsync();
            await using var command = new NpgsqlCommand("""
                SELECT count(*)
                FROM pg_catalog.pg_stat_activity
                WHERE usename = 'softlicence_runtime_test_app'
                  AND wait_event_type = 'Lock'
                  AND query LIKE '%' || @fragment || '%';
                """, observer, observerTransaction);
            command.Parameters.AddWithValue("fragment", queryFragment);
            if (Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture) >= 1)
                return;
            await Task.Delay(10);
        }
        throw new TimeoutException($"Expected a recovery query blocked on {queryFragment}.");
    }

    /// <summary>
    /// Reads the durable recovery row counts used to prove a refusal changes only its own terminal
    /// namespace and never creates or mutates authorized provider resources.
    /// </summary>
    private static async Task<RecoveryCounts> ReadRecoveryCountsAsync(IDbContextFactory<LicenseDbContext> factory)
    {
        await using var db = await factory.CreateDbContextAsync();
        return new(
            await db.RuntimeSeatRecoveryAuthorizations.CountAsync(),
            await db.RuntimeSeatRecoveryReservations.CountAsync(),
            await db.RuntimeSeatRecoveryAuthorities.CountAsync(),
            await db.RuntimeRecoveryGrantOwnerships.CountAsync(),
            await db.RuntimeEnrollmentAuthorityGenerations.CountAsync(),
            await db.RuntimeEnrollmentAuthorityLineages.CountAsync(),
            await db.RuntimeRecoveryCommercialOwnerships.CountAsync(),
            await db.Licenses.CountAsync(),
            await db.LicenseSeats.CountAsync(),
            await db.DistributionInstallationBindings.CountAsync(),
            await db.RuntimeEnrollments.CountAsync());
    }

    /// <summary>
    /// Installs isolated, test-owned row triggers over every commercial and Runtime authority table
    /// whose mutation would invalidate a terminal recovery replay.
    /// </summary>
    private static async Task InstallComposition10MutationAuditAsync(NpgsqlConnection connection)
    {
        await ExecuteAsync(connection, """
            CREATE TABLE public.tkt730_composition10_mutations (
                "TableName" text NOT NULL,
                "Operation" text NOT NULL
            );
            CREATE FUNCTION public.tkt730_composition10_record_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $audit$
            BEGIN
                INSERT INTO public.tkt730_composition10_mutations ("TableName", "Operation")
                VALUES (TG_TABLE_NAME, TG_OP);
                RETURN COALESCE(NEW, OLD);
            END;
            $audit$;
            DO $install$
            DECLARE target text;
            BEGIN
                FOREACH target IN ARRAY ARRAY[
                    'Licenses', 'LicenseSeats', 'DistributionInstallationBindings', 'RuntimeEnrollments',
                    'RuntimeSeatRecoveryAuthorizations', 'RuntimeSeatRecoveryReservations',
                    'RuntimeSeatRecoveryAuthorities', 'RuntimeSeatRecoveryProofReceipts',
                    'RuntimeSeatRecoveryActivationReceipts', 'RuntimeRecoveryGrantOwnerships',
                    'RuntimeRecoveryCommercialOwnerships', 'RuntimeEnrollmentAuthorityLineages',
                    'RuntimeEnrollmentAuthorityGenerations'
                ] LOOP
                    EXECUTE format(
                        'CREATE TRIGGER trg_tkt730_composition10_audit AFTER INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.tkt730_composition10_record_mutation()',
                        target);
                END LOOP;
            END;
            $install$;
            """);
    }

    /// <summary>
    /// Returns a privacy-safe digest of complete, deterministically ordered rows across the same
    /// commercial and Runtime authority graph; raw license and machine values never leave memory.
    /// </summary>
    private static async Task<string> ReadComposition10SnapshotSha256Async(NpgsqlConnection connection)
    {
        var builder = new StringBuilder();
        foreach (var table in Composition10SnapshotTables)
        {
            await using var command = new NpgsqlCommand(
                $"SELECT COALESCE(jsonb_agg(to_jsonb(row_value) ORDER BY to_jsonb(row_value)::text)::text, '[]') FROM public.\"{table}\" row_value;",
                connection);
            builder.Append('\n').Append(table).Append('=').Append(
                Convert.ToString(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture));
        }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    /// <summary>Removes every test-owned audit object even when the replay assertion fails.</summary>
    private static async Task RemoveComposition10MutationAuditAsync(NpgsqlConnection connection)
    {
        foreach (var table in Composition10SnapshotTables)
        {
            await ExecuteAsync(connection,
                $"DROP TRIGGER IF EXISTS trg_tkt730_composition10_audit ON public.\"{table}\";");
        }
        await ExecuteAsync(connection, """
            DROP FUNCTION IF EXISTS public.tkt730_composition10_record_mutation();
            DROP TABLE IF EXISTS public.tkt730_composition10_mutations;
            """);
    }

    /// <summary>Names the complete isolated recovery graph in deterministic ordinal order.</summary>
    private static readonly string[] Composition10SnapshotTables =
    [
        "Licenses", "LicenseSeats", "DistributionInstallationBindings", "RuntimeEnrollments",
        "RuntimeSeatRecoveryAuthorizations", "RuntimeSeatRecoveryReservations",
        "RuntimeSeatRecoveryAuthorities", "RuntimeSeatRecoveryProofReceipts",
        "RuntimeSeatRecoveryActivationReceipts", "RuntimeRecoveryGrantOwnerships",
        "RuntimeRecoveryCommercialOwnerships", "RuntimeEnrollmentAuthorityLineages",
        "RuntimeEnrollmentAuthorityGenerations"
    ];

    /// <summary>
    /// Counts the distinct PostgreSQL backends that wait on the test-owned recovery advisory lock
    /// until the bounded provider operation completes. The timeout scenario disables pooling for both
    /// observer and application connections, so each observed backend is exactly one transaction attempt.
    /// </summary>
    private static async Task<int> ObserveRecoveryAdvisoryLockAttemptsAsync(
        NpgsqlConnection observer,
        NpgsqlTransaction observerTransaction,
        Task<RuntimeSeatRecoveryHttpResult> pending)
    {
        var processIds = new HashSet<int>();
        while (!pending.IsCompleted)
        {
            await using (var clearSnapshot = new NpgsqlCommand(
                "SELECT pg_catalog.pg_stat_clear_snapshot();", observer, observerTransaction))
                await clearSnapshot.ExecuteNonQueryAsync();
            await using var command = new NpgsqlCommand("""
                SELECT pid
                FROM pg_catalog.pg_stat_activity
                WHERE usename = 'softlicence_runtime_test_app'
                  AND wait_event_type = 'Lock'
                  AND query LIKE '%pg_advisory_xact_lock(999831, 1)%';
                """, observer, observerTransaction);
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                processIds.Add(reader.GetInt32(0));
            await Task.Delay(5);
        }
        return processIds.Count;
    }

    /// <summary>
    /// Waits until the requested number of provider transactions are queued behind the test-owned
    /// global recovery advisory lock, making client A the deterministic first lock waiter.
    /// </summary>
    private static async Task WaitForRecoveryAdvisoryWaitersAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        int expectedWaiters)
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT count(*)
                FROM pg_catalog.pg_locks
                WHERE locktype = 'advisory' AND classid = 999831 AND objid = 1 AND NOT granted;
                """, connection, transaction);
            if (Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture) >= expectedWaiters)
                return;
            await Task.Delay(10);
        }
        throw new TimeoutException($"Expected {expectedWaiters} queued recovery advisory lock waiter(s).");
    }

    /// <summary>Captures every durable entity that authorization can create, bind, or otherwise affect.</summary>
    private sealed record RecoveryCounts(
        int Terminals,
        int Reservations,
        int Authorities,
        int GrantOwnerships,
        int Generations,
        int Lineages,
        int CommercialOwnerships,
        int Licenses,
        int Seats,
        int DistributionBindings,
        int RuntimeEnrollments);

    /// <summary>Identifies one isolated database and its seeded legacy F6 authority.</summary>
    private sealed record F6MigrationScenario(
        string Admin,
        Guid ReservationRef,
        Guid PreviousLineageId);

    /// <summary>Freezes every pre-F6 schema and row observation that must survive failed migration.</summary>
    private sealed record F6PreMigrationSnapshot(
        string AuthorityRow,
        string Columns,
        string Constraints,
        string Triggers,
        string LastMigration);

    /// <summary>Holds the exact preparation and optional confirmation used by one F1 race leg.</summary>
    private sealed record KeyProofRaceInput(
        Guid RequestId,
        Guid PrepareRef,
        RuntimeSeatRecoveryContractCodec.KeyPreparationParseResult Preparation,
        RuntimeSeatRecoveryContractCodec.KeyConfirmationParseResult? Confirmation);

    /// <summary>Holds one durable PROVED receipt and its canonical activation command.</summary>
    private sealed record ProvedActivationInput(
        Guid RequestId,
        Guid ReservationRef,
        Guid PrepareRef,
        DateTime ExpiresAtUtc,
        RuntimeSeatRecoveryContractCodec.ActivationParseResult Activation);

    /// <summary>Holds one provider-authenticated ownership transition raced against TKT-000773.</summary>
    private sealed record OwnershipRaceCommand(
        RuntimeRecoveryCommercialOwnershipCommandRequest Request);

    /// <summary>Holds one isolated provider scenario and its exact authority inputs.</summary>
    private sealed record RecoveryProviderScenario(
        TestDbFactory Factory,
        Guid ProductId,
        string InstallationId,
        Guid LicenseId,
        Guid SeatId,
        Guid PreviousAuthorityBindingId,
        string HardwareId,
        string HardwareDigest,
        string ArtifactDigest,
        Guid PreviousAuthorityLineageId,
        Guid PreviousAuthorityGenerationId,
        RuntimeSeatRecoveryAuthorizationService Service,
        RuntimeEnrollmentCryptoService Crypto,
        DateTime Now);
}
