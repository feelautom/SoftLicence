using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Hosting;
using SoftLicence.Server.Data;
using System.Data.Common;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises decision history against the existing PostgreSQL authority fixture using synthetic licences only.</summary>
/// <remarks>The runner owns one fresh bounded container; these tests never read production configuration or change licensing predicates.</remarks>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Proves a refusal raised after a real finalization SaveChanges undoes every business row and the provisional accepted event.</summary>
    /// <remarks>The injected refusal occurs before commit, after EF has accepted saved entity states. Only the refused decision may remain; a subsequent fault-free operation can still succeed.</remarks>
    [Fact]
    public async Task Tkt976_Finalize_RefusalAfterSavedBusiness_RestoresWholeDatabaseExceptRefusal()
    {
        var connections = await ProvisionAsync();
        var cleanFactory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(cleanFactory, includeSeat: false);
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState("business-after-save", requestCancellation, shutdown);
        var factory = new Tkt976FaultFactory(connections.App, fault);
        var now = DateTimeOffset.UtcNow;
        var protection = new EphemeralDataProtectionProvider();
        var service = new DistributionInstallationBindingService(factory, protection,
            new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var request = await Tkt976_CreateRequestAsync(service, fixture, now,
            Guid.NewGuid().ToString("N")[..16].ToUpperInvariant());
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        fault.Armed = true;
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
            "tkt976-synthetic-client", Sha256("tkt976-finalize"), request));
        Assert.Equal("synthetic_business_refusal", refusal.ErrorCode);
        Assert.True(fault.Triggered);
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using (var observed = await cleanFactory.CreateDbContextAsync())
        {
            var row = Assert.Single(await observed.LicenseHistories.Where(entry => entry.LicenseId == fixture.LicenseId).ToListAsync());
            Assert.Contains("synthetic_business_refusal", row.Details!);
            Assert.DoesNotContain("\"outcome\":\"accepted\"", row.Details!);
        }
        var retryService = new DistributionInstallationBindingService(cleanFactory, protection,
            new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        Assert.False((await retryService.FinalizeAsync(
            "tkt976-synthetic-client", Sha256("tkt976-finalize"), request)).Idempotent);
    }

    /// <summary>Proves refusal persistence failure/cancellation boundaries without changing the licensing refusal or claiming absence after an unknown commit.</summary>
    /// <param name="mode">One synthetic insertion, pre-commit, lost-acknowledgement, client-cancellation, host-stop or timeout fault.</param>
    /// <remarks>Faults are armed only after entitlement setup. A fresh observer verifies all business tables, history presence and lock release. Retrying without the fault must yield exactly one durable refusal.</remarks>
    [Theory]
    [InlineData("insert")]
    [InlineData("commit-before")]
    [InlineData("commit-ack")]
    [InlineData("cancel-before")]
    [InlineData("cancel-after")]
    [InlineData("host-stop")]
    [InlineData("timeout")]
    public async Task Tkt976_Finalize_PersistenceFaultsRemainExplicitAndReplayWithoutDuplicate(string mode)
    {
        var connections = await ProvisionAsync();
        var cleanFactory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(cleanFactory);
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        var factory = new Tkt976FaultFactory(connections.App, fault);
        var now = DateTimeOffset.UtcNow;
        var protection = new EphemeralDataProtectionProvider();
        var service = new DistributionInstallationBindingService(factory, protection,
            new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance,
            applicationLifetime: new Tkt976HostLifetime(shutdown));
        var request = await Tkt976_CreateRequestAsync(service, fixture, now,
            Guid.NewGuid().ToString("N")[..16].ToUpperInvariant());
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        fault.Armed = true;
        if (mode == "cancel-before")
            requestCancellation.Cancel();
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        if (mode == "cancel-before")
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("tkt976-finalize"), request, requestCancellation.Token));
        }
        else if (mode == "cancel-after")
        {
            var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("tkt976-finalize"), request, requestCancellation.Token));
            Assert.Equal(422, refusal.StatusCode);
            Assert.Equal("seat_limit_reached", refusal.ErrorCode);
            Assert.True(requestCancellation.IsCancellationRequested);
        }
        else
        {
            var technical = await Assert.ThrowsAsync<InvalidOperationException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("tkt976-finalize"), request, requestCancellation.Token));
            Assert.StartsWith("Licence decision ", technical.Message);
            if (mode == "commit-ack")
                Assert.Contains("indeterminate", technical.Message);
        }
        elapsed.Stop();
        if (mode == "timeout")
            Assert.InRange(elapsed.Elapsed.TotalSeconds, 4.5, 15);
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using (var observed = await cleanFactory.CreateDbContextAsync())
        {
            var expectedHistory = mode is "commit-ack" or "cancel-after" ? 1 : 0;
            Assert.Equal(expectedHistory, await observed.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId));
            await using var lockCheck = await observed.Database.BeginTransactionAsync();
            Assert.True(await observed.Database.SqlQueryRaw<bool>(
                "SELECT pg_try_advisory_xact_lock(999831, 1) AS \"Value\"").SingleAsync());
            await lockCheck.RollbackAsync();
        }

        // A new host/request may retry after an uncertain acknowledgement. Reuse the exact
        // operation and protected entitlement, never a time window or a changed client request.
        var retryService = new DistributionInstallationBindingService(cleanFactory, protection,
            new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var retried = await Assert.ThrowsAsync<DistributionOperationException>(() => retryService.FinalizeAsync(
            "tkt976-synthetic-client", Sha256("tkt976-finalize"), request));
        Assert.Equal("seat_limit_reached", retried.ErrorCode);
        await using var final = await cleanFactory.CreateDbContextAsync();
        Assert.Equal(1, await final.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId));
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
    }

    /// <summary>Shares one explicitly armed synthetic fault between interceptors; callers own both cancellation sources.</summary>
    private sealed class Tkt976FaultState(string mode, CancellationTokenSource request, CancellationTokenSource shutdown)
    {
        /// <summary>Closed theory mode; never derived from user input or production configuration.</summary>
        internal string Mode { get; } = mode;
        /// <summary>Setup remains unaffected until the test arms the single observed operation.</summary>
        internal bool Armed { get; set; }
        /// <summary>Records the single post-save business failure so refusal persistence cannot trigger the same injected failure again.</summary>
        internal bool Triggered { get; set; }
        /// <summary>Proves a paid ban was actually staged inactive before the producer cleared its context during refusal rollback.</summary>
        internal bool ObservedPendingPaidUnban { get; set; }
        /// <summary>Caller-owned HTTP cancellation source, independent of host shutdown.</summary>
        internal CancellationTokenSource Request { get; } = request;
        /// <summary>Caller-owned application shutdown source respected by bounded refusal persistence.</summary>
        internal CancellationTokenSource Shutdown { get; } = shutdown;
    }

    /// <summary>Creates isolated synthetic application-role contexts with fault hooks; no shared context is detached by production Clear.</summary>
    private sealed class Tkt976FaultFactory(string connection, Tkt976FaultState fault) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Returns a new caller-owned context; interceptors change only the armed synthetic operation.</summary>
        public LicenseDbContext CreateDbContext() => new(new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connection).AddInterceptors(new Tkt976TransactionFault(fault), new Tkt976InsertFault(fault)).Options);

        /// <summary>Honors cancellation before allocating an isolated context and transfers disposal responsibility to the caller.</summary>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CreateDbContext());
        }
    }

    /// <summary>Injects cancellation and commit acknowledgement faults at actual EF transaction boundaries, without starting another transaction.</summary>
    private sealed class Tkt976TransactionFault(Tkt976FaultState fault) : DbTransactionInterceptor
    {
        /// <summary>Cancels client or host at refusal rollback, or proves a synthetic 23505 leaves 25P02 before the real savepoint rollback restores transaction usability.</summary>
        public override async ValueTask<InterceptionResult> RollingBackToSavepointAsync(DbTransaction transaction,
            TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (fault.Armed && eventData.Context is { } context)
                fault.ObservedPendingPaidUnban |= context.ChangeTracker.Entries<BannedHardwareId>().Any(entry =>
                    entry.OriginalValues.GetValue<bool>(nameof(BannedHardwareId.IsActive)) && !entry.Entity.IsActive);
            if (fault.Armed && fault.Mode == "cancel-after") fault.Request.Cancel();
            if (fault.Armed && fault.Mode == "host-stop") fault.Shutdown.Cancel();
            if (fault.Armed && fault.Mode == "aborted-before-rollback")
            {
                var db = eventData.Context!;
                var duplicate = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => db.Database.ExecuteSqlRawAsync(
                    "INSERT INTO \"Licenses\" SELECT * FROM \"Licenses\" LIMIT 1", cancellationToken));
                Assert.Equal("23505", duplicate.SqlState);
                var aborted = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                    db.Database.ExecuteSqlRawAsync("SELECT 1", cancellationToken));
                Assert.Equal("25P02", aborted.SqlState);
                fault.Triggered = true;
            }
            return result;
        }

        /// <summary>Fails before PostgreSQL commit for the armed pre-commit fault; disposal must roll back the saved history.</summary>
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,
            TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (fault.Armed && fault.Mode == "commit-before") throw new IOException("Synthetic commit failure.");
            return ValueTask.FromResult(result);
        }

        /// <summary>Throws only after PostgreSQL committed, simulating loss of the acknowledgement observed by the service.</summary>
        public override Task TransactionCommittedAsync(DbTransaction transaction,
            TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            if (fault.Armed && fault.Mode == "commit-ack") throw new IOException("Synthetic lost commit acknowledgement.");
            return Task.CompletedTask;
        }
    }

    /// <summary>Injects SQL insertion failure, client/host cancellation at insertion, or the producer's five-second timeout at the decision persistence boundary; all faults use private synthetic state.</summary>
    private sealed class Tkt976InsertFault(Tkt976FaultState fault) : SaveChangesInterceptor
    {
        /// <summary>Raises a one-shot synthetic business refusal after accepted finalization rows were saved, before the service commits.</summary>
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData,
            int result, CancellationToken cancellationToken = default)
        {
            if (fault.Armed && !fault.Triggered && fault.Mode is "business-after-save" or "runtime-business-after-save"
                && eventData.Context!.ChangeTracker.Entries<LicenseHistory>().Any(entry =>
                    entry.Entity.Details?.Contains("\"outcome\":\"accepted\"", StringComparison.Ordinal) == true))
            {
                fault.Triggered = true;
                if (fault.Mode == "runtime-business-after-save")
                    throw new RuntimeEnrollmentException("synthetic_transfer_refusal", 422);
                throw new DistributionOperationException("synthetic_business_refusal", 422);
            }
            return ValueTask.FromResult(result);
        }

        /// <summary>Targets only added decision rows; setup and non-decision business saves retain their normal behavior.</summary>
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (fault.Armed && eventData.Context is { } db && db.ChangeTracker.Entries<LicenseHistory>()
                    .Any(entry => entry.State == EntityState.Added && entry.Entity.DecisionKey != null))
            {
                if (fault.Mode == "cancel-at-insert") fault.Request.Cancel();
                if (fault.Mode == "host-at-insert") fault.Shutdown.Cancel();
                if (fault.Mode == "timeout")
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                if (fault.Mode == "insert")
                    await db.Database.ExecuteSqlRawAsync(
                        "INSERT INTO \"LicenseHistories\" (\"Id\", \"LicenseId\", \"Timestamp\", \"Action\") VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', now(), 'TKT976_SYNTHETIC_INSERT')",
                        cancellationToken);
            }
            return result;
        }
    }

    /// <summary>Exposes caller-owned synthetic host shutdown without owning a real application lifecycle.</summary>
    private sealed class Tkt976HostLifetime(CancellationTokenSource shutdown) : IHostApplicationLifetime
    {
        /// <summary>No application-start notification is needed by this isolated service fixture.</summary>
        public CancellationToken ApplicationStarted => CancellationToken.None;
        /// <summary>Links bounded refusal persistence to the test-owned shutdown signal.</summary>
        public CancellationToken ApplicationStopping => shutdown.Token;
        /// <summary>No application-stopped notification is needed by this isolated service fixture.</summary>
        public CancellationToken ApplicationStopped => CancellationToken.None;
        /// <summary>Cancels only the fixture's synthetic host signal.</summary>
        public void StopApplication() => shutdown.Cancel();
    }

    /// <summary>Proves an outer transaction can retain only a decision after undoing already-saved business changes.</summary>
    /// <param name="failure">Synthetic failure after the business save: none, PostgreSQL division/uniqueness transaction-aborted, or request cancellation.</param>
    /// <remarks>The savepoint follows the authority lock. EF tracking must be cleared because SQL rollback does not restore its accepted entity values. Recovery uses a separate bounded token and never opens another transaction.</remarks>
    [Theory]
    [InlineData("none")]
    [InlineData("sql-aborted")]
    [InlineData("unique-aborted")]
    [InlineData("cancellation")]
    public async Task Tkt976_Savepoint_RestoresBusinessAndCommitsOnlyDecision(string failure)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        await using (var db = await factory.CreateDbContextAsync())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted);
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock({976}, {1})");
            await transaction.CreateSavepointAsync("tkt976_business");
            var seat = await db.LicenseSeats.SingleAsync(row => row.LicenseId == fixture.LicenseId);
            seat.IsActive = false;
            db.LicenseHistories.Add(new SoftLicence.Server.Data.LicenseHistory
            {
                LicenseId = fixture.LicenseId, Action = "TKT976_BUSINESS_ROLLED_BACK"
            });
            await db.SaveChangesAsync();
            if (failure == "sql-aborted")
            {
                var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                    db.Database.ExecuteSqlRawAsync("SELECT 1 / 0"));
                Assert.Equal("22012", error.SqlState);
                var aborted = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                    db.Database.ExecuteSqlRawAsync("SELECT 1"));
                Assert.Equal("25P02", aborted.SqlState);
            }
            else if (failure == "unique-aborted")
            {
                var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                    db.Database.ExecuteSqlInterpolatedAsync(
                        $"INSERT INTO \"LicenseSeats\" SELECT * FROM \"LicenseSeats\" WHERE \"Id\" = {seat.Id}"));
                Assert.Equal("23505", error.SqlState);
                var aborted = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                    db.Database.ExecuteSqlRawAsync("SELECT 1"));
                Assert.Equal("25P02", aborted.SqlState);
            }
            else if (failure == "cancellation")
            {
                using var canceled = new CancellationTokenSource();
                canceled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    db.Database.ExecuteSqlRawAsync("SELECT 1", canceled.Token));
            }

            using var recovery = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await transaction.RollbackToSavepointAsync("tkt976_business", recovery.Token);
            await db.Database.ExecuteSqlRawAsync("SELECT 1", recovery.Token);
            // The authority lock was acquired before the savepoint and must remain owned.
            var locks = await db.Database.SqlQueryRaw<int>(
                "SELECT count(*)::integer AS \"Value\" FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory' AND classid = 976 AND objid = 1 AND granted")
                .SingleAsync(recovery.Token);
            Assert.Equal(1, locks);
            Assert.False(seat.IsActive); // SQL rollback deliberately leaves this tracked object stale.
            db.ChangeTracker.Clear();
            db.LicenseHistories.Add(new SoftLicence.Server.Data.LicenseHistory
            {
                LicenseId = fixture.LicenseId, Action = "TKT976_DECISION_ONLY"
            });
            await db.SaveChangesAsync(recovery.Token);
            await transaction.CommitAsync(recovery.Token);
        }

        await using var observed = await factory.CreateDbContextAsync();
        Assert.True((await observed.LicenseSeats.SingleAsync(row => row.LicenseId == fixture.LicenseId)).IsActive);
        var history = await observed.LicenseHistories.Where(row => row.LicenseId == fixture.LicenseId).ToListAsync();
        Assert.Equal("TKT976_DECISION_ONLY", Assert.Single(history).Action);
    }

    /// <summary>Proves a full outer rollback loses a saved decision and cannot be presented as a durable savepoint recovery.</summary>
    /// <remarks>No fallback transaction is opened. A fresh context verifies the persisted absence after disposal of the rolled-back transaction.</remarks>
    [Fact]
    public async Task Tkt976_FullRollback_DoesNotPersistDecisionOrPermitSavepointRecovery()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        await using (var db = await factory.CreateDbContextAsync())
        {
            await using var transaction = await db.Database.BeginTransactionAsync();
            await transaction.CreateSavepointAsync("tkt976_business");
            db.LicenseHistories.Add(new SoftLicence.Server.Data.LicenseHistory
            {
                LicenseId = fixture.LicenseId, Action = "TKT976_NOT_DURABLE"
            });
            await db.SaveChangesAsync();
            await transaction.RollbackAsync();
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                transaction.RollbackToSavepointAsync("tkt976_business"));
        }
        await using var observed = await factory.CreateDbContextAsync();
        Assert.False(await observed.LicenseHistories.AnyAsync(row => row.LicenseId == fixture.LicenseId));
    }

    /// <summary>Proves a full-seat refusal survives business rollback, exact concurrent retries deduplicate, and a changed quota context remains a distinct decision.</summary>
    /// <remarks>Uses application-role transactions and server-owned entitlement. Full synthetic database fingerprints exclude only history, proving no business table or other synthetic client changes after refusal. Later context mutation is explicit test setup, never reconstructed into old history.</remarks>
    [Fact]
    public async Task Tkt976_Finalize_SeatLimitRefusal_PersistsDecisionAfterBusinessRollback()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var submitted = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        var request = await Tkt976_CreateRequestAsync(service, fixture, now, submitted);

        var beforeBusiness = await Tkt976_BusinessFingerprintAsync(connections.App);
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync("tkt976-synthetic-client", Sha256("tkt976-finalize"), request));
        Assert.Equal(422, refusal.StatusCode);
        Assert.Equal("seat_limit_reached", refusal.ErrorCode);
        Assert.Equal(beforeBusiness, await Tkt976_BusinessFingerprintAsync(connections.App));

        await using var observed = await factory.CreateDbContextAsync();
        var seats = await observed.LicenseSeats.AsNoTracking()
            .Where(seat => seat.LicenseId == fixture.LicenseId).ToListAsync();
        Assert.Equal(fixture.HardwareId, Assert.Single(seats).HardwareId);
        Assert.True(seats[0].IsActive);
        Assert.False(await observed.DistributionInstallationBindings.AnyAsync(binding => binding.LicenseId == fixture.LicenseId));
        Assert.False(await observed.DistributionBindingRequests.AnyAsync(receipt => receipt.RequestId == request.RequestId));
        var history = await observed.LicenseHistories.AsNoTracking()
            .Where(entry => entry.LicenseId == fixture.LicenseId).ToListAsync();
        Assert.Contains(history, entry => entry.Action == "ACTIVATION_DECISION_V1"
            && entry.Details != null && entry.Details.Contains("seat_limit_reached", StringComparison.Ordinal));
        var frozenRow = Assert.Single(history);
        var frozen = System.Text.Json.JsonSerializer.Deserialize<LicenseDecisionHistory>(frozenRow.Details!,
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!;
        Assert.Equal(submitted, frozen.SubmittedHardwareId);
        Assert.Equal(submitted, frozen.ResolvedHardwareId);
        Assert.Null(frozen.CorrelatedHardwareId);
        Assert.Equal(1, frozen.Snapshot.ActiveSeats);
        Assert.Equal(1, frozen.Snapshot.SeatLimit);
        Assert.Equal(fixture.Version, frozen.AppVersion);
        Assert.Equal(fixture.HardwareId, Assert.Single(frozen.Snapshot.ActiveSeatDetails!).HardwareId);
        Assert.False(frozen.Snapshot.ResolvedHardwareAlreadyActive);
        Assert.Equal("ordered_authority_locks", frozen.Snapshot.ObservationGuarantee);
        Assert.Equal("refused", frozen.Outcome);

        // Both calls recompute business eligibility; event deduplication is not a refusal cache.
        var retries = await Task.WhenAll(
            Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("tkt976-finalize"), request)),
            Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("tkt976-finalize"), request)));
        Assert.All(retries, retry => Assert.Equal("seat_limit_reached", retry.ErrorCode));
        Assert.Equal(1, await observed.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId));
        Assert.Equal(beforeBusiness, await Tkt976_BusinessFingerprintAsync(connections.App));

        await using (var setup = await factory.CreateDbContextAsync())
        {
            var license = await setup.Licenses.SingleAsync(row => row.Id == fixture.LicenseId);
            license.MaxSeats = 2;
            setup.LicenseSeats.Add(new SoftLicence.Server.Data.LicenseSeat
            {
                LicenseId = fixture.LicenseId, HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant()
            });
            await setup.SaveChangesAsync();
        }
        var changedRefusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync("tkt976-synthetic-client", Sha256("tkt976-finalize"), request));
        Assert.Equal("seat_limit_reached", changedRefusal.ErrorCode);
        Assert.Equal(2, await observed.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId));
        Assert.Equal(frozenRow.Details, (await observed.LicenseHistories.AsNoTracking()
            .SingleAsync(row => row.Id == frozenRow.Id)).Details);

        await using (var setup = await factory.CreateDbContextAsync())
        {
            var license = await setup.Licenses.SingleAsync(row => row.Id == fixture.LicenseId);
            license.MaxSeats = 3;
            await setup.SaveChangesAsync();
        }
        var accepted = await service.FinalizeAsync("tkt976-synthetic-client", Sha256("tkt976-finalize"), request);
        Assert.False(accepted.Idempotent);
        var replay = await service.FinalizeAsync("tkt976-synthetic-client", Sha256("tkt976-finalize"), request);
        Assert.True(replay.Idempotent);
        Assert.Equal(3, await observed.LicenseHistories.CountAsync(row =>
            row.LicenseId == fixture.LicenseId && row.DecisionOperationId == request.RequestId));
        Assert.Equal(3, await observed.LicenseSeats.CountAsync(row => row.LicenseId == fixture.LicenseId && row.IsActive));
    }

    /// <summary>Creates an authenticated v1 entitlement and an independent synthetic finalization request without changing client contracts.</summary>
    /// <remarks>The caller owns the fresh licence fixture and may arm fault injection only after this setup commits.</remarks>
    private static async Task<DistributionInstallationFinalizeRequest> Tkt976_CreateRequestAsync(
        DistributionInstallationBindingService service,
        (Guid ProductId, Guid LicenseId, string HardwareId, string Version, string GrantRef) fixture,
        DateTimeOffset now, string submitted)
    {
        var entitlement = await service.IssueEntitlementAsync(
            "tkt976-synthetic-client", Sha256("tkt976-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D")
            });
        return new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = Guid.NewGuid().ToString("D"),
            // Handoff identity is globally unique, including across synthetic product fixtures.
            HandoffDigestSha256 = Sha256("tkt976-handoff-" + fixture.ProductId.ToString("D")),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-5)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-4)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = submitted,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "Synthetic-Setup.exe",
                InstallerSha256 = Sha256("tkt976-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };
    }

    /// <summary>Fingerprints every public business table in the isolated synthetic harness, excluding only LicenseHistories.</summary>
    /// <param name="syntheticConnection">Application-role connection supplied by this test's fresh harness; never production configuration.</param>
    /// <returns>Ordered table/digest pairs without returning any row values, including cryptographic test fixture material.</returns>
    /// <remarks>Catalog names are identifier-quoted, not interpreted as SQL. PostgreSQL orders canonical JSON rows so physical tuple order cannot create false differences. No data is modified.</remarks>
    private static async Task<string[]> Tkt976_BusinessFingerprintAsync(string syntheticConnection)
    {
        await using var connection = new Npgsql.NpgsqlConnection(syntheticConnection);
        await connection.OpenAsync();
        var tables = new List<string>();
        await using (var catalog = new Npgsql.NpgsqlCommand(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> 'LicenseHistories' ORDER BY table_name", connection))
        await using (var rows = await catalog.ExecuteReaderAsync())
        {
            while (await rows.ReadAsync())
                tables.Add(rows.GetString(0));
        }
        var fingerprints = new List<string>();
        foreach (var table in tables)
        {
            var identifier = "\"" + table.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
            await using var command = new Npgsql.NpgsqlCommand(
                "SELECT md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text, '[]')) FROM public." + identifier + " t", connection);
            fingerprints.Add(table + ":" + (string)(await command.ExecuteScalarAsync())!);
        }
        return fingerprints.ToArray();
    }
}
