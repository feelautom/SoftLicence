using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Serializes the real PostgreSQL portal-deactivation contract tests on one isolated database.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PortalDeactivationPostgreSqlCollection : ICollectionFixture<PortalDeactivationPostgreSqlFixture>
{
    /// <summary>Gets the exact xUnit collection name used to serialize the isolated database fixture.</summary>
    public const string Name = "TKT-000798 portal deactivation PostgreSQL";
}

/// <summary>
/// Proves migration, exact replay, concurrency, guard policy, and terminal outcomes on PostgreSQL.
/// </summary>
[Collection(PortalDeactivationPostgreSqlCollection.Name)]
public sealed class PortalDeactivationPostgreSqlTests(PortalDeactivationPostgreSqlFixture fixture)
{
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 18, 0, 0, TimeSpan.Zero);

    /// <summary>Proves the additive migration is current and creates the provider idempotency table.</summary>
    [Fact]
    public async Task Migration_IsCurrentAndCreatesPortalOperationTable()
    {
        await using var db = fixture.Factory.CreateDbContext();

        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT to_regclass('\"PortalDeactivationOperations\"') IS NOT NULL";
        await db.Database.OpenConnectionAsync();
        Assert.True(Assert.IsType<bool>(await command.ExecuteScalarAsync()));
    }

    /// <summary>Proves concurrent exact calls mutate one seat and persist one terminal and one history row.</summary>
    [Fact]
    public async Task ConcurrentExactRequest_MutatesExactlyOnceAndReplaysStableResult()
    {
        var seed = await fixture.SeedAsync("concurrent", active: true, seatAge: TimeSpan.FromMinutes(10), Now);
        var request = seed.Request("subscription_termination");
        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ =>
            fixture.Service(Now).DeactivateAsync("tia-connect-website-portal", new string('a', 64), request)));

        Assert.Single(responses, response => !response.Idempotent);
        Assert.Equal(11, responses.Count(response => response.Idempotent));
        Assert.Single(responses.Select(response => response.Response).Distinct());
        Assert.All(responses, response => Assert.Equal(PortalDeactivationService.DeactivatedOutcome, response.Response.Outcome));
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.PortalDeactivationOperations.Where(row => row.RequestId == seed.RequestId).ToListAsync());
        Assert.Single(await verify.LicenseHistories.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
        Assert.False((await verify.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
    }

    /// <summary>Proves a reused request UUID with changed exact bytes fails with stable HTTP 409 semantics.</summary>
    [Fact]
    public async Task ChangedPayloadForCommittedRequest_ConflictsWithoutSecondMutation()
    {
        var seed = await fixture.SeedAsync("conflict", active: true, seatAge: TimeSpan.FromMinutes(10), Now);
        var service = fixture.Service(Now);
        await service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), seed.Request("uninstall"));

        var conflict = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.DeactivateAsync("tia-connect-website-portal", new string('b', 64), seed.Request("settings_button")));

        Assert.Equal("idempotency_conflict", conflict.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.PortalDeactivationOperations.Where(row => row.RequestId == seed.RequestId).ToListAsync());
        Assert.Single(await verify.LicenseHistories.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
    }

    /// <summary>Proves only settings and uninstall bypass the five-minute guard; subscription cleanup remains guarded.</summary>
    [Fact]
    public async Task RecentSeatReasonMatrix_OnlyInteractiveReasonsBypassGuard()
    {
        var now = await ReadDatabaseUtcNowAsync();
        var settings = await fixture.SeedAsync("settings", active: true, seatAge: TimeSpan.FromMinutes(1), now);
        var uninstall = await fixture.SeedAsync("uninstall", active: true, seatAge: TimeSpan.FromMinutes(1), now);
        var cleanup = await fixture.SeedAsync("cleanup", active: true, seatAge: TimeSpan.FromMinutes(1), now);
        var service = fixture.Service(now);

        Assert.Equal(PortalDeactivationService.DeactivatedOutcome,
            (await service.DeactivateAsync("tia-connect-website-portal", new string('c', 64), settings.Request("settings_button"))).Response.Outcome);
        Assert.Equal(PortalDeactivationService.DeactivatedOutcome,
            (await service.DeactivateAsync("tia-connect-website-portal", new string('d', 64), uninstall.Request("uninstall"))).Response.Outcome);
        var blocked = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.DeactivateAsync("tia-connect-website-portal", new string('e', 64), cleanup.Request("subscription_termination")));

        Assert.Equal("deactivation_guard_active", blocked.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, blocked.StatusCode);
        // Arrange this independent future-seat premise immediately before its request.
        var futureNow = await ReadDatabaseUtcNowAsync();
        var future = await fixture.SeedAsync("future", active: true, seatAge: TimeSpan.FromMinutes(-1), futureNow);
        var inconsistent = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.DeactivateAsync("tia-connect-website-portal", new string('0', 64), future.Request("settings_button")));
        Assert.Equal("authority_inconsistent", inconsistent.ErrorCode);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.True((await verify.LicenseSeats.SingleAsync(row => row.Id == cleanup.SeatId)).IsActive);
        Assert.True((await verify.LicenseSeats.SingleAsync(row => row.Id == future.SeatId)).IsActive);
        Assert.Empty(await verify.PortalDeactivationOperations.Where(row => row.RequestId == cleanup.RequestId).ToListAsync());
        Assert.Empty(await verify.PortalDeactivationOperations.Where(row => row.RequestId == future.RequestId).ToListAsync());
    }

    /// <summary>Proves an exact inactive seat returns a durable 200-compatible terminal without duplicate history.</summary>
    [Fact]
    public async Task ExactInactiveSeat_ReturnsDurableAlreadyInactiveTerminal()
    {
        var seed = await fixture.SeedAsync("inactive", active: false, seatAge: TimeSpan.FromHours(1), Now);

        var result = await fixture.Service(Now).DeactivateAsync(
            "tia-connect-website-portal", new string('f', 64), seed.Request("uninstall"));

        Assert.Equal(PortalDeactivationService.AlreadyInactiveOutcome, result.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.PortalDeactivationOperations.Where(row => row.RequestId == seed.RequestId).ToListAsync());
        Assert.Empty(await verify.LicenseHistories.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
    }

    /// <summary>
    /// Preserves authenticated subscription cleanup across multiple seats with a daily limit of 1. Since TKT-003751 no
    /// deactivation reason is ever limited by the daily hardware quota.
    /// </summary>
    [Fact]
    public async Task SubscriptionTermination_WithDailyLimitOne_CleansAllSeats()
    {
        var now = await ReadDailyScenarioAnchorAsync(ReadDatabaseUtcNowAsync, delay => Task.Delay(delay));
        var seed = await fixture.SeedAsync("termination-quota", true, TimeSpan.FromHours(1), now);
        var hardwareIds = new[] { "ABCDEF0123456789", "TERMINATION-SEAT-2", "TERMINATION-SEAT-3" };
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
            license.IsActive = false; // The real termination caller revokes before cleaning seats.
            license.Type!.MaxActivationsPerDay = 1;
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = seed.LicenseId, HardwareId = "ALREADY-UNLINKED",
                IsActive = false, FirstActivatedAt = now.UtcDateTime.AddHours(-2), UnlinkedAt = now.UtcDateTime });
            foreach (var hardwareId in hardwareIds.Skip(1))
                db.LicenseSeats.Add(new LicenseSeat { LicenseId = seed.LicenseId, HardwareId = hardwareId,
                    IsActive = true, FirstActivatedAt = now.UtcDateTime.AddHours(-1), LastCheckInAt = now.UtcDateTime });
            await db.SaveChangesAsync();
        }
        var requests = hardwareIds.Select(hardwareId => seed.Request("subscription_termination") with {
            RequestId = Guid.NewGuid().ToString("D"), HardwareId = hardwareId }).ToArray();
        // Match the real caller's concurrent per-seat cleanup and stable child request identities.
        var results = await Task.WhenAll(requests.Select(request => fixture.Service(now).DeactivateAsync(
            "tia-connect-website-portal", new string('e', 64), request)));
        Assert.All(results, result => Assert.Equal("deactivated", result.Response.Outcome));
        foreach (var request in requests)
            Assert.True((await fixture.Service(now).DeactivateAsync("tia-connect-website-portal", new string('e', 64), request)).Idempotent);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.False((await verify.Licenses.SingleAsync(row => row.Id == seed.LicenseId)).IsActive);
        Assert.Equal(0, await verify.LicenseSeats.CountAsync(row => row.LicenseId == seed.LicenseId && row.IsActive));
        Assert.Equal(3, await verify.PortalDeactivationOperations.CountAsync(row => row.LicenseId == seed.LicenseId));
        Assert.Equal(3, await verify.LicenseHistories.CountAsync(row => row.LicenseId == seed.LicenseId));
    }

    /// <summary>Reads a PostgreSQL UTC anchor before the scenario's relative timestamps are seeded.</summary>
    /// <returns>The real relational clock, rather than the service's non-relational TimeProvider fallback.</returns>
    private async Task<DateTimeOffset> ReadDatabaseUtcNowAsync()
    {
        await using var db = fixture.Factory.CreateDbContext();
        await db.Database.OpenConnectionAsync();
        return await RuntimeEnrollmentService.DatabaseNowAsync(db, CancellationToken.None);
    }

    /// <summary>Waits out the last UTC minute before arranging a daily quota scenario, without retrying any business operation.</summary>
    /// <param name="readUtc">Reads the authoritative database clock.</param>
    /// <param name="delay">Waits before any scenario data or request exists; injectable for boundary proofs.</param>
    /// <returns>The final anchor, used unchanged by every timestamp in the quota scenario.</returns>
    private static async Task<DateTimeOffset> ReadDailyScenarioAnchorAsync(
        Func<Task<DateTimeOffset>> readUtc, Func<TimeSpan, Task> delay)
    {
        var observed = await readUtc();
        var midnight = new DateTimeOffset(observed.UtcDateTime.Date.AddDays(1), TimeSpan.Zero);
        var remaining = midnight - observed;
        if (remaining >= TimeSpan.FromMinutes(1))
            return observed;

        await delay(remaining);
        var anchor = await readUtc();
        Assert.True(anchor >= midnight, "Database UTC clock moved backwards during pre-seed midnight preparation.");
        return anchor;
    }

    /// <summary>Proves ordinary timestamps need no wait and late-day preparation advances before any seed exists.</summary>
    [Theory]
    [InlineData(12, 0, 0)]
    [InlineData(23, 59, 30)]
    public async Task DailyScenarioAnchor_PreparesBeforeSeedingAtUtcMidnight(int hour, int minute, int second)
    {
        var clock = new DateTimeOffset(2026, 10, 2, hour, minute, second, TimeSpan.Zero);
        var initial = clock;
        var delays = new List<TimeSpan>();
        var reads = 0;
        var anchor = await ReadDailyScenarioAnchorAsync(
            () => { reads++; return Task.FromResult(clock); },
            delay => { delays.Add(delay); clock += delay; return Task.CompletedTask; });
        if (hour == 23)
        {
            Assert.Equal(TimeSpan.FromSeconds(30), Assert.Single(delays));
            Assert.Equal(initial.UtcDateTime.Date.AddDays(1), anchor.UtcDateTime);
            Assert.Equal(2, reads);
        }
        else
        {
            Assert.Empty(delays);
            Assert.Equal(initial, anchor);
            Assert.Equal(1, reads);
        }
    }

    /// <summary>
    /// TKT-003751 (owner rule): two concurrent dashboard unlinks of two seats with a daily limit of 1 both
    /// succeed; unlinking is never counted nor refused by the daily hardware quota.
    /// </summary>
    [Fact]
    public async Task DistinctRequests_AtDailyLimitOne_BothDeactivate()
    {
        var seed = await fixture.SeedAsync("quota-race", true, TimeSpan.FromHours(1), Now);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
            license.Type!.MaxActivationsPerDay = 1;
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = seed.LicenseId, HardwareId = "OTHER-QUOTA-SEAT",
                IsActive = true, FirstActivatedAt = Now.UtcDateTime.AddHours(-1), LastCheckInAt = Now.UtcDateTime });
            await db.SaveChangesAsync();
        }
        var first = seed.Request("settings_button");
        var second = first with { RequestId = Guid.NewGuid().ToString("D"), HardwareId = "OTHER-QUOTA-SEAT" };
        var failures = await Task.WhenAll(new[] { first, second }.Select(request => Record.ExceptionAsync(() =>
            fixture.Service(Now).DeactivateAsync("tia-connect-website-portal", new string('a', 64), request))));
        Assert.All(failures, failure => Assert.Null(failure));
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Equal(0, await verify.LicenseSeats.CountAsync(row => row.LicenseId == seed.LicenseId && row.IsActive));
        Assert.Equal(2, await verify.PortalDeactivationOperations.CountAsync(row => row.LicenseId == seed.LicenseId));
        Assert.Equal(2, await verify.LicenseHistories.CountAsync(row => row.LicenseId == seed.LicenseId));
    }

    /// <summary>Proves a receipt cannot mutate a reactivated seat, but a new operation can.</summary>
    [Fact]
    public async Task ReactivatedSeat_ExactReplayPreservesNewCycle_NewRequestDeactivates()
    {
        var seed = await fixture.SeedAsync("quota-cycle", true, TimeSpan.FromHours(1), Now);
        var request = seed.Request("settings_button");
        var service = fixture.Service(Now);
        await service.DeactivateAsync("tia-connect-website-portal", new string('b', 64), request);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var seat = await db.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId);
            seat.IsActive = true;
            seat.UnlinkedAt = null;
            await db.SaveChangesAsync();
        }
        var replay = await service.DeactivateAsync("tia-connect-website-portal", new string('b', 64), request);
        Assert.True(replay.Idempotent);
        await using (var verify = fixture.Factory.CreateDbContext())
            Assert.True((await verify.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
        await service.DeactivateAsync("tia-connect-website-portal", new string('c', 64), request with { RequestId = Guid.NewGuid().ToString("D") });
        await using var final = fixture.Factory.CreateDbContext();
        Assert.False((await final.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
        Assert.Equal(2, await final.PortalDeactivationOperations.CountAsync(row => row.LicenseId == seed.LicenseId));
    }

    /// <summary>
    /// TKT-003751 (owner rule, supersedes TKT-001206): unlink, reactivate the same seat and unlink again, three
    /// times with a daily limit of 1, is never refused; the same PC counts once at most in the day.
    /// </summary>
    [Fact]
    public async Task ReactivatedSeat_RepeatedUnlinks_AtLimitOne_NeverRefused()
    {
        var seed = await fixture.SeedAsync("tkt1206-cycle", true, TimeSpan.FromHours(1), Now);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
            license.Type!.MaxActivationsPerDay = 1;
            await db.SaveChangesAsync();
        }
        var service = fixture.Service(Now);
        for (var cycle = 0; cycle < 3; cycle++)
        {
            var request = seed.Request("settings_button") with { RequestId = Guid.NewGuid().ToString("D") };
            var result = await service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), request);
            Assert.Equal(PortalDeactivationService.DeactivatedOutcome, result.Response.Outcome);
            await ReactivateSeedSeatAsync(seed);
        }

        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Equal(3, await verify.PortalDeactivationOperations.CountAsync(row => row.LicenseId == seed.LicenseId));
        var license2 = await verify.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
        Assert.True((await SeatChangeQuota.GetStatusAsync(verify, license2, DateTime.UtcNow)).UsedToday <= 1);
    }

    /// <summary>
    /// TKT-003751: the quota counts distinct hardware identifiers whose seat became active within the UTC day.
    /// Two seat rows of the same identifier count once; an activation the day before, a seat never activated since
    /// the column exists, another licence, and every release record (Desktop unlink history, portal operations,
    /// administrator rows) count nothing.
    /// </summary>
    [Fact]
    public async Task SeatChangeQuota_CountsDistinctIdentifiersActivatedInTheUtcDay()
    {
        var seed = await fixture.SeedAsync("tkt1206-classify", true, TimeSpan.FromHours(1), Now);
        var other = await fixture.SeedAsync("tkt3751-other-licence", true, TimeSpan.FromHours(1), Now);
        var today = Now.UtcDateTime;
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
            license.Type!.MaxActivationsPerDay = 2;
            db.LicenseSeats.AddRange(
                Seat(seed.LicenseId, "TKT3751-PC-A", today.AddHours(-3)),
                Seat(seed.LicenseId, "TKT3751-PC-A", today.AddHours(-2)),
                Seat(seed.LicenseId, "TKT3751-PC-B", today.AddMinutes(-30)),
                Seat(seed.LicenseId, "TKT3751-PC-C", today.Date.AddTicks(-1)),
                Seat(other.LicenseId, "TKT3751-PC-D", today.AddMinutes(-10)));
            db.LicenseHistories.AddRange(
                History(seed.LicenseId, today.AddMinutes(-10), "203.0.113.7"),
                History(seed.LicenseId, today.AddMinutes(-8), "Admin (API)"));
            db.PortalDeactivationOperations.Add(Operation(seed, today.AddMinutes(-5), "settings_button", "deactivated"));
            await db.SaveChangesAsync();
            // The seeded seat was activated at the real clock, outside this fixed day: never activated in it.
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"LicenseSeats\" SET \"LastActivatedAt\" = NULL WHERE \"Id\" = {seed.SeatId}");
        }

        await using var read = fixture.Factory.CreateDbContext();
        var target = await read.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
        var status = await SeatChangeQuota.GetStatusAsync(read, target, today);

        Assert.Equal(2, status.UsedToday);
        Assert.Equal(2, status.Limit);
        Assert.True(status.IsExhausted);
        Assert.Equal(0, status.Remaining);
        Assert.Equal(today.Date.AddDays(1), status.ResetAtUtc);
        Assert.False(await SeatChangeQuota.IsActivationRefusedAsync(read, target, "TKT3751-PC-A", today));
        Assert.False(await SeatChangeQuota.IsActivationRefusedAsync(read, target, "TKT3751-PC-B", today));
        Assert.True(await SeatChangeQuota.IsActivationRefusedAsync(read, target, "TKT3751-PC-C", today));
        Assert.True(await SeatChangeQuota.IsActivationRefusedAsync(read, target, "TKT3751-PC-NEW", today));
    }

    /// <summary>
    /// Proves the limit is read live from the licence type on every evaluation, so an administrator
    /// change applies immediately, and that zero means unlimited.
    /// </summary>
    [Fact]
    public async Task SeatChangeQuota_ReadsLiveLimit_AndZeroIsUnlimited()
    {
        var seed = await fixture.SeedAsync("tkt1206-live", true, TimeSpan.FromHours(1), Now);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            db.LicenseSeats.Add(Seat(seed.LicenseId, "TKT3751-PC-LIVE", Now.UtcDateTime.AddMinutes(-5)));
            await db.SaveChangesAsync();
        }

        foreach (var (limit, exhausted, remaining) in new[] { (3, false, (int?)2), (1, true, (int?)0), (0, false, (int?)null) })
        {
            await using (var db = fixture.Factory.CreateDbContext())
            {
                var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
                license.Type!.MaxActivationsPerDay = limit;
                await db.SaveChangesAsync();
            }
            await using var read = fixture.Factory.CreateDbContext();
            var target = await read.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
            var status = await SeatChangeQuota.GetStatusAsync(read, target, Now.UtcDateTime);
            Assert.Equal(limit, status.Limit);
            Assert.Equal(1, status.UsedToday);
            Assert.Equal(exhausted, status.IsExhausted);
            Assert.Equal(remaining, status.Remaining);
        }
    }

    /// <summary>Rejects a non-UTC clock so the counting window cannot shift silently.</summary>
    [Fact]
    public async Task SeatChangeQuota_RejectsNonUtcClock()
    {
        var seed = await fixture.SeedAsync("tkt1206-clock", true, TimeSpan.FromHours(1), Now);
        await using var read = fixture.Factory.CreateDbContext();
        var target = await read.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
        await Assert.ThrowsAsync<ArgumentException>(() => SeatChangeQuota.GetStatusAsync(
            read, target, DateTime.SpecifyKind(Now.UtcDateTime, DateTimeKind.Unspecified)));
    }

    /// <summary>Simulates a later authenticated reactivation of the seeded seat row.</summary>
    private async Task ReactivateSeedSeatAsync(SeededPortalAuthority seed)
    {
        await using var db = fixture.Factory.CreateDbContext();
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId);
        seat.IsActive = true;
        seat.UnlinkedAt = null;
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Builds one released seat row whose last activation is the given UTC instant (set explicitly, so the context
    /// keeps it instead of stamping the real clock).
    /// </summary>
    private static LicenseSeat Seat(Guid licenseId, string hardwareId, DateTime lastActivatedAtUtc) => new()
    {
        LicenseId = licenseId,
        HardwareId = hardwareId,
        IsActive = false,
        FirstActivatedAt = lastActivatedAtUtc,
        LastCheckInAt = lastActivatedAtUtc,
        LastActivatedAt = lastActivatedAtUtc,
        UnlinkedAt = lastActivatedAtUtc
    };

    /// <summary>Builds one unlink history row with an exact performer and UTC timestamp.</summary>
    private static LicenseHistory History(Guid licenseId, DateTime timestampUtc, string performedBy) => new()
    {
        LicenseId = licenseId,
        Timestamp = timestampUtc,
        Action = HistoryActions.UnlinkedApi,
        Details = "TKT-001206 test",
        PerformedBy = performedBy
    };

    /// <summary>Builds one persisted portal operation that satisfies the table check constraints.</summary>
    private static PortalDeactivationOperation Operation(
        SeededPortalAuthority seed, DateTime createdAtUtc, string reason, string outcome) => new()
    {
        RequestId = Guid.NewGuid(),
        ClientId = "tia-connect-website-portal",
        RequestFingerprintSha256 = new string('f', 64),
        ProductId = seed.ProductId,
        LicenseId = seed.LicenseId,
        HardwareId = "ABCDEF0123456789",
        Reason = reason,
        Outcome = outcome,
        CreatedAtUtc = createdAtUtc
    };

}

/// <summary>Owns one random PostgreSQL database and removes it after the ticket-specific test collection.</summary>
public sealed class PortalDeactivationPostgreSqlFixture : IAsyncLifetime
{
    private string _maintenanceConnectionString = string.Empty;
    private string _database = string.Empty;

    /// <summary>Gets the factory bound only to the isolated TKT-000798 database.</summary>
    public TestDbContextFactory Factory { get; private set; } = null!;

    /// <summary>Clones the random database from the shared full current-schema model.</summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("portal");
        _database = clone.DatabaseName;
        _maintenanceConnectionString = clone.MaintenanceConnectionString;
        Factory = new TestDbContextFactory(clone.ConnectionString);
    }

    /// <summary>Drops the isolated database even when a contract test fails.</summary>
    public async Task DisposeAsync()
    {
        await DropDatabaseAsync();
    }

    /// <summary>Creates a service with a deterministic clock and no sensitive logger output.</summary>
    public PortalDeactivationService Service(DateTimeOffset now) =>
        new(Factory, new FixedTimeProvider(now), NullLogger<PortalDeactivationService>.Instance);

    /// <summary>Seeds one product-qualified licence and exact seat using deterministic identifiers.</summary>
    public async Task<SeededPortalAuthority> SeedAsync(
        string discriminator,
        bool active,
        TimeSpan seatAge,
        DateTimeOffset now)
    {
        var productId = DeterministicGuid(discriminator + ":product");
        var typeId = DeterministicGuid(discriminator + ":type");
        var licenseId = DeterministicGuid(discriminator + ":license");
        var seatId = DeterministicGuid(discriminator + ":seat");
        var requestId = DeterministicGuid(discriminator + ":request");
        await using var db = Factory.CreateDbContext();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TKT-000798 " + discriminator,
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = "test-only"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Portal test",
            Slug = "portal-" + discriminator
        });
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = "TKT798-" + discriminator.ToUpperInvariant(),
            HardwareId = active ? "ABCDEF0123456789" : null,
            ActivationDate = active ? now.UtcDateTime - seatAge : null,
            Seats =
            [
                new LicenseSeat
                {
                    Id = seatId,
                    LicenseId = licenseId,
                    HardwareId = "ABCDEF0123456789",
                    FirstActivatedAt = now.UtcDateTime - seatAge,
                    LastCheckInAt = now.UtcDateTime - TimeSpan.FromSeconds(30),
                    IsActive = active,
                    UnlinkedAt = active ? null : now.UtcDateTime - TimeSpan.FromMinutes(1)
                }
            ]
        });
        await db.SaveChangesAsync();
        return new SeededPortalAuthority(productId, licenseId, seatId, requestId);
    }

    private async Task DropDatabaseAsync()
    {
        if (string.IsNullOrEmpty(_database) || string.IsNullOrEmpty(_maintenanceConnectionString))
            return;
        await PostgreSqlModelDatabase.DropAsync(_maintenanceConnectionString, _database);
        _database = string.Empty;
        _maintenanceConnectionString = string.Empty;
    }

    private static Guid DeterministicGuid(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        var hexadecimal = Convert.ToHexStringLower(bytes.AsSpan(0, 16)).ToCharArray();
        hexadecimal[12] = '4';
        hexadecimal[16] = '8';
        return Guid.ParseExact(
            $"{new string(hexadecimal, 0, 8)}-{new string(hexadecimal, 8, 4)}-{new string(hexadecimal, 12, 4)}-{new string(hexadecimal, 16, 4)}-{new string(hexadecimal, 20, 12)}",
            "D");
    }

    /// <summary>Creates contexts for independent concurrent provider transactions.</summary>
    public sealed class TestDbContextFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options;

        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(_options);

        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

/// <summary>Contains deterministic provider identifiers for one PostgreSQL scenario.</summary>
/// <param name="ProductId">Exact product UUID.</param>
/// <param name="LicenseId">Exact licence UUID.</param>
/// <param name="SeatId">Exact seat UUID.</param>
/// <param name="RequestId">Exact request UUID.</param>
public sealed record SeededPortalAuthority(Guid ProductId, Guid LicenseId, Guid SeatId, Guid RequestId)
{
    /// <summary>Builds the exact closed request for this scenario.</summary>
    public PortalDeactivationRequest Request(string reason) => new(
        PortalDeactivationService.RequestSchema,
        RequestId.ToString("D"),
        ProductId.ToString("D"),
        LicenseId.ToString("D"),
        "ABCDEF0123456789",
        reason);
}
