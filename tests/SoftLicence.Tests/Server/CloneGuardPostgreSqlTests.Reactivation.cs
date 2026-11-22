using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.CloneGuard;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003615 guided reactivation and its place in the licence's single daily quota (product decision, 16/11/2026):
/// a reactivation counts one unit of <c>MaxActivationsPerDay</c> x <c>MaxSeats</c>, both read from the database at
/// the time of the call (never a constant), in the same counter as machine changes; an exhausted quota refuses the
/// reactivation and every new machine that day, keeps the active copy usable and alerts once. Concurrency is proven
/// with PostgreSQL's own blocking graph on the advisory lock 1312 that every admission holds.
/// </summary>
public sealed partial class CloneGuardPostgreSqlTests
{
    /// <summary>
    /// Snapshot restore: the restored copy (old token) is suspended, reactivates, receives a licence file, and the copy
    /// that was running is suspended at its next beat: one active copy only. The reactivation is journaled and counts
    /// one unit of today's quota.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task RestoredCopy_Reactivates_AndTheOtherCopyIsSuspended()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        var (running, restored) = await TwoCopiesAsync(bench, key);

        var suspended = await bench.CheckAsync(key, HardwareA, Pair(restored, out _));
        Assert.Equal("DUPLICATE_DETECTED", suspended.Status);
        var reactivationToken = Token();
        var reactivated = await bench.ReactivateAsync(key, HardwareA, reactivationToken, VmGenerationTwo);

        Assert.Equal(("VALID", CloneGuardOutcomes.Reactivated), (reactivated.Status, reactivated.Outcome));
        Assert.NotNull(reactivated.LicenseFile);
        Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareA, Pair(running, out _))).Status);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(reactivationToken, out _))).Outcome);
        Assert.Equal(1, await UsedTodayAsync(bench));
        Assert.Single(await bench.EventsAsync(SeatCloneGuardEventKinds.Reactivated));
        await bench.AssertNoSanctionAsync();
    }

    /// <summary>A reactivation answer lost on the network: the same next token sent again is applied and counted once.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ReactivationRetry_WithSameNextToken_IsCountedOnce()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await TwoCopiesAsync(bench, key);
        var token = Token();

        Assert.Equal(CloneGuardOutcomes.Reactivated, (await bench.ReactivateAsync(key, HardwareA, token)).Outcome);
        Assert.Equal(CloneGuardOutcomes.Reactivated, (await bench.ReactivateAsync(key, HardwareA, token)).Outcome);

        Assert.Equal(1, await UsedTodayAsync(bench));
    }

    /// <summary>
    /// The limit is MaxActivationsPerDay x MaxSeats read from the database: with N - 1 units already used today (half
    /// by machine changes, half by earlier reactivations), one reactivation passes and the next one is refused with
    /// REACTIVATION_LIMIT_REACHED and its clear message; the active copy stays usable, a new machine is refused for the
    /// rest of the day, and one Security.CloneSuspected alert is sent for the limit.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(3, 5)]
    [InlineData(2, 7)]
    public async Task Reactivation_CountsInTheLicenceDailyQuota_PerSeatTimesSeats(int perSeat, int seats)
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat, seats, HardwareA);
        var limit = perSeat * seats;
        var machineChanges = (limit - 1) / 2;
        await bench.UseMachineChangesTodayAsync(machineChanges);
        await TwoCopiesAsync(bench, key);
        for (var index = 0; index < limit - 1 - machineChanges; index++)
            Assert.Equal(CloneGuardOutcomes.Reactivated, (await bench.ReactivateAsync(key, HardwareA, Token())).Outcome);
        Assert.Equal(limit - 1, await UsedTodayAsync(bench));

        var activeToken = Token();
        Assert.Equal(CloneGuardOutcomes.Reactivated, (await bench.ReactivateAsync(key, HardwareA, activeToken)).Outcome);
        // A suspended copy keeps beating: collisions never use a quota unit.
        await bench.CheckAsync(key, HardwareA, Pair(null, out _));
        var refusedToken = Token();
        var refused = await bench.ReactivateAsync(key, HardwareA, refusedToken);

        Assert.Equal(("VALID", CloneGuardOutcomes.ReactivationLimitReached, CloneGuardReasons.DailyQuotaExhausted),
            (refused.Status, refused.Outcome, refused.Reason));
        Assert.Null(refused.LicenseFile);
        Assert.Contains("nombre maximal de changements de poste", refused.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(limit, await UsedTodayAsync(bench));
        Assert.Single(await bench.EventsAsync(SeatCloneGuardEventKinds.ReactivationRefused));
        Assert.True(await NewMachineRefusedAsync(bench), "an exhausted quota must refuse every new machine that day");
        Assert.Equal(1, bench.LimitAlerts());
        // Refusing changed nothing: the copy holding the current token keeps working, the refused one stays suspended.
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(activeToken, out _))).Outcome);
        Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareA, Pair(refusedToken, out _))).Status);
    }

    /// <summary>
    /// An administrator change of the seat count during the day applies to the next reactivation: 3 x 1 = 3 units used
    /// refuses; raising to 2 seats (limit 6) accepts the next one; lowering back to 1 seat refuses again.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SeatCountChangedDuringTheDay_AppliesToTheNextReactivation()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.UseMachineChangesTodayAsync(3);
        await TwoCopiesAsync(bench, key);

        Assert.Equal(CloneGuardOutcomes.ReactivationLimitReached, (await bench.ReactivateAsync(key, HardwareA, Token())).Outcome);
        await bench.SetMaxSeatsAsync(2);
        Assert.Equal(CloneGuardOutcomes.Reactivated, (await bench.ReactivateAsync(key, HardwareA, Token())).Outcome);
        await bench.SetMaxSeatsAsync(1);
        Assert.Equal(CloneGuardOutcomes.ReactivationLimitReached, (await bench.ReactivateAsync(key, HardwareA, Token())).Outcome);
        Assert.Equal(4, await UsedTodayAsync(bench));
    }

    /// <summary>
    /// A per-seat value changed by the administrator during the day applies too (type re-read under the barrier), and
    /// a type without limit (0) never refuses.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task PerSeatValueChangedDuringTheDay_AppliesToTheNextReactivation()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 1, seats: 1, HardwareA);
        await bench.UseMachineChangesTodayAsync(1);
        await TwoCopiesAsync(bench, key);
        Assert.Equal(CloneGuardOutcomes.ReactivationLimitReached, (await bench.ReactivateAsync(key, HardwareA, Token())).Outcome);

        await using (var db = bench.Db())
        {
            var type = await db.LicenseTypes.SingleAsync();
            type.MaxActivationsPerDay = 0;
            await db.SaveChangesAsync();
        }
        for (var index = 0; index < 3; index++)
            Assert.Equal(CloneGuardOutcomes.Reactivated, (await bench.ReactivateAsync(key, HardwareA, Token())).Outcome);
    }

    /// <summary>
    /// Owner rule: a paid licence always works on at least one machine. With the daily quota exhausted, the
    /// reactivation is refused only while the copy holding the current token is alive (last accepted check younger than
    /// two five-minute beats). If that copy stopped beating (11 minutes, e.g. the original VM was deleted and only the
    /// restored copy is left), the reactivation passes anyway: journaled with its reason, counted beyond the limit,
    /// limit alert sent, and the silent copy is suspended if it ever comes back.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(9, false)]
    [InlineData(11, true)]
    public async Task ExhaustedQuota_RefusesOnlyWhileTheHolderIsAlive(int holderSilentMinutes, bool expectedReactivated)
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 2, seats: 1, HardwareA);
        await bench.UseMachineChangesTodayAsync(2);
        var (running, _) = await TwoCopiesAsync(bench, key);
        await bench.AgeHolderAsync(TimeSpan.FromMinutes(holderSilentMinutes));
        var token = Token();

        var answer = await bench.ReactivateAsync(key, HardwareA, token);

        Assert.Equal(1, bench.LimitAlerts());
        if (!expectedReactivated)
        {
            Assert.Equal(CloneGuardOutcomes.ReactivationLimitReached, answer.Outcome);
            Assert.Null(answer.LicenseFile);
            Assert.Equal(2, await UsedTodayAsync(bench));
            Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(running, out _))).Outcome);
            return;
        }
        Assert.Equal(("VALID", CloneGuardOutcomes.Reactivated), (answer.Status, answer.Outcome));
        Assert.NotNull(answer.LicenseFile);
        Assert.Equal(3, await UsedTodayAsync(bench));
        var row = Assert.Single(await bench.EventsAsync(SeatCloneGuardEventKinds.Reactivated));
        Assert.Equal(CloneGuardReasons.QuotaExhaustedHolderInactive, row.Reason);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(token, out _))).Outcome);
        Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareA, Pair(running, out _))).Status);
    }

    /// <summary>
    /// Reactivation keeps every existing refusal first and changes nothing then: revoked licence, unknown seat.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Reactivation_RefusedLicenceOrSeat_ChangesNothing()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await TwoCopiesAsync(bench, key);
        var before = (await bench.SingleGuardAsync()).CurrentTokenHash;

        // Since review 2439 the reactivation answers exactly like the check for a machine without seat.
        Assert.Equal("HARDWARE_MISMATCH", (await bench.ReactivateAsync(key, HardwareB, Token())).Status);
        await bench.SetLicenseActiveAsync(false);
        Assert.Equal("REVOKED", (await bench.ReactivateAsync(key, HardwareA, Token())).Status);

        Assert.Equal(before, (await bench.SingleGuardAsync()).CurrentTokenHash);
        Assert.Equal(0, await UsedTodayAsync(bench));
    }

    /// <summary>
    /// Atomic quota under concurrency: with exactly one unit left, two reactivations of the same seat start while a
    /// third session holds the commercial barrier (advisory lock 1312); PostgreSQL shows both waiting on it, then
    /// exactly one is applied and the other is refused, and the day counts exactly the limit.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ConcurrentReactivations_OnTheLastUnit_ExactlyOneIsApplied()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.UseMachineChangesTodayAsync(2);
        await TwoCopiesAsync(bench, key);
        Answer? first = null, second = null;

        await RunBlockedOnBarrierAsync(bench,
            async () => first = await bench.ReactivateAsync(key, HardwareA, Token()),
            async () => second = await bench.ReactivateAsync(key, HardwareA, Token()));

        var outcomes = new[] { first!.Outcome, second!.Outcome }.Select(value => value ?? "<none>").OrderBy(value => value, StringComparer.Ordinal).ToArray();
        Assert.Equal([CloneGuardOutcomes.Reactivated, CloneGuardOutcomes.ReactivationLimitReached], outcomes);
        Assert.Equal(3, await UsedTodayAsync(bench));
    }

    /// <summary>
    /// Same counter, mixed paths: with one unit left, a reactivation and a key activation on a new machine start
    /// together behind the barrier; exactly one of them uses the last unit, never both.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ConcurrentReactivationAndNewMachine_OnTheLastUnit_OnlyOneWins()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 2, seats: 2, HardwareA);
        await bench.UseMachineChangesTodayAsync(3);
        await TwoCopiesAsync(bench, key);
        Answer? reactivation = null;
        HttpResponseMessage? activation = null;

        await RunBlockedOnBarrierAsync(bench,
            async () => reactivation = await bench.ReactivateAsync(key, HardwareA, Token()),
            async () => activation = await bench.Client.PostAsJsonAsync("/api/activation",
                new { LicenseKey = key, HardwareId = HardwareB, AppName }));

        var reactivated = reactivation!.Outcome == CloneGuardOutcomes.Reactivated;
        var activated = activation!.IsSuccessStatusCode;
        Assert.True(reactivated ^ activated,
            $"exactly one must use the last unit (reactivation {reactivation.Outcome}, activation {(int)activation.StatusCode})");
        Assert.Equal(4, await UsedTodayAsync(bench));
    }

    /// <summary>
    /// Arms the seat from the original installation, lets it beat once, and returns the token now current on the
    /// running copy and the consumed token still held by a copy restored from before that beat.
    /// </summary>
    private static async Task<(string Running, string Restored)> TwoCopiesAsync(Bench bench, string key)
    {
        await bench.CheckAsync(key, HardwareA, Pair(null, out var restored));
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(restored, out var running))).Outcome);
        return (running, restored);
    }

    /// <summary>Reads today's units through the production quota code.</summary>
    private static async Task<int> UsedTodayAsync(Bench bench)
    {
        await using var db = bench.Db();
        var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.LicenseKey == bench.SeededLicenseKey);
        return (await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow)).UsedToday;
    }

    /// <summary>Asks the production quota whether a never-seen machine would be refused today.</summary>
    private static async Task<bool> NewMachineRefusedAsync(Bench bench)
    {
        await using var db = bench.Db();
        var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.LicenseKey == bench.SeededLicenseKey);
        return await SeatChangeQuota.IsActivationRefusedAsync(db, license, "E000000000000001", DateTime.UtcNow);
    }

    /// <summary>
    /// Holds the commercial barrier (advisory lock 1312, 1) from a third session, starts both operations, waits until
    /// PostgreSQL reports both blocked by that session, then releases it and awaits both. Fails if the two operations
    /// were not really waiting together.
    /// </summary>
    private static async Task RunBlockedOnBarrierAsync(Bench bench, Func<Task> first, Func<Task> second)
    {
        await using var barrier = new NpgsqlConnection(bench.ConnectionString);
        await barrier.OpenAsync();
        await using (var hold = new NpgsqlCommand("SELECT pg_advisory_lock(1312, 1)", barrier))
            await hold.ExecuteNonQueryAsync();
        var firstTask = Task.Run(first);
        var secondTask = Task.Run(second);
        long waiting = 0;
        try
        {
            await using var observer = new NpgsqlConnection(bench.ConnectionString);
            await observer.OpenAsync();
            var deadline = DateTime.UtcNow.AddSeconds(10);
            do
            {
                await using var query = new NpgsqlCommand(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND @blocker = ANY(pg_blocking_pids(pid))", observer);
                query.Parameters.AddWithValue("blocker", barrier.ProcessID);
                waiting = (long)(await query.ExecuteScalarAsync() ?? 0L);
                if (waiting == 2) break;
                await Task.Delay(20);
            } while (DateTime.UtcNow < deadline);
        }
        finally
        {
            await using var release = new NpgsqlCommand("SELECT pg_advisory_unlock(1312, 1)", barrier);
            await release.ExecuteNonQueryAsync();
        }
        await Task.WhenAll(firstTask, secondTask);
        Assert.Equal(2, waiting);
    }
}
