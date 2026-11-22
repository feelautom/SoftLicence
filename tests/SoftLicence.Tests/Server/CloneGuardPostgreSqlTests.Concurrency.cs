using System.Net.Http.Json;
using System.Text.Json;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services.CloneGuard;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003615: two copies beating at the same instant, the SDK end to end against the real server, and the
/// administrator read route.
/// </summary>
public sealed partial class CloneGuardPostgreSqlTests
{
    /// <summary>
    /// Two copies present the same current token at the same instant: a third session holds the guard row lock,
    /// PostgreSQL shows both checks waiting on it, then exactly one consumes the token and the other is answered
    /// DUPLICATE_DETECTED. Repeated five times on fresh pairs to exercise both orders.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task TwoCopiesBeatingTogether_ExactlyOneConsumesTheToken()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var shared));

        for (var round = 0; round < 5; round++)
        {
            Answer? first = null, second = null;
            var firstPair = Pair(shared, out var firstNext);
            var secondPair = Pair(shared, out var secondNext);
            await RunBlockedOnGuardRowAsync(bench,
                async () => first = await bench.CheckAsync(key, HardwareA, firstPair),
                async () => second = await bench.CheckAsync(key, HardwareA, secondPair));

            var outcomes = new[] { first!.Outcome, second!.Outcome }.Select(value => value ?? "<none>").OrderBy(value => value, StringComparer.Ordinal).ToArray();
            Assert.Equal([CloneGuardOutcomes.Accepted, CloneGuardOutcomes.DuplicateDetected], outcomes);
            shared = first.Outcome == CloneGuardOutcomes.Accepted ? firstNext : secondNext;
        }
        Assert.Equal(5, (await bench.SingleGuardAsync()).CollisionCount);
    }

    /// <summary>
    /// The SDK end to end: GenerateToken, the guarded CheckStatusAsync overload (ARMED, ACCEPTED, REPLAYED,
    /// DUPLICATE_DETECTED with no licence file) and ReactivateCloneGuardAsync, parsed into
    /// <see cref="LicenseStatusResult.CloneGuard"/>; the historical overload still has no clone guard member.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Sdk_GuardedCheckAndReactivation_EndToEnd()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        var sdk = new SoftLicenceClient(bench.Client.BaseAddress!.ToString(), httpClient: bench.Client);

        var historical = await sdk.CheckStatusAsync(key, AppName, null, null, HardwareA);
        Assert.Equal("VALID", historical.Status);
        Assert.Null(historical.CloneGuard);

        var first = CloneGuardPresentation.GenerateToken();
        var armed = await sdk.CheckStatusAsync(key, AppName, null, null, HardwareA, new CloneGuardPresentation(null, first, VmGenerationOne));
        Assert.Equal(CloneGuardOutcome.Armed, armed.CloneGuard!.Outcome);
        Assert.True(armed.CloneGuard.NextTokenBecomesCurrent);

        var second = CloneGuardPresentation.GenerateToken();
        var pair = new CloneGuardPresentation(first, second, VmGenerationOne);
        Assert.Equal(CloneGuardOutcome.Accepted, (await sdk.CheckStatusAsync(key, AppName, null, null, HardwareA, pair)).CloneGuard!.Outcome);
        Assert.Equal(CloneGuardOutcome.Replayed, (await sdk.CheckStatusAsync(key, AppName, null, null, HardwareA, pair)).CloneGuard!.Outcome);

        var copy = await sdk.CheckStatusAsync(key, AppName, null, null, HardwareA,
            new CloneGuardPresentation(first, CloneGuardPresentation.GenerateToken(), null));
        Assert.True(copy.IsSuccess);
        Assert.Equal("DUPLICATE_DETECTED", copy.Status);
        Assert.Null(copy.LicenseFile);
        Assert.Equal((CloneGuardOutcome.DuplicateDetected, "stale_token"), (copy.CloneGuard!.Outcome, copy.CloneGuard.Reason));
        Assert.False(copy.CloneGuard.NextTokenBecomesCurrent);

        var reactivated = await sdk.ReactivateCloneGuardAsync(key, AppName, null, null, HardwareA, CloneGuardPresentation.GenerateToken(), null);
        Assert.Equal(("VALID", CloneGuardOutcome.Reactivated), (reactivated.Status, reactivated.CloneGuard!.Outcome));
        Assert.NotNull(reactivated.LicenseFile);
    }

    /// <summary>
    /// The administrator route lists every seat with its guard state and newest events, never token digests, and
    /// refuses an unauthenticated caller.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task AdminRoute_ShowsGuardStateAndEvents_WithoutDigests()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 2, HardwareA, HardwareB);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var shared));
        await bench.CheckAsync(key, HardwareA, Pair(shared, out _));
        await bench.CheckAsync(key, HardwareA, Pair(shared, out _));

        using var anonymous = await bench.Client.GetAsync($"/api/admin/licenses/{key}/clone-guard");
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/licenses/{key}/clone-guard");
        request.Headers.Add("X-Admin-Secret", AdminSecret);
        using var response = await bench.Client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        Assert.DoesNotContain("TokenHash", text, StringComparison.OrdinalIgnoreCase);
        using var document = JsonDocument.Parse(text);
        var seats = document.RootElement.EnumerateArray().ToList();
        Assert.Equal(2, seats.Count);
        var armed = seats.Single(seat => seat.GetProperty("hardwareId").GetString() == HardwareA);
        Assert.True(armed.GetProperty("armed").GetBoolean());
        Assert.Equal(1, armed.GetProperty("collisionCount").GetInt32());
        Assert.True(armed.GetProperty("duplicateDetectedLast24h").GetBoolean());
        Assert.Equal(SeatCloneGuardEventKinds.Collision, armed.GetProperty("events")[0].GetProperty("kind").GetString());
        Assert.False(seats.Single(seat => seat.GetProperty("hardwareId").GetString() == HardwareB).GetProperty("armed").GetBoolean());
    }

    /// <summary>
    /// Holds the guard row lock from a third session in an open transaction, starts both operations, waits until
    /// PostgreSQL reports both waiting (directly on the holder or queued behind each other), then commits and awaits both.
    /// </summary>
    private static async Task RunBlockedOnGuardRowAsync(Bench bench, Func<Task> first, Func<Task> second)
    {
        await using var holder = new NpgsqlConnection(bench.ConnectionString);
        await holder.OpenAsync();
        await using var transaction = await holder.BeginTransactionAsync();
        await using (var lockRow = new NpgsqlCommand("SELECT 1 FROM \"SeatCloneGuards\" FOR UPDATE", holder, transaction))
            await lockRow.ExecuteNonQueryAsync();
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
                // PostgreSQL queues waiters on one row behind the first waiter (tuple lock): the second check is
                // blocked by the first one, not by the holder. Count every session of this database that waits on
                // anything, the holder and the observer excluded, so both queued checks are seen.
                await using var query = new NpgsqlCommand(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid NOT IN (@holder, pg_backend_pid()) AND cardinality(pg_blocking_pids(pid)) > 0", observer);
                query.Parameters.AddWithValue("holder", holder.ProcessID);
                waiting = (long)(await query.ExecuteScalarAsync() ?? 0L);
                if (waiting == 2) break;
                await Task.Delay(20);
            } while (DateTime.UtcNow < deadline);
        }
        finally
        {
            await transaction.CommitAsync();
        }
        await Task.WhenAll(firstTask, secondTask);
        Assert.Equal(2, waiting);
    }
}
