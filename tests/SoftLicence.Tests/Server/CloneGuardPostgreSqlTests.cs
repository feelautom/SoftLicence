using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.CloneGuard;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003615 on PostgreSQL, through the real HTTP pipeline: single-use control token of the managed licence check.
/// Covers the unchanged historical answer, arming, rotation, exact replay after a lost response, sequential and
/// concurrent copies, snapshot restore, missing token and re-arm after activation, VM Generation ID signal, malformed
/// input, independent seats, in-place hardware migration, alerts, and the absence of any ban or threat score.
/// Contract: <c>docs/schema/jeton-anti-clonage.md</c>. Every test owns a cloned database (hence the exclusive-sessions
/// trait) and a fresh host whose notifier is a mock, so alerts are counted without any network delivery.
/// </summary>
public sealed partial class CloneGuardPostgreSqlTests
{
    /// <summary>Product name seeded by the bench; the check matches it case-insensitively.</summary>
    private const string AppName = "CloneApp";

    /// <summary>
    /// Canonical hardware identifiers (exactly 16 upper-case hexadecimal characters, as the check requires) of three
    /// distinct machines. None derives from a system UUID, so the requests carry no UUID and the machine-identity rule
    /// does not apply, like the native heartbeat.
    /// </summary>
    private const string HardwareA = "A1B2C3D4E5F60718";

    /// <inheritdoc cref="HardwareA"/>
    private const string HardwareB = "B1B2C3D4E5F60718";

    /// <inheritdoc cref="HardwareA"/>
    private const string HardwareC = "C1B2C3D4E5F60718";

    /// <summary>Valid VM Generation ID (32 lower-case hexadecimal characters) of the original VM.</summary>
    private const string VmGenerationOne = "0123456789abcdef0123456789abcdef";

    /// <summary>Valid VM Generation ID of a copy or a restored snapshot, different from <see cref="VmGenerationOne"/>.</summary>
    private const string VmGenerationTwo = "fedcba9876543210fedcba9876543210";

    /// <summary>
    /// Compatibility: a check without <c>cloneGuard</c> (installed versions, native heartbeat) gets exactly the
    /// historical members, no <c>cloneGuard</c> member, and no guard row is created, even on a seat already armed.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task CheckWithoutCloneGuard_KeepsHistoricalAnswer_AndCreatesNothing()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);

        var first = await bench.CheckAsync(key, HardwareA, guard: null);
        Assert.Equal("VALID", first.Status);
        Assert.NotNull(first.LicenseFile);
        Assert.False(first.Root.TryGetProperty("cloneGuard", out _));
        Assert.Equal(0, await bench.CountAsync<SeatCloneGuard>());

        await bench.CheckAsync(key, HardwareA, Pair(null, out _));
        var afterArming = await bench.CheckAsync(key, HardwareA, guard: null);
        Assert.Equal("VALID", afterArming.Status);
        Assert.NotNull(afterArming.LicenseFile);
        Assert.False(afterArming.Root.TryGetProperty("cloneGuard", out _));
    }

    /// <summary>
    /// The first guarded check arms the seat (one ARMED journal row); later checks rotate the token and are accepted
    /// without adding any journal row (no noise every five minutes).
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task FirstGuardedCheck_Arms_ThenEachRotationIsAccepted_WithoutJournalNoise()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);

        var armed = await bench.CheckAsync(key, HardwareA, Pair(null, out var current));
        Assert.Equal(("VALID", CloneGuardOutcomes.Armed), (armed.Status, armed.Outcome));
        Assert.NotNull(armed.LicenseFile);
        for (var beat = 0; beat < 4; beat++)
        {
            var accepted = await bench.CheckAsync(key, HardwareA, Pair(current, out var next));
            Assert.Equal(("VALID", CloneGuardOutcomes.Accepted), (accepted.Status, accepted.Outcome));
            Assert.NotNull(accepted.LicenseFile);
            current = next;
        }

        var kinds = await bench.EventKindsAsync();
        Assert.Equal([SeatCloneGuardEventKinds.Armed], kinds);
        var guard = await bench.SingleGuardAsync();
        Assert.Equal(SHA256.HashData(Decode(current)), guard.CurrentTokenHash);
        Assert.Equal(0, guard.CollisionCount);
    }

    /// <summary>
    /// Network loss: the same pair sent again 1, 2 and 5 times is answered REPLAYED each time, with a licence file,
    /// no collision and no state change; the next real beat is then accepted.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public async Task LostResponse_SamePairResent_IsReplayed_WithoutCollision(int resends)
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current));
        var pair = Pair(current, out var next);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, pair)).Outcome);

        for (var attempt = 0; attempt < resends; attempt++)
        {
            var replay = await bench.CheckAsync(key, HardwareA, pair);
            Assert.Equal(("VALID", CloneGuardOutcomes.Replayed), (replay.Status, replay.Outcome));
            Assert.NotNull(replay.LicenseFile);
        }

        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(next, out _))).Outcome);
        Assert.Equal(0, (await bench.SingleGuardAsync()).CollisionCount);
    }

    /// <summary>
    /// A lost answer to the very first (arming) check: the same pair with a null token is replayed, not a collision.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task LostArmingResponse_SameNullTokenPairResent_IsReplayed()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        var pair = Pair(null, out _);

        Assert.Equal(CloneGuardOutcomes.Armed, (await bench.CheckAsync(key, HardwareA, pair)).Outcome);
        Assert.Equal(CloneGuardOutcomes.Replayed, (await bench.CheckAsync(key, HardwareA, pair)).Outcome);
        Assert.Equal(0, (await bench.SingleGuardAsync()).CollisionCount);
    }

    /// <summary>
    /// Two copies of one installation (same key, same hardware identifier, same token): the first beat consumes the
    /// token, the second copy is answered DUPLICATE_DETECTED (stale_token, HTTP 200, no licence file, clear message),
    /// the first copy keeps beating normally, nothing is banned, released or scored.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SecondCopy_WithConsumedToken_IsSuspended_AndFirstCopyContinues()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var shared));

        var original = await bench.CheckAsync(key, HardwareA, Pair(shared, out var originalNext));
        var copy = await bench.CheckAsync(key, HardwareA, Pair(shared, out _));

        Assert.Equal(CloneGuardOutcomes.Accepted, original.Outcome);
        Assert.Equal(HttpStatusCode.OK, copy.HttpStatus);
        Assert.Equal("DUPLICATE_DETECTED", copy.Status);
        Assert.Equal(CloneGuardOutcomes.DuplicateDetected, copy.Outcome);
        Assert.Equal(CloneGuardReasons.StaleToken, copy.Reason);
        Assert.Null(copy.LicenseFile);
        Assert.Contains("copiée ou restaurée", copy.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(originalNext, out _))).Outcome);

        var guard = await bench.SingleGuardAsync();
        Assert.Equal(1, guard.CollisionCount);
        Assert.NotNull(guard.LastCollisionAt);
        await bench.AssertNoSanctionAsync();
    }

    /// <summary>
    /// The suspended copy keeps being answered DUPLICATE_DETECTED at every beat until it is reactivated, and each
    /// beat is journaled as a collision.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SuspendedCopy_StaysSuspended_AtEveryBeat()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var shared));
        await bench.CheckAsync(key, HardwareA, Pair(shared, out _));
        var stalePair = Pair(shared, out _);

        for (var beat = 0; beat < 3; beat++)
            Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareA, stalePair)).Status);

        Assert.Equal(3, (await bench.SingleGuardAsync()).CollisionCount);
        Assert.Equal(3, (await bench.EventKindsAsync()).Count(kind => kind == SeatCloneGuardEventKinds.Collision));
    }

    /// <summary>
    /// A status other than VALID keeps priority and consumes nothing: a revoked licence answers REVOKED with
    /// NOT_EVALUATED, and the same token is accepted once the licence is valid again.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task NonValidStatus_IsNotEvaluated_AndTokenIsNotConsumed()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current));
        await bench.SetLicenseActiveAsync(false);

        var revoked = await bench.CheckAsync(key, HardwareA, Pair(current, out _));
        Assert.Equal(("REVOKED", CloneGuardOutcomes.NotEvaluated), (revoked.Status, revoked.Outcome));

        await bench.SetLicenseActiveAsync(true);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(current, out _))).Outcome);
    }

    /// <summary>
    /// Decision Q2: a guard-aware client without token on an armed seat is a copy (token_missing) unless the seat was
    /// explicitly re-activated after the last accepted check, in which case the guard is re-armed silently.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task MissingToken_IsCollision_UnlessSeatWasReactivatedSinceLastAcceptedCheck()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current));
        await bench.CheckAsync(key, HardwareA, Pair(current, out current));

        var missing = await bench.CheckAsync(key, HardwareA, Pair(null, out _));
        Assert.Equal(("DUPLICATE_DETECTED", CloneGuardReasons.TokenMissing), (missing.Status, missing.Reason));

        // Sign-out then sign-in: the seat is released and becomes active again, which stamps LastActivatedAt.
        await bench.ReleaseAndReactivateSeatAsync(HardwareA);
        var rearmed = await bench.CheckAsync(key, HardwareA, Pair(null, out var fresh));
        Assert.Equal(("VALID", CloneGuardOutcomes.Armed), (rearmed.Status, rearmed.Outcome));
        Assert.Contains(SeatCloneGuardEventKinds.RearmedAfterActivation, await bench.EventKindsAsync());

        // The former live token is now stale: that copy is suspended at its next beat.
        Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareA, Pair(current, out _))).Status);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(fresh, out _))).Outcome);
    }

    /// <summary>
    /// A VM Generation ID change on an accepted check is a signal only: ACCEPTED, environmentChanged true, one
    /// VM_GENERATION_CHANGED row with both values; the upper-case form is stored lower-case.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task VmGenerationChange_IsSignaled_NeverRefused()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current, VmGenerationOne.ToUpperInvariant()));
        Assert.Equal(VmGenerationOne, (await bench.SingleGuardAsync()).LastVmGenerationId);

        var same = await bench.CheckAsync(key, HardwareA, Pair(current, out current, VmGenerationOne));
        Assert.False(same.EnvironmentChanged);
        var changed = await bench.CheckAsync(key, HardwareA, Pair(current, out _, VmGenerationTwo));

        Assert.Equal(("VALID", CloneGuardOutcomes.Accepted, true), (changed.Status, changed.Outcome, changed.EnvironmentChanged));
        var row = Assert.Single(await bench.EventsAsync(SeatCloneGuardEventKinds.VmGenerationChanged));
        Assert.Equal((VmGenerationTwo, VmGenerationOne), (row.VmGenerationId, row.KnownVmGenerationId));
        Assert.Equal(VmGenerationTwo, (await bench.SingleGuardAsync()).LastVmGenerationId);
    }

    /// <summary>
    /// Strict wire format: every malformed pair is answered MALFORMED with status VALID and consumes nothing; an
    /// invalid VM Generation ID alone is ignored. Cases: short, long, padded, standard base64 alphabet, non-canonical
    /// trailing bits, whitespace, next equal to current, missing next, unknown protocol.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData("short")]
    [InlineData("long")]
    [InlineData("padded")]
    [InlineData("plus")]
    [InlineData("trailingBits")]
    [InlineData("whitespace")]
    [InlineData("sameAsCurrent")]
    [InlineData("missingNext")]
    [InlineData("protocol2")]
    public async Task MalformedPair_ConsumesNothing(string variant)
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current));
        var good = Token();
        object guard = variant switch
        {
            "short" => Wire(current, good[..42]),
            "long" => Wire(current, good + "A"),
            "padded" => Wire(current, good + "="),
            "plus" => Wire(current, "+" + good[1..]),
            "trailingBits" => Wire(current, NonCanonical(good)),
            "whitespace" => Wire(current, " " + good[1..]),
            "sameAsCurrent" => Wire(current, current),
            "missingNext" => Wire(current, null),
            "protocol2" => new { ProtocolVersion = 2, Token = current, NextToken = good },
            _ => throw new ArgumentOutOfRangeException(nameof(variant))
        };

        var answer = await bench.CheckAsync(key, HardwareA, guard);

        Assert.Equal("VALID", answer.Status);
        Assert.Equal(variant == "protocol2" ? CloneGuardOutcomes.UnsupportedProtocol : CloneGuardOutcomes.Malformed, answer.Outcome);
        Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, HardwareA, Pair(current, out _))).Outcome);
        Assert.Equal(0, (await bench.SingleGuardAsync()).CollisionCount);
    }

    /// <summary>An invalid VM Generation ID never refuses: the pair is accepted and the known value is kept.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task InvalidVmGenerationId_IsIgnored()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current, VmGenerationOne));

        var answer = await bench.CheckAsync(key, HardwareA, new { ProtocolVersion = 1, Token = current, NextToken = Token(), VmGenerationId = "not-a-generation-id" });

        Assert.Equal(CloneGuardOutcomes.Accepted, answer.Outcome);
        Assert.Equal(VmGenerationOne, (await bench.SingleGuardAsync()).LastVmGenerationId);
    }

    /// <summary>Three machines on three seats of one licence: three independent guards, no interference.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ThreeSeats_HaveIndependentGuards()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 3, HardwareA, HardwareB, HardwareC);
        var tokens = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var hardware in new[] { HardwareA, HardwareB, HardwareC })
        {
            Assert.Equal(CloneGuardOutcomes.Armed, (await bench.CheckAsync(key, hardware, Pair(null, out var token))).Outcome);
            tokens[hardware] = token;
        }
        for (var beat = 0; beat < 2; beat++)
            foreach (var hardware in new[] { HardwareC, HardwareA, HardwareB })
            {
                Assert.Equal(CloneGuardOutcomes.Accepted, (await bench.CheckAsync(key, hardware, Pair(tokens[hardware], out var next))).Outcome);
                tokens[hardware] = next;
            }

        Assert.Equal(3, await bench.CountAsync<SeatCloneGuard>());
        Assert.DoesNotContain(SeatCloneGuardEventKinds.Collision, await bench.EventKindsAsync());
    }

    /// <summary>
    /// TKT-003614: a VM moved to new hardware keeps its seat (in-place identifier migration) and therefore its guard
    /// and token: the next check from the new identifier is accepted, with no collision.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task InPlaceHardwareMigration_KeepsTheGuard_WithoutCollision()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var current));

        await bench.MoveSeatAsync(HardwareA, HardwareB);
        var moved = await bench.CheckAsync(key, HardwareB, Pair(current, out _));

        Assert.Equal(("VALID", CloneGuardOutcomes.Accepted), (moved.Status, moved.Outcome));
        Assert.Equal(1, await bench.CountAsync<SeatCloneGuard>());
        Assert.Equal(0, (await bench.SingleGuardAsync()).CollisionCount);
    }

    /// <summary>
    /// Alerts: one collision alone does not alert; the second within 24 hours sends one Security.CloneSuspected; further
    /// collisions the same day send nothing more. No ban, no threat score.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task RepeatedCollisions_AlertOncePer24Hours_AndNeverSanction()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var shared));
        await bench.CheckAsync(key, HardwareA, Pair(shared, out _));

        await bench.CheckAsync(key, HardwareA, Pair(shared, out _));
        Assert.Equal(0, bench.CloneAlerts);
        await bench.CheckAsync(key, HardwareA, Pair(shared, out _));
        Assert.Equal(1, bench.CloneAlerts);
        for (var beat = 0; beat < 3; beat++)
            await bench.CheckAsync(key, HardwareA, Pair(shared, out _));

        Assert.Equal(1, bench.CloneAlerts);
        Assert.NotNull((await bench.SingleGuardAsync()).LastAlertAt);
        await bench.AssertNoSanctionAsync();
    }

    /// <summary>
    /// A single collision from another network than the live copy (another /24) alerts at once, while a single
    /// collision from the same /24 does not; the transport address is journaled.
    /// </summary>
    /// <remarks>
    /// The addresses are used by no other test: <c>SecurityService</c> keeps banned IPs in a process-wide static cache,
    /// and documentation ranges (203.0.113.0/24, 198.51.100.0/24) are banned by other tests of the same run.
    /// </remarks>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task CollisionFromAnotherNetwork_AlertsAtOnce_SameNetworkDoesNot()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 2, HardwareA, HardwareB);
        await bench.CheckAsync(key, HardwareA, Pair(null, out var sharedA), from: "185.233.19.10");
        await bench.CheckAsync(key, HardwareA, Pair(sharedA, out _), from: "185.233.19.10");
        await bench.CheckAsync(key, HardwareB, Pair(null, out var sharedB), from: "185.233.19.10");
        await bench.CheckAsync(key, HardwareB, Pair(sharedB, out _), from: "185.233.19.10");

        Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareB, Pair(sharedB, out _), from: "185.233.19.77")).Status);
        Assert.Equal(0, bench.CloneAlerts);
        Assert.Equal("DUPLICATE_DETECTED", (await bench.CheckAsync(key, HardwareA, Pair(sharedA, out _), from: "185.244.31.20")).Status);
        Assert.Equal(1, bench.CloneAlerts);
        Assert.Contains(await bench.EventsAsync(SeatCloneGuardEventKinds.Collision), row => row.IpAddress == "185.244.31.20");
    }

    /// <summary>Builds a valid wire pair: draws a next token, returns it through <paramref name="next"/>.</summary>
    private static object Pair(string? token, out string next, string? vmGenerationId = null)
    {
        next = Token();
        return new { ProtocolVersion = 1, Token = token, NextToken = next, VmGenerationId = vmGenerationId };
    }

    /// <summary>Builds a raw wire pair without validation, for malformed-input cases.</summary>
    private static object Wire(string? token, string? next) => new { ProtocolVersion = 1, Token = token, NextToken = next };

    /// <summary>Draws a canonical token (32 random bytes, unpadded base64url).</summary>
    private static string Token() => CloneGuardCodec.Encode(RandomNumberGenerator.GetBytes(32));

    /// <summary>Decodes a canonical token to its 32 bytes.</summary>
    private static byte[] Decode(string token) => Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + "=");

    /// <summary>
    /// Returns an alias of a canonical token whose last character keeps the same 32 decoded bytes but sets one of the
    /// two ignored trailing bits, which a lenient decoder would accept as the same token.
    /// </summary>
    private static string NonCanonical(string token)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var index = alphabet.IndexOf(token[^1], StringComparison.Ordinal);
        return token[..^1] + alphabet[index ^ 1];
    }
}
