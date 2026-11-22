using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Review 2439 (NO-GO on PR #562): the guided reactivation must refuse exactly what <c>/api/activation/check</c>
/// refuses, before any guard, quota or signature work. Every scenario arms the seat first, applies one refusal
/// condition, then sends the same identity to both routes and requires the same HTTP status, logical status, message
/// and the absence of a licence file, with no change to the guard, the journal or today's quota.
/// </summary>
public sealed partial class CloneGuardPostgreSqlTests
{
    /// <summary>Hardware identifier of a never-activated machine, used by the "other machine" scenario.</summary>
    private const string HardwareUnknown = "E1B2C3D4E5F60718";

    /// <summary>
    /// Regression of the review finding, arrangement of
    /// <c>ActivationSecurityRegressionTests.CheckStatus_WithHistoricalFreemiumOnSameHardware_ReturnsFreemiumConsumed</c>
    /// plus an active seat of the new licence: an older licence of the same single-use type was already consumed on
    /// this machine. The check answers <c>FREEMIUM_HWID_ALREADY_CONSUMED</c> without a file; the reactivation must give
    /// the same answer, never a signed file, and change nothing.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Reactivation_WithHistoricalFreemiumOnSameHardware_IsRefusedLikeTheCheck_AndSignsNothing()
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await ConsumeSingleUseTypeElsewhereAsync(bench, HardwareA);

        var check = await RawPostAsync(bench, "/api/activation/check", new { LicenseKey = key, HardwareId = HardwareA, AppName });
        var reactivation = await RawPostAsync(bench, "/api/activation/clone-guard/reactivate",
            new { LicenseKey = key, HardwareId = HardwareA, AppName, NextToken = Token() });

        Assert.Equal("FREEMIUM_HWID_ALREADY_CONSUMED", check.Status);
        Assert.Equal(check, reactivation with { Path = check.Path });
        Assert.Equal(0, await bench.CountAsync<SeatCloneGuard>());
        Assert.Equal(0, await bench.CountAsync<SeatCloneGuardEvent>());
        Assert.Equal(0, await UsedTodayAsync(bench));
    }

    /// <summary>
    /// Every refusal of the check is the refusal of the reactivation, with zero mutation of the guard, the journal and
    /// the quota. Scenarios: licence revoked, licence expired, security hardware ban, outdated-version ban, version
    /// below the product minimum, seat released, never-activated machine, unknown key, unknown product, non-canonical
    /// identifier, refused device UUID, single-use type already consumed on this machine.
    /// </summary>
    [Theory]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("hardwareBan")]
    [InlineData("outdatedVersionBan")]
    [InlineData("minimumVersion")]
    [InlineData("seatReleased")]
    [InlineData("otherMachine")]
    [InlineData("unknownKey")]
    [InlineData("unknownProduct")]
    [InlineData("nonCanonicalIdentifier")]
    [InlineData("deviceRefused")]
    [InlineData("singleUseConsumed")]
    public async Task EveryCheckRefusal_IsTheReactivationRefusal_WithoutAnyMutation(string scenario)
    {
        await using var bench = await Bench.CreateAsync();
        var key = await bench.SeedAsync(perSeat: 3, seats: 1, HardwareA);
        await bench.CheckAsync(key, HardwareA, Pair(null, out _));
        var guardBefore = (await bench.SingleGuardAsync()).CurrentTokenHash;
        var eventsBefore = await bench.CountAsync<SeatCloneGuardEvent>();
        var identity = await ApplyRefusalAsync(bench, key, scenario);

        var check = await RawPostAsync(bench, "/api/activation/check", identity.Check);
        var reactivation = await RawPostAsync(bench, "/api/activation/clone-guard/reactivate", identity.Reactivation);

        Assert.False(check.HttpStatus == HttpStatusCode.OK && check.Status == "VALID", $"scenario {scenario} must be refused by the check");
        Assert.Equal(check, reactivation with { Path = check.Path });
        Assert.Null(reactivation.LicenseFile);
        Assert.Equal(guardBefore, (await bench.SingleGuardAsync()).CurrentTokenHash);
        Assert.Equal(eventsBefore, await bench.CountAsync<SeatCloneGuardEvent>());
        Assert.Equal(0, await UsedTodayAsync(bench));
    }

    /// <summary>Request bodies of one scenario for both routes, with the same identity.</summary>
    /// <param name="Check">Body of the check.</param>
    /// <param name="Reactivation">Body of the reactivation (same fields plus a next token).</param>
    private sealed record ScenarioIdentity(object Check, object Reactivation);

    /// <summary>
    /// Applies one refusal condition to the seeded licence or chooses the refused identity, and returns the two
    /// request bodies. Database changes go through a fresh context, as an administrator change would.
    /// </summary>
    private static async Task<ScenarioIdentity> ApplyRefusalAsync(Bench bench, string key, string scenario)
    {
        string licenseKey = key, hardwareId = HardwareA, appName = AppName;
        string? appVersion = null, systemUuid = null;
        await using (var db = bench.Db())
        {
            var license = await db.Licenses.Include(row => row.Product).SingleAsync(row => row.LicenseKey == key);
            switch (scenario)
            {
                case "revoked":
                    license.RevokedAt = DateTime.UtcNow.AddMinutes(-1);
                    break;
                case "expired":
                    license.ExpirationDate = DateTime.UtcNow.AddDays(-1);
                    break;
                case "hardwareBan":
                case "outdatedVersionBan":
                    db.BannedHardwareIds.Add(new BannedHardwareId
                    {
                        HardwareId = HardwareA, ProductId = license.ProductId, Reason = "test",
                        BanCategory = scenario == "hardwareBan" ? BannedHardwareId.Categories.Manual : BannedHardwareId.Categories.OutdatedVersion
                    });
                    break;
                case "minimumVersion":
                    license.Product!.MinimumAllowedVersion = "9.0.0";
                    appVersion = "1.0.0";
                    break;
                case "seatReleased":
                    var seat = await db.LicenseSeats.SingleAsync(row => row.HardwareId == HardwareA);
                    seat.IsActive = false;
                    seat.UnlinkedAt = DateTime.UtcNow;
                    break;
                case "otherMachine":
                    hardwareId = HardwareUnknown;
                    break;
                case "unknownKey":
                    licenseKey = "NOSUCHKEY0000000000000000000000";
                    break;
                case "unknownProduct":
                    appName = "NoSuchProduct";
                    break;
                case "nonCanonicalIdentifier":
                    hardwareId = HardwareA.ToLowerInvariant();
                    break;
                case "deviceRefused":
                    systemUuid = "not-a-system-uuid";
                    break;
                case "singleUseConsumed":
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }
            await db.SaveChangesAsync();
        }
        if (scenario == "singleUseConsumed")
            await ConsumeSingleUseTypeElsewhereAsync(bench, HardwareA);
        return new ScenarioIdentity(
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName = appName, AppVersion = appVersion, SystemUuid = systemUuid },
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName = appName, AppVersion = appVersion, SystemUuid = systemUuid, NextToken = Token() });
    }

    /// <summary>
    /// Makes the seeded licence's type single-use per hardware identifier and adds an older revoked licence of the same
    /// type that was used on <paramref name="hardwareId"/> (released seat), like the Freemium history of the review.
    /// </summary>
    private static async Task ConsumeSingleUseTypeElsewhereAsync(Bench bench, string hardwareId)
    {
        await using var db = bench.Db();
        var current = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.LicenseKey == bench.SeededLicenseKey);
        current.Type!.EnforceSingleUsePerHardwareId = true;
        var old = new License
        {
            Id = Guid.NewGuid(), ProductId = current.ProductId, LicenseTypeId = current.LicenseTypeId,
            LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant(), CustomerName = "Old", CustomerEmail = "old@example.com",
            IsActive = false, RevokedAt = DateTime.UtcNow.AddDays(-1), RevocationReason = "test", MaxSeats = 1, AllowedVersions = "*",
            ActivationDate = DateTime.UtcNow.AddDays(-30), CreationDate = DateTime.UtcNow.AddDays(-30)
        };
        db.Licenses.Add(old);
        var longAgo = DateTime.UtcNow.AddDays(-30);
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = old.Id, HardwareId = hardwareId, IsActive = false, FirstActivatedAt = longAgo,
            LastActivatedAt = longAgo, LastCheckInAt = longAgo, UnlinkedAt = DateTime.UtcNow.AddDays(-1)
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Raw answer compared between the two routes; the JSON members are read only for a JSON body.</summary>
    /// <param name="Path">Route that produced the answer (excluded from the comparison by the callers).</param>
    /// <param name="HttpStatus">HTTP status code.</param>
    /// <param name="Status">Logical <c>status</c> member, or the raw body for a non-JSON answer.</param>
    /// <param name="ErrorMessage"><c>errorMessage</c> member, or <see langword="null"/>.</param>
    /// <param name="LicenseFile"><c>licenseFile</c> member, or <see langword="null"/> when absent or null.</param>
    private sealed record RawAnswer(string Path, HttpStatusCode HttpStatus, string? Status, string? ErrorMessage, string? LicenseFile);

    /// <summary>Posts JSON and reads the answer whether or not its body is JSON (404 and 400 answer plain text).</summary>
    private static async Task<RawAnswer> RawPostAsync(Bench bench, string path, object body)
    {
        using var response = await bench.Client.PostAsJsonAsync(path, body);
        var text = await response.Content.ReadAsStringAsync();
        try
        {
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return new RawAnswer(path, response.StatusCode, text, null, null);
            return new RawAnswer(path, response.StatusCode, Member(root, "status"), Member(root, "errorMessage"), Member(root, "licenseFile"));
        }
        catch (JsonException)
        {
            return new RawAnswer(path, response.StatusCode, text, null, null);
        }
    }

    /// <summary>Reads a string member in camelCase or PascalCase; <see langword="null"/> when absent or not a string.</summary>
    private static string? Member(JsonElement root, string camelName)
    {
        var pascal = char.ToUpperInvariant(camelName[0]) + camelName[1..];
        if ((root.TryGetProperty(camelName, out var value) || root.TryGetProperty(pascal, out value)) && value.ValueKind == JsonValueKind.String)
            return value.GetString();
        return null;
    }
}
