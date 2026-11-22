using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003189 on PostgreSQL: an IP that served a successful licence check of an active licence in the
/// last 30 days is neither banned nor alerted as a quarantine, while unknown IPs, revoked or expired
/// licences, stale or failed checks, non-canonical identifiers and admin brute force keep the normal
/// protection. The relational provider matters here: the decision is two SQL queries over
/// <c>AccessLogs</c>, <c>Licenses</c> and <c>LicenseSeats</c> with exact and upper-cased comparisons.
/// </summary>
/// <remarks>
/// Shares the isolated database of <see cref="ThreatScorePostgreSqlFixture"/>; each test uses its own
/// IP, its own synthetic product and its own hardware identifier, because the decision accepts a
/// hardware identifier bound to any active licence: a shared identifier would let one test's active
/// licence answer for another test's revoked one. The static verdict cache is cleared before
/// each decision so a previous test cannot answer for the current one.
/// </remarks>
[Collection(ThreatScorePostgreSqlCollection.Name)]
public sealed class ActiveClientThreatScorePostgreSqlTests(ThreatScorePostgreSqlFixture fixture)
{
    /// <summary>
    /// The 08/11 case: the licence moved to a new PC, the old PC's seat is unlinked but the licence is
    /// active, and the old PC checked successfully from this IP. Refusals reaching 250 points ban nothing,
    /// the score stays visible, and one alert is sent at 100 and one at 200, both saying "client actif".
    /// </summary>
    [Fact]
    public async Task UnlinkedSeatOfActiveLicence_IsNeverBanned_AndAlertsAt100And200()
    {
        const string ip = "198.51.100.120";
        await SeedLicenceAsync(ip, seatActive: false);
        var (service, notifier) = CreateService();

        for (var index = 0; index < 5; index++)
            await service.ReportThreatAsync(ip, 50, "Auth failure on /api/bugtrace/tickets (Multiplier: x1)",
                new ThreatScoreContext(ThreatScoreCategory.AuthFailure, "POST", "/api/bugtrace/tickets"));

        await using var db = fixture.Factory.CreateDbContext();
        Assert.False(await db.BannedIps.AnyAsync(ban => ban.IpAddress == ip));
        Assert.Equal(250, (await db.IpThreatScores.SingleAsync(row => row.IpAddress == ip)).Score);
        var titles = notifier.Invocations
            .Where(call => call.Method.Name == nameof(NotificationService.Notify)
                && (string)call.Arguments[0] == NotificationService.Triggers.SecurityThreatScoreRaised)
            .Select(call => (string)call.Arguments[1])
            .ToList();
        Assert.Equal(3, titles.Count);
        Assert.DoesNotContain(titles, title => title.Contains("quarantaine", StringComparison.Ordinal)
            && !title.Contains("ni quarantaine", StringComparison.Ordinal));
        Assert.Equal(2, titles.Count(title => title.Contains("client actif", StringComparison.Ordinal)));
        Assert.DoesNotContain(notifier.Invocations, call => call.Method.Name == nameof(NotificationService.Notify)
            && (string)call.Arguments[0] == NotificationService.Triggers.SecurityIpAutoBanned);
    }

    /// <summary>Each disqualifying fact removes the protection, and the IP is banned at 200 as before.</summary>
    /// <param name="ip">Distinct IP of the scenario.</param>
    /// <param name="scenario">Fact that must disqualify the IP.</param>
    [Theory]
    [InlineData("198.51.100.121", "unknown-ip")]
    [InlineData("198.51.100.122", "revoked")]
    [InlineData("198.51.100.123", "expired")]
    [InlineData("198.51.100.124", "inactive")]
    [InlineData("198.51.100.125", "stale-check")]
    [InlineData("198.51.100.126", "failed-check")]
    [InlineData("198.51.100.127", "lower-case-log")]
    [InlineData("198.51.100.128", "other-hardware")]
    public async Task DisqualifiedIp_KeepsNormalBan(string ip, string scenario)
    {
        if (scenario != "unknown-ip")
        {
            await SeedLicenceAsync(
                ip,
                seatActive: true,
                revoked: scenario == "revoked",
                expired: scenario == "expired",
                inactive: scenario == "inactive",
                checkAge: scenario == "stale-check" ? TimeSpan.FromDays(31) : TimeSpan.FromHours(1),
                resultStatus: scenario == "failed-check" ? "HARDWARE_NOT_ACTIVATED" : "OK",
                loggedHardwareIdTransform: scenario switch
                {
                    "lower-case-log" => hardwareId => hardwareId.ToLowerInvariant(),
                    "other-hardware" => _ => NewHardwareId(),
                    _ => null
                });
        }
        var (service, _) = CreateService();

        SecurityService.ClearActiveClientVerdicts();
        Assert.False(await service.IsActiveClientIpAsync(ip));
        await service.ReportThreatAsync(ip, 150, "first", new ThreatScoreContext(ThreatScoreCategory.AuthFailure));
        await service.ReportThreatAsync(ip, 60, "second", new ThreatScoreContext(ThreatScoreCategory.AuthFailure));

        await using var db = fixture.Factory.CreateDbContext();
        Assert.True((await db.BannedIps.SingleAsync(ban => ban.IpAddress == ip)).IsActive);
    }

    /// <summary>
    /// The proof is server-side: the IPv4-mapped audit form counts for the plain IP, a seat stored with
    /// another casing still matches the canonical audit identifier, and both a current seat and the
    /// licence's primary identifier are accepted.
    /// </summary>
    /// <param name="ip">Plain IP asked about.</param>
    /// <param name="loggedIp">IP form written in the audit row.</param>
    /// <param name="proof">"seat", "lower-case-seat" (seat stored in lower case) or "primary" (no seat).</param>
    [Theory]
    [InlineData("198.51.100.130", "::ffff:198.51.100.130", "seat")]
    [InlineData("198.51.100.131", "198.51.100.131", "lower-case-seat")]
    [InlineData("198.51.100.132", "198.51.100.132", "primary")]
    public async Task ServerRecordsProveActiveClient(string ip, string loggedIp, string proof)
    {
        await SeedLicenceAsync(loggedIp, seatActive: true,
            seatHardwareIdTransform: proof == "lower-case-seat" ? hardwareId => hardwareId.ToLowerInvariant() : null,
            primaryIsHardwareId: proof == "primary", withSeat: proof != "primary");
        var (service, _) = CreateService();

        SecurityService.ClearActiveClientVerdicts();
        Assert.True(await service.IsActiveClientIpAsync(ip));
    }

    /// <summary>A failed admin login is never shielded, even from an IP that serves an active licence.</summary>
    [Fact]
    public async Task AdminLoginFailure_FromActiveClientIp_IsStillBanned()
    {
        const string ip = "198.51.100.133";
        await SeedLicenceAsync(ip, seatActive: true);
        var (service, _) = CreateService();
        var login = new ThreatScoreContext(ThreatScoreCategory.AdminLoginFailure, "POST", "/login");

        SecurityService.ClearActiveClientVerdicts();
        Assert.True(await service.IsActiveClientIpAsync(ip));
        for (var index = 0; index < 4; index++)
            await service.ReportThreatAsync(ip, 50, "Failed login attempt (user: admin)", login);

        await using var db = fixture.Factory.CreateDbContext();
        Assert.True((await db.BannedIps.SingleAsync(ban => ban.IpAddress == ip)).IsActive);
    }

    /// <summary>
    /// Builds a security service with a notifier mock the test can inspect, as one production request
    /// scope does, bound to the isolated PostgreSQL database.
    /// </summary>
    private (SecurityService Service, Mock<NotificationService> Notifier) CreateService()
    {
        var notifier = new Mock<NotificationService>(
            Mock.Of<IDbContextFactory<LicenseDbContext>>(),
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["AdminSettings:AllowedIps"] = string.Empty })
            .Build();
        return (new SecurityService(fixture.Factory, Mock.Of<ILogger<SecurityService>>(), notifier.Object, configuration), notifier);
    }

    /// <summary>Returns a fresh canonical hardware identifier: 16 upper-case hexadecimal characters.</summary>
    private static string NewHardwareId() => Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();

    /// <summary>
    /// Seeds one synthetic product, licence type and licence bound to a fresh hardware identifier, an
    /// optional seat, and one audited licence check from <paramref name="loggedIp"/>. Every flag defaults
    /// to the protected (active) case.
    /// </summary>
    /// <param name="loggedIp">IP text written in the audit row.</param>
    /// <param name="seatActive">Whether the seat is current (false = unlinked, as after a PC change).</param>
    /// <param name="revoked">Marks the licence revoked.</param>
    /// <param name="expired">Sets an expiration date in the past.</param>
    /// <param name="inactive">Clears the licence's active flag.</param>
    /// <param name="checkAge">Age of the audited check; 31 days is outside the lookback.</param>
    /// <param name="resultStatus">Audited result of the check.</param>
    /// <param name="loggedHardwareIdTransform">Optional rewrite of the identifier written in the audit row.</param>
    /// <param name="seatHardwareIdTransform">Optional rewrite of the identifier stored on the seat.</param>
    /// <param name="primaryIsHardwareId">Whether the identifier is also the licence's primary identifier.</param>
    /// <param name="withSeat">Whether a seat row is created.</param>
    /// <returns>The seeded canonical hardware identifier.</returns>
    private async Task<string> SeedLicenceAsync(
        string loggedIp,
        bool seatActive,
        bool revoked = false,
        bool expired = false,
        bool inactive = false,
        TimeSpan? checkAge = null,
        string resultStatus = "OK",
        Func<string, string>? loggedHardwareIdTransform = null,
        Func<string, string>? seatHardwareIdTransform = null,
        bool primaryIsHardwareId = false,
        bool withSeat = true)
    {
        var now = DateTime.UtcNow;
        var hardwareId = NewHardwareId();
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var product = new Product { Name = $"TKT3189 {suffix}", PrivateKeyXml = "synthetic", PublicKeyXml = "synthetic" };
        var type = new LicenseType { Product = product, Name = "Synthetic", Slug = $"TKT3189-{suffix}" };
        var license = new License
        {
            Product = product,
            Type = type,
            LicenseKey = $"TKT3189-{suffix}",
            CustomerEmail = "synthetic@example.invalid",
            HardwareId = primaryIsHardwareId ? hardwareId : null,
            IsActive = !inactive,
            RevokedAt = revoked ? now.AddDays(-1) : null,
            ExpirationDate = expired ? now.AddDays(-1) : now.AddDays(30)
        };
        await using var db = fixture.Factory.CreateDbContext();
        db.AddRange(product, type, license);
        if (withSeat)
        {
            db.LicenseSeats.Add(new LicenseSeat
            {
                License = license,
                HardwareId = seatHardwareIdTransform?.Invoke(hardwareId) ?? hardwareId,
                IsActive = seatActive,
                UnlinkedAt = seatActive ? null : now.AddDays(-1)
            });
        }
        db.AccessLogs.Add(new AccessLog
        {
            Timestamp = now - (checkAge ?? TimeSpan.FromHours(1)),
            ClientIp = loggedIp,
            Method = "POST",
            Path = "/api/activation/check",
            Endpoint = "CHECK",
            ResultStatus = resultStatus,
            HardwareId = loggedHardwareIdTransform?.Invoke(hardwareId) ?? hardwareId,
            LicenseKey = license.LicenseKey,
            AppName = "TKT3189",
            StatusCode = 200,
            IsSuccess = resultStatus == "OK"
        });
        await db.SaveChangesAsync();
        return hardwareId;
    }
}
