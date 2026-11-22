using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Migrations;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Serializes the TKT-002685 PostgreSQL threat-score tests on one isolated database.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ThreatScorePostgreSqlCollection : ICollectionFixture<ThreatScorePostgreSqlFixture>
{
    /// <summary>Exact xUnit collection name.</summary>
    public const string Name = "TKT-002685 threat score PostgreSQL";
}

/// <summary>
/// Proves on PostgreSQL the atomic score upsert (no lost point, no duplicate-key failure under concurrency),
/// the reset journal, and the webhook subscription SQL of the TKT-002685 and TKT-003668 migrations.
/// </summary>
[Collection(ThreatScorePostgreSqlCollection.Name)]
public sealed class ThreatScorePostgreSqlTests(ThreatScorePostgreSqlFixture fixture)
{
    /// <summary>The migration is applied and creates the reset journal.</summary>
    [Fact]
    public async Task Migration_IsCurrentAndCreatesResetJournal()
    {
        await using var db = fixture.Factory.CreateDbContext();

        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        Assert.Equal(0, await db.IpThreatScoreResets.CountAsync(row => row.IpAddress == "0.0.0.0"));
    }

    /// <summary>
    /// Forty concurrent events on a fresh IP, from distinct service instances as in production scopes,
    /// add up exactly, and the row is created once (the old read-then-insert lost points and logged
    /// duplicate-key failures).
    /// </summary>
    [Fact]
    public async Task ConcurrentIncrements_AreAtomic()
    {
        const string ip = "198.51.100.40";

        await Task.WhenAll(Enumerable.Range(0, 40).Select(index =>
            Task.Run(() => fixture.Service().ReportThreatAsync(ip, 2, $"concurrent {index}"))));

        await using var db = fixture.Factory.CreateDbContext();
        var row = await db.IpThreatScores.SingleAsync(score => score.IpAddress == ip);
        Assert.Equal(80, row.Score);
        Assert.Equal(80, fixture.Service().GetThreatScore(ip));
    }

    /// <summary>An existing row keeps its first-seen time and accumulates from the database value.</summary>
    [Fact]
    public async Task Increment_AddsToPersistedValue_AndKeepsFirstSeen()
    {
        const string ip = "198.51.100.41";
        // Inside the 30-day decay window, whole seconds so PostgreSQL stores it exactly.
        var recent = DateTime.UtcNow.AddDays(-29);
        var firstSeen = new DateTime(recent.Year, recent.Month, recent.Day, recent.Hour, recent.Minute, recent.Second, DateTimeKind.Utc);
        await using (var db = fixture.Factory.CreateDbContext())
        {
            db.IpThreatScores.Add(new IpThreatScore { IpAddress = ip, Score = 50, FirstSeen = firstSeen, LastHit = firstSeen });
            await db.SaveChangesAsync();
        }

        await fixture.Service().ReportThreatAsync(ip, 10, "test");

        await using var verify = fixture.Factory.CreateDbContext();
        var row = await verify.IpThreatScores.SingleAsync(score => score.IpAddress == ip);
        Assert.Equal(60, row.Score);
        Assert.Equal(firstSeen, row.FirstSeen);
        Assert.True(row.LastHit > firstSeen);
    }

    /// <summary>
    /// The decay on PostgreSQL: one statement erases only scores below 200 idle for 30 days or more,
    /// journals each with « inactif 30 j », and the targeted form touches only its IP.
    /// </summary>
    [Fact]
    public async Task DecaySweep_ErasesAndJournalsOnlyIdleScoresBelowBanThreshold()
    {
        var now = DateTime.UtcNow;
        var rows = new (string Ip, int Score, DateTime LastHit, bool Erased)[]
        {
            ("198.51.100.50", 50, now.AddDays(-30).AddMinutes(-1), true),
            ("::ffff:198.51.100.51", 199, now.AddDays(-45), true),
            ("198.51.100.52", 150, now.AddDays(-29), false),
            ("198.51.100.53", 250, now.AddDays(-90), false),
            ("198.51.100.54", 50, now.AddDays(-40), true)
        };
        await using (var db = fixture.Factory.CreateDbContext())
        {
            db.IpThreatScores.AddRange(rows.Select(row => new IpThreatScore
            {
                IpAddress = row.Ip, Score = row.Score, FirstSeen = row.LastHit, LastHit = row.LastHit
            }));
            await db.SaveChangesAsync();
        }

        Assert.Equal(1, await fixture.Service().PurgeInactiveThreatScoresAsync(now, "198.51.100.54"));
        Assert.Equal(0, await fixture.Service().PurgeInactiveThreatScoresAsync(now, "198.51.100.52"));
        Assert.True(await fixture.Service().PurgeInactiveThreatScoresAsync(now) >= 2);

        await using var verify = fixture.Factory.CreateDbContext();
        var ips = rows.Select(row => row.Ip).ToList();
        var remaining = await verify.IpThreatScores.Where(row => ips.Contains(row.IpAddress))
            .Select(row => row.IpAddress).ToListAsync();
        Assert.Equal(rows.Where(row => !row.Erased).Select(row => row.Ip).OrderBy(ip => ip, StringComparer.Ordinal),
            remaining.OrderBy(ip => ip, StringComparer.Ordinal));
        var journal = await verify.IpThreatScoreResets.Where(row => ips.Contains(row.IpAddress)).ToListAsync();
        Assert.Equal(3, journal.Count);
        Assert.All(journal, row =>
        {
            Assert.Equal("inactif 30 j", row.Reason);
            Assert.Equal(SecurityService.InactivityResetActor, row.ResetBy);
        });
        Assert.Equal(199, journal.Single(row => row.IpAddress == "::ffff:198.51.100.51").PreviousScore);
    }

    /// <summary>Reaching 200 bans the IP and the persisted score is removed before the call returns.</summary>
    [Fact]
    public async Task Ban_RemovesPersistedScoreBeforeReturning()
    {
        const string ip = "198.51.100.42";

        await fixture.Service().ReportThreatAsync(ip, 150, "first");
        await fixture.Service().ReportThreatAsync(ip, 60, "second");

        await using var db = fixture.Factory.CreateDbContext();
        Assert.False(await db.IpThreatScores.AnyAsync(score => score.IpAddress == ip));
        Assert.True((await db.BannedIps.SingleAsync(ban => ban.IpAddress == ip)).IsActive);
    }

    /// <summary>Reset deletes both key forms and writes the journal on PostgreSQL.</summary>
    [Fact]
    public async Task Reset_DeletesBothKeyFormsAndJournals()
    {
        const string plain = "198.51.100.43";
        const string mapped = "::ffff:198.51.100.43";
        await fixture.Service().ReportThreatAsync(plain, 40, "a");
        await fixture.Service().ReportThreatAsync(mapped, 30, "b");

        var result = await fixture.Service().ResetThreatScoreAsync(plain, "mcp:test", "TKT-002685 test");

        Assert.Equal(70, result.PreviousScore);
        await using var db = fixture.Factory.CreateDbContext();
        Assert.False(await db.IpThreatScores.AnyAsync(score => score.IpAddress == plain || score.IpAddress == mapped));
        var journal = await db.IpThreatScoreResets.SingleAsync(row => row.Id == result.ResetId);
        Assert.Equal(plain, journal.IpAddress);
        Assert.Equal(70, journal.PreviousScore);
        Assert.Equal(0, fixture.Service().GetThreatScore(plain));
    }

    /// <summary>
    /// The migration subscribes exactly the webhooks receiving IP bans, once, with exact trimmed matching,
    /// and the rollback removes only the new trigger.
    /// </summary>
    [Fact]
    public async Task WebhookSubscription_IsExactIdempotentAndReversible()
    {
        var rows = new Dictionary<string, (string Before, string AfterUp, string AfterDown)>
        {
            ["ntfy"] = ("Security.IpBanned,Security.ZombieDetected,Security.AuthFailure,License.Revoked",
                "Security.IpBanned,Security.ZombieDetected,Security.AuthFailure,License.Revoked,Security.ThreatScoreRaised",
                "Security.IpBanned,Security.ZombieDetected,Security.AuthFailure,License.Revoked"),
            ["spaced"] = ("License.Created, Security.IpBanned",
                "License.Created, Security.IpBanned,Security.ThreatScoreRaised",
                "License.Created, Security.IpBanned"),
            ["already"] = ("Security.IpBanned,Security.ThreatScoreRaised",
                "Security.IpBanned,Security.ThreatScoreRaised",
                "Security.IpBanned"),
            ["lookalike"] = ("Security.IpBannedV2,security.ipbanned", "Security.IpBannedV2,security.ipbanned",
                "Security.IpBannedV2,security.ipbanned"),
            ["other"] = ("License.Created", "License.Created", "License.Created")
        };
        await using (var db = fixture.Factory.CreateDbContext())
        {
            await db.Webhooks.ExecuteDeleteAsync();
            foreach (var (name, values) in rows)
                db.Webhooks.Add(new Webhook { Name = name, Url = "https://ntfy.example.test/topic", EnabledEvents = values.Before, IsEnabled = true });
            await db.SaveChangesAsync();
        }

        await ExecuteAsync(AddTkt002685ThreatScoreResets.SubscribeThreatScoreAlertSql);
        await ExecuteAsync(AddTkt002685ThreatScoreResets.SubscribeThreatScoreAlertSql);
        await AssertEventsAsync(rows.ToDictionary(row => row.Key, row => row.Value.AfterUp));

        await ExecuteAsync(AddTkt002685ThreatScoreResets.UnsubscribeThreatScoreAlertSql);
        await AssertEventsAsync(rows.ToDictionary(row => row.Key, row => row.Value.AfterDown));
    }

    /// <summary>
    /// TKT-003668: the migration subscribes exactly the webhooks receiving serious bans to the three serious triggers,
    /// once each, with exact trimmed matching; a noise-only webhook and look-alike entries are untouched, the
    /// Security.BinaryTampered subscription owned by the TKT-003674 migration is neither duplicated nor removed, and
    /// the rollback removes only the three triggers.
    /// </summary>
    [Fact]
    public async Task SeriousAlertSubscription_IsExactIdempotentAndReversible()
    {
        const string serious = ",Security.LockReported,Security.LockBanned,Security.LicenseServerSpoofed";
        var rows = new Dictionary<string, (string Before, string AfterUp, string AfterDown)>
        {
            ["ntfy"] = ("Security.IpBanned,Security.ZombieDetected,Security.AuthFailure,License.Revoked,Security.ThreatScoreRaised",
                "Security.IpBanned,Security.ZombieDetected,Security.AuthFailure,License.Revoked,Security.ThreatScoreRaised" + serious,
                "Security.IpBanned,Security.ZombieDetected,Security.AuthFailure,License.Revoked,Security.ThreatScoreRaised"),
            ["spaced"] = ("License.Created, Security.IpBanned",
                "License.Created, Security.IpBanned" + serious,
                "License.Created, Security.IpBanned"),
            ["partly"] = ("Security.IpBanned, Security.LockReported",
                "Security.IpBanned, Security.LockReported,Security.LockBanned,Security.LicenseServerSpoofed",
                "Security.IpBanned"),
            ["binary"] = ("Security.IpBanned,Security.BinaryTampered",
                "Security.IpBanned,Security.BinaryTampered" + serious,
                "Security.IpBanned,Security.BinaryTampered"),
            ["noise"] = ("Security.IpAutoBanned,Security.OutdatedVersionBanned",
                "Security.IpAutoBanned,Security.OutdatedVersionBanned",
                "Security.IpAutoBanned,Security.OutdatedVersionBanned"),
            ["lookalike"] = ("Security.IpBannedV2,security.ipbanned,Security.LockReportedV2",
                "Security.IpBannedV2,security.ipbanned,Security.LockReportedV2",
                "Security.IpBannedV2,security.ipbanned,Security.LockReportedV2"),
            ["other"] = ("License.Created", "License.Created", "License.Created")
        };
        await using (var db = fixture.Factory.CreateDbContext())
        {
            await db.Webhooks.ExecuteDeleteAsync();
            foreach (var (name, values) in rows)
                db.Webhooks.Add(new Webhook { Name = name, Url = "https://ntfy.example.test/topic", EnabledEvents = values.Before, IsEnabled = true });
            await db.SaveChangesAsync();
        }

        await ExecuteAsync(AddTkt003668SeriousAlertSubscriptions.SubscribeSeriousAlertsSql);
        await ExecuteAsync(AddTkt003668SeriousAlertSubscriptions.SubscribeSeriousAlertsSql);
        await AssertEventsAsync(rows.ToDictionary(row => row.Key, row => row.Value.AfterUp));

        await ExecuteAsync(AddTkt003668SeriousAlertSubscriptions.UnsubscribeSeriousAlertsSql);
        await AssertEventsAsync(rows.ToDictionary(row => row.Key, row => row.Value.AfterDown));
    }

    private async Task ExecuteAsync(string sql)
    {
        await using var db = fixture.Factory.CreateDbContext();
        await db.Database.ExecuteSqlRawAsync(sql);
    }

    private async Task AssertEventsAsync(IReadOnlyDictionary<string, string> expected)
    {
        await using var db = fixture.Factory.CreateDbContext();
        var actual = await db.Webhooks.AsNoTracking().ToDictionaryAsync(hook => hook.Name, hook => hook.EnabledEvents);
        foreach (var (name, events) in expected)
            Assert.Equal(events, actual[name]);
    }
}

/// <summary>Isolated PostgreSQL clone for the TKT-002685 tests.</summary>
public sealed class ThreatScorePostgreSqlFixture : IAsyncLifetime
{
    private string _maintenanceConnectionString = string.Empty;
    private string _database = string.Empty;

    /// <summary>Factory bound only to the isolated database.</summary>
    public PortalDeactivationPostgreSqlFixture.TestDbContextFactory Factory { get; private set; } = null!;

    /// <summary>Clones the current-schema model.</summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("threatscore");
        _database = clone.DatabaseName;
        _maintenanceConnectionString = clone.MaintenanceConnectionString;
        Factory = new PortalDeactivationPostgreSqlFixture.TestDbContextFactory(clone.ConnectionString);
    }

    /// <summary>Drops the clone even when a test fails.</summary>
    public async Task DisposeAsync()
    {
        if (string.IsNullOrEmpty(_database) || string.IsNullOrEmpty(_maintenanceConnectionString))
            return;
        await PostgreSqlModelDatabase.DropAsync(_maintenanceConnectionString, _database);
    }

    /// <summary>Creates one security service, as one request scope does in production.</summary>
    public SecurityService Service()
    {
        var notifier = new Mock<NotificationService>(
            Mock.Of<IDbContextFactory<LicenseDbContext>>(),
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["AdminSettings:AllowedIps"] = string.Empty })
            .Build();
        return new SecurityService(Factory, Mock.Of<ILogger<SecurityService>>(), notifier.Object, configuration);
    }
}
