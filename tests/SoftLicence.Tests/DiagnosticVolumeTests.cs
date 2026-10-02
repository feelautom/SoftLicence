using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Tests.Server;
using Xunit;

namespace SoftLicence.Tests;

/// <summary>Exercises explicit partial diagnostics against relational, over-limit histories.</summary>
public sealed class DiagnosticVolumeTests
{
    [Fact]
    public async Task ExactHistories_OptInPreservesEvidence_AndStrictReadersStillRejectOverflow()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        SqliteFullModelHarness.RegisterConnection(connection);
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseSqlite(connection)
            .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
            .Options;
        var productId = Guid.NewGuid();
        var banId = Guid.NewGuid();
        const string hardwareId = "HW-VOLUME";
        await using (var db = new LicenseDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            db.Products.Add(new Product { Id = productId, Name = "VolumeTest",
                PrivateKeyXml = "fixture", PublicKeyXml = "fixture", ApiSecret = "fixture" });
            db.BannedHardwareIds.Add(new BannedHardwareId { Id = banId, ProductId = productId,
                HardwareId = hardwareId, Reason = "Exact evidence must survive telemetry overflow" });
            var now = DateTime.UtcNow;
            db.TelemetryRecords.AddRange(Enumerable.Range(0, 10001).Select(index => new TelemetryRecord
            {
                ProductId = productId, HardwareId = hardwareId, AppName = "VolumeTest", Version = "1.0.0",
                Type = TelemetryType.Event, EventName = "Heartbeat", Timestamp = now.AddSeconds(-index),
                EventData = new TelemetryEvent { PropertiesJson = "{}" }
            }));
            db.TelemetryRecords.Add(new TelemetryRecord { ProductId = productId, HardwareId = "HW-volume",
                AppName = "OtherMachine", Version = "1.0.0", Type = TelemetryType.Event,
                EventName = "OtherMachine", Timestamp = now, EventData = new TelemetryEvent { PropertiesJson = "{}" } });
            await db.SaveChangesAsync();
        }

        var factory = new TestFactory(options);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var profiles = new TelemetryMachineProfileAnalyticsService(factory, cache);
        var profile = await profiles.GetMachineProfileForProductIdAsync(productId, hardwareId,
            take: 1000, requireComplete: true, allowPartial: true);
        Assert.False(profile.Complete);
        Assert.Contains("machine_profile_row_limit", profile.IncompleteReasons);
        Assert.Equal(1000, profile.RecentRecords.Count);
        Assert.DoesNotContain(profile.RecentRecords, row => row.EventName == "OtherMachine");
        await Assert.ThrowsAsync<InvalidOperationException>(() => profiles.GetMachineProfileForProductIdAsync(
            productId, hardwareId, take: 1000, requireComplete: true));
        var other = await profiles.GetMachineProfileForProductIdAsync(productId, "HW-volume",
            take: 1000, requireComplete: true, allowPartial: true);
        Assert.True(other.Complete);
        Assert.Empty(other.IncompleteReasons);
        Assert.Equal("OtherMachine", Assert.Single(other.RecentRecords).EventName);

        var bans = new SecurityBanAuditAnalyticsService(factory);
        var result = await bans.ListBansForProductIdAsync(productId, hardwareId,
            componentHash: null, componentType: null, clientIp: null, emailFragment: null,
            licenseFragment: null, includeInactive: true, includeSourceEvents: false,
            take: 100, exactHardwareId: true, allowPartial: true);
        Assert.False(result.Complete);
        Assert.Contains("telemetry_fingerprint_row_limit", result.IncompleteReasons);
        Assert.Contains(result.Bans, ban => ban.BanId == banId);
        await Assert.ThrowsAsync<InvalidOperationException>(() => bans.ListBansForProductIdAsync(
            productId, hardwareId, componentHash: null, componentType: null, clientIp: null,
            emailFragment: null, licenseFragment: null, includeInactive: true, includeSourceEvents: false,
            take: 100, exactHardwareId: true));
    }

    private sealed class TestFactory(DbContextOptions<LicenseDbContext> options) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
    }
}
