using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SecurityBanAuditAnalyticsServiceTests
{
    [Fact]
    public async Task ListBans_WhenExactResultExceedsBound_FailsClosed()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        SqliteFullModelHarness.RegisterConnection(connection);
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
            .Options;
        var productId = Guid.NewGuid();
        const string hardwareId = "HW-EXACT-OVERFLOW";
        await using (var db = new LicenseDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            db.Products.Add(new Product
            {
                Id = productId, Name = "TIAConnect", PrivateKeyXml = "test-private-key",
                PublicKeyXml = "test-public-key", ApiSecret = "test-api-secret"
            });
            var hashes = Enumerable.Range(1, 101).Select(index => index.ToString("x64")).ToArray();
            db.BannedComponents.AddRange(hashes.Select((hash, index) => new BannedComponent
            {
                Id = Guid.NewGuid(), ProductId = productId, ComponentType = "FP_EXE",
                ComponentHash = hash, Reason = $"Exact overflow fixture {index}"
            }));
            db.TelemetryRecords.AddRange(hashes.Select(hash =>
                CreateFingerprintEvent(productId, hardwareId, hash)));
            await db.SaveChangesAsync();
        }
        var service = new SecurityBanAuditAnalyticsService(new TestDbContextFactory(options));

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ListBansForProductIdAsync(
            productId, hardwareId, componentHash: null, componentType: null, clientIp: null,
            emailFragment: null, licenseFragment: null, includeInactive: true,
            includeSourceEvents: false, take: 100, exactHardwareId: true));
    }

    [Fact]
    public async Task ListBans_WhenCombinedExactBanKindsExceedBound_FailsClosed()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        SqliteFullModelHarness.RegisterConnection(connection);
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
            .Options;
        var productId = Guid.NewGuid();
        const string hardwareId = "HW-COMBINED-OVERFLOW";
        var componentHashes = Enumerable.Range(1, 100)
            .Select(index => index.ToString("x64"))
            .ToArray();

        await using (var db = new LicenseDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            db.Products.Add(new Product
            {
                Id = productId, Name = "TIAConnect", PrivateKeyXml = "test-private-key",
                PublicKeyXml = "test-public-key", ApiSecret = "test-api-secret"
            });
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                Id = Guid.NewGuid(), ProductId = productId, HardwareId = hardwareId,
                Reason = "Combined hardware fixture"
            });
            db.BannedComponents.AddRange(componentHashes.Select((hash, index) => new BannedComponent
            {
                Id = Guid.NewGuid(), ProductId = productId, ComponentType = "FP_EXE",
                ComponentHash = hash, Reason = $"Combined component fixture {index}"
            }));
            db.TelemetryRecords.AddRange(componentHashes.Select(hash =>
                CreateFingerprintEvent(productId, hardwareId, hash)));
            await db.SaveChangesAsync();
        }

        var service = new SecurityBanAuditAnalyticsService(new TestDbContextFactory(options));

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ListBansForProductIdAsync(
            productId, hardwareId, componentHash: null, componentType: null, clientIp: null,
            emailFragment: null, licenseFragment: null, includeInactive: true,
            includeSourceEvents: false, take: 100, exactHardwareId: true));
    }

    [Fact]
    public async Task ListBans_WhenExactHashUsesDifferentCase_IncludesTargetAndCorrelatedBans()
    {
        const string hardwareId = "HW-RELATIONAL-HASH";
        const string targetHash = "ca641f9d52d992cb49d39d1911c42c225ffa7665c3329a0b3f128b9558cbc8db";
        const string relatedHash = "62b6d2bf9266a83bef6c7e30a82d05f32a46fdafedf63ceeac9f43339ffaa82d";
        const string unrelatedHash = "164afce248e17395db6d987e7d7c9d9cebbd19da3d666ad710d6f946aef9ceac";

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        SqliteFullModelHarness.RegisterConnection(connection);

        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
            .Options;

        var productId = Guid.NewGuid();
        var targetBanId = Guid.NewGuid();
        var relatedBanId = Guid.NewGuid();
        var hardwareBanId = Guid.NewGuid();
        var unrelatedBanId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "TIAConnect",
                PrivateKeyXml = "test-private-key",
                PublicKeyXml = "test-public-key",
                ApiSecret = "test-api-secret"
            });
            db.TelemetryRecords.AddRange(
                CreateFingerprintEvent(productId, hardwareId, targetHash),
                CreateFingerprintEvent(productId, hardwareId, relatedHash));
            db.TelemetryRecords.AddRange(Enumerable.Range(0, 501).Select(index => new TelemetryRecord
            {
                ProductId = productId,
                HardwareId = hardwareId,
                AppName = "TIAConnect",
                Version = "2.1.839",
                EventName = "Heartbeat",
                Type = TelemetryType.Event,
                Timestamp = DateTime.UtcNow.AddDays(-1).AddSeconds(index),
                EventData = new TelemetryEvent { PropertiesJson = "{}" }
            }));
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                Id = hardwareBanId,
                ProductId = productId,
                HardwareId = hardwareId,
                Reason = "Relational hash regression fixture"
            });
            db.BannedComponents.AddRange(
                new BannedComponent
                {
                    Id = targetBanId,
                    ProductId = productId,
                    ComponentType = "FP_EXE",
                    ComponentHash = targetHash,
                    Reason = "Exact target"
                },
                new BannedComponent
                {
                    Id = relatedBanId,
                    ProductId = productId,
                    ComponentType = "FP_EXE",
                    ComponentHash = relatedHash,
                    Reason = "Correlated environment"
                },
                new BannedComponent
                {
                    Id = unrelatedBanId,
                    ProductId = productId,
                    ComponentType = "FP_EXE",
                    ComponentHash = unrelatedHash,
                    Reason = "Unrelated environment"
                });
            await db.SaveChangesAsync();
        }

        var service = new SecurityBanAuditAnalyticsService(new TestDbContextFactory(options));

        var result = await service.ListBansForProductIdAsync(
            productId,
            hardwareId: null,
            componentHash: targetHash.ToUpperInvariant(),
            componentType: "FP_EXE",
            clientIp: null,
            emailFragment: null,
            licenseFragment: null,
            includeInactive: true,
            includeSourceEvents: false,
            take: 10);

        Assert.Contains(hardwareId, result.ResolvedHardwareIds);
        Assert.Contains(result.Bans, ban => ban.BanId == hardwareBanId);
        Assert.Contains(result.Bans, ban => ban.BanId == targetBanId);
        Assert.Contains(result.Bans, ban => ban.BanId == relatedBanId);
        Assert.DoesNotContain(result.Bans, ban => ban.BanId == unrelatedBanId);

        var exact = await service.ListBansForProductIdAsync(
            productId, hardwareId, componentHash: null, componentType: null, clientIp: null,
            emailFragment: null, licenseFragment: null, includeInactive: true,
            includeSourceEvents: false, take: 10, exactHardwareId: true);

        Assert.True(exact.Query.ExactHardwareId);
        Assert.Contains(exact.Bans, ban => ban.BanId == targetBanId
            && ban.CorrelatedHardwareIds.SequenceEqual([hardwareId]));
        Assert.Contains(exact.Bans, ban => ban.BanId == relatedBanId
            && ban.CorrelatedHardwareIds.SequenceEqual([hardwareId]));
        Assert.DoesNotContain(exact.Bans, ban => ban.BanId == unrelatedBanId);
    }

    private static TelemetryRecord CreateFingerprintEvent(Guid productId, string hardwareId, string hash) =>
        new()
        {
            ProductId = productId,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = "2.1.839",
            EventName = "Startup_AppStarted",
            Type = TelemetryType.Event,
            Timestamp = DateTime.UtcNow,
            EventData = new TelemetryEvent
            {
                PropertiesJson = $$"""{"FP_EXE":"{{hash}}"}"""
            }
        };

    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
    }
}
