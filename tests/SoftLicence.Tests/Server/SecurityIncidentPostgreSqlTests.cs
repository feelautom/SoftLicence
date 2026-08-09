using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SecurityIncidentPostgreSqlTests
{
    private const string ConnectionStringEnvironmentVariable =
        "SOFTLICENCE_SECURITY_INCIDENT_TEST_POSTGRES";

    [Fact]
    [Trait("Category", "PostgreSqlZombieDetection")]
    public async Task ZombieDetection_TwoReplicasReserveOnlyOnePersistentNotification()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(connectionString)) return;

        await AssertFreshPostgreSql17DatabaseAsync(connectionString);
        IDbContextFactory<LicenseDbContext> factory = new TestDbContextFactory(connectionString);
        await using (var setupDb = await factory.CreateDbContextAsync())
            await setupDb.Database.EnsureCreatedAsync();

        const string hardwareId = "ABCDEF0123456789";
        var productId = Guid.NewGuid();
        await using (var seedDb = await factory.CreateDbContextAsync())
        {
            var product = new Product
            {
                Id = productId, Name = "Zombie fixture", PrivateKeyXml = "key",
                PublicKeyXml = "key", ApiSecret = "secret"
            };
            var type = new LicenseType
            {
                Id = Guid.NewGuid(), Name = "Team", Slug = "TEAM",
                DefaultMaxSeats = 3, ProductId = productId
            };
            seedDb.Licenses.Add(new License
            {
                LicenseKey = "ZOMBIE-POSTGRES-FIXTURE", HardwareId = hardwareId,
                IsActive = true, Product = product, ProductId = productId,
                Type = type, LicenseTypeId = type.Id, CustomerName = "Synthetic",
                CustomerEmail = "synthetic@example.test"
            });
            for (var index = 1; index <= 9; index++)
            {
                seedDb.AccessLogs.Add(new AccessLog
                {
                    HardwareId = hardwareId, ClientIp = $"{index}.20.30.40",
                    Timestamp = DateTime.UtcNow.AddMinutes(-index), AppName = "Test",
                    Endpoint = "CHECK", Path = "/api/activation/check", Method = "POST",
                    ResultStatus = "OK"
                });
            }
            await seedDb.SaveChangesAsync();
        }

        var notifications = new Mock<NotificationService>(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        notifications.Setup(n => n.Notify(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()));
        var configuration = new ConfigurationBuilder().Build();
        var first = new SecurityService(factory, Mock.Of<ILogger<SecurityService>>(), notifications.Object, configuration);
        var second = new SecurityService(factory, Mock.Of<ILogger<SecurityService>>(), notifications.Object, configuration);

        await Task.WhenAll(Enumerable.Range(0, 20).Select(index =>
            (index % 2 == 0 ? first : second).CheckForZombieAsync(hardwareId, "100.20.30.40")));

        await using var assertionDb = await factory.CreateDbContextAsync();
        var incident = Assert.Single(await assertionDb.SecurityIncidents
            .Include(row => row.Evidence)
            .Where(row =>
            row.ProductId == productId && row.HardwareId == hardwareId
            && row.Family == "zombie_critical").ToListAsync());
        Assert.Equal(10, incident.Evidence.Count);
        notifications.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityZombieDetected,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()), Times.Once);
    }

    [Fact]
    [Trait("Category", "PostgreSqlSecurityIncident")]
    public async Task RecordApprovedBinaryObservationAsync_TwoServiceInstancesPersistExactBoundedAggregate()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return;
        }

        await AssertFreshPostgreSql17DatabaseAsync(connectionString);

        IDbContextFactory<LicenseDbContext> factory = new TestDbContextFactory(connectionString);
        await using (var setupDb = await factory.CreateDbContextAsync())
        {
            await setupDb.Database.EnsureCreatedAsync();
        }

        var productId = Guid.NewGuid();
        await using (var seedDb = await factory.CreateDbContextAsync())
        {
            seedDb.Products.Add(new Product
            {
                Id = productId,
                Name = $"Product-{productId:N}",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "secret"
            });
            await seedDb.SaveChangesAsync();
        }

        var notifications = new Mock<NotificationService>(
            factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        notifications.Setup(notification => notification.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));

        var configuration = new ConfigurationBuilder().Build();
        var firstReplica = new SecurityIncidentService(
            factory,
            notifications.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            configuration);
        var secondReplica = new SecurityIncidentService(
            factory,
            notifications.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            configuration);
        var observedAt = new DateTime(2026, 7, 22, 12, 0, 0, DateTimeKind.Utc);
        const int observationCount = 40;

        await Task.WhenAll(Enumerable.Range(0, observationCount).Select(index =>
        {
            var replica = index % 2 == 0 ? firstReplica : secondReplica;
            return replica.RecordApprovedBinaryObservationAsync(
                productId,
                ApprovedBinaryObservationKind.Mismatch,
                new Dictionary<string, string> { ["FP_EXE"] = index.ToString("x64") },
                observedAt);
        }));

        await using var assertionDb = await factory.CreateDbContextAsync();
        var incident = await assertionDb.SecurityIncidents
            .Include(row => row.Evidence)
            .SingleAsync();
        Assert.Equal(observationCount, incident.OccurrenceCount);
        Assert.Equal(SecurityIncidentService.MaxEvidencePerPublicAggregate, incident.Evidence.Count);
        Assert.Equal(SecurityIncidentService.PublicTelemetryAggregateIdentity, incident.HardwareId);
        Assert.Null(incident.Version);
        Assert.Null(incident.ClientIp);
        notifications.Verify(notification => notification.Notify(
            NotificationService.Triggers.SecurityEvidenceObserved,
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()), Times.Once);

    }

    private static async Task AssertFreshPostgreSql17DatabaseAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();

        await using (var versionCommand = connection.CreateCommand())
        {
            versionCommand.CommandText = "SHOW server_version_num";
            var versionText = Assert.IsType<string>(await versionCommand.ExecuteScalarAsync());
            var versionNumber = int.Parse(versionText, System.Globalization.CultureInfo.InvariantCulture);
            Assert.InRange(versionNumber, 170000, 179999);
        }

        await using var freshnessCommand = connection.CreateCommand();
        freshnessCommand.CommandText =
            "SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'";
        var tableCount = Convert.ToInt64(
            await freshnessCommand.ExecuteScalarAsync(),
            System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(0, tableCount);
    }

    private sealed class TestDbContextFactory(string connectionString)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(
            new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(connectionString)
                .Options);
    }
}
