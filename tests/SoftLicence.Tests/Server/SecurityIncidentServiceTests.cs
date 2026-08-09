using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SecurityIncidentServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<LicenseDbContext> _options;
    private readonly IDbContextFactory<LicenseDbContext> _factory;

    public SecurityIncidentServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(_connection)
            .Options;
        using var db = new LicenseDbContext(_options);
        db.Database.EnsureCreated();
        _factory = new TestDbContextFactory(_options);
    }

    [Fact]
    public async Task RecordApprovedBinaryObservationAsync_TenOccurrencesWithTwoHashes_CreatesOneIncidentAndOneNotification()
    {
        var productId = await SeedProductAsync();
        var httpFactory = Mock.Of<IHttpClientFactory>();
        var notifications = new Mock<NotificationService>(
            _factory,
            Mock.Of<ILogger<NotificationService>>(),
            httpFactory);
        notifications.Setup(n => n.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Security:BinaryPatchedIncidentWindowMinutes"] = "1440"
            })
            .Build();
        var service = new SecurityIncidentService(
            _factory,
            notifications.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            config);
        var firstHash = new string('a', 64);
        var secondHash = new string('b', 64);
        var observedAt = new DateTime(2026, 7, 16, 8, 0, 0, DateTimeKind.Utc);

        await Task.WhenAll(Enumerable.Range(0, 10).Select(i =>
        {
            IReadOnlyDictionary<string, string> hashes = new Dictionary<string, string>
            {
                ["fp_exe"] = i < 5 ? firstHash : secondHash
            };
            return service.RecordApprovedBinaryObservationAsync(
                productId,
                ApprovedBinaryObservationKind.Mismatch,
                hashes,
                observedAt.AddMinutes(i));
        }));

        await using var db = await _factory.CreateDbContextAsync();
        var incident = await db.SecurityIncidents.Include(i => i.Evidence).SingleAsync();
        Assert.Equal(SecurityIncidentService.PublicTelemetryAggregateIdentity, incident.HardwareId);
        Assert.Null(incident.Version);
        Assert.Null(incident.ClientIp);
        Assert.Equal(10, incident.OccurrenceCount);
        Assert.Equal(SecurityIncidentService.ApprovedBinaryMismatchFamily, incident.Family);
        Assert.False(incident.IsHardwareBanned);
        Assert.Equal(observedAt, incident.FirstSeenUtc);
        Assert.Equal(observedAt.AddMinutes(9), incident.LastSeenUtc);
        Assert.Equal(2, incident.Evidence.Count);
        Assert.All(incident.Evidence, e => Assert.Equal(5, e.OccurrenceCount));
        Assert.Contains(incident.Evidence, e => e.ComponentHash == firstHash.ToUpperInvariant());
        Assert.Contains(incident.Evidence, e => e.ComponentHash == secondHash.ToUpperInvariant());
        Assert.NotNull(incident.InitialNotificationSentAtUtc);
        notifications.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityEvidenceObserved,
            "APPROVED BINARIES — ÉCART OBSERVÉ",
            It.IsAny<string>(),
            It.IsAny<object?>()), Times.Once);
        Assert.Contains(NotificationService.Triggers.SecurityEvidenceObserved, NotificationService.AvailableTriggers.Keys);
    }

    [Fact]
    public async Task RecordApprovedBinaryObservationAsync_InvalidHash_RejectsEvidenceWithoutPersistingIncident()
    {
        var productId = await SeedProductAsync();
        var notifications = new Mock<NotificationService>(
            _factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        var service = new SecurityIncidentService(
            _factory,
            notifications.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            new ConfigurationBuilder().Build());

        await Assert.ThrowsAsync<ArgumentException>(() => service.RecordApprovedBinaryObservationAsync(
            productId,
            ApprovedBinaryObservationKind.Mismatch,
            new Dictionary<string, string> { ["FP_EXE"] = "not-a-sha256" }));

        await using var db = await _factory.CreateDbContextAsync();
        Assert.Empty(await db.SecurityIncidents.ToListAsync());
    }

    [Fact]
    public async Task RecordApprovedBinaryObservationAsync_ManyDistinctHashes_CapsOneProductAggregateAndNotification()
    {
        var productId = await SeedProductAsync();
        var notifications = new Mock<NotificationService>(
            _factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        var service = new SecurityIncidentService(
            _factory,
            notifications.Object,
            Mock.Of<ILogger<SecurityIncidentService>>(),
            new ConfigurationBuilder().Build());
        var observedAt = new DateTime(2026, 7, 22, 9, 0, 0, DateTimeKind.Utc);

        await Task.WhenAll(Enumerable.Range(0, 40).Select(index =>
            service.RecordApprovedBinaryObservationAsync(
                productId,
                ApprovedBinaryObservationKind.Mismatch,
                new Dictionary<string, string> { ["FP_EXE"] = index.ToString("x64") },
                observedAt.AddSeconds(index))));

        await using var db = await _factory.CreateDbContextAsync();
        var incident = await db.SecurityIncidents.Include(row => row.Evidence).SingleAsync();
        Assert.Equal(SecurityIncidentService.PublicTelemetryAggregateIdentity, incident.HardwareId);
        Assert.Null(incident.Version);
        Assert.Null(incident.ClientIp);
        Assert.Equal(40, incident.OccurrenceCount);
        Assert.Equal(SecurityIncidentService.MaxEvidencePerPublicAggregate, incident.Evidence.Count);
        notifications.Verify(notification => notification.Notify(
            NotificationService.Triggers.SecurityEvidenceObserved,
            It.IsAny<string>(),
            It.Is<string>(message => !message.Contains("HWID", StringComparison.OrdinalIgnoreCase)),
            It.IsAny<object?>()), Times.Once);
    }

    private async Task<Guid> SeedProductAsync()
    {
        var productId = Guid.NewGuid();
        await using var db = await _factory.CreateDbContextAsync();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = $"Product-{productId:N}",
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret"
        });
        await db.SaveChangesAsync();
        return productId;
    }

    public void Dispose() => _connection.Dispose();

    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
    }
}
