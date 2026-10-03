using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>TKT-001277 lot 2d: environment switch parsing, startup synchronization and grouped alerts.</summary>
public sealed class AssignmentEnforcementTests
{
    [Theory]
    [InlineData(null, "open", true)]
    [InlineData("", "open", true)]
    [InlineData("   ", "open", true)]
    [InlineData("open", "open", true)]
    [InlineData(" OPEN ", "open", true)]
    [InlineData("closed", "closed", true)]
    [InlineData("Closed", "closed", true)]
    [InlineData("close", "open", false)]
    [InlineData("true", "open", false)]
    [InlineData("closİd", "open", false)]
    public void TryParseMode_AcceptsOnlyOpenAndClosed_DefaultingToOpen(string? raw, string expected, bool valid)
    {
        Assert.Equal(valid, AssignmentEnforcement.TryParseMode(raw, out var mode));
        Assert.Equal(expected, mode);
    }

    [Theory]
    [InlineData("closed", "closed")]
    [InlineData(null, "open")]
    [InlineData("bogus", "open")]
    public async Task Synchronizer_WritesTheEnvironmentValue(string? raw, string expected)
    {
        var factory = CreateFactory();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [AssignmentEnforcement.EnvironmentVariable] = raw })
            .Build();

        await new AssignmentEnforcementModeSynchronizer(
            factory, configuration, NullLogger<AssignmentEnforcementModeSynchronizer>.Instance).StartAsync(default);

        await using var db = await factory.CreateDbContextAsync();
        var setting = await db.AssignmentEnforcementSettings.SingleAsync();
        Assert.Equal(expected, setting.Mode);
        Assert.Equal("startup:env", setting.UpdatedBy);
        Assert.Equal(expected == "open", await AssignmentEnforcement.IsOpenAsync(db, default));
    }

    [Fact]
    public async Task IsOpen_DefaultsToOpen_WhenTheRowIsMissing()
    {
        var factory = CreateFactory();
        await using var db = await factory.CreateDbContextAsync();
        db.AssignmentEnforcementSettings.RemoveRange(db.AssignmentEnforcementSettings);
        await db.SaveChangesAsync();

        Assert.True(await AssignmentEnforcement.IsOpenAsync(db, default));
    }

    [Fact]
    public async Task AlertWorker_SendsOneGroupedAlert_ThenNothingUntilNewEvents()
    {
        var factory = CreateFactory();
        await using (var db = await factory.CreateDbContextAsync())
        {
            for (var index = 0; index < 3; index++)
                AssignmentEnforcement.Record(db, "seat_release", "seat_release_assignment_missing",
                    "released_without_assignment_snapshot", Guid.NewGuid(), Guid.NewGuid(), null, "detail");
            db.AssignmentEnforcementEvents.Add(new AssignmentEnforcementEvent
            {
                Source = "database", Control = "assignment_trigger", CaseNumber = 1, Reason = "binding_mismatch",
                Action = "granted_from_binding", Detail = "d", ObservedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }
        var notifier = new Mock<NotificationService>(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        notifier.Setup(service => service.NotifyAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
            .ReturnsAsync(new NotificationDeliveryResult(1, 1, 0));
        var worker = new AssignmentEnforcementAlertWorker(factory, notifier.Object,
            new ConfigurationBuilder().Build(), NullLogger<AssignmentEnforcementAlertWorker>.Instance);

        Assert.Equal(4, await worker.SendPendingAsync(default));
        Assert.Equal(0, await worker.SendPendingAsync(default));

        notifier.Verify(service => service.NotifyAsync(
                NotificationService.Triggers.SecurityAssignmentEnforcement,
                It.Is<string>(title => title.Contains("4 blocage")),
                It.Is<string>(message => message.Contains("3 × seat_release / seat_release_assignment_missing")
                    && message.Contains("1 × assignment_trigger / binding_mismatch → granted_from_binding")),
                It.IsAny<object?>()),
            Times.Once);
        await using var check = await factory.CreateDbContextAsync();
        Assert.All(await check.AssignmentEnforcementEvents.ToListAsync(), row => Assert.NotNull(row.AlertedAtUtc));
    }

    /// <summary>
    /// TKT-001277 review I4: with no configured destination or a failed delivery the events stay pending and are
    /// sent again at the next cycle once a destination accepts them.
    /// </summary>
    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(1, 0, 1)]
    [InlineData(2, 0, 2)]
    public async Task AlertWorker_KeepsEventsPendingUntilAnAlertIsDelivered(int configured, int delivered, int failed)
    {
        var factory = CreateFactory();
        await using (var db = await factory.CreateDbContextAsync())
        {
            AssignmentEnforcement.Record(db, "seat_release", "seat_release_assignment_missing",
                "released_without_assignment_snapshot", Guid.NewGuid(), Guid.NewGuid(), null, "detail");
            await db.SaveChangesAsync();
        }
        var notifier = new Mock<NotificationService>(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        notifier.SetupSequence(service => service.NotifyAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
            .ReturnsAsync(new NotificationDeliveryResult(configured, delivered, failed))
            .ReturnsAsync(new NotificationDeliveryResult(1, 1, 0));
        var worker = new AssignmentEnforcementAlertWorker(factory, notifier.Object,
            new ConfigurationBuilder().Build(), NullLogger<AssignmentEnforcementAlertWorker>.Instance);

        Assert.Equal(0, await worker.SendPendingAsync(default));
        await using (var pending = await factory.CreateDbContextAsync())
            Assert.All(await pending.AssignmentEnforcementEvents.ToListAsync(), row => Assert.Null(row.AlertedAtUtc));

        Assert.Equal(1, await worker.SendPendingAsync(default));
        await using var sent = await factory.CreateDbContextAsync();
        Assert.All(await sent.AssignmentEnforcementEvents.ToListAsync(), row => Assert.NotNull(row.AlertedAtUtc));
    }

    private static IDbContextFactory<LicenseDbContext> CreateFactory()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase("assignment-enforcement-" + Guid.NewGuid().ToString("N")).Options;
        using (var db = new LicenseDbContext(options))
            db.Database.EnsureCreated();
        return new Factory(options);
    }

    private sealed class Factory(DbContextOptions<LicenseDbContext> options) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}
