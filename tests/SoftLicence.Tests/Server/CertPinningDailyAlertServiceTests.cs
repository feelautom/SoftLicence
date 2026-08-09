using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class CertPinningDailyAlertServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactory = new();

    public CertPinningDailyAlertServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _dbFactory.Setup(factory => factory.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task RecordAndClaimAsync_GroupsSameExactHardwareAcrossHostsAndVersionsForParisDay()
    {
        var productId = await SeedProductAsync();
        var service = CreateService();
        var firstSeen = new DateTime(2026, 7, 27, 8, 0, 0, DateTimeKind.Utc);

        var first = await service.RecordAndClaimAsync(
            productId,
            "584FA146332E8785",
            "api.t-ia-connect.com",
            "2.2.798",
            clientSuppressedCount: 2,
            firstSeen);
        await service.MarkNotificationSentAsync(first.AggregateId, first.ClaimId!.Value, firstSeen.AddSeconds(1));

        var second = await service.RecordAndClaimAsync(
            productId,
            "584FA146332E8785",
            "softlicence.EXAMPLE.COM",
            "2.2.843",
            clientSuppressedCount: 5,
            firstSeen.AddHours(5),
            failureReason: "PinMismatch",
            certificateIssuer: "CN=Enterprise Forward Trust");

        Assert.True(first.ShouldNotify);
        Assert.False(second.ShouldNotify);
        Assert.Equal(first.AggregateId, second.AggregateId);
        Assert.Equal(2, second.OccurrenceCount);
        Assert.Equal(7, second.ClientSuppressedCount);

        await using var db = new LicenseDbContext(_dbOptions);
        var aggregate = await db.TelemetryCertPinningDailyAlerts.SingleAsync();
        Assert.Equal(new DateOnly(2026, 7, 27), aggregate.ParisDate);
        Assert.Equal("api.t-ia-connect.com", aggregate.FirstHost);
        Assert.Equal("softlicence.EXAMPLE.COM", aggregate.LastHost);
        Assert.Equal("2.2.843", aggregate.LastVersion);
        Assert.Equal("PinMismatch", aggregate.LastFailureReason);
        Assert.Equal("CN=Enterprise Forward Trust", aggregate.LastCertificateIssuer);
        Assert.NotNull(aggregate.NotificationSentAtUtc);
    }

    [Fact]
    public async Task RecordAndClaimAsync_NextParisDayCreatesNewNotificationGroup()
    {
        var productId = await SeedProductAsync();
        var service = CreateService();
        var beforeParisMidnight = new DateTime(2026, 7, 27, 21, 59, 0, DateTimeKind.Utc);
        var afterParisMidnight = new DateTime(2026, 7, 27, 22, 1, 0, DateTimeKind.Utc);

        var first = await service.RecordAndClaimAsync(
            productId, "HW-EXACT", "api.t-ia-connect.com", "2.2.798", 0, beforeParisMidnight);
        await service.MarkNotificationSentAsync(first.AggregateId, first.ClaimId!.Value, beforeParisMidnight);

        var nextDay = await service.RecordAndClaimAsync(
            productId, "HW-EXACT", "api.t-ia-connect.com", "2.2.798", 0, afterParisMidnight);

        Assert.True(nextDay.ShouldNotify);
        Assert.NotEqual(first.AggregateId, nextDay.AggregateId);
        await using var db = new LicenseDbContext(_dbOptions);
        Assert.Equal(2, await db.TelemetryCertPinningDailyAlerts.CountAsync());
    }

    [Fact]
    public async Task RecordAndClaimAsync_PreservesExactHardwareIdEquality()
    {
        var productId = await SeedProductAsync();
        var service = CreateService();
        var observedAtUtc = new DateTime(2026, 7, 27, 12, 0, 0, DateTimeKind.Utc);

        var upper = await service.RecordAndClaimAsync(
            productId, "ABCDEF0123456789", "api.t-ia-connect.com", "2.2.798", 0, observedAtUtc);
        var lower = await service.RecordAndClaimAsync(
            productId, "abcdef0123456789", "api.t-ia-connect.com", "2.2.798", 0, observedAtUtc);

        Assert.True(upper.ShouldNotify);
        Assert.True(lower.ShouldNotify);
        Assert.NotEqual(upper.AggregateId, lower.AggregateId);
    }

    [Fact]
    public async Task FailedNotificationAttempt_DoesNotRetryOrCreateAnotherGroup()
    {
        var productId = await SeedProductAsync();
        var service = CreateService();
        var observedAtUtc = new DateTime(2026, 7, 27, 12, 0, 0, DateTimeKind.Utc);

        var first = await service.RecordAndClaimAsync(
            productId, "HW-RETRY", "api.t-ia-connect.com", "2.2.798", 0, observedAtUtc);

        var retry = await service.RecordAndClaimAsync(
            productId, "HW-RETRY", "softlicence.EXAMPLE.COM", "2.2.798", 0, observedAtUtc.AddMinutes(1));

        Assert.False(retry.ShouldNotify);
        Assert.Equal(first.AggregateId, retry.AggregateId);
        Assert.Null(retry.ClaimId);
        Assert.Equal(2, retry.OccurrenceCount);
    }

    [Fact]
    public async Task RecordAndClaimAsync_BoundsFailureReasonAndIssuerWithoutNormalization()
    {
        var productId = await SeedProductAsync();
        var service = CreateService();
        var observedAtUtc = new DateTime(2026, 7, 27, 12, 0, 0, DateTimeKind.Utc);
        var reason = new string('R', 127) + "😀tail";
        var issuer = new string('I', 511) + "😀tail";

        await service.RecordAndClaimAsync(
            productId,
            "HW-CONTEXT",
            "softlicence.EXAMPLE.COM",
            "2.2.798",
            0,
            observedAtUtc,
            failureReason: reason,
            certificateIssuer: issuer);

        await using var db = new LicenseDbContext(_dbOptions);
        var aggregate = await db.TelemetryCertPinningDailyAlerts.SingleAsync();
        Assert.Equal(new string('R', 127), aggregate.LastFailureReason);
        Assert.Equal(new string('I', 511), aggregate.LastCertificateIssuer);

        var exactReason = new string('R', 126) + "😀";
        var exactIssuer = new string('I', 510) + "😀";
        await service.RecordAndClaimAsync(
            productId,
            "HW-CONTEXT",
            "softlicence.EXAMPLE.COM",
            "2.2.798",
            0,
            observedAtUtc.AddMinutes(1),
            failureReason: exactReason,
            certificateIssuer: exactIssuer);

        await db.Entry(aggregate).ReloadAsync();
        Assert.Equal(exactReason, aggregate.LastFailureReason);
        Assert.Equal(exactIssuer, aggregate.LastCertificateIssuer);
    }

    [Fact]
    public async Task RecordAndClaimAsync_OutOfOrderObservations_PreserveChronologicalEndpoints()
    {
        var productId = await SeedProductAsync();
        var service = CreateService();
        var middle = new DateTime(2026, 7, 27, 12, 0, 0, DateTimeKind.Utc);

        await service.RecordAndClaimAsync(
            productId, "HW-ORDER", "middle.example", "2.2.800", 0, middle);
        await service.RecordAndClaimAsync(
            productId, "HW-ORDER", "last.example", "2.2.900", 0, middle.AddHours(1));
        await service.RecordAndClaimAsync(
            productId, "HW-ORDER", "first.example", "2.2.700", 0, middle.AddHours(-1));

        await using var db = new LicenseDbContext(_dbOptions);
        var aggregate = await db.TelemetryCertPinningDailyAlerts.SingleAsync();
        Assert.Equal(middle.AddHours(-1), aggregate.FirstSeenUtc);
        Assert.Equal("first.example", aggregate.FirstHost);
        Assert.Equal(middle.AddHours(1), aggregate.LastSeenUtc);
        Assert.Equal("last.example", aggregate.LastHost);
        Assert.Equal("2.2.900", aggregate.LastVersion);
    }

    private CertPinningDailyAlertService CreateService() =>
        new(_dbFactory.Object, NullLogger<CertPinningDailyAlertService>.Instance);

    private async Task<Guid> SeedProductAsync()
    {
        var productId = Guid.NewGuid();
        await using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TIAConnect",
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret"
        });
        await db.SaveChangesAsync();
        return productId;
    }
}
