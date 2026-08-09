using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
    public async Task CertPinningDailyAlert_ConcurrentExactHardwareEvents_CreateOneClaimAndExactCount()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var productId = Guid.NewGuid();
        await using (var seed = await factory.CreateDbContextAsync())
        {
            seed.Products.Add(new Product
            {
                Id = productId,
                Name = "Cert pinning concurrency " + productId.ToString("N"),
                PrivateKeyXml = string.Empty,
                PublicKeyXml = string.Empty,
                ApiSecret = Guid.NewGuid().ToString("N")
            });
            await seed.SaveChangesAsync();
        }

        var service = new CertPinningDailyAlertService(
            factory,
            NullLogger<CertPinningDailyAlertService>.Instance);
        var observedAtUtc = new DateTime(2026, 7, 27, 12, 0, 0, DateTimeKind.Utc);
        const string hardwareId = "584FA146332E8785";
        const int eventCount = 20;

        var results = await Task.WhenAll(Enumerable.Range(0, eventCount).Select(index =>
            service.RecordAndClaimAsync(
                productId,
                hardwareId,
                index % 2 == 0 ? "api.t-ia-connect.com" : "softlicence.EXAMPLE.COM",
                index % 2 == 0 ? "2.2.798" : "2.2.843",
                clientSuppressedCount: 1,
                observedAtUtc.AddMilliseconds(index))));

        var winningClaim = Assert.Single(results, result => result.ShouldNotify);
        Assert.NotNull(winningClaim.ClaimId);
        Assert.Single(results.Select(result => result.AggregateId).Distinct());

        await using (var verify = await factory.CreateDbContextAsync())
        {
            var aggregate = await verify.TelemetryCertPinningDailyAlerts.SingleAsync(alert =>
                alert.ProductId == productId && alert.HardwareId == hardwareId);
            Assert.Equal(eventCount, aggregate.OccurrenceCount);
            Assert.Equal(eventCount, aggregate.ClientSuppressedCount);
            Assert.Equal(winningClaim.ClaimId, aggregate.NotificationClaimId);
        }

        await service.MarkNotificationSentAsync(
            winningClaim.AggregateId,
            winningClaim.ClaimId!.Value,
            observedAtUtc.AddMinutes(1));
        var later = await service.RecordAndClaimAsync(
            productId,
            hardwareId,
            "api.t-ia-connect.com",
            "2.2.900",
            clientSuppressedCount: 3,
            observedAtUtc.AddHours(1));
        Assert.False(later.ShouldNotify);
        Assert.Equal(eventCount + 1, later.OccurrenceCount);
        Assert.Equal(eventCount + 3, later.ClientSuppressedCount);

        var exactVariants = new[]
        {
            hardwareId.ToLowerInvariant(),
            " " + hardwareId,
            hardwareId + " ",
            "HW-É",
            "HW-E\u0301",
            "HW-漢"
        };
        foreach (var exactVariant in exactVariants)
        {
            var distinct = await service.RecordAndClaimAsync(
                productId,
                exactVariant,
                "api.t-ia-connect.com",
                "2.2.900",
                clientSuppressedCount: 0,
                observedAtUtc.AddHours(1));
            Assert.True(distinct.ShouldNotify);
        }

        await using var finalVerify = await factory.CreateDbContextAsync();
        Assert.Equal(1 + exactVariants.Length, await finalVerify.TelemetryCertPinningDailyAlerts
            .CountAsync(alert => alert.ProductId == productId));
    }
}
