using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class NotificationServiceTests
{
    [Theory]
    [InlineData(HttpStatusCode.OK, 1, 0)]
    [InlineData(HttpStatusCode.InternalServerError, 0, 1)]
    public async Task NotifyAsync_ReturnsExactDeliveryOutcomeAndTrimsCsvEntries(
        HttpStatusCode statusCode,
        int expectedDelivered,
        int expectedFailed)
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;
        await using (var db = new LicenseDbContext(options))
        {
            db.Webhooks.Add(new Webhook
            {
                Name = "UPD test",
                Url = "https://alerts.example.test/upd",
                EnabledEvents = "License.Created, " + NotificationService.Triggers.UpdatePreflightFailureShown,
                IsEnabled = true
            });
            await db.SaveChangesAsync();
        }

        var dbFactory = new Mock<IDbContextFactory<LicenseDbContext>>();
        dbFactory.Setup(factory => factory.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(options));
        var httpFactory = new Mock<IHttpClientFactory>();
        httpFactory.Setup(factory => factory.CreateClient(It.IsAny<string>()))
            .Returns(new HttpClient(new StaticResponseHandler(statusCode)));
        var service = new NotificationService(
            dbFactory.Object,
            NullLogger<NotificationService>.Instance,
            httpFactory.Object);

        var result = await service.NotifyAsync(
            NotificationService.Triggers.UpdatePreflightFailureShown,
            "UPD-1002",
            "test");

        Assert.Equal(1, result.Configured);
        Assert.Equal(expectedDelivered, result.Delivered);
        Assert.Equal(expectedFailed, result.Failed);
    }

    private sealed class StaticResponseHandler(HttpStatusCode statusCode) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode));
    }
}
