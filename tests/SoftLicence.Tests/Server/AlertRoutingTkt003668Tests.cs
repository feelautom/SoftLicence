using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003668: serious alerts reach ntfy at high or maximum priority, routine noise has its own low-priority triggers
/// that may never share a webhook with alerts, and the attack seen on HWID F32ED145 (modified binaries, alerted per
/// machine since TKT-003674, plus an activation through a local licence server, TKT-003671) raises critical alerts at
/// maximum priority. No database server is needed: the
/// webhook delivery tests use EF InMemory only to store webhook rows, whose matching is done in memory by design.
/// </summary>
public sealed class AlertRoutingTkt003668Tests
{
    /// <summary>The mixing rule refuses noise with any other trigger and accepts pure lists, after trimming.</summary>
    /// <param name="csv">Comma-separated subscription.</param>
    /// <param name="expected">Whether the subscription mixes noise with alerts.</param>
    [Theory]
    [InlineData("Security.IpAutoBanned,Security.OutdatedVersionBanned", false)]
    [InlineData("Security.IpAutoBanned", false)]
    [InlineData("Security.IpBanned,Security.LockReported,Security.BinaryTampered", false)]
    [InlineData("Security.IpAutoBanned,Security.LockReported", true)]
    [InlineData(" Security.OutdatedVersionBanned , Security.IpBanned ", true)]
    [InlineData("Security.IpAutoBanned,,  ", false)]
    [InlineData("security.ipautobanned,Security.IpBanned", false)]
    [InlineData("", false)]
    public void MixesNoiseWithAlerts_FollowsExactTrimmedOrdinalEntries(string csv, bool expected) =>
        Assert.Equal(expected, NotificationService.MixesNoiseWithAlerts(csv.Split(',')));

    /// <summary>Critical triggers are max priority, noise is low, other security events stay high.</summary>
    /// <param name="trigger">Exact trigger key.</param>
    /// <param name="expected">Expected ntfy priority, or null for the server default.</param>
    [Theory]
    [InlineData(NotificationService.Triggers.SecurityBinaryTampered, "5")]
    [InlineData(NotificationService.Triggers.SecurityLicenseServerSpoofed, "5")]
    [InlineData(NotificationService.Triggers.SecurityIpAutoBanned, "2")]
    [InlineData(NotificationService.Triggers.SecurityOutdatedVersionBanned, "2")]
    [InlineData(NotificationService.Triggers.SecurityIpBanned, "4")]
    [InlineData(NotificationService.Triggers.SecurityThreatScoreRaised, "4")]
    [InlineData(NotificationService.Triggers.ActivationIncident, "4")]
    [InlineData(NotificationService.Triggers.LicenseCreated, null)]
    public void NtfyPriorityFor_SeparatesCriticalAlertsFromNoise(string trigger, string? expected) =>
        Assert.Equal(expected, NotificationService.NtfyPriorityFor(trigger));

    /// <summary>Level 5 and lock bans are max priority; levels 3 and 4 are high.</summary>
    /// <param name="level">Lock level.</param>
    /// <param name="newBan">Whether the alert announces a ban.</param>
    /// <param name="expected">Expected ntfy priority.</param>
    [Theory]
    [InlineData(5, false, "5")]
    [InlineData(4, false, "4")]
    [InlineData(3, false, "4")]
    [InlineData(3, true, "5")]
    public void SecurityLockPriority_IsLevelBased(int level, bool newBan, string expected) =>
        Assert.Equal(expected, SecurityLockAlertPolicy.NtfyPriority(level, newBan));

    /// <summary>Every new trigger can be selected on the admin page, and noise and critical sets are disjoint.</summary>
    [Fact]
    public void NewTriggers_AreSelectableAndClassifiedOnce()
    {
        foreach (var trigger in new[]
                 {
                     NotificationService.Triggers.SecurityIpAutoBanned,
                     NotificationService.Triggers.SecurityOutdatedVersionBanned,
                     NotificationService.Triggers.SecurityBinaryTampered,
                     NotificationService.Triggers.SecurityLicenseServerSpoofed
                 })
            Assert.True(NotificationService.AvailableTriggers.ContainsKey(trigger), trigger);
        Assert.Empty(NotificationService.NoiseTriggers.Intersect(NotificationService.CriticalTriggers));
    }

    /// <summary>Local, loopback and private activation hosts are detected; public names and addresses are not.</summary>
    /// <param name="host">Reported activation host.</param>
    /// <param name="expected">Whether the host is local.</param>
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.10.0.5", true)]
    [InlineData(" localhost ", true)]
    [InlineData("LOCALHOST", true)]
    [InlineData("licence.localhost", true)]
    [InlineData("[::1]", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.1", true)]
    [InlineData("192.168.0.10", true)]
    [InlineData("169.254.0.10", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("softlicence.EXAMPLE.COM", false)]
    [InlineData("localhost.example.com", false)]
    [InlineData("softlicence", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsLocalActivationHost_DetectsOnlyLocalServers(string? host, bool expected) =>
        Assert.Equal(expected, ActivationIncidentService.IsLocalActivationHost(host));

    /// <summary>
    /// Case F32ED145 (TKT-003671): a successful Pro activation reporting <c>FailureHost = 127.0.0.1</c> raises the
    /// critical spoofed-server alert with the masked machine identity; a genuine activation raises nothing.
    /// </summary>
    [Fact]
    public async Task ActivationThroughLocalServer_RaisesCriticalAlert()
    {
        var notifier = CreateNotifierMock(CreateFactory());
        var service = new ActivationIncidentService(CreateFactory(), notifier.Object);

        await service.ProcessAsync(Guid.NewGuid(), Activation("127.0.0.1"), "183.196.89.35", null);
        await service.ProcessAsync(Guid.NewGuid(), Activation("softlicence.EXAMPLE.COM"), "203.0.113.9", null);

        notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityLicenseServerSpoofed,
            It.IsAny<string>(),
            It.Is<string>(message => message.Contains("F32E…5823", StringComparison.Ordinal)
                && message.Contains("127.0.0.1", StringComparison.Ordinal)
                && message.Contains("2.4.402", StringComparison.Ordinal)),
            It.IsAny<object?>()), Times.Once);
        notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityLicenseServerSpoofed,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()), Times.Once);
    }

    /// <summary>
    /// End to end on the webhook dispatcher, with the production subscription after the TKT-003674 and TKT-003668
    /// migrations plus a
    /// separate noise topic: a modified binary and a spoofed server reach only the alert topic at priority 5, and a
    /// scanner ban reaches only the noise topic at priority 2.
    /// </summary>
    [Fact]
    public async Task Delivery_RoutesCriticalAlertsAndNoiseToSeparateTopicsWithTheirPriority()
    {
        var factory = CreateFactory();
        await using (var db = await factory.CreateDbContextAsync())
        {
            db.Webhooks.Add(new Webhook
            {
                Name = "alerts",
                Url = "https://ntfy.example.invalid/softlicence-alerts",
                EnabledEvents = "Security.IpBanned,Security.ThreatScoreRaised,Security.LockReported,Security.LockBanned,"
                    + "Security.BinaryTampered,Security.LicenseServerSpoofed"
            });
            db.Webhooks.Add(new Webhook
            {
                Name = "noise",
                Url = "https://ntfy.example.invalid/softlicence-noise",
                EnabledEvents = "Security.IpAutoBanned,Security.OutdatedVersionBanned"
            });
            await db.SaveChangesAsync();
        }
        var requests = new List<(string Topic, string? Priority)>();
        var notifier = new NotificationService(factory, NullLogger<NotificationService>.Instance,
            new RecordingHttpClientFactory(request =>
            {
                lock (requests)
                    requests.Add((request.RequestUri!.AbsolutePath,
                        System.Web.HttpUtility.ParseQueryString(request.RequestUri.Query)["priority"]));
            }));

        Assert.Equal(new NotificationDeliveryResult(1, 1, 0), await notifier.NotifyAsync(
            NotificationService.Triggers.SecurityBinaryTampered, "APPROVED BINARIES — ÉCART OBSERVÉ", "18 EXE"));
        Assert.Equal(new NotificationDeliveryResult(1, 1, 0), await notifier.NotifyAsync(
            NotificationService.Triggers.SecurityLicenseServerSpoofed, "ACTIVATION PAR UN SERVEUR DE LICENCES LOCAL", "127.0.0.1"));
        Assert.Equal(new NotificationDeliveryResult(1, 1, 0), await notifier.NotifyAsync(
            NotificationService.Triggers.SecurityIpAutoBanned, "IP BANNIE", "scan /.env"));

        Assert.Equal(
            new[]
            {
                ("/softlicence-alerts", (string?)"5"),
                ("/softlicence-alerts", (string?)"5"),
                ("/softlicence-noise", (string?)"2")
            },
            requests);
    }

    /// <summary>Builds a successful activation event from the machine of TKT-003671.</summary>
    /// <param name="host">Reported activation host.</param>
    private static TelemetryEventRequest Activation(string host) => new()
    {
        HardwareId = "F32ED1455D865823",
        AppName = "TIAConnect",
        Version = "2.4.402",
        EventName = "LicenseActivation_Success",
        Properties = new Dictionary<string, string> { ["FailureHost"] = host }
    };

    /// <summary>Creates a notifier mock whose Notify records calls without sending anything.</summary>
    /// <param name="factory">Context factory required by the constructor.</param>
    private static Mock<NotificationService> CreateNotifierMock(IDbContextFactory<LicenseDbContext> factory)
    {
        var notifier = new Mock<NotificationService>(factory, NullLogger<NotificationService>.Instance,
            Mock.Of<IHttpClientFactory>());
        notifier.Setup(n => n.Notify(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()));
        return notifier;
    }

    /// <summary>Creates a factory over a fresh, isolated EF InMemory store.</summary>
    private static IDbContextFactory<LicenseDbContext> CreateFactory() => new InMemoryFactory(
        new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase("alerts-" + Guid.NewGuid().ToString("N")).Options);

    /// <summary>Context factory bound to one InMemory store; each call returns a new context.</summary>
    private sealed class InMemoryFactory(DbContextOptions<LicenseDbContext> options) : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);
    }

    /// <summary>HTTP client factory whose handler records each request and answers 200.</summary>
    private sealed class RecordingHttpClientFactory(Action<HttpRequestMessage> record) : IHttpClientFactory
    {
        /// <inheritdoc />
        public HttpClient CreateClient(string name) => new(new RecordingHandler(record));

        /// <summary>Records the request and answers 200 without network access.</summary>
        private sealed class RecordingHandler(Action<HttpRequestMessage> record) : HttpMessageHandler
        {
            /// <inheritdoc />
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                record(request);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }
        }
    }
}
