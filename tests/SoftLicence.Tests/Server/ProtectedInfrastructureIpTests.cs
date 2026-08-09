using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ProtectedInfrastructureIpTests
{
    [Theory]
    [InlineData("91.134.136.142", "91.134.136.142", true)]
    [InlineData("91.134.136.142", "::ffff:91.134.136.142", true)]
    [InlineData("2001:db8::1", "2001:0db8:0:0:0:0:0:1", true)]
    [InlineData(" 91.134.136.142 , 2001:db8::1 ", "2001:db8::1", true)]
    [InlineData("91.134.136.142,91.134.136.142", "91.134.136.142", true)]
    [InlineData("91.134.136.142", "91.134.136.143", false)]
    [InlineData("91.134.136.0/24", "91.134.136.142", false)]
    [InlineData("*.example.test", "91.134.136.142", false)]
    [InlineData("not-an-ip", "91.134.136.142", false)]
    [InlineData("", "91.134.136.142", false)]
    public void IsProtectedInfrastructureIp_UsesExactCanonicalIpEquality(
        string configuredIps,
        string candidate,
        bool expected)
    {
        var fixture = CreateFixture(configuredIps);

        Assert.Equal(expected, fixture.Service.IsProtectedInfrastructureIp(candidate));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    [InlineData("invalid, also-invalid")]
    public void IsProtectedInfrastructureIp_InvalidOrEmptyConfigurationFailsClosed(string? configuredIps)
    {
        var fixture = CreateFixture(configuredIps);

        Assert.False(fixture.Service.IsProtectedInfrastructureIp("91.134.136.142"));
    }

    [Fact]
    public void ProtectedInfrastructureIp_DoesNotGrantAdminWhitelistTrust()
    {
        const string ip = "91.134.136.142";
        var fixture = CreateFixture(ip);

        Assert.True(fixture.Service.IsProtectedInfrastructureIp(ip));
        Assert.False(fixture.Service.IsWhitelisted(ip));
    }

    [Fact]
    public async Task ReportThreatAsync_ProtectedInfrastructureIpDoesNotAccumulateOrBan()
    {
        const string ip = "91.134.136.142";
        var fixture = CreateFixture(ip);

        for (var index = 0; index < 4; index++)
            await fixture.Service.ReportThreatAsync(ip, 50, $"Internal probe {index}");

        Assert.Equal(0, fixture.Service.GetThreatScore(ip));
        await using var db = new LicenseDbContext(fixture.Options);
        Assert.Null(await db.IpThreatScores.FindAsync(ip));
        Assert.Null(await db.BannedIps.SingleOrDefaultAsync(row => row.IpAddress == ip));
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityIpBanned,
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object>()), Times.Never);
    }

    [Fact]
    public async Task ReportThreatAsync_UnprotectedIpStillBansWhenInfrastructureProtectionIsConfigured()
    {
        const string protectedIp = "91.134.136.142";
        const string ordinaryIp = "203.0.113.25";
        var fixture = CreateFixture(protectedIp);

        for (var index = 0; index < 4; index++)
            await fixture.Service.ReportThreatAsync(ordinaryIp, 50, $"External failure {index}");

        await using var db = new LicenseDbContext(fixture.Options);
        var ban = await db.BannedIps.SingleAsync(row => row.IpAddress == ordinaryIp);
        Assert.True(ban.IsActive);
        Assert.True(await fixture.Service.IsBannedAsync(ordinaryIp));
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityIpBanned,
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object>()), Times.Once);
    }

    [Fact]
    public async Task BanIpAsync_ProtectedInfrastructureIpCannotBeBannedDirectly()
    {
        const string ip = "91.134.136.142";
        var fixture = CreateFixture(ip);

        await fixture.Service.BanIpAsync(ip, "Manual or automatic request");

        await using var db = new LicenseDbContext(fixture.Options);
        Assert.Null(await db.BannedIps.SingleOrDefaultAsync(row => row.IpAddress == ip));
        Assert.False(await fixture.Service.IsBannedAsync(ip));
    }

    [Fact]
    public async Task IsBannedAsync_ProtectedInfrastructureIpIgnoresHistoricalActiveBanAndHistory()
    {
        const string ip = "91.134.136.142";
        var fixture = CreateFixture(ip);
        await using (var db = new LicenseDbContext(fixture.Options))
        {
            db.BannedIps.Add(new BannedIp
            {
                IpAddress = ip,
                Reason = "Historical false positive",
                BannedAt = DateTime.UtcNow.AddMinutes(-10),
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                BanCount = 2,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        Assert.False(await fixture.Service.IsBannedAsync(ip));
        Assert.Equal(0, await fixture.Service.GetBanCountAsync(ip));
    }

    private static Fixture CreateFixture(string? protectedInfrastructureIps)
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var dbFactory = new Mock<IDbContextFactory<LicenseDbContext>>();
        dbFactory.Setup(factory => factory.CreateDbContextAsync(default))
            .Returns(() => Task.FromResult(new LicenseDbContext(options)));

        var notifier = new Mock<NotificationService>(
            Mock.Of<IDbContextFactory<LicenseDbContext>>(),
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AdminSettings:AllowedIps"] = string.Empty,
                ["SecuritySettings:ProtectedInfrastructureIps"] = protectedInfrastructureIps
            })
            .Build();
        var service = new SecurityService(
            dbFactory.Object,
            Mock.Of<ILogger<SecurityService>>(),
            notifier.Object,
            configuration);
        return new Fixture(service, options, notifier);
    }

    private sealed record Fixture(
        SecurityService Service,
        DbContextOptions<LicenseDbContext> Options,
        Mock<NotificationService> Notifier);
}
