using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentLifecycleTests
{
    [Fact]
    public async Task Cleanup_ModeOff_DoesNotCreateDatabaseContext()
    {
        var factory = new Mock<IDbContextFactory<LicenseDbContext>>(MockBehavior.Strict);
        var service = new RuntimeEnrollmentCleanupService(
            factory.Object,
            Options.Create(new RuntimeEnrollmentOptions { Mode = "off" }),
            TimeProvider.System,
            NullLogger<RuntimeEnrollmentCleanupService>.Instance);

        await service.StartAsync(CancellationToken.None);
        await service.StopAsync(CancellationToken.None);

        factory.VerifyNoOtherCalls();
    }

    [Fact]
    public void Defaults_KeepOneLivePendingAndFiveMinuteChallenge()
    {
        var options = new RuntimeEnrollmentOptions();

        Assert.Equal(1, options.PendingEnrollmentLimitPerBinding);
        Assert.Equal(300, options.ChallengeTtlSeconds);
    }
}
