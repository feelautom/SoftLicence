using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class HealthControllerCanaryPolicyTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task LegacyCanary_RegardlessOfSeverity_HasNoDurableEffect(int severity)
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options;
        await using (var seed = new LicenseDbContext(options))
        {
            seed.Products.Add(new Product { Name = "TIAConnect", PrivateKeyXml = "x", PublicKeyXml = "x", ApiSecret = "x" });
            await seed.SaveChangesAsync();
        }
        var controller = new HealthController(Mock.Of<ILogger<HealthController>>())
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        var result = await controller.Ping(new CanaryPingRequest
        {
            HardwareId = "HW-FORGED-LEGACY",
            Trigger = "IntegrityCheck_CoreDllTampered",
            Severity = severity,
            AppVersion = "2.2.843",
            BuildConfiguration = "Release"
        });

        Assert.IsType<AcceptedResult>(result);
        await using var db = new LicenseDbContext(options);
        Assert.False(await db.CanaryAlerts.AnyAsync());
        Assert.False(await db.BannedHardwareIds.AnyAsync());
        Assert.False(await db.Licenses.AnyAsync());
    }
}
