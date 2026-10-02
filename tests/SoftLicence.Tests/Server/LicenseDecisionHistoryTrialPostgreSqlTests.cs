using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises explicit and automatic trial producers using only synthetic signing material and relational fixtures.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Proves both trial surfaces keep refusal finalization bounded and roll back creation/recovery when the accepted history cannot be saved.</summary>
    /// <remarks>Every row uses a private database and in-memory signing key. Independent observation distinguishes lost commit acknowledgement from rollback; all other failed attempts leave the complete business fingerprint unchanged.</remarks>
    [Theory]
    [InlineData(false, "refused", "insert")]
    [InlineData(true, "refused", "insert")]
    [InlineData(false, "refused", "cancel-after")]
    [InlineData(true, "refused", "cancel-after")]
    [InlineData(false, "refused", "host-stop")]
    [InlineData(true, "refused", "host-stop")]
    [InlineData(false, "refused", "timeout")]
    [InlineData(true, "refused", "timeout")]
    [InlineData(false, "refused", "commit-before")]
    [InlineData(true, "refused", "commit-before")]
    [InlineData(false, "refused", "commit-ack")]
    [InlineData(true, "refused", "commit-ack")]
    [InlineData(false, "existing", "insert")]
    [InlineData(true, "existing", "insert")]
    [InlineData(false, "new", "insert")]
    [InlineData(true, "new", "insert")]
    [InlineData(false, "new", "commit-before")]
    [InlineData(true, "new", "commit-before")]
    [InlineData(false, "new", "commit-ack")]
    [InlineData(true, "new", "commit-ack")]
    public async Task Tkt976_Trial_FaultsPreserveBusinessAndConfirmedOutcome(bool automatic, string outcome, string mode)
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        using var host = Tkt976_CreateLegacyHost(new Tkt976FaultFactory(connections.App, fault));
        using var encryptionScope = host.Services.CreateScope();
        var encryption = encryptionScope.ServiceProvider.GetRequiredService<EncryptionService>();
        using var rsa = RSA.Create(2048);
        string productName;
        await using (var seed = await clean.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Product).Include(row => row.Type)
                .SingleAsync(row => row.Id == fixture.LicenseId);
            license.IsActive = outcome != "refused";
            license.Type!.Slug = "TRIAL";
            license.Product!.PrivateKeyXml = encryption.Encrypt(rsa.ToXmlString(true));
            productName = license.Product.Name;
            await seed.SaveChangesAsync();
        }
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        var hardwareId = outcome == "new" ? "1234567890ABCDEF" : fixture.HardwareId;
        using (var scope = host.Services.CreateScope())
        {
            var controller = ActivatorUtilities.CreateInstance<ActivationController>(scope.ServiceProvider,
                new Tkt976HostLifetime(shutdown));
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext
                {
                    RequestServices = scope.ServiceProvider, RequestAborted = requestCancellation.Token,
                    TraceIdentifier = "tkt976-trial-fault"
                }
            };
            controller.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
            controller.Response.Headers["X-Request-Id"] = "trial-request";
            controller.Response.Headers["X-Content-Type-Options"] = "nosniff";
            fault.Armed = true;
            IActionResult response = automatic
                ? await controller.Activate(new ActivationController.ActivationRequest
                { LicenseKey = "FREE-TRIAL", HardwareId = hardwareId, AppName = productName, AppVersion = fixture.Version })
                : await controller.GetTrial(new ActivationController.TrialRequest
                { TypeSlug = "TRIAL", HardwareId = hardwareId, AppName = productName, AppVersion = fixture.Version });
            Assert.Equal(mode == "cancel-after" ? 403 : 500, Assert.IsAssignableFrom<ObjectResult>(response).StatusCode);
            Assert.Equal("trial-request", controller.Response.Headers["X-Request-Id"].ToString());
            Assert.Equal("nosniff", controller.Response.Headers["X-Content-Type-Options"].ToString());
            if (mode == "cancel-after") Assert.True(requestCancellation.IsCancellationRequested);
            else Assert.False(controller.Response.Headers.ContainsKey("X-SoftLicence-Error-Code"));
        }
        if (outcome == "refused" || mode != "commit-ack")
            Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await clean.CreateDbContextAsync();
        var rows = await observed.LicenseHistories.Where(row => row.License!.ProductId == fixture.ProductId
            && row.Action == "ACTIVATION_DECISION_V1").ToListAsync();
        Assert.Equal(mode is "cancel-after" or "commit-ack" ? 1 : 0, rows.Count);
    }

    /// <summary>Trial recovery refusals and existing/new successes retain decisions without changing their public response or independent-request semantics.</summary>
    /// <remarks>RSA material is generated in memory and encrypted with the isolated test host protector; no private key is printed or written to source. Refused existing licences must leave every business table unchanged. New licences own accepted events only in the successful creation transaction.</remarks>
    [Theory]
    [InlineData(false, "refused")]
    [InlineData(true, "refused")]
    [InlineData(false, "existing")]
    [InlineData(true, "existing")]
    [InlineData(false, "new")]
    [InlineData(true, "new")]
    public async Task Tkt976_Trial_ExistingAndNewDecisions_AreRecorded(bool automatic, string outcome)
    {
        var connections = await ProvisionAsync();
        var database = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(database);
        using var host = Tkt976_CreateLegacyHost(database);
        using var encryptionScope = host.Services.CreateScope();
        var encryption = encryptionScope.ServiceProvider.GetRequiredService<EncryptionService>();
        using var rsa = RSA.Create(2048);
        string productName;
        await using (var seed = await database.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Product).Include(row => row.Type)
                .SingleAsync(row => row.Id == fixture.LicenseId);
            license.IsActive = outcome != "refused";
            license.Type!.Slug = "TRIAL";
            license.Product!.PrivateKeyXml = encryption.Encrypt(rsa.ToXmlString(true));
            productName = license.Product.Name;
            await seed.SaveChangesAsync();
        }
        var hardwareId = outcome == "new" ? "1234567890ABCDEF" : fixture.HardwareId;
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        using (var scope = host.Services.CreateScope())
        {
            var controller = Tkt976_CreateDirectLegacyController(scope.ServiceProvider);
            IActionResult response = automatic
                ? await controller.Activate(new ActivationController.ActivationRequest
                { LicenseKey = "FREE-TRIAL", HardwareId = hardwareId, AppName = productName, AppVersion = fixture.Version })
                : await controller.GetTrial(new ActivationController.TrialRequest
                { TypeSlug = "TRIAL", HardwareId = hardwareId, AppName = productName, AppVersion = fixture.Version });
            Assert.Equal(outcome == "refused" ? 403 : 200, Assert.IsAssignableFrom<ObjectResult>(response).StatusCode);
        }
        if (outcome == "refused") Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await database.CreateDbContextAsync();
        var history = Assert.Single(await observed.LicenseHistories.Where(row => row.License!.ProductId == fixture.ProductId
            && row.Action == "ACTIVATION_DECISION_V1").ToListAsync());
        Assert.Contains(outcome == "refused" ? "\"outcome\":\"refused\"" : "\"outcome\":\"accepted\"", history.Details!);
        Assert.Equal(hardwareId, history.DecisionSubmittedHardwareId);
        if (outcome == "new") Assert.NotEqual(fixture.LicenseId, history.LicenseId);
        else Assert.Equal(fixture.LicenseId, history.LicenseId);
    }
}
