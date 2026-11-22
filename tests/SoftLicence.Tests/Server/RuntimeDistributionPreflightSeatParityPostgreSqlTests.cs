using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>
    /// Issues a same-licence V3 entitlement and builds the matching Finalize v2 request of a fresh
    /// installation, so the preflight and finalize evaluate the exact same commercial authority.
    /// </summary>
    /// <param name="service">Production finalize service whose clock and stores issue the entitlement.</param>
    /// <param name="productId">Synthetic product.</param>
    /// <param name="licenseId">Synthetic licence.</param>
    /// <param name="version">Approved release version of the synthetic product.</param>
    /// <param name="hardwareId">Exact identifier submitted to finalize.</param>
    /// <param name="now">Fixed request clock.</param>
    /// <param name="label">Scenario label keeping digests distinct.</param>
    /// <returns>The finalize request and the raw grant reference whose digest the preflight sends.</returns>
    protected static async Task<(DistributionInstallationFinalizeRequest Request, string GrantRef)>
        Tkt1720_CreateFreshFinalizeRequestAsync(
            DistributionInstallationBindingService service,
            Guid productId,
            Guid licenseId,
            string version,
            string hardwareId,
            DateTimeOffset now,
            string label)
    {
        var grantRef = Guid.NewGuid().ToString("D");
        var entitlement = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("tkt1720-parity-issue-" + label),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = productId.ToString("D"),
                SoftLicenceLicenseId = licenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes("tkt1720-parity-subject-" + label)))
            });
        var request = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("tkt1720-parity-handoff-" + label + "-" + Guid.NewGuid().ToString("D")),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-2)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-1)),
            ProductId = productId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = hardwareId,
            AllowSameAuthorityRecovery = true,
            Release = new DistributionReleaseEvidence
            {
                Version = version,
                InstallerFilename = $"TiaConnect-Setup_v{version}.msi",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) }
            ]
        };
        return (request, grantRef);
    }

    /// <summary>Reduces one distribution operation to <c>accepted</c> or its public error code.</summary>
    /// <param name="operation">Operation returning <c>accepted</c> on success.</param>
    /// <returns>The outcome; any other exception type propagates and fails the test.</returns>
    protected static async Task<string> Tkt1720_OutcomeAsync(Func<Task<string>> operation)
    {
        try
        {
            return await operation();
        }
        catch (DistributionOperationException exception)
        {
            return exception.ErrorCode;
        }
    }
}

/// <summary>Runs the tests from RuntimeDistributionPreflightSeatParityPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeDistributionPreflightSeatParityPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// TKT-001720 parity: for each fresh-installation shape of one licence, the preflight prediction runs
    /// first and the real distribution finalize second, for the same machine, licence and entitlement.
    /// A predicted refusal must imply the finalize seat-capacity refusal, and every finalize acceptance
    /// must have been preceded by a preflight acceptance. The expected outcomes pin each shape.
    /// </summary>
    /// <param name = "scenarioName">Closed licence-shape selector.</param>
    /// <param name = "expectedPreflight">Expected preflight outcome: accepted or the public refusal code.</param>
    /// <param name = "expectedFinalize">Expected finalize outcome, or <c>any</c> when finalize owns a switch decision.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1720_Parity_PreflightSeatRefusalImpliesFinalizeSeatRefusal")]
    [InlineData("full-unknown-machine", "seat_limit_reached", "seat_limit_reached")]
    [InlineData("full-inactive-seat-of-machine", "seat_limit_reached", "seat_limit_reached")]
    [InlineData("full-machine-holds-active-seat", "accepted", "accepted")]
    [InlineData("one-free-seat", "accepted", "accepted")]
    [InlineData("full-new-activations-disabled", "accepted", "new_activations_disabled")]
    [InlineData("single-seat-licence-full", "accepted", "any")]
    public async Task Tkt1720_Parity_PreflightSeatRefusalImpliesFinalizeSeatRefusal(string scenarioName, string expectedPreflight, string expectedFinalize)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(admin, includeSeat: false);
        var machine = Tkt1720_HardwareId("parity-" + scenarioName);
        // A licence holding more active seats than its limit is not exercised: entitlement issue already
        // refuses it as entitlement_ineligible, so no finalize of a fresh installation can follow.
        var maxSeats = scenarioName == "single-seat-licence-full" ? 1 : 3;
        var otherSeats = scenarioName switch
        {
            "single-seat-licence-full" => 1,
            "one-free-seat" or "full-machine-holds-active-seat" => 2,
            _ => 3
        };
        await using (var seed = await admin.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == fixture.LicenseId);
            license.MaxSeats = maxSeats;
            if (scenarioName == "full-new-activations-disabled")
                license.Type!.DisableNewActivations = true;
            for (var index = 0; index < otherSeats; index++)
                seed.LicenseSeats.Add(Tkt1720_ActiveSeat(fixture.LicenseId, Tkt1720_HardwareId("parity-other-" + scenarioName + "-" + index)));
            if (scenarioName == "full-machine-holds-active-seat")
                seed.LicenseSeats.Add(Tkt1720_ActiveSeat(fixture.LicenseId, machine));
            if (scenarioName == "full-inactive-seat-of-machine")
            {
                var released = Tkt1720_ActiveSeat(fixture.LicenseId, machine);
                released.IsActive = false;
                released.UnlinkedAt = DateTime.UtcNow.AddHours(-1);
                seed.LicenseSeats.Add(released);
            }

            await seed.SaveChangesAsync();
        }

        var now = DateTimeOffset.UtcNow;
        var finalizeService = new DistributionInstallationBindingService(app, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var(finalizeRequest, grantRef) = await Tkt1720_CreateFreshFinalizeRequestAsync(finalizeService, fixture.ProductId, fixture.LicenseId, fixture.Version, machine, now, scenarioName);
        var preflightRequest = Tkt1720_DigestPreflightRequest(fixture.ProductId, fixture.LicenseId, grantRef, machine);
        var preflight = new RuntimeDistributionPreflightService(app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var preflightOutcome = await Tkt1720_OutcomeAsync(async () => (await preflight.EvaluateAsync("website-step1", Sha256("tkt1720-parity-preflight-" + scenarioName), preflightRequest, CancellationToken.None)).Decision);
        var finalizeOutcome = await Tkt1720_OutcomeAsync(async () =>
        {
            await finalizeService.FinalizeAsync("website-step1", Sha256("tkt1720-parity-finalize-" + scenarioName), finalizeRequest);
            return "accepted";
        });
        // The product invariant first: a predicted refusal is never a refusal finalize would not give.
        if (preflightOutcome == "seat_limit_reached")
            Assert.Equal("seat_limit_reached", finalizeOutcome);
        if (finalizeOutcome == "accepted")
            Assert.Equal("accepted", preflightOutcome);
        Assert.Equal(expectedPreflight, preflightOutcome);
        if (expectedFinalize != "any")
            Assert.Equal(expectedFinalize, finalizeOutcome);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal(preflightOutcome == "accepted" ? "accepted" : "refused", decision.Outcome);
    }
}
