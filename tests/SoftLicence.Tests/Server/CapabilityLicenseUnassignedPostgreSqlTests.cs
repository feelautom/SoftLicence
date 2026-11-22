using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002904 anti-regression suite. A healthy installation whose seat was released by a real release path receives a
/// non-terminal 409 <c>capability_license_unassigned</c>, or takes back a seat of the same account owner already active
/// on its machine. Bans, revocation, version, exclusion and the provider release keep their terminal 422. A seat is
/// never taken, and a licence whose seats its administrator manages (Team) never moves to another licence.
/// </summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed class CapabilityLicenseUnassignedPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    private const string WebsiteClientId = "website-step1";
    private const string OtherMachineUuid = "8d2f5c1e-4b7a-4e63-9f0d-2a6c8b1e7f35";

    /// <summary>
    /// Each real release path of the client, the portal and the automatic seat switch ends the assignment with
    /// <c>seat_released</c>; the next capability is the exact non-terminal 409 and writes nothing.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_SeatReleased_Returns409LicenseUnassigned_ExactBody_EnrollmentUnchanged")]
    [InlineData("client")]
    [InlineData("admin")]
    [InlineData("auto-switch")]
    public async Task Capability_SeatReleased_Returns409LicenseUnassigned_ExactBody_EnrollmentUnchanged(string route)
    {
        using var scenario = await ActivatedScenarioAsync();
        await CapabilityAsync(scenario);
        await ReleaseAsync(scenario, route);
        var before = await SnapshotAsync(scenario);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));

        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal(RuntimeCapabilityReattachment.LicenseUnassignedError, refused.ErrorCode);
        Assert.Equal("{\"error\":\"capability_license_unassigned\"}",
            JsonSerializer.Serialize(new RuntimeEnrollmentApiError(refused.ErrorCode), new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>An excluded machine stays terminal: exclusion also releases with <c>seat_released</c>.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_ExcludedMachine_Returns422")]
    public async Task Capability_ExcludedMachine_Returns422()
    {
        using var scenario = await ActivatedScenarioAsync();
        await ReleaseAsync(scenario, "exclusion");
        await AssertHistorical422Async(scenario);
    }

    /// <summary>The provider seat release invalidates binding and enrollment: it must never become a 409.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_ProviderSeatRelease_StaysTerminal")]
    public async Task Capability_ProviderSeatRelease_StaysTerminal()
    {
        using var scenario = await ActivatedScenarioAsync();
        await ReleaseAsync(scenario, "provider");
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));
        Assert.NotEqual(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.NotEqual(RuntimeCapabilityReattachment.LicenseUnassignedError, refused.ErrorCode);
        Assert.NotEqual(RuntimeCapabilityReattachment.OtherAccountError, refused.ErrorCode);
    }

    /// <summary>A live hardware ban on the released machine keeps the historical 422.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_SeatReleased_HardwareBan_Returns422")]
    public async Task Capability_SeatReleased_HardwareBan_Returns422()
    {
        using var scenario = await ActivatedScenarioAsync();
        await ReleaseAsync(scenario, "client");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = LegacyHardwareId.ToLowerInvariant(),
                ProductId = scenario.Fixture.ProductId,
                Reason = "tkt002904-synthetic-ban",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }
        await AssertHistorical422Async(scenario);
    }

    /// <summary>A live component ban on the installed binaries keeps the historical 422.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_SeatReleased_ComponentBan_Returns422")]
    public async Task Capability_SeatReleased_ComponentBan_Returns422()
    {
        using var scenario = await ActivatedScenarioAsync();
        await ReleaseAsync(scenario, "client");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            db.BannedComponents.Add(new BannedComponent
            {
                ComponentType = "FP_EXE",
                ComponentHash = new string('e', 64),
                ProductId = scenario.Fixture.ProductId,
                Reason = "tkt002904-synthetic-component-ban",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }
        await AssertHistorical422Async(scenario);
    }

    /// <summary>A licence revoked after the release, or a version no longer admitted, keeps the historical 422.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_SeatReleased_LicenseNoLongerUsable_Returns422")]
    [InlineData("revoked")]
    [InlineData("version")]
    public async Task Capability_SeatReleased_LicenseNoLongerUsable_Returns422(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        await ReleaseAsync(scenario, "client");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var licenseId = await InstallationLicenseIdAsync(db, scenario);
            if (mutation == "revoked")
                await db.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevokedAt\" = now(), \"RevocationReason\" = 'tkt002904-synthetic' WHERE \"Id\" = {licenseId}");
            else
                await db.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE \"Licenses\" SET \"AllowedVersions\" = '9.*' WHERE \"Id\" = {licenseId}");
        }
        await AssertHistorical422Async(scenario);
    }

    /// <summary>
    /// A seat of another licence of the same account owner, already active on this machine, is reattached inside the
    /// issuing transaction. No seat is created or switched and the history records the reattachment.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_SameOwnerOtherLicense_SeatOnThisMachine_RelinksAndReturns200")]
    public async Task Capability_SameOwnerOtherLicense_SeatOnThisMachine_RelinksAndReturns200()
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, await InstallationLicenseIdAsync(scenario), owner);
        await ReleaseAsync(scenario, "client");
        var (otherLicenseId, otherSeatId) = await AddLicenseWithSeatAsync(scenario, owner, LegacyHardwareId);
        var seatCount = await SeatCountAsync(scenario);

        var issued = await CapabilityAsync(scenario);

        Assert.False(issued.Idempotent);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(otherLicenseId, active.LicenseId);
        Assert.Equal(otherSeatId, active.LicenseSeatId);
        Assert.Equal(seatCount, await SeatCountAsync(scenario));
        Assert.Single(await db.LicenseHistories.AsNoTracking()
            .Where(row => row.LicenseId == otherLicenseId && row.Action == RuntimeCapabilityReattachment.ReattachedHistoryAction)
            .ToListAsync());
    }

    /// <summary>
    /// The installation's own licence reactivated on this machine by the real activation path is reattached even
    /// without a registered account owner (review condition 1).
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_OriginalLicenseReactivated_WithoutOwner_RelinksAndReturns200")]
    public async Task Capability_OriginalLicenseReactivated_WithoutOwner_RelinksAndReturns200()
    {
        using var scenario = await ActivatedScenarioAsync();
        await RemoveOwnersAsync(scenario);
        await ReleaseAsync(scenario, "client");
        await ActivateKeyAsync(scenario, LegacyHardwareId);

        await CapabilityAsync(scenario);

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(await InstallationLicenseIdAsync(db, scenario), active.LicenseId);
    }

    /// <summary>The only seat on this machine belongs to another account owner: 409 other account, no assignment.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_OtherOwnerSeatOnThisMachine_Returns409OtherAccount_NoAssignment")]
    public async Task Capability_OtherOwnerSeatOnThisMachine_Returns409OtherAccount_NoAssignment()
    {
        using var scenario = await ActivatedScenarioAsync();
        await SetOwnerAsync(scenario, await InstallationLicenseIdAsync(scenario), Guid.NewGuid());
        await ReleaseAsync(scenario, "client");
        await AddLicenseWithSeatAsync(scenario, Guid.NewGuid(), LegacyHardwareId);
        var before = await SnapshotAsync(scenario);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));

        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal(RuntimeCapabilityReattachment.OtherAccountError, refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>
    /// A same-owner licence with free capacity but no seat on this machine is never used: no seat is created, no
    /// quota is consumed, and the answer stays the non-terminal 409.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_NoSeatOnThisMachine_NeverTakesSeat_Returns409")]
    public async Task Capability_NoSeatOnThisMachine_NeverTakesSeat_Returns409()
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, await InstallationLicenseIdAsync(scenario), owner);
        await ReleaseAsync(scenario, "client");
        await AddLicenseWithSeatAsync(scenario, owner, "C0FFEE00C0FFEE00", seatActive: false);
        var before = await SnapshotAsync(scenario);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));

        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal(RuntimeCapabilityReattachment.LicenseUnassignedError, refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>
    /// Team: the installation licence has key activation disabled and its seat was unlinked. The answer is the
    /// non-terminal 409, never a 422, and no seat is taken.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_TeamLicenseKeyActivationDisabled_SeatReleased_Returns409_NoSeatTaken")]
    public async Task Capability_TeamLicenseKeyActivationDisabled_SeatReleased_Returns409_NoSeatTaken()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetOwnerAsync(scenario, licenseId, Guid.NewGuid());
        await DisableKeyActivationAsync(scenario, licenseId);
        await ReleaseAsync(scenario, "admin");
        var before = await SnapshotAsync(scenario);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));

        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal(RuntimeCapabilityReattachment.LicenseUnassignedError, refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>
    /// Team (decision of 31/10): a personal licence of the same registry owner active on this machine must not undo
    /// the administrator's unlink. 409 non-terminal and no assignment.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_TeamInstallation_SameOwnerPersonalSeatOnThisMachine_Returns409_NoAssignment")]
    public async Task Capability_TeamInstallation_SameOwnerPersonalSeatOnThisMachine_Returns409_NoAssignment()
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetOwnerAsync(scenario, licenseId, owner);
        await DisableKeyActivationAsync(scenario, licenseId);
        await ReleaseAsync(scenario, "admin");
        await AddLicenseWithSeatAsync(scenario, owner, LegacyHardwareId);
        var before = await SnapshotAsync(scenario);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));

        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal(RuntimeCapabilityReattachment.LicenseUnassignedError, refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>A capability receipt issued before the sign out is not revived by its exact replay.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.Capability_ReplayIssuedBeforeSignOut_StaysRefused")]
    public async Task Capability_ReplayIssuedBeforeSignOut_StaysRefused()
    {
        using var scenario = await ActivatedScenarioAsync();
        var (request, digest, proof) = CapabilityRequest(scenario);
        await scenario.Runtime.CreateCapabilityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await ReleaseAsync(scenario, "client");

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.CreateCapabilityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        Assert.Equal("authority_ineligible", refused.ErrorCode);
    }

    /// <summary>
    /// The database revalidates the installation-owner proof itself: another owner, a seat of another machine, or
    /// another client is refused even when the application layer is bypassed.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.CapabilityLicenseUnassignedPostgreSqlTests.RelinkWriter_InstallationOwnerProof_IsRevalidatedInDatabase")]
    [InlineData("other-owner")]
    [InlineData("other-machine")]
    [InlineData("other-client")]
    [InlineData("team-installation")]
    public async Task RelinkWriter_InstallationOwnerProof_IsRevalidatedInDatabase(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await SetOwnerAsync(scenario, installationLicenseId, owner);
        if (mutation == "team-installation")
            await DisableKeyActivationAsync(scenario, installationLicenseId);
        await ReleaseAsync(scenario, "client");
        var (licenseId, seatId) = await AddLicenseWithSeatAsync(scenario,
            mutation == "other-owner" ? Guid.NewGuid() : owner,
            mutation == "other-machine" ? "C0FFEE00C0FFEE00" : LegacyHardwareId);

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        await using var transaction = await db.Database.BeginTransactionAsync();
        var failure = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT public.relink_runtime_commercial_assignment(
                {enrollment.Id}, {licenseId}, {seatId}, {enrollment.SubjectRefDigestSha256},
                {(mutation == "other-client" ? "another-client" : enrollment.ClientId)},
                {(Guid?)null}, {(string?)null}, {(Guid?)owner});
            """));
        Assert.Equal("runtime_commercial_relink_authority_ineligible", failure.MessageText);
    }

    /// <summary>Creates the prepared scenario, activates it on the legacy machine, and returns it.</summary>
    private static async Task<PreparedBootstrapScenario> ActivatedScenarioAsync()
    {
        var scenario = await CreatePreparedBootstrapScenarioAsync();
        try
        {
            await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var licenseId = await InstallationLicenseIdAsync(db, scenario);
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"Licenses\" SET \"MaxSeats\" = 1, \"LicenseKey\" = upper(\"LicenseKey\") WHERE \"Id\" = {licenseId}");
            return scenario;
        }
        catch
        {
            scenario.Dispose();
            throw;
        }
    }

    /// <summary>Builds one fresh signed capability request of the scenario installation.</summary>
    private static (RuntimeEnrollmentCapabilityRequest Request, string Digest, RuntimeProofHeaders Proof) CapabilityRequest(
        PreparedBootstrapScenario scenario)
    {
        var request = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var digest = Sha256("tkt002904-capability-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId, request.Audience, "-", digest);
        return (request, digest, proof);
    }

    /// <summary>Issues one fresh capability through the production service.</summary>
    private static Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>> CapabilityAsync(
        PreparedBootstrapScenario scenario)
    {
        var (request, digest, proof) = CapabilityRequest(scenario);
        return scenario.Runtime.CreateCapabilityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
    }

    /// <summary>Asserts the unchanged historical terminal 422 and that nothing was written.</summary>
    private static async Task AssertHistorical422Async(PreparedBootstrapScenario scenario)
    {
        var before = await SnapshotAsync(scenario);
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        Assert.Equal("authority_ineligible", refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>
    /// Releases the scenario seat through one real path: legacy client deactivation, portal/admin unlink, automatic
    /// seat switch by another machine, licence exclusion, or provider seat release.
    /// </summary>
    private static async Task ReleaseAsync(PreparedBootstrapScenario scenario, string route)
    {
        if (route == "exclusion")
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var licenseId = await InstallationLicenseIdAsync(db, scenario);
            var service = new LicenseHardwareExclusionService(scenario.Factory, new FixedTimeProvider(DateTimeOffset.UtcNow),
                TestHardwareAuthorityAliasResolver.Instance, NullLogger<LicenseHardwareExclusionService>.Instance);
            await service.AddAsync("tia-connect-website-exclusions", new string('a', 64),
                new LicenseHardwareExclusionRequest(LicenseHardwareExclusionService.RequestSchema,
                    Guid.NewGuid().ToString("D"), scenario.Fixture.ProductId.ToString("D"),
                    licenseId.ToString("D"), LegacyHardwareId, true));
            await AssertReleasedAsync(scenario);
            return;
        }
        if (route == "provider")
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var binding = await db.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            var now = DateTimeOffset.UtcNow;
            var distribution = new DistributionInstallationBindingService(scenario.Factory,
                new EphemeralDataProtectionProvider(), new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
            await distribution.InvalidateAsync(WebsiteClientId, Sha256("tkt002904-provider-release-" + Guid.NewGuid()),
                new DistributionInstallationInvalidationRequest
                {
                    Schema = DistributionInstallationBindingService.InvalidationSchema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = scenario.Fixture.ProductId.ToString("D"),
                    BindingId = scenario.Fixture.BindingId.ToString("D"),
                    GrantRefDigestSha256 = binding.GrantRefDigestSha256,
                    Reason = "seat_released",
                    OccurredAtUtc = FormatUtc(now),
                    Epoch = 1
                });
            return;
        }

        string licenseKey, appName;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.AsNoTracking().Include(row => row.Product)
                .SingleAsync(row => row.Id == db.DistributionInstallationBindings
                    .Where(binding => binding.Id == scenario.Fixture.BindingId).Select(binding => binding.LicenseId).Single());
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
        }
        using var baseFactory = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var web = baseFactory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AdminSettings:ApiSecret", "tkt002904-test-only");
            builder.UseSetting("AdminSettings:AllowedIps", "");
        });
        using var client = web.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt002904-test-only");
        using var response = route switch
        {
            "admin" => await client.DeleteAsync($"/api/admin/licenses/{licenseKey}/seats/{LegacyHardwareId}"),
            "auto-switch" => await client.PostAsJsonAsync("/api/activation", new
            {
                LicenseKey = licenseKey, HardwareId = MachineIdentity.FromUuid(OtherMachineUuid).HardwareId,
                AppName = appName, AppVersion = scenario.Fixture.Version, SystemUuid = OtherMachineUuid, SdkVersion = "2.0.0"
            }),
            _ => await client.PostAsJsonAsync("/api/activation/deactivate",
                new { LicenseKey = licenseKey, AppName = appName, HardwareId = LegacyHardwareId, Source = "settings_button" })
        };
        Assert.True(response.StatusCode == HttpStatusCode.OK,
            $"{response.StatusCode} {string.Join(",", response.Headers.Where(h => h.Key.StartsWith("X-SoftLicence", StringComparison.Ordinal)).SelectMany(h => h.Value))} {await response.Content.ReadAsStringAsync()}");
        await AssertReleasedAsync(scenario);
    }

    /// <summary>Reactivates the installation licence key on one machine through the real anonymous activation route.</summary>
    private static async Task ActivateKeyAsync(PreparedBootstrapScenario scenario, string hardwareId)
    {
        string licenseKey, appName;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var licenseId = await InstallationLicenseIdAsync(db, scenario);
            var license = await db.Licenses.AsNoTracking().Include(row => row.Product).SingleAsync(row => row.Id == licenseId);
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
        }
        using var web = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var client = web.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/activation",
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName = appName, AppVersion = scenario.Fixture.Version, SdkVersion = "2.0.0" });
        Assert.True(response.StatusCode == HttpStatusCode.OK,
            $"{response.StatusCode} {string.Join(",", response.Headers.Where(h => h.Key.StartsWith("X-SoftLicence", StringComparison.Ordinal)).SelectMany(h => h.Value))} {await response.Content.ReadAsStringAsync()}");
    }

    /// <summary>Proves the precondition every release path must leave: no ACTIVE assignment and a seat_released end.</summary>
    private static async Task AssertReleasedAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.False(await db.EnrollmentLicenseAssignments.AsNoTracking()
            .AnyAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE"));
        var latest = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId)
            .OrderByDescending(row => row.Revision).FirstAsync();
        Assert.Equal("seat_released", latest.EndReason);
    }

    /// <summary>Captures every row a refused capability must leave unchanged.</summary>
    private static async Task<string> SnapshotAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignments = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId)
            .OrderBy(row => row.Revision).Select(row => row.Id + ":" + row.State + ":" + row.EndReason).ToListAsync();
        var seats = await db.LicenseSeats.AsNoTracking().OrderBy(row => row.Id)
            .Select(row => row.Id + ":" + row.IsActive + ":" + row.HardwareId).ToListAsync();
        var nonces = await db.RuntimeEnrollmentProofNonces.AsNoTracking().CountAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        var histories = await db.LicenseHistories.AsNoTracking().CountAsync();
        return string.Join("|", enrollment.State, enrollment.Epoch, enrollment.SecurityEpoch, enrollment.AuthorityEpoch,
            enrollment.InvalidationReason, string.Join(",", assignments), string.Join(",", seats), nonces, histories);
    }

    /// <summary>Returns the licence of the scenario binding.</summary>
    private static async Task<Guid> InstallationLicenseIdAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        return await InstallationLicenseIdAsync(db, scenario);
    }

    /// <summary>Returns the licence of the scenario binding with a caller-owned context.</summary>
    private static Task<Guid> InstallationLicenseIdAsync(LicenseDbContext db, PreparedBootstrapScenario scenario) =>
        db.DistributionInstallationBindings.AsNoTracking()
            .Where(row => row.Id == scenario.Fixture.BindingId).Select(row => row.LicenseId).SingleAsync();

    /// <summary>Counts every seat of the scenario database.</summary>
    private static async Task<int> SeatCountAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        return await db.LicenseSeats.AsNoTracking().CountAsync();
    }

    /// <summary>Records one account owner as the active registry owner of a licence, as licence creation does.</summary>
    private static async Task SetOwnerAsync(PreparedBootstrapScenario scenario, Guid licenseId, Guid owner)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        if (!await db.RuntimeRecoveryCommercialSubjects.AnyAsync(row => row.Id == owner))
            db.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
            {
                Id = owner, ProductId = scenario.Fixture.ProductId, CreatedAtUtc = DateTime.UtcNow
            });
        foreach (var current in await db.RuntimeRecoveryCommercialOwnerships
                     .Where(row => row.LicenseId == licenseId && row.State == "ACTIVE").ToListAsync())
            db.RuntimeRecoveryCommercialOwnerships.Remove(current);
        await db.SaveChangesAsync();
        db.RuntimeRecoveryCommercialOwnerships.Add(new RuntimeRecoveryCommercialOwnership
        {
            Id = Guid.NewGuid(), ProductId = scenario.Fixture.ProductId, LicenseId = licenseId,
            OwnerSubjectId = owner, State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Removes every registry owner of the scenario licence, the shape of a licence created before the registry.</summary>
    private static async Task RemoveOwnersAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var licenseId = await InstallationLicenseIdAsync(db, scenario);
        db.RuntimeRecoveryCommercialOwnerships.RemoveRange(
            await db.RuntimeRecoveryCommercialOwnerships.Where(row => row.LicenseId == licenseId).ToListAsync());
        await db.SaveChangesAsync();
    }

    /// <summary>Disables key activation on a licence, as a Team licence is configured (TKT-002475).</summary>
    private static async Task DisableKeyActivationAsync(PreparedBootstrapScenario scenario, Guid licenseId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        db.LicenseKeyActivationSettings.Add(new LicenseKeyActivationSetting
        {
            Id = Guid.NewGuid(), ProductId = scenario.Fixture.ProductId, LicenseId = licenseId, Disabled = true,
            DisabledAtUtc = DateTime.UtcNow, DisabledByRequestId = Guid.NewGuid(), DisabledByActor = LicenseKeyActivationSettingService.S2SActor,
            DisabledByClientId = "tkt002904-test", CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Adds another licence of the scenario product owned by one account owner, with one seat on the given machine.
    /// </summary>
    private static async Task<(Guid LicenseId, Guid SeatId)> AddLicenseWithSeatAsync(
        PreparedBootstrapScenario scenario, Guid owner, string hardwareId, bool seatActive = true)
    {
        Guid licenseId;
        Guid seatId;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var source = await db.Licenses.AsNoTracking()
                .SingleAsync(row => row.Id == db.DistributionInstallationBindings
                    .Where(binding => binding.Id == scenario.Fixture.BindingId).Select(binding => binding.LicenseId).Single());
            var license = (License)db.Entry(source).CurrentValues.ToObject();
            license.Id = Guid.NewGuid();
            license.LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant();
            license.HardwareId = seatActive ? hardwareId : null;
            license.MaxSeats = 1;
            db.Licenses.Add(license);
            var seat = new LicenseSeat
            {
                LicenseId = license.Id, HardwareId = hardwareId, IsActive = seatActive,
                UnlinkedAt = seatActive ? null : DateTime.UtcNow.AddDays(-1)
            };
            db.LicenseSeats.Add(seat);
            await db.SaveChangesAsync();
            licenseId = license.Id;
            seatId = seat.Id;
        }
        await SetOwnerAsync(scenario, licenseId, owner);
        return (licenseId, seatId);
    }
}
