using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>
    /// Builds a genuinely fresh installation request without replacement credentials or cached
    /// request identifiers. Finalize has no enrollment-key field; key possession is tested above
    /// at source discovery, and no claim about subsequent Prepare is inferred from this probe.
    /// </summary>
    /// <param name="issued">The authenticated target grant and approved release evidence.</param>
    /// <returns>A fresh, uncached same-hardware distribution request.</returns>
    protected static DistributionInstallationFinalizeRequest FreshComposedFinalizeRequest(
        DistributionInstallationFinalizeRequest issued) => new()
    {
        Schema = DistributionInstallationBindingService.FinalizeV2Schema, RequestId = Guid.NewGuid().ToString("D"),
        GrantRef = issued.GrantRef, HandoffDigestSha256 = issued.HandoffDigestSha256,
        HandoffIssuedAtUtc = FormatUtc(DateTimeOffset.UtcNow.AddSeconds(-20)),
        HandoffExpiresAtUtc = issued.HandoffExpiresAtUtc,
        DownloadCompletedAtUtc = FormatUtc(DateTimeOffset.UtcNow.AddSeconds(-10)), ProductId = issued.ProductId,
        EntitlementRef = issued.EntitlementRef, InstallationId = Guid.NewGuid().ToString("D"),
        HardwareId = issued.HardwareId, AllowSameAuthorityRecovery = true,
        Release = issued.Release, Binaries = issued.Binaries
    };

    /// <summary>
    /// Captures durable commercial, cryptographic and security state before and after a refusal.
    /// Economic history is included by the shared 1617 snapshot; refusal-only audit logs may grow.
    /// </summary>
    /// <param name="scenario">The isolated PostgreSQL scenario, never a production database.</param>
    /// <returns>An ordered exact snapshot including outstanding grants and active security barriers.</returns>
    protected static async Task<string> SnapshotComposedReinstallSecurityAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        return JsonSerializer.Serialize(new
        {
            Business = await ReadTkt1617CommercialStateAsync(db),
            Entitlements = await db.DistributionEntitlements.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
            Incidents = await db.RuntimeCriticalIncidents.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
            HardwareBans = await db.BannedHardwareIds.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
            ComponentBans = await db.BannedComponents.AsNoTracking().OrderBy(row => row.Id).ToListAsync()
        });
    }
}

/// <summary>Runs the tests from RuntimeReinstallComposedSecurityPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeReinstallComposedSecurityPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// Exercises the composed 1617/1651 server contract with an authenticated same-account grant,
    /// unchanged hardware and a different installation identifier. Open incidents and bans remain
    /// persistent barriers. An invalid signature refuses only that request and cannot establish a
    /// durable ban: a subsequent authenticated legitimate grant may authorize a new installation.
    /// This is a server-level probe, not a claim that WebSetup retries after a discovery refusal.
    /// </summary>
    /// <param name = "guard">The security boundary that must survive the new installation identifier.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617Tkt1651_FreshIdentityPreservesSecurityAndAllowsLegitimateAuthority")]
    [InlineData("invalid_proof")]
    [InlineData("incident_active")]
    [InlineData("incident_invalidated")]
    [InlineData("manual")]
    [InlineData("debugger")]
    [InlineData("piracy")]
    [InlineData("dev_canary_quarantine")]
    [InlineData("historical_null")]
    [InlineData("unknown_category")]
    [InlineData("component")]
    [InlineData("legitimate_stale_source")]
    public async Task Tkt1617Tkt1651_FreshIdentityPreservesSecurityAndAllowsLegitimateAuthority(string guard)
    {
        var hardware = Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617KnownSystemUuid).HardwareId);
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: hardware);
        await scenario.ConsumeAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        await SetScenarioHardwareAuthorityAsync(scenario, hardware);
        var(_, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var target = await CreateTkt1617TargetDistributionAsync(scenario, subjectRef, hardware, hardware, maximumSeats: 1, reuseHistoricalLicense: true);
        using var freshKey = RSA.Create(3072);
        var discovery = BuildReinstallSourceResolutionRequest(scenario);
        if (guard == "invalid_proof")
        {
            // The payload is exact; only possession of the historical enrolled key is missing.
            var payload = string.Join('\n', "distribution-reinstall-discovery-proof-v1", discovery.BootstrapId, discovery.RequestId, discovery.InstallationId, discovery.EnrollmentId, discovery.ReleaseVersion, discovery.KeyThumbprint, Convert.ToString(discovery.SecurityEpoch, CultureInfo.InvariantCulture), discovery.AttemptId, discovery.AuthoritySchema, discovery.Challenge);
            discovery.Signature = Base64Url(freshKey.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        else
        {
            await using var seed = await scenario.Factory.CreateDbContextAsync();
            var enrollment = await seed.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            if (guard.StartsWith("incident_", StringComparison.Ordinal))
            {
                seed.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident { EnrollmentId = enrollment.Id, BindingId = enrollment.BindingId, ProductId = enrollment.ProductId, InstallationId = enrollment.InstallationId, EventId = Guid.NewGuid().ToString("D"), Trigger = "RuntimeCheck_NativeDllSwapped", State = "OPEN", OpenedSecurityEpoch = enrollment.SecurityEpoch, OpenedAuthorityEpoch = enrollment.AuthorityEpoch, OpenedAtUtc = DateTime.UtcNow });
                if (guard == "incident_invalidated")
                {
                    enrollment.State = "INVALIDATED";
                    enrollment.InvalidatedAtUtc = DateTime.UtcNow;
                    enrollment.InvalidationReason = "seat_released";
                }
            }
            else if (guard == "component")
            {
                var binary = target.FinalizeRequest.Binaries!.First();
                seed.BannedComponents.Add(new BannedComponent { ProductId = enrollment.ProductId, ComponentType = binary.Key!, ComponentHash = binary.Sha256!, Reason = "composed test blocking component", IsActive = true });
            }
            else if (guard != "legitimate_stale_source")
            {
                seed.BannedHardwareIds.Add(new BannedHardwareId { ProductId = enrollment.ProductId, HardwareId = hardware, BanCategory = guard == "historical_null" ? null : guard, Reason = "composed test blocking hardware", IsActive = true });
            }

            await seed.SaveChangesAsync();
        }

        var before = await SnapshotComposedReinstallSecurityAsync(scenario);
        if (guard == "invalid_proof" || guard.StartsWith("incident_", StringComparison.Ordinal))
        {
            var discoveryRefusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ResolveReinstallSourceAuthorityAsync(target.ClientId, discovery));
            Assert.Equal(guard == "invalid_proof" ? "reinstall_signature_invalid" : "critical_incident_unresolved", discoveryRefusal.ErrorCode);
            Assert.Equal(guard == "invalid_proof" ? StatusCodes.Status403Forbidden : StatusCodes.Status423Locked, discoveryRefusal.StatusCode);
            Assert.Equal(before, await SnapshotComposedReinstallSecurityAsync(scenario));
        }

        // Omit all historical source credentials. The new installation retains the same account,
        // licence and hardware; a new key cannot confer possession of the old enrolled key.
        var fresh = FreshComposedFinalizeRequest(target.FinalizeRequest);
        await using (var validateChronology = await scenario.Factory.CreateDbContextAsync())
        {
            var source = await validateChronology.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            Assert.True(DateTime.Parse(fresh.HandoffIssuedAtUtc!, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal) > source.HandoffIssuedAtUtc);
        }

        var missing = BuildReinstallSourceResolutionRequest(scenario);
        missing.InstallationId = fresh.InstallationId;
        missing.EnrollmentId = Guid.NewGuid().ToString("D");
        missing.KeyThumbprint = Base64Url(SHA256.HashData(freshKey.ExportSubjectPublicKeyInfo()));
        var absent = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync(target.ClientId, missing);
        Assert.Equal("none", absent.Outcome);
        Assert.Equal(before, await SnapshotComposedReinstallSecurityAsync(scenario));
        var failure = await Record.ExceptionAsync(() => target.Service.FinalizeAsync(target.ClientId, Sha256(JsonSerializer.Serialize(fresh)), fresh));
        if (guard is "legitimate_stale_source" or "invalid_proof")
        {
            Assert.Null(failure);
            await using var check = await scenario.Factory.CreateDbContextAsync();
            var successor = await check.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.InstallationId == fresh.InstallationId);
            var source = await check.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            Assert.Equal(source.LicenseSeatId, successor.LicenseSeatId);
            Assert.Equal(target.LicenseId, successor.LicenseId);
            var historicalEnrollment = await check.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
            Assert.Equal(scenario.Fixture.InstallationId, historicalEnrollment.InstallationId);
            Assert.Equal(scenario.PrepareRequest.Key!.KeyThumbprint, historicalEnrollment.KeyThumbprint);
            Assert.Single(await check.LicenseSeats.Where(row => row.IsActive).ToListAsync());
            Assert.Empty(await check.LicenseHistories.Where(row => row.Action == HistoryActions.RuntimeCommercialNewIdentifier).ToListAsync());
            Assert.Empty(await check.RuntimeCriticalIncidents.ToListAsync());
            Assert.Empty(await check.BannedHardwareIds.ToListAsync());
            Assert.Empty(await check.BannedComponents.ToListAsync());
            Assert.Empty(await check.EnrollmentLicenseAssignmentQuarantines.ToListAsync());
            return;
        }

        Assert.True(failure is DistributionOperationException, $"Security guard {guard} must refuse fresh identity; observed {failure?.ToString() ?? "successful Finalize"}.");
        var refusal = Assert.IsType<DistributionOperationException>(failure);
        if (guard.StartsWith("incident_", StringComparison.Ordinal))
            Assert.Equal("replacement_source_incident", refusal.ReasonCode);
        Assert.Equal(guard == "component" ? "binary_mismatch" : guard.StartsWith("incident_", StringComparison.Ordinal) ? "binding_conflict" : "entitlement_ineligible", refusal.ErrorCode);
        Assert.Equal(before, await SnapshotComposedReinstallSecurityAsync(scenario));
    }

    /// <summary>
    /// A fresh installation is never sufficient authority by itself: the entitlement remains
    /// bound to the issuing client and exact grant. Refusal must preserve all durable business
    /// and security state, including seats, quotas, enrollment keys and outstanding grants.
    /// </summary>
    /// <param name = "mismatch">The current authenticated client or grant scope to invalidate.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617Tkt1651_FreshIdentityWrongClientOrGrantDoesNotMutateAuthority")]
    [InlineData("client")]
    [InlineData("grant")]
    public async Task Tkt1617Tkt1651_FreshIdentityWrongClientOrGrantDoesNotMutateAuthority(string mismatch)
    {
        var hardware = Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617KnownSystemUuid).HardwareId);
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: hardware);
        await scenario.ConsumeAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        await SetScenarioHardwareAuthorityAsync(scenario, hardware);
        var(_, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var target = await CreateTkt1617TargetDistributionAsync(scenario, subjectRef, hardware, hardware, maximumSeats: 1, reuseHistoricalLicense: true);
        var fresh = FreshComposedFinalizeRequest(target.FinalizeRequest);
        var client = mismatch == "client" ? "foreign-client" : target.ClientId;
        if (mismatch == "grant")
            fresh.GrantRef = Guid.NewGuid().ToString("D");
        var before = await SnapshotComposedReinstallSecurityAsync(scenario);
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => target.Service.FinalizeAsync(client, Sha256(JsonSerializer.Serialize(fresh)), fresh));
        Assert.Equal(mismatch == "grant" ? "grant_ownership_mismatch" : "entitlement_ineligible", refusal.ErrorCode);
        Assert.Equal(before, await SnapshotComposedReinstallSecurityAsync(scenario));
    }
}
