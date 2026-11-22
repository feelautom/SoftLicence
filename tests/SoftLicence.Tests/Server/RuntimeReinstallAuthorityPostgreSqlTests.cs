using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    protected static async Task ActivatePreparedEnrollmentAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        enrollment.State = "ACTIVE";
        enrollment.ActivatedAtUtc = DateTime.UtcNow;
        enrollment.SecurityEpoch = 1;
        await db.SaveChangesAsync();
    }

    protected static async Task<string> ConvertToLegacyV2AuthorityAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        binding.SubjectRefDigestSha256 = null;
        enrollment.SubjectRefDigestSha256 = null;
        db.DistributionEntitlements.Remove(await db.DistributionEntitlements.SingleAsync());
        db.DistributionBindingRequests.Remove(await db.DistributionBindingRequests.SingleAsync(row =>
            row.BindingId == binding.Id && row.Operation == "finalize_binding"));
        var ownership = await db.DistributionGrantOwnerships.SingleAsync(row =>
            row.ProductId == binding.ProductId && row.GrantRefDigestSha256 == binding.GrantRefDigestSha256);
        ownership.Source = "issue_v2";
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;
        await db.SaveChangesAsync();
        return binding.GrantRef;
    }

    protected static async Task<(string GrantRef, string SubjectRef)> ConfigureModernV2AuthorityAsync(
        PreparedBootstrapScenario scenario,
        string ownershipSource = "issue_v3")
    {
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var subjectDigest = Sha256(subjectRef);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.SingleAsync(row => row.Id == binding.EntitlementId);
        var ownership = await db.DistributionGrantOwnerships.SingleAsync(row =>
            row.ProductId == binding.ProductId && row.GrantRefDigestSha256 == binding.GrantRefDigestSha256);
        binding.SubjectRefDigestSha256 = subjectDigest;
        enrollment.SubjectRefDigestSha256 = subjectDigest;
        entitlement.SubjectRefDigestSha256 = subjectDigest;
        ownership.Source = ownershipSource;
        if (ownershipSource == "finalize_v1")
            db.DistributionEntitlements.Remove(entitlement);
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;
        await db.SaveChangesAsync();
        return (binding.GrantRef, subjectRef);
    }

    /// <summary>
    /// Aligns mutable Runtime ownership with an already finalized v4 entitlement while preserving
    /// every frozen entitlement authority field and its exact subject digest.
    /// </summary>
    protected static async Task<(string GrantRef, string SubjectDigest)> ConfigureModernV4AuthorityAsync(
        PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.SingleAsync(row => row.Id == binding.EntitlementId);
        var ownership = await db.DistributionGrantOwnerships.SingleAsync(row =>
            row.ProductId == binding.ProductId && row.GrantRefDigestSha256 == binding.GrantRefDigestSha256);
        Assert.Equal(4, entitlement.ContractVersion);
        Assert.Equal(binding.SubjectRefDigestSha256, entitlement.SubjectRefDigestSha256);
        enrollment.SubjectRefDigestSha256 = entitlement.SubjectRefDigestSha256;
        ownership.Source = "issue_v4";
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;
        await db.SaveChangesAsync();
        return (binding.GrantRef, Assert.IsType<string>(entitlement.SubjectRefDigestSha256));
    }

    protected static async Task<string> SnapshotReinstallAuthorityAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var entitlements = await db.DistributionEntitlements.AsNoTracking()
            .Where(row => row.Id == binding.EntitlementId)
            .OrderBy(row => row.Id)
            .Select(row => row.ClientId + ":" + row.ProductId + ":" + row.LicenseId + ":"
                + row.ContractVersion + ":" + row.State + ":" + row.SubjectRefDigestSha256 + ":"
                + row.AuthorityLineageId + ":" + row.AuthorityGenerationId + ":"
                + row.ArtifactSetDigestSha256)
            .ToListAsync();
        var ownerships = await db.DistributionGrantOwnerships.AsNoTracking()
            .Where(row => row.ProductId == binding.ProductId
                && row.GrantRefDigestSha256 == binding.GrantRefDigestSha256)
            .OrderBy(row => row.ClientId)
            .Select(row => row.ClientId + ":" + row.Source)
            .ToListAsync();
        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(row => row.BindingId == binding.Id && row.Operation == "finalize_binding")
            .OrderBy(row => row.ClientId).ThenBy(row => row.RequestId)
            .Select(row => row.ClientId + ":" + row.RequestId)
            .ToListAsync();
        var authorityGenerationRows = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .OrderBy(row => row.AuthorityLineageId).ThenBy(row => row.Sequence)
            .Select(row => new
            {
                row.AuthorityLineageId,
                row.AuthorityGenerationId,
                row.Sequence,
                row.AuthorityDigest,
                row.SignedStatementUtf8
            })
            .ToListAsync();
        var authorityGenerations = authorityGenerationRows.Select(row =>
            row.AuthorityLineageId + ":" + row.AuthorityGenerationId + ":"
            + row.Sequence + ":" + row.AuthorityDigest + ":"
            + Convert.ToBase64String(row.SignedStatementUtf8));
        return string.Join('|',
            enrollment.State, enrollment.SubjectRefDigestSha256, enrollment.AuthorityEpoch,
            binding.State, binding.SubjectRefDigestSha256, binding.GrantRefDigestSha256,
            string.Join(',', entitlements), string.Join(',', ownerships), string.Join(',', finalizeOwners),
            string.Join(',', authorityGenerations),
            (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch);
    }

    protected static async Task<string> SnapshotReinstallPayloadAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.AsNoTracking().SingleAsync(row => row.Id == binding.EntitlementId);
        return string.Join('|',
            enrollment.State, enrollment.SubjectRefDigestSha256, enrollment.AuthorityEpoch,
            binding.State, binding.SubjectRefDigestSha256, binding.GrantRefDigestSha256,
            entitlement.ClientId, entitlement.State, entitlement.SubjectRefDigestSha256);
    }

    protected static async Task AdvanceAuthorityEpochForUnrelatedProductAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        db.Products.Add(new Product
        {
            Id = Guid.NewGuid(),
            Name = "Unrelated Runtime product",
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = Guid.NewGuid().ToString("N"),
            MinimumAllowedVersion = "9.9.9"
        });
        await db.SaveChangesAsync();
    }

    protected static async Task MutateModernV2AuthorityAsync(
        PreparedBootstrapScenario scenario,
        string mutation)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.SingleAsync(row => row.Id == binding.EntitlementId);
        var ownership = await db.DistributionGrantOwnerships.SingleAsync();
        var finalize = await db.DistributionBindingRequests.SingleAsync(row =>
            row.BindingId == binding.Id && row.Operation == "finalize_binding");
        switch (mutation)
        {
            case "mixed-legacy-source":
                ownership.Source = "issue_v2";
                break;
            case "missing-entitlement":
                db.DistributionEntitlements.Remove(entitlement);
                break;
            case "missing-finalize":
                db.DistributionBindingRequests.Remove(finalize);
                break;
            case "ambiguous-finalize-owner":
                db.DistributionBindingRequests.Add(new DistributionBindingRequest
                {
                    ClientId = "other-client",
                    RequestId = Guid.NewGuid().ToString("D"),
                    Operation = "finalize_binding",
                    PayloadDigest = new string('d', 64),
                    BindingId = binding.Id,
                    ResponseJson = "{}",
                    CreatedAtUtc = DateTime.UtcNow
                });
                break;
            case "divergent-finalize-owner":
                finalize.ClientId = "other-client";
                break;
            case "case-divergent-finalize-owner":
                finalize.ClientId = "Website-step1";
                break;
            case "ownership-client":
                ownership.ClientId = "other-client";
                break;
            case "entitlement-client":
                entitlement.ClientId = "other-client";
                break;
            case "entitlement-product":
                var otherProduct = new Product
                {
                    Id = Guid.NewGuid(),
                    Name = "Divergent Runtime product",
                    PrivateKeyXml = string.Empty,
                    PublicKeyXml = string.Empty,
                    ApiSecret = Guid.NewGuid().ToString("N")
                };
                db.Products.Add(otherProduct);
                entitlement.ProductId = otherProduct.Id;
                break;
            case "entitlement-subject":
                entitlement.SubjectRefDigestSha256 = Sha256("another-subject");
                break;
            case "partial-subject":
                enrollment.SubjectRefDigestSha256 = null;
                break;
            default:
                throw new InvalidOperationException("Unknown mutation: " + mutation);
        }
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Adds bounded historical finalization requests for a single exact owner so the
    /// PostgreSQL regression exercises physical row multiplicity independently of ownership.
    /// </summary>
    /// <param name="scenario">Isolated PostgreSQL Runtime Enrollment scenario.</param>
    /// <param name="clientId">Exact owner value to persist without normalization.</param>
    /// <param name="count">Number of additional physical request rows.</param>
    protected static async Task AddFinalizeRequestsAsync(
        PreparedBootstrapScenario scenario,
        string clientId,
        int count)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        for (var index = 0; index < count; index++)
        {
            db.DistributionBindingRequests.Add(new DistributionBindingRequest
            {
                ClientId = clientId,
                RequestId = Guid.NewGuid().ToString("D"),
                Operation = "finalize_binding",
                PayloadDigest = new string((char)('a' + index), 64),
                BindingId = scenario.Fixture.BindingId,
                ResponseJson = "{}",
                CreatedAtUtc = DateTime.UtcNow.AddSeconds(index + 1)
            });
        }
        await db.SaveChangesAsync();
    }

    protected static RuntimeReinstallAuthorityRequest BuildReinstallAuthorityRequest(
        PreparedBootstrapScenario scenario)
    {
        var requestId = Guid.NewGuid().ToString("D");
        var bootstrapId = Guid.NewGuid().ToString("D");
        var challenge = Base64Url(RandomNumberGenerator.GetBytes(64));
        var thumbprint = scenario.PrepareRequest.Key!.KeyThumbprint!;
        var payload = string.Join('\n',
            "distribution-reinstall-proof-v1",
            bootstrapId,
            requestId,
            scenario.Fixture.InstallationId,
            scenario.EnrollmentId.ToString("D"),
            scenario.Fixture.Version,
            thumbprint,
            1.ToString(CultureInfo.InvariantCulture),
            challenge);
        return new RuntimeReinstallAuthorityRequest
        {
            Schema = RuntimeEnrollmentService.ReinstallAuthoritySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = requestId,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BootstrapId = bootstrapId,
            InstallationId = scenario.Fixture.InstallationId,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ReleaseVersion = scenario.Fixture.Version,
            KeyThumbprint = thumbprint,
            SecurityEpoch = 1,
            Challenge = challenge,
            Signature = Base64Url(scenario.EnrollmentKey.SignData(
                Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        };
    }

    protected static RuntimeReinstallSourceResolutionRequest BuildReinstallSourceResolutionRequest(
        PreparedBootstrapScenario scenario)
    {
        var requestId = Guid.NewGuid().ToString("D");
        var bootstrapId = Guid.NewGuid().ToString("D");
        var attemptId = Guid.NewGuid().ToString("D");
        var challenge = Base64Url(RandomNumberGenerator.GetBytes(64));
        var thumbprint = scenario.PrepareRequest.Key!.KeyThumbprint!;
        var payload = string.Join('\n',
            "distribution-reinstall-discovery-proof-v1",
            bootstrapId,
            requestId,
            scenario.Fixture.InstallationId,
            scenario.EnrollmentId.ToString("D"),
            scenario.Fixture.Version,
            thumbprint,
            1.ToString(CultureInfo.InvariantCulture),
            attemptId,
            RuntimeEnrollmentService.ReinstallDiscoveryAuthoritySchema,
            challenge);
        return new RuntimeReinstallSourceResolutionRequest
        {
            Schema = RuntimeEnrollmentService.ReinstallSourceResolutionSchema,
            RequestId = requestId,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BootstrapId = bootstrapId,
            InstallationId = scenario.Fixture.InstallationId,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ReleaseVersion = scenario.Fixture.Version,
            KeyThumbprint = thumbprint,
            SecurityEpoch = 1,
            AttemptId = attemptId,
            AuthoritySchema = RuntimeEnrollmentService.ReinstallDiscoveryAuthoritySchema,
            Challenge = challenge,
            Signature = Base64Url(scenario.EnrollmentKey.SignData(
                Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        };
    }

    protected static RuntimeReinstallAuthorityRequest BuildReinstallAuthorityRequest(
        PreparedBootstrapScenario scenario,
        string grantRef,
        string subjectRef)
    {
        var requestId = Guid.NewGuid().ToString("D");
        var bootstrapId = Guid.NewGuid().ToString("D");
        var challenge = Base64Url(RandomNumberGenerator.GetBytes(64));
        var thumbprint = scenario.PrepareRequest.Key!.KeyThumbprint!;
        var payload = string.Join('\n',
            "distribution-reinstall-proof-v2",
            bootstrapId,
            requestId,
            scenario.Fixture.InstallationId,
            scenario.EnrollmentId.ToString("D"),
            scenario.Fixture.Version,
            thumbprint,
            1.ToString(CultureInfo.InvariantCulture),
            grantRef,
            subjectRef,
            challenge);
        return new RuntimeReinstallAuthorityRequest
        {
            Schema = RuntimeEnrollmentService.ReinstallAuthorityV2Schema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = requestId,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BootstrapId = bootstrapId,
            InstallationId = scenario.Fixture.InstallationId,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ReleaseVersion = scenario.Fixture.Version,
            KeyThumbprint = thumbprint,
            SecurityEpoch = 1,
            GrantRef = grantRef,
            SubjectRef = subjectRef,
            Challenge = challenge,
            Signature = Base64Url(scenario.EnrollmentKey.SignData(
                Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        };
    }
}

/// <summary>Runs the tests from RuntimeReinstallAuthorityPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeReinstallAuthorityPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_ReconcilesMissingDigestsAndIsIdempotent")]
    public async Task ReinstallAuthority_LegacyV2_ReconcilesMissingDigestsAndIsIdempotent()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        var firstRequest = BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef);
        var first = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", firstRequest);
        var secondRequest = BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef);
        var second = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", secondRequest);
        var expectedDigest = Sha256(subjectRef);
        Assert.Equal(expectedDigest, first.SubjectRefDigestSha256);
        Assert.Equal(expectedDigest, second.SubjectRefDigestSha256);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(expectedDigest, (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(expectedDigest, (await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
        Assert.Empty(await check.DistributionEntitlements.ToListAsync());
        Assert.Empty(await check.DistributionBindingRequests.Where(row => row.Operation == "finalize_binding").ToListAsync());
        Assert.Equal("issue_v2", (await check.DistributionGrantOwnerships.SingleAsync()).Source);
    }

    /// <summary>
    /// Proves reconciled legacy authorization remains historical identity evidence after a product version-policy
    /// change. Since TKT-004062 the legacy discovery still requires current commerce but no longer judges the source
    /// release, which the reinstallation replaces: a source below the product minimum stays discoverable, and the
    /// target release is judged later by Finalize or the transition.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_VersionBelowMinimumKeepsIdentityAndDiscovery")]
    public async Task ReinstallAuthority_LegacyV2_VersionBelowMinimumKeepsIdentityAndDiscovery()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        var request = BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef);
        await scenario.Runtime.AuthorizeReinstallAsync("website-step1", request);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var product = await db.Products.SingleAsync(candidate => candidate.Id == scenario.Fixture.ProductId);
            product.MinimumAllowedVersion = "9.9.9";
            await db.SaveChangesAsync();
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var identity = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", request);
        var discovery = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        Assert.Equal("identity_confirmed", identity.Decision);
        Assert.Equal("source", discovery.Outcome);
        Assert.Equal("legacy", discovery.SourceKind);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_ConcurrentIdenticalRequestsConverge")]
    public async Task ReinstallAuthority_LegacyV2_ConcurrentIdenticalRequestsConverge()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        var responses = await Task.WhenAll(scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)), scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));
        var expectedDigest = Sha256(subjectRef);
        Assert.All(responses, response => Assert.Equal(expectedDigest, response.SubjectRefDigestSha256));
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(expectedDigest, (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(expectedDigest, (await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernV2_CompleteAuthorityIsAcceptedWithoutMutation")]
    public async Task ReinstallAuthority_ModernV2_CompleteAuthorityIsAcceptedWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    /// <summary>
    /// Historical modern source identity remains available after the old licence and its
    /// assignment lose current eligibility. Neither signed Runtime endpoint waits on the
    /// commercial barrier or treats the changed same-seat hardware as crypto identity.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallModernIdentity_CommercialBarrierAndInactiveSource_DoNotBlockOrGrant")]
    public async Task ReinstallModernIdentity_CommercialBarrierAndInactiveSource_DoNotBlockOrGrant()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await using (var revoke = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await revoke.Licenses.SingleAsync();
            license.IsActive = false;
            var seat = await revoke.LicenseSeats.SingleAsync();
            seat.HardwareId = "reinstall-current-seat-" + Guid.NewGuid().ToString("N");
            await revoke.SaveChangesAsync();
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand("SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", writer, transaction))
            await hold.ExecuteNonQueryAsync();
        try
        {
            var authorized = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)).WaitAsync(TimeSpan.FromSeconds(8));
            var discovered = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario)).WaitAsync(TimeSpan.FromSeconds(8));
            Assert.Equal("identity_confirmed", authorized.Decision);
            Assert.Equal("source", discovered.Outcome);
            Assert.Equal("modern", discovered.SourceKind);
            Assert.Equal(authorized.SoftLicenceLicenseId, discovered.SourceLicenseId);
            Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
            await using var verify = await scenario.Factory.CreateDbContextAsync();
            Assert.Empty(await verify.EnrollmentLicenseAssignments.Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());
        }
        finally
        {
            await transaction.RollbackAsync();
        }
    }

    /// <summary>
    /// Reconciled legacy source discovery waits for the commercial writer, whereas its
    /// identity-only authorization remains read-only after the source later loses B.
    /// The fallback never revives the terminated assignment.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallLegacyDiscovery_CommercialBarrierSerializesAndDenialReturnsNone")]
    public async Task ReinstallLegacyDiscovery_CommercialBarrierSerializesAndDenialReturnsNone()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        var incompleteBefore = await SnapshotReinstallAuthorityAsync(scenario);
        var incomplete = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        Assert.Equal("source", incomplete.Outcome);
        Assert.Equal("legacy", incomplete.SourceKind);
        Assert.Equal(incompleteBefore, await SnapshotReinstallAuthorityAsync(scenario));
        await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand("SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", writer, transaction))
            await hold.ExecuteNonQueryAsync();
        var pending = scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
        await observer.OpenAsync();
        var observedWait = false;
        for (var poll = 0; poll < 200 && !observedWait; poll++)
        {
            await using var activity = new NpgsqlCommand("""
                SELECT count(*) FROM pg_catalog.pg_stat_activity
                WHERE datname = pg_catalog.current_database()
                  AND pid <> pg_catalog.pg_backend_pid()
                  AND query LIKE '%pg_advisory_xact_lock_shared(1312, 1)%'
                  AND wait_event_type = 'Lock'
                  AND pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0;
                """, observer);
            observedWait = Convert.ToInt64(await activity.ExecuteScalarAsync()) > 0;
            if (!observedWait)
                await Task.Delay(10);
        }

        Assert.True(observedWait);
        Assert.False(pending.IsCompleted);
        await transaction.CommitAsync();
        var source = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("source", source.Outcome);
        Assert.Equal("legacy", source.SourceKind);
        Assert.Null(source.Authority);
        await using (var revoke = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await revoke.Licenses.SingleAsync();
            license.IsActive = false;
            await revoke.SaveChangesAsync();
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var denied = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        var identity = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal("none", denied.Outcome);
        Assert.Equal("identity_confirmed", identity.Decision);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await verify.EnrollmentLicenseAssignments.Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// A corrupt active assignment relation is unavailable infrastructure, not a bounded
    /// discovery miss. The historical source credential still proves identity separately.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallLegacyDiscovery_MissingAssignmentSeat_PropagatesUnavailable")]
    public async Task ReinstallLegacyDiscovery_MissingAssignmentSeat_PropagatesUnavailable()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var dropConstraint = new NpgsqlCommand("""
                DO $broken_relation$
                DECLARE constraint_name name;
                BEGIN
                    SELECT conname INTO constraint_name FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public."EnrollmentLicenseAssignments"'::pg_catalog.regclass
                      AND conname LIKE 'FK_EnrollmentLicenseAssignments_LicenseSeats%';
                    EXECUTE pg_catalog.format(
                        'ALTER TABLE public."EnrollmentLicenseAssignments" DROP CONSTRAINT %I',
                        constraint_name);
                END;
                $broken_relation$;
                """, admin);
            await dropConstraint.ExecuteNonQueryAsync();
            await using var breakRelation = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            breakRelation.Parameters.AddWithValue("missing", Guid.NewGuid());
            breakRelation.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            await breakRelation.ExecuteNonQueryAsync();
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var unavailable = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario)));
        var identity = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("authority_unavailable", unavailable.ErrorCode);
        Assert.Equal("assignment_relation_missing", unavailable.DiagnosticCode);
        Assert.Equal("identity_confirmed", identity.Decision);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallSourceResolution_ModernAuthority_VerifiesDiscoveryProofWithoutMutation")]
    public async Task ReinstallSourceResolution_ModernAuthority_VerifiesDiscoveryProofWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var response = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        await using var authorityCheck = await scenario.Factory.CreateDbContextAsync();
        var sourceLicenseId = (await authorityCheck.RuntimeEnrollments.AsNoTracking().SingleAsync()).LicenseId;
        Assert.Equal(RuntimeEnrollmentService.ReinstallSourceResolutionResponseSchema, response.Schema);
        Assert.Equal("source", response.Outcome);
        Assert.Equal("modern", response.SourceKind);
        Assert.Equal(grantRef, response.GrantRef);
        Assert.Equal(scenario.Fixture.BindingId.ToString("D"), response.BindingId);
        Assert.Equal(sourceLicenseId.ToString("D"), response.SourceLicenseId);
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Null(response.Authority);
        var v1Json = JsonSerializer.SerializeToElement(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal(["bindingId", "grantRef", "outcome", "requestId", "schema", "sourceKind", "sourceLicenseId", "subjectRefDigestSha256"], v1Json.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
        var v2Request = BuildReinstallSourceResolutionRequest(scenario);
        v2Request.Schema = RuntimeEnrollmentService.ReinstallSourceResolutionV2Schema;
        var v2Response = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", v2Request);
        Assert.Equal(RuntimeEnrollmentService.ReinstallSourceResolutionV2ResponseSchema, v2Response.Schema);
        Assert.Equal("source", v2Response.Outcome);
        Assert.Null(v2Response.Authority);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    /// <summary>
    /// Proves the negotiated v2 resolver returns the exact entitlement-linked provider statement
    /// without changing the Runtime, binding, entitlement, lineage, or generation state.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallSourceResolution_V2V4_ReturnsExactProviderAuthorityWithoutMutation")]
    public async Task ReinstallSourceResolution_V2V4_ReturnsExactProviderAuthorityWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync(useAuthorityGeneration: true);
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectDigest) = await ConfigureModernV4AuthorityAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var request = BuildReinstallSourceResolutionRequest(scenario);
        request.Schema = RuntimeEnrollmentService.ReinstallSourceResolutionV2Schema;
        Guid lineageId;
        Guid generationId;
        byte[] signedStatement;
        await using (var authorityDb = await scenario.Factory.CreateDbContextAsync())
        {
            var entitlement = await authorityDb.DistributionEntitlements.AsNoTracking().SingleAsync();
            lineageId = Assert.IsType<Guid>(entitlement.AuthorityLineageId);
            generationId = Assert.IsType<Guid>(entitlement.AuthorityGenerationId);
            signedStatement = await authorityDb.RuntimeEnrollmentAuthorityGenerations.AsNoTracking().Where(row => row.AuthorityLineageId == lineageId && row.AuthorityGenerationId == generationId).Select(row => row.SignedStatementUtf8).SingleAsync();
        }

        var response = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", request);
        Assert.Equal(RuntimeEnrollmentService.ReinstallSourceResolutionV2ResponseSchema, response.Schema);
        Assert.Equal("source", response.Outcome);
        Assert.Equal("modern", response.SourceKind);
        Assert.Equal(grantRef, response.GrantRef);
        Assert.Equal(subjectDigest, response.SubjectRefDigestSha256);
        var authority = Assert.IsType<RuntimeReinstallSourceAuthorityProvenance>(response.Authority);
        Assert.Equal(lineageId.ToString("D"), authority.AuthorityLineageId);
        Assert.Equal(generationId.ToString("D"), authority.AuthorityGenerationId);
        Assert.Equal(Base64Url(signedStatement), authority.SignedStatementBase64Url);
        var v2Json = JsonSerializer.SerializeToElement(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal(["authority", "bindingId", "grantRef", "outcome", "requestId", "schema", "sourceKind", "sourceLicenseId", "subjectRefDigestSha256"], v2Json.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(["authorityGenerationId", "authorityLineageId", "signedStatementBase64Url"], v2Json.GetProperty("authority").EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    /// <summary>
    /// TKT-001651: an invalid discovery proof is a security refusal. WebSetup restarts as a fresh
    /// installation on "none", so this refusal must stay distinct and must change nothing.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallSourceResolution_InvalidProof_IsRefusedNotReportedAsMissingSource")]
    public async Task ReinstallSourceResolution_InvalidProof_IsRefusedNotReportedAsMissingSource()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        await ConfigureModernV2AuthorityAsync(scenario);
        var request = BuildReinstallSourceResolutionRequest(scenario);
        request.Signature = Base64Url(RandomNumberGenerator.GetBytes(384));
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", request));
        Assert.Equal(StatusCodes.Status403Forbidden, refused.StatusCode);
        Assert.Equal("reinstall_signature_invalid", refused.ErrorCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    /// <summary>
    /// TKT-001651: an open critical incident is attached to this installation. Reporting it as
    /// "none" would let a fresh installation leave the incident behind, so it is refused as such,
    /// and the same request resolves again once the incident is closed.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallSourceResolution_OpenCriticalIncident_IsRefusedNotReportedAsMissingSource")]
    public async Task ReinstallSourceResolution_OpenCriticalIncident_IsRefusedNotReportedAsMissingSource()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        await ConfigureModernV2AuthorityAsync(scenario);
        Guid incidentId;
        await using (var open = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await open.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            var incident = new RuntimeCriticalIncident
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = enrollment.SecurityEpoch,
                OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
                OpenedAtUtc = DateTime.UtcNow
            };
            open.RuntimeCriticalIncidents.Add(incident);
            await open.SaveChangesAsync();
            incidentId = incident.Id;
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario)));
        Assert.Equal(StatusCodes.Status423Locked, refused.StatusCode);
        Assert.Equal("critical_incident_unresolved", refused.ErrorCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
        // The application role may open an incident but never remove one; only the test
        // administrator clears it, to prove the refusal was caused by the incident alone.
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var remove = new NpgsqlCommand("""DELETE FROM public."RuntimeCriticalIncidents" WHERE "Id" = @incident;""", admin);
            remove.Parameters.AddWithValue("incident", incidentId);
            Assert.Equal(1, await remove.ExecuteNonQueryAsync());
        }

        var resolved = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        Assert.Equal("source", resolved.Outcome);
    }

    /// <summary>
    /// TKT-001651: releasing a seat invalidates the enrollment. An invalidated enrollment answers
    /// "none", so the open incident of that same installation must be refused first; once the
    /// incident is gone, the invalidated enrollment is again a plain missing source.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallSourceResolution_OpenCriticalIncidentOnInvalidatedEnrollment_IsRefusedBeforeMissingSource")]
    public async Task ReinstallSourceResolution_OpenCriticalIncidentOnInvalidatedEnrollment_IsRefusedBeforeMissingSource()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        await ConfigureModernV2AuthorityAsync(scenario);
        Guid incidentId;
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await seed.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            var incident = new RuntimeCriticalIncident
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = enrollment.SecurityEpoch,
                OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
                OpenedAtUtc = DateTime.UtcNow
            };
            seed.RuntimeCriticalIncidents.Add(incident);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "seat_released";
            await seed.SaveChangesAsync();
            incidentId = incident.Id;
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario)));
        Assert.Equal(StatusCodes.Status423Locked, refused.StatusCode);
        Assert.Equal("critical_incident_unresolved", refused.ErrorCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
        // Another installation identifier must not learn anything about this enrollment.
        var foreignInstallation = BuildReinstallSourceResolutionRequest(scenario);
        foreignInstallation.InstallationId = Guid.NewGuid().ToString("D");
        var foreign = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", foreignInstallation);
        Assert.Equal("none", foreign.Outcome);
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var remove = new NpgsqlCommand("""DELETE FROM public."RuntimeCriticalIncidents" WHERE "Id" = @incident;""", admin);
            remove.Parameters.AddWithValue("incident", incidentId);
            Assert.Equal(1, await remove.ExecuteNonQueryAsync());
        }

        var inactive = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", BuildReinstallSourceResolutionRequest(scenario));
        Assert.Equal("none", inactive.Outcome);
        Assert.Null(inactive.SourceLicenseId);
        Assert.Null(inactive.GrantRef);
    }

    /// <summary>
    /// TKT-001651: an installation the server no longer recognizes stays a plain missing source,
    /// the only outcome WebSetup answers by starting again as a fresh installation.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallSourceResolution_InactiveOrUnknownEnrollment_StaysBoundedNone")]
    public async Task ReinstallSourceResolution_InactiveOrUnknownEnrollment_StaysBoundedNone()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        await ConfigureModernV2AuthorityAsync(scenario);
        var unknownRequest = BuildReinstallSourceResolutionRequest(scenario);
        unknownRequest.EnrollmentId = Guid.NewGuid().ToString("D");
        var unknown = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", unknownRequest);
        Assert.Equal("none", unknown.Outcome);
        var staleRequest = BuildReinstallSourceResolutionRequest(scenario);
        staleRequest.SecurityEpoch = staleRequest.SecurityEpoch + 1;
        var stale = await scenario.Runtime.ResolveReinstallSourceAuthorityAsync("website-step1", staleRequest);
        Assert.Equal("none", stale.Outcome);
        Assert.Null(stale.SourceLicenseId);
        Assert.Null(stale.GrantRef);
        Assert.Null(stale.BindingId);
        Assert.Null(stale.SubjectRefDigestSha256);
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernV2_RepeatedFinalizeRequestsFromSameOwnerAreAcceptedWithoutMutation")]
    public async Task ReinstallAuthority_ModernV2_RepeatedFinalizeRequestsFromSameOwnerAreAcceptedWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await AddFinalizeRequestsAsync(scenario, "website-step1", 3);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernFinalizeV1_CompleteAuthorityIsAcceptedWithoutMutation")]
    public async Task ReinstallAuthority_ModernFinalizeV1_CompleteAuthorityIsAcceptedWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario, "finalize_v1");
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernV2_UnrelatedProductMutationDoesNotMakeAuthorityIneligible")]
    public async Task ReinstallAuthority_ModernV2_UnrelatedProductMutationDoesNotMakeAuthorityIneligible()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        long enrollmentEpoch;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentEpoch = (await db.RuntimeEnrollments.AsNoTracking().SingleAsync()).AuthorityEpoch;
            db.Products.Add(new Product { Id = Guid.NewGuid(), Name = "Unrelated Runtime product", PrivateKeyXml = string.Empty, PublicKeyXml = string.Empty, ApiSecret = Guid.NewGuid().ToString("N"), MinimumAllowedVersion = "9.9.9" });
            await db.SaveChangesAsync();
            Assert.True((await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch > enrollmentEpoch);
        }

        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_ReconciledReplayIgnoresUnrelatedAuthorityEpochAdvance")]
    public async Task ReinstallAuthority_LegacyV2_ReconciledReplayIgnoresUnrelatedAuthorityEpochAdvance()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        await AdvanceAuthorityEpochForUnrelatedProductAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_IncompleteAuthorityStillRequiresCurrentEpochForReconciliation")]
    public async Task ReinstallAuthority_LegacyV2_IncompleteAuthorityStillRequiresCurrentEpochForReconciliation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await AdvanceAuthorityEpochForUnrelatedProductAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernV2_DivergentAuthorityFailsWithoutMutation")]
    [InlineData("mixed-legacy-source")]
    [InlineData("missing-entitlement")]
    [InlineData("missing-finalize")]
    [InlineData("divergent-finalize-owner")]
    [InlineData("case-divergent-finalize-owner")]
    [InlineData("ambiguous-finalize-owner")]
    [InlineData("ownership-client")]
    [InlineData("entitlement-client")]
    [InlineData("entitlement-product")]
    [InlineData("entitlement-subject")]
    [InlineData("partial-subject")]
    public async Task ReinstallAuthority_ModernV2_DivergentAuthorityFailsWithoutMutation(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await MutateModernV2AuthorityAsync(scenario, mutation);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));
        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        Assert.Equal(mutation switch
        {
            "missing-finalize" => "v2_finalize_owner_missing",
            "divergent-finalize-owner" or "case-divergent-finalize-owner" or "ambiguous-finalize-owner" => "v2_finalize_owner_mismatch",
            _ => "v2_authority_invariant_mismatch"
        }, error.DiagnosticCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernV2_ConcurrentIdenticalRequestsRemainReadOnly")]
    public async Task ReinstallAuthority_ModernV2_ConcurrentIdenticalRequestsRemainReadOnly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var repeatedRequest = BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef);
        var responses = await Task.WhenAll(scenario.Runtime.AuthorizeReinstallAsync("website-step1", repeatedRequest), scenario.Runtime.AuthorizeReinstallAsync("website-step1", repeatedRequest));
        Assert.All(responses, response =>
        {
            Assert.Equal("identity_confirmed", response.Decision);
            Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        });
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    /// <summary>
    /// Proves an exact replay of the legacy v1 request can only reproduce non-authorizing identity
    /// evidence and cannot mutate the protected Runtime authority graph.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthorityV1_ConcurrentExactReplayRemainsNonAuthorizingAndReadOnly")]
    public async Task ReinstallAuthorityV1_ConcurrentExactReplayRemainsNonAuthorizingAndReadOnly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var repeatedRequest = BuildReinstallAuthorityRequest(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);
        var responses = await Task.WhenAll(scenario.Runtime.AuthorizeReinstallAsync("website-step1", repeatedRequest), scenario.Runtime.AuthorizeReinstallAsync("website-step1", repeatedRequest));
        Assert.All(responses, response => Assert.Equal("identity_confirmed", response.Decision));
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_ModernV2_ConcurrentProtectedDivergenceIsRevalidatedWithoutEndpointMutation")]
    public async Task ReinstallAuthority_ModernV2_ConcurrentProtectedDivergenceIsRevalidatedWithoutEndpointMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var protectedStateBefore = await SnapshotReinstallPayloadAsync(scenario);
        await using var writer = await scenario.Factory.CreateDbContextAsync();
        await using var transaction = await writer.Database.BeginTransactionAsync();
        var ownership = await writer.DistributionGrantOwnerships.SingleAsync();
        ownership.ClientId = "other-client";
        await writer.SaveChangesAsync();
        var authorization = scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        await Task.Delay(100);
        Assert.False(authorization.IsCompleted);
        await transaction.CommitAsync();
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => authorization);
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        Assert.Equal(protectedStateBefore, await SnapshotReinstallPayloadAsync(scenario));
    }

    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_InvalidAuthorityDoesNotMutate")]
    [InlineData("signature")]
    [InlineData("grant")]
    [InlineData("ownership")]
    [InlineData("partial-digest")]
    [InlineData("grant-digest")]
    [InlineData("binding-inactive")]
    [InlineData("enrollment-inactive")]
    [InlineData("license-inactive")]
    [InlineData("seat-inactive")]
    public async Task ReinstallAuthority_LegacyV2_InvalidAuthorityDoesNotMutate(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        var request = BuildReinstallAuthorityRequest(scenario, mutation == "grant" ? Guid.NewGuid().ToString("D") : grantRef, subjectRef);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            if (mutation == "ownership")
                db.DistributionGrantOwnerships.Remove(await db.DistributionGrantOwnerships.SingleAsync());
            else if (mutation == "partial-digest")
                (await db.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256 = Sha256(subjectRef);
            else if (mutation == "grant-digest")
                (await db.DistributionInstallationBindings.SingleAsync()).GrantRefDigestSha256 = Sha256("another-grant");
            else if (mutation == "binding-inactive")
            {
                var binding = await db.DistributionInstallationBindings.SingleAsync();
                binding.State = "invalidated";
                binding.InvalidatedAtUtc = DateTime.UtcNow;
                binding.InvalidationReason = "test_revocation";
            }
            else if (mutation == "enrollment-inactive")
            {
                var enrollment = await db.RuntimeEnrollments.SingleAsync();
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = DateTime.UtcNow;
                enrollment.InvalidationReason = "test_authority_change";
            }
            else if (mutation == "license-inactive")
                (await db.Licenses.SingleAsync()).IsActive = false;
            else if (mutation == "seat-inactive")
                (await db.LicenseSeats.SingleAsync()).IsActive = false;
            if (mutation is not ("signature" or "grant"))
            {
                await db.SaveChangesAsync();
                var enrollment = await db.RuntimeEnrollments.SingleAsync();
                enrollment.AuthorityEpoch = (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;
                await db.SaveChangesAsync();
            }
        }

        if (mutation == "signature")
            request.Signature = Base64Url(RandomNumberGenerator.GetBytes(384));
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.AuthorizeReinstallAsync("website-step1", request));
        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        Assert.Equal(mutation == "signature" ? "reinstall_signature_invalid" : "reinstall_authority_ineligible", error.ErrorCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Null((await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(mutation == "partial-digest" ? Sha256(subjectRef) : null, (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_LegacyV2_DivergentIdempotentSubjectFailsClosed")]
    public async Task ReinstallAuthority_LegacyV2_DivergentIdempotentSubjectFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var originalSubjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, originalSubjectRef));
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.AuthorizeReinstallAsync("website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, Base64Url(RandomNumberGenerator.GetBytes(32)))));
        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        var expectedDigest = Sha256(originalSubjectRef);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(expectedDigest, (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(expectedDigest, (await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_CurrentActiveBinding_ReturnsMinimalAssertion")]
    public async Task ReinstallAuthority_CurrentActiveBinding_ReturnsMinimalAssertion()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var request = BuildReinstallAuthorityRequest(scenario);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", request);
        Assert.Equal(RuntimeEnrollmentService.ReinstallAuthorityResponseSchema, response.Schema);
        Assert.Equal("identity_confirmed", response.Decision);
        Assert.Equal(request.BootstrapId, response.CorrelationId);
        Assert.Equal(request.EnrollmentId, response.EnrollmentId);
        Assert.Equal(request.InstallationId, response.InstallationId);
        Assert.Equal(request.ReleaseVersion, response.ReleaseVersion);
        Assert.Equal(request.KeyThumbprint, response.KeyThumbprint);
        Assert.Equal(request.SecurityEpoch, response.SecurityEpoch);
        Assert.Matches("^[0-9a-f]{64}$", response.SubjectRefDigestSha256);
        Assert.Matches("^[0-9a-f-]{36}$", response.GrantRef);
    }

    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthorityV2_ExpiredLicense_ConfirmsIdentityWithoutGrantingLicenseAuthority")]
    public async Task ReinstallAuthorityV2_ExpiredLicense_ConfirmsIdentityWithoutGrantingLicenseAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            var license = await db.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        var request = BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", request);
        Assert.Equal("identity_confirmed", response.Decision);
        Assert.Equal(scenario.Fixture.BindingId.ToString("D"), response.BindingId);
        Assert.Equal(grantRef, response.GrantRef);
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
    }

    /// <summary>
    /// Proves each independent version policy confirms identity without granting reinstall authority.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthorityV2_IneligibleVersion_ConfirmsIdentityWithoutReinstallAuthority")]
    [InlineData("allowed_versions")]
    [InlineData("minimum_version")]
    public async Task ReinstallAuthorityV2_IneligibleVersion_ConfirmsIdentityWithoutReinstallAuthority(string policy)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var(grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            var license = await db.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            if (policy == "allowed_versions")
            {
                license.AllowedVersions = "9.*";
            }
            else if (policy == "minimum_version")
            {
                var product = await db.Products.SingleAsync(row => row.Id == license.ProductId);
                product.MinimumAllowedVersion = "9.9.9";
            }
            else
            {
                throw new InvalidOperationException("Unknown version-policy fixture.");
            }

            await db.SaveChangesAsync();
        }

        var request = BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef);
        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", request);
        Assert.Equal("identity_confirmed", response.Decision);
        Assert.Equal(request.ReleaseVersion, response.ReleaseVersion);
        Assert.Equal(scenario.Fixture.BindingId.ToString("D"), response.BindingId);
        Assert.Equal(grantRef, response.GrantRef);
        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
    }

    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.ReinstallAuthority_InvalidProofOrStaleAuthority_IsFailClosed")]
    [InlineData("signature")]
    [InlineData("installation")]
    [InlineData("binding")]
    public async Task ReinstallAuthority_InvalidProofOrStaleAuthority_IsFailClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var request = BuildReinstallAuthorityRequest(scenario);
        if (mutation == "signature")
        {
            request.Signature = Base64Url(RandomNumberGenerator.GetBytes(384));
        }
        else if (mutation == "installation")
        {
            request.InstallationId = Guid.NewGuid().ToString("D");
        }
        else
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = DateTime.UtcNow;
            binding.InvalidationReason = "test_revocation";
            await db.SaveChangesAsync();
        }

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.AuthorizeReinstallAsync("website-step1", request));
        Assert.Equal(mutation switch
        {
            "installation" => StatusCodes.Status409Conflict,
            "binding" => StatusCodes.Status422UnprocessableEntity,
            _ => StatusCodes.Status403Forbidden
        }, error.StatusCode);
        Assert.Equal(mutation switch
        {
            "signature" => "reinstall_signature_invalid",
            "installation" => "reinstall_binding_mismatch",
            _ => "binding_ineligible"
        }, error.ErrorCode);
    }
}
