using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
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

    [Fact]
    public async Task ReinstallAuthority_LegacyV2_ConcurrentIdenticalRequestsConverge()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);

        var responses = await Task.WhenAll(
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)),
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));

        var expectedDigest = Sha256(subjectRef);
        Assert.All(responses, response => Assert.Equal(expectedDigest, response.SubjectRefDigestSha256));
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(expectedDigest, (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(expectedDigest, (await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
    }

    [Fact]
    public async Task ReinstallAuthority_ModernV2_CompleteAuthorityIsAcceptedWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var response = await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));

        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact]
    public async Task ReinstallAuthority_ModernFinalizeV1_CompleteAuthorityIsAcceptedWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario, "finalize_v1");
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var response = await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));

        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact]
    public async Task ReinstallAuthority_ModernV2_UnrelatedProductMutationDoesNotMakeAuthorityIneligible()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        long enrollmentEpoch;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentEpoch = (await db.RuntimeEnrollments.AsNoTracking().SingleAsync()).AuthorityEpoch;
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
            Assert.True(
                (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch > enrollmentEpoch);
        }
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var response = await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));

        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact]
    public async Task ReinstallAuthority_LegacyV2_ReconciledReplayIgnoresUnrelatedAuthorityEpochAdvance()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        await AdvanceAuthorityEpochForUnrelatedProductAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var response = await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));

        Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact]
    public async Task ReinstallAuthority_LegacyV2_IncompleteAuthorityStillRequiresCurrentEpochForReconciliation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var subjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await AdvanceAuthorityEpochForUnrelatedProductAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));

        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Theory]
    [InlineData("mixed-legacy-source")]
    [InlineData("missing-entitlement")]
    [InlineData("missing-finalize")]
    [InlineData("duplicate-finalize-owner")]
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
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        await MutateModernV2AuthorityAsync(scenario, mutation);
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));

        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact]
    public async Task ReinstallAuthority_ModernV2_ConcurrentIdenticalRequestsRemainReadOnly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var before = await SnapshotReinstallAuthorityAsync(scenario);

        var responses = await Task.WhenAll(
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)),
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef)));

        Assert.All(responses, response => Assert.Equal(Sha256(subjectRef), response.SubjectRefDigestSha256));
        Assert.Equal(before, await SnapshotReinstallAuthorityAsync(scenario));
    }

    [Fact]
    public async Task ReinstallAuthority_ModernV2_ConcurrentProtectedDivergenceIsRevalidatedWithoutEndpointMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var (grantRef, subjectRef) = await ConfigureModernV2AuthorityAsync(scenario);
        var protectedStateBefore = await SnapshotReinstallPayloadAsync(scenario);
        await using var writer = await scenario.Factory.CreateDbContextAsync();
        await using var transaction = await writer.Database.BeginTransactionAsync();
        var ownership = await writer.DistributionGrantOwnerships.SingleAsync();
        ownership.ClientId = "other-client";
        await writer.SaveChangesAsync();

        var authorization = scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, subjectRef));
        await Task.Delay(100);
        Assert.False(authorization.IsCompleted);
        await transaction.CommitAsync();

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => authorization);
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        Assert.Equal(protectedStateBefore, await SnapshotReinstallPayloadAsync(scenario));
    }

    [Theory]
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
        var request = BuildReinstallAuthorityRequest(
            scenario,
            mutation == "grant" ? Guid.NewGuid().ToString("D") : grantRef,
            subjectRef);
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

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.AuthorizeReinstallAsync("website-step1", request));

        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        Assert.Equal(
            mutation == "signature" ? "reinstall_signature_invalid" : "reinstall_authority_ineligible",
            error.ErrorCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Null((await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(
            mutation == "partial-digest" ? Sha256(subjectRef) : null,
            (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
    }

    [Fact]
    public async Task ReinstallAuthority_LegacyV2_DivergentIdempotentSubjectFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var originalSubjectRef = Base64Url(RandomNumberGenerator.GetBytes(32));
        var grantRef = await ConvertToLegacyV2AuthorityAsync(scenario);
        await scenario.Runtime.AuthorizeReinstallAsync(
            "website-step1", BuildReinstallAuthorityRequest(scenario, grantRef, originalSubjectRef));

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.AuthorizeReinstallAsync(
                "website-step1",
                BuildReinstallAuthorityRequest(
                    scenario, grantRef, Base64Url(RandomNumberGenerator.GetBytes(32)))));

        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        Assert.Equal("reinstall_authority_ineligible", error.ErrorCode);
        var expectedDigest = Sha256(originalSubjectRef);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(expectedDigest, (await check.RuntimeEnrollments.SingleAsync()).SubjectRefDigestSha256);
        Assert.Equal(expectedDigest, (await check.DistributionInstallationBindings.SingleAsync()).SubjectRefDigestSha256);
    }

    [Fact]
    public async Task ReinstallAuthority_CurrentActiveBinding_ReturnsMinimalAssertion()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var request = BuildReinstallAuthorityRequest(scenario);

        var response = await scenario.Runtime.AuthorizeReinstallAsync("website-step1", request);

        Assert.Equal(RuntimeEnrollmentService.ReinstallAuthorityResponseSchema, response.Schema);
        Assert.Equal("authorized", response.Decision);
        Assert.Equal(request.BootstrapId, response.CorrelationId);
        Assert.Equal(request.EnrollmentId, response.EnrollmentId);
        Assert.Equal(request.InstallationId, response.InstallationId);
        Assert.Equal(request.ReleaseVersion, response.ReleaseVersion);
        Assert.Equal(request.KeyThumbprint, response.KeyThumbprint);
        Assert.Equal(request.SecurityEpoch, response.SecurityEpoch);
        Assert.Matches("^[0-9a-f]{64}$", response.SubjectRefDigestSha256);
        Assert.Matches("^[0-9a-f-]{36}$", response.GrantRef);
    }

    [Theory]
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

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.AuthorizeReinstallAsync("website-step1", request));

        Assert.Equal(
            mutation switch
            {
                "installation" => StatusCodes.Status409Conflict,
                "binding" => StatusCodes.Status422UnprocessableEntity,
                _ => StatusCodes.Status403Forbidden
            },
            error.StatusCode);
        Assert.Equal(
            mutation switch
            {
                "signature" => "reinstall_signature_invalid",
                "installation" => "reinstall_binding_mismatch",
                _ => "binding_ineligible"
            },
            error.ErrorCode);
    }

    private static async Task ActivatePreparedEnrollmentAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        enrollment.State = "ACTIVE";
        enrollment.ActivatedAtUtc = DateTime.UtcNow;
        enrollment.SecurityEpoch = 1;
        await db.SaveChangesAsync();
    }

    private static async Task<string> ConvertToLegacyV2AuthorityAsync(PreparedBootstrapScenario scenario)
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

    private static async Task<(string GrantRef, string SubjectRef)> ConfigureModernV2AuthorityAsync(
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

    private static async Task<string> SnapshotReinstallAuthorityAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var entitlements = await db.DistributionEntitlements.AsNoTracking()
            .Where(row => row.Id == binding.EntitlementId)
            .OrderBy(row => row.Id)
            .Select(row => row.ClientId + ":" + row.ProductId + ":" + row.LicenseId + ":"
                + row.ContractVersion + ":" + row.State + ":" + row.SubjectRefDigestSha256)
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
        return string.Join('|',
            enrollment.State, enrollment.SubjectRefDigestSha256, enrollment.AuthorityEpoch,
            binding.State, binding.SubjectRefDigestSha256, binding.GrantRefDigestSha256,
            string.Join(',', entitlements), string.Join(',', ownerships), string.Join(',', finalizeOwners),
            (await db.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch);
    }

    private static async Task<string> SnapshotReinstallPayloadAsync(PreparedBootstrapScenario scenario)
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

    private static async Task AdvanceAuthorityEpochForUnrelatedProductAsync(PreparedBootstrapScenario scenario)
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

    private static async Task MutateModernV2AuthorityAsync(
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
            case "duplicate-finalize-owner":
                db.DistributionBindingRequests.Add(new DistributionBindingRequest
                {
                    ClientId = "website-step1",
                    RequestId = Guid.NewGuid().ToString("D"),
                    Operation = "finalize_binding",
                    PayloadDigest = new string('e', 64),
                    BindingId = binding.Id,
                    ResponseJson = "{}",
                    CreatedAtUtc = DateTime.UtcNow
                });
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

    private static RuntimeReinstallAuthorityRequest BuildReinstallAuthorityRequest(
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

    private static RuntimeReinstallAuthorityRequest BuildReinstallAuthorityRequest(
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
