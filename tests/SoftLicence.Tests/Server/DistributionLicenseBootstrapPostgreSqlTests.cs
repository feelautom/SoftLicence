using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
    public async Task LicenseBootstrap_LostInitialIssueAfterCapabilityExpiry_CanRecoverNewGeneration()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issueRequest = scenario.NewIssueRequest();
        var issueDigest = Sha256("lost-initial-issue-" + Guid.NewGuid().ToString("D"));
        var lostIssue = await scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        await ExpireCapabilityAsync(scenario, lostIssue.Response.Capability);
        var expiredReplay = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest));
        Assert.Equal("bootstrap_expired", expiredReplay.ErrorCode);

        var recoverRequest = scenario.NewRecoverRequest();
        var recovered = await scenario.Bootstrap.RecoverAsync(
            "website-step1", Sha256("recover-initial-" + Guid.NewGuid().ToString("D")), recoverRequest);

        Assert.Equal(lostIssue.Response.BootstrapId, recovered.Response.BootstrapId);
        Assert.NotEqual(lostIssue.Response.Capability, recovered.Response.Capability);
    }

    [Fact]
    public async Task LicenseBootstrap_LostRemintAfterCapabilityExpiry_CanRecoverNextGeneration()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        var remintRequest = scenario.NewRemintRequest(issued.Response.BootstrapId);
        var remintDigest = Sha256("lost-remint-" + Guid.NewGuid().ToString("D"));
        var lostRemint = await scenario.Bootstrap.RemintAsync(
            "website-step1", remintDigest, remintRequest);
        await ExpireCapabilityAsync(scenario, lostRemint.Response.Capability);
        var expiredReplay = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RemintAsync("website-step1", remintDigest, remintRequest));
        Assert.Equal("bootstrap_expired", expiredReplay.ErrorCode);

        var recoverRequest = scenario.NewRecoverRequest();
        var recovered = await scenario.Bootstrap.RecoverAsync(
            "website-step1", Sha256("recover-remint-" + Guid.NewGuid().ToString("D")), recoverRequest);

        Assert.Equal(issued.Response.BootstrapId, recovered.Response.BootstrapId);
        Assert.NotEqual(lostRemint.Response.Capability, recovered.Response.Capability);
    }

    [Fact]
    public async Task LicenseBootstrap_RecoverReplayAndGenerationProgression_AreExactAndBounded()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await ExpireCapabilityAsync(scenario, issued.Response.Capability);
        var recoverRequest = scenario.NewRecoverRequest();
        var recoverDigest = Sha256("recover-exact-" + Guid.NewGuid().ToString("D"));

        var recovered = await scenario.Bootstrap.RecoverAsync("website-step1", recoverDigest, recoverRequest);
        var replay = await scenario.Bootstrap.RecoverAsync("website-step1", recoverDigest, recoverRequest);

        Assert.False(recovered.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(recovered.ExactResponseBody, replay.ExactResponseBody);
        Assert.Equal(recovered.Response.Capability, replay.Response.Capability);

        var overlapping = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync(
                "website-step1", Sha256("overlapping-recover-" + Guid.NewGuid().ToString("D")),
                scenario.NewRecoverRequest()));
        Assert.Equal("bootstrap_generation_active", overlapping.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, overlapping.StatusCode);

        await ExpireCapabilityAsync(scenario, recovered.Response.Capability);
        var expiredReplay = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync("website-step1", recoverDigest, recoverRequest));
        Assert.Equal("bootstrap_expired", expiredReplay.ErrorCode);
        Assert.Equal(StatusCodes.Status410Gone, expiredReplay.StatusCode);

        var next = await scenario.Bootstrap.RecoverAsync(
            "website-step1", Sha256("next-recover-" + Guid.NewGuid().ToString("D")),
            scenario.NewRecoverRequest());
        Assert.Equal(recovered.Response.BootstrapId, next.Response.BootstrapId);
        Assert.NotEqual(recovered.Response.Capability, next.Response.Capability);
    }

    [Fact]
    public async Task LicenseBootstrap_TwentyConcurrentRecoveries_ReturnOneGenerationAndExactReplays()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await ExpireCapabilityAsync(scenario, issued.Response.Capability);
        var request = scenario.NewRecoverRequest();
        var digest = Sha256("concurrent-recover-" + Guid.NewGuid().ToString("D"));

        var responses = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            scenario.Bootstrap.RecoverAsync("website-step1", digest, request)));

        Assert.Single(responses, response => !response.Idempotent);
        Assert.Equal(19, responses.Count(response => response.Idempotent));
        Assert.Single(responses.Select(response => Convert.ToBase64String(response.ExactResponseBody)).Distinct());
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await db.DistributionLicenseBootstrapCapabilities
            .Where(row => row.State == "ISSUED").ToListAsync());
    }

    [Theory]
    [InlineData("enrollment-invalidated")]
    [InlineData("binding-invalidated")]
    [InlineData("license-inactive")]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("seat-inactive")]
    [InlineData("seat-hwid-divergent")]
    [InlineData("hardware-banned")]
    [InlineData("component-banned")]
    [InlineData("approved-binary-changed")]
    [InlineData("authority-epoch-changed")]
    [InlineData("entitlement-expired")]
    [InlineData("entitlement-subject-divergent")]
    [InlineData("binding-release-divergent")]
    [InlineData("runtime-key-changed")]
    public async Task LicenseBootstrap_RecoverAfterAuthorityChange_FailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await ExpireCapabilityAsync(scenario, issued.Response.Capability);
        await MutateBootstrapReplayAuthorityAsync(scenario, mutation);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync(
                "website-step1", Sha256("authority-recover-" + Guid.NewGuid().ToString("D")),
                scenario.NewRecoverRequest()));

        Assert.Equal("bootstrap_ineligible", exception.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_RecoverSubstitutionsAndChangedReplay_AreRejected()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await ExpireCapabilityAsync(scenario, issued.Response.Capability);

        var wrongProduct = scenario.NewRecoverRequest();
        wrongProduct.ProductId = Guid.NewGuid().ToString("D");
        var wrongBinding = scenario.NewRecoverRequest();
        wrongBinding.BindingId = Guid.NewGuid().ToString("D");
        var wrongEnrollment = scenario.NewRecoverRequest();
        wrongEnrollment.EnrollmentId = Guid.NewGuid().ToString("D");
        var substitutions = new[] { wrongProduct, wrongBinding, wrongEnrollment };
        foreach (var substitution in substitutions)
        {
            var rejected = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                scenario.Bootstrap.RecoverAsync(
                    "website-step1", Sha256("substitution-" + Guid.NewGuid().ToString("D")), substitution));
            Assert.Equal("bootstrap_ineligible", rejected.ErrorCode);
        }

        var wrongClient = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync(
                "website-step2", Sha256("wrong-client-" + Guid.NewGuid().ToString("D")),
                scenario.NewRecoverRequest()));
        Assert.Equal("bootstrap_ineligible", wrongClient.ErrorCode);

        var request = scenario.NewRecoverRequest();
        var digest = Sha256("recover-replay-original");
        await scenario.Bootstrap.RecoverAsync("website-step1", digest, request);
        var changed = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync("website-step1", Sha256("recover-replay-changed"), request));
        Assert.Equal("idempotency_conflict", changed.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_RecoverAfterAuthorizationExpiry_FailsWithoutNewGeneration()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await ExpireCapabilityAsync(scenario, issued.Response.Capability);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            authorization.IssuedAtUtc = DateTime.UtcNow.AddMinutes(-2);
            authorization.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
            await db.SaveChangesAsync();
        }

        var rejected = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync(
                "website-step1", Sha256("expired-authorization-" + Guid.NewGuid().ToString("D")),
                scenario.NewRecoverRequest()));

        Assert.Equal("bootstrap_ineligible", rejected.ErrorCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await verify.DistributionLicenseBootstrapCapabilities
            .Where(row => row.State == "ISSUED" && row.ExpiresAtUtc > DateTime.UtcNow).ToListAsync());
    }

    [Fact]
    public async Task LicenseBootstrap_RecoverExactReplayAfterAuthorityMutation_FailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await ExpireCapabilityAsync(scenario, issued.Response.Capability);
        var request = scenario.NewRecoverRequest();
        var digest = Sha256("recover-before-authority-mutation-" + Guid.NewGuid().ToString("D"));
        await scenario.Bootstrap.RecoverAsync("website-step1", digest, request);
        await MutateBootstrapReplayAuthorityAsync(scenario, "binding-invalidated");

        var rejected = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RecoverAsync("website-step1", digest, request));

        Assert.Equal("bootstrap_ineligible", rejected.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_RecoverRacingDesktopConsumption_CannotMintSecondCapability()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        var consumption = scenario.ConsumeIssuedAsync(issued.Response);
        var recovery = scenario.Bootstrap.RecoverAsync(
            "website-step1", Sha256("recover-racing-consumption-" + Guid.NewGuid().ToString("D")),
            scenario.NewRecoverRequest());

        await consumption;
        var rejected = await Assert.ThrowsAsync<DistributionOperationException>(() => recovery);
        Assert.Contains(rejected.ErrorCode, new[] { "bootstrap_generation_active", "bootstrap_ineligible" });
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await db.DistributionLicenseBootstrapCapabilities
            .Where(row => row.State == "CONSUMED").ToListAsync());
        Assert.Empty(await db.DistributionLicenseBootstrapCapabilities
            .Where(row => row.State == "ISSUED").ToListAsync());
    }

    [Fact]
    public async Task LicenseBootstrap_S2SLineageOwnership_IsRequiredForIssueRemintAndConcurrentIssue()
    {
        using (var scenario = await CreatePreparedBootstrapScenarioAsync())
        {
            var otherClient = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                scenario.Bootstrap.IssueAsync("website-step2", Sha256("other-client-issue"),
                    scenario.NewIssueRequest()));
            Assert.Equal("bootstrap_ineligible", otherClient.ErrorCode);

            var issued = await scenario.IssueAsync();
            var remint = scenario.NewRemintRequest(issued.Response.BootstrapId);
            var otherRemint = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                scenario.Bootstrap.RemintAsync("website-step2", Sha256("other-client-remint"), remint));
            Assert.Equal("bootstrap_ineligible", otherRemint.ErrorCode);
        }

        using (var scenario = await CreatePreparedBootstrapScenarioAsync())
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var entitlement = await db.DistributionEntitlements.SingleAsync();
            entitlement.ClientId = "website-step2";
            await db.SaveChangesAsync();
            var mismatch = await Assert.ThrowsAsync<DistributionOperationException>(() => scenario.IssueAsync());
            Assert.Equal("bootstrap_ineligible", mismatch.ErrorCode);
        }

        using (var scenario = await CreatePreparedBootstrapScenarioAsync())
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var enrollment = await db.RuntimeEnrollments.SingleAsync();
            enrollment.ClientId = "website-step2";
            await db.SaveChangesAsync();
            var mismatch = await Assert.ThrowsAsync<DistributionOperationException>(() => scenario.IssueAsync());
            Assert.Equal("bootstrap_ineligible", mismatch.ErrorCode);
        }

        using (var scenario = await CreatePreparedBootstrapScenarioAsync())
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var owner = await db.DistributionBindingRequests.SingleAsync(row => row.Operation == "finalize_binding");
            owner.ClientId = "website-step2";
            await db.SaveChangesAsync();
            var mismatch = await Assert.ThrowsAsync<DistributionOperationException>(() => scenario.IssueAsync());
            Assert.Equal("bootstrap_ineligible", mismatch.ErrorCode);
        }

        using (var scenario = await CreatePreparedBootstrapScenarioAsync())
        {
            var ownerTask = scenario.IssueAsync();
            var otherTask = scenario.Bootstrap.IssueAsync(
                "website-step2", Sha256("concurrent-other-client"), scenario.NewIssueRequest());
            var issued = await ownerTask;
            var denied = await Assert.ThrowsAsync<DistributionOperationException>(() => otherTask);
            Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            Assert.Equal("website-step1", authorization.ClientId);
            Assert.Equal(issued.Response.BootstrapId, authorization.Id.ToString("D"));
        }
    }

    [Theory]
    [InlineData("enrollment-invalidated")]
    [InlineData("binding-invalidated")]
    [InlineData("license-inactive")]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("seat-inactive")]
    [InlineData("seat-hwid-divergent")]
    [InlineData("hardware-banned")]
    [InlineData("component-banned")]
    [InlineData("approved-binary-changed")]
    [InlineData("authority-epoch-changed")]
    [InlineData("entitlement-client-divergent")]
    [InlineData("entitlement-subject-divergent")]
    [InlineData("entitlement-grant-divergent")]
    [InlineData("entitlement-state-invalid")]
    [InlineData("entitlement-expired")]
    [InlineData("enrollment-client-divergent")]
    [InlineData("binding-owner-divergent")]
    [InlineData("binding-subject-divergent")]
    [InlineData("binding-grant-divergent")]
    [InlineData("binding-release-divergent")]
    [InlineData("runtime-epoch-changed")]
    [InlineData("security-epoch-changed")]
    [InlineData("runtime-key-changed")]
    public async Task LicenseBootstrap_ExactReplayAfterAuthorityChange_FailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await MutateBootstrapReplayAuthorityAsync(scenario, mutation);

        var exception = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());

        Assert.Equal("bootstrap_replay_authority_invalid", exception.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_ReplayRacingRevocation_IsSerializedAndFinalReplayFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();

        var racingReplay = scenario.ReplayAsync();
        var revocation = MutateBootstrapReplayAuthorityAsync(scenario, "binding-invalidated");
        try
        {
            await racingReplay;
        }
        catch (RuntimeEnrollmentException exception)
        {
            Assert.Equal("bootstrap_replay_authority_invalid", exception.ErrorCode);
        }
        await revocation;

        var finalReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());
        Assert.Equal("bootstrap_replay_authority_invalid", finalReplay.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_ExactReplayBeyondLegacyThreeHundredSeconds_RemainsAvailableUntilAuthorizationExpiry()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await SetConsumedReplayWindowAsync(scenario,
            consumedAtUtc: DateTime.UtcNow.AddSeconds(-301),
            replayExpiresAtUtc: DateTime.UtcNow.AddSeconds(-1));

        var replay = await scenario.ReplayAsync();

        Assert.True(replay.Idempotent);
        Assert.Equal(scenario.ConsumedResponseBytes, replay.ExactResponseBody);
    }

    [Fact]
    public async Task LicenseBootstrap_ExactReplayBeyondLegacyWindow_SurvivesServiceRestart()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await SetConsumedReplayWindowAsync(scenario,
            consumedAtUtc: DateTime.UtcNow.AddSeconds(-301),
            replayExpiresAtUtc: DateTime.UtcNow.AddSeconds(-1));
        var (restarted, restartedCrypto) = scenario.CreateRestartedRuntime();
        using (restartedCrypto)
        {
            var replay = await scenario.ReplayWithAsync(restarted);

            Assert.True(replay.Idempotent);
            Assert.Equal(scenario.ConsumedResponseBytes, replay.ExactResponseBody);
        }
    }

    [Fact]
    public async Task LicenseBootstrap_ConsumedReplayExpiry_EqualsOriginalAuthorizationAndNeverExtendsIt()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync();
        Assert.Equal(binding.HandoffExpiresAtUtc, authorization.ExpiresAtUtc);
        Assert.Equal(authorization.ExpiresAtUtc, authorization.ReplayExpiresAtUtc);
        Assert.True(authorization.ReplayExpiresAtUtc <= authorization.ExpiresAtUtc);
    }

    [Fact]
    public async Task LicenseBootstrap_ConsumedReplayAtAndAfterAuthorizationExpiry_IsTerminallyRejected()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            var binding = await db.DistributionInstallationBindings.SingleAsync();
            var expiredAt = DateTime.UtcNow.AddMilliseconds(-1);
            authorization.ExpiresAtUtc = expiredAt;
            authorization.ReplayExpiresAtUtc = expiredAt;
            binding.HandoffExpiresAtUtc = expiredAt;
            await db.SaveChangesAsync();
        }

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());

        Assert.Equal("bootstrap_replay_conflict", rejected.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_TwentyConcurrentReplaysBeyondLegacyWindow_ReturnFrozenBytesOnly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await SetConsumedReplayWindowAsync(scenario,
            consumedAtUtc: DateTime.UtcNow.AddSeconds(-301),
            replayExpiresAtUtc: DateTime.UtcNow.AddSeconds(-1));

        var replays = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => scenario.ReplayAsync()));

        Assert.All(replays, replay => Assert.True(replay.Idempotent));
        Assert.Single(replays.Select(replay => Convert.ToBase64String(replay.ExactResponseBody)).Distinct());
        Assert.Equal(scenario.ConsumedResponseBytes, replays[0].ExactResponseBody);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await db.DistributionLicenseBootstrapCapabilities
            .Where(row => row.State == "CONSUMED").ToListAsync());
        Assert.Empty(await db.DistributionLicenseBootstrapCapabilities
            .Where(row => row.State == "ISSUED").ToListAsync());
    }

    [Fact]
    public async Task LicenseBootstrap_CleanupOneSecondBeforeAuthorizationExpiry_PreservesReplayMaterial()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var boundary = await SetAuthorizationExpiryFromDatabaseClockAsync(scenario, 5);
        var delay = boundary.AddSeconds(-1) - DateTime.UtcNow;
        if (delay > TimeSpan.Zero)
            await Task.Delay(delay);
        await RunRuntimeCleanupAsync(scenario);

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.NotNull(authorization.ResponseCiphertext);
        Assert.NotNull(authorization.ResponseKeyId);
        Assert.NotNull(authorization.ResponseCiphertextLength);
        Assert.NotNull(authorization.ResponsePlaintextLength);
        Assert.Equal("CONSUMED", authorization.State);
        Assert.NotNull(authorization.ConsumedRequestId);
    }

    [Fact]
    public async Task LicenseBootstrap_CleanupExactlyAtAuthorizationExpiry_PurgesAllReplayMaterialAndKeepsTombstone()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await SetAuthorizationExpiryFromDatabaseClockAsync(scenario, 0);
        await RunRuntimeCleanupAsync(scenario);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());
        Assert.Equal("bootstrap_replay_conflict", rejected.ErrorCode);
        await AssertConsumedReplayMaterialPurgedAsync(scenario);
    }

    [Fact]
    public async Task LicenseBootstrap_CleanupOneSecondAfterAuthorizationExpiry_PurgesAllReplayMaterialAndKeepsTombstone()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await SetAuthorizationExpiryFromDatabaseClockAsync(scenario, -1);
        await RunRuntimeCleanupAsync(scenario);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());
        Assert.Equal("bootstrap_replay_conflict", rejected.ErrorCode);
        await AssertConsumedReplayMaterialPurgedAsync(scenario);
    }

    [Fact]
    public async Task LicenseBootstrap_CleanupRepairsLegacyPartialTombstoneAfterAuthorizationExpiry()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await SetAuthorizationExpiryFromDatabaseClockAsync(scenario, -1);
        await using (var partial = await scenario.Factory.CreateDbContextAsync())
        {
            var authorization = await partial.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            authorization.ResponseCiphertext = null;
            authorization.ResponseKeyId = null;
            authorization.ResponseCiphertextLength = null;
            Assert.NotNull(authorization.ResponsePlaintextLength);
            await partial.SaveChangesAsync();
        }

        await RunRuntimeCleanupAsync(scenario);

        await AssertConsumedReplayMaterialPurgedAsync(scenario);
    }

    private static async Task AssertConsumedReplayMaterialPurgedAsync(PreparedBootstrapScenario scenario)
    {
        await using var afterExpiry = await scenario.Factory.CreateDbContextAsync();
        var tombstone = await afterExpiry.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.Equal("CONSUMED", tombstone.State);
        Assert.Null(tombstone.ResponseCiphertext);
        Assert.Null(tombstone.ResponseKeyId);
        Assert.Null(tombstone.ResponseCiphertextLength);
        Assert.Null(tombstone.ResponsePlaintextLength);
        Assert.NotNull(tombstone.ConsumedRequestId);
        Assert.NotNull(tombstone.ConsumedBodyDigestSha256);
        Assert.NotNull(tombstone.ConsumedProofDigestSha256);
    }

    [Theory]
    [InlineData("ciphertext")]
    [InlineData("key-id")]
    [InlineData("ciphertext-length")]
    [InlineData("plaintext-length")]
    public async Task LicenseBootstrap_CorruptedConsumedReplayMaterial_FailsUnavailableWithoutResponse(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            switch (mutation)
            {
                case "ciphertext":
                    var corrupted = authorization.ResponseCiphertext!.ToArray();
                    corrupted[0] ^= 0x01;
                    authorization.ResponseCiphertext = corrupted;
                    break;
                case "key-id":
                    authorization.ResponseKeyId = "missing-replay-key";
                    break;
                case "ciphertext-length":
                    authorization.ResponseCiphertextLength += 1;
                    break;
                case "plaintext-length":
                    authorization.ResponsePlaintextLength += 1;
                    break;
            }
            await db.SaveChangesAsync();
        }

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());

        Assert.Equal("authority_unavailable", rejected.ErrorCode);
    }

    [Fact]
    public async Task LicenseBootstrap_IssueRemintAndTwentyConcurrentRedeems_ReturnOneExactUnicodeLicense()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.979");
        using var runtimeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, runtimeSigning, nextSigning);
        options.LicenseBootstrapCapabilityTtlSeconds = 120;
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var dataProtection = new EphemeralDataProtectionProvider();
        var productEncryption = new EncryptionService(dataProtection);
        var licenseKeys = LicenseService.GenerateKeys();
        string hardwareId;
        Guid licenseTypeId;
        await using (var db = await factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            binding.SubjectRefDigestSha256 = Sha256("website-subject-ref");
            binding.HandoffIssuedAtUtc = DateTime.UtcNow.AddMinutes(-1);
            binding.DownloadCompletedAtUtc = DateTime.UtcNow.AddSeconds(-30);
            binding.HandoffExpiresAtUtc = DateTime.UtcNow.AddMinutes(10);
            db.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = binding.EntitlementId, ClientId = "website-step1", ProductId = binding.ProductId,
                LicenseId = binding.LicenseId, GrantRefDigestSha256 = binding.GrantRefDigestSha256,
                SubjectRefDigestSha256 = binding.SubjectRefDigestSha256, ContractVersion = 3,
                State = "finalized", IssuedAtUtc = DateTime.UtcNow.AddMinutes(-2),
                ExpiresAtUtc = DateTime.UtcNow.AddHours(1), FinalizedAtUtc = DateTime.UtcNow.AddMinutes(-1)
            });
            var product = await db.Products.SingleAsync(row => row.Id == fixture.ProductId);
            product.PrivateKeyXml = productEncryption.Encrypt(licenseKeys.PrivateKey);
            product.PublicKeyXml = licenseKeys.PublicKey;
            var license = await db.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            license.CustomerName = "Franck – 測試";
            license.Reference = "plugin:mcp-tools:pluginVersion=β-1:allowedFeatures=read,write";
            licenseTypeId = license.LicenseTypeId;
            hardwareId = await db.LicenseSeats.Where(row => row.Id == binding.LicenseSeatId)
                .Select(row => row.HardwareId).SingleAsync();
            db.LicenseTypeCustomParams.Add(new LicenseTypeCustomParam
            {
                LicenseTypeId = licenseTypeId, Key = "unicodeLabel", Name = "Unicode", Value = "électricité-測試"
            });
            await db.SaveChangesAsync();
        }

        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var signedFiles = new SignedLicenseFileService(productEncryption);
        var runtime = new RuntimeEnrollmentService(
            factory, authority, registry, crypto, Options.Create(options), signedLicenseFiles: signedFiles);
        var prepared = await runtime.PrepareAsync(
            "website-step1", Sha256("bootstrap-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var bootstrap = new DistributionLicenseBootstrapService(
            factory, authority, crypto, registry, Options.Create(options), TimeProvider.System);
        var issueRequest = new DistributionLicenseBootstrapIssueRequest
        {
            Schema = DistributionLicenseBootstrapService.IssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D")
        };
        var issueDigest = Sha256("bootstrap-issue-exact");
        var issued = await bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        var issueReplay = await bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        Assert.False(issued.Idempotent);
        Assert.True(issueReplay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, issueReplay.ExactResponseBody);
        Assert.InRange(
            DateTimeOffset.Parse(issued.Response.CapabilityExpiresAtUtc) - DateTimeOffset.UtcNow,
            TimeSpan.FromSeconds(100), TimeSpan.FromSeconds(120));

        var remintRequest = new DistributionLicenseBootstrapRemintRequest
        {
            Schema = DistributionLicenseBootstrapService.RemintSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            BootstrapId = issued.Response.BootstrapId
        };
        var reminted = await bootstrap.RemintAsync("website-step1", Sha256("bootstrap-remint-exact"), remintRequest);
        Assert.Equal(issued.Response.BootstrapId, reminted.Response.BootstrapId);
        Assert.NotEqual(issued.Response.Capability, reminted.Response.Capability);

        issueRequest.ExtensionData = new Dictionary<string, JsonElement>
        {
            ["subjectRef"] = JsonSerializer.SerializeToElement("attacker-selected-subject"),
            ["licenseId"] = JsonSerializer.SerializeToElement(Guid.NewGuid().ToString("D")),
            ["grantRefDigestSha256"] = JsonSerializer.SerializeToElement(Sha256("attacker-selected-grant")),
            ["entitlementId"] = JsonSerializer.SerializeToElement(Guid.NewGuid().ToString("D"))
        };
        var authoritySelection = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            bootstrap.IssueAsync("website-step1", Sha256("bootstrap-authority-selection"), issueRequest));
        Assert.Equal("invalid_request", authoritySelection.ErrorCode);
        issueRequest.ExtensionData = null;

        var redeemRequest = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            InstallationId = fixture.InstallationId,
            BootstrapId = reminted.Response.BootstrapId,
            Capability = reminted.Response.Capability
        };
        var supersededRequest = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = redeemRequest.Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = redeemRequest.ProductId,
            BindingId = redeemRequest.BindingId,
            InstallationId = redeemRequest.InstallationId,
            BootstrapId = redeemRequest.BootstrapId,
            Capability = issued.Response.Capability
        };
        var supersededDigest = Sha256("bootstrap-superseded-capability");
        var supersededProof = Proof(enrollmentKey, "license-bootstrap", enrollmentId,
            options.ConfirmAudience, prepared.Response.Challenge, supersededDigest);
        var superseded = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            runtime.RedeemLicenseBootstrapAsync(
                enrollmentId, supersededDigest, supersededRequest, supersededProof, IPAddress.Loopback));
        Assert.Equal("bootstrap_expired", superseded.ErrorCode);

        var substitutionCases = new[]
        {
            CopyRedeemRequest(redeemRequest, request => request.ProductId = Guid.NewGuid().ToString("D")),
            CopyRedeemRequest(redeemRequest, request => request.BindingId = Guid.NewGuid().ToString("D")),
            CopyRedeemRequest(redeemRequest, request => request.InstallationId = Guid.NewGuid().ToString("D")),
            CopyRedeemRequest(redeemRequest, request => request.BootstrapId = Guid.NewGuid().ToString("D")),
            CopyRedeemRequest(redeemRequest, request => request.Capability = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
        };
        foreach (var substitutionRequest in substitutionCases)
        {
            var substitutionDigest = Sha256(JsonSerializer.Serialize(substitutionRequest));
            var substitutionProof = Proof(enrollmentKey, "license-bootstrap", enrollmentId,
                options.ConfirmAudience, prepared.Response.Challenge, substitutionDigest);
            await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                runtime.RedeemLicenseBootstrapAsync(
                    enrollmentId, substitutionDigest, substitutionRequest, substitutionProof, IPAddress.Loopback));
        }

        await using (var mutate = await factory.CreateDbContextAsync())
        {
            var mutableAuthorization = await mutate.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            mutableAuthorization.State = "REVOKED";
            await mutate.SaveChangesAsync();
        }
        var revokedDigest = Sha256("bootstrap-revoked");
        var revokedProof = Proof(enrollmentKey, "license-bootstrap", enrollmentId,
            options.ConfirmAudience, prepared.Response.Challenge, revokedDigest);
        var revoked = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            runtime.RedeemLicenseBootstrapAsync(
                enrollmentId, revokedDigest, redeemRequest, revokedProof, IPAddress.Loopback));
        Assert.Equal("bootstrap_ineligible", revoked.ErrorCode);
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var mutableAuthorization = await restore.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            mutableAuthorization.State = "ISSUED";
            var currentCapability = await restore.DistributionLicenseBootstrapCapabilities
                .SingleAsync(row => row.CapabilityDigestSha256 == Sha256(reminted.Response.Capability));
            currentCapability.MintedAtUtc = DateTime.UtcNow.AddMinutes(-2);
            currentCapability.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
            await restore.SaveChangesAsync();
        }
        var expiredDigest = Sha256("bootstrap-expired");
        var expiredProof = Proof(enrollmentKey, "license-bootstrap", enrollmentId,
            options.ConfirmAudience, prepared.Response.Challenge, expiredDigest);
        var expired = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            runtime.RedeemLicenseBootstrapAsync(
                enrollmentId, expiredDigest, redeemRequest, expiredProof, IPAddress.Loopback));
        Assert.Equal("bootstrap_expired", expired.ErrorCode);
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var currentCapability = await restore.DistributionLicenseBootstrapCapabilities
                .SingleAsync(row => row.CapabilityDigestSha256 == Sha256(reminted.Response.Capability));
            currentCapability.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(1);
            await restore.SaveChangesAsync();
        }

        var redeemDigest = Sha256("bootstrap-redeem-exact");
        var proof = Proof(enrollmentKey, "license-bootstrap", enrollmentId,
            options.ConfirmAudience, prepared.Response.Challenge, redeemDigest);
        var responses = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            runtime.RedeemLicenseBootstrapAsync(
                enrollmentId, redeemDigest, redeemRequest, proof, IPAddress.Loopback)));
        Assert.Single(responses.Select(response => Convert.ToBase64String(response.ExactResponseBody)).Distinct());
        Assert.Single(responses, response => !response.Idempotent);
        var divergentProof = Proof(enrollmentKey, "license-bootstrap", enrollmentId,
            options.ConfirmAudience, prepared.Response.Challenge, redeemDigest);
        var divergentReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            runtime.RedeemLicenseBootstrapAsync(
                enrollmentId, redeemDigest, redeemRequest, divergentProof, IPAddress.Loopback));
        Assert.Equal("bootstrap_replay_conflict", divergentReplay.ErrorCode);
        var result = LicenseService.ValidateLicense(
            responses[0].Response.LicenseFile, licenseKeys.PublicKey, hardwareId);
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal("Franck – 測試", result.License!.CustomerName);
        Assert.Equal("mcp-tools", result.License.PluginId);
        Assert.Equal("électricité-測試", result.License.Features["unicodeLabel"]);
        await using var verify = await factory.CreateDbContextAsync();
        var authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.Equal("CONSUMED", authorization.State);
        Assert.NotNull(authorization.ResponseCiphertext);
        Assert.DoesNotContain(
            responses[0].Response.LicenseFile,
            Encoding.ASCII.GetString(authorization.ResponseCiphertext!),
            StringComparison.Ordinal);
        var expiredAt = DateTime.UtcNow.AddSeconds(-1);
        authorization.IssuedAtUtc = expiredAt.AddMinutes(-1);
        authorization.ExpiresAtUtc = expiredAt;
        authorization.ReplayExpiresAtUtc = expiredAt;
        await verify.SaveChangesAsync();
        var cleanup = new RuntimeEnrollmentCleanupService(
            factory, Options.Create(options), TimeProvider.System,
            NullLogger<RuntimeEnrollmentCleanupService>.Instance);
        var cleanupMethod = typeof(RuntimeEnrollmentCleanupService).GetMethod(
            "CleanupAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(cleanupMethod);
        await (Task)cleanupMethod.Invoke(cleanup, [CancellationToken.None])!;
        verify.ChangeTracker.Clear();
        authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.Equal("CONSUMED", authorization.State);
        Assert.Null(authorization.ResponseCiphertext);
        Assert.Null(authorization.ResponseKeyId);
    }

    [Fact]
    public async Task LicenseBootstrap_LegacyBindingWithoutSubjectDigest_FailsClosed()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var runtime = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));
        var prepared = await runtime.PrepareAsync("website-step1", Sha256("legacy-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var service = new DistributionLicenseBootstrapService(
            factory, authority, crypto, registry, Options.Create(options), TimeProvider.System);
        var request = new DistributionLicenseBootstrapIssueRequest
        {
            Schema = DistributionLicenseBootstrapService.IssueSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"), EnrollmentId = prepared.Response.EnrollmentId
        };
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.IssueAsync("website-step1", Sha256("legacy-bootstrap"), request));
        Assert.Equal("bootstrap_ineligible", exception.ErrorCode);
    }

    private static RuntimeLicenseBootstrapRedeemRequest CopyRedeemRequest(
        RuntimeLicenseBootstrapRedeemRequest source,
        Action<RuntimeLicenseBootstrapRedeemRequest> change)
    {
        var copy = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = source.Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = source.ProductId,
            BindingId = source.BindingId,
            InstallationId = source.InstallationId,
            BootstrapId = source.BootstrapId,
            Capability = source.Capability
        };
        change(copy);
        return copy;
    }

    private static async Task<PreparedBootstrapScenario> CreatePreparedBootstrapScenarioAsync()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.979");
        var runtimeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, runtimeSigning, nextSigning);
        options.LicenseBootstrapCapabilityTtlSeconds = 120;
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var encryption = new EncryptionService(new EphemeralDataProtectionProvider());
        var licenseKeys = LicenseService.GenerateKeys();
        await using (var db = await factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            binding.SubjectRefDigestSha256 = Sha256("website-subject-ref");
            binding.HandoffIssuedAtUtc = DateTime.UtcNow.AddMinutes(-1);
            binding.DownloadCompletedAtUtc = DateTime.UtcNow.AddSeconds(-30);
            binding.HandoffExpiresAtUtc = DateTime.UtcNow.AddMinutes(10);
            db.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = binding.EntitlementId,
                ClientId = "website-step1",
                ProductId = binding.ProductId,
                LicenseId = binding.LicenseId,
                GrantRefDigestSha256 = binding.GrantRefDigestSha256,
                SubjectRefDigestSha256 = binding.SubjectRefDigestSha256,
                ContractVersion = 3,
                State = "finalized",
                IssuedAtUtc = DateTime.UtcNow.AddMinutes(-2),
                ExpiresAtUtc = DateTime.UtcNow.AddHours(1),
                FinalizedAtUtc = DateTime.UtcNow.AddMinutes(-1)
            });
            var product = await db.Products.SingleAsync(row => row.Id == fixture.ProductId);
            product.PrivateKeyXml = encryption.Encrypt(licenseKeys.PrivateKey);
            product.PublicKeyXml = licenseKeys.PublicKey;
            await db.SaveChangesAsync();
        }

        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var signedFiles = new SignedLicenseFileService(encryption);
        var runtime = new RuntimeEnrollmentService(factory, authority, registry, crypto,
            Options.Create(options), signedLicenseFiles: signedFiles);
        var prepareDigest = Sha256("bootstrap-prepare");
        var prepareRequest = PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey);
        var prepared = await runtime.PrepareAsync("website-step1", prepareDigest, prepareRequest);
        return new PreparedBootstrapScenario(
            factory,
            connections.Admin,
            connections.App,
            fixture,
            options,
            runtimeSigning,
            nextSigning,
            enrollmentKey,
            crypto,
            runtime,
            signedFiles,
            new DistributionLicenseBootstrapService(
                factory, authority, crypto, registry, Options.Create(options), TimeProvider.System),
            prepared.Response,
            prepareRequest,
            prepareDigest);
    }

    private static async Task ExpireCapabilityAsync(
        PreparedBootstrapScenario scenario,
        string capability)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var row = await db.DistributionLicenseBootstrapCapabilities.SingleAsync(candidate =>
            candidate.CapabilityDigestSha256 == Sha256(capability));
        row.MintedAtUtc = DateTime.UtcNow.AddMinutes(-2);
        row.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
        await db.SaveChangesAsync();
    }

    private static async Task SetConsumedReplayWindowAsync(
        PreparedBootstrapScenario scenario,
        DateTime consumedAtUtc,
        DateTime replayExpiresAtUtc)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        authorization.ConsumedAtUtc = consumedAtUtc;
        authorization.ReplayExpiresAtUtc = replayExpiresAtUtc;
        await db.SaveChangesAsync();
    }

    private static async Task<DateTime> SetAuthorizationExpiryFromDatabaseClockAsync(
        PreparedBootstrapScenario scenario,
        int offsetSeconds)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var boundary = await db.Database
            .SqlQuery<DateTime>($"SELECT clock_timestamp() + make_interval(secs => {offsetSeconds}) AS \"Value\"")
            .SingleAsync();
        var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync();
        authorization.IssuedAtUtc = boundary.AddMinutes(-1);
        authorization.ExpiresAtUtc = boundary;
        authorization.ReplayExpiresAtUtc = boundary;
        binding.HandoffIssuedAtUtc = boundary.AddMinutes(-1);
        binding.HandoffExpiresAtUtc = boundary;
        await db.SaveChangesAsync();
        return boundary;
    }

    private static async Task RunRuntimeCleanupAsync(PreparedBootstrapScenario scenario)
    {
        var cleanup = new RuntimeEnrollmentCleanupService(
            scenario.Factory, Options.Create(scenario.Options), TimeProvider.System,
            NullLogger<RuntimeEnrollmentCleanupService>.Instance);
        var cleanupMethod = typeof(RuntimeEnrollmentCleanupService).GetMethod(
            "CleanupAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(cleanupMethod);
        await (Task)cleanupMethod.Invoke(cleanup, [CancellationToken.None])!;
    }

    private static async Task MutateBootstrapReplayAuthorityAsync(
        PreparedBootstrapScenario scenario,
        string mutation)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync();
        var entitlement = await db.DistributionEntitlements.SingleAsync();
        var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        var license = await db.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        switch (mutation)
        {
            case "enrollment-invalidated":
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = DateTime.UtcNow;
                enrollment.InvalidationReason = "test_authority_change";
                break;
            case "binding-invalidated":
                binding.State = "invalidated";
                binding.InvalidatedAtUtc = DateTime.UtcNow;
                binding.InvalidationReason = "test_authority_change";
                break;
            case "license-inactive":
                license.IsActive = false;
                break;
            case "license-revoked":
                license.RevokedAt = DateTime.UtcNow;
                break;
            case "license-expired":
                license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
                break;
            case "seat-inactive":
                seat.IsActive = false;
                break;
            case "seat-hwid-divergent":
                seat.HardwareId = "runtime-hwid-divergent-" + Guid.NewGuid().ToString("N");
                break;
            case "hardware-banned":
                db.BannedHardwareIds.Add(new BannedHardwareId
                {
                    HardwareId = seat.HardwareId,
                    ProductId = binding.ProductId,
                    Reason = "bootstrap replay regression test",
                    IsActive = true
                });
                break;
            case "component-banned":
                db.BannedComponents.Add(new BannedComponent
                {
                    ComponentType = "FP_EXE",
                    ComponentHash = binding.ExecutableSha256,
                    ProductId = binding.ProductId,
                    Reason = "bootstrap replay regression test",
                    IsActive = true
                });
                break;
            case "approved-binary-changed":
                var approved = await db.ApprovedBinaries.SingleAsync(row =>
                    row.ProductId == binding.ProductId && row.Version == binding.Version && row.Key == "FP_EXE");
                approved.Hash = new string('a', 64);
                break;
            case "authority-epoch-changed":
                await db.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE public."DistributionBindingRequests"
                    SET "ClientId" = "ClientId"
                    WHERE "BindingId" = {binding.Id} AND "Operation" = 'finalize_binding';
                    """);
                return;
            case "entitlement-client-divergent":
                entitlement.ClientId = "website-step2";
                break;
            case "entitlement-subject-divergent":
                entitlement.SubjectRefDigestSha256 = Sha256("divergent-entitlement-subject");
                break;
            case "entitlement-grant-divergent":
                entitlement.GrantRefDigestSha256 = Sha256("divergent-entitlement-grant");
                break;
            case "entitlement-state-invalid":
                entitlement.State = "issued";
                entitlement.FinalizedAtUtc = null;
                break;
            case "entitlement-expired":
                entitlement.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
                break;
            case "enrollment-client-divergent":
                enrollment.ClientId = "website-step2";
                break;
            case "binding-owner-divergent":
                var owner = await db.DistributionBindingRequests.SingleAsync(row =>
                    row.BindingId == binding.Id && row.Operation == "finalize_binding");
                owner.ClientId = "website-step2";
                break;
            case "binding-subject-divergent":
                binding.SubjectRefDigestSha256 = Sha256("divergent-binding-subject");
                break;
            case "binding-grant-divergent":
                binding.GrantRefDigestSha256 = Sha256("divergent-binding-grant");
                break;
            case "binding-release-divergent":
                binding.Version = "2.2.980";
                break;
            case "runtime-epoch-changed":
                authorization.RuntimeEpoch += 1;
                break;
            case "security-epoch-changed":
                enrollment.SecurityEpoch += 1;
                break;
            case "runtime-key-changed":
                enrollment.PublicKeySpkiSha256 = Sha256("divergent-runtime-key");
                break;
            default:
                throw new InvalidOperationException("Unknown mutation: " + mutation);
        }
        await db.SaveChangesAsync();
    }

    private sealed class PreparedBootstrapScenario : IDisposable
    {
        private readonly RSA _runtimeSigning;
        private readonly RSA _nextSigning;
        private readonly RSA _enrollmentKey;
        private readonly RuntimeEnrollmentCryptoService _crypto;
        private readonly ISignedLicenseFileService _signedLicenseFiles;
        private readonly string _adminConnectionString;
        private readonly string _appConnectionString;

        public TestDbFactory Factory { get; }
        public (Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version) Fixture { get; }
        public RuntimeEnrollmentOptions Options { get; }
        public RuntimeEnrollmentService Runtime { get; }
        public DistributionLicenseBootstrapService Bootstrap { get; }
        public RuntimeEnrollmentPrepareResponse Prepared { get; }
        public RuntimeEnrollmentPrepareRequest PrepareRequest { get; }
        public string PrepareDigest { get; }
        public RSA EnrollmentKey => _enrollmentKey;
        public DistributionLicenseBootstrapIssuedResponse? Issued { get; private set; }
        public RuntimeLicenseBootstrapRedeemRequest? RedeemRequest { get; private set; }
        public RuntimeProofHeaders? ReplayProof { get; private set; }
        public string? RedeemDigest { get; private set; }
        public byte[]? ConsumedResponseBytes { get; private set; }
        public Guid EnrollmentId => Guid.Parse(Prepared.EnrollmentId);

        /// <summary>Gets the application-role PostgreSQL connection used by HTTP integration tests.</summary>
        public string AppConnectionString => _appConnectionString;

        /// <summary>Gets the PostgreSQL administrator connection used only for migration lifecycle tests.</summary>
        public string AdminConnectionString => _adminConnectionString;

        /// <summary>Gets the signer bound to the scenario product encryption authority.</summary>
        public ISignedLicenseFileService SignedLicenseFiles => _signedLicenseFiles;

        public PreparedBootstrapScenario(
            TestDbFactory factory,
            string adminConnectionString,
            string appConnectionString,
            (Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version) fixture,
            RuntimeEnrollmentOptions options,
            RSA runtimeSigning,
            RSA nextSigning,
            RSA enrollmentKey,
            RuntimeEnrollmentCryptoService crypto,
            RuntimeEnrollmentService runtime,
            ISignedLicenseFileService signedLicenseFiles,
            DistributionLicenseBootstrapService bootstrap,
            RuntimeEnrollmentPrepareResponse prepared,
            RuntimeEnrollmentPrepareRequest prepareRequest,
            string prepareDigest)
        {
            Factory = factory;
            _adminConnectionString = adminConnectionString;
            _appConnectionString = appConnectionString;
            Fixture = fixture;
            Options = options;
            _runtimeSigning = runtimeSigning;
            _nextSigning = nextSigning;
            _enrollmentKey = enrollmentKey;
            _crypto = crypto;
            _signedLicenseFiles = signedLicenseFiles;
            Runtime = runtime;
            Bootstrap = bootstrap;
            Prepared = prepared;
            PrepareRequest = prepareRequest;
            PrepareDigest = prepareDigest;
        }

        public DistributionLicenseBootstrapIssueRequest NewIssueRequest() => new()
        {
            Schema = DistributionLicenseBootstrapService.IssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = Fixture.ProductId.ToString("D"),
            BindingId = Fixture.BindingId.ToString("D"),
            EnrollmentId = EnrollmentId.ToString("D")
        };

        public DistributionLicenseBootstrapRemintRequest NewRemintRequest(string bootstrapId) => new()
        {
            Schema = DistributionLicenseBootstrapService.RemintSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = Fixture.ProductId.ToString("D"),
            BindingId = Fixture.BindingId.ToString("D"),
            EnrollmentId = EnrollmentId.ToString("D"),
            BootstrapId = bootstrapId
        };

        public DistributionLicenseBootstrapRecoverRequest NewRecoverRequest() => new()
        {
            Schema = DistributionLicenseBootstrapService.RecoverSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = Fixture.ProductId.ToString("D"),
            BindingId = Fixture.BindingId.ToString("D"),
            EnrollmentId = EnrollmentId.ToString("D")
        };

        public Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> IssueAsync() =>
            Bootstrap.IssueAsync("website-step1", Sha256("owner-issue-" + Guid.NewGuid().ToString("D")), NewIssueRequest());

        public async Task ConsumeAsync()
        {
            Issued = (await IssueAsync()).Response;
            RedeemRequest = new RuntimeLicenseBootstrapRedeemRequest
            {
                Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = Fixture.ProductId.ToString("D"),
                BindingId = Fixture.BindingId.ToString("D"),
                InstallationId = Fixture.InstallationId,
                BootstrapId = Issued.BootstrapId,
                Capability = Issued.Capability
            };
            RedeemDigest = Sha256("consumed-replay-exact-" + Guid.NewGuid().ToString("D"));
            ReplayProof = Proof(_enrollmentKey, "license-bootstrap", EnrollmentId,
                Options.ConfirmAudience, Prepared.Challenge, RedeemDigest);
            var consumed = await Runtime.RedeemLicenseBootstrapAsync(
                EnrollmentId, RedeemDigest, RedeemRequest, ReplayProof, IPAddress.Loopback);
            ConsumedResponseBytes = consumed.ExactResponseBody.ToArray();
        }

        public async Task ConsumeIssuedAsync(DistributionLicenseBootstrapIssuedResponse issued)
        {
            var request = new RuntimeLicenseBootstrapRedeemRequest
            {
                Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = Fixture.ProductId.ToString("D"),
                BindingId = Fixture.BindingId.ToString("D"),
                InstallationId = Fixture.InstallationId,
                BootstrapId = issued.BootstrapId,
                Capability = issued.Capability
            };
            var digest = Sha256("consume-issued-" + Guid.NewGuid().ToString("D"));
            var proof = Proof(_enrollmentKey, "license-bootstrap", EnrollmentId,
                Options.ConfirmAudience, Prepared.Challenge, digest);
            await Runtime.RedeemLicenseBootstrapAsync(
                EnrollmentId, digest, request, proof, IPAddress.Loopback);
        }

        public Task<RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>> ReplayAsync() =>
            ReplayWithAsync(Runtime);

        public Task<RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>> ReplayWithAsync(
            RuntimeEnrollmentService runtime) =>
            runtime.RedeemLicenseBootstrapAsync(
                EnrollmentId,
                RedeemDigest ?? throw new InvalidOperationException("Scenario was not consumed."),
                RedeemRequest ?? throw new InvalidOperationException("Scenario was not consumed."),
                ReplayProof ?? throw new InvalidOperationException("Scenario was not consumed."),
                IPAddress.Loopback);

        public (RuntimeEnrollmentService Runtime, RuntimeEnrollmentCryptoService Crypto) CreateRestartedRuntime()
        {
            var authority = new RuntimeEnrollmentAuthorityService(
                Factory, Microsoft.Extensions.Options.Options.Create(Options));
            var registry = new RuntimeEnrollmentKeyRegistryService(
                Factory, Microsoft.Extensions.Options.Options.Create(Options));
            var crypto = new RuntimeEnrollmentCryptoService(
                Microsoft.Extensions.Options.Options.Create(Options));
            return (new RuntimeEnrollmentService(
                Factory, authority, registry, crypto, Microsoft.Extensions.Options.Options.Create(Options),
                signedLicenseFiles: _signedLicenseFiles), crypto);
        }

        public void Dispose()
        {
            _crypto.Dispose();
            _enrollmentKey.Dispose();
            _nextSigning.Dispose();
            _runtimeSigning.Dispose();
            using var appConnection = new NpgsqlConnection(_appConnectionString);
            using var adminConnection = new NpgsqlConnection(_adminConnectionString);
            NpgsqlConnection.ClearPool(appConnection);
            NpgsqlConnection.ClearPool(adminConnection);
        }
    }
}
