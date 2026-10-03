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

    /// <summary>
    /// A first S2S lease attempt expires behind a real PostgreSQL advisory writer. A separate
    /// autocommit observer sees the blocked backend without inheriting the writer transaction's
    /// statistics snapshot. The next bounded whole-operation attempt must issue once after
    /// release; its exact replay cannot mint another generation.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_LeaseLockTimeout_RetriesWholeOperationExactly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        scenario.Options.LockTimeoutMilliseconds = 500;
        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);", writer, transaction))
            await lockCommand.ExecuteNonQueryAsync();
        await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
        await observer.OpenAsync();
        var request = scenario.NewIssueRequest();
        var digest = Sha256("bootstrap-retry-after-lock-timeout");
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        var issue = scenario.Bootstrap.IssueAsync("website-step1", digest, request);
        var observedWait = false;
        for (var poll = 0; poll < 200 && !observedWait; poll++)
        {
            await using var activity = new NpgsqlCommand("""
                SELECT count(*) FROM pg_catalog.pg_stat_activity
                WHERE datname = pg_catalog.current_database()
                  AND pid <> pg_catalog.pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0;
                """, observer);
            observedWait = Convert.ToInt64(await activity.ExecuteScalarAsync()) > 0;
            if (!observedWait)
                await Task.Delay(10);
        }
        Assert.True(observedWait);
        // Release at least 600 ms after the issue began, beyond its 500 ms first
        // timeout while a bounded later attempt is still waiting on this writer.
        var remaining = TimeSpan.FromMilliseconds(600) - elapsed.Elapsed;
        if (remaining > TimeSpan.Zero)
            await Task.Delay(remaining);
        Assert.False(issue.IsCompleted);
        await transaction.CommitAsync();
        var issued = await issue.WaitAsync(TimeSpan.FromSeconds(10));
        var replay = await scenario.Bootstrap.IssueAsync("website-step1", digest, request);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await verify.DistributionLicenseBootstrapAuthorizations.ToListAsync());
        Assert.Single(await verify.DistributionLicenseBootstrapCapabilities.ToListAsync());
    }

    /// <summary>
    /// Recover cannot mint from a generation whose credential, signed lineage, release or
    /// current commercial authority changed, even after its capability has expired.
    /// </summary>
    [Theory]
    [InlineData("enrollment-invalidated")]
    [InlineData("binding-invalidated")]
    [InlineData("license-inactive")]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("seat-inactive")]
    [InlineData("hardware-banned")]
    [InlineData("component-banned")]
    [InlineData("approved-binary-changed")]
    [InlineData("authorization-epoch-divergent")]
    [InlineData("entitlement-expired")]
    [InlineData("entitlement-subject-divergent")]
    [InlineData("authorization-release-divergent")]
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

    /// <summary>
    /// An exact CONSUMED replay rechecks current authority and returns a 422 denial, not a
    /// 409 idempotency conflict, after each credential, lineage or commercial mutation.
    /// </summary>
    [Theory]
    [InlineData("enrollment-invalidated")]
    [InlineData("binding-invalidated")]
    [InlineData("license-inactive")]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("seat-inactive")]
    [InlineData("hardware-banned")]
    [InlineData("component-banned")]
    [InlineData("approved-binary-changed")]
    [InlineData("authorization-epoch-divergent")]
    [InlineData("entitlement-client-divergent")]
    [InlineData("entitlement-subject-divergent")]
    [InlineData("entitlement-grant-divergent")]
    [InlineData("entitlement-state-invalid")]
    [InlineData("entitlement-expired")]
    [InlineData("enrollment-client-divergent")]
    [InlineData("binding-owner-divergent")]
    [InlineData("binding-subject-divergent")]
    [InlineData("binding-grant-divergent")]
    [InlineData("authorization-release-divergent")]
    [InlineData("runtime-epoch-changed")]
    [InlineData("security-epoch-changed")]
    [InlineData("runtime-key-changed")]
    public async Task LicenseBootstrap_ExactReplayAfterAuthorityChange_FailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await MutateBootstrapReplayAuthorityAsync(scenario, mutation);

        var exception = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, exception.StatusCode);
        Assert.Equal("bootstrap_ineligible", exception.ErrorCode);
    }

    /// <summary>
    /// A replay racing binding revocation either returns its original bytes before the
    /// revocation commits or receives a 422 afterward; every later replay remains denied.
    /// </summary>
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
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, exception.StatusCode);
            Assert.Equal("bootstrap_ineligible", exception.ErrorCode);
        }
        await revocation;

        var finalReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, finalReplay.StatusCode);
        Assert.Equal("bootstrap_ineligible", finalReplay.ErrorCode);
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

    /// <summary>
    /// A mutable seat hardware value supplies the new signed file, while the bootstrap
    /// authorization retains its original hardware digest and the Runtime key and epochs stay put.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_SameSeatHardwareChange_UsesCurrentSeatWithoutRewritingHistoricalAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issueRequest = scenario.NewIssueRequest();
        var issueDigest = Sha256("same-seat-hardware-issue");
        var issued = await scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        string historicalDigest;
        string publicKey;
        string currentHardware = "runtime-bootstrap-rotated-" + Guid.NewGuid().ToString("N");
        int originalEpoch;
        int originalSecurityEpoch;
        long originalAuthorityEpoch;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var authorization = await db.DistributionLicenseBootstrapAuthorizations.SingleAsync();
            var enrollment = await db.RuntimeEnrollments.SingleAsync();
            var binding = await db.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == authorization.BindingId);
            var seat = await db.LicenseSeats.SingleAsync(row => row.Id == authorization.LicenseSeatId);
            historicalDigest = authorization.HardwareIdHash;
            publicKey = (await db.Products.SingleAsync(row => row.Id == scenario.Fixture.ProductId)).PublicKeyXml;
            originalEpoch = enrollment.Epoch;
            originalSecurityEpoch = enrollment.SecurityEpoch;
            originalAuthorityEpoch = enrollment.AuthorityEpoch;
            seat.HardwareId = currentHardware;
            binding.HardwareIdHash = Sha256(currentHardware);
            await db.SaveChangesAsync();
        }

        var issueReplay = await scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        Assert.True(issueReplay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, issueReplay.ExactResponseBody);
        var reminted = await scenario.Bootstrap.RemintAsync("website-step1",
            Sha256("same-seat-hardware-remint"), scenario.NewRemintRequest(issued.Response.BootstrapId));
        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = reminted.Response.BootstrapId, Capability = reminted.Response.Capability
        };
        var digest = Sha256("same-seat-hardware-redeem");
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var redeemed = await scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var validation = LicenseService.ValidateLicense(redeemed.Response.LicenseFile, publicKey, currentHardware);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var seat = await db.LicenseSeats.SingleAsync();
            seat.HardwareId = "runtime-bootstrap-later-seat-" + Guid.NewGuid().ToString("N");
            await db.SaveChangesAsync();
        }
        // A consumed generation may replay only its frozen bytes after the new current-B
        // check. It must never silently regenerate a different file for the later hardware.
        var exactReplay = await scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.True(exactReplay.Idempotent);
        Assert.Equal(redeemed.ExactResponseBody, exactReplay.ExactResponseBody);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var unchanged = await verify.RuntimeEnrollments.SingleAsync();
        Assert.Equal(originalEpoch, unchanged.Epoch);
        Assert.Equal(originalSecurityEpoch, unchanged.SecurityEpoch);
        Assert.Equal(originalAuthorityEpoch, unchanged.AuthorityEpoch);
        Assert.Equal(historicalDigest,
            (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).HardwareIdHash);
        Assert.Single(await verify.EnrollmentLicenseAssignments.Where(row => row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// A second connection changes the same seat and optionally bans its new hardware before
    /// committing. Redemption waits for the existing global authority lock, then either signs
    /// the exact validated seat value or refuses the ban without consuming the capability.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LicenseBootstrap_ConcurrentSeatHardwareAndBan_UsesOneCommercialSnapshot(bool banNewHardware)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = issued.Response.BootstrapId, Capability = issued.Response.Capability
        };
        var digest = Sha256("seat-hardware-ban-race-" + banNewHardware);
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var newHardware = "runtime-bootstrap-race-hwid-" + Guid.NewGuid().ToString("N");
        await using var writer = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options);
        await using var transaction = await writer.Database.BeginTransactionAsync();
        var seat = await writer.LicenseSeats.SingleAsync();
        seat.HardwareId = newHardware;
        if (banNewHardware)
            writer.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = newHardware, ProductId = scenario.Fixture.ProductId,
                Reason = "bootstrap seat snapshot regression", IsActive = true
            });
        await writer.SaveChangesAsync();

        var redemption = scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await Task.Delay(200);
        Assert.False(redemption.IsCompleted);
        await transaction.CommitAsync().WaitAsync(TimeSpan.FromSeconds(20));

        if (banNewHardware)
        {
            var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(
                async () => await redemption.WaitAsync(TimeSpan.FromSeconds(20)));
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
            Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
            Assert.Equal("hardware_banned", denied.DiagnosticCode);
        }
        else
        {
            var accepted = await redemption.WaitAsync(TimeSpan.FromSeconds(20));
            await using var reader = await scenario.Factory.CreateDbContextAsync();
            var publicKey = (await reader.Products.SingleAsync()).PublicKeyXml;
            var validation = LicenseService.ValidateLicense(accepted.Response.LicenseFile, publicKey, newHardware);
            Assert.True(validation.IsValid, validation.ErrorMessage);
        }

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(1, enrollment.Epoch);
        Assert.Equal(1, enrollment.SecurityEpoch);
        Assert.Equal(newHardware, (await verify.LicenseSeats.SingleAsync()).HardwareId);
        Assert.Equal(banNewHardware ? "ISSUED" : "CONSUMED",
            (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).State);
        Assert.Equal(banNewHardware ? "ISSUED" : "CONSUMED",
            (await verify.DistributionLicenseBootstrapCapabilities.SingleAsync()).State);
    }

    /// <summary>
    /// A real RuntimeEnrollments terminal update holds its row through the deferred item-2
    /// assignment trigger. Redemption must wait in the same order, finish without deadlock,
    /// and cannot consume a generation after the writer ends its commercial authority.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_ConcurrentEnrollmentTerminationAndRedeem_IsAtomic()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = issued.Response.BootstrapId, Capability = issued.Response.Capability
        };
        var digest = Sha256("enrollment-termination-race-redeem");
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        await using var writer = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options);
        await using var transaction = await writer.Database.BeginTransactionAsync();
        var enrollment = await writer.RuntimeEnrollments.SingleAsync();
        enrollment.State = "INVALIDATED";
        enrollment.InvalidatedAtUtc = DateTime.UtcNow;
        enrollment.InvalidationReason = "bootstrap_termination_race";
        await writer.SaveChangesAsync();

        var redemption = scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await Task.Delay(200);
        Assert.False(redemption.IsCompleted);
        await transaction.CommitAsync().WaitAsync(TimeSpan.FromSeconds(20));
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(
            async () => await redemption.WaitAsync(TimeSpan.FromSeconds(20)));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
        Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var terminal = await verify.RuntimeEnrollments.SingleAsync();
        Assert.Equal("INVALIDATED", terminal.State);
        Assert.Equal(1, terminal.Epoch);
        Assert.Equal(1, terminal.SecurityEpoch);
        Assert.Empty(await verify.EnrollmentLicenseAssignments.Where(row => row.State == "ACTIVE").ToListAsync());
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).State);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapCapabilities.SingleAsync()).State);
    }

    /// <summary>
    /// A missing or quarantined enrollment has no current commercial grant even while its key, pending
    /// state and previously issued capability remain valid historical evidence.
    /// </summary>
    [Theory]
    [InlineData(false, "assignment_missing")]
    [InlineData(true, "assignment_quarantined")]
    public async Task LicenseBootstrap_MissingOrQuarantinedAssignment_DeniesWithoutCryptoMutation(
        bool quarantine, string expectedReason)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        await using (var admin = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options))
        {
            var assignment = await admin.EnrollmentLicenseAssignments.SingleAsync();
            admin.EnrollmentLicenseAssignments.Remove(assignment);
            if (quarantine)
                admin.EnrollmentLicenseAssignmentQuarantines.Add(new EnrollmentLicenseAssignmentQuarantine
                {
                    EnrollmentId = scenario.EnrollmentId, BindingId = scenario.Fixture.BindingId,
                    LicenseId = assignment.LicenseId, LicenseSeatId = assignment.LicenseSeatId,
                    Reason = "live_state_mismatch", ObservedAtUtc = DateTime.UtcNow
                });
            await admin.SaveChangesAsync();
        }

        var remint = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RemintAsync("website-step1", Sha256("quarantined-remint"),
                scenario.NewRemintRequest(issued.Response.BootstrapId)));
        Assert.Equal("bootstrap_ineligible", remint.ErrorCode);
        Assert.Equal(expectedReason, remint.ReasonCode);
        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = issued.Response.BootstrapId, Capability = issued.Response.Capability
        };
        var digest = Sha256("quarantined-redeem");
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RedeemLicenseBootstrapAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
        Assert.Equal(expectedReason, denied.DiagnosticCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(1, enrollment.Epoch);
        Assert.Equal(1, enrollment.SecurityEpoch);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).State);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapCapabilities.SingleAsync()).State);
        Assert.Empty(await verify.EnrollmentLicenseAssignments.ToListAsync());
    }

    /// <summary>
    /// Moving the current assignment to a different live seat cannot retarget an earlier
    /// bootstrap generation or its exact S2S replay to that seat.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_AssignmentSeatChange_RejectsOldGenerationWithoutEnrollmentMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issueRequest = scenario.NewIssueRequest();
        var issueDigest = Sha256("seat-transfer-issue");
        var issued = await scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        Guid replacementSeatId;
        await using (var admin = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options))
        {
            var assignment = await admin.EnrollmentLicenseAssignments.SingleAsync();
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.MaxSeats = 2;
            var replacement = new LicenseSeat
            {
                LicenseId = license.Id, HardwareId = "runtime-bootstrap-new-seat-" + Guid.NewGuid().ToString("N"),
                IsActive = true
            };
            replacementSeatId = replacement.Id;
            admin.LicenseSeats.Add(replacement);
            await admin.SaveChangesAsync();
        }
        // A separate administrator transaction simulates the commercial cutover after
        // the item-2 graph trigger has settled the newly active seat.
        await using (var admin = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options))
        {
            var assignment = await admin.EnrollmentLicenseAssignments.SingleAsync();
            assignment.LicenseSeatId = replacementSeatId;
            await admin.SaveChangesAsync();
        }

        var replay = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest));
        Assert.Equal("bootstrap_ineligible", replay.ErrorCode);
        var remint = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RemintAsync("website-step1", Sha256("seat-transfer-remint"),
                scenario.NewRemintRequest(issued.Response.BootstrapId)));
        Assert.Equal("bootstrap_ineligible", remint.ErrorCode);
        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = issued.Response.BootstrapId, Capability = issued.Response.Capability
        };
        var digest = Sha256("seat-transfer-redeem");
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RedeemLicenseBootstrapAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("PENDING", (await verify.RuntimeEnrollments.SingleAsync()).State);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).State);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapCapabilities.SingleAsync()).State);
    }

    /// <summary>
    /// A second PostgreSQL connection stages an assignment seat transfer behind the exclusive
    /// item-2 authority barrier. Redemption must wait for its commit, observe the new scope and
    /// roll back without consuming the old generation or changing enrollment identity.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_AssignmentTransferRacingRedeem_FailsClosedAfterBarrier()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issued = await scenario.IssueAsync();
        Guid replacementSeatId;
        await using (var admin = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options))
        {
            var assignment = await admin.EnrollmentLicenseAssignments.SingleAsync();
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.MaxSeats = 2;
            var replacement = new LicenseSeat
            {
                LicenseId = license.Id, HardwareId = "runtime-bootstrap-race-seat-" + Guid.NewGuid().ToString("N"),
                IsActive = true
            };
            replacementSeatId = replacement.Id;
            admin.LicenseSeats.Add(replacement);
            await admin.SaveChangesAsync();
        }
        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = issued.Response.BootstrapId, Capability = issued.Response.Capability
        };
        var digest = Sha256("assignment-transfer-race-redeem");
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);

        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var barrier = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", writer, transaction))
            await barrier.ExecuteNonQueryAsync();
        await using (var transfer = new NpgsqlCommand("""
            UPDATE public."EnrollmentLicenseAssignments"
            SET "LicenseSeatId" = @seat
            WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
            """, writer, transaction))
        {
            transfer.Parameters.AddWithValue("seat", replacementSeatId);
            transfer.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await transfer.ExecuteNonQueryAsync());
        }
        var redeem = scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await Task.Delay(200);
        Assert.False(redeem.IsCompleted);
        await transaction.CommitAsync();
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => redeem);
        Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("PENDING", (await verify.RuntimeEnrollments.SingleAsync()).State);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).State);
        Assert.Equal("ISSUED", (await verify.DistributionLicenseBootstrapCapabilities.SingleAsync()).State);
        Assert.Equal(replacementSeatId,
            (await verify.EnrollmentLicenseAssignments.SingleAsync()).LicenseSeatId);
    }

    /// <summary>
    /// A non-hardware policy mutation bumps the legacy global lease epoch but cannot change
    /// bootstrap credential identity. Its later commercial denial must be attributed to B.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_CommercialEpochBump_RechecksPolicyWithoutChangingCrypto()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var issueRequest = scenario.NewIssueRequest();
        var issueDigest = Sha256("policy-epoch-issue");
        var issued = await scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        long enrollmentAuthorityEpoch;
        long globalEpoch;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            enrollmentAuthorityEpoch = (await db.RuntimeEnrollments.SingleAsync()).AuthorityEpoch;
            globalEpoch = await db.RuntimeEnrollmentAuthorityStates.Select(row => row.Epoch).SingleAsync();
            var license = await db.Licenses.SingleAsync();
            license.MaxSeats += 1;
            await db.SaveChangesAsync();
        }
        await using (var db = await scenario.Factory.CreateDbContextAsync())
            Assert.True(await db.RuntimeEnrollmentAuthorityStates.Select(row => row.Epoch).SingleAsync() > globalEpoch);
        var replay = await scenario.Bootstrap.IssueAsync("website-step1", issueDigest, issueRequest);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);

        var request = new RuntimeLicenseBootstrapRedeemRequest
        {
            Schema = RuntimeEnrollmentService.LicenseBootstrapSchema,
            RequestId = Guid.NewGuid().ToString("D"), ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            BootstrapId = issued.Response.BootstrapId, Capability = issued.Response.Capability
        };
        var digest = Sha256("policy-epoch-redeem");
        var proof = Proof(scenario.EnrollmentKey, "license-bootstrap", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var redeemed = await scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var exactReplay = await scenario.Runtime.RedeemLicenseBootstrapAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.True(exactReplay.Idempotent);
        Assert.Equal(redeemed.ExactResponseBody, exactReplay.ExactResponseBody);

        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.SingleAsync();
            license.IsActive = false;
            await db.SaveChangesAsync();
        }
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RedeemLicenseBootstrapAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
        Assert.Equal("bootstrap_ineligible", denied.ErrorCode);
        Assert.Equal("assignment_missing", denied.DiagnosticCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(1, enrollment.Epoch);
        Assert.Equal(1, enrollment.SecurityEpoch);
        Assert.Equal(enrollmentAuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.Equal(enrollmentAuthorityEpoch,
            (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).AuthorityEpoch);
        Assert.Equal("CONSUMED", (await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync()).State);
        Assert.Equal("CONSUMED", (await verify.DistributionLicenseBootstrapCapabilities.SingleAsync()).State);
    }

    /// <summary>
    /// A broken assignment relation is infrastructure corruption; exact Runtime replay must
    /// retain 503 instead of translating the validator's unavailable result into a 409 denial.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_ReplayWithMissingAssignmentRelation_PreservesUnavailable()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var drop = new NpgsqlCommand("""
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
            await drop.ExecuteNonQueryAsync();
            await using var breakSeat = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            breakSeat.Parameters.AddWithValue("missing", Guid.NewGuid());
            breakSeat.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await breakSeat.ExecuteNonQueryAsync());
        }
        var unavailable = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.ReplayAsync());
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("authority_unavailable", unavailable.ErrorCode);
        Assert.Equal("assignment_relation_missing", unavailable.DiagnosticCode);
        var s2sUnavailable = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            scenario.Bootstrap.RemintAsync("website-step1", Sha256("missing-assignment-relation-remint"),
                scenario.NewRemintRequest(scenario.Issued!.BootstrapId)));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, s2sUnavailable.StatusCode);
        Assert.Equal("authority_unavailable", s2sUnavailable.ErrorCode);
        Assert.Equal("assignment_relation_missing", s2sUnavailable.ReasonCode);
    }

    /// <summary>
    /// A provider-issued v4 generation keeps its signed provenance and exact bootstrap
    /// response while the new assignment validator supplies only current commercial rights.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_V4AuthorityGeneration_RedeemsAndReplaysExactly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync(useAuthorityGeneration: true);
        await scenario.ConsumeAsync();
        var replay = await scenario.ReplayAsync();
        Assert.True(replay.Idempotent);
        Assert.Equal(scenario.ConsumedResponseBytes, replay.ExactResponseBody);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var entitlement = await verify.DistributionEntitlements.SingleAsync();
        Assert.Equal(4, entitlement.ContractVersion);
        Assert.NotNull(entitlement.AuthorityGenerationId);
        Assert.Single(await verify.EnrollmentLicenseAssignments.Where(row => row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// Historical hexadecimal release hashes may differ in letter case from the canonical
    /// approved baseline. PostgreSQL persists that shape, while their issuance digest still
    /// binds the exact historical text and only hex equality ignores case.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_HistoricalUppercaseBinaryHashes_KeepGenerationUsable()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync();
            binding.ExecutableSha256 = binding.ExecutableSha256.ToUpperInvariant();
            binding.NativeDllSha256 = binding.NativeDllSha256.ToUpperInvariant();
            binding.CoreSha256 = binding.CoreSha256.ToUpperInvariant();
            await db.SaveChangesAsync();
        }
        await scenario.ConsumeAsync();
        var replay = await scenario.ReplayAsync();
        Assert.True(replay.Idempotent);
        Assert.Equal(scenario.ConsumedResponseBytes, replay.ExactResponseBody);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        var bindingCheck = await verify.DistributionInstallationBindings.SingleAsync();
        Assert.Equal(Sha256(string.Join('\n', bindingCheck.ExecutableSha256,
            bindingCheck.NativeDllSha256, bindingCheck.CoreSha256)),
            authorization.ApprovedBinariesDigestSha256);
    }

    /// <summary>
    /// Twenty concurrent redeemers of one reminted capability produce one exact signed
    /// response, and the direct isolated-database fixture drops its own database afterward.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_IssueRemintAndTwentyConcurrentRedeems_ReturnOneExactUnicodeLicense()
    {
        var connections = await ProvisionIsolatedAsync();
        using var databaseCleanup = new BootstrapIsolatedDatabaseCleanup(connections.Admin, connections.App);
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
        Assert.Equal(StatusCodes.Status409Conflict, divergentReplay.StatusCode);
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

    /// <summary>
    /// A historical binding without its subject digest cannot issue a capability; this
    /// direct isolated-database case also owns and drops its generated database.
    /// </summary>
    [Fact]
    public async Task LicenseBootstrap_LegacyBindingWithoutSubjectDigest_FailsClosed()
    {
        var connections = await ProvisionIsolatedAsync();
        using var databaseCleanup = new BootstrapIsolatedDatabaseCleanup(connections.Admin, connections.App);
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

    /// <summary>
    /// Creates the shared prepared scenario, optionally binding its finalized entitlement to one
    /// provider-issued authority generation for v4 provenance tests. The fixture keeps the grant
    /// ownership source aligned with the entitlement contract so PostgreSQL exercises a coherent
    /// v3 or v4 authority graph rather than an impossible mixed-generation state. Preparation
    /// failures drop the generated database; after return the scenario owns that cleanup.
    /// </summary>
    private static async Task<PreparedBootstrapScenario> CreatePreparedBootstrapScenarioAsync(
        bool useAuthorityGeneration = false, string? initialHardwareId = null, string? initialSubjectRef = null)
    {
        var connections = await ProvisionIsolatedAsync();
        using var cleanupOnPreparationFailure = new BootstrapIsolatedDatabaseCleanup(
            connections.Admin, connections.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.979", initialHardwareId: initialHardwareId);
        Tkt000686Authority? projectedAuthority = null;
        if (useAuthorityGeneration)
        {
            await using var authorityDb = await factory.CreateDbContextAsync();
            var bindingAuthority = await authorityDb.DistributionInstallationBindings.AsNoTracking()
                .Where(row => row.Id == fixture.BindingId)
                .Select(row => new
                {
                    row.GrantRef,
                    row.ExecutableSha256,
                    row.NativeDllSha256,
                    row.CoreSha256
                })
                .SingleAsync();
            var approvedRows = await authorityDb.ApprovedBinaries
                .Where(row => row.ProductId == fixture.ProductId && row.Version == fixture.Version)
                .ToListAsync();
            authorityDb.ApprovedBinaries.RemoveRange(approvedRows);
            await authorityDb.SaveChangesAsync();
            var artifacts = new List<ApprovedBinaryArtifact>
            {
                new("FP_EXE", bindingAuthority.ExecutableSha256),
                new("FP_DLL", bindingAuthority.NativeDllSha256),
                new("FP_CORE", bindingAuthority.CoreSha256)
            };
            var registration = await new ApprovedBinaryService(
                    factory, NullLogger<ApprovedBinaryService>.Instance)
                .RegisterReleaseBaselineAsync(
                    fixture.ProductId,
                    fixture.Version,
                    $"tkt000699-{fixture.ProductId:D}",
                    new string('e', 64),
                    artifacts);
            Assert.Equal(ApprovedBinaryVerdict.Approved, registration.Result.Verdict);
            var artifactDigest = Assert.IsType<string>(registration.Result.BaselineDigestSha256);
            projectedAuthority = await PersistTkt000686AuthorityAsync(
                factory, fixture.ProductId, fixture.Version, bindingAuthority.GrantRef, artifactDigest);
        }
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
            binding.SubjectRefDigestSha256 = Sha256(initialSubjectRef ?? "website-subject-ref");
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
                AuthorityLineageId = projectedAuthority?.LineageId,
                AuthorityGenerationId = projectedAuthority?.GenerationId,
                ArtifactSetDigestSha256 = projectedAuthority?.ArtifactDigest,
                ContractVersion = useAuthorityGeneration ? 4 : 3,
                State = "finalized",
                IssuedAtUtc = DateTime.UtcNow.AddMinutes(-2),
                ExpiresAtUtc = DateTime.UtcNow.AddHours(1),
                FinalizedAtUtc = DateTime.UtcNow.AddMinutes(-1)
            });
            var grantOwnership = await db.DistributionGrantOwnerships.SingleAsync(row =>
                row.ProductId == binding.ProductId
                && row.GrantRefDigestSha256 == binding.GrantRefDigestSha256);
            grantOwnership.Source = useAuthorityGeneration ? "issue_v4" : "issue_v3";
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
        var scenario = new PreparedBootstrapScenario(
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
        cleanupOnPreparationFailure.Disarm();
        return scenario;
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

    /// <summary>
    /// Applies one admissible PostgreSQL authority change to an isolated bootstrap fixture.
    /// Historical authorization-field divergence covers frozen lineage; commercial graph
    /// changes must pass the item-2 dual-write trigger rather than manufacturing a live graph
    /// that its transaction would reject. Each caller observes the resulting public refusal.
    /// </summary>
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
            case "authorization-epoch-divergent":
                authorization.AuthorityEpoch += 1;
                break;
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
            case "authorization-release-divergent":
                authorization.ReleaseVersion = "2.2.980";
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

    /// <summary>
    /// Owns only the uniquely provisioned bootstrap test database. Its generated-name and
    /// captured catalog-OID checks prevent cleanup of the maintenance or a replacement database.
    /// </summary>
    private sealed class BootstrapIsolatedDatabaseCleanup : IDisposable
    {
        /// <summary>Exact administrator connection targeting the generated database, for pool clearing.</summary>
        private readonly string _adminConnectionString;
        /// <summary>Exact application-role connection targeting the generated database, for pool clearing.</summary>
        private readonly string _appConnectionString;
        /// <summary>Administrator connection targeting postgres so DROP runs outside its target.</summary>
        private readonly string _maintenanceConnectionString;
        /// <summary>Strictly validated generated identifier; never user-supplied database text.</summary>
        private readonly string _databaseName;
        /// <summary>Catalog identity captured when this fixture took ownership of its database.</summary>
        private readonly uint _databaseOid;
        /// <summary>Original database owner OID; a role change never authorizes cleanup.</summary>
        private readonly uint _databaseOwnerOid;
        /// <summary>Fixture administrator role allowed to retain only an idle connection at cleanup.</summary>
        private readonly string _adminRole;
        /// <summary>Fixture application role allowed to retain only an idle connection at cleanup.</summary>
        private readonly string _appRole;
        /// <summary>True after cleanup ownership is transferred or the exact database is dropped.</summary>
        private bool _disarmed;

        /// <summary>
        /// Captures the exact generated database, catalog OID, fixture roles and a separate
        /// maintenance connection. Rejects a name outside the harness GUID grammar.
        /// </summary>
        /// <param name="adminConnectionString">Administrator connection targeting the generated database.</param>
        /// <param name="appConnectionString">Application connection targeting that same database.</param>
        internal BootstrapIsolatedDatabaseCleanup(string adminConnectionString, string appConnectionString)
        {
            var builder = new NpgsqlConnectionStringBuilder(adminConnectionString);
            const string prefix = "softlicence_runtime_rotation_";
            var database = builder.Database;
            if (database is null || !database.StartsWith(prefix, StringComparison.Ordinal)
                || !Guid.TryParseExact(database[prefix.Length..], "N", out _))
                throw new InvalidOperationException("Bootstrap test database name is not generated by the isolated harness.");
            _databaseName = database;
            _adminConnectionString = adminConnectionString;
            _appConnectionString = appConnectionString;
            _adminRole = builder.Username
                ?? throw new InvalidOperationException("Bootstrap test administrator role is missing.");
            _appRole = new NpgsqlConnectionStringBuilder(appConnectionString).Username
                ?? throw new InvalidOperationException("Bootstrap test application role is missing.");
            builder.Database = "postgres";
            _maintenanceConnectionString = builder.ConnectionString;
            using var maintenance = new NpgsqlConnection(_maintenanceConnectionString);
            maintenance.Open();
            using var lookup = new NpgsqlCommand(
                "SELECT oid, datdba FROM pg_catalog.pg_database WHERE datname = @name;", maintenance);
            lookup.Parameters.AddWithValue("name", _databaseName);
            using var identity = lookup.ExecuteReader();
            if (!identity.Read())
                throw new InvalidOperationException("Generated bootstrap test database is absent at ownership transfer.");
            _databaseOid = identity.GetFieldValue<uint>(0);
            _databaseOwnerOid = identity.GetFieldValue<uint>(1);
        }

        /// <summary>Transfers successful scenario cleanup to its returned owning fixture.</summary>
        internal void Disarm() => _disarmed = true;

        /// <summary>
        /// Clears fixture pools, verifies the original catalog OID and absence of active work
        /// or foreign roles, then drops only that generated database. PostgreSQL may retain an
        /// idle fixture connection after pool clearing; FORCE closes those task-owned sessions.
        /// </summary>
        public void Dispose()
        {
            if (_disarmed)
                return;
            using var app = new NpgsqlConnection(_appConnectionString);
            using var admin = new NpgsqlConnection(_adminConnectionString);
            NpgsqlConnection.ClearPool(app);
            NpgsqlConnection.ClearPool(admin);
            using var maintenance = new NpgsqlConnection(_maintenanceConnectionString);
            maintenance.Open();
            using (var inspect = new NpgsqlCommand("""
                SELECT d.oid, d.datdba,
                       (SELECT count(*) FROM pg_catalog.pg_stat_activity a
                        WHERE a.datname = d.datname
                          AND (a.state IS DISTINCT FROM 'idle'
                               OR a.usename NOT IN (@admin_role, @app_role))),
                       (SELECT count(*) FROM pg_catalog.pg_stat_activity a
                        WHERE a.datname = d.datname AND a.backend_type = 'client backend'
                          AND a.state IS DISTINCT FROM 'idle'),
                       (SELECT count(*) FROM pg_catalog.pg_stat_activity a
                        WHERE a.datname = d.datname AND a.backend_type = 'client backend'
                          AND a.usename NOT IN (@admin_role, @app_role)),
                       (SELECT count(*) FROM pg_catalog.pg_stat_activity a
                        WHERE a.datname = d.datname AND a.backend_type = 'autovacuum worker')
                FROM pg_catalog.pg_database d WHERE d.datname = @name;
                """, maintenance))
            {
                inspect.Parameters.AddWithValue("name", _databaseName);
                inspect.Parameters.AddWithValue("admin_role", _adminRole);
                inspect.Parameters.AddWithValue("app_role", _appRole);
                using var reader = inspect.ExecuteReader();
                if (!reader.Read())
                    throw new InvalidOperationException("Generated bootstrap cleanup refused: database_exists=False.");
                var oidMatches = reader.GetFieldValue<uint>(0) == _databaseOid;
                var ownerMatches = reader.GetFieldValue<uint>(1) == _databaseOwnerOid;
                var blockedSessions = reader.GetInt64(2);
                if (!oidMatches || !ownerMatches || blockedSessions != 0)
                    throw new InvalidOperationException(
                        $"Generated bootstrap cleanup refused: oid_match={oidMatches}; owner_match={ownerMatches}; "
                        + $"blocked_sessions={blockedSessions}; active_clients={reader.GetInt64(3)}; "
                        + $"foreign_clients={reader.GetInt64(4)}; autovacuum_workers={reader.GetInt64(5)}.");
            }
            // Only idle fixture-role sessions can remain after the identity/use check. FORCE
            // closes these own pooled connections, while any active work stops cleanup above.
            using var command = new NpgsqlCommand(
                $"DROP DATABASE \"{_databaseName}\" WITH (FORCE);", maintenance);
            command.ExecuteNonQuery();
            _disarmed = true;
        }
    }

    /// <summary>
    /// Owns a prepared Runtime bootstrap graph, local signing keys and its uniquely generated
    /// PostgreSQL database; disposal releases keys and then drops only that database.
    /// </summary>
    private sealed class PreparedBootstrapScenario : IDisposable
    {
        /// <summary>Current signing key retained until scenario disposal.</summary>
        private readonly RSA _runtimeSigning;
        /// <summary>Next signing key retained until scenario disposal.</summary>
        private readonly RSA _nextSigning;
        /// <summary>Installation possession key retained until scenario disposal.</summary>
        private readonly RSA _enrollmentKey;
        /// <summary>Encrypted-field service retaining local key material until disposal.</summary>
        private readonly RuntimeEnrollmentCryptoService _crypto;
        /// <summary>Signed license generator configured for this product fixture.</summary>
        private readonly ISignedLicenseFileService _signedLicenseFiles;
        /// <summary>Exact administrator connection to this scenario's generated database.</summary>
        private readonly string _adminConnectionString;
        /// <summary>Exact application-role connection to this scenario's generated database.</summary>
        private readonly string _appConnectionString;
        /// <summary>Owns the exact generated database after preparation succeeds.</summary>
        private readonly BootstrapIsolatedDatabaseCleanup _databaseCleanup;

        /// <summary>Creates application-role contexts for the generated database.</summary>
        public TestDbFactory Factory { get; }
        /// <summary>Seeded product, binding, handoff, installation and release identifiers.</summary>
        public (Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version) Fixture { get; }
        /// <summary>Protocol and signing configuration used by both bootstrap services.</summary>
        public RuntimeEnrollmentOptions Options { get; }
        /// <summary>Runtime service under test.</summary>
        public RuntimeEnrollmentService Runtime { get; }
        /// <summary>Distribution bootstrap service under test.</summary>
        public DistributionLicenseBootstrapService Bootstrap { get; }
        /// <summary>Persisted prepare response including the challenge used for proof.</summary>
        public RuntimeEnrollmentPrepareResponse Prepared { get; }
        /// <summary>Exact prepare request that created the enrollment.</summary>
        public RuntimeEnrollmentPrepareRequest PrepareRequest { get; }
        /// <summary>Digest of the exact prepare request.</summary>
        public string PrepareDigest { get; }
        /// <summary>Installation key used to sign redemption proofs until disposal.</summary>
        public RSA EnrollmentKey => _enrollmentKey;
        /// <summary>Most recently issued generation retained for exact replay checks.</summary>
        public DistributionLicenseBootstrapIssuedResponse? Issued { get; private set; }
        /// <summary>Exact redeem request retained after ConsumeAsync.</summary>
        public RuntimeLicenseBootstrapRedeemRequest? RedeemRequest { get; private set; }
        /// <summary>Possession proof retained after ConsumeAsync for byte-identical replay.</summary>
        public RuntimeProofHeaders? ReplayProof { get; private set; }
        /// <summary>Exact body digest retained after ConsumeAsync for replay.</summary>
        public string? RedeemDigest { get; private set; }
        /// <summary>Original signed response bytes retained after ConsumeAsync.</summary>
        public byte[]? ConsumedResponseBytes { get; private set; }
        /// <summary>Canonical UUID parsed from the prepared enrollment response.</summary>
        public Guid EnrollmentId => Guid.Parse(Prepared.EnrollmentId);

        /// <summary>Gets the application-role PostgreSQL connection used by HTTP integration tests.</summary>
        public string AppConnectionString => _appConnectionString;

        /// <summary>Gets the PostgreSQL administrator connection used only for migration lifecycle tests.</summary>
        public string AdminConnectionString => _adminConnectionString;

        /// <summary>Gets the signer bound to the scenario product encryption authority.</summary>
        public ISignedLicenseFileService SignedLicenseFiles => _signedLicenseFiles;

        /// <summary>
        /// Transfers a fully prepared v3/v4 bootstrap fixture and its database cleanup to the
        /// returned scenario. Every supplied key and cryptographic service is scenario-owned.
        /// </summary>
        /// <param name="factory">Application-role EF context factory for the generated database.</param>
        /// <param name="adminConnectionString">Administrator connection to that exact database.</param>
        /// <param name="appConnectionString">Application-role connection to that exact database.</param>
        /// <param name="fixture">Seeded product, binding, handoff, installation and release scope.</param>
        /// <param name="options">Runtime protocol and signing configuration.</param>
        /// <param name="runtimeSigning">Current Runtime signing key owned by this scenario.</param>
        /// <param name="nextSigning">Next Runtime signing key owned by this scenario.</param>
        /// <param name="enrollmentKey">Installation possession key owned by this scenario.</param>
        /// <param name="crypto">Cipher service owned by this scenario.</param>
        /// <param name="runtime">Runtime service under test.</param>
        /// <param name="signedLicenseFiles">License file signer under test.</param>
        /// <param name="bootstrap">Distribution bootstrap service under test.</param>
        /// <param name="prepared">Persisted Runtime prepare response.</param>
        /// <param name="prepareRequest">Exact prepare request used to build that response.</param>
        /// <param name="prepareDigest">Exact request digest used for prepare.</param>
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
            _databaseCleanup = new BootstrapIsolatedDatabaseCleanup(adminConnectionString, appConnectionString);
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

        /// <summary>
        /// Releases in-memory keys, clears fixture connection pools, then drops only the
        /// validated generated database. A DROP failure surfaces as a test failure.
        /// </summary>
        public void Dispose()
        {
            _crypto.Dispose();
            _enrollmentKey.Dispose();
            _nextSigning.Dispose();
            _runtimeSigning.Dispose();
            _databaseCleanup.Dispose();
        }
    }
}
