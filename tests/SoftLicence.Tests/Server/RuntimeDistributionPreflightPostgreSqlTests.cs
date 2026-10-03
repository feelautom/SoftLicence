using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves pre-download decision replay semantics on the production PostgreSQL provider.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Proves two simultaneous exact payloads commit one decision and two observations.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_ConcurrentExactReplaySerializesToOneDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        var responses = await Task.WhenAll(
            service.EvaluateAsync("tia-connect-website", new string('d', 64), scenario.Request, CancellationToken.None),
            service.EvaluateAsync("tia-connect-website", new string('d', 64), scenario.Request, CancellationToken.None));

        Assert.Equal(responses[0], responses[1]);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.SingleAsync();
        Assert.Equal(2, decision.AttemptCount);
        Assert.Equal("accepted", decision.Outcome);
    }

    /// <summary>Proves an ordinary no-ban decision never waits for exclusive global mutation authority.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_NoBanFastPathDoesNotTakeGlobalMutationAuthority()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await AcquireGlobalMutationAuthorityAsync(blocker, transaction);

        var response = await service.EvaluateAsync(
            "tia-connect-website", new string('1', 64), scenario.Request, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal("accepted", response.Decision);
        await transaction.RollbackAsync();
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("accepted", decision.Outcome);
        Assert.Equal(1, decision.AttemptCount);
    }

    /// <summary>Proves a permanent-ban refusal stays on pass one while exclusive global authority is held.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_PermanentBanFastPathDoesNotWaitForGlobalMutationAuthority()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-PERMANENT";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.Piracy);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await AcquireGlobalMutationAuthorityAsync(blocker, transaction);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.EvaluateAsync(
                    "tia-connect-website", new string('7', 64), scenario.Request, CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("hardware_banned", exception.ReasonCode);
        await transaction.RollbackAsync();
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal(1, decision.AttemptCount);
        Assert.True((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>
    /// Proves paid auto-unban rolls the read pass back before waiting for global authority, then commits
    /// the ban change and first decision atomically from a fully recomputed mutation pass.
    /// </summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_PaidAutoUnbanRestartsWithoutReadPassSideEffects()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        const string applicationName = "tkt001312-d2l2-new-auto-unban";
        var app = NamedFactory(database.App, applicationName);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-NEW";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.OutdatedVersion);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await AcquireGlobalMutationAuthorityAsync(blocker, transaction);

        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('2', 64), scenario.Request, CancellationToken.None);
        await WaitForGlobalMutationAuthorityWaiterAsync(database.Admin, applicationName, blocker.ProcessID);
        await using (var beforeRelease = await admin.CreateDbContextAsync())
        {
            Assert.False(await beforeRelease.RuntimeDistributionHardwareDecisions.AnyAsync());
            Assert.True((await beforeRelease.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
        }

        await transaction.RollbackAsync();
        var response = await evaluation;

        Assert.Equal("accepted", response.Decision);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("auto-unbanned", decision.Outcome);
        Assert.Equal("paid_auto_unban", decision.ReasonCode);
        Assert.Equal(1, decision.AttemptCount);
        Assert.Equal(1, decision.AutoUnbannedCount);
        Assert.False((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>Proves identical requests crossing the restart create once and then replay exactly once.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_ConcurrentIdenticalRequestsAcrossRestartCommitOneDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        const string firstApplication = "tkt001312-d2l2-identical-first";
        const string secondApplication = "tkt001312-d2l2-identical-second";
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-IDENTICAL";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.QuotaAbuse);
        var firstService = new RuntimeDistributionPreflightService(
            NamedFactory(database.App, firstApplication),
            Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var secondService = new RuntimeDistributionPreflightService(
            NamedFactory(database.App, secondApplication),
            Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await AcquireGlobalMutationAuthorityAsync(blocker, transaction);

        var first = firstService.EvaluateAsync(
            "tia-connect-website", new string('8', 64), scenario.Request, CancellationToken.None);
        var second = secondService.EvaluateAsync(
            "tia-connect-website", new string('8', 64), scenario.Request, CancellationToken.None);
        await WaitForGlobalMutationAuthorityWaiterAsync(database.Admin, firstApplication, blocker.ProcessID);
        await WaitForGlobalMutationAuthorityWaiterAsync(database.Admin, secondApplication, blocker.ProcessID);
        await using (var beforeRelease = await admin.CreateDbContextAsync())
        {
            Assert.False(await beforeRelease.RuntimeDistributionHardwareDecisions.AnyAsync());
            Assert.True((await beforeRelease.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
        }

        await transaction.RollbackAsync();
        var responses = await Task.WhenAll(first, second);

        Assert.Equal(responses[0], responses[1]);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("auto-unbanned", decision.Outcome);
        Assert.Equal(2, decision.AttemptCount);
        Assert.Equal(1, decision.AutoUnbannedCount);
        Assert.False((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>Proves replay auto-unban changes only the established mutable replay observation fields.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_AcceptedReplayAutoUnbanPreservesFrozenDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        const string applicationName = "tkt001312-d2l2-replay-auto-unban";
        var app = NamedFactory(database.App, applicationName);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-REPLAY";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var first = await service.EvaluateAsync(
            "tia-connect-website", new string('3', 64), scenario.Request, CancellationToken.None);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.QuotaAbuse);
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await AcquireGlobalMutationAuthorityAsync(blocker, transaction);

        var replay = service.EvaluateAsync(
            "tia-connect-website", new string('3', 64), scenario.Request, CancellationToken.None);
        await WaitForGlobalMutationAuthorityWaiterAsync(database.Admin, applicationName, blocker.ProcessID);
        await using (var beforeRelease = await admin.CreateDbContextAsync())
        {
            var frozen = await beforeRelease.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
            Assert.Equal(1, frozen.AttemptCount);
            Assert.Equal("accepted", frozen.Outcome);
            Assert.Equal("eligible", frozen.ReasonCode);
            Assert.Equal(0, frozen.AutoUnbannedCount);
            Assert.Equal("[]", frozen.BanCategoriesJson);
        }

        await transaction.RollbackAsync();
        var repeated = await replay;

        Assert.Equal(first, repeated);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal(2, decision.AttemptCount);
        Assert.Equal("accepted", decision.Outcome);
        Assert.Equal("eligible", decision.ReasonCode);
        Assert.Equal(0, decision.AutoUnbannedCount);
        Assert.Equal("[]", decision.BanCategoriesJson);
        Assert.False((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>Proves a failed decision insert rolls the staged paid auto-unban back completely.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_AutoUnbanDecisionFailureRollsBackBanMutation()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-ROLLBACK";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.QuotaAbuse);
        await using (var setup = new NpgsqlConnection(database.Admin))
        {
            await setup.OpenAsync();
            await using var command = new NpgsqlCommand("""
                CREATE FUNCTION public.tkt001312_fail_preflight_decision()
                RETURNS trigger LANGUAGE plpgsql AS $body$
                BEGIN
                    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'task_owned_preflight_decision_failure';
                END;
                $body$;
                CREATE TRIGGER tkt001312_fail_preflight_decision
                BEFORE INSERT ON public."RuntimeDistributionHardwareDecisions"
                FOR EACH ROW EXECUTE FUNCTION public.tkt001312_fail_preflight_decision();
                """, setup);
            await command.ExecuteNonQueryAsync();
        }
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        await Assert.ThrowsAsync<DbUpdateException>(() => service.EvaluateAsync(
            "tia-connect-website", new string('4', 64), scenario.Request, CancellationToken.None));

        await using var verification = await admin.CreateDbContextAsync();
        Assert.False(await verification.RuntimeDistributionHardwareDecisions.AnyAsync());
        Assert.True((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>Proves pass two observes a commercial revocation committed after pass-one classification.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_RevocationBetweenPassesPreventsAutoUnban()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var interceptor = new PreflightGlobalMutationPassInterceptor();
        var app = new InterceptedDbFactory(database.App, interceptor);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-REVOKE";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.OutdatedVersion);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('5', 64), scenario.Request, CancellationToken.None);
        await interceptor.MutationPassStarting.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            await using var writer = await admin.CreateDbContextAsync();
            var license = await writer.Licenses.SingleAsync(candidate => candidate.Id == scenario.LicenseId);
            license.RevokedAt = DateTime.UtcNow;
            await writer.SaveChangesAsync();
        }
        finally
        {
            interceptor.Release();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("commercial_authority_invalid", exception.ReasonCode);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal("commercial_authority_invalid", decision.ReasonCode);
        Assert.True((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>Proves a ban reclassified after pass one is recomputed and never auto-unbanned.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_BanReclassifiedBetweenPassesPreventsAutoUnban()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var interceptor = new PreflightGlobalMutationPassInterceptor();
        var app = new InterceptedDbFactory(database.App, interceptor);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001312-D2L2-RECLASSIFY";
        scenario.Request.HardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        await SeedActiveHardwareBanAsync(admin, scenario.ProductId, hardwareId,
            BannedHardwareId.Categories.OutdatedVersion);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('9', 64), scenario.Request, CancellationToken.None);
        await interceptor.MutationPassStarting.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            var security = CreateSecurityService(new TestDbFactory(database.App));
            await security.BanHardwareIdAsync(
                hardwareId, "Task-owned inter-pass piracy reclassification", scenario.ProductId,
                banCategory: BannedHardwareId.Categories.Piracy, silent: true);
        }
        finally
        {
            interceptor.Release();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("hardware_banned", exception.ReasonCode);
        await using var verification = await admin.CreateDbContextAsync();
        var ban = await verification.BannedHardwareIds.AsNoTracking().SingleAsync();
        Assert.True(ban.IsActive);
        Assert.Equal(BannedHardwareId.Categories.Piracy, ban.BanCategory);
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal("hardware_banned", decision.ReasonCode);
        Assert.Equal(0, decision.AutoUnbannedCount);
    }

    /// <summary>Proves an item-2 assignment end committed between passes is authoritative in pass two.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_AssignmentEndedBetweenPassesPreventsAutoUnban()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, "AAAABBBBCCCCDDDD");
        var (clientId, request) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        string hardwareId;
        Guid licenseId;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
        {
            var assignment = await read.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(candidate => candidate.EnrollmentId == scenario.EnrollmentId
                    && candidate.State == "ACTIVE");
            licenseId = assignment.LicenseId;
            hardwareId = await read.LicenseSeats.AsNoTracking()
                .Where(candidate => candidate.Id == assignment.LicenseSeatId)
                .Select(candidate => candidate.HardwareId)
                .SingleAsync();
        }
        await SeedActiveHardwareBanAsync(
            new TestDbFactory(scenario.AdminConnectionString), scenario.Fixture.ProductId,
            hardwareId, BannedHardwareId.Categories.QuotaAbuse);
        var interceptor = new PreflightGlobalMutationPassInterceptor();
        var service = new RuntimeDistributionPreflightService(
            new InterceptedDbFactory(scenario.AppConnectionString, interceptor),
            Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var evaluation = service.EvaluateAsync(
            clientId, new string('a', 64), request, CancellationToken.None);
        await interceptor.MutationPassStarting.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            await using var writer = await new TestDbFactory(scenario.AdminConnectionString)
                .CreateDbContextAsync();
            var license = await writer.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.IsActive = false;
            await writer.SaveChangesAsync();
        }
        finally
        {
            interceptor.Release();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("assignment_missing", exception.ReasonCode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var assignmentAfter = await verification.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(candidate => candidate.EnrollmentId == scenario.EnrollmentId);
        Assert.Equal("ENDED", assignmentAfter.State);
        Assert.True((await verification.BannedHardwareIds.AsNoTracking().SingleAsync()).IsActive);
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal("assignment_missing", decision.ReasonCode);
        Assert.Equal(0, decision.AutoUnbannedCount);
    }

    /// <summary>Proves a corrupt assignment relation remains infrastructure failure and creates no decision.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_BrokenAssignmentRelationReturnsUnavailableWithoutDecision()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, "AAAABBBBCCCCDDDD");
        var (clientId, request) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var command = new NpgsqlCommand("""
                DO $broken_relation$
                DECLARE constraint_name name;
                BEGIN
                    SELECT conname INTO constraint_name
                    FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public."EnrollmentLicenseAssignments"'::pg_catalog.regclass
                      AND confrelid = 'public."LicenseSeats"'::pg_catalog.regclass
                      AND contype = 'f'
                    ORDER BY conname
                    LIMIT 1;
                    IF constraint_name IS NULL THEN
                        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'assignment_seat_fk_missing';
                    END IF;
                    EXECUTE pg_catalog.format(
                        'ALTER TABLE public."EnrollmentLicenseAssignments" DROP CONSTRAINT %I',
                        constraint_name);
                END;
                $broken_relation$;
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            command.Parameters.AddWithValue("missing", Guid.NewGuid());
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            await command.ExecuteNonQueryAsync();
        }
        var service = new RuntimeDistributionPreflightService(
            new TestDbFactory(scenario.AppConnectionString),
            Mock.Of<ILogger<RuntimeDistributionPreflightService>>());

        var unavailable = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.EvaluateAsync(clientId, new string('6', 64), request, CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("assignment_relation_missing", unavailable.ReasonCode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        Assert.False(await verification.RuntimeDistributionHardwareDecisions.AnyAsync());
    }

    /// <summary>Proves an uncommitted revocation blocks preflight and becomes authoritative after commit.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_ConcurrentRevocationWinsBeforeCommercialDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var revoke = await blocker.BeginTransactionAsync();
        await using (var command = blocker.CreateCommand())
        {
            command.Transaction = revoke;
            command.CommandText = "UPDATE \"Licenses\" SET \"RevokedAt\" = @revoked WHERE \"Id\" = @license";
            command.Parameters.AddWithValue("revoked", DateTime.UtcNow);
            command.Parameters.AddWithValue("license", scenario.LicenseId);
            await command.ExecuteNonQueryAsync();
        }

        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('d', 64), scenario.Request, CancellationToken.None);
        await Task.Delay(200);
        Assert.False(evaluation.IsCompleted);
        await revoke.CommitAsync();

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.SingleAsync();
        Assert.Equal("commercial_authority_invalid", decision.ReasonCode);
        Assert.True(decision.LicenseRevoked);
    }

    /// <summary>Proves an accepted exact replay rechecks commercial state after the same row-lock wait.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_AcceptedReplayConcurrentRevocationIsDeniedWithoutRewritingDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await service.EvaluateAsync(
            "tia-connect-website", new string('d', 64), scenario.Request, CancellationToken.None);
        RuntimeDistributionHardwareDecision frozen;
        await using (var beforeDenial = await admin.CreateDbContextAsync())
            frozen = await beforeDenial.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var revoke = await blocker.BeginTransactionAsync();
        await using (var command = blocker.CreateCommand())
        {
            command.Transaction = revoke;
            command.CommandText = "UPDATE \"Licenses\" SET \"RevokedAt\" = clock_timestamp() WHERE \"Id\" = @license";
            command.Parameters.AddWithValue("license", scenario.LicenseId);
            await command.ExecuteNonQueryAsync();
        }

        var replay = service.EvaluateAsync(
            "tia-connect-website", new string('d', 64), scenario.Request, CancellationToken.None);
        await Task.Delay(200);
        Assert.False(replay.IsCompleted);
        await revoke.CommitAsync();

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await replay);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("commercial_authority_invalid", exception.ReasonCode);
        await using var verification = await admin.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal(frozen.Id, decision.Id);
        Assert.Equal(frozen.PayloadDigestSha256, decision.PayloadDigestSha256);
        Assert.Equal(frozen.HardwareIdHash, decision.HardwareIdHash);
        Assert.Equal(frozen.AuthorityMode, decision.AuthorityMode);
        Assert.Equal(frozen.Outcome, decision.Outcome);
        Assert.Equal(frozen.ReasonCode, decision.ReasonCode);
        Assert.Equal(frozen.BanCategoriesJson, decision.BanCategoriesJson);
        Assert.Equal(frozen.AutoUnbannedCount, decision.AutoUnbannedCount);
        Assert.Equal(frozen.AttemptCount, decision.AttemptCount);
        Assert.Equal(frozen.CreatedAtUtc, decision.CreatedAtUtc);
        Assert.Equal(frozen.LastSeenAtUtc, decision.LastSeenAtUtc);
    }

    /// <summary>
    /// Proves a writer holding the enrollment row and committing item-2 terminalization before the shared
    /// barrier is observed by both a new decision and an accepted replay; neither may reuse the old A snapshot.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RuntimeDistributionPreflight_KnownEnrollmentInvalidatedDuringRowWait_IsDeniedAfterBarrier(
        bool acceptedReplay)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, "AAAABBBBCCCCDDDD");
        var (clientId, request) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        const string applicationName = "tkt001312-known-enrollment-race";
        var service = new RuntimeDistributionPreflightService(
            NamedFactory(scenario.AppConnectionString, applicationName),
            Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        const string payloadDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        if (acceptedReplay)
            await service.EvaluateAsync(clientId, payloadDigest, request, CancellationToken.None);

        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var command = writer.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE public."RuntimeEnrollments"
                SET "State" = 'INVALIDATED',
                    "InvalidatedAtUtc" = clock_timestamp(),
                    "InvalidationReason" = 'test_preflight_identity_rotation'
                WHERE "Id" = @enrollment
                """;
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        var evaluation = service.EvaluateAsync(clientId, payloadDigest, request, CancellationToken.None);
        await WaitForAnyLockWaiterAsync(scenario.AdminConnectionString, applicationName);
        Assert.False(evaluation.IsCompleted);
        await transaction.CommitAsync();

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("identity_authority_changed", exception.ReasonCode);
        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var decisions = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().ToListAsync();
        var decision = Assert.Single(decisions);
        if (acceptedReplay)
        {
            Assert.Equal("accepted", decision.Outcome);
            Assert.Equal(1, decision.AttemptCount);
        }
        else
        {
            Assert.Equal("refused", decision.Outcome);
            Assert.Equal("identity_authority_changed", decision.ReasonCode);
        }
    }

    /// <summary>Proves provider time is sampled after a commercial row-lock wait and observes expiry.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_LicenseExpiresDuringCommercialWait_IsDenied()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var app = new TestDbFactory(database.App);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var expiry = await blocker.BeginTransactionAsync();
        await using (var command = blocker.CreateCommand())
        {
            command.Transaction = expiry;
            command.CommandText = "UPDATE \"Licenses\" SET \"ExpirationDate\" = clock_timestamp() + interval '1 second' WHERE \"Id\" = @license";
            command.Parameters.AddWithValue("license", scenario.LicenseId);
            await command.ExecuteNonQueryAsync();
        }

        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('e', 64), scenario.Request, CancellationToken.None);
        await Task.Delay(1500);
        Assert.False(evaluation.IsCompleted);
        await expiry.CommitAsync();

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        Assert.Equal("commercial_authority_invalid", exception.ReasonCode);
        await using var verification = await admin.CreateDbContextAsync();
        Assert.True((await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync())
            .LicenseExpired);
    }

    /// <summary>Proves a piracy ban created while preflight waits is observed before any auto-unban.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_ConcurrentPiracyBanCreationWinsBeforeDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        const string preflightApplication = "tkt001076-preflight-create";
        const string writerApplication = "tkt001076-ban-create";
        var app = NamedFactory(database.App, preflightApplication);
        var writer = NamedFactory(database.App, writerApplication);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001076-CREATE-RACE";
        var hardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        scenario.Request.HardwareIdHash = hardwareIdHash;
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var security = CreateSecurityService(writer);
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var mutation = await blocker.BeginTransactionAsync();
        await AcquireHardwareDigestLockAsync(blocker, mutation, hardwareIdHash);

        var banMutation = security.BanHardwareIdAsync(
            hardwareId, "Forced concurrent piracy creation", scenario.ProductId,
            banCategory: BannedHardwareId.Categories.Piracy, silent: true);
        await WaitForAdvisoryLockWaiterAsync(database.Admin, writerApplication);
        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('e', 64), scenario.Request, CancellationToken.None);
        await WaitForAdvisoryLockWaiterAsync(database.Admin, preflightApplication);
        await mutation.CommitAsync();

        await banMutation;
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        await AssertPermanentBanDecisionAsync(admin, hardwareId, "hardware_banned");
    }

    /// <summary>Proves a concurrent reclassification to piracy cannot be overwritten by auto-unban.</summary>
    [Fact]
    public async Task RuntimeDistributionPreflight_ConcurrentPiracyReclassificationWinsBeforeDecision()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        const string preflightApplication = "tkt001076-preflight-reclassify";
        const string writerApplication = "tkt001076-ban-reclassify";
        var app = NamedFactory(database.App, preflightApplication);
        var writer = NamedFactory(database.App, writerApplication);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        const string hardwareId = "TKT001076-RECLASSIFY-RACE";
        var hardwareIdHash = SecurityService.ComputeHardwareBanDigest(hardwareId);
        scenario.Request.HardwareIdHash = hardwareIdHash;
        await using (var seed = await admin.CreateDbContextAsync())
        {
            seed.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = scenario.ProductId,
                Reason = "Auto-ban: forced outdated version fixture",
                BanCategory = BannedHardwareId.Categories.OutdatedVersion,
                IsActive = true
            });
            await seed.SaveChangesAsync();
        }
        var service = new RuntimeDistributionPreflightService(
            app, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var security = CreateSecurityService(writer);
        await using var blocker = new NpgsqlConnection(database.Admin);
        await blocker.OpenAsync();
        await using var mutation = await blocker.BeginTransactionAsync();
        await AcquireHardwareDigestLockAsync(blocker, mutation, hardwareIdHash);

        var banMutation = security.BanHardwareIdAsync(
            hardwareId, "Forced concurrent piracy reclassification", scenario.ProductId,
            banCategory: BannedHardwareId.Categories.Piracy, silent: true);
        await WaitForAdvisoryLockWaiterAsync(database.Admin, writerApplication);
        var evaluation = service.EvaluateAsync(
            "tia-connect-website", new string('f', 64), scenario.Request, CancellationToken.None);
        await WaitForAdvisoryLockWaiterAsync(database.Admin, preflightApplication);
        await mutation.CommitAsync();

        await banMutation;
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        await AssertPermanentBanDecisionAsync(admin, hardwareId, "hardware_banned");
    }

    /// <summary>Acquires the same canonical digest lock used by preflight and every ban writer.</summary>
    private static async Task AcquireHardwareDigestLockAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string hardwareIdHash)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT pg_advisory_xact_lock(hashtextextended(@key, 999095))";
        command.Parameters.AddWithValue("key", $"hardware-ban-digest|{hardwareIdHash}");
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Acquires the exact exclusive global mutation key used by every protected authority writer.</summary>
    private static async Task AcquireGlobalMutationAuthorityAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Proves the named preflight backend waits for the exact task-owned exclusive global authority key.
    /// The observer reads lock metadata only and never inspects statement text or credentials.
    /// </summary>
    private static async Task WaitForGlobalMutationAuthorityWaiterAsync(
        string connectionString,
        string applicationName,
        int blockingBackendPid)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var poll = 0; poll < 300; poll++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity AS activity
                    INNER JOIN pg_catalog.pg_locks AS authority_lock ON authority_lock.pid = activity.pid
                    WHERE activity.application_name = @application
                      AND authority_lock.locktype = 'advisory'
                      AND authority_lock.classid = 999831
                      AND authority_lock.objid = 1
                      AND authority_lock.objsubid = 2
                      AND authority_lock.mode = 'ExclusiveLock'
                      AND NOT authority_lock.granted
                      AND @blocking_backend_pid = ANY(pg_catalog.pg_blocking_pids(activity.pid)))
                """, observer);
            command.Parameters.AddWithValue("application", applicationName);
            command.Parameters.AddWithValue("blocking_backend_pid", blockingBackendPid);
            if (await command.ExecuteScalarAsync() is true) return;
            await Task.Delay(20);
        }

        Assert.Fail($"Preflight {applicationName} did not wait for the task-owned global authority lock.");
    }

    /// <summary>Seeds one exact active ban whose category is controlled by the caller.</summary>
    private static async Task SeedActiveHardwareBanAsync(
        TestDbFactory admin,
        Guid productId,
        string hardwareId,
        string category)
    {
        await using var db = await admin.CreateDbContextAsync();
        db.BannedHardwareIds.Add(new BannedHardwareId
        {
            HardwareId = hardwareId,
            ProductId = productId,
            Reason = "Task-owned Runtime Distribution Preflight concurrency fixture",
            BanCategory = category,
            IsActive = true
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Waits for one named PostgreSQL session to reach the advisory-lock wait queue.</summary>
    private static async Task WaitForAdvisoryLockWaiterAsync(
        string connectionString,
        string applicationName)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity
                    WHERE application_name = @application
                      AND wait_event_type = 'Lock'
                      AND wait_event = 'advisory')
                """;
            command.Parameters.AddWithValue("application", applicationName);
            if (await command.ExecuteScalarAsync() is true) return;
            await Task.Delay(25);
        }
        throw new TimeoutException($"PostgreSQL session {applicationName} did not reach the advisory-lock wait queue.");
    }

    /// <summary>Waits for one named PostgreSQL session to block on any transaction-owned lock.</summary>
    private static async Task WaitForAnyLockWaiterAsync(
        string connectionString,
        string applicationName)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity
                    WHERE application_name = @application
                      AND wait_event_type = 'Lock'
                      AND pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0)
                """;
            command.Parameters.AddWithValue("application", applicationName);
            if (await command.ExecuteScalarAsync() is true) return;
            await Task.Delay(25);
        }
        throw new TimeoutException($"PostgreSQL session {applicationName} did not reach a lock wait queue.");
    }

    /// <summary>Builds one known-enrollment request from the activated authoritative fixture.</summary>
    private static async Task<(string ClientId, RuntimeDistributionPreflightRequest Request)>
        BuildKnownDistributionPreflightRequestAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
        var entitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == binding.EntitlementId);
        return (entitlement.ClientId, new RuntimeDistributionPreflightRequest
        {
            Schema = "runtime-distribution-hardware-authority",
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = binding.ProductId.ToString("D"),
            SoftLicenceLicenseId = binding.LicenseId.ToString("D"),
            GrantRefDigestSha256 = binding.GrantRefDigestSha256,
            InstallationId = enrollment.InstallationId,
            KeyThumbprint = enrollment.KeyThumbprint
        });
    }

    /// <summary>Builds an application-named factory so PostgreSQL wait-state rendezvous is observable.</summary>
    private static TestDbFactory NamedFactory(string connectionString, string applicationName)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { ApplicationName = applicationName };
        return new TestDbFactory(builder.ConnectionString);
    }

    /// <summary>Builds the production hardware-ban mutation service without external notifications.</summary>
    private static SecurityService CreateSecurityService(IDbContextFactory<LicenseDbContext> factory)
    {
        var notifier = new Mock<NotificationService>(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        return new SecurityService(
            factory, Mock.Of<ILogger<SecurityService>>(), notifier.Object,
            new ConfigurationBuilder().Build());
    }

    /// <summary>
    /// Pauses only the first mutation-pass global-authority command before PostgreSQL executes it, allowing
    /// a test-owned commercial writer to commit between the discarded read pass and the authoritative pass.
    /// </summary>
    private sealed class PreflightGlobalMutationPassInterceptor : DbCommandInterceptor
    {
        private readonly TaskCompletionSource _mutationPassStarting =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _matched;

        /// <summary>Completes after pass one has rolled back and immediately before pass two requests global authority.</summary>
        internal Task MutationPassStarting => _mutationPassStarting.Task;

        /// <summary>Releases the single test-owned pass-two continuation pause.</summary>
        internal void Release() => _release.TrySetResult();

        /// <summary>Pauses the exact global mutation command once and leaves every other command unchanged.</summary>
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains(
                    "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);",
                    StringComparison.Ordinal)
                && Interlocked.CompareExchange(ref _matched, 1, 0) == 0)
            {
                _mutationPassStarting.TrySetResult();
                await _release.Task.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            }

            return result;
        }
    }

    /// <summary>Verifies both permanent final ban state and its privacy-safe refusal registry.</summary>
    private static async Task AssertPermanentBanDecisionAsync(
        TestDbFactory admin,
        string hardwareId,
        string reasonCode)
    {
        await using var verification = await admin.CreateDbContextAsync();
        var ban = await verification.BannedHardwareIds.AsNoTracking()
            .SingleAsync(candidate => candidate.HardwareId == hardwareId);
        Assert.True(ban.IsActive);
        Assert.Equal(BannedHardwareId.Categories.Piracy, ban.BanCategory);
        var decision = await verification.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("refused", decision.Outcome);
        Assert.Equal(reasonCode, decision.ReasonCode);
        Assert.Equal(0, decision.AutoUnbannedCount);
        Assert.Contains(BannedHardwareId.Categories.Piracy, decision.BanCategoriesJson, StringComparison.Ordinal);
    }

    /// <summary>Seeds one valid paid entitlement and returns its closed digest-only preflight request.</summary>
    private static async Task<(Guid ProductId, Guid LicenseId, RuntimeDistributionPreflightRequest Request)>
        SeedRuntimeDistributionScenarioAsync(TestDbFactory admin)
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var grantDigest = new string('a', 64);
        await using (var db = await admin.CreateDbContextAsync())
        {
            db.Products.Add(new Product
            {
                Id = productId, Name = "Runtime distribution PostgreSQL",
                PrivateKeyXml = string.Empty, PublicKeyXml = string.Empty
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = typeId, ProductId = productId, Name = "Paid", Slug = "PRO", IsFree = false
            });
            db.Licenses.Add(new License
            {
                Id = licenseId, ProductId = productId, LicenseTypeId = typeId,
                LicenseKey = "POSTGRES-TEST", IsActive = true
            });
            db.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = Guid.NewGuid(), ClientId = "tia-connect-website", ProductId = productId,
                LicenseId = licenseId, GrantRefDigestSha256 = grantDigest,
                SubjectRefDigestSha256 = new string('b', 64), ContractVersion = 3,
                State = "issued", IssuedAtUtc = DateTime.UtcNow.AddMinutes(-1),
                ExpiresAtUtc = DateTime.UtcNow.AddHours(1)
            });
            await db.SaveChangesAsync();
        }
        var request = new RuntimeDistributionPreflightRequest
        {
            Schema = "runtime-distribution-hardware-authority",
            RequestId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProductId = productId.ToString("D"),
            SoftLicenceLicenseId = licenseId.ToString("D"),
            GrantRefDigestSha256 = grantDigest,
            HardwareIdHash = new string('c', 64)
        };
        return (productId, licenseId, request);
    }
}
