using Microsoft.EntityFrameworkCore;
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
