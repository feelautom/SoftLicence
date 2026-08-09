using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
    public async Task HardwareAutoUnban_PostgreSql_MixedAuthorityFailsClosedWithoutMutation()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var productId = Guid.NewGuid();
        var hardwareId = "PG-MIXED-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        await SeedHardwareBanProductAsync(factory, productId);
        var security = CreateHardwareSecurityService(factory);
        await security.BanHardwareIdAsync(
            hardwareId,
            "Auto-ban: outdated version",
            productId,
            banCategory: BannedHardwareId.Categories.OutdatedVersion,
            silent: true);
        await security.BanHardwareIdAsync(
            hardwareId,
            "Auto-ban: quarantine remains operator-owned",
            productId: null,
            banCategory: BannedHardwareId.Categories.DevCanaryQuarantine,
            silent: true);

        long epochBefore;
        await using (var before = await factory.CreateDbContextAsync())
            epochBefore = (await before.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;

        Assert.False(await security.AutoUnbanByHwidAsync(hardwareId, productId));

        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal(2, await check.BannedHardwareIds.CountAsync(candidate =>
            candidate.HardwareId == hardwareId && candidate.IsActive));
        Assert.Equal(epochBefore,
            (await check.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch);
    }

    [Fact]
    public async Task HardwareBanConcurrency_PostgreSql_SecurityBanCannotBeLiftedByVersionAutoUnban()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var productId = Guid.NewGuid();
        var hardwareId = "PG-RACE-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        await SeedHardwareBanProductAsync(factory, productId);
        var firstReplica = CreateHardwareSecurityService(factory);
        var secondReplica = CreateHardwareSecurityService(factory);
        await firstReplica.BanHardwareIdAsync(
            hardwareId,
            "Auto-ban: outdated version",
            productId,
            banCategory: BannedHardwareId.Categories.OutdatedVersion,
            silent: true);

        await Task.WhenAll(
            firstReplica.AutoUnbanByHwidAsync(hardwareId, productId),
            secondReplica.BanHardwareIdAsync(
                hardwareId,
                "Piracy authority",
                productId,
                banCategory: BannedHardwareId.Categories.Piracy,
                silent: true));

        await using var check = await factory.CreateDbContextAsync();
        var active = await check.BannedHardwareIds
            .Where(candidate => candidate.HardwareId == hardwareId && candidate.IsActive)
            .ToListAsync();
        Assert.Single(active);
        Assert.Equal(BannedHardwareId.Categories.Piracy, active[0].BanCategory);
        Assert.Equal("Piracy authority", active[0].Reason);
    }

    [Fact]
    public async Task HardwareBanTwoReplicas_PostgreSql_ObserveCommittedUnbanWithoutPositiveCacheDelay()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var productId = Guid.NewGuid();
        var hardwareId = "pg-replica-" + Guid.NewGuid().ToString("N");
        await SeedHardwareBanProductAsync(factory, productId);
        var firstReplica = CreateHardwareSecurityService(factory);
        var secondReplica = CreateHardwareSecurityService(factory);
        await firstReplica.BanHardwareIdAsync(
            hardwareId,
            "Operator ban",
            productId,
            banCategory: BannedHardwareId.Categories.Manual,
            silent: true);

        Assert.True(await secondReplica.IsHardwareIdBannedAsync(hardwareId, productId));
        Guid banId;
        await using (var db = await factory.CreateDbContextAsync())
            banId = await db.BannedHardwareIds
                .Where(candidate => candidate.HardwareId == hardwareId.ToUpperInvariant() && candidate.IsActive)
                .Select(candidate => candidate.Id)
                .SingleAsync();

        Assert.True(await firstReplica.UnbanHardwareIdAsync(banId, "ticket=TKT-000095"));
        Assert.False(await secondReplica.IsHardwareIdBannedAsync(hardwareId.ToUpperInvariant(), productId));
    }

    [Fact]
    public async Task ExpiredHardwareBanCleanup_PostgreSql_RevalidatesConcurrentRenewalUnderSharedBusinessLock()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var productId = Guid.NewGuid();
        var hardwareId = "PG-EXPIRY-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        await SeedHardwareBanProductAsync(factory, productId);
        var security = CreateHardwareSecurityService(factory);
        await security.BanHardwareIdAsync(
            hardwareId,
            "Temporary operator ban",
            productId,
            expiresAt: DateTime.UtcNow.AddMinutes(-1),
            banCategory: BannedHardwareId.Categories.Manual,
            silent: true);

        var adminOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connections.Admin)
            .Options;
        await using var blocker = new LicenseDbContext(adminOptions);
        await using var blockerTransaction = await blocker.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        var lockKey = $"hardware-ban-v1|{hardwareId}";
        await blocker.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({lockKey}, {999095L}))");

        var cleanup = security.IsHardwareIdBannedAsync(hardwareId, productId);
        await Task.Delay(100);
        var renewed = await blocker.BannedHardwareIds.SingleAsync(candidate =>
            candidate.HardwareId == hardwareId && candidate.ProductId == productId);
        renewed.ExpiresAt = DateTime.UtcNow.AddMinutes(5);
        await blocker.SaveChangesAsync();
        await blockerTransaction.CommitAsync();

        Assert.True(await cleanup);
        await using var check = await factory.CreateDbContextAsync();
        var stored = await check.BannedHardwareIds.SingleAsync(candidate =>
            candidate.HardwareId == hardwareId && candidate.ProductId == productId);
        Assert.True(stored.IsActive);
        Assert.True(stored.ExpiresAt > DateTime.UtcNow);
    }

    [Fact]
    public async Task LicenseRevokeRestoreConcurrency_PostgreSql_ConvergesToCommittedSerializableState()
    {
        var connections = await ProvisionIsolatedAsync();
        const string adminSecret = "tkt-000095-postgresql-admin";
        var licenseKey = "PG-STATE-RACE-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connections.App)
            .Options;
        Guid licenseId;
        long epochBefore;
        await using (var seed = new LicenseDbContext(dbOptions))
        {
            var product = new Product
            {
                Name = "License state race " + Guid.NewGuid().ToString("N"),
                ApiSecret = Guid.NewGuid().ToString("N"),
                PrivateKeyXml = string.Empty,
                PublicKeyXml = string.Empty
            };
            var type = new LicenseType
            {
                Product = product,
                Name = "Pro",
                Slug = "PRO-" + Guid.NewGuid().ToString("N"),
                DefaultDurationDays = 30
            };
            var license = new License
            {
                Product = product,
                Type = type,
                LicenseKey = licenseKey,
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*",
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            };
            seed.AddRange(product, type, license);
            await seed.SaveChangesAsync();
            licenseId = license.Id;
            epochBefore = (await seed.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;
        }

        using var webFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", adminSecret);
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connections.App));
            });
        });
        using var revokeClient = webFactory.CreateClient();
        using var restoreClient = webFactory.CreateClient();
        revokeClient.DefaultRequestHeaders.Add("X-Admin-Secret", adminSecret);
        restoreClient.DefaultRequestHeaders.Add("X-Admin-Secret", adminSecret);

        var responses = await Task.WhenAll(
            revokeClient.PostAsJsonAsync(
                $"/api/admin/licenses/{licenseKey}/revoke",
                new { Reason = "concurrent operator revoke" }),
            restoreClient.PostAsync($"/api/admin/licenses/{licenseKey}/unrevoke", content: null));

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        await using var check = new LicenseDbContext(dbOptions);
        var stored = await check.Licenses.AsNoTracking().SingleAsync(candidate => candidate.Id == licenseId);
        var history = await check.LicenseHistories.AsNoTracking()
            .Where(candidate => candidate.LicenseId == licenseId)
            .OrderBy(candidate => candidate.Timestamp)
            .ToListAsync();
        var epochAfter = (await check.RuntimeEnrollmentAuthorityStates.AsNoTracking().SingleAsync()).Epoch;
        if (stored.IsActive)
        {
            Assert.Null(stored.RevokedAt);
            Assert.Equal(new[] { HistoryActions.Revoked, "UNREVOKED" }, history.Select(row => row.Action));
            Assert.Equal(epochBefore + 2, epochAfter);
        }
        else
        {
            Assert.NotNull(stored.RevokedAt);
            Assert.Single(history);
            Assert.Equal(HistoryActions.Revoked, history[0].Action);
            Assert.Equal(epochBefore + 1, epochAfter);
        }
    }

    [Theory]
    [InlineData("ban")]
    [InlineData("revoke")]
    public async Task SecurityAuthorityTransition_PostgreSql_InvalidatesOldEnrollmentAndRestoresViaFreshEnrollment(
        string transition)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var initialCapability = NewSecurityCapability(scenario, "initial");
        var issued = await scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId,
            initialCapability.Digest,
            initialCapability.Request,
            initialCapability.Proof,
            IPAddress.Loopback);
        using (var payload = JsonDocument.Parse(
                   DecodeBase64Url(issued.Response.CapabilityToken.Split('.')[1])))
        {
            var issuedAt = payload.RootElement.GetProperty("iat").GetInt64();
            var expiresAt = payload.RootElement.GetProperty("exp").GetInt64();
            Assert.Equal(120, expiresAt - issuedAt);
        }

        Guid licenseId;
        string hardwareId;
        await using (var authority = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await authority.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
            licenseId = binding.LicenseId;
            hardwareId = await authority.LicenseSeats.AsNoTracking()
                .Where(candidate => candidate.Id == binding.LicenseSeatId)
                .Select(candidate => candidate.HardwareId)
                .SingleAsync();
        }

        Guid? banId = null;
        var security = CreateHardwareSecurityService(scenario.Factory);
        if (transition == "ban")
        {
            await security.BanHardwareIdAsync(
                hardwareId,
                "Operator security ban",
                scenario.Fixture.ProductId,
                banCategory: BannedHardwareId.Categories.Manual,
                silent: true);
            await using var banLookup = await scenario.Factory.CreateDbContextAsync();
            banId = await banLookup.BannedHardwareIds
                .Where(candidate => candidate.HardwareId == hardwareId.ToUpperInvariant() && candidate.IsActive)
                .Select(candidate => candidate.Id)
                .SingleAsync();
        }
        else
        {
            await using var revoke = await scenario.Factory.CreateDbContextAsync();
            var license = await revoke.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.IsActive = false;
            license.RevokedAt = DateTime.UtcNow;
            license.RevocationReason = "Operator revoke";
            await revoke.SaveChangesAsync();
        }

        var rejectedCapability = NewSecurityCapability(scenario, "after-" + transition);
        var rejection = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.CreateCapabilityAsync(
                scenario.EnrollmentId,
                rejectedCapability.Digest,
                rejectedCapability.Request,
                rejectedCapability.Proof,
                IPAddress.Loopback));
        Assert.Equal("authority_ineligible", rejection.ErrorCode);

        await using (var invalidated = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await invalidated.RuntimeEnrollments
                .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            var binding = await invalidated.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
            Assert.Equal("INVALIDATED", enrollment.State);
            Assert.Equal(1, enrollment.SecurityEpoch);
            Assert.Equal("active", binding.State);
        }

        if (transition == "ban")
        {
            Assert.True(await security.UnbanHardwareIdAsync(
                banId ?? throw new InvalidOperationException("Missing ban id."),
                "ticket=TKT-000095"));
        }
        else
        {
            await using var restore = await scenario.Factory.CreateDbContextAsync();
            var license = await restore.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            license.RevocationReason = null;
            await restore.SaveChangesAsync();
        }

        using var replacementKey = System.Security.Cryptography.RSA.Create(3072);
        var replacementRequest = PrepareRequest(
            scenario.Fixture,
            Guid.NewGuid().ToString("D"),
            replacementKey);
        var replacement = await scenario.Runtime.PrepareAsync(
            "website-step1",
            Sha256("security-restore-prepare-" + transition + Guid.NewGuid().ToString("N")),
            replacementRequest);

        Assert.NotEqual(scenario.EnrollmentId.ToString("D"), replacement.Response.EnrollmentId);
        await using var finalCheck = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("INVALIDATED", (await finalCheck.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId)).State);
        var replacementEnrollment = await finalCheck.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == Guid.Parse(replacement.Response.EnrollmentId));
        Assert.Equal("PENDING", replacementEnrollment.State);
        Assert.Equal(1, replacementEnrollment.SecurityEpoch);
    }

    private static SecurityService CreateHardwareSecurityService(IDbContextFactory<LicenseDbContext> factory)
    {
        var notifier = new Mock<NotificationService>(
            factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        return new SecurityService(
            factory,
            Mock.Of<ILogger<SecurityService>>(),
            notifier.Object,
            new ConfigurationBuilder().Build());
    }

    private static async Task SeedHardwareBanProductAsync(
        IDbContextFactory<LicenseDbContext> factory,
        Guid productId)
    {
        await using var db = await factory.CreateDbContextAsync();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "Hardware ban test " + productId.ToString("N"),
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = Guid.NewGuid().ToString("N")
        });
        await db.SaveChangesAsync();
    }

    private static (RuntimeEnrollmentCapabilityRequest Request, string Digest, RuntimeProofHeaders Proof)
        NewSecurityCapability(PreparedBootstrapScenario scenario, string suffix)
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
        var digest = Sha256("security-capability-" + suffix + Guid.NewGuid().ToString("N"));
        var proof = Proof(
            scenario.EnrollmentKey,
            "capability",
            scenario.EnrollmentId,
            request.Audience,
            "-",
            digest);
        return (request, digest, proof);
    }
}
