using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Theory]
    [InlineData(PaidActivationFailure.SeatLimit)]
    [InlineData(PaidActivationFailure.Signing)]
    [InlineData(PaidActivationFailure.Cleanup)]
    public async Task PaidAutoUnbanActivation_PostgreSql_FailureRollsBackWholeAuthorityGraph(
        string failure)
    {
        using var scenario = await CreatePaidAutoUnbanScenarioAsync(failure);
        var before = await SnapshotPaidAutoUnbanScenarioAsync(scenario);

        var response = await scenario.Client.PostAsJsonAsync("/api/activation", scenario.Request);

        Assert.Equal(
            failure == PaidActivationFailure.SeatLimit
                ? HttpStatusCode.BadRequest
                : HttpStatusCode.InternalServerError,
            response.StatusCode);
        Assert.Equal(before, await SnapshotPaidAutoUnbanScenarioAsync(scenario));
        scenario.Notification.Verify(
            notifier => notifier.Notify(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<object?>()),
            Times.Never);
    }

    [Fact]
    public async Task PaidAutoUnbanActivation_PostgreSql_ReplayIsIdempotentAndNotifiesOnce()
    {
        using var scenario = await CreatePaidAutoUnbanScenarioAsync(PaidActivationFailure.None);

        var first = await scenario.Client.PostAsJsonAsync("/api/activation", scenario.Request);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var afterFirst = await SnapshotPaidAutoUnbanScenarioAsync(scenario);

        var replay = await scenario.Client.PostAsJsonAsync("/api/activation", scenario.Request);

        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var afterReplay = await SnapshotPaidAutoUnbanScenarioAsync(scenario);
        Assert.False(afterReplay.EligibleBanActive);
        Assert.Equal(afterFirst.EligibleBanActive, afterReplay.EligibleBanActive);
        Assert.Equal(afterFirst.ConflictingSeatActive, afterReplay.ConflictingSeatActive);
        Assert.Equal(afterFirst.BindingState, afterReplay.BindingState);
        Assert.Equal(afterFirst.BindingInvalidatedAtUtc, afterReplay.BindingInvalidatedAtUtc);
        Assert.Equal(afterFirst.EnrollmentState, afterReplay.EnrollmentState);
        Assert.Equal(afterFirst.EnrollmentInvalidatedAtUtc, afterReplay.EnrollmentInvalidatedAtUtc);
        Assert.Equal(afterFirst.EnrollmentAuthorityEpoch, afterReplay.EnrollmentAuthorityEpoch);
        scenario.Notification.Verify(
            notifier => notifier.Notify(
                NotificationService.Triggers.SecurityIpBanned,
                It.Is<string>(title => title.StartsWith("AUTO-UNBAN", StringComparison.Ordinal)),
                It.IsAny<string>(),
                It.IsAny<object?>()),
            Times.Once);
    }

    [Fact]
    public async Task PaidAutoUnbanActivation_PostgreSql_ConcurrentRebanWaitsForActivationAndAdvancesAuthorityEpoch()
    {
        var signer = new BlockingSignedLicenseFileService();
        using var scenario = await CreatePaidAutoUnbanScenarioAsync(PaidActivationFailure.None, signer);
        var epochBefore = (await SnapshotPaidAutoUnbanScenarioAsync(scenario)).GlobalAuthorityEpoch;

        var activation = scenario.Client.PostAsJsonAsync("/api/activation", scenario.Request);
        await signer.Entered.Task.WaitAsync(TimeSpan.FromSeconds(15));

        var security = CreateHardwareSecurityService(scenario.Factory);
        var reban = security.BanHardwareIdAsync(
            scenario.HardwareId,
            "Concurrent operator piracy re-ban",
            scenario.ProductId,
            banCategory: BannedHardwareId.Categories.Piracy,
            silent: true);
        await WaitForHardwareBanWaiterAsync(scenario.AdminConnectionString, scenario.HardwareId);
        Assert.False(reban.IsCompleted);

        signer.Release.TrySetResult();
        var activationResponse = await activation;
        await reban;

        Assert.Equal(HttpStatusCode.OK, activationResponse.StatusCode);
        var after = await SnapshotPaidAutoUnbanScenarioAsync(scenario);
        Assert.False(after.EligibleBanActive);
        Assert.True(after.PiracyBanActive);
        Assert.True(after.TargetSeatActive);
        Assert.False(after.ConflictingSeatActive);
        Assert.Equal("invalidated", after.BindingState);
        Assert.Equal("INVALIDATED", after.EnrollmentState);
        Assert.True(after.EnrollmentAuthorityEpoch > epochBefore);
        Assert.True(after.GlobalAuthorityEpoch > after.EnrollmentAuthorityEpoch);
        scenario.Notification.Verify(
            notifier => notifier.Notify(
                NotificationService.Triggers.SecurityIpBanned,
                It.Is<string>(title => title.StartsWith("AUTO-UNBAN", StringComparison.Ordinal)),
                It.IsAny<string>(),
                It.IsAny<object?>()),
            Times.Once);
    }

    private static async Task<PaidAutoUnbanScenario> CreatePaidAutoUnbanScenarioAsync(
        string failure,
        ISignedLicenseFileService? signer = null)
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var notification = new Mock<NotificationService>(
            factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        notification.Setup(service => service.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));

        signer ??= failure == PaidActivationFailure.Signing
            ? new ThrowingSignedLicenseFileService()
            : new FixedSignedLicenseFileService();
        var cleanupInterceptor = failure == PaidActivationFailure.Cleanup
            ? new DistributionBindingCleanupFailureInterceptor()
            : null;

        var webFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                {
                    options.UseNpgsql(connections.App);
                    if (cleanupInterceptor != null)
                        options.AddInterceptors(cleanupInterceptor);
                });
                services.RemoveAll<NotificationService>();
                services.AddSingleton(notification.Object);
                services.RemoveAll<ISignedLicenseFileService>();
                services.AddSingleton(signer);
            });
        });

        var productId = Guid.NewGuid();
        var targetLicenseId = Guid.NewGuid();
        var conflictingLicenseId = Guid.NewGuid();
        var conflictingSeatId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var enrollmentId = Guid.NewGuid();
        var eligibleBanId = Guid.NewGuid();
        var hardwareId = "PAID-AUTO-UNBAN-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        var appName = "Paid activation " + Guid.NewGuid().ToString("N");
        var licenseKey = "PAID-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        var now = DateTime.UtcNow;
        var adminOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connections.Admin)
            .Options;
        await using (var db = new LicenseDbContext(adminOptions))
        {
            var product = new Product
            {
                Id = productId,
                Name = appName,
                ApiSecret = Guid.NewGuid().ToString("N"),
                PrivateKeyXml = string.Empty,
                PublicKeyXml = string.Empty
            };
            var type = new LicenseType
            {
                Id = Guid.NewGuid(),
                ProductId = productId,
                Name = "Paid",
                Slug = "PAID-" + Guid.NewGuid().ToString("N"),
                IsFree = false
            };
            var target = new License
            {
                Id = targetLicenseId,
                ProductId = productId,
                LicenseTypeId = type.Id,
                LicenseKey = licenseKey,
                CustomerEmail = "paid@example.test",
                CustomerName = "Paid customer",
                IsActive = true,
                MaxSeats = failure == PaidActivationFailure.SeatLimit ? 1 : 2,
                AllowedVersions = "*",
                ExpirationDate = now.AddDays(30)
            };
            var conflicting = new License
            {
                Id = conflictingLicenseId,
                ProductId = productId,
                LicenseTypeId = type.Id,
                LicenseKey = "CONFLICT-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                CustomerEmail = "conflict@example.test",
                CustomerName = "Conflicting customer",
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*",
                ExpirationDate = now.AddDays(30)
            };
            db.AddRange(product, type, target, conflicting);
            db.LicenseSeats.Add(new LicenseSeat
            {
                Id = conflictingSeatId,
                LicenseId = conflictingLicenseId,
                HardwareId = hardwareId,
                IsActive = true,
                FirstActivatedAt = now.AddDays(-2),
                LastCheckInAt = now.AddDays(-1),
                AppVersion = "2.2.999"
            });
            if (failure == PaidActivationFailure.SeatLimit)
            {
                db.LicenseSeats.Add(new LicenseSeat
                {
                    Id = Guid.NewGuid(),
                    LicenseId = targetLicenseId,
                    HardwareId = "OCCUPIED-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                    IsActive = true,
                    FirstActivatedAt = now.AddDays(-3),
                    LastCheckInAt = now.AddDays(-1)
                });
            }

            var grantRef = Guid.NewGuid().ToString("D");
            var handoffDigest = Sha256("paid-auto-unban-handoff-" + Guid.NewGuid().ToString("N"));
            db.DistributionInstallationBindings.Add(new DistributionInstallationBinding
            {
                Id = bindingId,
                ProductId = productId,
                LicenseId = conflictingLicenseId,
                LicenseSeatId = conflictingSeatId,
                EntitlementId = Guid.NewGuid(),
                SubjectRefDigestSha256 = Sha256("paid-auto-unban-subject"),
                GrantRef = grantRef,
                GrantRefDigestSha256 = Sha256(grantRef),
                HandoffDigestSha256 = handoffDigest,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareIdHash = Sha256(hardwareId),
                Version = "2.2.999",
                InstallerFilename = "TiaConnect-Setup_v2.2.999.msi",
                InstallerSha256 = new string('f', 64),
                ExecutableSha256 = new string('a', 64),
                NativeDllSha256 = new string('b', 64),
                CoreSha256 = new string('c', 64),
                ApprovedBinariesSource = "release",
                State = "active",
                BoundAtUtc = now.AddDays(-1)
            });
            const string encryptionKeyId = "paid-auto-unban-test";
            db.RuntimeEnrollmentKeyRegistries.Add(new RuntimeEnrollmentKeyRegistry
            {
                Purpose = "encryption",
                KeyId = encryptionKeyId,
                MaterialDigestSha256 = Sha256("paid-auto-unban-key"),
                State = "active",
                Epoch = 1,
                CreatedAtUtc = now.AddDays(-2)
            });
            var authorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(row => row.Id == 1)
                .Select(row => row.Epoch)
                .SingleAsync();
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = "website-step1",
                BindingId = bindingId,
                ProductId = productId,
                LicenseId = conflictingLicenseId,
                LicenseSeatId = conflictingSeatId,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareIdHash = Sha256(hardwareId),
                ReleaseVersion = "2.2.999",
                HandoffDigestSha256 = handoffDigest,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = encryptionKeyId,
                PublicKeySpkiSha256 = new string('d', 64),
                KeyThumbprint = "thumb-" + Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test",
                ChallengeKeyId = encryptionKeyId,
                ChallengeDigestSha256 = new string('e', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 1,
                AuthorityEpoch = authorityEpoch,
                ChallengeExpiresAtUtc = now.AddHours(1),
                CreatedAtUtc = now.AddDays(-1),
                ActivatedAtUtc = now.AddDays(-1),
                ChallengeConsumedAtUtc = now.AddDays(-1)
            });
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                Id = eligibleBanId,
                HardwareId = hardwareId,
                ProductId = productId,
                Reason = "Auto-ban: outdated version",
                BanCategory = BannedHardwareId.Categories.OutdatedVersion,
                IsActive = true,
                BannedAt = now.AddMinutes(-5)
            });
            await db.SaveChangesAsync();
        }

        var client = webFactory.CreateClient();
        return new PaidAutoUnbanScenario(
            webFactory,
            client,
            factory,
            connections.Admin,
            notification,
            productId,
            targetLicenseId,
            conflictingSeatId,
            bindingId,
            enrollmentId,
            eligibleBanId,
            hardwareId,
            new
            {
                LicenseKey = licenseKey,
                HardwareId = hardwareId,
                AppName = appName,
                AppVersion = "2.2.999",
                CustomerEmail = "paid@example.test"
            });
    }

    private static async Task<PaidAutoUnbanSnapshot> SnapshotPaidAutoUnbanScenarioAsync(
        PaidAutoUnbanScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var targetSeats = await db.LicenseSeats.AsNoTracking()
            .Where(seat => seat.LicenseId == scenario.TargetLicenseId && seat.HardwareId == scenario.HardwareId)
            .ToListAsync();
        var conflictingSeat = await db.LicenseSeats.AsNoTracking()
            .SingleAsync(seat => seat.Id == scenario.ConflictingSeatId);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.BindingId);
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        return new PaidAutoUnbanSnapshot(
            await db.BannedHardwareIds.AsNoTracking().AnyAsync(row =>
                row.Id == scenario.EligibleBanId
                && row.BanCategory == BannedHardwareId.Categories.OutdatedVersion
                && row.IsActive),
            await db.BannedHardwareIds.AsNoTracking().AnyAsync(row =>
                row.HardwareId == scenario.HardwareId
                && row.ProductId == scenario.ProductId
                && row.BanCategory == BannedHardwareId.Categories.Piracy
                && row.IsActive),
            targetSeats.Count == 1 && targetSeats[0].IsActive,
            targetSeats.Count,
            conflictingSeat.IsActive,
            conflictingSeat.UnlinkedAt,
            binding.State,
            binding.InvalidatedAtUtc,
            binding.InvalidationReason,
            enrollment.State,
            enrollment.InvalidatedAtUtc,
            enrollment.InvalidationReason,
            enrollment.AuthorityEpoch,
            await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(row => row.Id == 1)
                .Select(row => row.Epoch)
                .SingleAsync());
    }

    private static async Task WaitForHardwareBanWaiterAsync(string connectionString, string hardwareId)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 200; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                WITH target AS (
                    SELECT pg_catalog.hashtextextended(@lock_name, 999095)::bigint AS key
                )
                SELECT count(*)
                FROM pg_catalog.pg_locks AS held
                CROSS JOIN target
                WHERE held.locktype = 'advisory'
                  AND held.database = (
                      SELECT oid FROM pg_catalog.pg_database
                      WHERE datname = pg_catalog.current_database())
                  AND held.classid = (((target.key >> 32) & 4294967295)::bigint)::oid
                  AND held.objid = ((target.key & 4294967295)::bigint)::oid
                  AND held.objsubid = 1
                  AND NOT held.granted;
                """;
            command.Parameters.AddWithValue("lock_name", $"hardware-ban-v1|{hardwareId.ToUpperInvariant()}");
            if (Convert.ToInt32(await command.ExecuteScalarAsync()) >= 1)
                return;
            await Task.Delay(50);
        }

        throw new TimeoutException("Expected a PostgreSQL waiter on the hardware-ban authority lock.");
    }

    private static class PaidActivationFailure
    {
        public const string None = "none";
        public const string SeatLimit = "seat-limit";
        public const string Signing = "signing";
        public const string Cleanup = "cleanup";
    }

    private sealed class FixedSignedLicenseFileService : ISignedLicenseFileService
    {
        public string Generate(
            License license,
            string hardwareId,
            IReadOnlyDictionary<string, string>? featureOverride = null) => "signed-test-license";
    }

    private sealed class ThrowingSignedLicenseFileService : ISignedLicenseFileService
    {
        public string Generate(
            License license,
            string hardwareId,
            IReadOnlyDictionary<string, string>? featureOverride = null) =>
            throw new InvalidOperationException("Injected signing failure.");
    }

    private sealed class BlockingSignedLicenseFileService : ISignedLicenseFileService
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Generate(
            License license,
            string hardwareId,
            IReadOnlyDictionary<string, string>? featureOverride = null)
        {
            Entered.TrySetResult();
            Release.Task.GetAwaiter().GetResult();
            return "signed-test-license";
        }
    }

    private sealed class DistributionBindingCleanupFailureInterceptor : DbCommandInterceptor
    {
        public override InterceptionResult<int> NonQueryExecuting(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result)
        {
            ThrowIfCleanup(command);
            return result;
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCleanup(command);
            return ValueTask.FromResult(result);
        }

        public override InterceptionResult<DbDataReader> ReaderExecuting(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result)
        {
            ThrowIfCleanup(command);
            return result;
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCleanup(command);
            return ValueTask.FromResult(result);
        }

        private static void ThrowIfCleanup(DbCommand command)
        {
            if (command.CommandText.Contains(
                    "UPDATE \"DistributionInstallationBindings\"",
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Injected distribution cleanup failure.");
            }
        }
    }

    private sealed record PaidAutoUnbanSnapshot(
        bool EligibleBanActive,
        bool PiracyBanActive,
        bool TargetSeatActive,
        int TargetSeatCount,
        bool ConflictingSeatActive,
        DateTime? ConflictingSeatUnlinkedAtUtc,
        string BindingState,
        DateTime? BindingInvalidatedAtUtc,
        string? BindingInvalidationReason,
        string EnrollmentState,
        DateTime? EnrollmentInvalidatedAtUtc,
        string? EnrollmentInvalidationReason,
        long EnrollmentAuthorityEpoch,
        long GlobalAuthorityEpoch);

    private sealed class PaidAutoUnbanScenario : IDisposable
    {
        private readonly WebApplicationFactory<Program> _webFactory;

        public HttpClient Client { get; }
        public TestDbFactory Factory { get; }
        public string AdminConnectionString { get; }
        public Mock<NotificationService> Notification { get; }
        public Guid ProductId { get; }
        public Guid TargetLicenseId { get; }
        public Guid ConflictingSeatId { get; }
        public Guid BindingId { get; }
        public Guid EnrollmentId { get; }
        public Guid EligibleBanId { get; }
        public string HardwareId { get; }
        public object Request { get; }

        public PaidAutoUnbanScenario(
            WebApplicationFactory<Program> webFactory,
            HttpClient client,
            TestDbFactory factory,
            string adminConnectionString,
            Mock<NotificationService> notification,
            Guid productId,
            Guid targetLicenseId,
            Guid conflictingSeatId,
            Guid bindingId,
            Guid enrollmentId,
            Guid eligibleBanId,
            string hardwareId,
            object request)
        {
            _webFactory = webFactory;
            Client = client;
            Factory = factory;
            AdminConnectionString = adminConnectionString;
            Notification = notification;
            ProductId = productId;
            TargetLicenseId = targetLicenseId;
            ConflictingSeatId = conflictingSeatId;
            BindingId = bindingId;
            EnrollmentId = enrollmentId;
            EligibleBanId = eligibleBanId;
            HardwareId = hardwareId;
            Request = request;
        }

        public void Dispose()
        {
            Client.Dispose();
            _webFactory.Dispose();
        }
    }
}
