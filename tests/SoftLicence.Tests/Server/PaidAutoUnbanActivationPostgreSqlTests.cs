using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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

        if (failure == PaidActivationFailure.Cleanup)
        {
            Assert.NotNull(scenario.CleanupInterceptor);
            Assert.True(scenario.CleanupInterceptor.Triggered);
        }
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
    public async Task PaidAutoUnbanActivation_PostgreSql_ConcurrentRebanPreservesIdentityAndRevokesCommercialUse()
    {
        var signer = new BlockingSignedLicenseFileService();
        using var scenario = await CreatePaidAutoUnbanScenarioAsync(PaidActivationFailure.None, signer);
        var epochBefore = (await SnapshotPaidAutoUnbanScenarioAsync(scenario)).GlobalAuthorityEpoch;
        var identityBefore = await SnapshotRetainedRuntimeIdentityAsync(scenario.Factory, scenario.EnrollmentId);
        EnrollmentLicenseAssignment assignmentBefore;
        await using (var original = await scenario.Factory.CreateDbContextAsync())
            assignmentBefore = await original.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");

        var activation = scenario.Client.PostAsJsonAsync("/api/activation", scenario.Request);
        await signer.Entered.Task.WaitAsync(TimeSpan.FromSeconds(15));

        var security = CreateHardwareSecurityService(scenario.Factory);
        var reban = security.BanHardwareIdAsync(
            scenario.HardwareId,
            "Concurrent operator piracy re-ban",
            scenario.ProductId,
            banCategory: BannedHardwareId.Categories.Piracy,
            silent: true);
        await WaitForGlobalAuthorityWaitersAsync(scenario.AdminConnectionString, 1);
        Assert.False(reban.IsCompleted);

        signer.Release.TrySetResult();
        var activationResponse = await activation;
        await reban;

        Assert.Equal(HttpStatusCode.OK, activationResponse.StatusCode);
        var activationBody = await activationResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(string.IsNullOrEmpty(activationBody.GetProperty("licenseFile").GetString()));
        var after = await SnapshotPaidAutoUnbanScenarioAsync(scenario);
        Assert.False(after.EligibleBanActive);
        Assert.True(after.PiracyBanActive);
        Assert.True(after.TargetSeatActive);
        Assert.False(after.ConflictingSeatActive);
        Assert.Equal(identityBefore, await SnapshotRetainedRuntimeIdentityAsync(scenario.Factory, scenario.EnrollmentId));
        Assert.True(after.GlobalAuthorityEpoch > epochBefore);
        Assert.True(after.GlobalAuthorityEpoch > after.EnrollmentAuthorityEpoch);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var ended = await check.EnrollmentLicenseAssignments.SingleAsync(row => row.Id == assignmentBefore.Id);
            Assert.Equal("ENDED", ended.State);
            Assert.Equal("seat_released", ended.EndReason);
            Assert.NotNull(ended.EndedAtUtc);
            Assert.Equal(assignmentBefore.Revision, ended.Revision);
            Assert.Empty(await check.EnrollmentLicenseAssignments.Where(row =>
                row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());
        }
        await AssertEndedAssignmentDeniesRuntimeAsync(scenario.Factory, scenario.EnrollmentId);
        using var statusResponse = await scenario.Client.PostAsJsonAsync("/api/activation/check", scenario.Request);
        Assert.Equal(HttpStatusCode.OK, statusResponse.StatusCode);
        var statusBody = await statusResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("REVOKED", statusBody.GetProperty("status").GetString());
        scenario.Notification.Verify(
            notifier => notifier.Notify(
                NotificationService.Triggers.SecurityIpBanned,
                It.Is<string>(title => title.StartsWith("AUTO-UNBAN", StringComparison.Ordinal)),
                It.IsAny<string>(),
                It.IsAny<object?>()),
            Times.Once);
    }

    /// <summary>
    /// Proves the opposite commit order: a standalone permanent ban queued first on the global
    /// authority commits before paid activation, which then observes the ban and changes no
    /// activation graph. Both production operations wait on the same PostgreSQL authority key.
    /// </summary>
    [Fact]
    public async Task PaidAutoUnbanActivation_PostgreSql_StandaloneBanCommittedFirstRefusesWithoutPartialActivation()
    {
        using var scenario = await CreatePaidAutoUnbanScenarioAsync(PaidActivationFailure.None);
        var before = await SnapshotPaidAutoUnbanScenarioAsync(scenario);
        await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)", blocker, blockerTransaction))
        {
            await hold.ExecuteNonQueryAsync();
        }

        var security = CreateHardwareSecurityService(scenario.Factory);
        var ban = security.BanHardwareIdAsync(
            scenario.HardwareId,
            "Standalone operator piracy ban",
            scenario.ProductId,
            banCategory: BannedHardwareId.Categories.Piracy,
            silent: true);
        await WaitForGlobalAuthorityWaitersAsync(scenario.AdminConnectionString, 1);
        Assert.False(ban.IsCompleted);

        var activation = scenario.Client.PostAsJsonAsync("/api/activation", scenario.Request);
        await WaitForGlobalAuthorityWaitersAsync(scenario.AdminConnectionString, 2);
        Assert.False(activation.IsCompleted);

        await blockerTransaction.CommitAsync();
        await ban.WaitAsync(TimeSpan.FromSeconds(15));
        var response = await activation.WaitAsync(TimeSpan.FromSeconds(15));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("BANNED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        using (var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync()))
            Assert.Equal("BANNED", payload.RootElement.GetProperty("errorCode").GetString());
        var after = await SnapshotPaidAutoUnbanScenarioAsync(scenario);
        Assert.True(after.PiracyBanActive);
        Assert.False(after.TargetSeatActive);
        Assert.Equal(before.ConflictingSeatActive, after.ConflictingSeatActive);
        Assert.Equal(before.BindingState, after.BindingState);
        Assert.Equal(before.EnrollmentState, after.EnrollmentState);
        Assert.Equal(before.EnrollmentAuthorityEpoch, after.EnrollmentAuthorityEpoch);
        scenario.Notification.Verify(
            notifier => notifier.Notify(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<object?>()),
            Times.Never);
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
        if (cleanupInterceptor != null)
            cleanupInterceptor.LosingSeatId = conflictingSeatId;
        var bindingId = Guid.NewGuid();
        var enrollmentId = Guid.NewGuid();
        var eligibleBanId = Guid.NewGuid();
        var hardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
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
                MaxSeats = 2,
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
                // Keep a real multi-seat capacity refusal; mono-seat replacement is intentional.
                for (var capacitySeat = 0; capacitySeat < 2; capacitySeat++)
                db.LicenseSeats.Add(new LicenseSeat
                {
                    Id = Guid.NewGuid(),
                    LicenseId = targetLicenseId,
                    HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                    IsActive = true,
                    FirstActivatedAt = now.AddDays(-3),
                    LastCheckInAt = now.AddDays(-1)
                });
            }

            var grantRef = Guid.NewGuid().ToString("D");
            var handoffDigest = Sha256("paid-auto-unban-handoff-" + Guid.NewGuid().ToString("N"));
            var installationId = Guid.NewGuid().ToString("D");
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
                InstallationId = installationId,
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
                InstallationId = installationId,
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
            cleanupInterceptor,
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

    /// <summary>
    /// Waits until the requested number of PostgreSQL sessions are blocked on the repository-wide
    /// commercial mutation key. This proves standalone ban and activation writers serialize before
    /// either can acquire narrower hardware, product, licence, seat or ban-row authority.
    /// </summary>
    /// <param name="connectionString">An administrator connection able to read <c>pg_locks</c>.</param>
    /// <param name="minimumWaiters">Minimum number of non-granted global authority locks.</param>
    /// <exception cref="TimeoutException">No waiter appeared within about ten seconds.</exception>
    private static async Task WaitForGlobalAuthorityWaitersAsync(string connectionString, int minimumWaiters)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 200; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT count(*)
                FROM pg_catalog.pg_locks AS held
                WHERE held.locktype = 'advisory'
                  AND held.database = (
                      SELECT oid FROM pg_catalog.pg_database
                      WHERE datname = pg_catalog.current_database())
                  AND held.classid = 999831::oid
                  AND held.objid = 1::oid
                  AND held.objsubid = 2
                  AND NOT held.granted;
                """;
            if (Convert.ToInt32(await command.ExecuteScalarAsync()) >= minimumWaiters)
                return;
            await Task.Delay(50);
        }

        throw new TimeoutException(
            $"Expected at least {minimumWaiters} PostgreSQL waiter(s) on the global mutation authority lock.");
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

    /// <summary>Injects failure only when the fixture's losing seat is written inactive by commercial cleanup.</summary>
    private sealed class DistributionBindingCleanupFailureInterceptor : DbCommandInterceptor
    {
        /// <summary>Exact synthetic losing seat; unrelated updates must not trigger the fault.</summary>
        internal Guid LosingSeatId { get; set; }
        /// <summary>Proves the expected cleanup command was intercepted, preventing a vacuous rollback test.</summary>
        internal bool Triggered { get; private set; }
        public override InterceptionResult<int> NonQueryExecuting(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result)
        {
            ThrowIfCleanup(command, eventData);
            return result;
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCleanup(command, eventData);
            return ValueTask.FromResult(result);
        }

        public override InterceptionResult<DbDataReader> ReaderExecuting(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result)
        {
            ThrowIfCleanup(command, eventData);
            return result;
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCleanup(command, eventData);
            return ValueTask.FromResult(result);
        }

        /// <summary>Matches the real seat write and its exact tracked transition without changing SQL or constraints.</summary>
        private void ThrowIfCleanup(DbCommand command, CommandEventData eventData)
        {
            if (LosingSeatId != Guid.Empty
                && command.CommandText.Contains("UPDATE \"LicenseSeats\"", StringComparison.Ordinal)
                && command.Parameters.Cast<DbParameter>().Any(parameter => Equals(parameter.Value, LosingSeatId))
                && eventData.Context is LicenseDbContext db
                && db.ChangeTracker.Entries<LicenseSeat>().Any(entry =>
                    entry.Entity.Id == LosingSeatId && entry.State == EntityState.Modified
                    && !entry.Entity.IsActive && entry.Property(seat => seat.IsActive).OriginalValue))
            {
                Triggered = true;
                throw new InvalidOperationException("Injected commercial seat cleanup failure.");
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
        /// <summary>Optional synthetic cleanup fault whose execution the failure scenario must prove.</summary>
        public DistributionBindingCleanupFailureInterceptor? CleanupInterceptor { get; }

        public PaidAutoUnbanScenario(
            WebApplicationFactory<Program> webFactory,
            HttpClient client,
            TestDbFactory factory,
            string adminConnectionString,
            Mock<NotificationService> notification,
            DistributionBindingCleanupFailureInterceptor? cleanupInterceptor,
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
            CleanupInterceptor = cleanupInterceptor;
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
