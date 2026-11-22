using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Serializes the real PostgreSQL licence-hardware-exclusion contract tests on one isolated database.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LicenseHardwareExclusionPostgreSqlCollection : ICollectionFixture<LicenseHardwareExclusionPostgreSqlFixture>
{
    /// <summary>Gets the exact xUnit collection name used to serialize the isolated database fixture.</summary>
    public const string Name = "TKT-002041 licence hardware exclusion PostgreSQL";
}

/// <summary>
/// Proves the exclusion table, atomic release-plus-exclude, idempotent replay, lift and list,
/// and the shared admission refusal matrix on PostgreSQL.
/// </summary>
[Collection(LicenseHardwareExclusionPostgreSqlCollection.Name)]
public sealed class LicenseHardwareExclusionPostgreSqlTests(LicenseHardwareExclusionPostgreSqlFixture fixture)
{
    private const string HardwareId = "ABCDEF0123456789";
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 10, 0, 0, TimeSpan.Zero);

    /// <summary>Proves the additive migration is current and creates the exclusion table.</summary>
    [Fact]
    public async Task Migration_IsCurrentAndCreatesExclusionTable()
    {
        await using var db = fixture.Factory.CreateDbContext();

        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT to_regclass('\"LicenseHardwareExclusions\"') IS NOT NULL";
        await db.Database.OpenConnectionAsync();
        Assert.True(Assert.IsType<bool>(await command.ExecuteScalarAsync()));
    }

    /// <summary>
    /// Proves one atomic add releases the active seat with the provider-authority reason and
    /// inserts the exclusion, even when the seat-change quota is exhausted and the seat is
    /// younger than the five-minute guard.
    /// </summary>
    [Fact]
    public async Task Add_AtQuotaWithFreshSeat_ReleasesSeatAndExcludesMachine()
    {
        var seed = await fixture.SeedAsync("atomic-release", active: true, seatAge: TimeSpan.FromMinutes(1), Now);
        await ExhaustQuotaAsync(seed);
        var request = seed.AddRequest();

        var result = await fixture.Service(Now).AddAsync("tia-connect-website-exclusions", new string('a', 64), request);

        Assert.False(result.Idempotent);
        Assert.Equal(LicenseHardwareExclusionService.ExcludedOutcome, result.Response.Outcome);
        Assert.Equal(PortalDeactivationService.DeactivatedOutcome, result.Response.ReleaseOutcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.False((await verify.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
        var exclusion = Assert.Single(await verify.LicenseHardwareExclusions
            .Where(row => row.LicenseId == seed.LicenseId && row.HardwareId == HardwareId)
            .ToListAsync());
        Assert.Equal(LicenseHardwareExclusionService.S2SActor, exclusion.Actor);
        Assert.True(exclusion.ReleaseActiveSeat);
        var history = await verify.LicenseHistories.SingleAsync(row => row.LicenseId == seed.LicenseId);
        Assert.Contains(
            LicenseHardwareExclusionService.DeriveReleaseRequestId(seed.RequestId).ToString("D"),
            history.Details);
        Assert.Contains("provider_authority_release", history.Details);
        // The exclusion is a licence-scoped commercial refusal: it never writes a security ban.
        Assert.Empty(await verify.BannedHardwareIds.Where(row => row.HardwareId == HardwareId).ToListAsync());
    }

    /// <summary>Proves a second distinct add on the same machine returns the stable already-excluded terminal.</summary>
    [Fact]
    public async Task Add_SecondRequestOnSameMachine_IsAlreadyExcludedWithoutSecondRow()
    {
        var seed = await fixture.SeedAsync("already", active: true, seatAge: TimeSpan.FromHours(1), Now);
        var service = fixture.Service(Now);
        await service.AddAsync("tia-connect-website-exclusions", new string('a', 64), seed.AddRequest());

        var second = await service.AddAsync(
            "tia-connect-website-exclusions", new string('b', 64),
            seed.AddRequest() with { RequestId = Guid.NewGuid().ToString("D"), ReleaseActiveSeat = false });

        Assert.Equal(LicenseHardwareExclusionService.AlreadyExcludedOutcome, second.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.LicenseHardwareExclusions.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
    }

    /// <summary>
    /// Proves a release finds the active seat when its persisted identity is a legacy alias and the
    /// Website submits the later canonical identity. Alias lookup only identifies the seat.
    /// </summary>
    [Fact]
    public async Task Add_ReleasesActiveSeatStoredUnderAliasIdentity()
    {
        const string legacyHardwareId = "0123456789ABCDEF";
        var seed = await fixture.SeedAsync("alias-release", active: true, TimeSpan.FromHours(1), Now);
        await using var seedDatabase = fixture.Factory.CreateDbContext();
        var seat = await seedDatabase.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId);
        seat.HardwareId = legacyHardwareId;

        var bindingId = Guid.NewGuid();
        var installationId = Guid.NewGuid();
        var legacyDigest = Sha256(legacyHardwareId);
        var canonicalDigest = Sha256(HardwareId);
        seedDatabase.DistributionInstallationBindings.Add(new DistributionInstallationBinding
        {
            Id = bindingId,
            ProductId = seed.ProductId,
            LicenseId = seed.LicenseId,
            LicenseSeatId = seed.SeatId,
            EntitlementId = Guid.NewGuid(),
            SubjectRefDigestSha256 = Sha256("alias-release:subject"),
            GrantRef = "TKT-002041-alias-release",
            GrantRefDigestSha256 = Sha256("alias-release:grant"),
            HandoffDigestSha256 = Sha256("alias-release:handoff"),
            HandoffIssuedAtUtc = Now.UtcDateTime.AddHours(-2),
            HandoffExpiresAtUtc = Now.UtcDateTime.AddHours(1),
            DownloadCompletedAtUtc = Now.UtcDateTime.AddHours(-1),
            InstallationId = installationId.ToString("D"),
            HardwareIdHash = canonicalDigest,
            Version = "2026.10",
            InstallerFilename = "tkt-002041-alias-release.bin",
            InstallerSha256 = Sha256("alias-release:installer"),
            ExecutableSha256 = Sha256("alias-release:executable"),
            NativeDllSha256 = Sha256("alias-release:native"),
            CoreSha256 = Sha256("alias-release:core"),
            ApprovedBinariesSource = "test",
            State = "active",
            BoundAtUtc = Now.UtcDateTime.AddHours(-2),
            InitialSecurityEpoch = 1
        });
        var encryptionKeyId = "tkt-002041-alias-release-public";
        var challengeKeyId = "tkt-002041-alias-release-challenge";
        seedDatabase.RuntimeEnrollmentKeyRegistries.Add(new RuntimeEnrollmentKeyRegistry
        {
            Purpose = "encryption",
            KeyId = encryptionKeyId,
            MaterialDigestSha256 = Sha256("alias-release:public-material"),
            State = "active",
            Epoch = 1,
            CreatedAtUtc = Now.UtcDateTime.AddHours(-2)
        });
        seedDatabase.RuntimeEnrollmentKeyRegistries.Add(new RuntimeEnrollmentKeyRegistry
        {
            Purpose = "encryption",
            KeyId = challengeKeyId,
            MaterialDigestSha256 = Sha256("alias-release:challenge-material"),
            State = "active",
            Epoch = 1,
            CreatedAtUtc = Now.UtcDateTime.AddHours(-2)
        });
        seedDatabase.RuntimeEnrollments.Add(new RuntimeEnrollment
        {
            Id = Guid.NewGuid(),
            ClientId = "test-only",
            BindingId = bindingId,
            ProductId = seed.ProductId,
            LicenseId = seed.LicenseId,
            LicenseSeatId = seed.SeatId,
            InstallationId = installationId.ToString("D"),
            HardwareIdHash = canonicalDigest,
            ReleaseVersion = "2026.10",
            HandoffDigestSha256 = Sha256("alias-release:handoff"),
            SubjectRefDigestSha256 = Sha256("alias-release:subject"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            Algorithm = "RSA",
            KeyBackend = "test",
            AttestationLevel = "none",
            PublicKeySpkiCiphertext = "test-only",
            PublicKeySpkiKeyId = encryptionKeyId,
            PublicKeySpkiSha256 = Sha256("alias-release:public-key"),
            KeyThumbprint = "tkt-002041-alias-release-thumbprint",
            ChallengeCiphertext = "test-only",
            ChallengeKeyId = challengeKeyId,
            ChallengeDigestSha256 = Sha256("alias-release:challenge"),
            State = "ACTIVE",
            Epoch = 1,
            SecurityEpoch = 1,
            ChallengeExpiresAtUtc = Now.UtcDateTime.AddHours(1),
            CreatedAtUtc = Now.UtcDateTime.AddHours(-2),
            ActivatedAtUtc = Now.UtcDateTime.AddHours(-1),
            AuthorityEpoch = 1
        });
        seedDatabase.HardwareAuthorityAliases.Add(new HardwareAuthorityAlias
        {
            ProductId = seed.ProductId,
            LicenseId = seed.LicenseId,
            LicenseSeatId = seed.SeatId,
            RuntimeEnrollmentId = seedDatabase.RuntimeEnrollments.Local.Single().Id,
            BindingId = bindingId,
            MigrationRequestId = Guid.NewGuid(),
            LegacyHardwareIdSha256 = legacyDigest,
            CanonicalHardwareIdSha256 = canonicalDigest,
            SecurityEpoch = 1,
            AuthorityEpoch = 1,
            IsActive = true,
            CreatedAtUtc = Now.UtcDateTime.AddHours(-1)
        });
        await seedDatabase.SaveChangesAsync();

        var result = await fixture.Service(Now).AddAsync(
            "tia-connect-website-exclusions", new string('a', 64), seed.AddRequest());

        Assert.False(result.Idempotent);
        Assert.Equal(LicenseHardwareExclusionService.ExcludedOutcome, result.Response.Outcome);
        Assert.Equal(PortalDeactivationService.DeactivatedOutcome, result.Response.ReleaseOutcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.False((await verify.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
        var exclusion = Assert.Single(await verify.LicenseHardwareExclusions
            .Where(row => row.LicenseId == seed.LicenseId)
            .ToListAsync());
        Assert.Equal(HardwareId, exclusion.HardwareId);
    }

    /// <summary>Proves exact bytes replay the stored terminal and changed bytes conflict without mutation.</summary>
    [Fact]
    public async Task Add_ReplayAndConflict_KeepOneExclusionRow()
    {
        var seed = await fixture.SeedAsync("replay", active: true, seatAge: TimeSpan.FromHours(1), Now);
        var service = fixture.Service(Now);
        var request = seed.AddRequest();
        var first = await service.AddAsync("tia-connect-website-exclusions", new string('a', 64), request);

        var replay = await service.AddAsync("tia-connect-website-exclusions", new string('a', 64), request);
        Assert.True(replay.Idempotent);
        Assert.Equal(first.Response, replay.Response);

        var conflict = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.AddAsync("tia-connect-website-exclusions", new string('b', 64), request));
        Assert.Equal("idempotency_conflict", conflict.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.LicenseHardwareExclusions.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
    }

    /// <summary>Proves an exact add without release stores the none outcome and keeps the seat active.</summary>
    [Fact]
    public async Task Add_WithoutRelease_KeepsSeatActiveWithNoneOutcome()
    {
        var seed = await fixture.SeedAsync("no-release", active: true, seatAge: TimeSpan.FromHours(1), Now);

        var result = await fixture.Service(Now).AddAsync(
            "tia-connect-website-exclusions", new string('a', 64),
            seed.AddRequest() with { ReleaseActiveSeat = false });

        Assert.Equal("none", result.Response.ReleaseOutcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.True((await verify.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
        Assert.False((await verify.LicenseHardwareExclusions.SingleAsync(row => row.LicenseId == seed.LicenseId)).ReleaseActiveSeat);
    }

    /// <summary>Proves lift, exact lift replay and already-lifted keep one bounded terminal each.</summary>
    [Fact]
    public async Task Lift_ReplayAndAlreadyLifted_FollowTheDurableTerminals()
    {
        var seed = await fixture.SeedAsync("lift", active: false, seatAge: TimeSpan.FromHours(1), Now);
        var service = fixture.Service(Now);
        await service.AddAsync("tia-connect-website-exclusions", new string('a', 64), seed.AddRequest());
        var liftRequest = seed.LiftRequest();

        var lifted = await service.LiftAsync(LicenseHardwareExclusionService.S2SActor, "tia-connect-website-exclusions", liftRequest);
        Assert.Equal(LicenseHardwareExclusionService.LiftedOutcome, lifted.Outcome);
        var replay = await service.LiftAsync(LicenseHardwareExclusionService.S2SActor, "tia-connect-website-exclusions", liftRequest);
        Assert.Equal(LicenseHardwareExclusionService.LiftedOutcome, replay.Outcome);
        var again = await service.LiftAsync(
            LicenseHardwareExclusionService.S2SActor, "tia-connect-website-exclusions",
            liftRequest with { RequestId = Guid.NewGuid().ToString("D") });
        Assert.Equal(LicenseHardwareExclusionService.AlreadyLiftedOutcome, again.Outcome);

        await using var verify = fixture.Factory.CreateDbContext();
        var exclusion = await verify.LicenseHardwareExclusions.SingleAsync(row => row.LicenseId == seed.LicenseId);
        Assert.NotNull(exclusion.LiftedAtUtc);
        Assert.Equal(LicenseHardwareExclusionService.S2SActor, exclusion.LiftedByActor);

        // After the lift, the machine can be admitted again on the same licence.
        await LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
            verify, seed.LicenseId, HardwareId, HardwareId, CancellationToken.None);
    }

    /// <summary>Proves the bounded list returns active first and lifted lines only when included.</summary>
    [Fact]
    public async Task List_ReturnsActiveFirstAndLiftedOnlyWhenIncluded()
    {
        var seed = await fixture.SeedAsync("list", active: false, seatAge: TimeSpan.FromHours(1), Now);
        var service = fixture.Service(Now);
        await service.AddAsync("tia-connect-website-exclusions", new string('a', 64), seed.AddRequest());
        await service.LiftAsync(LicenseHardwareExclusionService.S2SActor, "tia-connect-website-exclusions", seed.LiftRequest());
        await service.AddAsync(
            "tia-connect-website-exclusions", new string('b', 64),
            seed.AddRequest() with { RequestId = Guid.NewGuid().ToString("D") });

        var activeOnly = await service.ListAsync(seed.ListRequest());
        Assert.Single(activeOnly.Entries);
        Assert.Null(activeOnly.Entries.Single().LiftedAtUtc);

        var includingLifted = await service.ListAsync(seed.ListRequest() with { IncludeLifted = true });
        Assert.Equal(2, includingLifted.Entries.Count);
        Assert.Null(includingLifted.Entries[0].LiftedAtUtc);
        Assert.NotNull(includingLifted.Entries[1].LiftedAtUtc);
    }

    /// <summary>
    /// Proves the shared admission refusal matrix: exact ordinal matching on both identities,
    /// licence scope isolation, and case sensitivity without any normalization.
    /// </summary>
    [Fact]
    public async Task Checker_MatchesOrdinalBothIdentitiesAndStaysLicenceScoped()
    {
        var seed = await fixture.SeedAsync("checker", active: false, seatAge: TimeSpan.FromHours(1), Now);
        var other = await fixture.SeedAsync("checker-other", active: false, seatAge: TimeSpan.FromHours(1), Now);
        await fixture.Service(Now).AddAsync("tia-connect-website-exclusions", new string('a', 64), seed.AddRequest());

        await using var db = fixture.Factory.CreateDbContext();
        // Exact canonical match on the submitted identity is refused with the stable code.
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(db, seed.LicenseId, HardwareId, null, CancellationToken.None));
        Assert.Equal(LicenseHardwareExclusionChecker.PublicErrorCode, refused.ErrorCode);
        Assert.Equal(StatusCodes.Status403Forbidden, refused.StatusCode);
        // The resolved effective identity is refused even when the submitted one differs.
        var alias = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
                db, seed.LicenseId, "0123456789ABCDEF", HardwareId, CancellationToken.None));
        Assert.Equal(LicenseHardwareExclusionChecker.PublicErrorCode, alias.ErrorCode);
        // Lowercase is a different ordinal identity: no case folding, no normalization.
        await LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
            db, seed.LicenseId, HardwareId.ToLowerInvariant(), null, CancellationToken.None);
        // Another licence of the same product stays free for the same machine.
        await LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
            db, other.LicenseId, HardwareId, HardwareId, CancellationToken.None);
    }

    /// <summary>Proves the lift replay of a different caller identity conflicts instead of stealing the lift.</summary>
    [Fact]
    public async Task Lift_SameRequestDifferentClient_Conflicts()
    {
        var seed = await fixture.SeedAsync("lift-conflict", active: false, seatAge: TimeSpan.FromHours(1), Now);
        var service = fixture.Service(Now);
        await service.AddAsync("tia-connect-website-exclusions", new string('a', 64), seed.AddRequest());

        await service.LiftAsync(LicenseHardwareExclusionService.AdminActor, string.Empty, seed.LiftRequest());
        var conflict = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.LiftAsync(LicenseHardwareExclusionService.S2SActor, "tia-connect-website-exclusions", seed.LiftRequest()));

        Assert.Equal("idempotency_conflict", conflict.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
    }

    /// <summary>Proves the closed portal reason releases an excluded fresh seat even at quota.</summary>
    [Fact]
    public async Task PortalDeactivation_ProviderAuthorityRelease_BypassesQuotaAndFreshSeatGuard()
    {
        // The portal service reads the database clock: seed the fresh seat relative to it.
        await using var clock = fixture.Factory.CreateDbContext();
        await clock.Database.OpenConnectionAsync();
        var dbNow = await RuntimeEnrollmentService.DatabaseNowAsync(clock, CancellationToken.None);
        var seed = await fixture.SeedAsync("portal-reason", active: true, seatAge: TimeSpan.FromMinutes(1), dbNow);
        await ExhaustQuotaAsync(seed);

        var result = await fixture.PortalService(Now).DeactivateAsync(
            "tia-connect-website-portal", new string('a', 64), seed.PortalRequest());

        Assert.Equal(PortalDeactivationService.DeactivatedOutcome, result.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.False((await verify.LicenseSeats.SingleAsync(row => row.Id == seed.SeatId)).IsActive);
        var operation = await verify.PortalDeactivationOperations.SingleAsync(row => row.RequestId == seed.RequestId);
        Assert.Equal(PortalDeactivationService.ProviderAuthorityReleaseReason, operation.Reason);
    }

    /// <summary>Hashes a validated test identifier exactly as the production resolver does.</summary>
    private static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));

    private async Task ExhaustQuotaAsync(SeededExclusionAuthority seed)
    {
        await using var db = fixture.Factory.CreateDbContext();
        await db.Database.OpenConnectionAsync();
        var dbNow = await RuntimeEnrollmentService.DatabaseNowAsync(db, CancellationToken.None);
        var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == seed.LicenseId);
        license.Type!.MaxActivationsPerDay = 1;
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = seed.LicenseId,
            HardwareId = "QUOTA-CONSUMED-SEAT",
            IsActive = false,
            FirstActivatedAt = dbNow.UtcDateTime.AddHours(-2),
            UnlinkedAt = dbNow.UtcDateTime.AddMinutes(-90)
        });
        db.PortalDeactivationOperations.Add(new PortalDeactivationOperation
        {
            RequestId = Guid.NewGuid(),
            ClientId = "tia-connect-website-portal",
            RequestFingerprintSha256 = new string('f', 64),
            ProductId = seed.ProductId,
            LicenseId = seed.LicenseId,
            HardwareId = "QUOTA-CONSUMED-SEAT",
            Reason = "settings_button",
            Outcome = "deactivated",
            CreatedAtUtc = dbNow.UtcDateTime.AddMinutes(-30)
        });
        await db.SaveChangesAsync();
    }
}

/// <summary>Owns one random PostgreSQL database and removes it after the exclusion test collection.</summary>
public sealed class LicenseHardwareExclusionPostgreSqlFixture : IAsyncLifetime
{
    private const string HardwareId = "ABCDEF0123456789";

    private string _maintenanceConnectionString = string.Empty;
    private string _database = string.Empty;

    /// <summary>Gets the factory bound only to the isolated TKT-002041 database.</summary>
    public PortalDeactivationPostgreSqlFixture.TestDbContextFactory Factory { get; private set; } = null!;

    /// <summary>Clones the random database from the shared full current-schema model.</summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("exclusion");
        _database = clone.DatabaseName;
        _maintenanceConnectionString = clone.MaintenanceConnectionString;
        Factory = new PortalDeactivationPostgreSqlFixture.TestDbContextFactory(clone.ConnectionString);
    }

    /// <summary>Drops the isolated database even when a contract test fails.</summary>
    public async Task DisposeAsync()
    {
        await DropDatabaseAsync();
    }

    /// <summary>Creates the exclusion service with a deterministic clock.</summary>
    public LicenseHardwareExclusionService Service(DateTimeOffset now) =>
        new(
            Factory,
            new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance,
            NullLogger<LicenseHardwareExclusionService>.Instance);

    /// <summary>Creates the portal deactivation service with the same deterministic clock.</summary>
    public PortalDeactivationService PortalService(DateTimeOffset now) =>
        new(Factory, new FixedTimeProvider(now), NullLogger<PortalDeactivationService>.Instance);

    /// <summary>Seeds one product-qualified licence and its exact seat with deterministic identifiers.</summary>
    public async Task<SeededExclusionAuthority> SeedAsync(
        string discriminator,
        bool active,
        TimeSpan seatAge,
        DateTimeOffset now)
    {
        var productId = DeterministicGuid(discriminator + ":product");
        var typeId = DeterministicGuid(discriminator + ":type");
        var licenseId = DeterministicGuid(discriminator + ":license");
        var seatId = DeterministicGuid(discriminator + ":seat");
        var requestId = DeterministicGuid(discriminator + ":request");
        await using var db = Factory.CreateDbContext();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TKT-002041 " + discriminator,
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = "test-only"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Exclusion test",
            Slug = "exclusion-" + discriminator
        });
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = "TKT2041-" + discriminator.ToUpperInvariant(),
            HardwareId = active ? HardwareId : null,
            ActivationDate = active ? now.UtcDateTime - seatAge : null,
            Seats =
            [
                new LicenseSeat
                {
                    Id = seatId,
                    LicenseId = licenseId,
                    HardwareId = HardwareId,
                    FirstActivatedAt = now.UtcDateTime - seatAge,
                    LastCheckInAt = now.UtcDateTime - TimeSpan.FromSeconds(30),
                    IsActive = active,
                    UnlinkedAt = active ? null : now.UtcDateTime - TimeSpan.FromMinutes(1)
                }
            ]
        });
        await db.SaveChangesAsync();
        return new SeededExclusionAuthority(productId, licenseId, seatId, requestId);
    }

    private async Task DropDatabaseAsync()
    {
        if (string.IsNullOrEmpty(_database) || string.IsNullOrEmpty(_maintenanceConnectionString))
            return;
        await PostgreSqlModelDatabase.DropAsync(_maintenanceConnectionString, _database);
        _database = string.Empty;
        _maintenanceConnectionString = string.Empty;
    }

    private static Guid DeterministicGuid(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        var hexadecimal = Convert.ToHexStringLower(bytes.AsSpan(0, 16)).ToCharArray();
        hexadecimal[12] = '4';
        hexadecimal[16] = '8';
        return Guid.ParseExact(
            $"{new string(hexadecimal, 0, 8)}-{new string(hexadecimal, 8, 4)}-{new string(hexadecimal, 12, 4)}-{new string(hexadecimal, 16, 4)}-{new string(hexadecimal, 20, 12)}",
            "D");
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

/// <summary>Contains deterministic exclusion identifiers for one PostgreSQL scenario.</summary>
/// <param name="ProductId">Exact product UUID.</param>
/// <param name="LicenseId">Exact licence UUID.</param>
/// <param name="SeatId">Exact seat UUID.</param>
/// <param name="RequestId">Exact default request UUID.</param>
public sealed record SeededExclusionAuthority(Guid ProductId, Guid LicenseId, Guid SeatId, Guid RequestId)
{
    private const string HardwareId = "ABCDEF0123456789";

    /// <summary>Builds the exact closed add request for this scenario.</summary>
    public LicenseHardwareExclusionRequest AddRequest() => new(
        LicenseHardwareExclusionService.RequestSchema,
        RequestId.ToString("D"),
        ProductId.ToString("D"),
        LicenseId.ToString("D"),
        HardwareId,
        true);

    /// <summary>Builds the exact closed lift request for this scenario.</summary>
    public LicenseHardwareExclusionLiftRequest LiftRequest() => new(
        LicenseHardwareExclusionService.LiftRequestSchema,
        RequestId.ToString("D"),
        ProductId.ToString("D"),
        LicenseId.ToString("D"),
        HardwareId);

    /// <summary>Builds the exact closed list request for this scenario.</summary>
    public LicenseHardwareExclusionListRequest ListRequest() => new(
        LicenseHardwareExclusionService.ListRequestSchema,
        RequestId.ToString("D"),
        ProductId.ToString("D"),
        LicenseId.ToString("D"),
        null);

    /// <summary>Builds the exact closed portal request carrying the provider-authority reason.</summary>
    public PortalDeactivationRequest PortalRequest() => new(
        PortalDeactivationService.RequestSchema,
        RequestId.ToString("D"),
        ProductId.ToString("D"),
        LicenseId.ToString("D"),
        HardwareId,
        PortalDeactivationService.ProviderAuthorityReleaseReason);
}
