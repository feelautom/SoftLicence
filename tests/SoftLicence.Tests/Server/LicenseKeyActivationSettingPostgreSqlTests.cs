using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Serializes the real PostgreSQL key-activation-setting contract tests on one isolated database.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LicenseKeyActivationSettingPostgreSqlCollection
    : ICollectionFixture<LicenseKeyActivationSettingPostgreSqlFixture>
{
    /// <summary>Gets the exact xUnit collection name used to serialize the isolated database fixture.</summary>
    public const string Name = "TKT-002475 license key activation setting PostgreSQL";
}

/// <summary>
/// Proves the additive migration, idempotent disable and lift terminals frozen in one receipt per
/// request, stale-replay safety, replay conflicts, and the admission checker on real PostgreSQL (TKT-002475).
/// </summary>
[Collection(LicenseKeyActivationSettingPostgreSqlCollection.Name)]
public sealed class LicenseKeyActivationSettingPostgreSqlTests(LicenseKeyActivationSettingPostgreSqlFixture fixture)
{
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 14, 0, 0, TimeSpan.Zero);

    /// <summary>Proves the additive migration is current and creates the settings and receipt tables.</summary>
    [Fact]
    public async Task Migration_IsCurrentAndCreatesSettingsTable()
    {
        await using var db = fixture.Factory.CreateDbContext();

        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT to_regclass('\"LicenseKeyActivationSettings\"') IS NOT NULL "
            + "AND to_regclass('\"LicenseKeyActivationOperations\"') IS NOT NULL";
        await db.Database.OpenConnectionAsync();
        Assert.True(Assert.IsType<bool>(await command.ExecuteScalarAsync()));
    }

    /// <summary>Proves a pose creates exactly one disabled row and one history entry.</summary>
    [Fact]
    public async Task Disable_CreatesDisabledRowAndHistory()
    {
        var seed = await fixture.SeedAsync("disable");
        var command = seed.Command();

        var result = await fixture.Service(Now).DisableAsync(command);

        Assert.False(result.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.DisabledOutcome, result.Response.Outcome);
        Assert.Equal(LicenseKeyActivationSettingService.ResponseSchema, result.Response.Schema);
        await using var verify = fixture.Factory.CreateDbContext();
        var setting = Assert.Single(await verify.LicenseKeyActivationSettings
            .Where(row => row.LicenseId == seed.LicenseId)
            .ToListAsync());
        Assert.True(setting.Disabled);
        Assert.Equal(command.RequestId, setting.DisabledByRequestId);
        Assert.Equal(LicenseKeyActivationSettingService.S2SActor, setting.DisabledByActor);
        Assert.Null(setting.LiftedAtUtc);
        Assert.Null(setting.LiftedByRequestId);
        var history = Assert.Single(await verify.LicenseHistories
            .Where(row => row.LicenseId == seed.LicenseId)
            .ToListAsync());
        Assert.Equal(HistoryActions.KeyActivationDisabled, history.Action);
        Assert.Contains(command.RequestId.ToString("D"), history.Details);
        Assert.Equal("S2S:provider-settings-client", history.PerformedBy);
    }

    /// <summary>Proves an exact replay returns the original terminal without writing anything.</summary>
    [Fact]
    public async Task Disable_ExactReplay_ReturnsOriginalTerminalWithoutWrites()
    {
        var seed = await fixture.SeedAsync("disable-replay");
        var service = fixture.Service(Now);
        var command = seed.Command();
        await service.DisableAsync(command);

        var replay = await service.DisableAsync(command);

        Assert.True(replay.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.DisabledOutcome, replay.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.LicenseKeyActivationSettings.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
        Assert.Single(await verify.LicenseHistories.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
    }

    /// <summary>Proves a second disable on an already-disabled license is a stable terminal without history.</summary>
    [Fact]
    public async Task Disable_SecondRequest_IsAlreadyDisabledWithoutHistory()
    {
        var seed = await fixture.SeedAsync("already-disabled");
        var service = fixture.Service(Now);
        await service.DisableAsync(seed.Command());

        var second = await service.DisableAsync(seed.Command() with { RequestId = Guid.NewGuid() });

        Assert.False(second.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.AlreadyDisabledOutcome, second.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.LicenseHistories.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
    }

    /// <summary>Proves a lift updates the stored row with its own request memory and history entry.</summary>
    [Fact]
    public async Task Lift_AfterDisable_StoresLiftMemoryAndHistory()
    {
        var seed = await fixture.SeedAsync("lift");
        var service = fixture.Service(Now);
        await service.DisableAsync(seed.Command());
        var liftCommand = seed.Command() with { RequestId = Guid.NewGuid() };

        var lifted = await service.LiftAsync(liftCommand);

        Assert.False(lifted.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.LiftedOutcome, lifted.Response.Outcome);
        Assert.Equal(LicenseKeyActivationSettingService.ResponseLiftSchema, lifted.Response.Schema);
        await using var verify = fixture.Factory.CreateDbContext();
        var setting = await verify.LicenseKeyActivationSettings.SingleAsync(row => row.LicenseId == seed.LicenseId);
        Assert.False(setting.Disabled);
        Assert.Equal(liftCommand.RequestId, setting.LiftedByRequestId);
        Assert.Equal(LicenseKeyActivationSettingService.S2SActor, setting.LiftedByActor);
        Assert.Equal("provider-settings-client", setting.LiftedByClientId);
        var history = Assert.Single(await verify.LicenseHistories
            .Where(row => row.LicenseId == seed.LicenseId && row.Action == HistoryActions.KeyActivationLifted)
            .ToListAsync());
        Assert.Equal(seed.LicenseId, history.LicenseId);
    }

    /// <summary>Proves lift replays and repeats return their stable terminal without new history.</summary>
    [Fact]
    public async Task Lift_ReplayAndRepeat_AreStableTerminals()
    {
        var seed = await fixture.SeedAsync("lift-repeat");
        var service = fixture.Service(Now);
        await service.DisableAsync(seed.Command());
        var liftCommand = seed.Command() with { RequestId = Guid.NewGuid() };
        await service.LiftAsync(liftCommand);

        var replay = await service.LiftAsync(liftCommand);
        var repeat = await service.LiftAsync(seed.Command() with { RequestId = Guid.NewGuid() });

        Assert.True(replay.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.LiftedOutcome, replay.Response.Outcome);
        Assert.False(repeat.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.AlreadyLiftedOutcome, repeat.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.LicenseHistories
            .Where(row => row.LicenseId == seed.LicenseId && row.Action == HistoryActions.KeyActivationLifted)
            .ToListAsync());
    }

    /// <summary>Proves lifting a setting that was never disabled creates no row and no history.</summary>
    [Fact]
    public async Task Lift_WithoutSetting_IsAlreadyLiftedWithoutRow()
    {
        var seed = await fixture.SeedAsync("lift-absent");

        var result = await fixture.Service(Now).LiftAsync(seed.Command());

        Assert.False(result.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.AlreadyLiftedOutcome, result.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Empty(await verify.LicenseKeyActivationSettings.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
        Assert.Empty(await verify.LicenseHistories.Where(row => row.LicenseId == seed.LicenseId).ToListAsync());
        var receipt = await verify.LicenseKeyActivationOperations.SingleAsync(row => row.LicenseId == seed.LicenseId);
        Assert.Equal(LicenseKeyActivationSettingService.LiftIntent, receipt.Intent);
        Assert.Equal(LicenseKeyActivationSettingService.AlreadyLiftedOutcome, receipt.Outcome);
    }

    /// <summary>Proves a pose after a lift re-disables the same row and clears the lift memory.</summary>
    [Fact]
    public async Task Disable_AfterLift_ReDisablesAndClearsLiftMemory()
    {
        var seed = await fixture.SeedAsync("re-disable");
        var service = fixture.Service(Now);
        await service.DisableAsync(seed.Command());
        await service.LiftAsync(seed.Command() with { RequestId = Guid.NewGuid() });
        var reDisable = seed.Command() with { RequestId = Guid.NewGuid() };

        var result = await service.DisableAsync(reDisable);

        Assert.Equal(LicenseKeyActivationSettingService.DisabledOutcome, result.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        var setting = Assert.Single(await verify.LicenseKeyActivationSettings
            .Where(row => row.LicenseId == seed.LicenseId)
            .ToListAsync());
        Assert.True(setting.Disabled);
        Assert.Equal(reDisable.RequestId, setting.DisabledByRequestId);
        Assert.Null(setting.LiftedAtUtc);
        Assert.Null(setting.LiftedByRequestId);
        Assert.Null(setting.LiftedByActor);
        Assert.Null(setting.LiftedByClientId);
        Assert.Equal(3, await verify.LicenseHistories.CountAsync(row => row.LicenseId == seed.LicenseId));
    }

    /// <summary>
    /// Proves an old pose replayed after a newer lift is answered from its receipt only: the replay
    /// returns <c>disabled</c> and the license stays lifted (PR #422, point 3).
    /// </summary>
    [Fact]
    public async Task Disable_StaleReplayAfterLift_NeverUndoesTheLift()
    {
        var seed = await fixture.SeedAsync("stale-disable");
        var service = fixture.Service(Now);
        var pose = seed.Command();
        await service.DisableAsync(pose);
        await service.LiftAsync(seed.Command());

        var replay = await service.DisableAsync(pose);

        Assert.True(replay.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.DisabledOutcome, replay.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.False(await LicenseKeyActivationChecker.IsDisabledAsync(verify, seed.LicenseId));
        Assert.Equal(2, await verify.LicenseHistories.CountAsync(row => row.LicenseId == seed.LicenseId));
    }

    /// <summary>
    /// Proves an old lift replayed after a newer pose is answered from its receipt only: the replay
    /// returns <c>lifted</c> and the license stays disabled (PR #422, point 3).
    /// </summary>
    [Fact]
    public async Task Lift_StaleReplayAfterReDisable_NeverUndoesThePose()
    {
        var seed = await fixture.SeedAsync("stale-lift");
        var service = fixture.Service(Now);
        await service.DisableAsync(seed.Command());
        var lift = seed.Command();
        await service.LiftAsync(lift);
        await service.DisableAsync(seed.Command());

        var replay = await service.LiftAsync(lift);

        Assert.True(replay.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.LiftedOutcome, replay.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.True(await LicenseKeyActivationChecker.IsDisabledAsync(verify, seed.LicenseId));
        Assert.Equal(3, await verify.LicenseHistories.CountAsync(row => row.LicenseId == seed.LicenseId));
    }

    /// <summary>
    /// Proves an <c>already_disabled</c> terminal is frozen too: its replay returns the same terminal, and
    /// every request owns exactly one receipt with its intent, product, license and outcome.
    /// </summary>
    [Fact]
    public async Task Receipts_FreezeEveryTerminal_IncludingAlreadyDisabled()
    {
        var seed = await fixture.SeedAsync("receipts");
        var service = fixture.Service(Now);
        var first = seed.Command();
        var second = seed.Command();
        await service.DisableAsync(first);
        await service.DisableAsync(second);
        await service.LiftAsync(seed.Command());

        var replay = await service.DisableAsync(second);

        Assert.True(replay.Idempotent);
        Assert.Equal(LicenseKeyActivationSettingService.AlreadyDisabledOutcome, replay.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        var receipts = await verify.LicenseKeyActivationOperations
            .Where(row => row.LicenseId == seed.LicenseId)
            .ToListAsync();
        Assert.Equal(3, receipts.Count);
        Assert.All(receipts, receipt =>
        {
            Assert.Equal(seed.ProductId, receipt.ProductId);
            Assert.Equal(LicenseKeyActivationSettingService.S2SActor, receipt.Actor);
        });
        var secondReceipt = Assert.Single(receipts, row => row.RequestId == second.RequestId);
        Assert.Equal(LicenseKeyActivationSettingService.DisableIntent, secondReceipt.Intent);
        Assert.Equal(LicenseKeyActivationSettingService.AlreadyDisabledOutcome, secondReceipt.Outcome);
    }

    /// <summary>Proves a pose request UUID reused for a lift is an idempotency conflict without effect.</summary>
    [Fact]
    public async Task Lift_WithPoseRequestId_IsIdempotencyConflict()
    {
        var seed = await fixture.SeedAsync("intent-conflict");
        var service = fixture.Service(Now);
        var pose = seed.Command();
        await service.DisableAsync(pose);

        var failure = await Assert.ThrowsAsync<DistributionOperationException>(() => service.LiftAsync(pose));

        Assert.Equal("idempotency_conflict", failure.ErrorCode);
        Assert.Equal(409, failure.StatusCode);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.True(await LicenseKeyActivationChecker.IsDisabledAsync(verify, seed.LicenseId));
    }

    /// <summary>Proves an unknown product/license pair is refused before any write.</summary>
    [Fact]
    public async Task Disable_UnknownLicense_IsTargetNotFound()
    {
        var seed = await fixture.SeedAsync("unknown");
        var command = seed.Command() with { LicenseId = Guid.NewGuid() };

        var failure = await Assert.ThrowsAsync<DistributionOperationException>(
            () => fixture.Service(Now).DisableAsync(command));

        Assert.Equal("target_not_found", failure.ErrorCode);
        Assert.Equal(404, failure.StatusCode);
    }

    /// <summary>Proves a recorded request replayed against another license is an idempotency conflict.</summary>
    [Fact]
    public async Task Disable_ReplayedRequestId_OnOtherLicense_IsIdempotencyConflict()
    {
        var first = await fixture.SeedAsync("conflict-first");
        var second = await fixture.SeedAsync("conflict-second");
        var service = fixture.Service(Now);
        var recorded = first.Command();
        await service.DisableAsync(recorded);

        var failure = await Assert.ThrowsAsync<DistributionOperationException>(
            () => service.DisableAsync(second.Command() with { RequestId = recorded.RequestId }));

        Assert.Equal("idempotency_conflict", failure.ErrorCode);
        Assert.Equal(409, failure.StatusCode);
    }

    /// <summary>
    /// Proves the legacy admission checker refuses only the exact disabled license: another license
    /// without the setting and the same license after a lift both keep the current behavior.
    /// </summary>
    [Fact]
    public async Task Checker_RefusesDisabledLicense_AndAllowsOthers()
    {
        var guarded = await fixture.SeedAsync("checker-guarded");
        var other = await fixture.SeedAsync("checker-other");
        var service = fixture.Service(Now);
        await service.DisableAsync(guarded.Command());

        await using var db = fixture.Factory.CreateDbContext();
        Assert.True(await LicenseKeyActivationChecker.IsDisabledAsync(db, guarded.LicenseId));
        Assert.False(await LicenseKeyActivationChecker.IsDisabledAsync(db, other.LicenseId));

        await service.LiftAsync(guarded.Command() with { RequestId = Guid.NewGuid() });
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.False(await LicenseKeyActivationChecker.IsDisabledAsync(verify, guarded.LicenseId));
    }
}

/// <summary>Owns the isolated TKT-002475 PostgreSQL database and the deterministic service factory.</summary>
public sealed class LicenseKeyActivationSettingPostgreSqlFixture : IAsyncLifetime
{
    private string _maintenanceConnectionString = string.Empty;
    private string _database = string.Empty;

    /// <summary>Gets the factory bound only to the isolated TKT-002475 database.</summary>
    public PortalDeactivationPostgreSqlFixture.TestDbContextFactory Factory { get; private set; } = null!;

    /// <summary>Clones the random database from the shared full current-schema model.</summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("keyactivation");
        _database = clone.DatabaseName;
        _maintenanceConnectionString = clone.MaintenanceConnectionString;
        Factory = new PortalDeactivationPostgreSqlFixture.TestDbContextFactory(clone.ConnectionString);
    }

    /// <summary>Drops the isolated database even when a contract test fails.</summary>
    public async Task DisposeAsync()
    {
        await DropDatabaseAsync();
    }

    /// <summary>Creates the setting service with a deterministic clock.</summary>
    public LicenseKeyActivationSettingService Service(DateTimeOffset now) =>
        new(Factory, new FixedTimeProvider(now), NullLogger<LicenseKeyActivationSettingService>.Instance);

    /// <summary>Seeds one product-qualified license with deterministic identifiers.</summary>
    public async Task<SeededKeyActivationLicense> SeedAsync(string discriminator)
    {
        var productId = DeterministicGuid(discriminator + ":product");
        var typeId = DeterministicGuid(discriminator + ":type");
        var licenseId = DeterministicGuid(discriminator + ":license");
        await using var db = Factory.CreateDbContext();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TKT-002475 " + discriminator,
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = "test-only"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Key activation test",
            Slug = "key-activation-" + discriminator
        });
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = "TKT2475-" + discriminator.ToUpperInvariant()
        });
        await db.SaveChangesAsync();
        return new SeededKeyActivationLicense(productId, licenseId);
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
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value));
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

/// <summary>Contains deterministic identifiers for one key-activation PostgreSQL scenario.</summary>
/// <param name="ProductId">Exact product UUID.</param>
/// <param name="LicenseId">Exact license UUID.</param>
public sealed record SeededKeyActivationLicense(Guid ProductId, Guid LicenseId)
{
    /// <summary>Builds the default S2S-shaped command for this license.</summary>
    public LicenseKeyActivationCommand Command() => new(
        Guid.NewGuid(),
        ProductId,
        LicenseId,
        LicenseKeyActivationSettingService.S2SActor,
        "provider-settings-client");
}
