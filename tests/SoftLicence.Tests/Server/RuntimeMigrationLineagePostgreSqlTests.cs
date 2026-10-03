using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Preserves the direct equal-digest Confirm path without requiring newly introduced historical receipts.</summary>
    [Fact]
    public async Task MigrationLineage_DirectDigestEqualityRetainsExistingAdmission()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "receipt-direct-equality");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var source = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == successor.SourceBindingId);
            var target = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == successor.BindingId);
            source.HardwareIdHash = target.HardwareIdHash;
            var alias = await db.HardwareAuthorityAliases.SingleAsync();
            alias.MigrationReceiptId = null;
            alias.MigrationRequestId = null;
            await db.SaveChangesAsync();
        }
        await scenario.Runtime.ConfirmAsync(successor.EnrollmentId, successor.ConfirmDigest,
            successor.ConfirmRequest, successor.ConfirmProof, IPAddress.Loopback);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(successor.EnrollmentId, (await check.HardwareAuthorityAliases.SingleAsync()).RuntimeEnrollmentId);
    }

    /// <summary>Rejects a foreign signing key or a changed signed body before any durable acceptance is created.</summary>
    /// <param name="wrongKey">Selects foreign-key forgery rather than a body-digest substitution.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MigrationLineage_UnacceptedSignatureNeverCreatesReceipt(bool wrongKey)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var attacker = RSA.Create(3072);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("accepted-body-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(wrongKey ? attacker : scenario.EnrollmentKey, "hardware-authority-migration",
            scenario.EnrollmentId, scenario.Options.ConfirmAudience, "-", digest);
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, wrongKey ? digest : Sha256("substituted-body"), request, proof, IPAddress.Loopback));
        Assert.Equal("authentication_failed", error.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await db.HardwareAuthorityMigrationReceipts.ToListAsync());
        Assert.Empty(await db.HardwareAuthorityAliases.ToListAsync());
    }

    /// <summary>Exact accepted migration replay returns the original bytes without duplicating its durable receipt.</summary>
    [Fact]
    public async Task MigrationLineage_ExactMigrationReplayCreatesOneReceipt()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("receipt-replay-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var first = await scenario.Runtime.MigrateHardwareAuthorityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var second = await scenario.Runtime.MigrateHardwareAuthorityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(first.Idempotent);
        Assert.True(second.Idempotent);
        Assert.Equal(first.ExactResponseBody, second.ExactResponseBody);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var receipt = Assert.Single(await db.HardwareAuthorityMigrationReceipts.ToListAsync());
        Assert.Equal(Guid.Parse(request.RequestId!), receipt.RequestId);
        Assert.Equal(receipt.Id, (await db.HardwareAuthorityAliases.SingleAsync()).MigrationReceiptId);
    }

    /// <summary>
    /// Changes only whitespace inside the retirement-state SQL literal: startup must reject the altered function
    /// even though a whitespace-stripping comparison would incorrectly consider the two bodies equivalent.
    /// </summary>
    [Fact]
    public async Task MigrationLineage_WhitespaceInsideGuardLiteralFailsStartup()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var registry = new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options));
        await registry.ValidateAsync();
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        const string original = SoftLicence.Server.Migrations.MigrationReceiptGuards.KeyRetentionSource;
        var altered = original.Replace("'retired'", "'ret ired'", StringComparison.Ordinal);
        Assert.NotEqual(original, altered);
        await ReplaceMigrationReceiptKeyGuardAsync(connection, altered);
        try { await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ValidateAsync()); }
        finally { await ReplaceMigrationReceiptKeyGuardAsync(connection, original); }
        await registry.ValidateAsync();
    }

    /// <summary>Replaces only the owned fixture's guard body, preserving its owner, security mode and fixed search path.</summary>
    /// <param name="connection">Administrator connection to the isolated synthetic database.</param>
    /// <param name="body">Closed test constant or its single intentional literal mutation; never user-controlled SQL.</param>
    private static Task ReplaceMigrationReceiptKeyGuardAsync(NpgsqlConnection connection, string body) =>
        ExecuteAsync(connection, "CREATE OR REPLACE FUNCTION public.runtime_migration_receipt_key_retirement() "
            + "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $guard$"
            + body + "$guard$;");

    /// <summary>
    /// Confirms that additive schema rollback is allowed only before proof exists; populated rollback preserves
    /// receipts and reports the explicit restore-backup requirement rather than silently discarding authority.
    /// </summary>
    /// <param name="acceptedProof">Whether a signed migration has committed durable evidence.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MigrationLineage_SchemaRollbackRequiresEmptyEvidence(bool acceptedProof)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        if (acceptedProof)
        {
            await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
            await MigrateScenarioAsync(scenario);
        }
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options;
        await using var admin = new LicenseDbContext(options);
        var migrator = admin.GetService<IMigrator>();
        const string previous = "20260929190522_AddAssignmentEnforcementSwitch";
        if (acceptedProof)
        {
            var dataBefore = await Tkt976_BusinessFingerprintAsync(scenario.AdminConnectionString);
            var schemaBefore = await ReadMigrationReceiptSchemaAsync(scenario.AdminConnectionString);
            var migrationsBefore = (await admin.Database.GetAppliedMigrationsAsync()).ToArray();
            var envelope = await Assert.ThrowsAsync<InvalidOperationException>(() => migrator.MigrateAsync(previous));
            var error = Assert.IsType<PostgresException>(envelope.InnerException);
            Assert.Equal("55000", error.SqlState);
            Assert.Equal("durable migration receipts exist; restore a verified backup instead of dropping proof", error.MessageText);
            Assert.Single(await admin.HardwareAuthorityMigrationReceipts.ToListAsync());
            Assert.Equal(dataBefore, await Tkt976_BusinessFingerprintAsync(scenario.AdminConnectionString));
            Assert.Equal(schemaBefore, await ReadMigrationReceiptSchemaAsync(scenario.AdminConnectionString));
            Assert.Equal(migrationsBefore, (await admin.Database.GetAppliedMigrationsAsync()).ToArray());
            await new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)).ValidateAsync();
        }
        else
        {
            await migrator.MigrateAsync(previous);
            await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT to_regclass('public.\"HardwareAuthorityMigrationReceipts\"') IS NULL";
            Assert.True((bool)(await command.ExecuteScalarAsync())!);
            await migrator.MigrateAsync();
            Assert.Empty(await admin.HardwareAuthorityMigrationReceipts.ToListAsync());
        }
    }

    /// <summary>Snapshots receipt-related columns, constraints, indexes, triggers, guard functions and history without returning row data.</summary>
    /// <param name="connectionString">Administrator connection to the caller-owned synthetic database only.</param>
    /// <returns>Ordered catalogue definitions and a history digest for exact before/after rollback comparison.</returns>
    private static async Task<string[]> ReadMigrationReceiptSchemaAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT definition FROM (
                SELECT 'column:' || table_name || ':' || column_name || ':' || to_jsonb(c)::text AS definition
                FROM information_schema.columns c
                WHERE table_schema = 'public' AND table_name IN ('HardwareAuthorityMigrationReceipts', 'HardwareAuthorityAliases')
                UNION ALL
                SELECT 'constraint:' || c.conname || ':' || pg_get_constraintdef(c.oid)
                FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = 'public' AND t.relname IN ('HardwareAuthorityMigrationReceipts', 'HardwareAuthorityAliases')
                UNION ALL
                SELECT 'index:' || indexname || ':' || indexdef FROM pg_indexes
                WHERE schemaname = 'public' AND tablename IN ('HardwareAuthorityMigrationReceipts', 'HardwareAuthorityAliases')
                UNION ALL
                SELECT 'trigger:' || t.tgname || ':' || t.tgenabled::text || ':' || pg_get_triggerdef(t.oid)
                FROM pg_trigger t WHERE t.tgname IN ('TR_MigrationReceipt_Immutable', 'TR_MigrationReceipt_NoTruncate', 'TR_MigrationReceipt_KeyRetention')
                UNION ALL
                SELECT 'function:' || p.proname || ':' || pg_get_functiondef(p.oid)
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND p.proname IN ('runtime_migration_receipt_immutable', 'runtime_migration_receipt_key_retirement')
                UNION ALL
                SELECT 'history:' || md5(COALESCE(jsonb_agg(to_jsonb(h) ORDER BY to_jsonb(h)::text)::text, '[]'))
                FROM public."LicenseHistories" h
            ) snapshot ORDER BY definition COLLATE "C";
            """, connection);
        var definitions = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) definitions.Add(reader.GetString(0));
        Assert.NotEmpty(definitions);
        return definitions.ToArray();
    }

    /// <summary>Accepts the historical server shape S without an L-to-S receipt after a real signed S-to-U migration.</summary>
    /// <remarks>The old alias is not backfilled. Only the new accepted edge is a receipt root;
    /// Finalize, Prepare and signed successor Confirm all use the real services.</remarks>
    [Fact]
    public async Task MigrationLineage_HistoricalStableBindingWithoutReceipt_SignedUuidMigrationConfirmsSuccessor()
        => await ExerciseHistoricalStableConfirmAsync("none");

    /// <summary>Accepts the legitimate historical backfill shape with a null request id, without rewriting it.</summary>
    [Fact]
    public async Task MigrationLineage_HistoricalBackfillWithoutRequestOrReceipt_SignedUuidMigrationConfirmsSuccessor()
        => await ExerciseHistoricalStableConfirmAsync("backfill");

    /// <summary>Replays the exact signed Confirm after selection without changing the retained historical alias.</summary>
    [Fact]
    public async Task MigrationLineage_HistoricalSelection_ExactConfirmReplayIsIdempotent()
        => await ExerciseHistoricalStableConfirmAsync("exact-replay");

    /// <summary>Observes both exact Confirms blocked before allowing one selection and one replay.</summary>
    [Fact]
    public async Task MigrationLineage_HistoricalSelection_ConcurrentExactConfirmsRepointOnce()
        => await ExerciseHistoricalStableConfirmAsync("concurrent");

    /// <summary>Exercises historical selection after real key rotation and migration nonce retention cleanup.</summary>
    [Fact]
    public async Task MigrationLineage_HistoricalSelection_RotationAndNonceRetentionPreserveReceipt()
        => await ExerciseHistoricalStableConfirmAsync("rotation-retention");

    /// <summary>Rejects a real server-accepted foreign receipt on the new historical selection path.</summary>
    [Fact]
    public async Task MigrationLineage_HistoricalSelection_RealForeignReceiptCannotAuthorizeCurrentAlias()
        => await ExerciseHistoricalStableConfirmAsync("real-foreign-receipt");

    /// <summary>Proves PostgreSQL rejects a second same-license S root before Confirm, preserving the genuine accepted root.</summary>
    /// <remarks>This is an exact database uniqueness proof, not a claim that two authenticated candidates reached Confirm.</remarks>
    [Fact]
    public async Task MigrationLineage_HistoricalSelection_DuplicateCurrentRootFailsDatabaseUniqueness()
        => await ExerciseHistoricalStableConfirmAsync("duplicate-current-root");

    /// <summary>Rejects a foreign or ambiguous historical companion without mutating either alias or consuming Confirm.</summary>
    [Theory]
    [InlineData("historical-product")]
    [InlineData("historical-license")]
    [InlineData("historical-seat")]
    [InlineData("historical-binding")]
    [InlineData("historical-enrollment")]
    [InlineData("historical-destination")]
    [InlineData("historical-source-is-target")]
    [InlineData("historical-security")]
    [InlineData("historical-authority")]
    [InlineData("historical-time")]
    [InlineData("historical-request-empty")]
    [InlineData("historical-receipt-borrowed")]
    [InlineData("current-receipt-missing")]
    [InlineData("current-request-forged")]
    [InlineData("current-source-foreign")]
    [InlineData("current-destination-foreign")]
    [InlineData("current-disabled")]
    [InlineData("second-current-alias")]
    public async Task MigrationLineage_HistoricalCompanionMutationFailsClosed(string mutation)
        => await ExerciseHistoricalStableConfirmAsync(mutation);

    /// <summary>Runs the exact old-server S shape, genuine signed migration, and real successor protocol.</summary>
    /// <param name="mutation">A named positive lifecycle variant or one bounded adversarial mutation.
    /// Every positive preserves the entire historical row from before migration through Confirm;
    /// concurrent Confirm observes both waiters, while rotation retains the receipt key and removes only replay nonces.</param>
    private static async Task ExerciseHistoricalStableConfirmAsync(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subjectRef = Base64Url(SHA256.HashData("historical-stable-receipt-subject"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await SeedPreUuidStableSeatAsync(scenario, bindingCarriesLegacy: false);
        if (mutation == "backfill")
        {
            await using var backfill = await scenario.Factory.CreateDbContextAsync();
            (await backfill.HardwareAuthorityAliases.SingleAsync()).MigrationRequestId = null;
            await backfill.SaveChangesAsync();
        }
        var adversarial = mutation is not ("none" or "backfill" or "exact-replay" or "concurrent" or "rotation-retention" or "duplicate-current-root");
        Guid historicalAliasId;
        string historicalBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            var historical = Assert.Single(await before.HardwareAuthorityAliases.AsNoTracking().ToListAsync());
            historicalAliasId = historical.Id;
            historicalBefore = JsonSerializer.Serialize(historical);
            if (mutation == "backfill") Assert.Null(historical.MigrationRequestId);
            else Assert.NotNull(historical.MigrationRequestId);
            Assert.Null(historical.MigrationReceiptId);
            Assert.Equal(Sha256(LegacyHardwareId), historical.LegacyHardwareIdSha256);
            Assert.Equal(Sha256(PreUuidStableHardwareId), historical.CanonicalHardwareIdSha256);
            Assert.Empty(await before.HardwareAuthorityMigrationReceipts.ToListAsync());
            Assert.Equal(Sha256(PreUuidStableHardwareId),
                (await before.DistributionInstallationBindings.SingleAsync()).HardwareIdHash);
            Assert.Equal(Sha256(PreUuidStableHardwareId),
                (await before.RuntimeEnrollments.SingleAsync()).HardwareIdHash);
        }
        var request = MigrationRequest(scenario, PreUuidStableHardwareId, StableHardwareId);
        var digest = Sha256("historical-stable-signed-migration");
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var migration = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.Equal("migrated", migration.Response.Decision);
        Guid rootReceiptId;
        Guid currentAliasId;
        await using (var migrated = await scenario.Factory.CreateDbContextAsync())
        {
            var receipt = Assert.Single(await migrated.HardwareAuthorityMigrationReceipts.AsNoTracking().ToListAsync());
            rootReceiptId = receipt.Id;
            Assert.Null(receipt.ParentReceiptId);
            Assert.Equal(scenario.EnrollmentId, receipt.EnrollmentId);
            Assert.True(Guid.TryParse(request.RequestId, out var signedRequestId));
            Assert.Equal(signedRequestId, receipt.RequestId);
            var aliases = await migrated.HardwareAuthorityAliases.AsNoTracking().ToListAsync();
            Assert.Equal(2, aliases.Count);
            var oldAlias = Assert.Single(aliases, row => row.Id == historicalAliasId);
            Assert.Equal(historicalBefore, JsonSerializer.Serialize(oldAlias));
            Assert.Null(oldAlias.MigrationReceiptId);
            Assert.Equal(Sha256(PreUuidStableHardwareId), oldAlias.CanonicalHardwareIdSha256);
            var current = Assert.Single(aliases, row => row.Id != historicalAliasId);
            currentAliasId = current.Id;
            Assert.Equal(rootReceiptId, current.MigrationReceiptId);
            Assert.Equal(Sha256(PreUuidStableHardwareId), current.LegacyHardwareIdSha256);
            Assert.Equal(Sha256(StableHardwareId), current.CanonicalHardwareIdSha256);
            Assert.Equal(Sha256(PreUuidStableHardwareId),
                (await migrated.DistributionInstallationBindings.SingleAsync()).HardwareIdHash);
        }
        if (mutation == "duplicate-current-root")
        {
            string graphBefore;
            await using (var read = await scenario.Factory.CreateDbContextAsync())
                graphBefore = JsonSerializer.Serialize(await read.HardwareAuthorityAliases.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
            await using (var duplicate = await scenario.Factory.CreateDbContextAsync())
            {
                var second = await duplicate.HardwareAuthorityAliases.AsNoTracking().SingleAsync(row => row.Id == currentAliasId);
                second.Id = Guid.NewGuid();
                duplicate.HardwareAuthorityAliases.Add(second);
                var failure = await Assert.ThrowsAsync<DbUpdateException>(() => duplicate.SaveChangesAsync());
                var postgres = Assert.IsType<PostgresException>(failure.InnerException);
                Assert.Equal("23505", postgres.SqlState);
                Assert.Equal("IX_HardwareAuthorityAliases_LicenseId_LegacyHardwareIdSha256", postgres.ConstraintName);
            }
            await using var unchanged = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal(graphBefore, JsonSerializer.Serialize(await unchanged.HardwareAuthorityAliases.AsNoTracking()
                .OrderBy(row => row.Id).ToListAsync()));
            Assert.Equal(rootReceiptId, (await unchanged.HardwareAuthorityMigrationReceipts.SingleAsync()).Id);
        }
        await using var resolverDb = await scenario.Factory.CreateDbContextAsync();
        var distribution = await PrepareDistributionFinalizeAsync(scenario, subjectRef, StableHardwareId,
            hardwareAuthorityAliases: CreateAliasResolver(resolverDb));
        var finalized = await distribution.Service.FinalizeAsync(
            "website-step1", Sha256("historical-stable-finalize"), distribution.Request);
        var bindingId = Guid.Parse(finalized.Response.BindingId);
        using var successorKey = RSA.Create(3072);
        RuntimeEnrollmentPrepareRequest prepareRequest;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Equal(historicalBefore, JsonSerializer.Serialize(await db.HardwareAuthorityAliases.AsNoTracking()
                .SingleAsync(row => row.Id == historicalAliasId)));
            var binding = await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == bindingId);
            Assert.Equal(Sha256(StableHardwareId), binding.HardwareIdHash);
            Assert.Equal(scenario.Fixture.BindingId, binding.SupersededBindingId);
            prepareRequest = PrepareRequest((binding.ProductId, binding.Id, binding.HandoffDigestSha256,
                binding.InstallationId, binding.Version), Guid.NewGuid().ToString("D"), successorKey);
        }
        prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var prepared = await scenario.Runtime.PrepareAsync("website-step1", Sha256("historical-stable-prepare"), prepareRequest);
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema, ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"), Epoch = 1
        };
        var confirmDigest = Sha256("historical-stable-confirm");
        var confirmProof = Proof(successorKey, "confirm", enrollmentId, scenario.Options.ConfirmAudience,
            prepared.Response.Challenge, confirmDigest);
        if (adversarial)
        {
            await using var mutate = await scenario.Factory.CreateDbContextAsync();
            var historical = await mutate.HardwareAuthorityAliases.SingleAsync(row => row.Id == historicalAliasId);
            var current = await mutate.HardwareAuthorityAliases.SingleAsync(row => row.Id == currentAliasId);
            if (mutation is "historical-product" or "historical-license" or "historical-seat")
            {
                var foreign = await SeedAuthorityAsync(scenario.Factory, "2.2.944");
                var foreignBinding = await mutate.DistributionInstallationBindings.AsNoTracking()
                    .SingleAsync(row => row.Id == foreign.BindingId);
                if (mutation == "historical-product") historical.ProductId = foreign.ProductId;
                if (mutation == "historical-license") historical.LicenseId = foreignBinding.LicenseId;
                if (mutation == "historical-seat") historical.LicenseSeatId = foreignBinding.LicenseSeatId;
            }
            else if (mutation == "real-foreign-receipt")
            {
                using var foreign = await CreatePreparedBootstrapScenarioAsync();
                await ActivateCanonicalScenarioAsync(foreign, LegacyHardwareId);
                await MigrateScenarioAsync(foreign);
                await using var foreignDb = await foreign.Factory.CreateDbContextAsync();
                var borrowed = await foreignDb.HardwareAuthorityMigrationReceipts.AsNoTracking().SingleAsync();
                Assert.NotEqual(foreign.Fixture.ProductId, scenario.Fixture.ProductId);
                Assert.NotEqual(borrowed.EnrollmentId, scenario.EnrollmentId);
                // Preserve the genuine foreign envelope. Relabeling the indexed owner cannot authenticate it locally.
                borrowed.EnrollmentId = scenario.EnrollmentId;
                borrowed.KeyId = (await mutate.HardwareAuthorityMigrationReceipts.SingleAsync()).KeyId;
                mutate.HardwareAuthorityMigrationReceipts.Add(borrowed);
                current.MigrationReceiptId = borrowed.Id;
            }
            else switch (mutation)
            {
                case "historical-binding": historical.BindingId = bindingId; break;
                case "historical-enrollment": historical.RuntimeEnrollmentId = enrollmentId; break;
                case "historical-destination": historical.CanonicalHardwareIdSha256 = Sha256("foreign-destination"); break;
                case "historical-source-is-target": historical.LegacyHardwareIdSha256 = Sha256(StableHardwareId); break;
                case "historical-security": historical.SecurityEpoch = int.MaxValue; break;
                case "historical-authority": historical.AuthorityEpoch = long.MaxValue; break;
                case "historical-time": historical.CreatedAtUtc = DateTime.UtcNow.AddDays(1); break;
                case "historical-request-empty": historical.MigrationRequestId = Guid.Empty; break;
                case "historical-receipt-borrowed": historical.MigrationReceiptId = rootReceiptId; break;
                case "current-receipt-missing": current.MigrationReceiptId = null; break;
                case "current-request-forged": current.MigrationRequestId = Guid.NewGuid(); break;
                case "current-source-foreign": current.LegacyHardwareIdSha256 = Sha256("foreign-source"); break;
                case "current-destination-foreign": current.CanonicalHardwareIdSha256 = Sha256("foreign-target"); break;
                case "current-disabled":
                    current.IsActive = false; current.DisabledAtUtc = DateTime.UtcNow;
                    current.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason; break;
                case "second-current-alias": historical.CanonicalHardwareIdSha256 = Sha256(StableHardwareId); break;
                default: throw new InvalidOperationException("Unknown historical alias test mutation.");
            }
            await mutate.SaveChangesAsync();
        }
        string aliasesBefore;
        await using (var snapshot = await scenario.Factory.CreateDbContextAsync())
            aliasesBefore = JsonSerializer.Serialize(await snapshot.HardwareAuthorityAliases.AsNoTracking()
                .OrderBy(row => row.Id).ToListAsync());
        if (adversarial)
        {
            var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ConfirmAsync(
                enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback));
            if (mutation == "real-foreign-receipt") Assert.Equal("authority_unavailable", refusal.ErrorCode);
            else
            {
                Assert.Equal("enrollment_conflict", refusal.ErrorCode);
                Assert.Equal(mutation == "current-disabled" ? "confirm_alias_boundary_mismatch" : "confirm_alias_ambiguous",
                    refusal.DiagnosticCode);
            }
            await using var refused = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal(aliasesBefore, JsonSerializer.Serialize(await refused.HardwareAuthorityAliases.AsNoTracking()
                .OrderBy(row => row.Id).ToListAsync()));
            Assert.Equal("PENDING", (await refused.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).State);
            Assert.Empty(await refused.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "confirm").ToListAsync());
            return;
        }
        if (mutation == "concurrent")
        {
            var firstName = "historical-confirm-first-" + Guid.NewGuid().ToString("N");
            var secondName = "historical-confirm-second-" + Guid.NewGuid().ToString("N");
            var firstRuntime = CreateTaggedRuntime(scenario, firstName);
            var secondRuntime = CreateTaggedRuntime(scenario, secondName);
            using var firstCrypto = firstRuntime.Crypto;
            using var secondCrypto = secondRuntime.Crypto;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var ct = timeout.Token;
            await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
            await blocker.OpenAsync(ct);
            await using var transaction = await blocker.BeginTransactionAsync(ct);
            await using (var command = blocker.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
                await command.ExecuteNonQueryAsync(ct);
            }
            var first = CaptureConfirmAsync(firstRuntime.Runtime.ConfirmAsync(
                enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback, ct));
            var second = CaptureConfirmAsync(secondRuntime.Runtime.ConfirmAsync(
                enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback, ct));
            await WaitForAdvisoryWaitersAsync(scenario.AdminConnectionString,
                [firstName, secondName], minimumWaiters: 2, ct);
            await transaction.CommitAsync(ct);
            var outcomes = await Task.WhenAll(first, second).WaitAsync(ct);
            Assert.All(outcomes, outcome => Assert.Null(outcome.Error));
            Assert.Single(outcomes, outcome => outcome.Result is { Idempotent: false });
            Assert.Single(outcomes, outcome => outcome.Result is { Idempotent: true });
        }
        else if (mutation == "rotation-retention")
        {
            var previousOptions = JsonSerializer.Deserialize<RuntimeEnrollmentOptions>(JsonSerializer.Serialize(scenario.Options))
                ?? throw new InvalidOperationException("Synthetic runtime options could not be copied.");
            var oldKeyId = previousOptions.Encryption.ActiveKeyId;
            scenario.Options.KeyRegistryVersion++;
            scenario.Options.Encryption.ActiveKeyId = "historical-receipt-rotated-key";
            scenario.Options.Encryption.Keys.Add(new RuntimeEncryptionKeyOptions
            {
                KeyId = scenario.Options.Encryption.ActiveKeyId,
                KeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            });
            await RotateKeyRegistryAsync(scenario.AdminConnectionString, previousOptions, scenario.Options);
            await using (var retention = await scenario.Factory.CreateDbContextAsync())
            {
                Assert.Equal(oldKeyId, (await retention.HardwareAuthorityMigrationReceipts.SingleAsync()).KeyId);
                Assert.Equal(1, await retention.RuntimeEnrollmentProofNonces
                    .Where(row => row.Operation == "hardware-authority-migration").ExecuteDeleteAsync());
            }
            await new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options)).ValidateAsync();
            var restarted = scenario.CreateRestartedRuntime();
            using var crypto = restarted.Crypto;
            var confirmed = await restarted.Runtime.ConfirmAsync(enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback);
            Assert.False(confirmed.Idempotent);
            var withoutOldKey = JsonSerializer.Deserialize<RuntimeEnrollmentOptions>(JsonSerializer.Serialize(scenario.Options))
                ?? throw new InvalidOperationException("Synthetic rotated options could not be copied.");
            withoutOldKey.Encryption.Keys.RemoveAll(key => key.KeyId == oldKeyId);
            await Assert.ThrowsAsync<InvalidOperationException>(() => new RuntimeEnrollmentKeyRegistryService(
                scenario.Factory, Options.Create(withoutOldKey)).ValidateAsync());
        }
        else
        {
            var confirmed = await scenario.Runtime.ConfirmAsync(enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback);
            Assert.False(confirmed.Idempotent);
            if (mutation == "exact-replay")
            {
                var replay = await scenario.Runtime.ConfirmAsync(enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback);
                Assert.True(replay.Idempotent);
                Assert.Equal(confirmed.Response, replay.Response);
            }
        }
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(historicalBefore, JsonSerializer.Serialize(await check.HardwareAuthorityAliases.AsNoTracking()
            .SingleAsync(row => row.Id == historicalAliasId)));
        Assert.Equal("ACTIVE", (await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).State);
        var rebound = await check.HardwareAuthorityAliases.SingleAsync(row => row.Id == currentAliasId);
        Assert.Equal(enrollmentId, rebound.RuntimeEnrollmentId);
        Assert.Equal(bindingId, rebound.BindingId);
        Assert.Equal(rootReceiptId, rebound.MigrationReceiptId);
        Assert.Null((await check.HardwareAuthorityAliases.SingleAsync(row => row.Id == historicalAliasId)).MigrationReceiptId);
        Assert.Single(await check.HardwareAuthorityMigrationReceipts.ToListAsync());
        var seat = Assert.Single(await check.LicenseSeats.Where(row => row.IsActive).ToListAsync());
        Assert.Equal(StableHardwareId, seat.HardwareId);
        Assert.Single(await check.RuntimeEnrollmentProofNonces.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "confirm").ToListAsync());
    }

    /// <summary>Does not fabricate an old acceptance edge when a later signed migration extends an unproved alias.</summary>
    [Fact]
    public async Task MigrationLineage_UnprovedHistoricalParentIsNotBackfilled()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "unproved-parent",
            () => RemoveParentProofThenExtendAsync(scenario));
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Null((await db.HardwareAuthorityAliases.SingleAsync()).MigrationReceiptId);
            Assert.Single(await db.HardwareAuthorityMigrationReceipts.ToListAsync());
        }
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ConfirmAsync(
            successor.EnrollmentId, successor.ConfirmDigest, successor.ConfirmRequest, successor.ConfirmProof,
            IPAddress.Loopback));
        Assert.Equal("enrollment_conflict", error.ErrorCode);
        Assert.Equal("confirm_alias_boundary_mismatch", error.DiagnosticCode);
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>Removes only the synthetic alias's proof reference, then performs a genuine second signed migration.</summary>
    /// <param name="scenario">Owned active migration fixture.</param>
    private static async Task RemoveParentProofThenExtendAsync(PreparedBootstrapScenario scenario)
    {
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            (await db.HardwareAuthorityAliases.SingleAsync()).MigrationReceiptId = null;
            await db.SaveChangesAsync();
        }
        await ExtendSignedMigrationChainAsync(scenario);
    }

    /// <summary>Rejects a genuine accepted receipt borrowed from another product, license, seat and signing enrollment.</summary>
    [Fact]
    public async Task MigrationLineage_RealForeignReceiptCannotAuthorizeLocalSuccessor()
    {
        using var foreign = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(foreign, LegacyHardwareId);
        await MigrateScenarioAsync(foreign);
        await using var foreignDb = await foreign.Factory.CreateDbContextAsync();
        var borrowed = await foreignDb.HardwareAuthorityMigrationReceipts.AsNoTracking().SingleAsync();

        using var local = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(local, "foreign-accepted-receipt");
        await using (var db = await local.Factory.CreateDbContextAsync())
        {
            Assert.NotEqual(foreign.Fixture.ProductId, local.Fixture.ProductId);
            Assert.NotEqual(borrowed.EnrollmentId, successor.SourceEnrollmentId);
            var localReceipt = await db.HardwareAuthorityMigrationReceipts.SingleAsync();
            // The attacker relabels indexed ownership to satisfy local FKs; the genuine envelope still authenticates its foreign owner.
            borrowed.EnrollmentId = successor.SourceEnrollmentId;
            borrowed.KeyId = localReceipt.KeyId;
            db.HardwareAuthorityMigrationReceipts.Add(borrowed);
            (await db.HardwareAuthorityAliases.SingleAsync()).MigrationReceiptId = borrowed.Id;
            await db.SaveChangesAsync();
        }
        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => local.Runtime.ConfirmAsync(
            successor.EnrollmentId, successor.ConfirmDigest, successor.ConfirmRequest, successor.ConfirmProof,
            IPAddress.Loopback));
        Assert.Equal("authority_unavailable", error.ErrorCode);
        await AssertPendingSuccessorAndStaleAliasAsync(local, successor);
    }

    /// <summary>Proves a disabled storage/key guard prevents startup; restores only the exact test-disabled trigger.</summary>
    /// <param name="trigger">Allowlisted trigger under test.</param>
    [Theory]
    [InlineData("TR_MigrationReceipt_Immutable")]
    [InlineData("TR_MigrationReceipt_NoTruncate")]
    [InlineData("TR_MigrationReceipt_KeyRetention")]
    public async Task MigrationLineage_DisabledGuardFailsStartup(string trigger)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var table = trigger == "TR_MigrationReceipt_KeyRetention"
            ? "RuntimeEnrollmentKeyRegistries" : "HardwareAuthorityMigrationReceipts";
        var registry = new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options));
        await registry.ValidateAsync();
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"ALTER TABLE public.\"{table}\" DISABLE TRIGGER \"{trigger}\";");
        try { await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ValidateAsync()); }
        finally { await ExecuteAsync(connection, $"ALTER TABLE public.\"{table}\" ENABLE TRIGGER \"{trigger}\";"); }
        await registry.ValidateAsync();
    }

    /// <summary>
    /// Rotates the encryption key using the real registry procedure, retains the old receipt decrypt key,
    /// removes migration replay nonces, and confirms through a newly constructed runtime service.
    /// </summary>
    [Fact]
    public async Task MigrationLineage_KeyRotationPreservesOldReceiptAndRefusesKeyRemoval()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "receipt-rotation");
        var before = JsonSerializer.Deserialize<RuntimeEnrollmentOptions>(JsonSerializer.Serialize(scenario.Options))!;
        var oldKeyId = before.Encryption.ActiveKeyId;
        scenario.Options.KeyRegistryVersion++;
        scenario.Options.Encryption.ActiveKeyId = "receipt-rotated-key";
        scenario.Options.Encryption.Keys.Add(new RuntimeEncryptionKeyOptions
        {
            KeyId = scenario.Options.Encryption.ActiveKeyId,
            KeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        });
        await RotateKeyRegistryAsync(scenario.AdminConnectionString, before, scenario.Options);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Equal(oldKeyId, (await db.HardwareAuthorityMigrationReceipts.SingleAsync()).KeyId);
            await db.RuntimeEnrollmentProofNonces.Where(row => row.Operation == "hardware-authority-migration")
                .ExecuteDeleteAsync();
        }
        var registry = new RuntimeEnrollmentKeyRegistryService(scenario.Factory, Options.Create(scenario.Options));
        await registry.ValidateAsync();
        var restarted = scenario.CreateRestartedRuntime();
        using var crypto = restarted.Crypto;
        await restarted.Runtime.ConfirmAsync(successor.EnrollmentId, successor.ConfirmDigest,
            successor.ConfirmRequest, successor.ConfirmProof, IPAddress.Loopback);

        var withoutOldKey = JsonSerializer.Deserialize<RuntimeEnrollmentOptions>(JsonSerializer.Serialize(scenario.Options))!;
        withoutOldKey.Encryption.Keys.RemoveAll(key => key.KeyId == oldKeyId);
        await Assert.ThrowsAsync<InvalidOperationException>(() => new RuntimeEnrollmentKeyRegistryService(
            scenario.Factory, Options.Create(withoutOldKey)).ValidateAsync());
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(successor.EnrollmentId, (await check.HardwareAuthorityAliases.SingleAsync()).RuntimeEnrollmentId);
    }

    /// <summary>
    /// Injects an AFTER INSERT failure to prove receipt, alias, nonce, history and seat mutations share one transaction.
    /// The injection exists only in this owned synthetic database and is always removed before disposal.
    /// </summary>
    [Fact]
    public async Task MigrationLineage_FailureAfterReceiptInsertionRollsBackWholeMigration()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, """
            CREATE FUNCTION public.test_migration_receipt_insert_failure() RETURNS trigger
            LANGUAGE plpgsql AS $body$ BEGIN RAISE EXCEPTION 'injected after receipt insertion'; END; $body$;
            CREATE TRIGGER test_migration_receipt_insert_failure AFTER INSERT
            ON public."HardwareAuthorityMigrationReceipts" FOR EACH ROW
            EXECUTE FUNCTION public.test_migration_receipt_insert_failure();
            """);
        try
        {
            await Assert.ThrowsAsync<DbUpdateException>(() => MigrateScenarioAsync(scenario));
        }
        finally
        {
            await ExecuteAsync(connection, """
                DROP TRIGGER test_migration_receipt_insert_failure ON public."HardwareAuthorityMigrationReceipts";
                DROP FUNCTION public.test_migration_receipt_insert_failure();
                """);
        }
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await check.HardwareAuthorityMigrationReceipts.ToListAsync());
        Assert.Empty(await check.HardwareAuthorityAliases.ToListAsync());
        Assert.Empty(await check.RuntimeEnrollmentProofNonces.Where(row => row.Operation == "hardware-authority-migration").ToListAsync());
        Assert.Empty(await check.LicenseHistories.Where(row => row.Action == "HWID_V2_MIGRATED").ToListAsync());
        Assert.Equal(LegacyHardwareId, (await check.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId);
        Assert.Equal(1, (await check.RuntimeEnrollments.SingleAsync()).SecurityEpoch);
    }

    /// <summary>
    /// Proves two real signed migrations form a durable L-to-S-to-U chain; substituting the old head
    /// cannot authorize the final target. Both migration replay nonces are removed before Confirm.
    /// </summary>
    /// <param name="substituteOldHead">Whether to attack the final edge by restoring the first receipt reference.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MigrationLineage_SignedChainRequiresItsExactFinalEdge(bool substituteOldHead)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "receipt-chain",
            () => ExtendSignedMigrationChainAsync(scenario));
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var receipts = await db.HardwareAuthorityMigrationReceipts.ToListAsync();
            Assert.Equal(2, receipts.Count);
            var first = Assert.Single(receipts, row => row.ParentReceiptId == null);
            var second = Assert.Single(receipts, row => row.ParentReceiptId == first.Id);
            var alias = await db.HardwareAuthorityAliases.SingleAsync(row => row.Id == successor.AliasId);
            Assert.Equal(second.Id, alias.MigrationReceiptId);
            if (substituteOldHead) alias.MigrationReceiptId = first.Id;
            await db.SaveChangesAsync();
            Assert.Equal(2, await db.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == successor.SourceEnrollmentId && row.Operation == "hardware-authority-migration")
                .ExecuteDeleteAsync());
        }
        if (substituteOldHead)
        {
            var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ConfirmAsync(
                successor.EnrollmentId, successor.ConfirmDigest, successor.ConfirmRequest,
                successor.ConfirmProof, IPAddress.Loopback));
            Assert.Equal("enrollment_conflict", error.ErrorCode);
            Assert.Equal("confirm_alias_boundary_mismatch", error.DiagnosticCode);
            await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
        }
        else
        {
            await scenario.Runtime.ConfirmAsync(successor.EnrollmentId, successor.ConfirmDigest,
                successor.ConfirmRequest, successor.ConfirmProof, IPAddress.Loopback);
            await using var check = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal(successor.EnrollmentId, (await check.HardwareAuthorityAliases.SingleAsync()).RuntimeEnrollmentId);
            Assert.Equal(2, await check.HardwareAuthorityMigrationReceipts.CountAsync());
        }
    }

    /// <summary>Extends an accepted synthetic migration through a second actual signed request with a distinct UUID.</summary>
    /// <param name="scenario">Active source credential and isolated database after the first accepted migration.</param>
    private static async Task ExtendSignedMigrationChainAsync(PreparedBootstrapScenario scenario)
    {
        const string secondUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E33";
        var target = MachineIdentity.FromUuid(secondUuid).HardwareId
            ?? throw new InvalidOperationException("Synthetic chain UUID was refused.");
        var request = MigrationRequest(scenario, StableHardwareId, target);
        request.SystemUuid = secondUuid;
        var digest = Sha256("receipt-chain-second-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var result = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.Equal("migrated", result.Response.Decision);
    }

    /// <summary>Proves an accepted migration remains usable after actual deletion of its expiring replay nonce.</summary>
    [Fact]
    public async Task MigrationLineage_ConfirmAfterNoncePurgeRetainsDurableAcceptance()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "receipt-retention");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Single(await db.HardwareAuthorityMigrationReceipts.ToListAsync());
            var removed = await db.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == successor.SourceEnrollmentId && row.Operation == "hardware-authority-migration")
                .ExecuteDeleteAsync();
            Assert.Equal(1, removed);
        }
        await scenario.Runtime.ConfirmAsync(successor.EnrollmentId, successor.ConfirmDigest,
            successor.ConfirmRequest, successor.ConfirmProof, IPAddress.Loopback);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var alias = await check.HardwareAuthorityAliases.SingleAsync(row => row.Id == successor.AliasId);
        Assert.Equal(successor.EnrollmentId, alias.RuntimeEnrollmentId);
        Assert.Equal(successor.BindingId, alias.BindingId);
        Assert.Single(await check.HardwareAuthorityMigrationReceipts.ToListAsync());
    }

    /// <summary>
    /// Rejects missing or substituted durable lineage without advancing the successor or repointing its alias.
    /// Corrupt ciphertext keeps the distinct authority-unavailable error instead of becoming a business success.
    /// </summary>
    /// <param name="mutation">Exact receipt or linkage dimension corrupted in this isolated synthetic database.</param>
    /// <param name="expectedError">Public refusal preserving crypto versus authority-graph semantics.</param>
    [Theory]
    [InlineData("missing", "enrollment_conflict")]
    [InlineData("request", "enrollment_conflict")]
    [InlineData("alias-source", "enrollment_conflict")]
    [InlineData("binding-source", "enrollment_conflict")]
    [InlineData("signing-key", "enrollment_conflict")]
    [InlineData("borrowed-envelope", "authority_unavailable")]
    public async Task MigrationLineage_UnprovedOrSubstitutedReceiptFailsClosed(string mutation, string expectedError)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "receipt-" + mutation);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await db.HardwareAuthorityAliases.SingleAsync(row => row.Id == successor.AliasId);
            switch (mutation)
            {
                case "missing": alias.MigrationReceiptId = null; break;
                case "request": alias.MigrationRequestId = Guid.NewGuid(); break;
                case "alias-source": alias.LegacyHardwareIdSha256 = Sha256("foreign-machine"); break;
                case "binding-source":
                    (await db.DistributionInstallationBindings.SingleAsync(row => row.Id == successor.SourceBindingId))
                        .HardwareIdHash = Sha256("foreign-machine");
                    break;
                case "signing-key":
                    (await db.RuntimeEnrollments.SingleAsync(row => row.Id == successor.SourceEnrollmentId))
                        .PublicKeySpkiSha256 = Sha256("foreign-signing-key");
                    break;
                case "borrowed-envelope":
                    var original = await db.HardwareAuthorityMigrationReceipts.AsNoTracking().SingleAsync();
                    var counterfeit = new HardwareAuthorityMigrationReceipt
                    {
                        Id = Guid.NewGuid(), EnrollmentId = original.EnrollmentId,
                        EnrollmentEpoch = original.EnrollmentEpoch, RequestId = Guid.NewGuid(), Jti = Guid.NewGuid(),
                        KeyId = original.KeyId, Ciphertext = original.Ciphertext
                    };
                    db.HardwareAuthorityMigrationReceipts.Add(counterfeit);
                    alias.MigrationReceiptId = counterfeit.Id;
                    break;
                default: throw new InvalidOperationException("Unknown receipt mutation.");
            }
            await db.SaveChangesAsync();
        }
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ConfirmAsync(
            successor.EnrollmentId, successor.ConfirmDigest, successor.ConfirmRequest, successor.ConfirmProof,
            IPAddress.Loopback));
        Assert.Equal(expectedError, refused.ErrorCode);
        if (expectedError == "enrollment_conflict")
            Assert.Equal("confirm_alias_boundary_mismatch", refused.DiagnosticCode);
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>
    /// Proves a different protocol epoch cannot be persisted: the canonical model requires Epoch=1.
    /// The SQL constraint rejects this attack before Confirm, preserving the entire graph and stale alias.
    /// No constraint is disabled to manufacture an otherwise unreachable application state.
    /// </summary>
    [Fact]
    public async Task MigrationLineage_SigningGenerationMutationFailsDatabaseConstraintWithoutGraphChange()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var successor = await PrepareAliasSuccessorConfirmScenarioAsync(scenario, "receipt-signing-generation");
        var before = await Tkt976_BusinessFingerprintAsync(scenario.AdminConnectionString);
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var source = await db.RuntimeEnrollments.SingleAsync(row => row.Id == successor.SourceEnrollmentId);
            Assert.Equal(1, source.Epoch);
            source.Epoch++;
            var envelope = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            var error = Assert.IsType<PostgresException>(envelope.InnerException);
            Assert.Equal("23514", error.SqlState);
            Assert.Equal("CK_RuntimeEnrollments_Epoch", error.ConstraintName);
            Assert.Equal("RuntimeEnrollments", error.TableName);
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(scenario.AdminConnectionString));
        await AssertPendingSuccessorAndStaleAliasAsync(scenario, successor);
    }

    /// <summary>Proves persisted acceptance cannot be rewritten or deleted, even using the fixture's owner connection.</summary>
    /// <param name="operation">Closed destructive operation attempted against the owned synthetic receipt.</param>
    [Theory]
    [InlineData("update")]
    [InlineData("delete")]
    [InlineData("truncate")]
    public async Task MigrationLineage_ReceiptIsImmutable(string operation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = operation switch
        {
            "delete" => "DELETE FROM public.\"HardwareAuthorityMigrationReceipts\"",
            "truncate" => "TRUNCATE public.\"HardwareAuthorityMigrationReceipts\" CASCADE",
            "update" => "UPDATE public.\"HardwareAuthorityMigrationReceipts\" SET \"Ciphertext\" = 'tampered'",
            _ => throw new InvalidOperationException("Unknown receipt write operation.")
        };
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal("55000", error.SqlState);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.HardwareAuthorityMigrationReceipts.ToListAsync());
    }
}
