using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Builds historical alias fixtures on a fresh historical schema, then leaves real upgrades to the test.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>The last schema before alias creation and its authenticated-history backfill.</summary>
    private const string HistoricalAliasBaseline = "20260816131533_AllowRuntimeHardwareAuthorityMigrationProofs";

    /// <summary>
    /// Seeds one synthetic historical migration graph into a new database at the pre-alias schema.
    /// A current isolated scenario supplies valid cryptographic material, but no current assignment,
    /// alias, migration-history row or production data is copied. The historical installation and
    /// enrollment carry the canonical digest, as the pre-assignment migration contract required.
    /// </summary>
    /// <param name="subjectRef">Optional synthetic subject used by the later Finalize scenario.</param>
    /// <returns>A scenario owning the historical database and independent keys; callers must upgrade before using current services.</returns>
    /// <remarks>Every seed insert is bounded to the template product/binding. Failure cleans both owned databases. No Down migration is invoked.</remarks>
    private static async Task<PreparedBootstrapScenario> CreateHistoricalAliasScenarioAsync(string? subjectRef = null)
    {
        var connections = await ProvisionIsolatedAsync(targetMigration: HistoricalAliasBaseline);
        using var cleanup = new BootstrapIsolatedDatabaseCleanup(connections.Admin, connections.App);
        // The template must finish cleanup before database and key ownership can pass to the returned scenario.
        RSA? activeSigning = null;
        RSA? nextSigning = null;
        RSA? enrollmentKey = null;
        RuntimeEnrollmentCryptoService? crypto = null;
        var transferred = false;
        try
        {
            PreparedBootstrapScenario scenario;
            using (var template = await CreatePreparedBootstrapScenarioAsync())
            {
                await ActivateCanonicalScenarioAsync(template, LegacyHardwareId);
                if (subjectRef is not null)
                    await SetScenarioSubjectAuthorityAsync(template, subjectRef);
                await MigrateScenarioAsync(template);

                await using (var source = new NpgsqlConnection(template.AdminConnectionString))
                await using (var target = new NpgsqlConnection(connections.Admin))
                {
                    await source.OpenAsync();
                    await target.OpenAsync();
                    Assert.Equal(HistoricalAliasBaseline, await ScalarAsync<string>(target,
                        "SELECT max(\"MigrationId\") FROM \"__EFMigrationsHistory\";"));
                    Assert.True(await ScalarAsync<bool>(target, """
                        SELECT to_regclass('public."HardwareAuthorityAliases"') IS NULL
                           AND to_regclass('public."EnrollmentLicenseAssignments"') IS NULL;
                        """));
                    await UpsertKeyRegistryAsync(connections.Admin, template.Options);

                    // This closed table list follows historical foreign-key order; identifiers never come from test input.
                    await CopyHistoricalAliasRowsAsync(source, target, "Products", "row.\"Id\" = @product", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "LicenseTypes", "row.\"ProductId\" = @product", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "Licenses", "row.\"ProductId\" = @product", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "LicenseSeats", "row.\"LicenseId\" IN (SELECT \"Id\" FROM \"Licenses\" WHERE \"ProductId\" = @product)", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "ApprovedBinaries", "row.\"ProductId\" = @product", template, 3, 3);
                    await CopyHistoricalAliasRowsAsync(source, target, "DistributionInstallationBindings", "row.\"Id\" = @binding", template, 1, 1, canonicalDigest: true);
                    await CopyHistoricalAliasRowsAsync(source, target, "DistributionEntitlements", "row.\"ProductId\" = @product", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "DistributionGrantOwnerships", "row.\"ProductId\" = @product", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "DistributionBindingRequests", "row.\"BindingId\" = @binding", template, 1, 1);
                    await CopyHistoricalAliasRowsAsync(source, target, "RuntimeEnrollments", "row.\"Id\" = @enrollment", template, 1, 1, canonicalDigest: true);
                    await CopyHistoricalAliasRowsAsync(source, target, "LicenseHistories", "row.\"LicenseId\" IN (SELECT \"Id\" FROM \"Licenses\" WHERE \"ProductId\" = @product) AND row.\"Action\" = 'HWID_V2_MIGRATED'", template, 1, 1);
                    await using var invariant = new NpgsqlCommand("""
                        SELECT count(*) FROM "RuntimeEnrollments" e
                        JOIN "DistributionInstallationBindings" b ON b."Id" = e."BindingId"
                        JOIN "LicenseSeats" s ON s."Id" = e."LicenseSeatId"
                        WHERE e."Id" = @enrollment AND b."Id" = @binding AND e."ProductId" = @product
                          AND e."LicenseId" = b."LicenseId" AND s."LicenseId" = b."LicenseId"
                          AND b."LicenseSeatId" = s."Id" AND e."State" = 'ACTIVE' AND s."IsActive"
                          AND e."HardwareIdHash" = @digest AND b."HardwareIdHash" = @digest
                          AND encode(sha256(convert_to(s."HardwareId", 'UTF8')), 'hex') = @digest;
                        """, target);
                    invariant.Parameters.AddWithValue("enrollment", template.EnrollmentId);
                    invariant.Parameters.AddWithValue("binding", template.Fixture.BindingId);
                    invariant.Parameters.AddWithValue("product", template.Fixture.ProductId);
                    invariant.Parameters.AddWithValue("digest", Sha256(StableHardwareId));
                    Assert.Equal(1L, await invariant.ExecuteScalarAsync());
                }

                var factory = new TestDbFactory(connections.App);
                activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
                nextSigning = CreateSigningKey(NextSigningPrivateKey);
                enrollmentKey = RSA.Create();
                enrollmentKey.ImportPkcs8PrivateKey(template.EnrollmentKey.ExportPkcs8PrivateKey(), out _);
                crypto = new RuntimeEnrollmentCryptoService(Options.Create(template.Options));
                var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(template.Options));
                var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(template.Options));
                var runtime = new RuntimeEnrollmentService(factory, authority, registry, crypto,
                    Options.Create(template.Options), signedLicenseFiles: template.SignedLicenseFiles);
                scenario = new PreparedBootstrapScenario(factory, connections.Admin, connections.App,
                    template.Fixture, template.Options, activeSigning, nextSigning, enrollmentKey, crypto, runtime,
                    template.SignedLicenseFiles,
                    new DistributionLicenseBootstrapService(factory, authority, crypto, registry,
                        Options.Create(template.Options), TimeProvider.System),
                    template.Prepared, template.PrepareRequest, template.PrepareDigest);
            }
            cleanup.Disarm();
            transferred = true;
            return scenario;
        }
        finally
        {
            if (!transferred)
            {
                crypto?.Dispose();
                enrollmentKey?.Dispose();
                nextSigning?.Dispose();
                activeSigning?.Dispose();
            }
        }
    }

    /// <summary>Copies a bounded synthetic row set through the destination's historical composite type, omitting later columns.</summary>
    /// <param name="source">Open connection to the independently owned current template database.</param>
    /// <param name="target">Open connection to the fresh historical scenario database.</param>
    /// <param name="table">Fixed table identifier from the caller's closed seed list.</param>
    /// <param name="predicate">Fixed SQL predicate using only the bound scenario identifiers.</param>
    /// <param name="scenario">Template whose synthetic identifiers bound the selected graph.</param>
    /// <param name="minimumRows">Minimum expected seed cardinality.</param>
    /// <param name="maximumRows">Maximum expected seed cardinality, preventing unrelated graph copies.</param>
    /// <param name="canonicalDigest">Whether to represent the historical contract that stored the canonical digest on this row.</param>
    /// <returns>A task completing after the exact row count was inserted with historical constraints enabled.</returns>
    /// <remarks>JSON stays in process memory and is never logged. No constraint, trigger or migration ledger is disabled or rewritten.</remarks>
    private static async Task CopyHistoricalAliasRowsAsync(NpgsqlConnection source, NpgsqlConnection target,
        string table, string predicate, PreparedBootstrapScenario scenario, int minimumRows, int maximumRows,
        bool canonicalDigest = false)
    {
        var projection = canonicalDigest
            ? "to_jsonb(row) || jsonb_build_object('HardwareIdHash', @digest::text)"
            : "to_jsonb(row)";
        await using var read = new NpgsqlCommand(
            $"SELECT COALESCE(jsonb_agg({projection}), '[]'::jsonb)::text FROM public.\"{table}\" row WHERE {predicate};", source);
        read.Parameters.AddWithValue("product", scenario.Fixture.ProductId);
        read.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
        read.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
        read.Parameters.AddWithValue("digest", Sha256(StableHardwareId));
        var payload = (string)(await read.ExecuteScalarAsync())!;
        using var parsed = JsonDocument.Parse(payload);
        var count = parsed.RootElement.GetArrayLength();
        Assert.InRange(count, minimumRows, maximumRows);
        await using var insert = new NpgsqlCommand(
            $"INSERT INTO public.\"{table}\" SELECT * FROM jsonb_populate_recordset(NULL::public.\"{table}\", @rows);", target);
        insert.Parameters.AddWithValue("rows", NpgsqlDbType.Jsonb, payload);
        Assert.Equal(count, await insert.ExecuteNonQueryAsync());
    }

    /// <summary>Identifies the historical licence, released canonical seat and newly active legacy seat.</summary>
    /// <param name="LicenseId">Licence shared by the two seats.</param>
    /// <param name="SourceSeatId">Canonical seat released before alias backfill.</param>
    /// <param name="LegacySeatId">New legacy seat created before alias backfill.</param>
    private sealed record HistoricalAliasGraph(Guid LicenseId, Guid SourceSeatId, Guid LegacySeatId);

    /// <summary>Builds the historical inactive graph using schema-compatible SQL before the real upgrade.</summary>
    /// <param name="scenario">Owned pre-alias database seeded with exactly one active migrated enrollment.</param>
    /// <returns>The exact licence and seat identifiers used by the unchanged assertions after upgrade.</returns>
    /// <remarks>All mutations are parameterized and transactional; current EF entities are not queried against the historical schema.</remarks>
    private static async Task<HistoricalAliasGraph> ReleaseHistoricalAliasSeatAsync(PreparedBootstrapScenario scenario)
    {
        await using var connection = new NpgsqlConnection(scenario.AdminConnectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var select = new NpgsqlCommand("""
            SELECT "LicenseId", "LicenseSeatId" FROM "DistributionInstallationBindings" WHERE "Id" = @binding;
            """, connection, transaction);
        select.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
        Guid licenseId;
        Guid seatId;
        await using (var reader = await select.ExecuteReaderAsync())
        {
            Assert.True(await reader.ReadAsync());
            licenseId = reader.GetGuid(0);
            seatId = reader.GetGuid(1);
            Assert.False(await reader.ReadAsync());
        }
        var legacySeatId = Guid.NewGuid();
        await using var mutate = new NpgsqlCommand("""
            UPDATE "LicenseSeats" SET "IsActive" = FALSE, "UnlinkedAt" = CURRENT_TIMESTAMP - INTERVAL '5 minutes'
            WHERE "Id" = @seat AND "LicenseId" = @license;
            UPDATE "RuntimeEnrollments" SET "State" = 'INVALIDATED',
                "InvalidatedAtUtc" = CURRENT_TIMESTAMP - INTERVAL '4 minutes', "InvalidationReason" = 'authority_ineligible'
            WHERE "Id" = @enrollment AND "BindingId" = @binding;
            INSERT INTO "LicenseSeats"
            SELECT (jsonb_populate_record(NULL::"LicenseSeats", to_jsonb(s) || jsonb_build_object(
                'Id', @legacy::text, 'HardwareId', @hardware::text, 'IsActive', TRUE, 'UnlinkedAt', NULL,
                'FirstActivatedAt', CURRENT_TIMESTAMP - INTERVAL '3 minutes',
                'LastCheckInAt', CURRENT_TIMESTAMP - INTERVAL '3 minutes', 'AppVersion', @version::text))).*
            FROM "LicenseSeats" s WHERE s."Id" = @seat;
            """, connection, transaction);
        mutate.Parameters.AddWithValue("seat", seatId);
        mutate.Parameters.AddWithValue("license", licenseId);
        mutate.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
        mutate.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
        mutate.Parameters.AddWithValue("legacy", legacySeatId);
        mutate.Parameters.AddWithValue("hardware", LegacyHardwareId);
        mutate.Parameters.AddWithValue("version", scenario.Fixture.Version);
        Assert.Equal(3, await mutate.ExecuteNonQueryAsync());
        await transaction.CommitAsync();
        return new(licenseId, seatId, legacySeatId);
    }
}
