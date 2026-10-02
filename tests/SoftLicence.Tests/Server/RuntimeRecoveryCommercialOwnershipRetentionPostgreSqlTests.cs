using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves PostgreSQL physically retains commercial ownership authority across DELETE and TRUNCATE attempts.
/// </summary>
public sealed class RuntimeRecoveryCommercialOwnershipRetentionPostgreSqlTests
{
    /// <summary>Identifies the additive migration that installs the physical-retention guard.</summary>
    private const string Tkt783Migration =
        "20260829160000_AddTkt000783CommercialOwnershipRetention";

    /// <summary>Identifies the exact TKT-000782 schema to use for upgrade and rollback proofs.</summary>
    private const string Tkt783PreviousMigration =
        "20260829143035_AddTkt000782CommercialOwnershipTransitions";

    /// <summary>Names the only function allowed to reject physical ownership-history removal.</summary>
    private const string RetentionFunction =
        "tkt000783_reject_commercial_ownership_removal";

    /// <summary>Names the row-level DELETE trigger installed by TKT-000783.</summary>
    private const string DeleteTrigger =
        "trg_tkt000783_commercial_ownership_no_delete";

    /// <summary>Names the statement-level TRUNCATE trigger installed by TKT-000783.</summary>
    private const string TruncateTrigger =
        "trg_tkt000783_commercial_ownership_no_truncate";

    /// <summary>
    /// Proves EF discovers the bounded migration and that its raw SQL declares both required trigger levels.
    /// </summary>
    [Fact]
    public void MigrationAssembly_ContainsTkt783RetentionGuard()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations[Tkt783Migration], db.Database.ProviderName!);

        var upSql = Assert.Single(migration.UpOperations.OfType<SqlOperation>()).Sql;
        Assert.Contains("ERRCODE = '55000'", upSql, StringComparison.Ordinal);
        Assert.Contains("BEFORE DELETE", upSql, StringComparison.Ordinal);
        Assert.Contains("FOR EACH ROW", upSql, StringComparison.Ordinal);
        Assert.Contains("BEFORE TRUNCATE", upSql, StringComparison.Ordinal);
        Assert.Contains("FOR EACH STATEMENT", upSql, StringComparison.Ordinal);

        Assert.Single(migration.UpOperations);
        var downSql = Assert.Single(migration.DownOperations.OfType<SqlOperation>()).Sql;
        Assert.Single(migration.DownOperations);
        Assert.Equal(1, CountOrdinal(downSql, $"DROP TRIGGER IF EXISTS {DeleteTrigger}"));
        Assert.Equal(1, CountOrdinal(downSql, $"DROP TRIGGER IF EXISTS {TruncateTrigger}"));
        Assert.Equal(1, CountOrdinal(downSql, $"DROP FUNCTION IF EXISTS public.{RetentionFunction}()"));
        Assert.DoesNotContain("tkt000782", downSql, StringComparison.Ordinal);
    }

    /// <summary>
    /// Proves an exact TKT-000782 database upgrades without rewriting its ownership row and installs
    /// one enabled DELETE-row trigger, one enabled TRUNCATE-statement trigger, and one trigger function.
    /// </summary>
    [Fact]
    public async Task Migration_Tkt782HeadInstallsExactEnabledObjectsWithoutRewritingHistory()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync(Tkt783PreviousMigration);
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var fixture = await SeedOwnershipAsync(provision.ConnectionString);

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        var before = await OwnershipHistoryAsync(connection, fixture.ProductId);
        await using (var db = new LicenseDbContext(options))
            await db.GetService<IMigrator>().MigrateAsync(Tkt783Migration);

        Assert.Equal(before, await OwnershipHistoryAsync(connection, fixture.ProductId));
        Assert.Equal(1L, await ScalarAsync<long>(connection, $$"""
            SELECT count(*)::bigint
            FROM pg_catalog.pg_proc AS p
            JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = '{{RetentionFunction}}'
              AND p.prorettype = 'trigger'::regtype;
            """));

        var triggers = await TriggerDefinitionsAsync(connection);
        Assert.Equal(2, triggers.Count);
        Assert.Equal((short)11, triggers[DeleteTrigger].TypeBits);
        Assert.Equal("O", triggers[DeleteTrigger].Enabled);
        Assert.Contains("BEFORE DELETE", triggers[DeleteTrigger].Definition, StringComparison.Ordinal);
        Assert.Contains("FOR EACH ROW", triggers[DeleteTrigger].Definition, StringComparison.Ordinal);
        Assert.Equal((short)34, triggers[TruncateTrigger].TypeBits);
        Assert.Equal("O", triggers[TruncateTrigger].Enabled);
        Assert.Contains("BEFORE TRUNCATE", triggers[TruncateTrigger].Definition, StringComparison.Ordinal);
        Assert.Contains("FOR EACH STATEMENT", triggers[TruncateTrigger].Definition, StringComparison.Ordinal);
    }

    /// <summary>
    /// Proves ownership DELETE and cascading TRUNCATE return SQLSTATE 55000, non-cascading
    /// TRUNCATE remains closed by PostgreSQL, parent removal stays blocked, and every row remains intact.
    /// </summary>
    [Fact]
    public async Task PhysicalRemoval_DeleteTruncateAndParentPathsFailClosedWithoutDataLoss()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var fixture = await SeedOwnershipAsync(provision.ConnectionString);
        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        var before = await OwnershipHistoryAsync(connection, fixture.ProductId);

        var deleteOwnership = await AssertSqlStateAsync(
            PostgresErrorCodes.ObjectNotInPrerequisiteState,
            () => ExecuteAsync(connection, $$"""
                DELETE FROM public."RuntimeRecoveryCommercialOwnerships"
                WHERE "Id" = '{{fixture.OwnershipId:D}}'::uuid;
                """));
        Assert.Equal("commercial ownership authority history cannot be physically removed",
            deleteOwnership.MessageText);

        await AssertSqlStateAsync(
            PostgresErrorCodes.FeatureNotSupported,
            () => ExecuteAsync(connection, "TRUNCATE TABLE public.\"RuntimeRecoveryCommercialOwnerships\";"));
        await AssertSqlStateAsync(
            PostgresErrorCodes.ObjectNotInPrerequisiteState,
            () => ExecuteAsync(connection, "TRUNCATE TABLE public.\"RuntimeRecoveryCommercialOwnerships\" CASCADE;"));

        await AssertSqlStateAsync(
            PostgresErrorCodes.ForeignKeyViolation,
            () => ExecuteAsync(connection, $$"""
                DELETE FROM public."RuntimeRecoveryCommercialSubjects"
                WHERE "ProductId" = '{{fixture.ProductId:D}}'::uuid
                  AND "Id" = '{{fixture.SubjectId:D}}'::uuid;
                """));
        await AssertSqlStateAsync(
            PostgresErrorCodes.ForeignKeyViolation,
            () => ExecuteAsync(connection, $$"""
                DELETE FROM public."Licenses" WHERE "Id" = '{{fixture.LicenseId:D}}'::uuid;
                """));
        await AssertSqlStateAsync(
            PostgresErrorCodes.ForeignKeyViolation,
            () => ExecuteAsync(connection, $$"""
                DELETE FROM public."Products" WHERE "Id" = '{{fixture.ProductId:D}}'::uuid;
                """));

        await AssertSqlStateAsync(
            "0A000",
            () => ExecuteAsync(connection, "TRUNCATE TABLE public.\"RuntimeRecoveryCommercialSubjects\";"));
        await AssertSqlStateAsync(
            PostgresErrorCodes.ObjectNotInPrerequisiteState,
            () => ExecuteAsync(connection,
                "TRUNCATE TABLE public.\"RuntimeRecoveryCommercialSubjects\" CASCADE;"));

        Assert.Equal(before, await OwnershipHistoryAsync(connection, fixture.ProductId));
        Assert.Equal(1L, await ScalarAsync<long>(connection, $$"""
            SELECT count(*)::bigint FROM public."Products"
            WHERE "Id" = '{{fixture.ProductId:D}}'::uuid;
            """));
        Assert.Equal(1L, await ScalarAsync<long>(connection, $$"""
            SELECT count(*)::bigint FROM public."Licenses"
            WHERE "Id" = '{{fixture.LicenseId:D}}'::uuid;
            """));
        Assert.Equal(1L, await ScalarAsync<long>(connection, $$"""
            SELECT count(*)::bigint FROM public."RuntimeRecoveryCommercialSubjects"
            WHERE "ProductId" = '{{fixture.ProductId:D}}'::uuid
              AND "Id" = '{{fixture.SubjectId:D}}'::uuid;
            """));

        Assert.Equal(3L, await ScalarAsync<long>(connection, """
            SELECT count(*)::bigint FROM pg_catalog.pg_constraint
            WHERE conname IN (
                'FK_RRCO_Products_ProductId',
                'FK_RRCO_Licenses_ProductId_LicenseId',
                'FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId')
              AND contype = 'f' AND convalidated AND confdeltype = 'a';
            """));
    }

    /// <summary>
    /// Proves rollback to TKT-000782 removes only TKT-000783 objects, leaves the TKT-000782 UPDATE
    /// guard installed, permits physical removal again, and supports a clean forward re-application.
    /// </summary>
    [Fact]
    public async Task MigrationDown_RemovesOnlyRetentionObjectsAndCanMigrateForwardAgain()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var fixture = await SeedOwnershipAsync(provision.ConnectionString);

        await using (var db = new LicenseDbContext(options))
            await db.GetService<IMigrator>().MigrateAsync(Tkt783PreviousMigration);

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        Assert.Empty(await TriggerDefinitionsAsync(connection));
        Assert.Equal(0L, await ScalarAsync<long>(connection, $$"""
            SELECT count(*)::bigint FROM pg_catalog.pg_proc AS p
            JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = '{{RetentionFunction}}';
            """));
        Assert.Equal(1L, await ScalarAsync<long>(connection, """
            SELECT count(*)::bigint FROM pg_catalog.pg_trigger
            WHERE tgname = 'trg_tkt000782_commercial_ownership_version' AND tgenabled = 'O';
            """));
        Assert.Equal(1, await ExecuteAsync(connection, $$"""
            DELETE FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "Id" = '{{fixture.OwnershipId:D}}'::uuid;
            """));

        await using (var db = new LicenseDbContext(options))
            await db.GetService<IMigrator>().MigrateAsync(Tkt783Migration);
        Assert.Equal(2, (await TriggerDefinitionsAsync(connection)).Count);
    }

    /// <summary>
    /// Seeds one exact product, license, opaque subject, and ACTIVE ownership version. The context model
    /// matches the schema actually present, because some callers stop the database at a historical
    /// migration that predates later columns such as <c>Licenses.AuthorityVersion</c>.
    /// </summary>
    /// <param name="connectionString">Connection to the isolated PostgreSQL database.</param>
    /// <returns>The provider-owned UUID tuple required by destructive-operation proofs.</returns>
    private static async Task<OwnershipFixture> SeedOwnershipAsync(string connectionString)
    {
        await using var db = await HistoricalSchemaModel.CreateContextAsync(connectionString);
        var product = new Product
        {
            Name = "tkt783-product-" + Guid.NewGuid().ToString("N"),
            ApiSecret = "tkt783-product-secret-" + Guid.NewGuid().ToString("N")
        };
        var type = new LicenseType
        {
            Product = product,
            Name = "TKT-783 retention",
            Slug = "TKT783-" + Guid.NewGuid().ToString("N")
        };
        var license = new License
        {
            Product = product,
            Type = type,
            LicenseKey = "TKT783-" + Guid.NewGuid().ToString("N")
        };
        var subject = new RuntimeRecoveryCommercialSubject
        {
            Product = product,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        var ownership = new RuntimeRecoveryCommercialOwnership
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            LicenseId = license.Id,
            OwnerSubjectId = subject.Id,
            State = "ACTIVE",
            CreatedAtUtc = DateTime.UtcNow
        };
        db.AddRange(product, type, license, subject, ownership);
        await db.SaveChangesAsync();
        return new(product.Id, license.Id, subject.Id, ownership.Id);
    }

    /// <summary>Reads the canonical JSONB projection of all ownership rows in one product scope.</summary>
    /// <param name="connection">Open isolated PostgreSQL connection.</param>
    /// <param name="productId">Exact product scope whose history must remain unchanged.</param>
    /// <returns>Deterministic JSONB text ordered by ownership UUID.</returns>
    private static Task<string> OwnershipHistoryAsync(NpgsqlConnection connection, Guid productId) =>
        ScalarAsync<string>(connection, $$"""
            SELECT COALESCE(jsonb_agg(to_jsonb(ownership) ORDER BY ownership."Id"), '[]'::jsonb)::text
            FROM public."RuntimeRecoveryCommercialOwnerships" AS ownership
            WHERE ownership."ProductId" = '{{productId:D}}'::uuid;
            """);

    /// <summary>Reads the enabled state, trigger-level bit mask, and server-rendered definition of each guard.</summary>
    /// <param name="connection">Open isolated PostgreSQL connection.</param>
    /// <returns>Definitions keyed by exact trigger name using ordinal comparison.</returns>
    private static async Task<Dictionary<string, TriggerDefinition>> TriggerDefinitionsAsync(
        NpgsqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $$"""
            SELECT trigger.tgname, trigger.tgtype::smallint, trigger.tgenabled::text,
                   pg_catalog.pg_get_triggerdef(trigger.oid)
            FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgname IN ('{{DeleteTrigger}}', '{{TruncateTrigger}}')
              AND NOT trigger.tgisinternal
            ORDER BY trigger.tgname COLLATE "C";
            """;
        await using var reader = await command.ExecuteReaderAsync();
        var result = new Dictionary<string, TriggerDefinition>(StringComparer.Ordinal);
        while (await reader.ReadAsync())
            result.Add(reader.GetString(0), new(reader.GetInt16(1), reader.GetString(2), reader.GetString(3)));
        return result;
    }

    /// <summary>Executes one direct PostgreSQL command and returns its affected-row count.</summary>
    /// <param name="connection">Open isolated PostgreSQL connection.</param>
    /// <param name="sql">Closed test SQL generated only from fixture-owned UUIDs and literals.</param>
    /// <returns>The provider-reported affected-row count.</returns>
    private static async Task<int> ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteNonQueryAsync();
    }

    /// <summary>Asserts one direct operation fails with the exact five-character PostgreSQL SQLSTATE.</summary>
    /// <param name="sqlState">Exact provider SQLSTATE expected from the closed failure.</param>
    /// <param name="operation">Single autocommit operation whose statement rollback must preserve data.</param>
    /// <returns>The provider exception for additional message or constraint assertions.</returns>
    private static async Task<PostgresException> AssertSqlStateAsync(
        string sqlState,
        Func<Task> operation)
    {
        var exception = await Assert.ThrowsAsync<PostgresException>(operation);
        Assert.Equal(sqlState, exception.SqlState);
        return exception;
    }

    /// <summary>Reads one scalar value from an open isolated PostgreSQL connection.</summary>
    /// <typeparam name="T">Provider scalar type expected by the assertion.</typeparam>
    /// <param name="connection">Open isolated PostgreSQL connection.</param>
    /// <param name="sql">Closed read-only SQL statement.</param>
    /// <returns>The non-null scalar returned by PostgreSQL.</returns>
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>Counts exact ordinal occurrences without normalizing migration SQL.</summary>
    /// <param name="value">Complete SQL batch.</param>
    /// <param name="needle">Exact invariant fragment to count.</param>
    /// <returns>The number of non-overlapping ordinal matches.</returns>
    private static int CountOrdinal(string value, string needle)
    {
        var count = 0;
        for (var index = 0; (index = value.IndexOf(needle, index, StringComparison.Ordinal)) >= 0;
             index += needle.Length)
            count++;
        return count;
    }

    /// <summary>Groups the exact provider-owned identifiers used by one retention fixture.</summary>
    /// <param name="ProductId">Product scope protected by ownership foreign keys.</param>
    /// <param name="LicenseId">License referenced by the retained ownership version.</param>
    /// <param name="SubjectId">Opaque commercial subject referenced by the retained version.</param>
    /// <param name="OwnershipId">ACTIVE ownership-version UUID protected from physical removal.</param>
    private sealed record OwnershipFixture(
        Guid ProductId,
        Guid LicenseId,
        Guid SubjectId,
        Guid OwnershipId);

    /// <summary>Captures one PostgreSQL trigger's level bits, enable mode, and rendered definition.</summary>
    /// <param name="TypeBits">PostgreSQL trigger event/timing/level bit mask.</param>
    /// <param name="Enabled">PostgreSQL enable mode; ordinary enabled triggers use `O`.</param>
    /// <param name="Definition">Server-rendered trigger definition used for structural assertions.</param>
    private sealed record TriggerDefinition(short TypeBits, string Enabled, string Definition);

    /// <summary>Owns one isolated PostgreSQL database and force-removes it after every proof.</summary>
    /// <param name="maintenanceConnectionString">Maintenance connection used only for create/drop.</param>
    /// <param name="connectionString">Connection string of the isolated application database.</param>
    /// <param name="database">Generated database name exclusively owned by this fixture.</param>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated application connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Creates and migrates one isolated database from the configured PostgreSQL authority.</summary>
        /// <param name="targetMigration">Optional exact migration endpoint; null applies the current head.</param>
        /// <returns>An owner that force-drops the database during asynchronous disposal.</returns>
        public static async Task<PostgreSqlProvision> CreateAsync(string? targetMigration = null)
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000783 PostgreSQL tests.");

            var database = "tkt783_retention_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured)
            {
                Database = "postgres",
                Pooling = false
            }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var target = new NpgsqlConnectionStringBuilder(configured)
            {
                Database = database,
                Pooling = false
            }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
            await using (var db = new LicenseDbContext(options))
                await db.GetService<IMigrator>().MigrateAsync(targetMigration);
            return new(maintenance, target, database);
        }

        /// <summary>Clears provider pools and force-drops only this fixture's generated database.</summary>
        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync();
        }
    }
}
