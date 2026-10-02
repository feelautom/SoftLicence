using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves the provider-owned commercial-subject schema and ownership relations against PostgreSQL.
/// Every test uses an isolated database and preserves the shared harness database unchanged.
/// </summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Names the exact independently reviewed F6 schema from which TKT-000779 upgrades.</summary>
    private const string Tkt779PreviousMigration =
        "20260829110137_CloseTkt000763F6RecoveryAuthorityIntegrity";

    /// <summary>
    /// Proves the additive migration succeeds from an empty exact F6 baseline without creating any
    /// commercial subject or ownership row, and installs the three product-scoped NO ACTION relations.
    /// </summary>
    [Fact]
    public async Task RuntimeRecoveryCommercialSubjectMigration_EmptyF6BaselineAddsOnlyIntegritySchema()
    {
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt779_empty_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
            var connectionString = new NpgsqlConnectionStringBuilder(shared.Admin)
                { Database = database }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(connectionString).Options;
            await using (var db = new LicenseDbContext(options))
            {
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(Tkt779PreviousMigration);
                await migrator.MigrateAsync();
            }

            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            Assert.Equal(0L, await ScalarAsync<long>(connection, """
                SELECT count(*)::bigint AS "Value"
                FROM public."RuntimeRecoveryCommercialSubjects";
                """));
            Assert.Equal(0L, await ScalarAsync<long>(connection, """
                SELECT count(*)::bigint AS "Value"
                FROM public."RuntimeRecoveryCommercialOwnerships";
                """));
            Assert.Equal(3L, await ScalarAsync<long>(connection, """
                SELECT count(*)::bigint AS "Value"
                FROM pg_catalog.pg_constraint
                WHERE conname IN (
                    'FK_RRCO_Products_ProductId',
                    'FK_RRCO_Licenses_ProductId_LicenseId',
                    'FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId')
                  AND contype = 'f' AND convalidated AND confdeltype = 'a';
                """));
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, database);
        }
    }

    /// <summary>
    /// Proves a pre-existing ownership without an explicitly persisted subject makes the migration
    /// fail with 23503 and leaves the schema, row, and migration head exactly at the F6 baseline.
    /// </summary>
    [Fact]
    public async Task RuntimeRecoveryCommercialSubjectMigration_OrphanOwnershipRollsBackAtomically()
    {
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt779_orphan_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
            var connectionString = new NpgsqlConnectionStringBuilder(shared.Admin)
                { Database = database }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(connectionString).Options;
            await using (var db = new LicenseDbContext(options))
                await db.GetService<IMigrator>().MigrateAsync(Tkt779PreviousMigration);

            var app = new NpgsqlConnectionStringBuilder(connectionString)
            {
                Username = "softlicence_runtime_test_app",
                Password = "runtime-test-only"
            }.ConnectionString;
            await using (var privilegeConnection = new NpgsqlConnection(connectionString))
            {
                await privilegeConnection.OpenAsync();
                await GrantApplicationRuntimePrivilegesAsync(privilegeConnection);
            }
            var provider = await PrepareRecoveryProviderAsync(connectionString, app);

            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            var before = await ReadTkt779MigrationSnapshotAsync(connection, provider.ProductId);
            await using (var db = new LicenseDbContext(options))
            {
                var failure = await Record.ExceptionAsync(() =>
                    db.GetService<IMigrator>().MigrateAsync());
                Assert.NotNull(failure);
                var postgres = Assert.IsType<PostgresException>(failure.GetBaseException());
                Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, postgres.SqlState);
            }
            var after = await ReadTkt779MigrationSnapshotAsync(connection, provider.ProductId);
            Assert.Equal(before, after);
            Assert.Equal(Tkt779PreviousMigration, after.LastMigration);
            Assert.False(after.SubjectTableExists);
            Assert.False(after.OwnershipConstraintsExist);
            Assert.False(after.OwnershipSubjectIndexExists);
            Assert.False(after.LicenseProductKeyExists);
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, database);
        }
    }

    /// <summary>
    /// Proves same-product ownership succeeds while absent or cross-product references, duplicate
    /// ACTIVE versions, invalid lifecycle shapes, and deletion of referenced authority all fail closed.
    /// Terminal ownership versions remain appendable as retained history.
    /// </summary>
    [Fact]
    public async Task RuntimeRecoveryCommercialOwnership_ProductScopedForeignKeysAndLifecycleFailClosed()
    {
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt779_matrix_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
            var connectionString = new NpgsqlConnectionStringBuilder(shared.Admin)
                { Database = database }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(connectionString).Options;
            await using (var db = new LicenseDbContext(options))
                await db.Database.MigrateAsync();

            var first = await SeedTkt779CommercialScopeAsync(options, "first");
            var second = await SeedTkt779CommercialScopeAsync(options, "second");
            var activeId = Guid.NewGuid();
            await InsertTkt779OwnershipAsync(connectionString, activeId, first.ProductId,
                first.LicenseId, first.SubjectId, "ACTIVE", null);

            await AssertTkt779SqlStateAsync(PostgresErrorCodes.ForeignKeyViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), Guid.NewGuid(),
                    first.LicenseId, first.SubjectId, "TRANSFERRED", DateTime.UtcNow));
            await AssertTkt779SqlStateAsync(PostgresErrorCodes.ForeignKeyViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                    Guid.NewGuid(), first.SubjectId, "TRANSFERRED", DateTime.UtcNow));
            await AssertTkt779SqlStateAsync(PostgresErrorCodes.ForeignKeyViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                    first.LicenseId, Guid.NewGuid(), "TRANSFERRED", DateTime.UtcNow));
            await AssertTkt779SqlStateAsync(PostgresErrorCodes.ForeignKeyViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                    second.LicenseId, first.SubjectId, "TRANSFERRED", DateTime.UtcNow));
            await AssertTkt779SqlStateAsync(PostgresErrorCodes.ForeignKeyViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                    first.LicenseId, second.SubjectId, "TRANSFERRED", DateTime.UtcNow));
            await AssertTkt779SqlStateAsync(PostgresErrorCodes.UniqueViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                    first.LicenseId, first.SubjectId, "ACTIVE", null));
            await AssertTkt779SqlStateAsync(PostgresErrorCodes.CheckViolation, () =>
                InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                    first.LicenseId, first.SubjectId, "REVOKED", null));

            await InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                first.LicenseId, first.SubjectId, "TRANSFERRED", DateTime.UtcNow);
            await InsertTkt779OwnershipAsync(connectionString, Guid.NewGuid(), first.ProductId,
                first.LicenseId, first.SubjectId, "REVOKED", DateTime.UtcNow);

            await AssertTkt779DeleteRejectedAsync(connectionString,
                "RuntimeRecoveryCommercialSubjects", first.ProductId, first.SubjectId);
            await AssertTkt779DeleteRejectedAsync(connectionString,
                "Licenses", first.ProductId, first.LicenseId);
            await AssertTkt779DeleteRejectedAsync(connectionString,
                "Products", null, first.ProductId);

            await using var verify = new NpgsqlConnection(connectionString);
            await verify.OpenAsync();
            Assert.Equal(3L, await ScalarAsync<long>(verify, $$"""
                SELECT count(*)::bigint AS "Value"
                FROM public."RuntimeRecoveryCommercialOwnerships"
                WHERE "ProductId" = '{{first.ProductId:D}}'::uuid
                  AND "LicenseId" = '{{first.LicenseId:D}}'::uuid;
                """));
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, database);
        }
    }

    /// <summary>Seeds one explicit provider-owned subject and one license inside the same product scope.</summary>
    /// <param name="options">Isolated current-schema database options owned by the calling test.</param>
    /// <param name="suffix">Bounded fixture label used only to avoid unique-name collisions.</param>
    /// <returns>The three exact UUIDs required to exercise product-scoped ownership.</returns>
    private static async Task<Tkt779CommercialScope> SeedTkt779CommercialScopeAsync(
        DbContextOptions<LicenseDbContext> options, string suffix)
    {
        await using var db = new LicenseDbContext(options);
        var product = new Product
        {
            Name = "tkt779-" + suffix + "-" + Guid.NewGuid().ToString("N"),
            PrivateKeyXml = "test-private",
            PublicKeyXml = "test-public",
            ApiSecret = "test-secret"
        };
        var type = new LicenseType
        {
            Name = "TKT-779 " + suffix,
            Slug = "TKT779_" + suffix,
            Product = product
        };
        var license = new License
        {
            LicenseKey = "TKT779-" + Guid.NewGuid().ToString("N"),
            CustomerName = string.Empty,
            CustomerEmail = string.Empty,
            Type = type,
            Product = product
        };
        var subject = new RuntimeRecoveryCommercialSubject
        {
            Id = Guid.NewGuid(),
            Product = product,
            CreatedAtUtc = DateTime.UtcNow
        };
        db.AddRange(product, type, license, subject);
        await db.SaveChangesAsync();
        return new(product.Id, license.Id, subject.Id);
    }

    /// <summary>Inserts one ownership row without allowing EF fix-up to hide a PostgreSQL constraint result.</summary>
    /// <param name="connectionString">Administrator connection for the isolated test database.</param>
    /// <param name="id">Unique ownership-version UUID.</param>
    /// <param name="productId">Exact product scope asserted by the row.</param>
    /// <param name="licenseId">Exact license asserted by the row.</param>
    /// <param name="subjectId">Exact provider-owned subject asserted by the row.</param>
    /// <param name="state">Closed ownership lifecycle state.</param>
    /// <param name="endedAtUtc">Required terminal instant, or null only for ACTIVE.</param>
    /// <returns>A task completing only after PostgreSQL accepts the row.</returns>
    private static async Task InsertTkt779OwnershipAsync(
        string connectionString, Guid id, Guid productId, Guid licenseId, Guid subjectId,
        string state, DateTime? endedAtUtc)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public."RuntimeRecoveryCommercialOwnerships"
                ("Id","ProductId","LicenseId","OwnerSubjectId","State","CreatedAtUtc","EndedAtUtc")
            VALUES (@id,@product,@license,@subject,@state,clock_timestamp(),@ended);
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("product", productId);
        command.Parameters.AddWithValue("license", licenseId);
        command.Parameters.AddWithValue("subject", subjectId);
        command.Parameters.AddWithValue("state", state);
        command.Parameters.AddWithValue("ended", endedAtUtc is null ? DBNull.Value : endedAtUtc.Value);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Asserts one PostgreSQL operation fails with the exact integrity SQLSTATE.</summary>
    /// <param name="expectedSqlState">Exact five-character PostgreSQL SQLSTATE.</param>
    /// <param name="operation">Single isolated operation expected to fail.</param>
    /// <returns>A task completing after the expected failure is proven.</returns>
    private static async Task AssertTkt779SqlStateAsync(string expectedSqlState, Func<Task> operation)
    {
        var exception = await Assert.ThrowsAsync<PostgresException>(operation);
        Assert.Equal(expectedSqlState, exception.SqlState);
    }

    /// <summary>Proves a referenced product-scoped authority row cannot be physically deleted.</summary>
    /// <param name="connectionString">Administrator connection for the isolated test database.</param>
    /// <param name="table">One closed, test-owned authority table name from the local allowlist.</param>
    /// <param name="productId">Product component for a composite row identity, or null for Product.</param>
    /// <param name="id">Subject, license, or product UUID selected for deletion.</param>
    /// <returns>A task completing after PostgreSQL returns 23503.</returns>
    private static async Task AssertTkt779DeleteRejectedAsync(
        string connectionString, string table, Guid? productId, Guid id)
    {
        Assert.Contains(table,
            new[] { "RuntimeRecoveryCommercialSubjects", "Licenses", "Products" });
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        var predicate = productId is null
            ? "\"Id\" = @id"
            : "\"ProductId\" = @product AND \"Id\" = @id";
        await using var command = new NpgsqlCommand(
            $"DELETE FROM public.\"{table}\" WHERE {predicate};", connection);
        command.Parameters.AddWithValue("id", id);
        if (productId is not null)
            command.Parameters.AddWithValue("product", productId.Value);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, exception.SqlState);
    }

    /// <summary>Captures the decisive no-partial-migration evidence around an orphan ownership.</summary>
    /// <param name="connection">Open connection to the exact isolated F6 database.</param>
    /// <param name="productId">Product scope of the pre-existing ownership row.</param>
    /// <returns>Data, schema, index, key, and migration-head evidence compared across the failed upgrade.</returns>
    private static async Task<Tkt779MigrationSnapshot> ReadTkt779MigrationSnapshotAsync(
        NpgsqlConnection connection, Guid productId)
    {
        await using var command = new NpgsqlCommand("""
            SELECT
                (SELECT count(*)::bigint
                 FROM public."RuntimeRecoveryCommercialOwnerships"
                 WHERE "ProductId" = @product),
                to_regclass('public."RuntimeRecoveryCommercialSubjects"') IS NOT NULL,
                EXISTS (
                    SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conname IN (
                        'FK_RRCO_Products_ProductId',
                        'FK_RRCO_Licenses_ProductId_LicenseId',
                        'FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId')),
                to_regclass('public."IX_RuntimeRecoveryCommercialOwnerships_ProductId_OwnerSubjectId"')
                    IS NOT NULL,
                EXISTS (
                    SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conname = 'AK_Licenses_ProductId_Id'),
                (SELECT "MigrationId" FROM public."__EFMigrationsHistory"
                 ORDER BY "MigrationId" DESC LIMIT 1);
            """, connection);
        command.Parameters.AddWithValue("product", productId);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return new(reader.GetInt64(0), reader.GetBoolean(1), reader.GetBoolean(2),
            reader.GetBoolean(3), reader.GetBoolean(4), reader.GetString(5));
    }

    /// <summary>Groups one explicit same-product subject and license fixture.</summary>
    /// <param name="ProductId">Exact product UUID.</param>
    /// <param name="LicenseId">License UUID owned by that product.</param>
    /// <param name="SubjectId">Opaque subject UUID owned by that product.</param>
    private sealed record Tkt779CommercialScope(Guid ProductId, Guid LicenseId, Guid SubjectId);

    /// <summary>Freezes the data and schema surfaces that a failed TKT-000779 migration must preserve.</summary>
    /// <param name="OwnershipCount">Pre-existing ownership rows in the tested product.</param>
    /// <param name="SubjectTableExists">Whether the new subject table survived.</param>
    /// <param name="OwnershipConstraintsExist">Whether any new ownership FK survived.</param>
    /// <param name="OwnershipSubjectIndexExists">Whether the new subject lookup index survived.</param>
    /// <param name="LicenseProductKeyExists">Whether the new composite License principal key survived.</param>
    /// <param name="LastMigration">Exact durable migration-history head.</param>
    private sealed record Tkt779MigrationSnapshot(
        long OwnershipCount,
        bool SubjectTableExists,
        bool OwnershipConstraintsExist,
        bool OwnershipSubjectIndexExists,
        bool LicenseProductKeyExists,
        string LastMigration);
}
