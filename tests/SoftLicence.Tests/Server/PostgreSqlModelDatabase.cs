using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Creates immutable schema-model databases once per exact migration target, then gives each
/// PostgreSQL test its own database cloned from that model. Models are process-local and remain
/// untouched until the ticket-owned PostgreSQL container is removed by the canonical launcher.
/// </summary>
internal static class PostgreSqlModelDatabase
{
    private const string CurrentSchemaKey = "\0current";
    private static readonly SemaphoreSlim ModelLock = new(1, 1);
    private static readonly Dictionary<ModelKey, string> Models = [];

    /// <summary>
    /// Creates one independently owned database at the requested exact schema boundary.
    /// The returned clone has a short-lived dedicated pool so concurrent suites reuse sockets without
    /// exhausting the workstation ephemeral-port range. After this method returns, the caller owns cleanup.
    /// </summary>
    /// <param name="nameSegment">Short lowercase identifier used only in the generated database name.</param>
    /// <param name="targetMigration">Exact EF migration identifier, or null for the current schema.</param>
    /// <returns>Connections and the generated identifier for one isolated clone.</returns>
    internal static async Task<PostgreSqlDatabaseClone> CloneAsync(
        string nameSegment,
        string? targetMigration = null)
    {
        if (nameSegment.Length is < 1 or > 18
            || nameSegment[0] is < 'a' or > 'z'
            || nameSegment.Any(character => character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '_'))
        {
            throw new ArgumentException(
                "The PostgreSQL clone name segment must contain 1-18 lowercase ASCII letters, digits, or underscores and start with a letter.",
                nameof(nameSegment));
        }

        var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(configured))
            throw new InvalidOperationException(
                "SOFTLICENCE_RUNTIME_TEST_POSTGRES must target the ticket-owned PostgreSQL test server.");

        var configuredBuilder = new NpgsqlConnectionStringBuilder(configured);
        if (configuredBuilder.Host is not ("localhost" or "127.0.0.1" or "::1"))
            throw new InvalidOperationException("PostgreSQL model clones require a loopback test server.");

        configuredBuilder.Database = "postgres";
        configuredBuilder.Pooling = false;
        var maintenance = configuredBuilder.ConnectionString;
        var model = await GetOrCreateModelAsync(maintenance, targetMigration);
        var database = $"softlicence_{nameSegment}_{Guid.NewGuid():N}";
        try
        {
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"CREATE DATABASE \"{database}\" TEMPLATE \"{model}\"");
            }

            configuredBuilder.Database = database;
            configuredBuilder.Pooling = true;
            configuredBuilder.ConnectionIdleLifetime = 1;
            configuredBuilder.ConnectionPruningInterval = 1;
            var target = configuredBuilder.ConnectionString;
            return new PostgreSqlDatabaseClone(maintenance, target, database);
        }
        catch (Exception provisioningFailure)
        {
            try
            {
                await DropAsync(maintenance, database);
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(
                    "PostgreSQL model clone provisioning and mandatory cleanup both failed.",
                    provisioningFailure,
                    cleanupFailure);
            }
            throw;
        }
    }

    /// <summary>Drops one internally generated clone without changing any other database.</summary>
    internal static async Task DropAsync(string maintenanceConnectionString, string database)
    {
        ValidateDatabaseIdentifier(database);
        var target = new NpgsqlConnectionStringBuilder(maintenanceConnectionString)
        {
            Database = database,
            Pooling = true,
            ConnectionIdleLifetime = 1,
            ConnectionPruningInterval = 1
        }.ConnectionString;
        using (var pooledConnection = new NpgsqlConnection(target))
            NpgsqlConnection.ClearPool(pooledConnection);
        await using var connection = new NpgsqlConnection(WithoutPooling(maintenanceConnectionString));
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)");
    }

    private static async Task<string> GetOrCreateModelAsync(
        string maintenanceConnectionString,
        string? targetMigration)
    {
        var key = new ModelKey(maintenanceConnectionString, targetMigration ?? CurrentSchemaKey);
        await ModelLock.WaitAsync();
        try
        {
            if (Models.TryGetValue(key, out var existing))
                return existing;

            var model = $"softlicence_model_{Guid.NewGuid():N}";
            try
            {
                await using (var maintenance = new NpgsqlConnection(maintenanceConnectionString))
                {
                    await maintenance.OpenAsync();
                    await EnsureDatabaseRolesAsync(maintenance);
                    await ExecuteAsync(maintenance, $"CREATE DATABASE \"{model}\"");
                }

                var modelConnection = new NpgsqlConnectionStringBuilder(maintenanceConnectionString)
                {
                    Database = model,
                    Pooling = false
                }.ConnectionString;
                var options = new DbContextOptionsBuilder<LicenseDbContext>()
                    .UseNpgsql(modelConnection)
                    .Options;
                await using (var db = new LicenseDbContext(options))
                    await db.GetService<IMigrator>().MigrateAsync(targetMigration);

                Models.Add(key, model);
                return model;
            }
            catch (Exception provisioningFailure)
            {
                try
                {
                    await DropAsync(maintenanceConnectionString, model);
                }
                catch (Exception cleanupFailure)
                {
                    throw new AggregateException(
                        "PostgreSQL model provisioning and mandatory cleanup both failed.",
                        provisioningFailure,
                        cleanupFailure);
                }
                throw;
            }
        }
        finally
        {
            ModelLock.Release();
        }
    }

    private static string WithoutPooling(string connectionString) =>
        new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false }.ConnectionString;

    /// <summary>
    /// Creates the production-shaped authority and application roles before model migration so role
    /// validation and conditional grants are deterministic regardless of which test requests the first model.
    /// </summary>
    private static Task EnsureDatabaseRolesAsync(NpgsqlConnection connection) =>
        ExecuteAsync(
            connection,
            """
            DO $database_roles$
            BEGIN
                -- Role names are cluster-global, so parallel fixtures must serialize first creation.
                PERFORM pg_catalog.pg_advisory_xact_lock(1836, 1);
                IF NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'softlicence_runtime_authority_owner'
                ) THEN
                    CREATE ROLE softlicence_runtime_authority_owner NOLOGIN;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app'
                ) THEN
                    CREATE ROLE softlicence_app LOGIN PASSWORD 'runtime-production-role-test-only';
                END IF;
                ALTER ROLE softlicence_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'runtime-production-role-test-only';
            END;
            $database_roles$;
            """);

    private static void ValidateDatabaseIdentifier(string database)
    {
        if (database.Length is < 1 or > 63
            || database.Any(character => character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '_'))
        {
            throw new ArgumentException(
                "A PostgreSQL model database identifier must contain 1-63 lowercase ASCII letters, digits, or underscores.",
                nameof(database));
        }
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    private sealed record ModelKey(string MaintenanceConnectionString, string MigrationKey);
}

/// <summary>
/// Describes one freshly cloned database. The caller owns it and must pass the exact maintenance
/// connection and generated name to <see cref="PostgreSqlModelDatabase.DropAsync"/>.
/// </summary>
/// <param name="MaintenanceConnectionString">Unpooled connection to the test server maintenance database.</param>
/// <param name="ConnectionString">Short-lived pooled administrator connection to the isolated clone.</param>
/// <param name="DatabaseName">Generated lowercase ASCII database identifier.</param>
internal sealed record PostgreSqlDatabaseClone(
    string MaintenanceConnectionString,
    string ConnectionString,
    string DatabaseName);
