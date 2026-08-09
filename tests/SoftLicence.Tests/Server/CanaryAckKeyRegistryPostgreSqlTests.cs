using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class CanaryAckKeyRegistryPostgreSqlTests
{
    [Fact]
    public async Task Registry_AOnlyMigrationConcurrencyDriftRollbackAndLifecycle_AreFailClosed()
    {
        var provision = await PostgreSqlProvision.CreateAsync();
        try
        {
            await AssertApplicationRoleIsReadOnlyAsync(provision.ApplicationConnectionString);
            using var active = RSA.Create(2048);
            using var replacement = RSA.Create(2048);
            using var next = RSA.Create(2048);
            using var reusedNext = RSA.Create(2048);
            var version1 = LegacyOptions(active);

            await AssertLegacyApplicationStillSignsAsync(provision.ConnectionString, active);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
                CanaryAckKeyRegistryProvisioner.InitializeOrValidateAsync(
                    provision.ConnectionString,
                    version1)));

            var version1Keyring = new CanaryAckKeyring(Options.Create(version1));
            var registry = new CanaryAckKeyRegistryService(
                new TestDbFactory(provision.ConnectionString),
                version1Keyring);
            await registry.ValidateAsync();

            var beforeDrift = await SnapshotAsync(provision.ConnectionString);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                CanaryAckKeyRegistryProvisioner.InitializeOrValidateAsync(
                    provision.ConnectionString,
                    LegacyOptions(replacement)));
            Assert.Equal(beforeDrift, await SnapshotAsync(provision.ConnectionString));

            await AssertRollbackBeforeCommitAsync(provision.ConnectionString);
            Assert.Equal(beforeDrift, await SnapshotAsync(provision.ConnectionString));

            var version2 = ExplicitOptions(active, next, 2);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
                CanaryAckKeyRegistryProvisioner.InitializeOrValidateAsync(
                    provision.ConnectionString,
                    version2)));
            var version2Registry = new CanaryAckKeyRegistryService(
                new TestDbFactory(provision.ConnectionString),
                new CanaryAckKeyring(Options.Create(version2)));
            await version2Registry.ValidateAsync();

            var beforeReuse = await SnapshotAsync(provision.ConnectionString);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                CanaryAckKeyRegistryProvisioner.InitializeOrValidateAsync(
                    provision.ConnectionString,
                    ExplicitOptions(active, reusedNext, 2)));
            Assert.Equal(beforeReuse, await SnapshotAsync(provision.ConnectionString));

            await AssertTransitionRejectedAsync(provision.ConnectionString,
                "UPDATE public.\"CanaryAckKeyRegistries\" SET \"State\"='previous', \"RetainUntilUtc\"=clock_timestamp()+interval '1 hour', \"Epoch\"=\"Epoch\"+1 WHERE \"State\"='active'");
            await AssertTransitionRejectedAsync(provision.ConnectionString,
                "UPDATE public.\"CanaryAckKeyRegistries\" SET \"State\"='active', \"Epoch\"=\"Epoch\"+1 WHERE \"State\"='next'");
            await AssertTransitionRejectedAsync(provision.ConnectionString,
                "DELETE FROM public.\"CanaryAckKeyRegistries\" WHERE \"State\"='next'");
            Assert.Equal(beforeReuse, await SnapshotAsync(provision.ConnectionString));

            await SeedExpiredPreviousFixtureAsync(provision.ConnectionString);
            Assert.True(await version2Registry.IsRetentionElapsedAsync("canary-rs256-2025-01"));
            await using var verify = new NpgsqlConnection(provision.ConnectionString);
            await verify.OpenAsync();
            await using var stateCommand = new NpgsqlCommand(
                "SELECT \"State\" FROM public.\"CanaryAckKeyRegistries\" WHERE \"KeyId\"='canary-rs256-2025-01'",
                verify);
            Assert.Equal("previous", await stateCommand.ExecuteScalarAsync());
        }
        finally
        {
            await provision.DisposeAsync();
        }
    }

    [Fact]
    public async Task StartupValidation_RejectsConfiguredPrivateKeyThatDoesNotMatchPostgreSqlActive()
    {
        var provision = await PostgreSqlProvision.CreateAsync();
        try
        {
            using var active = RSA.Create(2048);
            using var other = RSA.Create(2048);
            await CanaryAckKeyRegistryProvisioner.InitializeOrValidateAsync(
                provision.ConnectionString,
                LegacyOptions(active));
            var mismatched = new CanaryAckKeyRegistryService(
                new TestDbFactory(provision.ConnectionString),
                new CanaryAckKeyring(Options.Create(LegacyOptions(other))));

            await Assert.ThrowsAsync<InvalidOperationException>(() => mismatched.ValidateAsync());
        }
        finally
        {
            await provision.DisposeAsync();
        }
    }

    private static CanaryAckOptions LegacyOptions(RSA active) => new()
    {
        RegistryVersion = 1,
        ActiveKeyId = CanaryAckOptions.InitialKeyId,
        PrivateKeyPem = active.ExportPkcs8PrivateKeyPem()
    };

    private static CanaryAckOptions ExplicitOptions(RSA active, RSA next, int version) => new()
    {
        RegistryVersion = version,
        ActiveKeyId = CanaryAckOptions.InitialKeyId,
        PrivateKeyPem = active.ExportPkcs8PrivateKeyPem(),
        Keys =
        [
            new CanaryAckPublicKeyOptions
            {
                KeyId = CanaryAckOptions.InitialKeyId,
                PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                Role = "active"
            },
            new CanaryAckPublicKeyOptions
            {
                KeyId = "canary-rs256-2026-02",
                PublicKeyPem = next.ExportSubjectPublicKeyInfoPem(),
                Role = "next"
            }
        ]
    };

    private static Task AssertLegacyApplicationStillSignsAsync(
        string connectionString,
        RSA active)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["CanaryAck:PrivateKeyPem"] = active.ExportPkcs8PrivateKeyPem()
            }).Build();
        var service = new CanaryAckService(
            new TestDbFactory(connectionString),
            configuration,
            TimeProvider.System);
        var request = new CanaryAckValidatedRequest(
            Guid.NewGuid().ToString("D"),
            DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
            "LEGACY-AFTER-ADDITIVE-MIGRATION",
            "2.2.979",
            "test",
            3);

        var receipt = service.CreateReceipt(request, "ack", DateTimeOffset.UtcNow);
        Assert.Equal(CanaryAckService.Schema, receipt.Schema);
        Assert.Equal(CanaryAckService.KeyId, receipt.KeyId);
        Assert.False(string.IsNullOrEmpty(receipt.Signature));
        return Task.CompletedTask;
    }

    private static async Task AssertRollbackBeforeCommitAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var insert = new NpgsqlCommand(
            """
            INSERT INTO public."CanaryAckKeyRegistries"
                ("KeyId","MaterialDigestSha256","State","Epoch","CreatedAtUtc","RetainUntilUtc","RetiredAtUtc")
            VALUES ('canary-rs256-2026-02',repeat('a',64),'next',1,clock_timestamp(),NULL,NULL)
            """,
            connection,
            transaction))
        {
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        }
        await using var invalid = new NpgsqlCommand(
            """
            UPDATE public."CanaryAckKeyRegistryStates"
            SET "RegistryVersion"=2, "UpdatedAtUtc"=clock_timestamp()
            WHERE "Id"=1
            """,
            connection,
            transaction);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => invalid.ExecuteNonQueryAsync());
        Assert.Equal("55000", exception.SqlState);
        await transaction.RollbackAsync();
    }

    private static async Task AssertTransitionRejectedAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal("55000", exception.SqlState);
    }

    private static async Task AssertApplicationRoleIsReadOnlyAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using (var read = new NpgsqlCommand(
            "SELECT count(*) FROM public.\"CanaryAckKeyRegistries\"",
            connection))
            Assert.Equal(0L, await read.ExecuteScalarAsync());

        await using var write = new NpgsqlCommand(
            """
            INSERT INTO public."CanaryAckKeyRegistries"
                ("KeyId","MaterialDigestSha256","State","Epoch","CreatedAtUtc","RetainUntilUtc","RetiredAtUtc")
            VALUES ('canary-rs256-unauthorized',repeat('a',64),'next',1,clock_timestamp(),NULL,NULL)
            """,
            connection);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => write.ExecuteNonQueryAsync());
        Assert.Equal("42501", exception.SqlState);
    }

    private static async Task SeedExpiredPreviousFixtureAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            """
            SET session_replication_role = replica;
            INSERT INTO public."CanaryAckKeyRegistries"
                ("KeyId","MaterialDigestSha256","State","Epoch","CreatedAtUtc","RetainUntilUtc","RetiredAtUtc")
            VALUES ('canary-rs256-2025-01',repeat('f',64),'previous',2,
                    clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 second',NULL);
            SET session_replication_role = origin;
            """,
            connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<string> SnapshotAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var stateCommand = new NpgsqlCommand(
            """
            SELECT "RegistryVersion"::text || ':' || "UpdatedAtUtc"::text || ':' || xmin::text
            FROM public."CanaryAckKeyRegistryStates"
            """,
            connection);
        var state = Assert.IsType<string>(await stateCommand.ExecuteScalarAsync());
        await using var keysCommand = new NpgsqlCommand(
            """
            SELECT string_agg("KeyId" || ':' || "State" || ':' || "Epoch"::text || ':' || xmin::text,
                              ',' ORDER BY "KeyId" COLLATE "C")
            FROM public."CanaryAckKeyRegistries"
            """,
            connection);
        var keys = Assert.IsType<string>(await keysCommand.ExecuteScalarAsync());
        return $"{state}:{keys}";
    }

    private sealed class TestDbFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => Create();
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Create());

        private LicenseDbContext Create() => new(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);
    }

    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string applicationConnectionString,
        string database) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;
        public string ApplicationConnectionString { get; } = applicationConnectionString;

        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES must target PostgreSQL 17.");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using var connection = new NpgsqlConnection(maintenance);
            await connection.OpenAsync();
            await using (var version = new NpgsqlCommand("SHOW server_version_num", connection))
            {
                var number = int.Parse(Assert.IsType<string>(await version.ExecuteScalarAsync()),
                    System.Globalization.CultureInfo.InvariantCulture);
                Assert.InRange(number, 170000, 179999);
            }
            await using (var role = new NpgsqlCommand(
                """
                DO $roles$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_runtime_authority_owner') THEN
                        CREATE ROLE softlicence_runtime_authority_owner NOLOGIN;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                        CREATE ROLE softlicence_app LOGIN PASSWORD 'runtime-production-role-test-only';
                    END IF;
                END;
                $roles$;
                ALTER ROLE softlicence_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'runtime-production-role-test-only';
                """,
                connection))
                await role.ExecuteNonQueryAsync();

            var database = $"softlicence_canary_keyring_{Guid.NewGuid():N}";
            await using (var create = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", connection))
                await create.ExecuteNonQueryAsync();
            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            await using (var db = new LicenseDbContext(
                new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options))
                await db.Database.MigrateAsync();
            var application = new NpgsqlConnectionStringBuilder(target)
            {
                Username = "softlicence_app",
                Password = "runtime-production-role-test-only"
            }.ConnectionString;
            return new PostgreSqlProvision(maintenance, target, application, database);
        }

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", connection)
            {
                CommandTimeout = 120
            };
            await drop.ExecuteNonQueryAsync();
        }
    }
}
