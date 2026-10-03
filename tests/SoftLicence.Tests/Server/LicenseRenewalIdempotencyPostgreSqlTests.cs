using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves the versioned renewal fingerprint, strict historical policy, and concurrent replay contract
/// against the production PostgreSQL provider rather than EF InMemory comparison semantics.
/// </summary>
public sealed class LicenseRenewalIdempotencyPostgreSqlTests
{
    private const string GlobalSecret = "tkt794-provider-secret";
    private const string PreviousMigration = "20260830003915_AddTkt000789RuntimeAuthorityKeyRegistry";

    /// <summary>
    /// Proves the additive migration preserves an existing renewal without inventing request identity
    /// and that the HTTP replay path rejects that row with the product-approved non-retryable conflict.
    /// </summary>
    [Fact]
    public async Task Migration_HistoricalRenewalRemainsUnverifiedAndReplayFailsClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync(PreviousMigration);
        var fixture = await SeedRecurringLicenseAsync(provision.ConnectionString, "historical", historicalSchema: true);
        const string transactionId = "TX-794-PG-HISTORICAL";
        await using (var connection = new NpgsqlConnection(provision.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO "LicenseRenewals"
                    ("Id", "LicenseId", "TransactionId", "RenewalDate", "DaysAdded",
                     "ResultingExpirationDate", "ResultingReference")
                VALUES
                    (@id, @licenseId, @transactionId, @renewalDate, 30, @expiration, @reference)
                """;
            command.Parameters.AddWithValue("id", Guid.NewGuid());
            command.Parameters.AddWithValue("licenseId", fixture.LicenseId);
            command.Parameters.AddWithValue("transactionId", transactionId);
            command.Parameters.AddWithValue("renewalDate", fixture.Expiration.AddDays(-30));
            command.Parameters.AddWithValue("expiration", fixture.Expiration);
            command.Parameters.AddWithValue("reference", "LEGACY-REFERENCE");
            await command.ExecuteNonQueryAsync();
        }

        await using (var migration = CreateDb(provision.ConnectionString))
            await migration.Database.MigrateAsync();

        using var factory = CreateFactory(provision.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        using var response = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{fixture.LicenseKey}/renew",
            new { TransactionId = transactionId, Reference = "LEGACY-REFERENCE", DaysToAdd = 30 });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("legacy_transaction_unverified", body.GetProperty("error").GetString());
        Assert.False(body.GetProperty("retryable").GetBoolean());

        await using var verify = CreateDb(provision.ConnectionString);
        var renewal = await verify.LicenseRenewals.SingleAsync(item => item.TransactionId == transactionId);
        Assert.Null(renewal.RequestFingerprintVersion);
        Assert.Null(renewal.RequestFingerprint);
        Assert.Equal(fixture.Expiration, (await verify.Licenses.SingleAsync(item => item.Id == fixture.LicenseId)).ExpirationDate);
    }

    /// <summary>
    /// Proves identical concurrent calls converge on one fingerprinted ledger result while a later
    /// divergent request cannot mutate the frozen license expiration or add another renewal row.
    /// </summary>
    [Fact]
    public async Task Replay_ConcurrentIdenticalRequestsConvergeAndDivergenceFailsClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var fixture = await SeedRecurringLicenseAsync(provision.ConnectionString, "concurrent");
        using var factory = CreateFactory(provision.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        const string transactionId = "TX-794-PG-CONCURRENT";
        var target = fixture.Expiration.AddDays(31);
        var payload = new { TransactionId = transactionId, Reference = " PG-794 ", TargetExpirationUtc = target };

        var responses = await Task.WhenAll(Enumerable.Range(0, 4)
            .Select(_ => client.PostAsJsonAsync($"/api/admin/licenses/{fixture.LicenseKey}/renew", payload)));
        try
        {
            Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
            var expirations = new List<DateTime>();
            foreach (var response in responses)
            {
                var body = await response.Content.ReadFromJsonAsync<JsonElement>();
                expirations.Add(body.GetProperty("newExpirationDate").GetDateTime());
            }
            Assert.All(expirations, expiration => Assert.Equal(target, expiration));
        }
        finally
        {
            foreach (var response in responses)
                response.Dispose();
        }

        using var divergent = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{fixture.LicenseKey}/renew",
            new { TransactionId = transactionId, Reference = "PG-794-CHANGED", TargetExpirationUtc = target });
        Assert.Equal(HttpStatusCode.Conflict, divergent.StatusCode);
        Assert.Equal("transaction_payload_conflict",
            (await divergent.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        await using var verify = CreateDb(provision.ConnectionString);
        var renewal = await verify.LicenseRenewals.SingleAsync(item => item.TransactionId == transactionId);
        Assert.Equal(1, renewal.RequestFingerprintVersion);
        Assert.Matches("^[0-9a-f]{64}$", renewal.RequestFingerprint!);
        Assert.Equal(1, await verify.LicenseRenewals.CountAsync(item => item.TransactionId == transactionId));
        Assert.Equal(target, (await verify.Licenses.SingleAsync(item => item.Id == fixture.LicenseId)).ExpirationDate);
        Assert.Equal("PG-794", renewal.ResultingReference);
    }

    /// <summary>
    /// Proves malformed, noncanonical, missing, and unsupported persisted fingerprint forms all use
    /// the strict legacy-unverified response without culture, Unicode, or broad case compatibility.
    /// </summary>
    [Fact]
    public async Task Replay_UnverifiablePersistedFingerprintFormsReturnLegacyConflict()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var fixture = await SeedRecurringLicenseAsync(provision.ConnectionString, "malformed");
        using var factory = CreateFactory(provision.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        const string transactionId = "TX-794-PG-MALFORMED";
        var payload = new { TransactionId = transactionId, DaysToAdd = 30 };
        using var first = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{fixture.LicenseKey}/renew", payload);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        await using var db = CreateDb(provision.ConnectionString);
        var renewal = await db.LicenseRenewals.SingleAsync(item => item.TransactionId == transactionId);
        var canonical = renewal.RequestFingerprint!;
        var rejectedForms = new (string? Fingerprint, int? Version)[]
        {
            (canonical.ToUpperInvariant(), 1),
            (new string('a', 63), 1),
            ("Ａ" + canonical[1..], 1),
            (canonical, 2),
            (null, null)
        };

        foreach (var rejected in rejectedForms)
        {
            renewal.RequestFingerprint = rejected.Fingerprint;
            renewal.RequestFingerprintVersion = rejected.Version;
            await db.SaveChangesAsync();
            using var response = await client.PostAsJsonAsync(
                $"/api/admin/licenses/{fixture.LicenseKey}/renew", payload);
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("legacy_transaction_unverified", body.GetProperty("error").GetString());
            Assert.False(body.GetProperty("retryable").GetBoolean());
        }

        Assert.Equal(1, await db.LicenseRenewals.CountAsync(item => item.TransactionId == transactionId));
    }

    /// <summary>Builds an authenticated server host over the isolated PostgreSQL database.</summary>
    /// <param name="connectionString">The ticket-owned database connection string.</param>
    /// <returns>A disposable HTTP factory whose scoped contexts use Npgsql.</returns>
    private static WebApplicationFactory<Program> CreateFactory(string connectionString) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", GlobalSecret);
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connectionString));
            });
        });

    /// <summary>Creates a direct Npgsql context for migration, fixture, and assertion operations.</summary>
    /// <param name="connectionString">The isolated database connection string.</param>
    /// <returns>A new context that the caller must dispose.</returns>
    private static LicenseDbContext CreateDb(string connectionString) => new(
        new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    /// <summary>Seeds one recurring provider-owned license without creating any renewal ledger row.</summary>
    /// <param name="connectionString">The isolated database connection string.</param>
    /// <param name="suffix">A deterministic semantic label used to keep fixtures distinct.</param>
    /// <param name="historicalSchema">Uses only the known pre-AuthorityVersion model at PreviousMigration.</param>
    /// <returns>The identifiers and exact expiration required by the HTTP assertions.</returns>
    private static async Task<RenewalFixture> SeedRecurringLicenseAsync(
        string connectionString,
        string suffix,
        bool historicalSchema = false)
    {
        // The August boundary predates this generated column; all other mapped fields remain strict.
        await using var db = historicalSchema
            ? HistoricalSchemaModel.CreateContext(connectionString, [(typeof(License), nameof(License.AuthorityVersion))])
            : CreateDb(connectionString);
        if (historicalSchema)
            Assert.Equal(PreviousMigration, (await db.Database.GetAppliedMigrationsAsync()).Last());
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = $"tkt794-{suffix}-{Guid.NewGuid():N}",
            ApiSecret = "tkt794-product-secret"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(),
            Product = product,
            Name = "TKT-794 recurring",
            Slug = "TKT794-RECURRING",
            DefaultDurationDays = 30,
            DefaultMaxSeats = 1,
            IsRecurring = true
        };
        var expiration = new DateTime(2027, 5, 1, 10, 0, 0, DateTimeKind.Utc);
        var license = new License
        {
            Id = Guid.NewGuid(),
            Product = product,
            Type = type,
            LicenseTypeId = type.Id,
            LicenseKey = $"TKT794-{suffix}-{Guid.NewGuid():N}".ToUpperInvariant(),
            CustomerName = "TKT-794 relational fixture",
            CustomerEmail = $"tkt794-{suffix}@example.test",
            ExpirationDate = expiration,
            IsActive = true,
            MaxSeats = 1
        };
        db.AddRange(product, type, license);
        await db.SaveChangesAsync();
        return new RenewalFixture(license.Id, license.LicenseKey, expiration);
    }

    /// <summary>Identifies the stable database state used by one renewal scenario.</summary>
    private sealed record RenewalFixture(Guid LicenseId, string LicenseKey, DateTime Expiration);

    /// <summary>Owns one isolated PostgreSQL database and force-drops it after each proof.</summary>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated ticket-owned database connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Creates and migrates one bounded PostgreSQL database.</summary>
        /// <param name="targetMigration">An optional historical migration boundary.</param>
        /// <returns>The database owner that guarantees cleanup through asynchronous disposal.</returns>
        public static async Task<PostgreSqlProvision> CreateAsync(string? targetMigration = null)
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000794 PostgreSQL tests.");

            var database = "tkt794_renewal_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            try
            {
                await using var db = CreateDb(target);
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(targetMigration);
                return new PostgreSqlProvision(maintenance, target, database);
            }
            catch
            {
                await DropDatabaseAsync(maintenance, database);
                throw;
            }
        }

        /// <summary>Clears Npgsql pools and drops the exact database created by this instance.</summary>
        public async ValueTask DisposeAsync() =>
            await DropDatabaseAsync(maintenanceConnectionString, database);

        /// <summary>Removes one exact generated database after clearing pooled connections.</summary>
        /// <param name="maintenanceConnectionString">The maintenance database connection string.</param>
        /// <param name="database">The generated database identifier, never caller input.</param>
        private static async Task DropDatabaseAsync(string maintenanceConnectionString, string database)
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
