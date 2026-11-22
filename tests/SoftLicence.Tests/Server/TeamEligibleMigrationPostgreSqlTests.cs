using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002717: the <c>TeamEligible</c> migration on a real PostgreSQL 17 database. Rows written before the
/// migration must all come out not team eligible (false), and the column must be a non-null boolean with a false
/// default, so a type only carries the setting after an explicit administrator change.
/// </summary>
public sealed class TeamEligibleMigrationPostgreSqlTests
{
    /// <summary>Last migration before the column exists.</summary>
    private const string PreviousMigration = "20261023155840_AddTkt002475LicenseKeyActivationSettings";
    /// <summary>Migration under test.</summary>
    private const string TeamEligibleMigration = "20261026064149_AddTkt002717LicenseTypeTeamEligible";

    /// <summary>Existing free, paid, anonymous and plugin types are all false after the migration; the column is NOT NULL DEFAULT false.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Tkt2717_Migration_ExistingTypesAreNotTeamEligible_ColumnIsNotNullDefaultFalse()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("team_eligible_mig", PreviousMigration);
        try
        {
            Assert.Equal(0L, await CountColumnAsync(clone.ConnectionString));
            await using (var historical = await HistoricalSchemaModel.CreateContextAsync(clone.ConnectionString))
            {
                var product = new Product { Name = clone.DatabaseName, ApiSecret = "tkt2717-migration", PrivateKeyXml = "synthetic", PublicKeyXml = "synthetic" };
                historical.Products.Add(product);
                historical.LicenseTypes.AddRange(
                    new LicenseType { ProductId = product.Id, Name = "Free recurring", Slug = "SYN-COMMUNITY", DefaultDurationDays = 30, IsFree = true, IsRecurring = true },
                    new LicenseType { ProductId = product.Id, Name = "Paid", Slug = "SYN-PRO", DefaultDurationDays = 365 },
                    new LicenseType { ProductId = product.Id, Name = "Anonymous", Slug = "SYN-ANON", DefaultDurationDays = 30, AllowAnonymous = true },
                    new LicenseType { ProductId = product.Id, Name = "Plugin", Slug = "SYN.PLUGIN", DefaultDurationDays = 0 });
                await historical.SaveChangesAsync();
            }

            await using (var migration = new LicenseDbContext(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(clone.ConnectionString).Options))
                await migration.Database.MigrateAsync();

            await using var connection = new NpgsqlConnection(clone.ConnectionString);
            await connection.OpenAsync();
            await using (var column = new NpgsqlCommand("""
                SELECT is_nullable, data_type, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'LicenseTypes' AND column_name = 'TeamEligible'
                """, connection))
            await using (var reader = await column.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync());
                Assert.Equal("NO", reader.GetString(0));
                Assert.Equal("boolean", reader.GetString(1));
                Assert.Equal("false", reader.GetString(2));
                Assert.False(await reader.ReadAsync());
            }

            await using (var rows = new NpgsqlCommand("""
                SELECT count(*), count(*) FILTER (WHERE "TeamEligible" IS DISTINCT FROM false)
                FROM "LicenseTypes"
                """, connection))
            await using (var reader = await rows.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync());
                Assert.Equal(4L, reader.GetInt64(0));
                Assert.Equal(0L, reader.GetInt64(1));
            }

            await using var applied = new NpgsqlCommand(
                "SELECT count(*) FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\" = @id", connection);
            applied.Parameters.AddWithValue("id", TeamEligibleMigration);
            Assert.Equal(1L, (long)(await applied.ExecuteScalarAsync())!);
        }
        finally
        {
            await PostgreSqlModelDatabase.DropAsync(clone.MaintenanceConnectionString, clone.DatabaseName);
        }
    }

    /// <summary>Counts the <c>TeamEligible</c> column in the catalogue (0 before the migration, 1 after).</summary>
    /// <param name="connectionString">Isolated clone connection.</param>
    /// <returns>Number of matching columns.</returns>
    private static async Task<long> CountColumnAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'LicenseTypes' AND column_name = 'TeamEligible'
            """, connection);
        return (long)(await command.ExecuteScalarAsync())!;
    }
}
