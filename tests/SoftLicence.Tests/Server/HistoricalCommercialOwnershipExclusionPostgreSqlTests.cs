using System.Data;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves that the TKT-000781 inventory is read-only, excludes personal data, and recognizes
/// commercial authority only from the exact provider-provisioning tuple delivered by TKT-000780.
/// </summary>
public sealed partial class HistoricalCommercialOwnershipExclusionPostgreSqlTests
{
    /// <summary>Identifies the last schema version whose commercial writer is owned by TKT-000780.</summary>
    private const string Tkt780Migration =
        "20260829133039_AddTkt000780CommercialSubjectProvisioning";

    /// <summary>
    /// Exercises legacy, advisory trial-like, exact provider, malformed hash, incomplete, divergent,
    /// and cross-product cohorts in PostgreSQL and proves that the commercial graph is unchanged.
    /// </summary>
    [Fact]
    [Trait("Category", "PrivateRepository")]
    public async Task Inventory_OnlyExactTkt780TupleIsAttributedAndCommercialGraphRemainsUnchanged()
    {
        var reportSql = await File.ReadAllTextAsync(InventoryScriptPath());
        AssertSelectOnlyAndPiiFree(reportSql);

        await using var provision = await PostgreSqlProvision.CreateAsync();
        var expected = await SeedMatrixAsync(provision.ConnectionString);
        var before = await ReadCommercialGraphCountsAsync(provision.ConnectionString);

        var rows = await ExecuteReadOnlyInventoryAsync(provision.ConnectionString, reportSql);

        Assert.Equal(expected, rows.OrderBy(RowKey).ToArray());
        Assert.Equal(before, await ReadCommercialGraphCountsAsync(provision.ConnectionString));
    }

    /// <summary>
    /// Rejects any executable statement outside a single SELECT report and any reference to fields
    /// that could expose customer, license-key, hardware, or commercial-reference data.
    /// </summary>
    /// <param name="sql">The complete task-owned report text.</param>
    private static void AssertSelectOnlyAndPiiFree(string sql)
    {
        var executable = SqlComments().Replace(sql, string.Empty);
        Assert.DoesNotMatch(MutatingSql(), executable);
        Assert.Matches(@"(?is)^\s*WITH\b.+\bSELECT\b.+;\s*$", executable);

        var forbiddenColumns = new[]
        {
            "CustomerName", "CustomerEmail", "LicenseKey", "HardwareId", "Reference",
            "PartnerCode", "ApiSecret", "PrivateKeyXml", "PublicKeyXml"
        };
        Assert.All(forbiddenColumns, column =>
            Assert.DoesNotContain($"\"{column}\"", executable, StringComparison.Ordinal));
    }

    /// <summary>
    /// Finds the checked-out SELECT report without requiring a project-file content copy, so the
    /// implementation remains confined to the two paths approved for TKT-000781.
    /// </summary>
    /// <param name="sourceFile">The compiler-recorded test source path used as the authoritative checkout anchor.</param>
    /// <returns>The absolute path to the task-owned inventory script.</returns>
    private static string InventoryScriptPath([CallerFilePath] string sourceFile = "")
    {
        foreach (var start in new[]
                 {
                     Path.GetDirectoryName(sourceFile) ?? string.Empty,
                     Directory.GetCurrentDirectory(),
                     AppContext.BaseDirectory
                 })
        {
            if (string.IsNullOrEmpty(start))
                continue;
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, "scripts",
                    "tkt-000781-commercial-ownership-inventory.sql");
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        throw new FileNotFoundException("The TKT-000781 inventory script was not found.");
    }

    /// <summary>
    /// Seeds only observable relational facts. Human presentation values are deliberately identical
    /// noise and never participate in the expected authority classification.
    /// </summary>
    /// <param name="connectionString">The isolated TKT-000781 database.</param>
    /// <returns>The complete closed aggregate expected from the report.</returns>
    private static async Task<InventoryRow[]> SeedMatrixAsync(string connectionString)
    {
        var historicalProductId = Guid.Parse("78100000-0000-0000-0000-000000000001");
        var trialProductId = Guid.Parse("78100000-0000-0000-0000-000000000002");
        var providerProductId = Guid.Parse("78100000-0000-0000-0000-000000000003");
        var crossProductId = Guid.Parse("78100000-0000-0000-0000-000000000004");
        var providerSubjectId = Guid.Parse("78110000-0000-0000-0000-000000000001");
        var divergentSubjectId = Guid.Parse("78110000-0000-0000-0000-000000000002");
        var crossSubjectId = Guid.Parse("78110000-0000-0000-0000-000000000003");
        var exactLedgerId = Guid.Parse("78120000-0000-0000-0000-000000000001");
        var incompleteLedgerId = Guid.Parse("78120000-0000-0000-0000-000000000002");
        var divergentLedgerId = Guid.Parse("78120000-0000-0000-0000-000000000003");
        var legacyLedgerId = Guid.Parse("78120000-0000-0000-0000-000000000004");
        var uppercaseLedgerId = Guid.Parse("78120000-0000-0000-0000-000000000005");
        var mixedLedgerId = Guid.Parse("78120000-0000-0000-0000-000000000006");

        var products = new[]
        {
            Product(historicalProductId, "TKT781-HISTORICAL"),
            Product(trialProductId, "TKT781-TRIAL"),
            Product(providerProductId, "TKT781-PROVIDER"),
            Product(crossProductId, "TKT781-CROSS")
        };
        var proTypes = products.ToDictionary(product => product.Id,
            product => LicenseType(product, "PRO"));
        var trialType = LicenseType(products[1], "trial");
        var freeTrialType = LicenseType(products[1], "SUITE-FREE-TRIAL");
        var providerTrialType = LicenseType(products[2], "TrIaL");

        var exactLedger = Ledger(exactLedgerId, providerProductId, "TKT781-EXACT",
            new string('a', 64), providerSubjectId,
            LicenseProvisioningRequest.ProviderAdminApiProvenance);
        var incompleteLedger = Ledger(incompleteLedgerId, providerProductId, "TKT781-INCOMPLETE",
            new string('b', 64), providerSubjectId,
            LicenseProvisioningRequest.ProviderAdminApiProvenance);
        var divergentLedger = Ledger(divergentLedgerId, providerProductId, "TKT781-DIVERGENT",
            new string('c', 64), providerSubjectId,
            LicenseProvisioningRequest.ProviderAdminApiProvenance);
        var legacyLedger = Ledger(legacyLedgerId, historicalProductId, "TKT781-LEGACY",
            new string('d', 64), null, null);
        var uppercaseLedger = Ledger(uppercaseLedgerId, providerProductId, "TKT800-UPPERCASE",
            new string('A', 64), providerSubjectId,
            LicenseProvisioningRequest.ProviderAdminApiProvenance);
        var mixedLedger = Ledger(mixedLedgerId, providerProductId, "TKT800-MIXED",
            string.Concat(Enumerable.Repeat("Aa", 32)), providerSubjectId,
            LicenseProvisioningRequest.ProviderAdminApiProvenance);

        // Keep the exact TKT780 schema: only the later generated AuthorityVersion column is absent.
        await using (var db = HistoricalSchemaModel.CreateContext(connectionString,
            [(typeof(SoftLicence.Server.Data.License), nameof(SoftLicence.Server.Data.License.AuthorityVersion))]))
        {
            Assert.Equal(Tkt780Migration, (await db.Database.GetAppliedMigrationsAsync()).Last());
            db.AddRange(products);
            db.AddRange(proTypes.Values);
            db.AddRange(trialType, freeTrialType, providerTrialType);
            db.AddRange(
                new RuntimeRecoveryCommercialSubject
                    { ProductId = providerProductId, Id = providerSubjectId, CreatedAtUtc = DateTime.UtcNow },
                new RuntimeRecoveryCommercialSubject
                    { ProductId = providerProductId, Id = divergentSubjectId, CreatedAtUtc = DateTime.UtcNow },
                new RuntimeRecoveryCommercialSubject
                    { ProductId = crossProductId, Id = crossSubjectId, CreatedAtUtc = DateTime.UtcNow });
            db.AddRange(exactLedger, incompleteLedger, divergentLedger, legacyLedger, uppercaseLedger, mixedLedger);

            db.AddRange(
                License(historicalProductId, proTypes[historicalProductId].Id, null, null),
                License(historicalProductId, proTypes[historicalProductId].Id, legacyLedgerId, 0),
                License(trialProductId, trialType.Id, null, null),
                License(trialProductId, freeTrialType.Id, null, null),
                License(providerProductId, proTypes[providerProductId].Id, exactLedgerId, 0),
                License(providerProductId, providerTrialType.Id, exactLedgerId, 1),
                License(providerProductId, proTypes[providerProductId].Id, incompleteLedgerId, 0),
                License(providerProductId, proTypes[providerProductId].Id, divergentLedgerId, 0),
                License(providerProductId, proTypes[providerProductId].Id, uppercaseLedgerId, 0),
                License(providerProductId, proTypes[providerProductId].Id, mixedLedgerId, 0),
                License(crossProductId, proTypes[crossProductId].Id, exactLedgerId, 2));
            await db.SaveChangesAsync();
        }

        await InsertActiveOwnershipsAsync(connectionString, new[]
        {
            new OwnershipSeed(providerProductId, exactLedger.Licenses.ElementAt(0).Id, providerSubjectId),
            new OwnershipSeed(providerProductId, exactLedger.Licenses.ElementAt(1).Id, providerSubjectId),
            new OwnershipSeed(providerProductId, divergentLedger.Licenses.Single().Id, divergentSubjectId),
            new OwnershipSeed(providerProductId, uppercaseLedger.Licenses.Single().Id, providerSubjectId),
            new OwnershipSeed(providerProductId, mixedLedger.Licenses.Single().Id, providerSubjectId),
            new OwnershipSeed(crossProductId, exactLedger.Licenses.ElementAt(2).Id, crossSubjectId)
        });

        return new[]
        {
            new InventoryRow(historicalProductId, "PROVENANCE_UNPROVABLE", false, 2),
            new InventoryRow(trialProductId, "PROVENANCE_UNPROVABLE", true, 2),
            new InventoryRow(providerProductId, "PROVIDER_ATTRIBUTED", false, 1),
            new InventoryRow(providerProductId, "PROVIDER_ATTRIBUTED", true, 1),
            new InventoryRow(providerProductId, "PROVENANCE_UNPROVABLE", false, 4),
            new InventoryRow(crossProductId, "PROVENANCE_UNPROVABLE", false, 1)
        }.OrderBy(RowKey).ToArray();
    }

    /// <summary>Creates one product carrying no meaningful customer or authority information.</summary>
    /// <param name="id">The opaque product identifier preserved by the report.</param>
    /// <param name="name">A non-customer fixture label.</param>
    /// <returns>A product suitable only for the isolated regression database.</returns>
    private static Product Product(Guid id, string name) => new()
    {
        Id = id,
        Name = name,
        PrivateKeyXml = "test-only",
        PublicKeyXml = "test-only",
        ApiSecret = "test-only"
    };

    /// <summary>Creates an exact product-scoped technical type used only as an advisory report input.</summary>
    /// <param name="product">The product that owns the type.</param>
    /// <param name="slug">The literal ASCII marker observed without granting authority.</param>
    /// <returns>A product-scoped test license type.</returns>
    private static LicenseType LicenseType(Product product, string slug) => new()
    {
        Id = Guid.NewGuid(),
        Product = product,
        Name = "Presentation only",
        Slug = slug,
        Description = string.Empty,
        DefaultDurationDays = 30,
        DefaultAllowedVersions = "*",
        DefaultMaxSeats = 1
    };

    /// <summary>Creates a ledger fact without deriving its product or subject from presentation data.</summary>
    /// <param name="id">The opaque ledger identifier.</param>
    /// <param name="productId">The exact product scope persisted by the provider writer.</param>
    /// <param name="reference">A test-only idempotency reference that the report never reads.</param>
    /// <param name="requestHash">The exact persisted SHA-256 text representation under test.</param>
    /// <param name="subjectId">The optional server-owned commercial subject identifier.</param>
    /// <param name="provenance">The optional server-owned authority provenance.</param>
    /// <returns>A provisioning ledger fixture with explicit relational authority facts.</returns>
    private static LicenseProvisioningRequest Ledger(Guid id, Guid productId, string reference,
        string requestHash, Guid? subjectId, string? provenance) => new()
    {
        Id = id,
        ProductId = productId,
        Reference = reference,
        RequestHash = requestHash,
        CommercialSubjectId = subjectId,
        AuthorityProvenance = provenance,
        CreatedAt = DateTime.UtcNow
    };

    /// <summary>Creates a license fixture whose linkage facts alone determine inventory classification.</summary>
    /// <param name="productId">The exact product scope of the license.</param>
    /// <param name="typeId">The product-scoped technical type identifier.</param>
    /// <param name="ledgerId">The optional provider-ledger link observed by the report.</param>
    /// <param name="sequence">The optional provider batch sequence observed by the report.</param>
    /// <returns>A license carrying presentation noise that cannot influence authority.</returns>
    private static License License(Guid productId, Guid typeId, Guid? ledgerId, int? sequence) => new()
    {
        Id = Guid.NewGuid(),
        ProductId = productId,
        LicenseTypeId = typeId,
        LicenseKey = "TKT781-" + Guid.NewGuid().ToString("N"),
        CustomerName = "Presentation only",
        CustomerEmail = "presentation@example.test",
        CreationDate = DateTime.UtcNow,
        AllowedVersions = "*",
        MaxSeats = 1,
        IsActive = true,
        ProvisioningRequestId = ledgerId,
        ProvisioningSequence = sequence
    };

    /// <summary>
    /// Inserts TKT-000780-shaped ACTIVE ownership facts with an explicit column list so the test remains
    /// pinned to the TKT-000780 migration while the unrelated TKT-000782 model candidate is present.
    /// </summary>
    /// <param name="connectionString">The isolated TKT-000781 database connection.</param>
    /// <param name="ownerships">The exact product, license, and subject tuples to persist as fixtures.</param>
    private static async Task InsertActiveOwnershipsAsync(string connectionString,
        IEnumerable<OwnershipSeed> ownerships)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        foreach (var ownership in ownerships)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO public."RuntimeRecoveryCommercialOwnerships"
                    ("Id", "ProductId", "LicenseId", "OwnerSubjectId", "State", "CreatedAtUtc", "EndedAtUtc")
                VALUES (@id, @product, @license, @subject, 'ACTIVE', @created, NULL);
                """;
            command.Parameters.AddWithValue("id", Guid.NewGuid());
            command.Parameters.AddWithValue("product", ownership.ProductId);
            command.Parameters.AddWithValue("license", ownership.LicenseId);
            command.Parameters.AddWithValue("subject", ownership.SubjectId);
            command.Parameters.AddWithValue("created", DateTime.UtcNow);
            await command.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// Executes the report after PostgreSQL confirms the transaction is READ ONLY and returns only its
    /// four approved aggregate columns.
    /// </summary>
    /// <param name="connectionString">The isolated TKT-000781 database connection.</param>
    /// <param name="sql">The previously audited SELECT-only report.</param>
    /// <returns>The closed aggregate ordered by opaque product and ordinal classifications.</returns>
    private static async Task<InventoryRow[]> ExecuteReadOnlyInventoryAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using (var readOnly = connection.CreateCommand())
        {
            readOnly.Transaction = transaction;
            readOnly.CommandText = "SET TRANSACTION READ ONLY; SHOW transaction_read_only;";
            Assert.Equal("on", await readOnly.ExecuteScalarAsync());
        }

        var rows = new List<InventoryRow>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync();
            Assert.Equal(new[] { "ProductId", "Classification", "TrialLikeObserved", "LicenseCount" },
                Enumerable.Range(0, reader.FieldCount).Select(reader.GetName));
            while (await reader.ReadAsync())
                rows.Add(new InventoryRow(reader.GetGuid(0), reader.GetString(1), reader.GetBoolean(2),
                    reader.GetInt64(3)));
        }

        await transaction.CommitAsync();
        return rows.OrderBy(RowKey).ToArray();
    }

    /// <summary>Reads the four commercial graph cardinalities that the report must never modify.</summary>
    /// <param name="connectionString">The isolated TKT-000781 database connection.</param>
    /// <returns>The cardinalities used to prove zero commercial mutation.</returns>
    private static async Task<CommercialGraphCounts> ReadCommercialGraphCountsAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT COUNT(*) FROM public."Licenses"),
                (SELECT COUNT(*) FROM public."LicenseProvisioningRequests"),
                (SELECT COUNT(*) FROM public."RuntimeRecoveryCommercialSubjects"),
                (SELECT COUNT(*) FROM public."RuntimeRecoveryCommercialOwnerships");
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return new CommercialGraphCounts(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2),
            reader.GetInt64(3));
    }

    /// <summary>Produces a stable ordinal key for aggregate comparison without normalizing opaque values.</summary>
    /// <param name="row">The aggregate whose exact values form the comparison key.</param>
    /// <returns>An ordinal test-only key; it is never persisted or used as authority.</returns>
    private static string RowKey(InventoryRow row) =>
        $"{row.ProductId:D}|{row.Classification}|{row.TrialLikeObserved}";

    /// <summary>Represents one exact aggregate emitted by the PII-free inventory.</summary>
    /// <param name="ProductId">The opaque product scope.</param>
    /// <param name="Classification">One closed ordinal inventory classification.</param>
    /// <param name="TrialLikeObserved">Whether a non-authoritative ASCII trial marker was observed.</param>
    /// <param name="LicenseCount">The number of matching licenses.</param>
    private sealed record InventoryRow(Guid ProductId, string Classification, bool TrialLikeObserved,
        long LicenseCount);

    /// <summary>Represents the commercial graph cardinalities protected by the read-only proof.</summary>
    /// <param name="Licenses">The total number of licenses.</param>
    /// <param name="Ledgers">The total number of provisioning ledger rows.</param>
    /// <param name="Subjects">The total number of commercial subjects.</param>
    /// <param name="Ownerships">The total number of commercial ownership rows.</param>
    private sealed record CommercialGraphCounts(long Licenses, long Ledgers, long Subjects, long Ownerships);

    /// <summary>Represents one explicit ACTIVE ownership inserted against the TKT-000780 schema.</summary>
    /// <param name="ProductId">The exact product scope.</param>
    /// <param name="LicenseId">The owned license identifier.</param>
    /// <param name="SubjectId">The server-owned commercial subject identifier.</param>
    private sealed record OwnershipSeed(Guid ProductId, Guid LicenseId, Guid SubjectId);

    /// <summary>Removes line and block comments before executable-statement auditing.</summary>
    /// <returns>A deterministic expression matching SQL comments only.</returns>
    [GeneratedRegex(@"(?s)/\*.*?\*/|--[^\r\n]*")]
    private static partial Regex SqlComments();

    /// <summary>Matches every SQL statement family forbidden from the inventory executable text.</summary>
    /// <returns>A case-insensitive expression matching forbidden SQL statement keywords.</returns>
    [GeneratedRegex(@"(?i)\b(?:INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|CALL|DO|COPY)\b")]
    private static partial Regex MutatingSql();

    /// <summary>Owns one isolated database pinned to the exact TKT-000780 migration.</summary>
    /// <param name="maintenanceConnectionString">The maintenance database used only for bounded create/drop.</param>
    /// <param name="connectionString">The isolated application database connection.</param>
    /// <param name="database">The generated database name owned by this fixture.</param>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated application connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Creates and migrates one isolated database without observing later migrations.</summary>
        /// <returns>A fixture that owns cleanup of the generated database.</returns>
        /// <exception cref="InvalidOperationException">The bounded PostgreSQL test connection is absent.</exception>
        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000781 PostgreSQL tests.");

            var database = "tkt781_negative_inventory_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }
                .ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
            await using (var db = new LicenseDbContext(options))
                await db.GetService<IMigrator>().MigrateAsync(Tkt780Migration);
            return new PostgreSqlProvision(maintenance, target, database);
        }

        /// <summary>Forcibly drops only the database created by this fixture after clearing local pools.</summary>
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
