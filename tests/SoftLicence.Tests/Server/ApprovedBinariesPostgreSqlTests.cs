using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ApprovedBinariesPostgreSqlTests
{
    [Fact]
    public async Task Registration_ReplayConflictsAndReadback_AreStableOnPostgreSql()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "primary");
        var otherProductId = await SeedProductAsync(provision.ConnectionString, "other");
        var service = CreateService(provision.ConnectionString);
        var artifacts = Artifacts('A', 'B', 'C');

        var uppercaseManifest = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.39", "manifest-uppercase", Hash('D'), artifacts);
        var paddedManifest = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.39", "manifest-padded", $" {Hash('d')} ", artifacts);

        var created = await service.RegisterReleaseBaselineAsync(
            productId, " 2.3.40 ", "Release/2.3.40#A", Hash('d'), artifacts);
        var replay = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "Release/2.3.40#A", Hash('d'), artifacts);
        var changedBody = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "Release/2.3.40#A", Hash('d'), Artifacts('F', 'B', 'C'));
        var changedManifest = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "Release/2.3.40#A", Hash('e'), artifacts);
        var changedProduct = await service.RegisterReleaseBaselineAsync(
            otherProductId, "2.3.40", "Release/2.3.40#A", Hash('d'), artifacts);
        var changedVersion = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.41", "Release/2.3.40#A", Hash('d'), artifacts);
        var differentKey = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "release/2.3.40#A", Hash('d'), artifacts);
        var caseDistinctKey = await service.RegisterReleaseBaselineAsync(
            otherProductId, "2.3.41", "release/2.3.40#A", Hash('d'), artifacts);
        var maximumLengthKey = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.42", new string('x', 128), Hash('d'), artifacts);
        var readback = await service.GetAuthoritativeBaselineAsync(productId, "2.3.40");

        Assert.Equal("invalid_manifest_digest", uppercaseManifest.Result.ErrorCode);
        Assert.Equal("invalid_manifest_digest", paddedManifest.Result.ErrorCode);
        Assert.False(created.Result.Idempotent);
        Assert.True(replay.Result.Idempotent);
        Assert.Equal(created.Result.BaselineId, replay.Result.BaselineId);
        Assert.Equal(created.Result.BaselineId, readback.Result.BaselineId);
        Assert.Equal("Release/2.3.40#A", readback.Result.RegistrationId);
        Assert.Equal(Hash('d'), readback.Result.ManifestDigestSha256);
        Assert.Equal(ApprovedBinaryService.ReleaseSource, readback.Result.Source);
        Assert.Equal(["FP_EXE", "FP_DLL", "FP_CORE"], readback.Result.Artifacts.Select(a => a.Key));
        Assert.All(readback.Result.Artifacts, artifact => Assert.Equal(artifact.Sha256.ToLowerInvariant(), artifact.Sha256));
        Assert.Equal("registration_id_conflict", changedBody.Result.ErrorCode);
        Assert.Equal("registration_id_conflict", changedManifest.Result.ErrorCode);
        Assert.Equal("registration_id_conflict", changedProduct.Result.ErrorCode);
        Assert.Equal("registration_id_conflict", changedVersion.Result.ErrorCode);
        Assert.Equal("baseline_registration_conflict", differentKey.Result.ErrorCode);
        Assert.Equal(ApprovedBinaryVerdict.Approved, caseDistinctKey.Result.Verdict);
        Assert.Equal(ApprovedBinaryVerdict.Approved, maximumLengthKey.Result.Verdict);

        await using var db = CreateDb(provision.ConnectionString);
        Assert.Equal(3, await db.ApprovedBinaryRegistrations.CountAsync());
        Assert.Equal(9, await db.ApprovedBinaries.CountAsync());
    }

    [Fact]
    public async Task ConcurrentIdenticalAndDivergentRegistrations_HaveOneFrozenWinner()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "concurrent-identical");
        var service = CreateService(provision.ConnectionString);
        var identical = Enumerable.Range(0, 2).Select(_ => service.RegisterReleaseBaselineAsync(
            productId, "2.3.41", "concurrent-identical", Hash('d'), Artifacts('a', 'b', 'c')));

        var identicalResults = await Task.WhenAll(identical);

        Assert.Single(identicalResults, result => !result.Result.Idempotent);
        Assert.Single(identicalResults, result => result.Result.Idempotent);
        Assert.Single(identicalResults.Select(result => result.Result.BaselineId).Distinct());

        var divergentProductId = await SeedProductAsync(provision.ConnectionString, "concurrent-divergent");
        var first = service.RegisterReleaseBaselineAsync(
            divergentProductId, "2.3.42", "divergent-a", Hash('d'), Artifacts('1', '2', '3'));
        var second = service.RegisterReleaseBaselineAsync(
            divergentProductId, "2.3.42", "divergent-b", Hash('e'), Artifacts('4', '5', '6'));
        var divergentResults = await Task.WhenAll(first, second);

        Assert.Single(divergentResults, result => result.Result.Verdict == ApprovedBinaryVerdict.Approved);
        Assert.Single(divergentResults, result => result.Result.ErrorCode == "baseline_registration_conflict");
        await using var db = CreateDb(provision.ConnectionString);
        Assert.Equal(2, await db.ApprovedBinaryRegistrations.CountAsync());
        Assert.Equal(6, await db.ApprovedBinaries.CountAsync());
    }

    [Fact]
    public async Task LegacyTiaConnect2362Adoption_IsSerializableAndLeavesOneExactAggregate()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = ApprovedBinaryService.TiaConnectLegacyAdoptionProductId;
        await SeedProductAsync(provision.ConnectionString, "tia-legacy", productId);
        await SeedHistoricalBaselineAsync(
            provision.ConnectionString, productId, "2.3.62", ApprovedBinaryService.ReleaseSource, 'a');
        List<object> metadataBefore;
        await using (var beforeDb = CreateDb(provision.ConnectionString))
            metadataBefore = await LoadLegacyMetadataAsync(beforeDb, productId);
        var service = CreateService(provision.ConnectionString);
        var artifacts = Artifacts('a', 'b', 'c');

        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            service.AdoptTiaConnect2362LegacyBaselineAsync(
                productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), artifacts)));

        Assert.All(results, result => Assert.Equal(ApprovedBinaryVerdict.Approved, result.Result.Verdict));
        Assert.Single(results, result => !result.Result.Idempotent);
        Assert.Single(results, result => result.Result.Idempotent);
        Assert.Single(results.Select(result => result.Result.BaselineId).Distinct());

        await using var db = CreateDb(provision.ConnectionString);
        Assert.Single(await db.ApprovedBinaryRegistrations.ToListAsync());
        var rows = await db.ApprovedBinaries.Where(row => row.ProductId == productId && row.Version == "2.3.62").ToListAsync();
        Assert.Equal(3, rows.Count);
        Assert.All(rows, row => Assert.Equal(results[0].Result.BaselineId, row.ApprovedBinaryRegistrationId));
        Assert.Equal(artifacts.OrderBy(item => item.Key).Select(item => item.Sha256), rows.OrderBy(row => row.Key).Select(row => row.Hash));
        Assert.Equal(metadataBefore, await LoadLegacyMetadataAsync(db, productId));
    }

    [Fact]
    public async Task LegacyTiaConnect2362Adoption_DivergentRelationalState_RollsBackWithoutMetadataMutation()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = ApprovedBinaryService.TiaConnectLegacyAdoptionProductId;
        await SeedProductAsync(provision.ConnectionString, "tia-legacy-adversarial", productId);
        await SeedHistoricalBaselineAsync(
            provision.ConnectionString, productId, "2.3.62", ApprovedBinaryService.ReleaseSource, 'a');

        await using (var mutationDb = CreateDb(provision.ConnectionString))
        {
            var mixedRow = await mutationDb.ApprovedBinaries.SingleAsync(row =>
                row.ProductId == productId && row.Version == "2.3.62" && row.Key == "FP_DLL");
            mixedRow.Source = ApprovedBinaryService.AdminSource;
            await mutationDb.SaveChangesAsync();
        }
        List<object> mixedBefore;
        await using (var beforeDb = CreateDb(provision.ConnectionString))
            mixedBefore = await LoadLegacyMetadataAsync(beforeDb, productId);

        var service = CreateService(provision.ConnectionString);
        var mixedResult = await service.AdoptTiaConnect2362LegacyBaselineAsync(
            productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), Artifacts('a', 'b', 'c'));

        Assert.Equal("legacy_baseline_not_adoptable", mixedResult.Result.ErrorCode);
        await using (var mixedVerification = CreateDb(provision.ConnectionString))
        {
            Assert.Empty(await mixedVerification.ApprovedBinaryRegistrations.ToListAsync());
            Assert.All(await mixedVerification.ApprovedBinaries.Where(row => row.ProductId == productId).ToListAsync(),
                row => Assert.Null(row.ApprovedBinaryRegistrationId));
            Assert.Equal(mixedBefore, await LoadLegacyMetadataAsync(mixedVerification, productId));
        }

        await using (var repairDb = CreateDb(provision.ConnectionString))
        {
            var mixedRow = await repairDb.ApprovedBinaries.SingleAsync(row =>
                row.ProductId == productId && row.Version == "2.3.62" && row.Key == "FP_DLL");
            mixedRow.Source = ApprovedBinaryService.ReleaseSource;
            await repairDb.SaveChangesAsync();
        }
        List<object> mismatchBefore;
        await using (var beforeDb = CreateDb(provision.ConnectionString))
            mismatchBefore = await LoadLegacyMetadataAsync(beforeDb, productId);

        var mismatchResult = await service.AdoptTiaConnect2362LegacyBaselineAsync(
            productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), Artifacts('f', 'b', 'c'));

        Assert.Equal("legacy_baseline_mismatch", mismatchResult.Result.ErrorCode);
        await using var mismatchVerification = CreateDb(provision.ConnectionString);
        Assert.Empty(await mismatchVerification.ApprovedBinaryRegistrations.ToListAsync());
        Assert.All(await mismatchVerification.ApprovedBinaries.Where(row => row.ProductId == productId).ToListAsync(),
            row => Assert.Null(row.ApprovedBinaryRegistrationId));
        Assert.Equal(mismatchBefore, await LoadLegacyMetadataAsync(mismatchVerification, productId));
    }

    [Fact]
    public async Task HistoricalPublishAndLocalTestRows_SurviveMigrationButRemainNonAuthoritative()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync(
            "20260803223205_AddSameAuthorityInstallationRecovery");
        var productId = await SeedProductAsync(provision.ConnectionString, "historical-sources");
        await SeedHistoricalBaselineAsync(provision.ConnectionString, productId, "2.3.38", "publish", '1');
        await SeedHistoricalBaselineAsync(provision.ConnectionString, productId, "2.3.39", "local-test", '4');

        await using (var migrationDb = CreateDb(provision.ConnectionString))
            await migrationDb.Database.MigrateAsync();

        await using (var verificationDb = CreateDb(provision.ConnectionString))
        {
            var rows = await verificationDb.ApprovedBinaries
                .OrderBy(row => row.Version)
                .ThenBy(row => row.Key)
                .ToListAsync();
            Assert.Equal(6, rows.Count);
            Assert.Equal(3, rows.Count(row => row.Source == "publish"));
            Assert.Equal(3, rows.Count(row => row.Source == "local-test"));
            Assert.All(rows, row => Assert.Null(row.ApprovedBinaryRegistrationId));
            Assert.Empty(await verificationDb.ApprovedBinaryRegistrations.ToListAsync());
        }

        var service = CreateService(provision.ConnectionString);
        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.38")).Result.ErrorCode);
        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.39")).Result.ErrorCode);
    }

    [Fact]
    public async Task SourceConstraintsCanonicalizationAndLookupPlan_AreRelationallyEnforced()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "constraints");
        var service = CreateService(provision.ConnectionString);
        await service.RegisterReleaseBaselineAsync(
            productId, "2.3.43+RC", "CaseSensitive", Hash('a'), Artifacts('A', 'B', 'C'));

        await using (var seed = CreateDb(provision.ConnectionString))
        {
            seed.ApprovedBinaries.AddRange(Artifacts('1', '2', '3').Select(artifact => new ApprovedBinary
            {
                ProductId = productId,
                Version = "2.3.44",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = ApprovedBinaryService.AdminSource,
                ApprovedBy = "admin"
            }));
            seed.ApprovedBinaries.AddRange(Artifacts('4', '5', '6').Select((artifact, index) => new ApprovedBinary
            {
                ProductId = productId,
                Version = "2.3.45",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = index == 0 ? ApprovedBinaryService.ReleaseSource : ApprovedBinaryService.AdminSource,
                ApprovedBy = "admin"
            }));
            await seed.SaveChangesAsync();
        }

        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.44")).Result.ErrorCode);
        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.45")).Result.ErrorCode);

        Assert.False(ApprovedBinaryService.IsValidRegistrationKey(" CaseSensitive"));
        Assert.False(ApprovedBinaryService.IsValidRegistrationKey("CaseSensitive "));
        Assert.True(ApprovedBinaryService.IsValidRegistrationKey(new string('x', 128)));
        Assert.False(ApprovedBinaryService.IsValidRegistrationKey(new string('x', 129)));

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaryRegistrations\" SET \"Source\"='admin'");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaryRegistrations\" SET \"ManifestDigestSha256\"=upper(\"ManifestDigestSha256\")");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Hash\"=upper(\"Hash\")");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Key\"=lower(\"Key\")");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Version\"=' invalid'");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Source\"='admin'");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Source\"='unknown' WHERE \"ApprovedBinaryRegistrationId\" IS NULL");

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SET enable_seqscan=off; EXPLAIN (FORMAT TEXT) SELECT * FROM \"ApprovedBinaryRegistrations\" WHERE \"ProductId\"=@productId AND \"Version\"=@version";
            command.Parameters.AddWithValue("productId", productId);
            command.Parameters.AddWithValue("version", "2.3.43+RC");
            await using var reader = await command.ExecuteReaderAsync();
            var plan = new List<string>();
            while (await reader.ReadAsync())
                plan.Add(reader.GetString(0));
            Assert.Contains(plan, line => line.Contains(
                "IX_ApprovedBinaryRegistrations_ProductId_Version", StringComparison.Ordinal));
        }

        await using var db = CreateDb(provision.ConnectionString);
        var registrationSql = db.ApprovedBinaryRegistrations
            .Where(row => row.ProductId == productId && row.Version == "2.3.43+RC")
            .ToQueryString();
        Assert.DoesNotContain("lower(", registrationSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("upper(", registrationSql, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task AssertCheckViolationAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, exception.SqlState);
    }

    private static ApprovedBinaryService CreateService(string connectionString) => new(
        new TestDbContextFactory(connectionString),
        NullLogger<ApprovedBinaryService>.Instance);

    private static LicenseDbContext CreateDb(string connectionString) => new(
        new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    private static async Task<Guid> SeedProductAsync(string connectionString, string suffix, Guid? productId = null)
    {
        await using var db = CreateDb(connectionString);
        var product = new Product
        {
            Id = productId ?? Guid.NewGuid(),
            Name = $"ApprovedBinaries-{suffix}-{Guid.NewGuid():N}",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = Guid.NewGuid().ToString("N")
        };
        db.Products.Add(product);
        await db.SaveChangesAsync();
        return product.Id;
    }

    private static async Task SeedHistoricalBaselineAsync(
        string connectionString,
        Guid productId,
        string version,
        string source,
        char firstHashCharacter)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        for (var index = 0; index < 3; index++)
        {
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                INSERT INTO "ApprovedBinaries"
                    ("Id", "ProductId", "Version", "Key", "Hash", "ApprovedAt", "Source", "ApprovedBy")
                VALUES
                    (@id, @productId, @version, @key, @hash, @approvedAt, @source, @approvedBy)
                """;
            command.Parameters.AddWithValue("id", Guid.NewGuid());
            command.Parameters.AddWithValue("productId", productId);
            command.Parameters.AddWithValue("version", version);
            command.Parameters.AddWithValue("key", new[] { "FP_EXE", "FP_DLL", "FP_CORE" }[index]);
            command.Parameters.AddWithValue("hash", Hash((char)(firstHashCharacter + index)));
            command.Parameters.AddWithValue("approvedAt", DateTime.UtcNow);
            command.Parameters.AddWithValue("source", source);
            command.Parameters.AddWithValue("approvedBy", "historical-test");
            await command.ExecuteNonQueryAsync();
        }
    }

    private static List<ApprovedBinaryArtifact> Artifacts(char exe, char dll, char core) =>
    [
        new("FP_CORE", Hash(core)),
        new("FP_EXE", Hash(exe)),
        new("FP_DLL", Hash(dll))
    ];

    private static string Hash(char value) => new(value, 64);

    private static async Task<List<object>> LoadLegacyMetadataAsync(LicenseDbContext db, Guid productId) =>
        (await db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == productId && row.Version == "2.3.62")
            .OrderBy(row => row.Key)
            .Select(row => new
            {
                row.Id,
                row.Key,
                row.Hash,
                row.Source,
                row.ApprovedAt,
                row.ApprovedBy
            })
            .ToListAsync())
        .Cast<object>()
        .ToList();

    private sealed class TestDbContextFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public static async Task<PostgreSqlProvision> CreateAsync(string? targetMigration = null)
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");

            var database = "approved_binaries_" + Guid.NewGuid().ToString("N");
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
                if (targetMigration is null)
                    await db.Database.MigrateAsync();
                else
                    await db.Database.MigrateAsync(targetMigration);
                return new PostgreSqlProvision(maintenance, target, database);
            }
            catch
            {
                await DropDatabaseAsync(maintenance, database);
                throw;
            }
        }

        public async ValueTask DisposeAsync() => await DropDatabaseAsync(maintenanceConnectionString, database);

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
