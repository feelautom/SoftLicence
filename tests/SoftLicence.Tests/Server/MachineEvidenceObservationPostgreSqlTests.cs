using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001277 lot 2a: relational proof of the machine-evidence store on PostgreSQL (migration, unique key,
/// ordinal comparison of canonical keys, deduplication and concurrent identical reports).
/// </summary>
public sealed class MachineEvidenceObservationPostgreSqlTests
{
    private const string Uuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";

    [Fact]
    public async Task IdenticalReports_ShareOneRow_DistinctKeysCreateDistinctRows()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);
        var productA = Guid.NewGuid();
        var productB = Guid.NewGuid();
        var hardwareId = MachineIdentity.FromUuid(Uuid).HardwareId!;
        var evidence = Json("{\"bios\":\"  SN-1 \"}");

        await service.ObserveAsync(productA, hardwareId, Uuid, evidence, "ACTIVATE", "3.0.0", default);
        await service.ObserveAsync(productA, hardwareId, Uuid, evidence, "CHECK", "3.0.1", default);
        await service.ObserveAsync(productA, hardwareId, Uuid, Json("{\"bios\":\"SN-1\"}"), "CHECK", null, default);
        await service.ObserveAsync(productA, hardwareId, Uuid.ToLowerInvariant(), evidence, "CHECK", null, default);
        await service.ObserveAsync(productA, "A1B2C3D4E5F60718", Uuid, evidence, "CHECK", null, default);
        await service.ObserveAsync(productB, hardwareId, Uuid, evidence, "CHECK", null, default);

        await using var db = CreateDb(provision.ConnectionString);
        var rows = await db.MachineEvidenceObservations.AsNoTracking().ToListAsync();
        Assert.Equal(5, rows.Count);
        var repeated = Assert.Single(rows, row => row.ProductId == productA && row.HardwareId == hardwareId
            && row.SystemUuidRaw == Uuid && row.EvidenceJson == "{\"bios\":\"  SN-1 \"}");
        Assert.Equal(2, repeated.ObservationCount);
        Assert.Equal("CHECK", repeated.LastEndpoint);
        Assert.Equal("3.0.1", repeated.LastAppVersion);
        Assert.All(rows, row => Assert.Equal(row.EvidenceSha256.ToLowerInvariant(), row.EvidenceSha256));
        Assert.Equal(MachineIdentity.RefusalIdentifierMismatch,
            Assert.Single(rows, row => row.HardwareId == "A1B2C3D4E5F60718").RefusalCode);
        Assert.Equal(2, rows.Count(row => row.SystemUuidCanonical == Uuid && row.ProductId == productA && row.HardwareId == hardwareId
            && row.EvidenceJson == "{\"bios\":\"  SN-1 \"}"));
    }

    /// <summary>
    /// TKT-001277 counter-review M1: the preflight's final classification is what the observation stores, so a
    /// WebSetup read failure is recorded as UUID_ILLISIBLE, like the AR-02 answer; an accepted UUID can never be
    /// recorded as refused by that refinement.
    /// </summary>
    [Fact]
    public async Task DerivedObservation_StoresTheFinalRefusalClassification()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);
        var productId = Guid.NewGuid();

        await service.ObserveDerivedAsync(productId, null, Json("{\"systemUuidRead\":\"error\"}"), "PREFLIGHT",
            default, MachineIdentity.RefusalUuidUnreadable);
        await service.ObserveDerivedAsync(productId, Uuid, Json("{\"systemUuidRead\":\"present\"}"), "PREFLIGHT",
            default, MachineIdentity.RefusalUuidUnreadable);

        await using var db = CreateDb(provision.ConnectionString);
        var rows = await db.MachineEvidenceObservations.AsNoTracking().ToListAsync();
        Assert.Equal(MachineIdentity.RefusalUuidUnreadable, Assert.Single(rows, row => row.SystemUuidRaw == null).RefusalCode);
        Assert.Null(Assert.Single(rows, row => row.SystemUuidRaw == Uuid).RefusalCode);
    }

    [Fact]
    public async Task ConcurrentIdenticalReports_NeverDuplicateTheRow()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);
        var productId = Guid.NewGuid();
        var hardwareId = MachineIdentity.FromUuid(Uuid).HardwareId!;

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            service.ObserveAsync(productId, hardwareId, Uuid, Json("{\"a\":1}"), "CHECK", null, default)));

        await using var db = CreateDb(provision.ConnectionString);
        var row = Assert.Single(await db.MachineEvidenceObservations.AsNoTracking().ToListAsync());
        Assert.InRange(row.ObservationCount, 1, 8);
    }

    [Fact]
    public async Task UniqueKey_IsEnforcedByTheDatabase_AndLookupComparesColumnsDirectly()
    {
        await using var provision = await Provision.CreateAsync();
        var productId = Guid.NewGuid();
        await using var db = CreateDb(provision.ConnectionString);
        db.MachineEvidenceObservations.Add(Row(productId));
        await db.SaveChangesAsync();

        await using var duplicate = CreateDb(provision.ConnectionString);
        duplicate.MachineEvidenceObservations.Add(Row(productId));
        await Assert.ThrowsAsync<DbUpdateException>(() => duplicate.SaveChangesAsync());

        var sql = db.MachineEvidenceObservations.Where(candidate => candidate.ProductId == productId
            && candidate.HardwareId == "A1B2C3D4E5F60718" && candidate.EvidenceSha256 == new string('a', 64)).ToQueryString();
        Assert.DoesNotContain("lower(", sql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("upper(", sql, StringComparison.OrdinalIgnoreCase);

        await using var command = new NpgsqlConnection(provision.ConnectionString);
        await command.OpenAsync();
        await using var query = command.CreateCommand();
        query.CommandText = "SELECT indexdef FROM pg_indexes WHERE tablename = 'MachineEvidenceObservations' AND indexdef LIKE 'CREATE UNIQUE%'";
        var indexes = new List<string>();
        await using (var reader = await query.ExecuteReaderAsync())
            while (await reader.ReadAsync()) indexes.Add(reader.GetString(0));
        Assert.Contains(indexes, index => index.Contains("\"ProductId\", \"HardwareId\", \"EvidenceSha256\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RefusedUuid_IsStoredWithReason_AndLegacyCallStoresNothing()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);
        var productId = Guid.NewGuid();

        var legacy = await service.ObserveAsync(productId, "A1B2C3D4E5F60718", null, null, "CHECK", null, default);
        var refused = await service.ObserveAsync(productId, "A1B2C3D4E5F60718", "03000200-0400-0500-0006-000700080009", null, "ACTIVATE", null, default);
        var oversized = await service.ObserveAsync(productId, "A1B2C3D4E5F60718", new string('A', 129), null, "ACTIVATE", null, default);

        Assert.False(legacy.Applies);
        Assert.Equal(MachineIdentity.RefusalUuidGenericKnown, refused.RefusalCode);
        Assert.Equal(MachineIdentity.RefusalUuidInvalidFormat, oversized.RefusalCode);
        await using var db = CreateDb(provision.ConnectionString);
        var rows = await db.MachineEvidenceObservations.AsNoTracking().OrderBy(row => row.RefusalCode).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.Null(rows.Single(row => row.RefusalCode == MachineIdentity.RefusalUuidInvalidFormat).SystemUuidRaw);
        Assert.Null(rows.Single(row => row.RefusalCode == MachineIdentity.RefusalUuidGenericKnown).SystemUuidCanonical);
    }

    private static MachineEvidenceObservation Row(Guid productId) => new()
    {
        ProductId = productId,
        HardwareId = "A1B2C3D4E5F60718",
        EvidenceSha256 = new string('a', 64),
        LastEndpoint = "CHECK",
        FirstSeenAtUtc = DateTime.UtcNow,
        LastSeenAtUtc = DateTime.UtcNow,
        ObservationCount = 1,
    };

    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();

    private static MachineIdentityObservationService CreateService(string connectionString) =>
        new(new Factory(connectionString), NullLogger<MachineIdentityObservationService>.Instance);

    private static LicenseDbContext CreateDb(string connectionString) =>
        new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    private sealed class Factory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => CreateDb(connectionString);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class Provision(string maintenance, string database) : IAsyncDisposable
    {
        public string ConnectionString { get; private init; } = string.Empty;

        public static async Task<Provision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");

            var database = "machine_evidence_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var provision = new Provision(maintenance, database)
            {
                ConnectionString = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString
            };
            try
            {
                await using var db = CreateDb(provision.ConnectionString);
                await db.Database.MigrateAsync();
                return provision;
            }
            catch
            {
                await provision.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenance);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync();
        }
    }
}
