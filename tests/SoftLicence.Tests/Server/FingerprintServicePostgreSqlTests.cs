using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001805: relational proof of the hardware-fingerprint upsert on PostgreSQL (concurrent first reports of a
/// new machine, update of an existing row, exact comparison of the identifier against the unique index).
/// </summary>
public sealed class FingerprintServicePostgreSqlTests
{
    /// <summary>
    /// Production case of 12/10/2026: two startup events of a machine never seen before reached the server 10 ms
    /// apart, both found no row and both inserted. Every concurrent call must now succeed and leave one row.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ConcurrentFirstReports_CreateOneRowPerMachine_WithoutUniqueViolation()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);
        // 16 simultaneous sessions at most: the complete suite shares a server limited to 100 connections.
        var machines = Enumerable.Range(0, 2).Select(index => $"A1B2C3D4E5F6{index:X4}").ToArray();

        // Task.WhenAll rethrows the unique violation of a losing insert, which is the defect itself.
        await Task.WhenAll(machines.SelectMany(machine => Enumerable.Range(0, 8).Select(_ =>
            service.UpsertFingerprintAsync(machine, Fingerprints("cpu-" + machine, "bios-" + machine)))));

        await using var db = CreateDb(provision.ConnectionString);
        var rows = await db.HardwareFingerprints.AsNoTracking().ToListAsync();
        Assert.Equal(machines.Length, rows.Count);
        Assert.All(machines, machine =>
        {
            var row = Assert.Single(rows, candidate => candidate.HardwareId == machine);
            Assert.Equal("cpu-" + machine, row.CpuHash);
            Assert.Equal("bios-" + machine, row.BiosHash);
        });
    }

    /// <summary>A later report updates only the components it carries and keeps the row identity.</summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task LaterReport_UpdatesTheExistingRow_AndKeepsAbsentComponents()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);

        await service.UpsertFingerprintAsync("A1B2C3D4E5F60718", Fingerprints("cpu-1", "bios-1"));
        await using var db = CreateDb(provision.ConnectionString);
        var first = Assert.Single(await db.HardwareFingerprints.AsNoTracking().ToListAsync());

        await service.UpsertFingerprintAsync("A1B2C3D4E5F60718", new Dictionary<string, string> { ["FP_CPU"] = "cpu-2" });

        var row = Assert.Single(await db.HardwareFingerprints.AsNoTracking().ToListAsync());
        Assert.Equal("cpu-2", row.CpuHash);
        Assert.Equal("bios-1", row.BiosHash);
        Assert.Equal(first.Id, row.Id);
        Assert.Equal(first.FirstSeenAt, row.FirstSeenAt);
        Assert.True(row.LastSeenAt >= first.LastSeenAt);
    }

    /// <summary>
    /// The identifier is an exact machine key: every query compares the column directly, like the unique index, so
    /// two spellings that differ only by case stay two rows and no path folds case in SQL.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task Identifier_IsComparedExactly_ByTheLookupAndTheUniqueIndex()
    {
        await using var provision = await Provision.CreateAsync();
        var service = CreateService(provision.ConnectionString);

        await service.UpsertFingerprintAsync("A1B2C3D4E5F60718", Fingerprints("cpu-upper", "bios-upper"));
        await service.UpsertFingerprintAsync("a1b2c3d4e5f60718", Fingerprints("cpu-lower", "bios-lower"));

        await using var db = CreateDb(provision.ConnectionString);
        var rows = await db.HardwareFingerprints.AsNoTracking().ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal("cpu-upper", Assert.Single(rows, row => row.HardwareId == "A1B2C3D4E5F60718").CpuHash);
        Assert.Equal("cpu-lower", Assert.Single(rows, row => row.HardwareId == "a1b2c3d4e5f60718").CpuHash);

        var sql = db.HardwareFingerprints.Where(row => row.HardwareId == "A1B2C3D4E5F60718").ToQueryString();
        Assert.DoesNotContain("lower(", sql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("upper(", sql, StringComparison.OrdinalIgnoreCase);

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT indexdef FROM pg_indexes WHERE tablename = 'HardwareFingerprints' AND indexdef LIKE 'CREATE UNIQUE%'";
        var indexes = new List<string>();
        await using (var reader = await query.ExecuteReaderAsync())
            while (await reader.ReadAsync()) indexes.Add(reader.GetString(0));
        Assert.Contains(indexes, index => index.Contains("(\"HardwareId\")", StringComparison.Ordinal));
    }

    private static Dictionary<string, string> Fingerprints(string cpu, string bios) =>
        new() { ["FP_CPU"] = cpu, ["FP_BIOS"] = bios };

    // The upsert never reads settings; only the cluster queries of the service do.
    private static FingerprintService CreateService(string connectionString) =>
        new(new Factory(connectionString), NullLogger<FingerprintService>.Instance, null!);

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
            var clone = await PostgreSqlModelDatabase.CloneAsync("fingerprint");
            return new Provision(clone.MaintenanceConnectionString, clone.DatabaseName)
            {
                ConnectionString = clone.ConnectionString
            };
        }

        public async ValueTask DisposeAsync()
            => await PostgreSqlModelDatabase.DropAsync(maintenance, database);
    }
}
