using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Builds <see cref="LicenseDbContext"/> instances whose EF model matches a PostgreSQL database that a
/// migration test deliberately stopped at a historical migration. Fixtures on such databases must not
/// write or read back columns added by later migrations (for example <c>Licenses.AuthorityVersion</c>,
/// added by <c>20260906055438_AddTkt000939LicenseAuthorityVersion</c> and generated on add/update).
/// </summary>
internal static class HistoricalSchemaModel
{
    /// <summary>
    /// Lists every mapped scalar property of an existing <c>public</c> table whose column is absent from
    /// the target database. Keys, foreign keys, shadow properties, owned types and absent tables are never
    /// listed: such a divergence must still fail loudly instead of being hidden from the fixture.
    /// </summary>
    /// <param name="connectionString">A connection able to read <c>information_schema</c> of the target database.</param>
    /// <returns>An empty list for a database at the current schema; otherwise the properties to ignore.</returns>
    internal static async Task<IReadOnlyList<(Type ClrType, string Property)>> DetectMissingScalarPropertiesAsync(
        string connectionString)
    {
        var columns = new HashSet<(string Table, string Column)>();
        await using (var connection = new NpgsqlConnection(connectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("""
                SELECT table_name, column_name
                FROM information_schema.columns
                WHERE table_schema = 'public';
                """, connection);
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                columns.Add((reader.GetString(0), reader.GetString(1)));
        }
        var tables = columns.Select(column => column.Table).ToHashSet(StringComparer.Ordinal);
        var ignored = new List<(Type ClrType, string Property)>();
        await using var probe = new LicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);
        foreach (var entityType in probe.Model.GetEntityTypes())
        {
            var table = entityType.GetTableName();
            if (entityType.IsOwned() || table is null
                || (entityType.GetSchema() ?? "public") != "public" || !tables.Contains(table))
                continue;
            var store = StoreObjectIdentifier.Table(table, entityType.GetSchema());
            foreach (var property in entityType.GetProperties())
            {
                if (property.IsKey() || property.IsForeignKey() || property.IsShadowProperty())
                    continue;
                var column = property.GetColumnName(store);
                if (column is not null && !columns.Contains((table, column)))
                    ignored.Add((entityType.ClrType, property.Name));
            }
        }
        return ignored;
    }

    /// <summary>
    /// Creates a context on <paramref name="connectionString"/>: the unchanged production model when
    /// <paramref name="ignored"/> is empty, otherwise a model without those properties.
    /// </summary>
    /// <param name="connectionString">The connection used by the context.</param>
    /// <param name="ignored">Properties returned by <see cref="DetectMissingScalarPropertiesAsync"/>.</param>
    /// <returns>A new context owned and disposed by the caller.</returns>
    internal static LicenseDbContext CreateContext(
        string connectionString, IReadOnlyList<(Type ClrType, string Property)> ignored) => ignored.Count > 0
        ? new HistoricalSchemaLicenseDbContext(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString)
                .ReplaceService<IModelCacheKeyFactory, HistoricalSchemaModelCacheKeyFactory>().Options,
            ignored)
        : new LicenseDbContext(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    /// <summary>Detects the target schema and creates one matching context; see <see cref="CreateContext"/>.</summary>
    /// <param name="connectionString">The connection used both for detection and by the context.</param>
    /// <returns>A new context owned and disposed by the caller.</returns>
    internal static async Task<LicenseDbContext> CreateContextAsync(string connectionString) =>
        CreateContext(connectionString, await DetectMissingScalarPropertiesAsync(connectionString));
}

/// <summary>
/// Production context whose model omits scalar properties absent from a historical schema. The
/// production configuration runs first; only the listed properties are then ignored.
/// </summary>
internal sealed class HistoricalSchemaLicenseDbContext : LicenseDbContext
{
    private readonly IReadOnlyList<(Type ClrType, string Property)> _ignored;

    /// <summary>Creates a context whose model ignores <paramref name="ignored"/>.</summary>
    /// <param name="options">Options that must replace the model cache key factory with <see cref="HistoricalSchemaModelCacheKeyFactory"/>.</param>
    /// <param name="ignored">Scalar properties absent from the target schema.</param>
    public HistoricalSchemaLicenseDbContext(
        DbContextOptions<LicenseDbContext> options, IReadOnlyList<(Type ClrType, string Property)> ignored)
        : base(options)
    {
        _ignored = ignored;
        ModelKey = string.Join('|', ignored
            .Select(item => item.ClrType.FullName + "." + item.Property)
            .Order(StringComparer.Ordinal));
    }

    /// <summary>Stable ordinal key of the ignored set; distinct schemas must not share a cached model.</summary>
    public string ModelKey { get; }

    /// <summary>Applies the production model, then removes the properties missing from the schema.</summary>
    /// <param name="modelBuilder">The builder for this context's model.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        foreach (var (clrType, property) in _ignored)
            modelBuilder.Entity(clrType).Ignore(property);
    }
}

/// <summary>
/// Keys cached EF models by the ignored-property set as well as the context type, because EF would
/// otherwise reuse the first historical model for every later schema in the same test process.
/// </summary>
internal sealed class HistoricalSchemaModelCacheKeyFactory : IModelCacheKeyFactory
{
    /// <summary>Returns the cache key for <paramref name="context"/>.</summary>
    /// <param name="context">The context whose model is requested.</param>
    /// <param name="designTime">Whether the design-time model is requested.</param>
    /// <returns>A key including the historical ignored-property set when present.</returns>
    public object Create(DbContext context, bool designTime) => context is HistoricalSchemaLicenseDbContext historical
        ? (context.GetType(), historical.ModelKey, designTime)
        : (context.GetType(), designTime);
}
