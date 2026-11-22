using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using SoftLicence.Server.Data;

namespace SoftLicence.SchemaGen;

/// <summary>Modèle relationnel lu dans EF Core.</summary>
public sealed record DatabaseModel(IReadOnlyList<TableInfo> Tables);

/// <summary>Une table et ce qu'elle porte.</summary>
public sealed record TableInfo(
    string Name,
    string EntityName,
    IReadOnlyList<ColumnInfo> Columns,
    IReadOnlyList<RelationshipInfo> Relationships,
    IReadOnlyList<string> UniqueIndexes,
    IReadOnlyList<string> CheckConstraints,
    int OmittedSecretColumns);

/// <summary>Une colonne non secrète.</summary>
public sealed record ColumnInfo(
    string Name,
    string StoreType,
    string DiagramType,
    bool IsNullable,
    bool IsPrimaryKey,
    bool IsForeignKey,
    bool IsUnique,
    IReadOnlyList<string> EnumValues,
    IReadOnlyList<string> Notes);

/// <summary>Clé étrangère portée par la table dépendante, vers la table principale.</summary>
public sealed record RelationshipInfo(
    string Key,
    string DependentTable,
    string PrincipalTable,
    bool IsRequired,
    bool IsOneToOne,
    string DeleteBehavior);

/// <summary>
/// Lit le modèle EF Core de conception de <see cref="LicenseDbContext"/> (celui des migrations PostgreSQL)
/// sans se connecter : la chaîne de connexion vise un hôte invalide et n'est jamais ouverte.
/// </summary>
public static partial class DatabaseModelReader
{
    /// <summary>Construit le modèle et en extrait les tables, triées par nom ordinal.</summary>
    public static DatabaseModel Read()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=schema-generator.invalid;Database=none")
            .Options;
        using var context = new LicenseDbContext(options);
        var model = context.GetService<IDesignTimeModel>().Model;

        var tables = model.GetEntityTypes()
            .Where(entity => entity.GetTableName() is not null && entity.FindOwnership() is null)
            .Select(entity => ReadTable(entity, entity.GetTableName()!))
            .OrderBy(table => table.Name, StringComparer.Ordinal)
            .ToList();
        return new DatabaseModel(tables);
    }

    /// <summary>Colonne portant un secret ou une empreinte de secret : jamais écrite dans docs/schema.</summary>
    public static bool IsSecretColumn(string columnName) => SecretColumnPattern().IsMatch(columnName);

    [GeneratedRegex("password|secret|hash|securitystamp|token|licensekey|privatekey|fingerprint",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SecretColumnPattern();

    /// <summary>Extrait colonnes, liens, unicités et contraintes d'une table mappée.</summary>
    private static TableInfo ReadTable(IEntityType entity, string tableName)
    {
        var store = StoreObjectIdentifier.Table(tableName, entity.GetSchema());
        var primaryKey = entity.FindPrimaryKey()?.Properties.ToHashSet() ?? [];
        var foreignKeyProperties = entity.GetForeignKeys().SelectMany(key => key.Properties).ToHashSet();
        var uniqueSingle = entity.GetIndexes()
            .Where(index => index.IsUnique && index.Properties.Count == 1)
            .Select(index => index.Properties[0])
            .ToHashSet();

        var columns = new List<ColumnInfo>();
        var omittedSecrets = 0;
        foreach (var property in entity.GetProperties())
        {
            var columnName = property.GetColumnName(store);
            if (columnName is null)
                continue;
            if (IsSecretColumn(columnName))
            {
                omittedSecrets++;
                continue;
            }

            var clrType = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
            var notes = new List<string>();
            if (property.GetMaxLength() is int maxLength)
                notes.Add($"longueur max {maxLength}");
            if (property.IsConcurrencyToken)
                notes.Add("jeton de concurrence");
            columns.Add(new ColumnInfo(
                columnName,
                property.GetColumnType(),
                DiagramType(clrType),
                property.IsColumnNullable(store),
                primaryKey.Contains(property),
                foreignKeyProperties.Contains(property),
                uniqueSingle.Contains(property),
                clrType.IsEnum ? Enum.GetNames(clrType) : [],
                notes));
        }

        var relationships = entity.GetForeignKeys()
            .Where(key => key.PrincipalEntityType.GetTableName() is not null)
            .Select(key => new RelationshipInfo(
                $"{tableName}.{string.Join("+", key.Properties.Select(property => property.GetColumnName(store)))}",
                tableName,
                key.PrincipalEntityType.GetTableName()!,
                key.IsRequired,
                key.IsUnique,
                key.DeleteBehavior.ToString()))
            .OrderBy(relationship => relationship.Key, StringComparer.Ordinal)
            .ToList();

        var uniqueIndexes = entity.GetIndexes()
            .Where(index => index.IsUnique)
            .Select(index => (Columns: index.Properties.Select(property => property.GetColumnName(store) ?? property.Name).ToList(),
                Filter: index.GetFilter()))
            .Where(index => !index.Columns.Any(IsSecretColumn))
            .Select(index => string.Join(", ", index.Columns) +
                (index.Filter is null ? "" : $" (filtre : {index.Filter.Replace("\"", "", StringComparison.Ordinal)})"))
            .OrderBy(text => text, StringComparer.Ordinal)
            .ToList();

        var checks = entity.GetCheckConstraints()
            .Select(check => check.ModelName)
            .Where(name => !IsSecretColumn(name))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        return new TableInfo(tableName, entity.ClrType.Name, columns, relationships, uniqueIndexes, checks, omittedSecrets);
    }

    /// <summary>Type court lisible dans un diagramme Mermaid.</summary>
    private static string DiagramType(Type clrType) => clrType switch
    {
        _ when clrType == typeof(Guid) => "uuid",
        _ when clrType == typeof(string) => "string",
        _ when clrType == typeof(bool) => "bool",
        _ when clrType == typeof(int) || clrType == typeof(short) || clrType.IsEnum => "int",
        _ when clrType == typeof(long) => "bigint",
        _ when clrType == typeof(float) || clrType == typeof(double) => "float",
        _ when clrType == typeof(decimal) => "decimal",
        _ when clrType == typeof(DateTime) => "datetime",
        _ when clrType == typeof(DateTimeOffset) => "datetimeoffset",
        _ when clrType == typeof(byte[]) => "bytes",
        _ => "string"
    };
}
