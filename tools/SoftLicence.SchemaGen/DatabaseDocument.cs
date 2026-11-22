using System.Text;

namespace SoftLicence.SchemaGen;

/// <summary>Rendu Markdown de docs/schema/database.md : diagramme Mermaid des liens puis détail par table.</summary>
public static class DatabaseDocument
{
    /// <summary>Produit le document complet, stable d'une génération à l'autre.</summary>
    public static string Render(DatabaseModel model)
    {
        var text = new StringBuilder();
        text.Append(MarkdownText.GeneratedHeader);
        text.Append("# Schéma de la base de données\n\n");
        text.Append($"{model.Tables.Count} tables du modèle EF Core de `SoftLicence.Server` (`LicenseDbContext`, celui des migrations PostgreSQL), ");
        text.Append("lu sans base de données. Les colonnes qui portent un secret ou son empreinte (mot de passe, secret, empreinte, jeton, clé) ");
        text.Append("sont omises et seulement comptées.\n\n");
        text.Append("Les dates d'une licence et leurs règles sont décrites à part dans `licence-dates.md`.\n\n");

        // Le diagramme ne garde que les clés : avec plus de cent tables, toutes les colonnes dépasseraient la taille rendue par Mermaid.
        text.Append("## Tables et liens\n\n```mermaid\nerDiagram\n");
        foreach (var relationship in model.Tables.SelectMany(table => table.Relationships))
        {
            var principal = relationship.IsRequired ? "||" : "|o";
            var dependent = relationship.IsOneToOne ? "o|" : "o{";
            var line = relationship.IsRequired ? "--" : "..";
            text.Append($"    {relationship.PrincipalTable} {principal}{line}{dependent} {relationship.DependentTable} : ");
            text.Append($"\"{MarkdownText.Mermaid(relationship.Key[(relationship.DependentTable.Length + 1)..])}\"\n");
        }
        foreach (var table in model.Tables)
        {
            text.Append($"    {table.Name} {{\n");
            foreach (var column in table.Columns.Where(column => column.IsPrimaryKey || column.IsForeignKey))
                text.Append($"        {column.DiagramType} {column.Name} {DiagramKeys(column)}\n");
            text.Append("    }\n");
        }
        text.Append("```\n\n");

        text.Append("## Détail des tables\n");
        foreach (var table in model.Tables)
        {
            text.Append($"\n### {table.Name}\n\n");
            text.Append($"Entité `{table.EntityName}`.\n\n");
            text.Append("| Colonne | Type PostgreSQL | Null | Clé | Notes |\n|---|---|---|---|---|\n");
            foreach (var column in table.Columns)
            {
                var notes = column.EnumValues.Count > 0
                    ? column.Notes.Prepend("enum " + string.Join(", ", column.EnumValues))
                    : column.Notes;
                text.Append($"| {column.Name} | {column.StoreType} | {(column.IsNullable ? "oui" : "non")} | ");
                text.Append($"{DiagramKeys(column)} | {MarkdownText.Cell(string.Join(" ; ", notes))} |\n");
            }
            text.Append('\n');
            foreach (var relationship in table.Relationships)
            {
                text.Append($"- Lien `{relationship.Key}` vers `{relationship.PrincipalTable}` ");
                text.Append($"({(relationship.IsRequired ? "obligatoire" : "facultatif")}, ");
                text.Append($"{(relationship.IsOneToOne ? "un pour un" : "plusieurs pour un")}, suppression {relationship.DeleteBehavior}).\n");
            }
            foreach (var index in table.UniqueIndexes)
                text.Append($"- Unicité : {index}.\n");
            foreach (var check in table.CheckConstraints)
                text.Append($"- Contrainte : `{check}`.\n");
            if (table.OmittedSecretColumns > 0)
                text.Append($"- Colonnes secrètes omises : {table.OmittedSecretColumns}.\n");
        }
        return text.ToString();
    }

    /// <summary>Marques PK, FK et UK d'une colonne.</summary>
    private static string DiagramKeys(ColumnInfo column)
    {
        var keys = new List<string>();
        if (column.IsPrimaryKey) keys.Add("PK");
        if (column.IsForeignKey) keys.Add("FK");
        if (column.IsUnique) keys.Add("UK");
        return string.Join(", ", keys);
    }
}

/// <summary>Échappements communs aux documents générés.</summary>
internal static class MarkdownText
{
    public const string GeneratedHeader =
        "<!-- Fichier généré par tools/SoftLicence.SchemaGen : ne pas modifier à la main. " +
        "Régénérer : dotnet run --project tools/SoftLicence.SchemaGen -- write -->\n\n";

    /// <summary>Texte sûr dans une cellule de tableau Markdown.</summary>
    public static string Cell(string value) =>
        value.Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

    /// <summary>Texte sûr entre guillemets dans un libellé Mermaid.</summary>
    public static string Mermaid(string value) =>
        value.Replace("\"", "'", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
