using System.Text;

namespace SoftLicence.SchemaGen;

/// <summary>
/// Produit les fichiers générés de docs/schema et les compare au dépôt.
/// Les fichiers tenus à la main (README, roles.md, licence-dates.md) ne sont jamais écrits ici.
/// </summary>
public static class SchemaGenerator
{
    public const string SchemaDirectory = "docs/schema";
    public const string DatabaseFile = SchemaDirectory + "/database.md";
    public const string ApiFile = SchemaDirectory + "/api.md";

    /// <summary>Génère le contenu attendu de chaque fichier, indexé par chemin relatif à la racine du dépôt.</summary>
    public static SortedDictionary<string, string> Generate(string repositoryRoot)
    {
        var sources = new SourceLocator(repositoryRoot);
        return new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            [DatabaseFile] = DatabaseDocument.Render(DatabaseModelReader.Read()),
            [ApiFile] = ApiDocument.Render(RouteReader.Read(), sources)
        };
    }

    /// <summary>Écrit les fichiers générés en UTF-8 sans BOM et fins de ligne LF.</summary>
    public static void Write(string repositoryRoot, IReadOnlyDictionary<string, string> documents)
    {
        foreach (var (relativePath, content) in documents)
        {
            var path = Path.Combine(repositoryRoot, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
    }

    /// <summary>Liste les fichiers absents ou différents du contenu attendu.</summary>
    public static IReadOnlyList<string> FindStaleDocuments(
        string repositoryRoot,
        IReadOnlyDictionary<string, string> documents)
    {
        var stale = new List<string>();
        foreach (var (relativePath, expected) in documents)
        {
            var path = Path.Combine(repositoryRoot, relativePath);
            // Fins de ligne ignorées : un checkout Windows peut convertir en CRLF.
            if (!File.Exists(path) || NormalizeLineEndings(File.ReadAllText(path)) != expected)
                stale.Add(relativePath);
        }
        return stale;
    }

    /// <summary>Remonte jusqu'au dossier qui contient src/SoftLicence.sln.</summary>
    public static string FindRepositoryRoot(string startDirectory)
    {
        for (var directory = new DirectoryInfo(startDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "src", "SoftLicence.sln")))
                return directory.FullName;
        }
        throw new SchemaGenerationException(
            "Racine du dépôt introuvable (src/SoftLicence.sln) : lancez la commande depuis le dépôt.");
    }

    internal static string NormalizeLineEndings(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);
}

/// <summary>Erreur attendue de génération : message lisible, sans pile d'appels.</summary>
public sealed class SchemaGenerationException(string message) : Exception(message);
