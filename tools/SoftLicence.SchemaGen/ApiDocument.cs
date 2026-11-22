using System.Text;
using System.Text.RegularExpressions;

namespace SoftLicence.SchemaGen;

/// <summary>Rendu Markdown de docs/schema/api.md : un tableau par contrôleur ou groupe de pages.</summary>
public static class ApiDocument
{
    /// <summary>Produit le document complet, stable d'une génération à l'autre.</summary>
    public static string Render(IReadOnlyList<RouteInfo> routes, SourceLocator sources)
    {
        var text = new StringBuilder();
        text.Append(MarkdownText.GeneratedHeader);
        text.Append("# API et routes\n\n");
        var apiCount = routes.Count(route => route.Kind == "API");
        text.Append($"{routes.Count} routes déclarées dans `SoftLicence.Server` : {apiCount} actions de contrôleurs et ");
        text.Append($"{routes.Count - apiCount} pages Blazor, relevées par réflexion sans démarrer l'application.\n\n");
        text.Append("Colonne protection : attributs `Authorize` ou `AllowAnonymous`, et services d'authentification reçus par le contrôleur. ");
        text.Append("SoftLicence vérifie la plupart des appels dans le contrôleur lui-même (secret admin `X-Admin-Secret`, signature) ou par un ");
        text.Append("middleware de `Program.cs` : « aucune déclarée » ne veut pas dire « ouverte », lire le gestionnaire avant de conclure. ");
        text.Append("Les règles des dates d'une licence sont dans `licence-dates.md`, la grille des rôles dans `roles.md`.\n");

        foreach (var group in routes.GroupBy(route => (route.Kind, route.HandlerType.Name))
                     .OrderBy(group => group.Key.Kind, StringComparer.Ordinal)
                     .ThenBy(group => group.Key.Name, StringComparer.Ordinal))
        {
            var first = group.First();
            text.Append($"\n## {(group.Key.Kind == "API" ? "API" : "Page")} `{group.Key.Name}`\n\n");
            text.Append($"Source : `{sources.Describe(first.HandlerType)}`.\n\n");
            text.Append("| Méthode | Chemin | Protection | Limitation | Gestionnaire |\n|---|---|---|---|---|\n");
            foreach (var route in group)
            {
                text.Append($"| {route.Method} | `{MarkdownText.Cell(route.Path)}` | {MarkdownText.Cell(route.Protection)} | ");
                text.Append($"{MarkdownText.Cell(route.RateLimit)} | {route.HandlerName ?? ""} |\n");
            }
        }
        return text.ToString();
    }
}

/// <summary>
/// Retrouve le ou les fichiers source d'un type dans src/SoftLicence.Server (classes partielles comprises).
/// Les numéros de ligne sont volontairement omis : ils changeraient à chaque modification sans rapport.
/// </summary>
public sealed partial class SourceLocator
{
    private readonly Dictionary<string, SortedSet<string>> _files = new(StringComparer.Ordinal);

    /// <summary>Indexe les déclarations de types des fichiers .cs et les composants .razor du serveur.</summary>
    public SourceLocator(string repositoryRoot)
    {
        var sourceRoot = Path.Combine(repositoryRoot, "src", "SoftLicence.Server");
        foreach (var path in Directory.EnumerateFiles(sourceRoot, "*.*", SearchOption.AllDirectories)
                     .Where(path => !IsBuildOutput(path)))
        {
            var relative = Path.GetRelativePath(repositoryRoot, path).Replace('\\', '/');
            if (path.EndsWith(".razor", StringComparison.Ordinal))
                Add(Path.GetFileNameWithoutExtension(path), relative);
            else if (path.EndsWith(".cs", StringComparison.Ordinal))
            {
                foreach (Match match in TypeDeclaration().Matches(File.ReadAllText(path)))
                    Add(match.Groups[1].Value, relative);
            }
        }
    }

    /// <summary>Chemins des fichiers qui déclarent le type, séparés par des virgules.</summary>
    public string Describe(Type type) =>
        _files.TryGetValue(type.Name, out var files) ? string.Join("`, `", files) : type.FullName ?? type.Name;

    private void Add(string typeName, string relativePath)
    {
        if (!_files.TryGetValue(typeName, out var files))
            _files[typeName] = files = new SortedSet<string>(StringComparer.Ordinal);
        files.Add(relativePath);
    }

    private static bool IsBuildOutput(string path)
    {
        var separator = Path.DirectorySeparatorChar;
        return path.Contains($"{separator}bin{separator}", StringComparison.Ordinal) ||
               path.Contains($"{separator}obj{separator}", StringComparison.Ordinal);
    }

    [GeneratedRegex(@"\b(?:class|record|struct)\s+([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex TypeDeclaration();
}
