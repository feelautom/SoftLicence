namespace SoftLicence.SchemaGen;

/// <summary>
/// Point d'entrée : <c>write</c> régénère les fichiers générés de docs/schema, <c>check</c> refuse un dossier périmé.
/// </summary>
public static class Program
{
    public const string WriteCommand = "dotnet run --project tools/SoftLicence.SchemaGen -- write";

    /// <summary>Retourne 0 si tout va bien, 1 si docs/schema est périmé ou la génération échoue, 2 si l'usage est faux.</summary>
    public static int Main(string[] args)
    {
        var mode = args.Length == 1 ? args[0] : null;
        if (mode is not ("write" or "check"))
        {
            Console.Error.WriteLine("Usage : dotnet run --project tools/SoftLicence.SchemaGen -- write|check");
            return 2;
        }

        string repositoryRoot;
        SortedDictionary<string, string> documents;
        try
        {
            repositoryRoot = SchemaGenerator.FindRepositoryRoot(Directory.GetCurrentDirectory());
            documents = SchemaGenerator.Generate(repositoryRoot);
        }
        catch (SchemaGenerationException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }

        if (mode == "write")
        {
            SchemaGenerator.Write(repositoryRoot, documents);
            foreach (var path in documents.Keys)
                Console.WriteLine($"écrit : {path}");
            return 0;
        }

        var stale = SchemaGenerator.FindStaleDocuments(repositoryRoot, documents);
        if (stale.Count == 0)
        {
            Console.WriteLine("docs/schema est à jour.");
            return 0;
        }

        foreach (var path in stale)
            Console.Error.WriteLine($"périmé : {path}");
        Console.Error.WriteLine(
            $"docs/schema n'est plus à jour avec le code. Lancez « {WriteCommand} » " +
            "depuis la racine du dépôt, relisez le diff et commitez-le dans la même pull request.");
        return 1;
    }
}
