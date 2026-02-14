using System.IO;
using Xunit;

namespace SoftLicence.Tests.Server;

public class ProjectIntegrityTests
{
    [Theory]
    [InlineData("src/SoftLicence.Server/SoftLicence.Server.csproj")]
    [InlineData("src/SoftLicence.SDK/SoftLicence.SDK.csproj")]
    public void ProjectFiles_MustTreatWarningsAsErrors(string relativePath)
    {
        // On remonte à la racine depuis le dossier de test
        var projectRoot = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "../../../../../"));
        var fullPath = Path.Combine(projectRoot, relativePath);

        Assert.True(File.Exists(fullPath), $"Le fichier projet {fullPath} est introuvable.");

        var content = File.ReadAllText(fullPath);
        
        // On vérifie la présence de la règle stricte
        Assert.Contains("<TreatWarningsAsErrors>true</TreatWarningsAsErrors>", content);
    }
}
