using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Pins the Audit page contract of the threat-score Reset buttons (TKT-003191): they stay disabled while the
/// mandatory reason is empty, and the reason field updates on every keystroke so the buttons become usable while
/// the operator types. With the default change binding the buttons only enabled after the field lost focus,
/// which made them look broken.
/// </summary>
public class AuditThreatScoreResetButtonTests
{
    [Fact]
    public void ReasonField_BindsOnEveryKeystroke()
    {
        var page = ReadRepositoryFile("src/SoftLicence.Server/Components/Pages/Audit.razor");
        var field = page.IndexOf("@bind=\"ThreatResetReason\"", StringComparison.Ordinal);

        Assert.True(field > 0, "The reset reason field must bind ThreatResetReason.");
        var tagEnd = page.IndexOf("/>", field, StringComparison.Ordinal);
        Assert.Contains("@bind:event=\"oninput\"", page[field..tagEnd]);
    }

    [Fact]
    public void ResetButtons_StayDisabledWithoutReason()
    {
        var page = ReadRepositoryFile("src/SoftLicence.Server/Components/Pages/Audit.razor");

        Assert.Contains("disabled=\"@string.IsNullOrWhiteSpace(ThreatResetReason)\"", page);
    }

    /// <summary>Reads a repository file by walking up from the test output to the folder holding src and tests.</summary>
    /// <param name="relativePath">Path relative to the repository root, with forward slashes.</param>
    /// <returns>The file text.</returns>
    /// <exception cref="DirectoryNotFoundException">No parent folder of the test output holds both src and tests.</exception>
    private static string ReadRepositoryFile(string relativePath)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src")) && Directory.Exists(Path.Combine(directory.FullName, "tests")))
                return File.ReadAllText(Path.Combine(directory.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        }

        throw new DirectoryNotFoundException("Repository root not found above the test output.");
    }
}
