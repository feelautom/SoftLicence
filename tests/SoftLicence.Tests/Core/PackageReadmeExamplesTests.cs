using SoftLicence.SDK;
using System.Text.RegularExpressions;
using Xunit;

namespace SoftLicence.Tests.Core;

[Collection(MachineIdentityReadersCollection.Name)]
public class PackageReadmeExamplesTests
{
    [Fact]
    public void RefusalHandlingExample_UsesThePublicContract()
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
            WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
            {
                new Dictionary<string, string?> { [properties[0]] = className == "Win32_ComputerSystemProduct" ? "03000200-0400-0500-0006-000700080009" : "X" }
            }));

        string? shownToCustomer = null;
        string? loggedInternally = null;
        try
        {
            string hardwareId = HardwareInfo.GetHardwareId();
            Assert.Fail("A generic UUID must not produce an identifier: " + hardwareId);
        }
        catch (MachineIdentityRefusedException refused)
        {
            shownToCustomer = refused.Message;
            loggedInternally = refused.RefusalCode;
        }

        Assert.Equal("Device refused (code AR-04).", shownToCustomer);
        Assert.Equal(MachineIdentity.RefusalUuidGenericKnown, loggedInternally);
    }

    [Fact]
    public void PackageReadme_DocumentsTheUuidIdentityAndSupportCodes()
    {
        string repositoryRoot = FindRepositoryRoot();
        string readmePath = Path.Combine(repositoryRoot, "src", "SoftLicence.SDK", "PACKAGE_README.md");
        string readme = File.ReadAllText(readmePath);

        Assert.Contains("HardwareInfo.GetHardwareId()", readme, StringComparison.Ordinal);
        Assert.Contains("Win32_ComputerSystemProduct.UUID", readme, StringComparison.Ordinal);
        Assert.Contains("MachineIdentityRefusedException", readme, StringComparison.Ordinal);
        foreach (var code in new[] { "AR-01", "AR-02", "AR-03", "AR-04", "AR-05" })
            Assert.Contains(code, readme, StringComparison.Ordinal);
        Assert.DoesNotContain("HardwareInfo.GetStableHardwareId()", readme, StringComparison.Ordinal);
        Assert.DoesNotContain("HardwareInfo.GetHardwareIdMigrationInfo()", readme, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"\b[A-F0-9]{16}\b", RegexOptions.IgnoreCase), readme);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "src", "SoftLicence.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the SoftLicence repository root.");
    }
}
