using SoftLicence.SDK;
using System.Text.RegularExpressions;
using Xunit;

namespace SoftLicence.Tests.Core;

public class PackageReadmeExamplesTests
{
    [Fact]
    public void ObservationFirstExample_UsesThePublicMigrationContract()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-DOC-TEST",
                "Win32_BaseBoard" => "MB-DOC-TEST",
                "Win32_BIOS" => "BIOS-DOC-TEST",
                "Win32_DiskDrive" when whereClause == "Index=0" => "STABLE-DOC-TEST",
                "Win32_DiskDrive" => "LEGACY-DOC-TEST",
                _ => "UNKNOWN"
            });

        string licenseHardwareId = HardwareInfo.GetHardwareId();
        HardwareIdMigrationInfo migration = HardwareInfo.GetHardwareIdMigrationInfo();

        var hardwareIdObservation = new
        {
            HardwareId = licenseHardwareId,
            migration.LegacyHardwareId,
            migration.StableHardwareId,
            migration.HasStableHardwareId,
            migration.HasDistinctHardwareIds
        };

        Assert.Equal(migration.LegacyHardwareId, hardwareIdObservation.HardwareId);
        Assert.True(hardwareIdObservation.HasStableHardwareId);
        Assert.True(hardwareIdObservation.HasDistinctHardwareIds);
        Assert.NotNull(hardwareIdObservation.StableHardwareId);
    }

    [Fact]
    public void PackageReadme_DocumentsTheLegacyAndV2SafetyBoundary()
    {
        string repositoryRoot = FindRepositoryRoot();
        string readmePath = Path.Combine(repositoryRoot, "src", "SoftLicence.SDK", "PACKAGE_README.md");
        string readme = File.ReadAllText(readmePath);

        Assert.Contains("HardwareInfo.GetHardwareId()", readme, StringComparison.Ordinal);
        Assert.Contains("HardwareInfo.GetStableHardwareId()", readme, StringComparison.Ordinal);
        Assert.Contains("HardwareInfo.GetHardwareIdMigrationInfo()", readme, StringComparison.Ordinal);
        Assert.Contains("HasStableHardwareId", readme, StringComparison.Ordinal);
        Assert.Contains("HasDistinctHardwareIds", readme, StringComparison.Ordinal);
        Assert.Contains("V2 is observation-only", readme, StringComparison.Ordinal);
        Assert.Contains("Do not use it as the primary", readme, StringComparison.Ordinal);
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
