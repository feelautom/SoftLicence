using System.Security.Cryptography;
using System.Text;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

public class HardwareInfoTests
{
    [Fact]
    public void GetHardwareId_UsesDiskIndexZero_WhenLegacyDiskOrderWouldReturnAnotherDisk()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" when whereClause == "Index=0" => "SYSTEM-DISK",
                "Win32_DiskDrive" => "OTHER-DISK-FIRST",
                _ => "UNKNOWN"
            });

        var expected = ComputeHardwareId("CPU-1", "MB-1", "BIOS-1", "SYSTEM-DISK", Environment.MachineName);

        Assert.Equal(expected, HardwareInfo.GetHardwareId());
    }

    [Fact]
    public void GetHardwareId_FallsBackToLegacyDiskSelection_WhenIndexZeroIsUnknown()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" when whereClause == "Index=0" => "UNKNOWN",
                "Win32_DiskDrive" => "LEGACY-DISK",
                _ => "UNKNOWN"
            });

        var expected = ComputeHardwareId("CPU-1", "MB-1", "BIOS-1", "LEGACY-DISK", Environment.MachineName);

        Assert.Equal(expected, HardwareInfo.GetHardwareId());
    }

    [Fact]
    public void GetComponentFingerprints_UsesDiskIndexZero_ForFpDisk()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" when whereClause == "Index=0" => "SYSTEM-DISK",
                "Win32_DiskDrive" => "OTHER-DISK-FIRST",
                _ => "UNKNOWN"
            });

        var fingerprints = HardwareInfo.GetComponentFingerprints();

        Assert.Equal(ComputeComponentHash("SYSTEM-DISK"), fingerprints["FP_DISK"]);
        Assert.NotEqual(ComputeComponentHash("OTHER-DISK-FIRST"), fingerprints["FP_DISK"]);
    }

    [Fact]
    public void GetComponentFingerprints_FallsBackToLegacyDiskSelection_WhenIndexZeroIsEmpty()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" when whereClause == "Index=0" => "",
                "Win32_DiskDrive" => "LEGACY-DISK",
                _ => "UNKNOWN"
            });

        var fingerprints = HardwareInfo.GetComponentFingerprints();

        Assert.Equal(ComputeComponentHash("LEGACY-DISK"), fingerprints["FP_DISK"]);
    }

    private static string ComputeHardwareId(string cpuId, string motherboardId, string biosId, string diskId, string machineName)
    {
        var rawId = string.Concat(cpuId, motherboardId, biosId, diskId, machineName);
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawId));
        return BitConverter.ToString(bytes).Replace("-", "").Substring(0, 16).ToUpperInvariant();
    }

    private static string ComputeComponentHash(string value)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(value));
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }
}
