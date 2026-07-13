using System.Security.Cryptography;
using System.Text;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

public class HardwareInfoTests
{
    [Fact]
    public void GetHardwareId_UsesLegacyDiskSelection_WhenIndexZeroWouldReturnAnotherDisk()
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

        var expected = ComputeHardwareId("CPU-1", "MB-1", "BIOS-1", "OTHER-DISK-FIRST", Environment.MachineName);

        Assert.Equal(expected, HardwareInfo.GetHardwareId());
    }

    [Fact]
    public void GetStableHardwareId_UsesDiskIndexZero_WhenLegacyDiskOrderWouldReturnAnotherDisk()
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

        Assert.Equal(expected, HardwareInfo.GetStableHardwareId());
    }

    [Fact]
    public void GetHardwareIdMigrationInfo_ReturnsLegacyStableAndDifferenceFlag_ForMultiDisk()
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

        var info = HardwareInfo.GetHardwareIdMigrationInfo();

        Assert.Equal(ComputeHardwareId("CPU-1", "MB-1", "BIOS-1", "OTHER-DISK-FIRST", Environment.MachineName), info.LegacyHardwareId);
        Assert.Equal(ComputeHardwareId("CPU-1", "MB-1", "BIOS-1", "SYSTEM-DISK", Environment.MachineName), info.StableHardwareId);
        Assert.True(info.HasStableHardwareId);
        Assert.True(info.HasDistinctHardwareIds);
    }

    [Fact]
    public void GetHardwareIdMigrationInfo_ReturnsNoDifference_WhenLegacyAndStableDiskMatch()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" => "SYSTEM-DISK",
                _ => "UNKNOWN"
            });

        var info = HardwareInfo.GetHardwareIdMigrationInfo();

        Assert.Equal(info.LegacyHardwareId, info.StableHardwareId);
        Assert.True(info.HasStableHardwareId);
        Assert.False(info.HasDistinctHardwareIds);
    }

    [Fact]
    public void GetStableHardwareId_ReturnsNull_WhenIndexZeroIsEmpty()
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

        var info = HardwareInfo.GetHardwareIdMigrationInfo();

        Assert.Equal(ComputeHardwareId("CPU-1", "MB-1", "BIOS-1", "LEGACY-DISK", Environment.MachineName), info.LegacyHardwareId);
        Assert.Null(info.StableHardwareId);
        Assert.False(info.HasStableHardwareId);
        Assert.False(info.HasDistinctHardwareIds);
    }

    [Fact]
    public void GetComponentFingerprints_UsesLegacyDiskSelection_ForFpDisk()
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

        Assert.Equal(ComputeComponentHash("OTHER-DISK-FIRST"), fingerprints["FP_DISK"]);
        Assert.NotEqual(ComputeComponentHash("SYSTEM-DISK"), fingerprints["FP_DISK"]);
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
