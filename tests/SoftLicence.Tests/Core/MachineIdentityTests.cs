using System.Security.Cryptography;
using System.Text;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

[Collection(MachineIdentityReadersCollection.Name)]
public class MachineIdentityTests
{
    [Theory]
    [InlineData(null, null)]
    [InlineData(MachineIdentity.RefusalUuidAbsent, "AR-01")]
    [InlineData(MachineIdentity.RefusalUuidUnreadable, "AR-02")]
    [InlineData(MachineIdentity.RefusalUuidInvalidFormat, "AR-03")]
    [InlineData(MachineIdentity.RefusalUuidGenericKnown, "AR-04")]
    [InlineData(MachineIdentity.RefusalIdentifierMismatch, "AR-05")]
    [InlineData("SOMETHING_ELSE", "AR-00")]
    public void ToSupportCode_MapsEveryRefusalCode(string? refusalCode, string? supportCode)
    {
        Assert.Equal(supportCode, MachineIdentity.ToSupportCode(refusalCode));
    }

    private const string SampleUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";

    [Theory]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E32")]
    [InlineData("4c4c4544-0051-3610-8052-b7c04f4a4e32")]
    [InlineData("4c4C4544-0051-3610-8052-B7c04F4a4E32")]
    [InlineData("  4C4C4544-0051-3610-8052-B7C04F4A4E32\t")]
    [InlineData("{4C4C4544-0051-3610-8052-B7C04F4A4E32}")]
    [InlineData(" {4c4c4544-0051-3610-8052-b7c04f4a4e32} ")]
    public void FromUuid_AcceptsEquivalentRepresentations_WithOneCanonicalFormAndOneIdentifier(string raw)
    {
        var result = MachineIdentity.FromUuid(raw);

        Assert.True(result.IsAccepted);
        Assert.Null(result.RefusalCode);
        Assert.Equal(SampleUuid, result.CanonicalUuid);
        Assert.Equal(ExpectedHardwareId(SampleUuid), result.HardwareId);
    }

    [Fact]
    public void FromUuid_ProducesSixteenUppercaseHexCharacters()
    {
        var hardwareId = MachineIdentity.FromUuid(SampleUuid).HardwareId!;

        Assert.Equal(16, hardwareId.Length);
        Assert.All(hardwareId, c => Assert.True((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')));
    }

    [Fact]
    public void FromUuid_DistinctUuids_ProduceDistinctIdentifiers()
    {
        var first = MachineIdentity.FromUuid("4C4C4544-0051-3610-8052-B7C04F4A4E32").HardwareId;
        var second = MachineIdentity.FromUuid("4C4C4544-0051-3610-8052-B7C04F4A4E33").HardwareId;

        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void FromUuid_RefusesMissingValue_AsAbsent(string? raw)
    {
        AssertRefused(raw, MachineIdentity.RefusalUuidAbsent);
    }

    [Theory]
    [InlineData("UNKNOWN")]
    [InlineData("NON-WINDOWS")]
    [InlineData("4C4C4544005136108052B7C04F4A4E32")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E3")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E321")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4EZ2")]
    [InlineData("4C4C4544_0051-3610-8052-B7C04F4A4E32")]
    [InlineData("{4C4C4544-0051-3610-8052-B7C04F4A4E32")]
    [InlineData("{{4C4C4544-0051-3610-8052-B7C04F4A4E32}}")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E3٢")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E3２")]
    [InlineData("4C4C4544-0051-3610-8052 B7C04F4A4E32")]
    [InlineData("To be filled by O.E.M.")]
    public void FromUuid_RefusesMalformedValue_AsInvalidFormat(string raw)
    {
        AssertRefused(raw, MachineIdentity.RefusalUuidInvalidFormat);
    }

    [Theory]
    [InlineData("03000200-0400-0500-0006-000700080009")]
    [InlineData("03000200-0400-0500-0006-000700080009 ")]
    [InlineData("{03000200-0400-0500-0006-000700080009}")]
    [InlineData("00020003-0004-0005-0006-000700080009")]
    [InlineData("12345678-1234-5678-90ab-cddeefaabbcc")]
    [InlineData("01234567-8910-1112-1314-151617181920")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")]
    [InlineData("ffffffff-ffff-ffff-ffff-ffffffffffff")]
    [InlineData("11111111-1111-1111-1111-111111111111")]
    public void FromUuid_RefusesKnownPlaceholder_AsGeneric(string raw)
    {
        AssertRefused(raw, MachineIdentity.RefusalUuidGenericKnown);
    }

    [Fact]
    public void FromUuid_IsCultureIndependent()
    {
        var previous = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("tr-TR");
            var result = MachineIdentity.FromUuid("4c4c4544-0051-3610-8052-b7c04f4a4e32");
            Assert.Equal(SampleUuid, result.CanonicalUuid);
            Assert.Equal(ExpectedHardwareId(SampleUuid), result.HardwareId);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = previous;
        }
    }

    [Fact]
    public void Resolve_ReadsOnlySystemUuidQuery()
    {
        var queried = new List<string>();
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
        {
            queried.Add(className + "." + string.Join(",", properties));
            return Rows(("UUID", " " + SampleUuid.ToLowerInvariant()));
        });

        var result = MachineIdentity.Resolve();

        Assert.True(result.IsAccepted);
        Assert.Equal(ExpectedHardwareId(SampleUuid), result.HardwareId);
        Assert.Equal(new[] { "Win32_ComputerSystemProduct.UUID" }, queried);
    }

    [Fact]
    public void Resolve_WmiFailure_IsUnreadable_WithCause()
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((_, _) => WmiQueryResult.Failed("System.Management.ManagementException"));

        var result = MachineIdentity.Resolve();

        Assert.False(result.IsAccepted);
        Assert.Equal(MachineIdentity.RefusalUuidUnreadable, result.RefusalCode);
        Assert.Equal("System.Management.ManagementException", result.ReadFailure);
        Assert.Null(result.HardwareId);
    }

    [Fact]
    public void Resolve_NonWindows_IsUnreadable()
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((_, _) => WmiQueryResult.Unsupported());

        var result = MachineIdentity.Resolve();

        Assert.Equal(MachineIdentity.RefusalUuidUnreadable, result.RefusalCode);
        Assert.Equal("NON-WINDOWS", result.ReadFailure);
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(true, null)]
    [InlineData(true, "")]
    [InlineData(true, "   ")]
    public void Resolve_SuccessfulQueryWithoutUuid_IsAbsent(bool hasRow, string? value)
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((_, _) =>
            hasRow ? Rows(("UUID", value)) : WmiQueryResult.Success(Array.Empty<IReadOnlyDictionary<string, string?>>()));

        var result = MachineIdentity.Resolve();

        Assert.Equal(MachineIdentity.RefusalUuidAbsent, result.RefusalCode);
        Assert.Null(result.ReadFailure);
    }

    [Fact]
    public void Resolve_GenericUuidFromWmi_IsRefusedAsGeneric()
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((_, _) => Rows(("UUID", "03000200-0400-0500-0006-000700080009")));

        Assert.Equal(MachineIdentity.RefusalUuidGenericKnown, MachineIdentity.Resolve().RefusalCode);
    }

    [Fact]
    public void CollectEvidence_KeepsRawValues_AndDistinguishesPresentAbsentErrorUnsupported()
    {
        using var wmi = MachineIdentity.UseWmiQueryReaderForTests((className, properties) => className switch
        {
            "Win32_ComputerSystemProduct" => Rows(("UUID", " 4c4c4544-0051-3610-8052-b7c04f4a4e32 ")),
            "Win32_Processor" => WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
            {
                Row(("ProcessorId", "BFEBFBFF000906A3")),
                Row(("ProcessorId", "BFEBFBFF000906A4")),
            }),
            "Win32_BaseBoard" => Rows(("SerialNumber", "UNKNOWN")),
            "Win32_BIOS" => Rows(("SerialNumber", null)),
            "Win32_DiskDrive" => WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
            {
                Row(("Index", "1"), ("SerialNumber", "USB-DISK")),
                Row(("Index", "0"), ("SerialNumber", "  SYSTEM-DISK  ")),
            }),
            "Win32_ComputerSystem" => WmiQueryResult.Failed("System.Runtime.InteropServices.COMException"),
            _ => WmiQueryResult.Unsupported()
        });
        using var registry = MachineIdentity.UseRegistryValueReaderForTests((_, keyPath, valueName) => (keyPath, valueName) switch
        {
            (@"SOFTWARE\Microsoft\Cryptography", "MachineGuid") => MachineEvidenceValue.Present("0f7a1c2e-aaaa-bbbb-cccc-1234567890ab"),
            (@"SOFTWARE\Microsoft\SQMClient", "MachineId") => MachineEvidenceValue.Failed("System.UnauthorizedAccessException"),
            _ => MachineEvidenceValue.Absent()
        });

        var evidence = MachineIdentity.CollectEvidence();

        Assert.Equal(MachineEvidenceStatus.Present, evidence.SystemUuid.Status);
        Assert.Equal(" 4c4c4544-0051-3610-8052-b7c04f4a4e32 ", evidence.SystemUuid.Value);
        Assert.Equal(new[] { "BFEBFBFF000906A3", "BFEBFBFF000906A4" }, evidence.ProcessorId.Values);
        Assert.Equal(MachineEvidenceStatus.Present, evidence.MotherboardSerial.Status);
        Assert.Equal("UNKNOWN", evidence.MotherboardSerial.Value);
        Assert.Equal(MachineEvidenceStatus.Absent, evidence.BiosSerial.Status);
        Assert.Equal(MachineEvidenceStatus.Present, evidence.SystemDiskSerial.Status);
        Assert.Equal("  SYSTEM-DISK  ", evidence.SystemDiskSerial.Value);
        Assert.Equal(MachineEvidenceStatus.Error, evidence.SystemModel.Status);
        Assert.Equal("System.Runtime.InteropServices.COMException", evidence.SystemModel.Error);
        Assert.Equal(Environment.MachineName, evidence.MachineName);
        Assert.Equal("0f7a1c2e-aaaa-bbbb-cccc-1234567890ab", evidence.MachineGuid.Value);
        Assert.Equal(MachineEvidenceStatus.Error, evidence.WindowsDeviceId.Status);
        Assert.Equal(MachineEvidenceStatus.Absent, evidence.GlobalDeviceId.Status);
    }

    [Fact]
    public void CollectEvidence_WithoutDiskIndexZero_ReportsSystemDiskAbsent()
    {
        using var wmi = MachineIdentity.UseWmiQueryReaderForTests((className, _) =>
            className == "Win32_DiskDrive" ? Rows(("Index", "2"), ("SerialNumber", "OTHER")) : WmiQueryResult.Unsupported());
        using var registry = MachineIdentity.UseRegistryValueReaderForTests((_, _, _) => MachineEvidenceValue.Unsupported());

        var evidence = MachineIdentity.CollectEvidence();

        Assert.Equal(MachineEvidenceStatus.Absent, evidence.SystemDiskSerial.Status);
        Assert.Equal(MachineEvidenceStatus.Unsupported, evidence.SystemUuid.Status);
    }

    private static WmiQueryResult Rows(params (string Name, string? Value)[] properties) =>
        WmiQueryResult.Success(new[] { Row(properties) });

    private static IReadOnlyDictionary<string, string?> Row(params (string Name, string? Value)[] properties) =>
        properties.ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);

    private static void AssertRefused(string? raw, string expectedCode)
    {
        var result = MachineIdentity.FromUuid(raw);

        Assert.False(result.IsAccepted);
        Assert.Equal(expectedCode, result.RefusalCode);
        Assert.Null(result.HardwareId);
        Assert.Null(result.CanonicalUuid);
    }

    private static string ExpectedHardwareId(string canonicalUuid)
    {
        using var sha256 = SHA256.Create();
        var digest = sha256.ComputeHash(Encoding.UTF8.GetBytes("SOFTLICENCE-MACHINE-UUID|" + canonicalUuid));
        return Convert.ToHexString(digest)[..16];
    }
}
