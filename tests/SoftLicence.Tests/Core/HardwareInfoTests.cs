using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

[Collection(MachineIdentityReadersCollection.Name)]
public class HardwareInfoTests
{
    private const string Uuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";

    [Fact]
    public void GetHardwareId_IsDerivedFromSystemUuidOnly()
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
            className == "Win32_ComputerSystemProduct" ? Row("UUID", " " + Uuid.ToLowerInvariant()) : Row(properties[0], "OTHER-" + className));

        Assert.Equal(MachineIdentity.FromUuid(Uuid).HardwareId, HardwareInfo.GetHardwareId());
    }

    [Fact]
    public void GetHardwareId_DoesNotChange_WhenOtherComponentsChange()
    {
        string first;
        using (MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
            className == "Win32_ComputerSystemProduct" ? Row("UUID", Uuid) : Row(properties[0], "A")))
            first = HardwareInfo.GetHardwareId();

        string second;
        using (MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
            className == "Win32_ComputerSystemProduct" ? Row("UUID", Uuid) : WmiQueryResult.Failed("System.Management.ManagementException")))
            second = HardwareInfo.GetHardwareId();

        Assert.Equal(first, second);
    }

    [Theory]
    [InlineData("03000200-0400-0500-0006-000700080009", MachineIdentity.RefusalUuidGenericKnown, "AR-04")]
    [InlineData("not-a-uuid", MachineIdentity.RefusalUuidInvalidFormat, "AR-03")]
    [InlineData("", MachineIdentity.RefusalUuidAbsent, "AR-01")]
    public void GetHardwareId_RefusedUuid_ThrowsWithSupportCode_AndInventsNothing(string uuid, string refusalCode, string supportCode)
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
            className == "Win32_ComputerSystemProduct" ? Row("UUID", uuid) : Row(properties[0], "PRESENT"));

        var refused = Assert.Throws<MachineIdentityRefusedException>(() => HardwareInfo.GetHardwareId());

        Assert.Equal(refusalCode, refused.RefusalCode);
        Assert.Equal(supportCode, refused.SupportCode);
        Assert.Equal("Device refused (code " + supportCode + ").", refused.Message);
        Assert.DoesNotContain(refusalCode, refused.Message);
    }

    [Fact]
    public void GetHardwareId_WmiFailure_ThrowsUnreadable_WithCause()
    {
        using var _ = MachineIdentity.UseWmiQueryReaderForTests((_, _) => WmiQueryResult.Failed("System.Management.ManagementException"));

        var refused = Assert.Throws<MachineIdentityRefusedException>(() => HardwareInfo.GetHardwareId());

        Assert.Equal("AR-02", refused.SupportCode);
        Assert.Equal("System.Management.ManagementException", refused.ReadFailure);
    }

    private static WmiQueryResult Row(string property, string? value) =>
        WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
        {
            new Dictionary<string, string?>(StringComparer.Ordinal) { [property] = value }
        });
}
