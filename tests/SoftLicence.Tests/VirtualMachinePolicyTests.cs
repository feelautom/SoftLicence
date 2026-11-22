using System.Text.Json;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests;

/// <summary>Checks real wire shapes and conservative manufacturer/model interpretation independently of persistence.</summary>
public sealed class VirtualMachinePolicyTests
{
    /// <summary>Each supported hypervisor requires its manufacturer/model pair; both producer shapes retain the same meaning.</summary>
    [Theory]
    [InlineData("VMware, Inc.", "VMware Virtual Platform")]
    [InlineData(" vmware, inc. ", " vmware virtual platform ")]
    [InlineData("innotek GmbH", "VirtualBox")]
    [InlineData("QEMU", "Standard PC (Q35 + ICH9, 2009)")]
    [InlineData("Microsoft Corporation", "Virtual Machine")]
    [InlineData("Xen", "HVM domU")]
    [InlineData("Parallels Software International Inc.", "Parallels Virtual Platform")]
    public void Tkt1550_TwoProducerShapesRecognizeSixHypervisors(string manufacturer, string model)
    {
        var sdk = Server.PersonalDayPassPostgreSqlTests.VmPolicyEvidence(manufacturer, model);
        var web = JsonSerializer.SerializeToElement(new {
            systemManufacturer = new { status = "present", value = manufacturer },
            systemModel = new { status = "present", value = model },
            hypervisorPresent = new { status = "present", value = "False" }
        });
        Assert.Equal("virtual", VirtualMachinePolicy.Classify(sdk).Kind);
        Assert.Equal("virtual", VirtualMachinePolicy.Classify(web).Kind);
        Assert.Null(VirtualMachinePolicy.Refusal("PAID", VirtualMachinePolicy.Classify(web)));
        Assert.Null(VirtualMachinePolicy.Refusal("UNKNOWN", VirtualMachinePolicy.Classify(web)));
    }

    /// <summary>Physical systems keep working when Windows Hyper-V/VBS reports a hypervisor.</summary>
    [Theory]
    [InlineData("Dell Inc.", "Precision 7680")]
    [InlineData("LENOVO", "ThinkPad P16")]
    [InlineData("Microsoft Corporation", "Surface Pro 9")]
    public void Tkt1550_PhysicalHypervisorPresentIsNotVm(string manufacturer, string model) =>
        Assert.Equal("physical", VirtualMachinePolicy.Classify(Server.PersonalDayPassPostgreSqlTests.VmPolicyEvidence(manufacturer, model)).Kind);

    /// <summary>Malformed, duplicate, absent, unsupported, or contradictory observations cannot authorize a restricted license.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("{\"hypervisorPresent\":{\"status\":\"present\",\"value\":\"True\"}}")]
    [InlineData("{\"systemManufacturer\":{\"status\":\"error\",\"value\":\"Dell Inc.\"},\"systemModel\":{\"status\":\"present\",\"value\":\"Precision\"}}")]
    [InlineData("{\"systemManufacturer\":{\"status\":\"present\",\"value\":\"Dell Inc.\",\"Values\":[\"VMware, Inc.\"]},\"systemModel\":{\"status\":\"present\",\"value\":\"Precision\"}}")]
    [InlineData("{\"systemManufacturer\":{\"status\":\"present\",\"value\":\"Dell Inc.\"},\"SystemManufacturer\":{\"Status\":\"Present\",\"Values\":[\"VMware, Inc.\"]},\"systemModel\":{\"status\":\"present\",\"value\":\"Precision\"}}")]
    [InlineData("{\"systemManufacturer\":{\"status\":\"present\",\"value\":\"VMware, Inc.\"},\"systemModel\":{\"status\":\"present\",\"value\":\"Precision\"}}")]
    [InlineData("{\"SystemManufacturer\":{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\",\"VMware, Inc.\"]},\"SystemModel\":{\"Status\":\"Present\",\"Values\":[\"Precision\"]}}")]
    public void Tkt1550_UnusableEvidenceRequiresUpdate(string json)
    {
        var evidence = JsonSerializer.Deserialize<JsonElement>(json);
        var result = VirtualMachinePolicy.Classify(evidence);
        Assert.Equal("unknown", result.Kind);
        Assert.Equal(VirtualMachinePolicy.EvidenceRequiredCode, VirtualMachinePolicy.Refusal("FREE", result));
        Assert.Null(VirtualMachinePolicy.Refusal("UNKNOWN", result));
    }

    /// <summary>
    /// TKT-001784: only the SDK's own duplicate, a one-element list and an ordinally identical Value, is readable.
    /// A differing, differently spelled, non-string or multi-element pair stays a mixed representation.
    /// </summary>
    [Theory]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"Value\":\"Dell Inc.\",\"Error\":null}", "physical")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"Value\":\"VMware, Inc.\",\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"Value\":\"dell inc.\",\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"Value\":\"Dell Inc. \",\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"Value\":null,\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\",\"Dell Inc.\"],\"Value\":\"Dell Inc.\",\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"value\":\"Dell Inc.\",\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"values\":[\"Dell Inc.\"],\"Value\":\"Dell Inc.\",\"Error\":null}", "unknown")]
    [InlineData("{\"Status\":\"Present\",\"Values\":[\"Dell Inc.\"],\"Value\":\"Dell Inc.\",\"Error\":\"System.Exception\"}", "unknown")]
    public void Tkt1784_OnlyTheIdenticalSdkValueCopyIsReadable(string manufacturerObservation, string expectedKind)
    {
        var evidence = JsonSerializer.Deserialize<JsonElement>("{\"SystemManufacturer\":" + manufacturerObservation
            + ",\"SystemModel\":{\"Status\":\"Present\",\"Values\":[\"Precision 7680\"],\"Value\":\"Precision 7680\",\"Error\":null}}");

        Assert.Equal(expectedKind, VirtualMachinePolicy.Classify(evidence).Kind);
    }

    /// <summary>
    /// TKT-001784 review: the Value copy is readable only inside the exact SDK shape. The same pair under the
    /// WebSetup observation name, with a WebSetup status spelling or with an extra field stays unknown.
    /// </summary>
    [Theory]
    [InlineData("systemManufacturer", "systemModel", "\"Status\":\"Present\"", ",\"Error\":null")]
    [InlineData("SystemManufacturer", "systemModel", "\"Status\":\"Present\"", ",\"Error\":null")]
    [InlineData("SystemManufacturer", "SystemModel", "\"status\":\"Present\"", ",\"Error\":null")]
    [InlineData("SystemManufacturer", "SystemModel", "\"Status\":\"present\"", ",\"Error\":null")]
    [InlineData("SystemManufacturer", "SystemModel", "\"Status\":\"Present\"", "")]
    [InlineData("SystemManufacturer", "SystemModel", "\"Status\":\"Present\"", ",\"Source\":\"wmi\"")]
    [InlineData("SystemManufacturer", "SystemModel", "\"Status\":\"Present\"", ",\"error\":null")]
    [InlineData("SystemManufacturer", "SystemModel", "\"Status\":\"Present\"", ",\"Error\":null,\"Source\":\"wmi\"")]
    public void Tkt1784_ValueCopyOutsideTheExactSdkShapeStaysUnknown(string manufacturerName, string modelName, string status, string extraField)
    {
        // The exact SDK shape carries Error; here it is absent, misspelled or accompanied by a foreign field.
        string Observation(string text) => "{" + status + ",\"Values\":[\"" + text + "\"],\"Value\":\"" + text + "\"" + extraField + "}";
        var evidence = JsonSerializer.Deserialize<JsonElement>("{\"" + manufacturerName + "\":" + Observation("Dell Inc.")
            + ",\"" + modelName + "\":" + Observation("Precision 7680") + "}");

        var result = VirtualMachinePolicy.Classify(evidence);
        Assert.Equal("unknown", result.Kind);
        Assert.Equal(VirtualMachinePolicy.EvidenceRequiredCode, VirtualMachinePolicy.Refusal("FREE", result));
    }
}
