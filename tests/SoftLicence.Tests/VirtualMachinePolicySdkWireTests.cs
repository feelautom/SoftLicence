using System.Net;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using SoftLicence.Server.Services;
using SoftLicence.Tests.Core;
using Xunit;

namespace SoftLicence.Tests;

/// <summary>
/// TKT-001784: classifies the machine evidence exactly as <see cref="SoftLicenceClient"/> puts it on the wire,
/// captured from a real activation request, instead of a hand-written object. SDK 2.0.0 serializes each
/// observation with both <c>Values</c> and its first-value shortcut <c>Value</c>.
/// </summary>
[Collection(MachineIdentityReadersCollection.Name)]
public sealed class VirtualMachinePolicySdkWireTests
{
    private const string Uuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";

    /// <summary>A physical computer reported by the real SDK is readable, so a restricted license is not refused.</summary>
    [Theory]
    [InlineData("LENOVO", "21K7CTO1WW")]
    [InlineData("Dell Inc.", "Precision 7680")]
    public async Task RealSdkPayload_OfAPhysicalComputer_IsClassifiedPhysical(string manufacturer, string model)
    {
        var evidence = await CaptureSdkEvidenceAsync(manufacturer, model);

        // Guards the premise: the wire really carries the list and its shortcut for the same observation.
        var observation = evidence.GetProperty("SystemManufacturer");
        Assert.Equal(manufacturer, observation.GetProperty("Value").GetString());
        Assert.Equal(manufacturer, Assert.Single(observation.GetProperty("Values").EnumerateArray()).GetString());

        var assessment = VirtualMachinePolicy.Classify(evidence);
        Assert.Equal("physical", assessment.Kind);
        Assert.Null(VirtualMachinePolicy.Refusal("FIRST_ORDER_FREE", assessment));
        Assert.Null(VirtualMachinePolicy.Refusal("FREE", assessment));
        Assert.Null(VirtualMachinePolicy.Refusal("PAID_TRIAL", assessment));
    }

    /// <summary>Reading the real shape must not weaken the rule: a virtual machine stays refused.</summary>
    [Fact]
    public async Task RealSdkPayload_OfAVirtualMachine_StaysRefused()
    {
        var assessment = VirtualMachinePolicy.Classify(await CaptureSdkEvidenceAsync("VMware, Inc.", "VMware Virtual Platform"));

        Assert.Equal("virtual", assessment.Kind);
        Assert.Equal(VirtualMachinePolicy.VirtualMachineCode, VirtualMachinePolicy.Refusal("FREE", assessment));
    }

    /// <summary>A firmware placeholder reported by the real SDK still proves nothing.</summary>
    [Fact]
    public async Task RealSdkPayload_WithPlaceholderManufacturer_StaysUnknown()
    {
        var assessment = VirtualMachinePolicy.Classify(await CaptureSdkEvidenceAsync("System manufacturer", "System Product Name"));

        Assert.Equal("unknown", assessment.Kind);
        Assert.Equal(VirtualMachinePolicy.EvidenceRequiredCode, VirtualMachinePolicy.Refusal("FREE", assessment));
    }

    /// <summary>Sends one real activation through the SDK client and returns the <c>MachineEvidence</c> it serialized.</summary>
    private static async Task<JsonElement> CaptureSdkEvidenceAsync(string manufacturer, string model)
    {
        using var wmi = MachineIdentity.UseWmiQueryReaderForTests((className, properties) => className switch
        {
            "Win32_ComputerSystemProduct" => Rows(("UUID", Uuid)),
            "Win32_ComputerSystem" => Rows(("Manufacturer", manufacturer), ("Model", model), ("HypervisorPresent", "True")),
            _ => WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
            {
                properties.ToDictionary(property => property, property => (string?)(className + "." + property))
            })
        });
        using var registry = MachineIdentity.UseRegistryValueReaderForTests((_, _, _) => MachineEvidenceValue.Unsupported());

        string? payload = null;
        var handler = new MockHttpMessageHandler(request =>
        {
            payload = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"LicenseFile\":\"abc\"}", Encoding.UTF8, "application/json")
            };
        });
        await new SoftLicenceClient("http://localhost:5200", null, new HttpClient(handler)).ActivateAsync("KEY-123", "TestApp");

        using var document = JsonDocument.Parse(payload!);
        return document.RootElement.GetProperty("MachineEvidence").Clone();
    }

    private static WmiQueryResult Rows(params (string Name, string? Value)[] properties) =>
        WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
        {
            properties.ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal)
        });
}
