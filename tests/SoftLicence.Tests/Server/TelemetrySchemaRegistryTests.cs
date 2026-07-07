using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetrySchemaRegistryTests
{
    [Theory]
    [InlineData("Startup_AppStarted", "startup")]
    [InlineData("Update_Check", "update")]
    [InlineData("Update_Available", "update")]
    [InlineData("Mcp_ToolCall", "mcp")]
    [InlineData("Copilot_ToolCall", "copilot")]
    [InlineData("CertPinningFailed", "cert-pinning")]
    [InlineData("UnknownThing", "other")]
    public void ClassifyFamily_ReturnsExpectedFamily(string eventName, string expected)
    {
        Assert.Equal(expected, TelemetrySchemaRegistry.ClassifyFamily(eventName));
    }

    [Theory]
    [InlineData("Update_Check", true)]
    [InlineData("Update_NotAvailable", true)]
    [InlineData("Startup_AppStarted", true)]
    [InlineData("Mcp_ToolCall", false)]
    [InlineData("Tag_Create", false)]
    public void IsSystemNoiseEvent_ReturnsExpectedResult(string eventName, bool expected)
    {
        Assert.Equal(expected, TelemetrySchemaRegistry.IsSystemNoiseEvent(eventName));
    }

    [Theory]
    [InlineData("Update_Check", false)]
    [InlineData("Startup_AppStarted", false)]
    [InlineData("UI_Navigate", false)]
    [InlineData("Wizard_McpToolSelected", false)]
    [InlineData("Mcp_ToolCall", true)]
    [InlineData("API_Call", true)]
    [InlineData("Compile_Success", true)]
    [InlineData("Block_Export", true)]
    [InlineData("Tag_Create", true)]
    [InlineData("Project_Save", true)]
    public void IsRealUserActivityEvent_ReturnsExpectedResult(string eventName, bool expected)
    {
        Assert.Equal(expected, TelemetrySchemaRegistry.IsRealUserActivityEvent(eventName));
    }

    [Fact]
    public void ParseProperties_RemovesSensitiveKeys()
    {
        var props = TelemetrySchemaRegistry.ParseProperties(
            """{"Tool":"compile_device","LicenseKey":"SECRET","Token":"abc","ApiSecret":"product-secret","Authorization":"Bearer abc","Cookie":"session=abc","OS":"Windows"}""");

        Assert.Equal("compile_device", props["Tool"]);
        Assert.Equal("Windows", props["OS"]);
        Assert.False(props.ContainsKey("LicenseKey"));
        Assert.False(props.ContainsKey("Token"));
        Assert.False(props.ContainsKey("ApiSecret"));
        Assert.False(props.ContainsKey("Authorization"));
        Assert.False(props.ContainsKey("Cookie"));
    }

    [Fact]
    public void ParseProperties_RemovesSensitiveKeysByFragment()
    {
        var props = TelemetrySchemaRegistry.ParseProperties(
            """{"RefreshToken":"abc","ProductSecretValue":"secret","BearerHeader":"abc","RegularField":"ok"}""");

        Assert.Equal("ok", props["RegularField"]);
        Assert.False(props.ContainsKey("RefreshToken"));
        Assert.False(props.ContainsKey("ProductSecretValue"));
        Assert.False(props.ContainsKey("BearerHeader"));
    }

    [Fact]
    public void ParseProperties_RedactsNestedSensitiveKeys()
    {
        var props = TelemetrySchemaRegistry.ParseProperties(
            """{"Context":{"User":"alice","Token":"abc","Nested":{"Password":"pwd","Status":"ok"}}}""");

        Assert.Contains("\"User\":\"alice\"", props["Context"]);
        Assert.Contains("\"Status\":\"ok\"", props["Context"]);
        Assert.DoesNotContain("Token", props["Context"]);
        Assert.DoesNotContain("Password", props["Context"]);
        Assert.DoesNotContain("abc", props["Context"]);
        Assert.DoesNotContain("pwd", props["Context"]);
    }

    [Fact]
    public void ParseKeys_RemovesSensitiveKeysButKeepsUnknownTelemetryKeys()
    {
        var keys = TelemetrySchemaRegistry.ParseKeys(
            """{"CFP_SystemUuid":"uuid","LicensePrompt_CopyMachineIdClicked":"true","LicenseKey":"SECRET","RefreshToken":"abc"}""");

        Assert.Contains("CFP_SystemUuid", keys);
        Assert.Contains("LicensePrompt_CopyMachineIdClicked", keys);
        Assert.DoesNotContain("LicenseKey", keys);
        Assert.DoesNotContain("RefreshToken", keys);
    }
}
