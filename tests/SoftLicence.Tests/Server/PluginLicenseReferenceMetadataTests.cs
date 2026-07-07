using System.Reflection;
using SoftLicence.SDK;
using SoftLicence.Server.Controllers;
using Xunit;

namespace SoftLicence.Tests.Server;

public class PluginLicenseReferenceMetadataTests
{
    [Fact]
    public void BuildLicenseReference_WithRuntimePluginIdAndBusinessReference_KeepsPluginPrefix()
    {
        var request = new AdminController.CreateLicenseRequest
        {
            ProductName = "YOUR_APP_NAME",
            CustomerName = "Test Customer",
            TypeSlug = "YOUR_APP_NAME.PLUGIN.DND",
            Reference = "INV-001",
            RuntimePluginId = "com.YOUR_APP_NAME.dnd",
            PluginVersion = "1.0.2.0",
            MinAppVersion = "1.1.70",
            AllowedFeatures = new[] { "*" }
        };

        var reference = InvokeBuildLicenseReference(request);

        Assert.Equal(
            "plugin:com.YOUR_APP_NAME.dnd:reference=INV-001:pluginVersion=1.0.2.0:minAppVersion=1.1.70:allowedFeatures=*",
            reference);
    }

    [Fact]
    public void ApplyPluginMetadataFromReference_ReadsPluginVersionFromReferenceMetadata()
    {
        var model = new LicenseModel
        {
            Reference = "plugin:com.YOUR_APP_NAME.dnd:reference=INV-001:pluginVersion=1.0.2.0:minAppVersion=1.1.70:allowedFeatures=*",
            Features = new Dictionary<string, string>()
        };

        InvokeApplyPluginMetadataFromReference(model);

        Assert.Equal("com.YOUR_APP_NAME.dnd", model.PluginId);
        Assert.Equal("1.0.2.0", model.PluginVersion);
        Assert.Equal("1.1.70", model.MinAppVersion);
        Assert.Equal(new[] { "*" }, model.AllowedFeatures);
    }

    private static string? InvokeBuildLicenseReference(AdminController.CreateLicenseRequest request)
    {
        var method = typeof(AdminController).GetMethod(
            "BuildLicenseReference",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        return (string?)method.Invoke(null, new object[] { request });
    }

    private static void InvokeApplyPluginMetadataFromReference(LicenseModel model)
    {
        var method = typeof(ActivationController).GetMethod(
            "ApplyPluginMetadataFromReference",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        method.Invoke(null, new object[] { model });
    }
}
