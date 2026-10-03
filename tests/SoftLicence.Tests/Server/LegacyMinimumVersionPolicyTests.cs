using System.Globalization;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Adversarial version syntax and culture tests for the scoped legacy compatibility boundary.</summary>
public sealed class LegacyMinimumVersionPolicyTests
{
    /// <summary>Uses numeric ordering and rejects ambiguous declarations without culture-dependent coercion.</summary>
    [Theory]
    [InlineData(null, "APP_VERSION_REQUIRED")]
    [InlineData("", "APP_VERSION_REQUIRED")]
    [InlineData(" \t", "APP_VERSION_REQUIRED")]
    [InlineData("2.1.357", "APP_VERSION_BELOW_MINIMUM")]
    [InlineData("2.4.30", "APP_VERSION_BELOW_MINIMUM")]
    [InlineData("2.4.300", null)]
    [InlineData(" 2.4.300 ", null)]
    [InlineData("2.4.300.0", null)]
    [InlineData("2.10", null)]
    [InlineData("02.04.0300", null)]
    [InlineData("999", "APP_VERSION_INVALID")]
    [InlineData("2.4.300-preview", "APP_VERSION_INVALID")]
    [InlineData("2.4.300+meta", "APP_VERSION_INVALID")]
    [InlineData("2.4.300.0.0", "APP_VERSION_INVALID")]
    [InlineData("2.+4.300", "APP_VERSION_INVALID")]
    [InlineData("2. 4.300", "APP_VERSION_INVALID")]
    [InlineData("2.٤.300", "APP_VERSION_INVALID")]
    [InlineData("2.4.2147483648", "APP_VERSION_INVALID")]
    public void VersionSyntaxAndOrdering(string? version, string? expected)
    {
        var before = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            Assert.Equal(expected, LegacyMinimumVersionPolicy.Evaluate("tiaconnect", version, "2.4.300"));
        }
        finally { CultureInfo.CurrentCulture = before; }
    }

    /// <summary>Limits the new policy to the resolved product and fails closed on a malformed server threshold.</summary>
    [Theory]
    [InlineData("YOUR_APP_NAME", "2.4.300", null)]
    [InlineData("TIAConnectPlugin", "2.4.300", null)]
    [InlineData("TIAConnect", null, null)]
    [InlineData("TIAConnect", " ", null)]
    [InlineData("TIAConnect", "oops", "MINIMUM_VERSION_CONFIGURATION_INVALID")]
    public void ProductAndConfigurationScope(string product, string? minimum, string? expected) =>
        Assert.Equal(expected, LegacyMinimumVersionPolicy.Evaluate(product, null, minimum));
}
