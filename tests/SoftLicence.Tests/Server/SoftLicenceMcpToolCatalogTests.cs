using System.Reflection;
using ModelContextProtocol.Server;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SoftLicenceMcpToolCatalogTests
{
    [Fact]
    public void OnboardingMetricsTool_UsesShortPublishedName()
    {
        var toolMethods = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        var onboardingMethod = Assert.Single(toolMethods, method => method.Name == "GetLicenseOnboardingMetrics");

        Assert.Equal("get_license_onboarding_metrics", ToSnakeCase(onboardingMethod.Name));
        Assert.DoesNotContain(toolMethods, method => method.Name == "GetRecentLicenseOnboardingMetrics");
        Assert.DoesNotContain(toolMethods, method => ToSnakeCase(method.Name) == "get_recent_license_onboarding_metrics");
    }

    [Fact]
    public void UsageScoresTool_UsesShortPublishedName()
    {
        var toolMethods = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        var usageScoresMethod = Assert.Single(toolMethods, method => method.Name == "GetLicenseUsageScores");

        Assert.Equal("get_license_usage_scores", ToSnakeCase(usageScoresMethod.Name));
    }

    [Fact]
    public void HardwareBanWriteTools_UseExpectedPublishedNames()
    {
        var toolMethods = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "create_security_hardware_ban");
        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "unban_security_hardware_ban");
        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "get_security_hardware_ban_categories");
    }

    [Fact]
    public void CustomerLicenseTimelineTool_UsesExpectedPublishedName()
    {
        var toolMethods = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "get_customer_license_timeline");
    }

    [Fact]
    public void OversizedResultTools_ExposeInfoAndChunkReads()
    {
        var toolMethods = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "get_mcp_result_artifact_info");
        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "get_mcp_result_artifact_chunk");
    }

    [Fact]
    public void CustomerLicenseTimelineTool_DescribesAutomaticNinetyDaySegmentation()
    {
        var method = typeof(SoftLicenceAnalyticsTools).GetMethod(nameof(SoftLicenceAnalyticsTools.GetCustomerLicenseTimeline));
        Assert.NotNull(method);

        foreach (var parameterName in new[] { "fromUtc", "toUtc" })
        {
            var parameter = Assert.Single(method.GetParameters(), value => value.Name == parameterName);
            var description = parameter.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>();

            Assert.NotNull(description);
            Assert.Contains("90 days", description.Description, StringComparison.Ordinal);
            Assert.Contains("automatically split", description.Description, StringComparison.OrdinalIgnoreCase);
        }

        var daysParameter = Assert.Single(method.GetParameters(), value => value.Name == "days");
        var daysDescription = daysParameter.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>();
        Assert.NotNull(daysDescription);
        Assert.Contains("90", daysDescription.Description, StringComparison.Ordinal);
    }

    private static string ToSnakeCase(string value)
    {
        var chars = new List<char>(value.Length + 8);

        for (var index = 0; index < value.Length; index++)
        {
            var current = value[index];
            if (char.IsUpper(current))
            {
                if (index > 0)
                    chars.Add('_');

                chars.Add(char.ToLowerInvariant(current));
                continue;
            }

            chars.Add(current);
        }

        return new string(chars.ToArray());
    }
}
