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
