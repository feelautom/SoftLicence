using System.Reflection;
using ModelContextProtocol.Server;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SoftLicenceMcpToolCatalogTests
{
    [Fact]
    public void RuntimeDistributionDecisionRegistryTool_UsesUnversionedPublishedName()
    {
        var method = typeof(SoftLicenceAnalyticsTools).GetMethod(
            nameof(SoftLicenceAnalyticsTools.GetRuntimeDistributionHardwareDecisions));

        Assert.NotNull(method);
        Assert.NotNull(method.GetCustomAttribute<McpServerToolAttribute>());
        Assert.Equal("get_runtime_distribution_hardware_decisions", ToSnakeCase(method.Name));
        Assert.DoesNotContain("v1", method.Name, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("v2", method.Name, StringComparison.OrdinalIgnoreCase);
    }

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

    /// <summary>Ensures the TKT-002685 threat-score tools keep their published MCP names.</summary>
    [Fact]
    public void ThreatScoreTools_UseExpectedPublishedNames()
    {
        var toolMethods = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "list_ip_threat_scores");
        Assert.Contains(toolMethods, method => ToSnakeCase(method.Name) == "reset_ip_threat_score");
    }

    /// <summary>Ensures the five TKT-001838 lot-one tools keep their published MCP names.</summary>
    [Fact]
    public void SecurityLockAdministrationTools_UseExpectedPublishedNames()
    {
        var publishedNames = typeof(SoftLicenceAnalyticsTools)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .Select(method => ToSnakeCase(method.Name))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains("list_security_locks", publishedNames);
        Assert.Contains("get_security_lock", publishedNames);
        Assert.Contains("decide_security_lock", publishedNames);
        Assert.Contains("unban_security_lock", publishedNames);
        Assert.Contains("list_security_lock_release_decisions", publishedNames);
        Assert.Contains("revoke_security_lock_release_decision", publishedNames);
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
