using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Database-free checks of the TKT-003652 weekly activity helpers: usage and license-failure classification
/// (ordinal, case-insensitive event names) and ISO-week bucketing across an ISO year boundary.
/// </summary>
public sealed class PaidWeeklyActivityClassifierTests
{
    /// <summary>Checks the pure classification and ISO-week helpers, including an ISO year boundary.</summary>
    [Fact]
    public void Classifiers_AndIsoWeekHelpers_FollowTheDocumentedContract()
    {
        Assert.True(PaidWeeklyActivityAnalyticsService.IsUsageEvent("Security_SetPassword", TelemetryType.Event));
        Assert.True(PaidWeeklyActivityAnalyticsService.IsUsageEvent("mcp_toolcall", TelemetryType.Event));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsUsageEvent("Mcp_ToolResult", TelemetryType.Event));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsUsageEvent("Startup_AppStarted", TelemetryType.Event));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsUsageEvent("LicensePrompt_Shown", TelemetryType.Event));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsUsageEvent("Block_Export", TelemetryType.Error));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsUsageEvent("  ", TelemetryType.Event));

        Assert.True(PaidWeeklyActivityAnalyticsService.IsLicenseFailure("LicenseCache_HardwareMismatch"));
        Assert.True(PaidWeeklyActivityAnalyticsService.IsLicenseFailure("LicenseActivation_InvalidKey"));
        Assert.True(PaidWeeklyActivityAnalyticsService.IsLicenseFailure("Startup_NoLicenseDetected"));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsLicenseFailure("LicenseActivation_Success"));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsLicenseFailure("LicensePrompt_Shown"));
        Assert.False(PaidWeeklyActivityAnalyticsService.IsLicenseFailure("Compile_Failed"));

        var sunday = new DateTime(2027, 1, 3, 23, 59, 0, DateTimeKind.Utc);
        var monday = PaidWeeklyActivityAnalyticsService.StartOfIsoWeek(sunday);
        Assert.Equal(new DateTime(2026, 12, 28, 0, 0, 0, DateTimeKind.Utc), monday);
        Assert.Equal("2026-W53", PaidWeeklyActivityAnalyticsService.FormatIsoWeek(monday));
    }

}
