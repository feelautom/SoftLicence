using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public class TimeZoneServiceTests
{
    [Fact]
    public void ToLocal_ShouldReturnParisTime_WhenOffsetNotSet()
    {
        // Arrange
        var service = new TimeZoneService();
        var utcTime = new DateTime(2026, 2, 12, 12, 0, 0, DateTimeKind.Utc);

        // Act
        var result = service.ToLocal(utcTime);

        // Assert
        Assert.Equal(13, result.Hour);
        Assert.Equal(DateTimeKind.Unspecified, result.Kind);
    }

    [Fact]
    public void ToLocal_ShouldIgnoreBrowserOffset_ForBackwardCompatibility()
    {
        // Arrange
        var service = new TimeZoneService();
        service.SetOffset(300); // Legacy browser offset, intentionally ignored.
        var utcTime = new DateTime(2026, 2, 12, 12, 0, 0, DateTimeKind.Utc);

        // Act
        var result = service.ToLocal(utcTime);

        // Assert
        Assert.Equal(13, result.Hour);
    }

    [Fact]
    public void ToLocal_ShouldApplyParisDst()
    {
        // Arrange
        var service = new TimeZoneService();
        var utcTime = new DateTime(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);

        // Act
        var result = service.ToLocal(utcTime);

        // Assert
        Assert.Equal(14, result.Hour);
    }
}
