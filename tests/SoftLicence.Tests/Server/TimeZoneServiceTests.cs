using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public class TimeZoneServiceTests
{
    [Fact]
    public void ToLocal_ShouldReturnUtc_WhenOffsetNotSet()
    {
        // Arrange
        var service = new TimeZoneService();
        var utcNow = DateTime.UtcNow;

        // Act
        var result = service.ToLocal(utcNow);

        // Assert
        Assert.Equal(utcNow, result);
    }

    [Fact]
    public void ToLocal_ShouldAdjustTime_ForPositiveOffset()
    {
        // Arrange
        var service = new TimeZoneService();
        service.SetOffset(300); // UTC-5 (New York)
        var utcTime = new DateTime(2026, 2, 12, 12, 0, 0, DateTimeKind.Utc);

        // Act
        var result = service.ToLocal(utcTime);

        // Assert
        // Browser offset 300 means UTC - Local = 300, so Local = UTC - 300 min
        Assert.Equal(7, result.Hour); // 12:00 - 5h = 07:00
    }

    [Fact]
    public void ToLocal_ShouldAdjustTime_ForNegativeOffset()
    {
        // Arrange
        var service = new TimeZoneService();
        service.SetOffset(-60); // UTC+1 (Paris)
        var utcTime = new DateTime(2026, 2, 12, 12, 0, 0, DateTimeKind.Utc);

        // Act
        var result = service.ToLocal(utcTime);

        // Assert
        // Browser offset -60 means UTC - Local = -60, so Local = UTC + 60 min
        Assert.Equal(13, result.Hour); // 12:00 + 1h = 13:00
    }
}
