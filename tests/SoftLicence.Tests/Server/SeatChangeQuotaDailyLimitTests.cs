using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>TKT-002030: the shared daily limit multiplies the per-seat quota by the licence seat count.</summary>
public sealed class SeatChangeQuotaDailyLimitTests
{
    /// <summary>Covers single seat, multi-seat, unlimited, non-positive seat count and saturation cases.</summary>
    [Theory]
    [InlineData(3, 1, 3)]
    [InlineData(3, 5, 15)]
    [InlineData(3, 0, 3)]
    [InlineData(0, 5, 0)]
    [InlineData(-1, 5, 0)]
    [InlineData(int.MaxValue, 2, int.MaxValue)]
    public void GetDailyLimit_MultipliesPerSeatQuotaBySeats(int perSeat, int maxSeats, int expected)
    {
        var license = new License { MaxSeats = maxSeats, Type = new LicenseType { MaxActivationsPerDay = perSeat } };

        Assert.Equal(expected, SeatChangeQuota.GetDailyLimit(license));
    }

    /// <summary>A licence whose type is not loaded stays unlimited, matching the previous enforcement.</summary>
    [Fact]
    public void GetDailyLimit_WithoutType_IsUnlimited()
        => Assert.Equal(0, SeatChangeQuota.GetDailyLimit(new License { MaxSeats = 5 }));
}
