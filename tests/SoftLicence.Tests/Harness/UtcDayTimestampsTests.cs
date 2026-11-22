using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Harness;

/// <summary>
/// TKT-004196: proves, at simulated clock times including 00:30 UTC, that timestamps built by
/// <see cref="UtcDayTimestamps.Today"/> are counted by the real daily quota, which the former
/// <c>DateTime.UtcNow.AddHours(-2)</c> seeding was not between 00:00 and 02:00 UTC.
/// </summary>
public sealed class UtcDayTimestampsTests
{
    /// <summary>
    /// Two identifiers seeded "earlier today" with the helper exhaust a quota of two at any time of the UTC day,
    /// including 00:30 UTC (the hour of runs #775 and #776) and the first millisecond after midnight.
    /// <see cref="SeatChangeQuota.GetStatusAsync"/> receives the simulated instant, so the decision is the product's.
    /// </summary>
    /// <param name="simulatedNow">Simulated UTC clock, ISO 8601.</param>
    [Theory]
    [InlineData("2026-11-22T00:30:00.0000000Z")]
    [InlineData("2026-11-22T00:00:00.0010000Z")]
    [InlineData("2026-11-22T12:00:00.0000000Z")]
    [InlineData("2026-11-22T23:59:59.9990000Z")]
    public async Task SeededActivations_AreCountedByTheDailyQuota_AtAnyTimeOfTheUtcDay(string simulatedNow)
    {
        var now = DateTime.Parse(simulatedNow, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase("tkt-004196-" + Guid.NewGuid().ToString("N")).Options;
        await using var db = new LicenseDbContext(options);
        var type = new LicenseType { ProductId = Guid.NewGuid(), Name = "TKT-004196", Slug = "TKT4196", MaxActivationsPerDay = 1 };
        var license = new License
        {
            ProductId = type.ProductId, LicenseTypeId = type.Id, Type = type, LicenseKey = "TKT4196-" + Guid.NewGuid().ToString("N"),
            IsActive = true, MaxSeats = 2, ExpirationDate = now.AddDays(1)
        };
        // Same shape as the fixed tests: two identifiers activated then released earlier today, in this order.
        var first = UtcDayTimestamps.Today(now, 0.25);
        var second = UtcDayTimestamps.Today(now, 0.5);
        license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT4196-TODAY-ONE", IsActive = false, FirstActivatedAt = first, LastActivatedAt = first, UnlinkedAt = second });
        license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT4196-TODAY-TWO", IsActive = false, FirstActivatedAt = second, LastActivatedAt = second, UnlinkedAt = UtcDayTimestamps.Today(now, 0.75) });
        db.AddRange(type, license);
        await db.SaveChangesAsync();

        var status = await SeatChangeQuota.GetStatusAsync(db, license, now);

        Assert.Equal(2, status.UsedToday);
        Assert.True(status.IsExhausted);
    }

    /// <summary>
    /// The helper stays inside [UTC midnight, now], keeps the UTC kind and preserves the order of fractions,
    /// including at midnight exactly, where every fraction gives midnight.
    /// </summary>
    /// <param name="simulatedNow">Simulated UTC clock, ISO 8601.</param>
    [Theory]
    [InlineData("2026-11-22T00:30:00.0000000Z")]
    [InlineData("2026-11-22T00:00:00.0000000Z")]
    [InlineData("2026-11-22T23:59:59.9999999Z")]
    public void Today_StaysInsideTheElapsedUtcDay_AndKeepsOrder(string simulatedNow)
    {
        var now = DateTime.Parse(simulatedNow, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);

        var instants = new[] { 0.0, 1.0 / 3, 2.0 / 3, 1.0 }.Select(fraction => UtcDayTimestamps.Today(now, fraction)).ToArray();

        Assert.All(instants, instant =>
        {
            Assert.Equal(DateTimeKind.Utc, instant.Kind);
            Assert.InRange(instant, now.Date, now);
        });
        Assert.Equal(instants.OrderBy(instant => instant), instants);
        Assert.Equal(now.Date, instants[0]);
        Assert.Equal(now, instants[^1]);
    }

    /// <summary>A non-UTC reference or a fraction outside [0, 1] is refused instead of silently shifting the day.</summary>
    [Fact]
    public void Today_RefusesNonUtcReferenceAndOutOfRangeFraction()
    {
        var utc = new DateTime(2026, 11, 22, 0, 30, 0, DateTimeKind.Utc);

        Assert.Throws<ArgumentException>(() => UtcDayTimestamps.Today(DateTime.SpecifyKind(utc, DateTimeKind.Local), 0.5));
        Assert.Throws<ArgumentException>(() => UtcDayTimestamps.Today(DateTime.SpecifyKind(utc, DateTimeKind.Unspecified), 0.5));
        Assert.Throws<ArgumentOutOfRangeException>(() => UtcDayTimestamps.Today(utc, -0.1));
        Assert.Throws<ArgumentOutOfRangeException>(() => UtcDayTimestamps.Today(utc, 1.1));
        Assert.Throws<ArgumentOutOfRangeException>(() => UtcDayTimestamps.Today(utc, double.NaN));
    }
}
