using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Checks elapsed-time and exact-identity policy without clocks, provider access or persistence.</summary>
public sealed class PersonalDayPassPolicyTests
{
    /// <summary>Late delivery cannot turn a historical paid gap into free present-day time.</summary>
    [Fact]
    public void ReverseDeliveryKeepsChronologicalPeriodsAndExactDay()
    {
        var first = new DateTime(2026, 10, 24, 18, 0, 0, DateTimeKind.Utc);
        var a = new PersonalDayPassPolicy.Payment("A", first, 1);
        var b = new PersonalDayPassPolicy.Payment("B", first.AddDays(3), 5, PrioritySupport: true);
        Assert.Equal(PersonalDayPassPolicy.Allocate([a, b]), PersonalDayPassPolicy.Allocate([b, a]));
        var periods = PersonalDayPassPolicy.Allocate([b, a]);
        Assert.Equal(first.AddDays(4), periods[^1].ExpiresAtUtc);
        Assert.All(periods, p => Assert.Equal(86_400, (p.ExpiresAtUtc - p.StartsAtUtc).TotalSeconds));
        Assert.Equal(5, periods[^1].MaxSeats);
        Assert.True(periods[^1].PrioritySupport);
        Assert.False(periods[0].PrioritySupport);
        Assert.Equal(first.AddDays(2), PersonalDayPassPolicy.Allocate([a, b with { PaidAtUtc = first.AddHours(1) }])[^1].ExpiresAtUtc);
        Assert.Equal(first.AddDays(3), PersonalDayPassPolicy.Allocate([a], first.AddDays(2))[^1].ExpiresAtUtc);
    }

    /// <summary>Provider identities retain casing, combining marks and valid non-BMP pairs; malformed UTF-16 is refused.</summary>
    [Fact]
    public void ExactUnicodeAndFramedTuplesDoNotAlias()
    {
        Assert.True(PersonalDayPassPolicy.IsOpaqueIdentity("pi_é😀"));
        Assert.True(PersonalDayPassPolicy.IsOpaqueIdentity("pi_e\u0301"));
        Assert.False(PersonalDayPassPolicy.IsOpaqueIdentity("pi_\ud800"));
        Assert.False(PersonalDayPassPolicy.IsOpaqueIdentity("pi_\udc00"));
        Assert.False(PersonalDayPassPolicy.IsOpaqueIdentity(" pi_x"));
        Assert.False(PersonalDayPassPolicy.IsOpaqueIdentity("\ufeffpi_x"));
        Assert.True(PersonalDayPassPolicy.IsOpaqueIdentity("\u0085pi_x"));
        Assert.NotEqual(PersonalDayPassPolicy.Identity("a|b", "c", "test", "X"), PersonalDayPassPolicy.Identity("a", "b|c", "test", "X"));
        var now = new DateTime(2026, 9, 7, 0, 0, 0, DateTimeKind.Utc);
        Assert.Equal("A", PersonalDayPassPolicy.Allocate([new("a", now, 1), new("A", now, 1)])[0].Identity);
        Assert.Throws<ArgumentException>(() => PersonalDayPassPolicy.Allocate([new("a", now, 1), new("a", now, 1)]));
        Assert.Throws<ArgumentException>(() => PersonalDayPassPolicy.Allocate([new("a", now, 11)]));
    }
}
