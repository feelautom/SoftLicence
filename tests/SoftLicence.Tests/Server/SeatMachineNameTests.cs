using System.Text.Json;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003404: unit matrix of the PC display-name cleaning and extraction rules of <see cref="SeatMachineName"/>.
/// No database is involved: the relational behaviour (persisted, refreshed, never erased, exposed) is proved by
/// <see cref="SeatMachineNamePostgreSqlTests"/>.
/// </summary>
public sealed class SeatMachineNameTests
{
    /// <summary>Accepted names keep their casing and lose only edge whitespace and invisible characters.</summary>
    [Theory]
    [InlineData("PC-ATELIER", "PC-ATELIER")]
    [InlineData("  Bureau-Alice \t", "Bureau-Alice")]
    [InlineData("pc-atelier", "pc-atelier")]
    [InlineData("PC\u200B-ZW", "PC-ZW")]
    [InlineData("PC\u202E-RTL", "PC-RTL")]
    [InlineData("PC\r\n-LINE", "PC-LINE")]
    [InlineData("PC\u0000-NUL", "PC-NUL")]
    [InlineData("PC\u2028-SEP", "PC-SEP")]
    [InlineData("PC\uE000-PUA", "PC-PUA")]
    [InlineData("PC\uFFFD-REP", "PC-REP")]
    [InlineData("POSTE-I\u0130", "POSTE-I\u0130")]
    public void Clean_KeepsDisplayableTextOnly(string raw, string expected)
        => Assert.Equal(expected, SeatMachineName.Clean(raw));

    /// <summary>Nothing displayable left means absent, so the caller never erases a stored name with it.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\u200B\u0007\r\n")]
    public void Clean_ReturnsNullWhenNothingRemains(string? raw) => Assert.Null(SeatMachineName.Clean(raw));

    /// <summary>
    /// An unpaired surrogate is dropped. Kept out of the theory data because xUnit serialises theory arguments
    /// for discovery and ill-formed UTF-16 would make that serialisation unreliable.
    /// </summary>
    [Fact]
    public void Clean_DropsUnpairedSurrogate()
        => Assert.Equal("PC-LONE", SeatMachineName.Clean("PC" + (char)0xD800 + "-LONE"));

    /// <summary>A decomposed name is stored in NFC so an identical name never causes a write.</summary>
    [Fact]
    public void Clean_ComposesUnicode()
        => Assert.Equal("POSTE-\u00C9", SeatMachineName.Clean("POSTE-E\u0301"));

    /// <summary>The 64-unit bound applies to the stored form and never keeps half of a surrogate pair.</summary>
    [Fact]
    public void Clean_BoundsLengthWithoutSplittingSurrogatePair()
    {
        Assert.Equal(new string('A', SeatMachineName.MaxLength), SeatMachineName.Clean(new string('A', 200)));

        var cut = SeatMachineName.Clean(new string('A', SeatMachineName.MaxLength - 1) + "\U0001F600" + "TAIL");
        Assert.Equal(new string('A', SeatMachineName.MaxLength - 1), cut);
    }

    /// <summary>The SDK PascalCase property and a camelCase variant are both read; other shapes are ignored.</summary>
    [Theory]
    [InlineData("""{"MachineName":"PC-ONE"}""", "PC-ONE")]
    [InlineData("""{"machineName":"PC-TWO","SystemModel":{"Status":"Present"}}""", "PC-TWO")]
    [InlineData("""{"MachineName":42}""", null)]
    [InlineData("""{"MachineName":null}""", null)]
    [InlineData("""{"MachineName":"PC-A","machineName":"PC-B"}""", null)]
    [InlineData("""{"SystemModel":{"Status":"Present"}}""", null)]
    [InlineData("""["PC-ARRAY"]""", null)]
    [InlineData("""  "PC-STRING" """, null)]
    public void Read_ExtractsOnlyAnUnambiguousStringProperty(string json, string? expected)
        => Assert.Equal(expected, SeatMachineName.Read(JsonSerializer.Deserialize<JsonElement>(json)));

    /// <summary>A request without evidence reads as absent.</summary>
    [Fact]
    public void Read_NullEvidenceIsAbsent() => Assert.Null(SeatMachineName.Read(null));

    /// <summary>Apply writes only a usable, different value and reports whether the seat changed.</summary>
    [Fact]
    public void Apply_UpdatesOnChangeAndNeverErases()
    {
        var seat = new LicenseSeat { MachineName = "PC-OLD" };

        Assert.False(SeatMachineName.Apply(seat, null));
        Assert.False(SeatMachineName.Apply(seat, Evidence("   ")));
        Assert.Equal("PC-OLD", seat.MachineName);

        Assert.False(SeatMachineName.Apply(seat, Evidence(" PC-OLD ")));
        Assert.True(SeatMachineName.Apply(seat, Evidence("pc-old")));
        Assert.Equal("pc-old", seat.MachineName);
    }

    /// <summary>Builds an evidence object carrying only a machine name.</summary>
    private static JsonElement Evidence(string name)
        => JsonSerializer.SerializeToElement(new { MachineName = name });
}
