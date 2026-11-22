using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002030 and TKT-003751 on PostgreSQL: <see cref="LicenseType.MaxActivationsPerDay"/> applies per seat, so a
/// licence of S seats may be activated on at most N = MaxActivationsPerDay x S different hardware identifiers per UTC
/// day, N being read from the type on every request. Releases are never counted. A single-seat licence keeps exactly
/// the configured value, and simultaneous machines stay capped by <see cref="License.MaxSeats"/>.
/// </summary>
public sealed partial class HardwareIdSwitchPostgreSqlTests
{
    /// <summary>
    /// TKT-003751: a single-seat licence switching to a new identifier is accepted while fewer than N =
    /// <see cref="LicenseType.MaxActivationsPerDay"/> identifiers were activated today, and refused with 400
    /// <c>MAX_DAILY_ACTIVATIONS_REACHED</c> once N were, the previous seat then staying attached. The previous
    /// identifier is seeded active today, so it counts as one of them besides <paramref name="identifiersActivatedToday"/>.
    /// </summary>
    [Theory]
    [InlineData(1, 0, false)]
    [InlineData(2, 0, true)]
    [InlineData(2, 1, false)]
    [InlineData(3, 1, true)]
    [InlineData(3, 2, false)]
    public async Task SeatQuota_SingleSeat_RefusesSwitchBeyondConfiguredDistinctIdentifiersPerDay(int maxPerDay, int identifiersActivatedToday, bool accepted)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10),
            otherIdentifiersActivatedToday: identifiersActivatedToday);

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId));

        if (accepted)
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("MAX_DAILY_ACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        }
        var seats = await SeatsAsync(provision.ConnectionString);
        Assert.Equal(!accepted, seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
        Assert.Equal(accepted, seats.Any(seat => seat.HardwareId == NewHardwareId && seat.IsActive));
        await using var db = CreateDb(provision.ConnectionString);
        var license = await db.Licenses.Include(row => row.Type).SingleAsync();
        var status = await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow);
        Assert.Equal(maxPerDay, status.Limit);
        // Seeded identifiers, plus the previous one, plus the new one only when it was activated.
        Assert.Equal(identifiersActivatedToday + 1 + (accepted ? 1 : 0), status.UsedToday);
    }

    /// <summary>A five-seat licence installs its five machines on the first day; a sixth machine is refused by seat capacity only.</summary>
    [Fact]
    public async Task SeatQuota_FiveSeats_InstallsAllMachinesOnFirstDay()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedMultiSeatAsync(provision.ConnectionString, host, maxSeats: 5, seatsActivatedToday: 0);
        var client = host.CreateClient();

        for (var machine = 1; machine <= 5; machine++)
        {
            using var accepted = await client.PostAsJsonAsync("/api/activation", MachineRequest(licenseKey, machine));
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        }
        using var sixth = await client.PostAsJsonAsync("/api/activation", MachineRequest(licenseKey, 6));

        Assert.Equal("SEAT_LIMIT", sixth.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        await using var db = CreateDb(provision.ConnectionString);
        Assert.Equal(5, await db.LicenseSeats.CountAsync(seat => seat.IsActive));
        var license = await db.Licenses.Include(row => row.Type).SingleAsync();
        Assert.Equal(15, (await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow)).Limit);
    }

    /// <summary>
    /// TKT-003751: a five-seat licence accepts a first activation on a new identifier while fewer than N =
    /// <see cref="LicenseType.MaxActivationsPerDay"/> x 5 different identifiers were activated today, and refuses it
    /// with 400 <c>MAX_DAILY_ACTIVATIONS_REACHED</c>, creating no seat, once N were.
    /// </summary>
    [Theory]
    [InlineData(3, 14, true)]
    [InlineData(3, 15, false)]
    [InlineData(1, 4, true)]
    [InlineData(1, 5, false)]
    public async Task SeatQuota_FiveSeats_RefusesNewIdentifierBeyondTypeLimitTimesSeats(int maxPerDay, int seatsActivatedToday, bool accepted)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedMultiSeatAsync(provision.ConnectionString, host, maxSeats: 5, seatsActivatedToday, maxPerDay);

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", MachineRequest(licenseKey, 1));

        if (accepted)
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("MAX_DAILY_ACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        }
        await using var db = CreateDb(provision.ConnectionString);
        Assert.Equal(accepted ? 1 : 0, await db.LicenseSeats.CountAsync(seat => seat.IsActive));
        var license = await db.Licenses.Include(row => row.Type).SingleAsync();
        var status = await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow);
        Assert.Equal(maxPerDay * 5, status.Limit);
        Assert.Equal(seatsActivatedToday + (accepted ? 1 : 0), status.UsedToday);
    }

    /// <summary>
    /// TKT-003751: a five-seat licence switching its seat to a new identifier with <c>PreviousHardwareId</c> is
    /// accepted while fewer than N = <see cref="LicenseType.MaxActivationsPerDay"/> x 5 different identifiers were
    /// activated today, and refused with 400 <c>MAX_DAILY_ACTIVATIONS_REACHED</c> once N were, the previous seat then
    /// staying active. The previous identifier is seeded active today and counts besides
    /// <paramref name="identifiersActivatedToday"/>.
    /// </summary>
    [Theory]
    [InlineData(3, 13, true)]
    [InlineData(3, 14, false)]
    [InlineData(1, 3, true)]
    [InlineData(1, 4, false)]
    public async Task SeatQuota_FiveSeats_RefusesIdentifierSwitchBeyondTypeLimitTimesSeats(int maxPerDay, int identifiersActivatedToday, bool accepted)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10),
            otherIdentifiersActivatedToday: identifiersActivatedToday);
        await using (var setup = CreateDb(provision.ConnectionString))
        {
            (await setup.Licenses.SingleAsync()).MaxSeats = 5;
            await setup.SaveChangesAsync();
        }

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId));

        if (accepted)
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("MAX_DAILY_ACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        }
        var seats = await SeatsAsync(provision.ConnectionString);
        Assert.Equal(!accepted, seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
        Assert.Equal(accepted, seats.Any(seat => seat.HardwareId == NewHardwareId && seat.IsActive));
        await using var db = CreateDb(provision.ConnectionString);
        var license = await db.Licenses.Include(row => row.Type).SingleAsync();
        Assert.Equal(maxPerDay * 5, (await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow)).Limit);
    }

    /// <summary>
    /// Seeds a licence of <paramref name="maxSeats"/> seats at <paramref name="maxPerDay"/> activations per seat and
    /// day, without any active machine, plus <paramref name="seatsActivatedToday"/> released seats on distinct
    /// identifiers activated today, which the TKT-003751 quota counts through <see cref="LicenseSeat.LastActivatedAt"/>.
    /// </summary>
    /// <param name="connectionString">Database of the test host, used to reshape the seeded licence.</param>
    /// <param name="host">Test host used by <see cref="SeedAsync"/>.</param>
    /// <param name="maxSeats">Seat count of the licence.</param>
    /// <param name="seatsActivatedToday">Distinct identifiers already activated today; zero leaves the quota empty.</param>
    /// <param name="maxPerDay">Value of <see cref="LicenseType.MaxActivationsPerDay"/>; three by default.</param>
    /// <returns>The licence key to activate.</returns>
    private static async Task<string> SeedMultiSeatAsync(string connectionString, Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> host, int maxSeats, int seatsActivatedToday, int maxPerDay = 3)
    {
        var licenseKey = await SeedAsync(host, maxPerDay, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10));
        await using var db = CreateDb(connectionString);
        var license = await db.Licenses.SingleAsync();
        license.MaxSeats = maxSeats;
        license.HardwareId = null;
        db.LicenseSeats.Remove(await db.LicenseSeats.SingleAsync());
        AddSeatsActivatedToday(db, license.Id, seatsActivatedToday);
        await db.SaveChangesAsync();
        return licenseKey;
    }

    /// <summary>Builds a first activation of one distinct synthetic machine identified by its SMBIOS UUID.</summary>
    private static object MachineRequest(string licenseKey, int machine)
    {
        var uuid = $"4C4C4544-0051-3610-8052-{machine:D12}";
        return new { LicenseKey = licenseKey, HardwareId = MachineIdentity.FromUuid(uuid).HardwareId, AppName, SystemUuid = uuid };
    }
}
