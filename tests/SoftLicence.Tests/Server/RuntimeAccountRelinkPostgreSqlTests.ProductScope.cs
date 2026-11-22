using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003751: replays on PostgreSQL 17 the licence sequence of 13/11/2026 (one machine, two licences of the same
/// product) and proves the owner rule: « Une même clé de licence ne peut pas être activée sur plus de N
/// identifiants matériels différents dans la même journée. Tout le reste est libre. » N is read from
/// <c>LicenseTypes.MaxActivationsPerDay</c> (several values, 1 included); a quota refusal never blocks the licence,
/// and a machine never keeps two active seats of the same product.
/// </summary>
public sealed partial class RuntimeAccountRelinkPostgreSqlTests
{
    /// <summary>
    /// 13:38:42 UTC: the installation licence was signed out, then a second licence of the same product was activated
    /// by key on the same machine. The account relink takes the installation licence back: the other licence's seat
    /// on that machine is released with the product-scope history (never two active seats), its seat row and
    /// hardware identifier are kept, and neither licence's daily count changes because of that release.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_OtherLicenseActiveOnSameMachine_ReleasesIt_WithoutQuota")]
    public async Task AccountRelink_OtherLicenseActiveOnSameMachine_ReleasesIt_WithoutQuota()
    {
        using var scenario = await ActivatedScenarioAsync();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, installationLicenseId, 1);
        await ReleaseAsync(scenario, "client");
        var (otherLicenseId, otherSeatId) = await AddLicenseWithSeatAsync(
            scenario, Guid.NewGuid(), LegacyHardwareId, seatActive: true);
        await SetActivationsPerDayAsync(scenario, otherLicenseId, 1);
        var otherBefore = await SeatChangeQuotaAsync(scenario, otherLicenseId);

        await RelinkAsync(scenario, await BuildAsync(scenario, installationLicenseId, owner: null));

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var activeOnMachine = await db.LicenseSeats.AsNoTracking()
            .Where(row => row.HardwareId == LegacyHardwareId && row.IsActive
                && row.License!.ProductId == scenario.Fixture.ProductId)
            .Select(row => row.LicenseId)
            .ToListAsync();
        Assert.Equal([installationLicenseId], activeOnMachine);
        var otherSeat = await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == otherSeatId);
        Assert.False(otherSeat.IsActive);
        Assert.Equal(LegacyHardwareId, otherSeat.HardwareId);
        Assert.NotNull(otherSeat.UnlinkedAt);
        Assert.Single(await db.LicenseHistories.AsNoTracking()
            .Where(row => row.LicenseId == otherLicenseId && row.Action == HistoryActions.AutoUnlinkedProductScope)
            .ToListAsync());
        Assert.Equal(otherBefore.UsedToday, (await SeatChangeQuotaAsync(scenario, otherLicenseId)).UsedToday);
        Assert.Equal(1, (await SeatChangeQuotaAsync(scenario, installationLicenseId)).UsedToday);
    }

    /// <summary>
    /// 13:35:22 UTC: another licence of the same product is activated by key on the machine that holds the
    /// installation licence. The product-scope cleanup frees the installation licence's seat; that release changes
    /// nothing in the installation licence's daily count, and the same machine may come back to it at once even
    /// with N = 1 already used.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.ProductScopeCleanup_SameMachineOtherLicense_ConsumesNothing_MachineStaysAllowed")]
    public async Task ProductScopeCleanup_SameMachineOtherLicense_ConsumesNothing_MachineStaysAllowed()
    {
        using var scenario = await ActivatedScenarioAsync();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, installationLicenseId, 1);
        var before = await SeatChangeQuotaAsync(scenario, installationLicenseId);
        var (winnerLicenseId, _) = await AddLicenseWithSeatAsync(
            scenario, Guid.NewGuid(), LegacyHardwareId, seatActive: true);

        await using (var cleanupDb = await scenario.Factory.CreateDbContextAsync())
        {
            var cleanup = new SeatCleanupService(cleanupDb, NullLogger<SeatCleanupService>.Instance);
            await using var transaction = await cleanup.BeginProductScopeCleanupAsync(
                scenario.Fixture.ProductId, LegacyHardwareId);
            Assert.Single(await cleanup.UnlinkHwidFromOtherProductLicensesAsync(
                LegacyHardwareId, winnerLicenseId, scenario.Fixture.ProductId));
            if (transaction != null)
                await transaction.CommitAsync();
        }

        Assert.Equal(before.UsedToday, (await SeatChangeQuotaAsync(scenario, installationLicenseId)).UsedToday);
        Assert.False(await IsActivationRefusedAsync(scenario, installationLicenseId, LegacyHardwareId));
    }

    /// <summary>
    /// Owner rule: with N = 1 already used by this machine, signing out and reconnecting on the same PC is never
    /// counted nor refused, as many times as wanted (here three full rounds of sign-out then account relink).
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.SignOutThenRelinkSameMachine_Repeated_AtLimitOne_NeverCountedNorRefused")]
    public async Task SignOutThenRelinkSameMachine_Repeated_AtLimitOne_NeverCountedNorRefused()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, licenseId, 1);
        Assert.True((await SeatChangeQuotaAsync(scenario, licenseId)).IsExhausted);

        for (var round = 0; round < 3; round++)
        {
            await ReleaseAsync(scenario, "client");
            await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner: null));
        }

        var quota = await SeatChangeQuotaAsync(scenario, licenseId);
        Assert.Equal(1, quota.UsedToday);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.True(await db.LicenseSeats.AsNoTracking()
            .AnyAsync(row => row.LicenseId == licenseId && row.HardwareId == LegacyHardwareId && row.IsActive));
    }

    /// <summary>
    /// Quota exhausted by other identifiers today: the installation machine, activated yesterday and no longer the
    /// last PC of the key, is refused with 422 <c>activation_rate_limited</c> and nothing is written; with room left
    /// it is accepted and counts once. N comes from the type: 1, 2 and 3 with as many other identifiers today.
    /// </summary>
    /// <param name="perDay">Value of <c>LicenseTypes.MaxActivationsPerDay</c> (single-seat licence, so N = perDay).</param>
    /// <param name="otherIdentifiersToday">Other identifiers the key was activated on today.</param>
    /// <param name="accepted">Whether the relink of the installation machine must succeed.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_NewIdentifierOfTheDay_CountedAgainstTypeLimit")]
    [InlineData(1, 1, false)]
    [InlineData(1, 0, true)]
    [InlineData(2, 1, true)]
    [InlineData(2, 2, false)]
    [InlineData(3, 3, false)]
    public async Task AccountRelink_NewIdentifierOfTheDay_CountedAgainstTypeLimit(
        int perDay, int otherIdentifiersToday, bool accepted)
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, licenseId, perDay);
        await ReleaseAsync(scenario, "client");
        await using (var admin = AdminContext(scenario))
        {
            // The installation machine was activated yesterday; the key then went to other PCs today.
            await admin.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"LicenseSeats\" SET \"LastActivatedAt\" = {DateTime.UtcNow.AddDays(-1)} WHERE \"LicenseId\" = {licenseId}");
            for (var index = 0; index < otherIdentifiersToday; index++)
                admin.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = licenseId, HardwareId = $"C0FFEE00C0FFEE{index:D2}", IsActive = false,
                    FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow,
                    LastActivatedAt = DateTime.UtcNow, UnlinkedAt = DateTime.UtcNow
                });
            await admin.SaveChangesAsync();
        }
        Assert.Equal(otherIdentifiersToday, (await SeatChangeQuotaAsync(scenario, licenseId)).UsedToday);
        var request = await BuildAsync(scenario, licenseId, owner: null);

        if (!accepted)
        {
            await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status422UnprocessableEntity,
                "activation_rate_limited");
            return;
        }
        await RelinkAsync(scenario, request);
        Assert.Equal(otherIdentifiersToday + 1, (await SeatChangeQuotaAsync(scenario, licenseId)).UsedToday);
    }

    /// <summary>
    /// The last PC where the key was successfully activated stays usable even when today's quota is exhausted: after
    /// a sign-out the same machine is accepted again and nothing more is counted, while a different identifier is
    /// refused. Proves the decision helper the admission paths share, with N = 2 read from the type.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.QuotaExhausted_LastPcStillAccepted_OtherIdentifierRefused")]
    public async Task QuotaExhausted_LastPcStillAccepted_OtherIdentifierRefused()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, licenseId, 2);
        // TKT-004196: the quota counts from UTC midnight, so "earlier today" is anchored in the current UTC day;
        // DateTime.UtcNow.AddHours(-2) fell on the previous day between 00:00 and 02:00 UTC (runs #775 and #776).
        var now = DateTime.UtcNow;
        var activatedAt = SoftLicence.Tests.Harness.UtcDayTimestamps.Today(now, 1.0 / 3);
        var unlinkedAt = SoftLicence.Tests.Harness.UtcDayTimestamps.Today(now, 2.0 / 3);
        await using (var admin = AdminContext(scenario))
        {
            admin.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId, HardwareId = OtherCanonicalHardwareId, IsActive = false,
                FirstActivatedAt = activatedAt, LastCheckInAt = activatedAt,
                LastActivatedAt = activatedAt, UnlinkedAt = unlinkedAt
            });
            await admin.SaveChangesAsync();
        }
        await ReleaseAsync(scenario, "client");
        Assert.True((await SeatChangeQuotaAsync(scenario, licenseId)).IsExhausted);

        Assert.False(await IsActivationRefusedAsync(scenario, licenseId, LegacyHardwareId));
        Assert.True(await IsActivationRefusedAsync(scenario, licenseId, "C0FFEE00C0FFEE99"));
        await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner: null));
        Assert.Equal(2, (await SeatChangeQuotaAsync(scenario, licenseId)).UsedToday);
    }

    /// <summary>Calls the shared admission decision of <see cref="SeatChangeQuota"/> for one licence and identifier, now.</summary>
    /// <param name="scenario">Prepared PostgreSQL scenario.</param>
    /// <param name="licenseId">Licence whose type gives N.</param>
    /// <param name="hardwareId">Canonical identifier about to be activated.</param>
    /// <returns>True when the activation would be refused.</returns>
    private static async Task<bool> IsActivationRefusedAsync(
        PreparedBootstrapScenario scenario, Guid licenseId, string hardwareId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.AsNoTracking().Include(row => row.Type).SingleAsync(row => row.Id == licenseId);
        return await SeatChangeQuota.IsActivationRefusedAsync(db, license, hardwareId, DateTime.UtcNow);
    }
}
