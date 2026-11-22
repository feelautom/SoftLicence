using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003260 (target model of the Website subscriptions, rules R2, R9 and R10): one Pro key per customer, extended by
/// every cadence whatever its licence type. Covers the 06/11/2026 case (a configurator key with its own per-customer type
/// could never receive a day pass), the key designated by the Website on a first payment, the attachment of an unowned
/// key, and the refusals that must never mint a second key.
/// </summary>
public sealed partial class PersonalDayPassPostgreSqlTests
{
    /// <summary>Reads the stable error code of a refused payment.</summary>
    private static async Task<string?> ErrorCodeAsync(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString();

    /// <summary>
    /// A designated configurator key with no owner is attached to the paying subject and extended in place: same key,
    /// same licence type, one more day, no second key, even though its stored name and e-mail differ from the profile.
    /// </summary>
    [Fact]
    public async Task DesignatedUnownedConfiguratorKeyIsAttachedAndExtendedWithoutMinting()
    {
        await using var f = await Fixture.CreateAsync();
        var existing = await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), ownerSubject: null);
        var receipt = await f.ReadResponseAsync(f.Request() with { DesignatedLicenseId = existing.Id });
        Assert.Equal(existing.Id, receipt.LicenseId);
        Assert.Equal(existing.LicenseKey, receipt.LicenseKey);
        Assert.Equal(existing.LicenseTypeId, receipt.CurrentLicenseTypeId);
        Assert.Equal(existing.ExpirationDate!.Value.AddDays(1), receipt.CurrentExpirationUtc);
        await using var db = f.Db();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(existing.LicenseTypeId, license.LicenseTypeId);
        Assert.Equal("Configurator customer", license.CustomerName);
        var owner = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync();
        Assert.Equal((existing.Id, f.SubjectId, "ACTIVE"), (owner.LicenseId, owner.OwnerSubjectId, owner.State));
    }

    /// <summary>
    /// The same attachment with V2 commercial evidence, as the Website sends for a qualified commercial order: the
    /// attached ownership is visible to the evidence ownership check, so the key is attached, extended and its evidence
    /// recorded, with no second key (review of PR #498: the ownership was only tracked and the payment was refused).
    /// </summary>
    [Fact]
    public async Task DesignatedUnownedKeyWithCommercialEvidenceIsAttachedAndExtended()
    {
        await using var f = await Fixture.CreateAsync();
        var existing = await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), ownerSubject: null);
        var receipt = await f.ReadResponseAsync(Qualified(f.Request() with { DesignatedLicenseId = existing.Id }, "PAID", 3000));
        Assert.Equal(existing.Id, receipt.LicenseId);
        Assert.Equal(existing.ExpirationDate!.Value.AddDays(1), receipt.CurrentExpirationUtc);
        await using var db = f.Db();
        Assert.Equal(1, await db.Licenses.CountAsync());
        var owner = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync();
        Assert.Equal((existing.Id, f.SubjectId, "ACTIVE"), (owner.LicenseId, owner.OwnerSubjectId, owner.State));
        Assert.Equal(existing.Id, (await db.Set<CommercialOrderEvidence>().AsNoTracking().SingleAsync()).LicenseId);
    }

    /// <summary>An owned key of another licence type is extended without designation (the 06/11 refusal is gone).</summary>
    [Fact]
    public async Task OwnedKeyOfAnotherTypeIsExtendedInPlace()
    {
        await using var f = await Fixture.CreateAsync();
        var existing = await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), f.SubjectId);
        var receipt = await f.ReadResponseAsync(f.Request());
        Assert.Equal(existing.Id, receipt.LicenseId);
        Assert.Equal(existing.LicenseTypeId, receipt.CurrentLicenseTypeId);
        await using var db = f.Db();
        Assert.Equal(1, await db.Licenses.CountAsync());
    }

    /// <summary>A designated key owned by another subject, owned by a partner, or unknown is refused, and no key is minted.</summary>
    [Fact]
    public async Task DesignatedKeyRefusalsNeverMintAKey()
    {
        await using var f = await Fixture.CreateAsync();
        var foreign = await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), Guid.NewGuid());
        using (var response = await f.PostAsync(f.Request() with { DesignatedLicenseId = foreign.Id }))
        {
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal("personal_pass_designated_owner_conflict", await ErrorCodeAsync(response));
        }
        var partner = await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), ownerSubject: null, partnerCode: "RESELLER-1");
        using (var response = await f.PostAsync(f.Request() with { DesignatedLicenseId = partner.Id }))
            Assert.Equal("personal_pass_designated_partner_key", await ErrorCodeAsync(response));
        using (var response = await f.PostAsync(f.Request() with { DesignatedLicenseId = Guid.NewGuid() }))
            Assert.Equal("personal_pass_designated_key_missing", await ErrorCodeAsync(response));
        await using var db = f.Db();
        Assert.Equal(2, await db.Licenses.CountAsync());
        Assert.Equal(0, await db.PersonalDayPassPayments.CountAsync());
        Assert.Equal(0, await db.PersonalDayPasses.CountAsync());
        // The refused attachment of the partner key was rolled back: only the foreign subject's ownership remains.
        Assert.Equal(1, await db.RuntimeRecoveryCommercialOwnerships.CountAsync());
    }

    /// <summary>An owned key that differs from the designated one is refused: the two systems disagree, nothing changes.</summary>
    [Fact]
    public async Task DesignationDisagreeingWithTheOwnedKeyIsRefused()
    {
        await using var f = await Fixture.CreateAsync();
        await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), f.SubjectId);
        var other = await f.SeedForeignTypeLicenseAsync(Fixture.PaidAt.AddDays(10), ownerSubject: null);
        using var response = await f.PostAsync(f.Request() with { DesignatedLicenseId = other.Id });
        Assert.Equal("personal_pass_designated_key_conflict", await ErrorCodeAsync(response));
        await using var db = f.Db();
        Assert.Equal(0, await db.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>A request without designation serializes exactly as before, so historical operation digests are unchanged.</summary>
    [Fact]
    public void RequestWithoutDesignationKeepsItsHistoricalShape()
    {
        var request = new AdminController.PersonalDayPassRequest(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "stripe", "account", "test", "pi_1", DateTime.UtcNow, 1000, "eur", 1, null, "a@example.test", "A");
        Assert.DoesNotContain("DesignatedLicenseId", JsonSerializer.Serialize(request));
        Assert.Contains("DesignatedLicenseId", JsonSerializer.Serialize(request with { DesignatedLicenseId = Guid.NewGuid() }));
    }
}
