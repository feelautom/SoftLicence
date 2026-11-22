using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002331 : comportement des dates d'une clé du registre des périodes payées
/// (<c>Licenses.ExpirationDate</c> et <c>PersonalDayPasses.PaidThroughUtc</c>, voir docs/schema/licence-dates.md).
/// Écrits d'abord pour figer le comportement d'avant le correctif, puis inversés par le correctif : l'historique
/// de la pull request montre chaque changement de comportement.
/// </summary>
public sealed partial class PersonalDayPassPostgreSqlTests
{
    /// <summary>
    /// TKT-002331 : une modification admin de la date de fin (PUT licence, jours ajoutés) change la clé sans le
    /// registre. Avant le correctif, un nouveau poste levait alors une exception non gérée (erreur 500) et le
    /// paiement suivant était refusé (personal_pass_authority_conflict). Désormais les deux dates peuvent
    /// différer : le poste s'active et le paiement est accepté ; il recale la clé sur la nouvelle période payée,
    /// comme le site T-IA Connect l'attend aujourd'hui (contrat inchangé).
    /// </summary>
    [Fact]
    public async Task Tkt2331_AdminDateEditDivergesKeyFromLedgerWithoutBlockingActivationOrPayment()
    {
        await using var f = await Fixture.CreateAsync();
        var firstRequest = f.Request();
        var first = await f.ReadResponseAsync(firstRequest);
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000101");
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000102");

        using (var edit = await f.Client.PutAsJsonAsync($"/api/admin/licenses/{first.LicenseKey}", new { DaysToAdd = 1 }))
            Assert.True(edit.StatusCode == HttpStatusCode.OK, await edit.Content.ReadAsStringAsync());

        await using (var db = f.Db())
        {
            var pass = await db.PersonalDayPasses.AsNoTracking().SingleAsync();
            var license = await db.Licenses.AsNoTracking().SingleAsync();
            // La clé avance d'un jour, le registre ne bouge pas : les deux dates diffèrent.
            Assert.Equal(pass.PaidThroughUtc.AddDays(1), license.ExpirationDate);
        }

        var seatsBefore = await CountSeatsAsync(f);
        // Avant : exception non gérée « The paid-pass horizon contradicts licence authority. » (erreur 500).
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000103");
        Assert.Equal(seatsBefore + 1, await CountSeatsAsync(f));

        var current = await f.ReadResponseAsync(firstRequest);
        var renewal = f.Extend(f.Request() with { PaymentId = "after-admin-edit", PaidAtUtc = firstRequest.PaidAtUtc.AddSeconds(1) }, current);
        using var payment = await f.PostAsync(renewal);
        // Avant : 409 personal_pass_authority_conflict.
        Assert.True(payment.StatusCode == HttpStatusCode.OK, await payment.Content.ReadAsStringAsync());
        await using var after = f.Db();
        var paid = await after.PersonalDayPasses.AsNoTracking().SingleAsync();
        Assert.Equal(paid.PaidThroughUtc, (await after.Licenses.AsNoTracking().SingleAsync()).ExpirationDate);
    }

    /// <summary>
    /// Comportement actuel : <c>/renew</c> avec une date cible fixe la fin de la clé et recopie cette date dans
    /// le registre, si bien que les deux dates restent égales (chemin utilisé par le site, PR #857).
    /// </summary>
    [Fact]
    public async Task Tkt2331_RenewWithTargetCopiesKeyExpiryIntoLedger()
    {
        await using var f = await Fixture.CreateAsync();
        var first = await f.ReadResponseAsync(f.Request());
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000201");
        DateTime target;
        await using (var db = f.Db())
            target = (await db.Licenses.AsNoTracking().SingleAsync()).ExpirationDate!.Value.AddDays(30);

        using (var renew = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{first.LicenseKey}/renew",
                   new { TransactionId = "in_tkt2331_renew", TargetExpirationUtc = new DateTimeOffset(target, TimeSpan.Zero) }))
            Assert.True(renew.StatusCode == HttpStatusCode.OK, await renew.Content.ReadAsStringAsync());

        await using var check = f.Db();
        var pass = await check.PersonalDayPasses.AsNoTracking().SingleAsync();
        var license = await check.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(target, license.ExpirationDate);
        // Comportement actuel : le registre est recalé sur la clé.
        Assert.Equal(license.ExpirationDate, pass.PaidThroughUtc);
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000202");
    }

    /// <summary>Comportement actuel : <c>/renew</c> avec date cible refuse une clé du registre jamais activée.</summary>
    [Fact]
    public async Task Tkt2331_RenewWithTargetRefusesNeverActivatedLedgerKey()
    {
        await using var f = await Fixture.CreateAsync();
        var first = await f.ReadResponseAsync(f.Request());
        Assert.True(first.CurrentPendingFirstActivation);

        using var renew = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{first.LicenseKey}/renew",
            new { TransactionId = "in_tkt2331_pending", TargetExpirationUtc = new DateTimeOffset(Fixture.PaidAt.AddDays(60), TimeSpan.Zero) });
        Assert.Equal(HttpStatusCode.BadRequest, renew.StatusCode);
        Assert.Contains("target_expiration_requires_activation", await renew.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        await using var db = f.Db();
        Assert.Null((await db.Licenses.AsNoTracking().SingleAsync()).ExpirationDate);
    }

    /// <summary>Compte les postes enregistrés, actifs ou non.</summary>
    private static async Task<int> CountSeatsAsync(Fixture f)
    {
        await using var db = f.Db();
        return await db.LicenseSeats.CountAsync();
    }
}
