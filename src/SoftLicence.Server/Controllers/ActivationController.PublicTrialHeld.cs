using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Decides, for the anonymous trial routes, which licence the hardware already holds may be processed (TKT-002468,
/// audit finding C5). Someone who only knows a HWID must never receive or modify a licence they could not obtain
/// themselves: only a licence of the requested, opted-in type, without a paid commercial nature, is ever returned.
/// </summary>
public partial class ActivationController
{
    /// <summary>
    /// Refusal code when the hardware already holds a licence that an anonymous trial route must not return: a current
    /// licence of another type, or a licence of the requested type with a paid commercial nature.
    /// </summary>
    internal const string HardwareAlreadyLicensedCode = "HARDWARE_ALREADY_LICENSED";

    /// <summary>Refusal code when the held licence of the requested type has expired and the route cannot renew it.</summary>
    internal const string PublicTrialLicenceExpiredCode = "LICENSE_EXPIRED";

    /// <summary>
    /// Stored commercial natures that prove a payment. UNKNOWN is deliberately absent: keys issued through the
    /// administrator API without commercial evidence (for example a website Community licence) are UNKNOWN, and their
    /// type's public-trial opt-in is what makes them returnable. Values are code constants compared ordinally.
    /// </summary>
    private static readonly string[] PaidCommercialNatures = ["PAID", "PAID_TRIAL"];

    /// <summary>Outcome of <see cref="SelectHeldLicenceForPublicTrialAsync"/>.</summary>
    /// <param name="Held">
    /// The held licence the route must process (requested type, or revoked licence kept for the legacy 403), or
    /// <c>null</c> when the route proceeds to its creation checks.
    /// </param>
    /// <param name="Refusal">A typed refusal decided before any write, or <c>null</c>.</param>
    private readonly record struct HeldTrialSelection(License? Held, IActionResult? Refusal);

    /// <summary>
    /// Reads every licence of the product held by the hardware (licence row or seat) and decides, before any lock or
    /// write, what an anonymous trial request for <paramref name="type"/> may do with them.
    /// </summary>
    /// <remarks>
    /// Callers have already refused a reserved pass type and a type without the public-trial opt-in, so
    /// <paramref name="type"/> is opted in. Rules, in order:
    /// <list type="number">
    /// <item>Another type's licence that is active and not expired: refusal <see cref="HardwareAlreadyLicensedCode"/>.
    /// Nothing is returned, and no seat of that licence is unlinked by a creation.</item>
    /// <item>The preferred held licence (requested type first, then active, then latest expiry, a missing expiry
    /// counting as latest) of another type is either revoked (returned for the legacy 403) or expired (creation proceeds,
    /// which is the switch from an expired plan to a free type).</item>
    /// <item>A held licence of the requested type with a paid nature: refusal <see cref="HardwareAlreadyLicensedCode"/>.</item>
    /// <item>A held licence of the requested type that has expired and that <paramref name="renewable"/> rejects:
    /// refusal <see cref="PublicTrialLicenceExpiredCode"/>, instead of the accidental 503 of the product-scope cleanup.</item>
    /// </list>
    /// Type identity is compared by identifier, never by slug text. The HWID is compared exactly in SQL, as before.
    /// The refusals expose no key, name or e-mail; they only reveal that this hardware holds a licence of the product.
    /// </remarks>
    /// <param name="productId">Resolved product.</param>
    /// <param name="type">Requested, opted-in licence type of that product.</param>
    /// <param name="hardwareId">Hardware identifier sent by the caller, used verbatim.</param>
    /// <param name="renewable">Route-specific automatic renewal rule for an expired licence of the requested type.</param>
    /// <returns>The licence to process, or a refusal, or neither (creation).</returns>
    private async Task<HeldTrialSelection> SelectHeldLicenceForPublicTrialAsync(
        Guid productId, LicenseType type, string hardwareId, Func<License, bool> renewable)
    {
        var held = await _db.Licenses
            .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
            .Where(l => l.ProductId == productId
                && (l.HardwareId == hardwareId || l.Seats.Any(s => s.HardwareId == hardwareId)))
            .ToListAsync(HttpContext.RequestAborted);
        if (held.Count == 0)
            return new HeldTrialSelection(null, null);

        var now = DateTime.UtcNow;
        bool IsExpired(License license) => license.ExpirationDate.HasValue && now > license.ExpirationDate.Value;

        if (held.Any(l => l.LicenseTypeId != type.Id && l.IsActive && !IsExpired(l)))
            return new HeldTrialSelection(null, RefuseHeldLicence(type, HardwareAlreadyLicensedCode,
                "This computer already holds a licence for this product; recover it with its licence key."));

        var preferred = held
            .OrderByDescending(l => l.LicenseTypeId == type.Id ? 1 : 0)
            .ThenByDescending(l => l.IsActive ? 1 : 0)
            .ThenByDescending(l => l.ExpirationDate ?? DateTime.MaxValue)
            .First();

        if (preferred.LicenseTypeId != type.Id)
            return new HeldTrialSelection(preferred.IsActive ? null : preferred, null);
        if (!preferred.IsActive)
            return new HeldTrialSelection(preferred, null);

        if (PaidCommercialNatures.Contains(preferred.CommercialNature, StringComparer.Ordinal))
            return new HeldTrialSelection(null, RefuseHeldLicence(type, HardwareAlreadyLicensedCode,
                "This computer already holds a licence for this product; recover it with its licence key."));

        if (IsExpired(preferred) && !renewable(preferred))
            return new HeldTrialSelection(null, RefuseHeldLicence(type, PublicTrialLicenceExpiredCode,
                "The licence held by this computer has expired and cannot be renewed automatically."));

        return new HeldTrialSelection(preferred, null);
    }

    /// <summary>Logs and returns one typed refusal of <see cref="SelectHeldLicenceForPublicTrialAsync"/>; no licence data is logged.</summary>
    /// <param name="type">Requested licence type.</param>
    /// <param name="code">Public error code.</param>
    /// <param name="message">Public English message.</param>
    private IActionResult RefuseHeldLicence(LicenseType type, string code, string message)
    {
        _logger.LogWarning("Public trial refused ({Code}) for requested license type {LicenseTypeSlug} ({LicenseTypeId}).",
            code, type.Slug, type.Id);
        return ActivationJsonFailure(code, message);
    }
}
