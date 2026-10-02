using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>
/// Permanent hardware bans issued by the lock system (automatic ENFORCE and admin BAN). Invariant: the table has a
/// unique (HardwareId, ProductId) index and historical rows may be stored in any case or be inactive/expired, so a
/// ban reuses an existing row for the same product instead of inserting a duplicate that would fail the transaction.
/// </summary>
public static class SecurityLockBans
{
    /// <summary>
    /// Stages a permanent, active ban in <paramref name="db"/> (the caller saves it in its own transaction). The exact
    /// canonical row is preferred; otherwise a case-variant row is reused and canonicalized only when no exact row
    /// exists, so the unique index can never be violated.
    /// </summary>
    /// <param name="db">Context whose transaction also persists the lock decision.</param>
    /// <param name="canonicalHardwareId">Validated canonical upper-case hardware identifier.</param>
    /// <param name="productId">Product of the lock.</param>
    /// <param name="reason">Ban reason.</param>
    /// <param name="category">Known ban category.</param>
    /// <param name="nowUtc">Decision time.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task StagePermanentBanAsync(
        LicenseDbContext db,
        string canonicalHardwareId,
        Guid productId,
        string reason,
        string category,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        var candidates = await db.BannedHardwareIds
            .Where(ban => ban.HardwareId.ToUpper() == canonicalHardwareId && ban.ProductId == productId)
            .ToListAsync(cancellationToken);
        var exact = candidates.FirstOrDefault(ban => string.Equals(ban.HardwareId, canonicalHardwareId, StringComparison.Ordinal));
        var target = exact ?? candidates.FirstOrDefault();
        if (target == null)
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = canonicalHardwareId,
                ProductId = productId,
                BannedAt = nowUtc,
                Reason = reason,
                BanCategory = category,
                IsActive = true
            });
            return;
        }

        if (exact == null)
            target.HardwareId = canonicalHardwareId;
        target.IsActive = true;
        target.ExpiresAt = null;
        target.BannedAt = nowUtc;
        target.Reason = reason;
        target.BanCategory = category;
    }
}
