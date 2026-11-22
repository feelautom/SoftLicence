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

    /// <summary>
    /// Stages deactivation of every active global or product ban applicable to one canonical hardware identity.
    /// The caller owns the transaction and hardware advisory lock.
    /// </summary>
    /// <param name="db">Caller-owned context and transaction.</param>
    /// <param name="canonicalHardwareId">Exact canonical hardware identifier.</param>
    /// <param name="productId">Product whose lock is being explicitly unbanned.</param>
    /// <param name="admin">Named administrator.</param>
    /// <param name="auditedReason">Bounded reason containing the named audit reference.</param>
    /// <param name="nowUtc">Authoritative mutation time.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The number of active ban rows deactivated.</returns>
    public static async Task<int> StageUnbanAsync(
        LicenseDbContext db,
        string canonicalHardwareId,
        Guid productId,
        string admin,
        string auditedReason,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        var bans = await db.BannedHardwareIds
            .Where(ban => ban.HardwareId.ToUpper() == canonicalHardwareId
                && ban.IsActive
                && (ban.ProductId == null || ban.ProductId == productId))
            .ToListAsync(cancellationToken);
        var entry = $"unban={nowUtc:O} | admin={admin} | {auditedReason}";
        foreach (var ban in bans)
        {
            ban.IsActive = false;
            ban.Reason = JoinBoundedAuditReason(ban.Reason, entry, 500);
        }
        return bans.Count;
    }

    /// <summary>Appends the newest audit entry while retaining as much prior reason text as the column allows.</summary>
    private static string JoinBoundedAuditReason(string? current, string entry, int maxLength)
    {
        if (entry.Length >= maxLength)
            return entry[..maxLength];
        if (string.IsNullOrWhiteSpace(current))
            return entry;
        const string separator = " | ";
        var prior = current.Trim();
        var available = maxLength - entry.Length - separator.Length;
        if (prior.Length > available)
            prior = prior[..available];
        return $"{prior}{separator}{entry}";
    }
}
