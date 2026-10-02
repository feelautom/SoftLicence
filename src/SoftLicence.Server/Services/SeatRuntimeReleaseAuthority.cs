using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Terminalizes Runtime rights belonging to an explicitly released provider seat.
/// Callers authorize the operation and acquire this authority before reading mutable seat state.
/// All mutations and their audit records must commit in the caller's transaction.
/// </summary>
internal static class SeatRuntimeReleaseAuthority
{
    /// <summary>Existing terminal reason shared with the signed distribution release protocol.</summary>
    internal const string Reason = "seat_released";

    /// <summary>
    /// Begins a read-committed transaction when needed and acquires the global Runtime mutation
    /// lock before any seat or binding row lock. The caller owns the returned transaction;
    /// an existing transaction remains caller-owned. Disposal rolls back uncommitted changes.
    /// </summary>
    internal static async Task<IDbContextTransaction?> BeginAsync(
        LicenseDbContext db, CancellationToken cancellationToken = default)
    {
        var transaction = await ProductHardwareSeatLockAuthority.BeginReadCommittedTransactionAsync(db, cancellationToken);
        try
        {
            if (db.Database.IsNpgsql())
                await db.Database.ExecuteSqlRawAsync(
                    "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)", cancellationToken);
            return transaction;
        }
        catch
        {
            if (transaction != null)
                await transaction.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Marks every active binding and live enrollment of the exact seat terminal, without
    /// deleting evidence or changing another seat. The global mutation lock must already be held.
    /// A divergent ownership graph fails closed and rolls back with the caller's transaction.
    /// State codes are exact persisted protocol values; no case folding is permitted.
    /// </summary>
    internal static async Task InvalidateAsync(
        LicenseDbContext db, Guid productId, LicenseSeat seat, DateTime now,
        CancellationToken cancellationToken = default)
    {
        var bindings = await db.DistributionInstallationBindings
            .Where(candidate => candidate.LicenseSeatId == seat.Id && candidate.State == "active")
            .OrderBy(candidate => candidate.Id).ToListAsync(cancellationToken);
        if (bindings.Any(candidate => candidate.ProductId != productId || candidate.LicenseId != seat.LicenseId))
            throw new DistributionOperationException("authority_inconsistent", StatusCodes.Status409Conflict);

        foreach (var binding in bindings)
        {
            var enrollments = await db.RuntimeEnrollments
                .Where(candidate => candidate.BindingId == binding.Id
                    && (candidate.State == "PENDING" || candidate.State == "ACTIVE"))
                .OrderBy(candidate => candidate.Id).ToListAsync(cancellationToken);
            if (enrollments.Any(candidate => candidate.ProductId != productId
                    || candidate.LicenseId != seat.LicenseId || candidate.LicenseSeatId != seat.Id
                    || candidate.InstallationId != binding.InstallationId
                    || candidate.HardwareIdHash != binding.HardwareIdHash
                    || candidate.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256))
                throw new DistributionOperationException("authority_inconsistent", StatusCodes.Status409Conflict);
            foreach (var enrollment in enrollments)
            {
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = now;
                enrollment.InvalidationReason = Reason;
            }
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = now;
            binding.InvalidationReason = Reason;
        }
    }

    /// <summary>
    /// Reconciles historical active bindings only for the authenticated migration's own licence,
    /// product, non-null subject and exact target hash, where the old seat was explicitly unlinked
    /// after binding creation. The caller already holds the global Runtime mutation lock and has
    /// verified the current enrollment proof. Conflicts outside this scope remain untouched.
    /// The active product/hash unique index excludes an orphan when the current binding already
    /// uses the target hash. Any later refusal rolls everything back with the migration.
    /// </summary>
    internal static async Task ReconcileHistoricalAsync(
        LicenseDbContext db, DistributionInstallationBinding current, string targetHash,
        DateTime now, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(current.SubjectRefDigestSha256))
            return;
        var candidates = await (from binding in db.DistributionInstallationBindings
            join seat in db.LicenseSeats on binding.LicenseSeatId equals seat.Id
            where binding.Id != current.Id && binding.ProductId == current.ProductId
                && binding.LicenseId == current.LicenseId && seat.LicenseId == current.LicenseId
                && binding.SubjectRefDigestSha256 == current.SubjectRefDigestSha256
                && binding.State == "active" && binding.HardwareIdHash == targetHash
                && !seat.IsActive && seat.UnlinkedAt != null
                && seat.UnlinkedAt >= binding.BoundAtUtc && seat.UnlinkedAt <= now
                && seat.UnlinkedAt <= current.BoundAtUtc
                && binding.InvalidatedAtUtc == null && binding.InvalidationReason == null
            select seat).Distinct().ToListAsync(cancellationToken);
        var reconciled = false;
        foreach (var seat in candidates)
        {
            // Never infer hardware equivalence from telemetry or an unrelated historical seat.
            var exactHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(seat.HardwareId)));
            if (!string.Equals(exactHash, targetHash, StringComparison.Ordinal))
                continue;
            var otherAuthority = await db.DistributionInstallationBindings.AnyAsync(candidate =>
                candidate.LicenseSeatId == seat.Id && candidate.State == "active"
                && (candidate.ProductId != current.ProductId || candidate.LicenseId != current.LicenseId
                    || candidate.SubjectRefDigestSha256 != current.SubjectRefDigestSha256
                    || candidate.HardwareIdHash != targetHash
                    || candidate.BoundAtUtc > seat.UnlinkedAt
                    || candidate.InvalidatedAtUtc != null || candidate.InvalidationReason != null), cancellationToken);
            if (otherAuthority)
                continue;
            await InvalidateAsync(db, current.ProductId, seat, now, cancellationToken);
            reconciled = true;
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = current.LicenseId,
                Timestamp = now,
                Action = "RUNTIME_RELEASE_RECONCILED",
                PerformedBy = "Runtime authority",
                Details = $"Terminalized historical Runtime rights of explicitly unlinked seat {seat.Id}."
            });
        }
        // Make the unchanged competing-binding SQL guard observe terminal states in this transaction.
        if (reconciled)
            await db.SaveChangesAsync(cancellationToken);
    }
}
