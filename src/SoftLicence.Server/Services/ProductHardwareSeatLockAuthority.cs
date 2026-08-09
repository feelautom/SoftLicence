using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

internal static class ProductHardwareSeatLockAuthority
{
    public static async Task<IDbContextTransaction?> BeginReadCommittedTransactionAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken = default)
    {
        if (!db.Database.IsRelational() || db.Database.CurrentTransaction != null)
            return null;

        return await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
    }

    public static async Task AcquireAsync(
        LicenseDbContext db,
        Guid productId,
        string exactHardwareId,
        CancellationToken cancellationToken = default)
    {
        if (!db.Database.IsNpgsql())
            return;
        if (db.Database.CurrentTransaction == null)
            throw new InvalidOperationException("The product hardware seat lock requires an active transaction.");

        var lockName = $"distribution-product-hardware-seat:{productId:D}:{exactHardwareId}";
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({lockName}, 0))",
            cancellationToken);
    }
}
