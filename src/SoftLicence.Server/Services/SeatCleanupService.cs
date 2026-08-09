using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public class SeatCleanupService
{
    internal const string RuntimeInvalidationReason = "seat_reassigned_product_scope";

    private readonly LicenseDbContext _db;
    private readonly ILogger<SeatCleanupService> _logger;

    public SeatCleanupService(LicenseDbContext db, ILogger<SeatCleanupService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Unlinks a HWID from all other active licenses of the same product.
    /// The license identified by keepLicenseId "wins" and keeps the seat.
    /// </summary>
    public async Task<List<string>> UnlinkHwidFromOtherProductLicensesAsync(
        string hardwareId, Guid keepLicenseId, Guid productId, bool redactSensitiveDetails = false)
    {
        await using var transaction = await ProductHardwareSeatLockAuthority
            .BeginReadCommittedTransactionAsync(_db);
        await ProductHardwareSeatLockAuthority.AcquireAsync(_db, productId, hardwareId);

        var conflictingSeats = await _db.LicenseSeats
            .Include(s => s.License)
            .Where(s => s.HardwareId == hardwareId
                && s.IsActive
                && s.LicenseId != keepLicenseId
                && s.License!.ProductId == productId)
            .ToListAsync();

        var hardwareIdHash = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId)));
        var conflictingSeatIds = conflictingSeats
            .Select(seat => seat.Id)
            .ToHashSet();
        if (conflictingSeatIds.Count > 0 && _db.Database.IsNpgsql())
        {
            // Runtime enrollment operations acquire this authority lock before binding rows.
            // Taking the exclusive form before binding selection prevents stale active-state
            // snapshots and cleanup/prepare lock-order deadlocks. Protected-table triggers can
            // reacquire the same transaction lock when the rows are mutated below.
            await _db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)");
        }

        var bindingIds = await _db.DistributionInstallationBindings
            .Where(binding => binding.ProductId == productId
                && binding.LicenseId != keepLicenseId
                && binding.HardwareIdHash == hardwareIdHash
                && binding.State == "active"
                && conflictingSeatIds.Contains(binding.LicenseSeatId))
            .Select(binding => binding.Id)
            .OrderBy(id => id)
            .ToListAsync();
        var bindings = new List<DistributionInstallationBinding>(bindingIds.Count);
        foreach (var bindingId in bindingIds)
        {
            var binding = _db.Database.IsNpgsql()
                ? await _db.DistributionInstallationBindings
                    .FromSqlInterpolated($"SELECT * FROM public.\"DistributionInstallationBindings\" WHERE \"Id\" = {bindingId} FOR UPDATE")
                    .SingleAsync()
                : await _db.DistributionInstallationBindings.SingleAsync(candidate => candidate.Id == bindingId);
            if (binding.State == "active"
                && binding.ProductId == productId
                && binding.LicenseId != keepLicenseId
                && binding.HardwareIdHash == hardwareIdHash
                && conflictingSeatIds.Contains(binding.LicenseSeatId))
            {
                bindings.Add(binding);
            }
        }

        var enrollments = new List<RuntimeEnrollment>();
        foreach (var binding in bindings)
        {
            var correlated = _db.Database.IsNpgsql()
                ? await _db.RuntimeEnrollments
                    .FromSqlInterpolated($"SELECT * FROM public.\"RuntimeEnrollments\" WHERE \"BindingId\" = {binding.Id} AND \"State\" IN ('PENDING', 'ACTIVE') ORDER BY \"Id\" FOR UPDATE")
                    .ToListAsync()
                : await _db.RuntimeEnrollments
                    .Where(candidate => candidate.BindingId == binding.Id
                        && (candidate.State == "PENDING" || candidate.State == "ACTIVE"))
                    .OrderBy(candidate => candidate.Id)
                    .ToListAsync();
            enrollments.AddRange(correlated);
        }

        var unlinkedFromKeys = new List<string>();
        var now = DateTime.UtcNow;
        foreach (var seat in conflictingSeats)
        {
            seat.IsActive = false;
            seat.UnlinkedAt = now;
            unlinkedFromKeys.Add(seat.License!.LicenseKey);

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = seat.LicenseId,
                Action = HistoryActions.AutoUnlinkedProductScope,
                Details = redactSensitiveDetails
                    ? $"Hardware auto-unlinked after offline activation on license {keepLicenseId} (same product)"
                    : $"HWID {hardwareId} auto-unlinked: activated on license {keepLicenseId} (same product)",
                PerformedBy = "System",
                Timestamp = now
            });

            _logger.LogInformation(
                "Auto-unlinked hardware from license {LicenseId} (product scope enforcement)",
                seat.LicenseId);
        }

        foreach (var binding in bindings)
        {
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = now;
            binding.InvalidationReason = RuntimeInvalidationReason;
        }

        if (conflictingSeats.Count > 0 || bindings.Count > 0)
            await _db.SaveChangesAsync();

        if (enrollments.Count > 0)
        {
            var authorityEpoch = await _db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                .Where(candidate => candidate.Id == 1)
                .Select(candidate => (long?)candidate.Epoch)
                .SingleOrDefaultAsync()
                ?? enrollments.Max(candidate => candidate.AuthorityEpoch);
            foreach (var enrollment in enrollments)
            {
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = now;
                enrollment.InvalidationReason = RuntimeInvalidationReason;
                enrollment.AuthorityEpoch = authorityEpoch;
            }

            await _db.SaveChangesAsync();
        }

        if (transaction != null)
            await transaction.CommitAsync();

        return unlinkedFromKeys;
    }
}
