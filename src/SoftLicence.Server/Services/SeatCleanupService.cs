using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Serializes product-scope commercial seat cleanup, ends losing assignments through item2, and
/// preserves Runtime bindings, enrollments, cryptographic epochs, and proof state.
/// </summary>
public class SeatCleanupService
{
    /// <summary>Historical reason retained for readers of pre-B2 Runtime invalidation evidence.</summary>
    internal const string RuntimeInvalidationReason = "seat_reassigned_product_scope";

    private readonly LicenseDbContext _db;
    private readonly ILogger<SeatCleanupService> _logger;
    /// <summary>Identifies the exact relational transaction that acquired global and item2 authority.</summary>
    private Guid? _productScopeAuthorityTransactionId;
    /// <summary>Records authority acquisition only for non-relational test providers without transactions.</summary>
    private bool _nonRelationalProductScopeAuthorityHeld;

    public SeatCleanupService(LicenseDbContext db, ILogger<SeatCleanupService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Begins the product-scope cleanup transaction and acquires global commercial authority
    /// before the product/hardware lock or any mutable authority row.
    /// </summary>
    /// <param name="productId">The exact product whose active seat ownership may change.</param>
    /// <param name="hardwareId">The exact canonical hardware identifier being activated.</param>
    /// <param name="cancellationToken">Stops the database operation before commit.</param>
    /// <returns>
    /// The newly created transaction owned by the caller, or <see langword="null"/> when the context
    /// already owns a transaction or the non-relational provider does not create one.
    /// </returns>
    internal async Task<IDbContextTransaction?> BeginProductScopeCleanupAsync(
        Guid productId,
        string hardwareId,
        CancellationToken cancellationToken = default)
    {
        var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(_db, cancellationToken);
        try
        {
            await ProductHardwareSeatLockAuthority.AcquireAsync(
                _db, productId, hardwareId, cancellationToken);
            if (_db.Database.IsRelational())
            {
                var currentTransaction = _db.Database.CurrentTransaction;
                if (currentTransaction == null)
                    throw Unavailable("product_scope_authority_order_missing");
                _productScopeAuthorityTransactionId = currentTransaction.TransactionId;
                _nonRelationalProductScopeAuthorityHeld = false;
            }
            else
            {
                _productScopeAuthorityTransactionId = null;
                _nonRelationalProductScopeAuthorityHeld = true;
            }
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
    /// Deactivates every losing commercial seat for one product and exact hardware identifier,
    /// then proves that item2 ended each original assignment without mutating Runtime identity.
    /// </summary>
    /// <param name="hardwareId">The exact canonical licensing hardware value.</param>
    /// <param name="keepLicenseId">The licence whose unique active seat remains current.</param>
    /// <param name="productId">The product that owns the winning and losing licences.</param>
    /// <param name="redactSensitiveDetails">Whether history omits the submitted hardware value.</param>
    /// <returns>The licence keys whose seats were deactivated, in deterministic seat order.</returns>
    /// <exception cref="DistributionOperationException">
    /// The winning authority or an affected assignment relation is absent, ambiguous, or divergent.
    /// </exception>
    public async Task<List<string>> UnlinkHwidFromOtherProductLicensesAsync(
        string hardwareId, Guid keepLicenseId, Guid productId, bool redactSensitiveDetails = false)
    {
        IDbContextTransaction? ownedTransaction = null;
        var currentTransaction = _db.Database.CurrentTransaction;
        if (currentTransaction == null)
        {
            ownedTransaction = await BeginProductScopeCleanupAsync(productId, hardwareId);
        }
        else if (_db.Database.IsRelational()
            ? _productScopeAuthorityTransactionId != currentTransaction.TransactionId
            : !_nonRelationalProductScopeAuthorityHeld)
        {
            throw Unavailable("product_scope_authority_order_missing");
        }

        await using (ownedTransaction)
        {
            // Hierarchical activation and authenticated aliases may resolve a different
            // product/hardware pair after the global barriers were acquired. The global
            // exclusive lease serializes contenders while this exact scope is added.
            await ProductHardwareSeatLockAuthority.AcquireAsync(_db, productId, hardwareId);
            var winningLicense = _db.Database.IsNpgsql()
                ? await _db.Licenses.FromSqlInterpolated(
                        $"SELECT * FROM public.\"Licenses\" WHERE \"Id\" = {keepLicenseId} FOR UPDATE")
                    .SingleOrDefaultAsync()
                : await _db.Licenses.SingleOrDefaultAsync(candidate => candidate.Id == keepLicenseId);
            if (winningLicense == null || winningLicense.ProductId != productId)
                throw Unavailable("product_scope_winner_missing");

            var winningSeatIds = await _db.LicenseSeats.AsNoTracking()
                .Where(candidate => candidate.LicenseId == keepLicenseId
                    && candidate.HardwareId == hardwareId
                    && candidate.IsActive)
                .Select(candidate => candidate.Id)
                .OrderBy(candidate => candidate)
                .ToListAsync();
            if (winningSeatIds.Count != 1)
                throw Unavailable(winningSeatIds.Count == 0
                    ? "product_scope_winner_seat_missing"
                    : "product_scope_winner_seat_ambiguous");
            var winningSeat = _db.Database.IsNpgsql()
                ? await _db.LicenseSeats.FromSqlInterpolated(
                        $"SELECT * FROM public.\"LicenseSeats\" WHERE \"Id\" = {winningSeatIds[0]} FOR UPDATE")
                    .SingleAsync()
                : await _db.LicenseSeats.SingleAsync(candidate => candidate.Id == winningSeatIds[0]);
            if (!winningSeat.IsActive
                || winningSeat.LicenseId != keepLicenseId
                || !string.Equals(winningSeat.HardwareId, hardwareId, StringComparison.Ordinal))
            {
                throw Unavailable("product_scope_winner_seat_changed");
            }

            var conflictingSeatIds = await _db.LicenseSeats.AsNoTracking()
                .Where(candidate => candidate.HardwareId == hardwareId
                    && candidate.IsActive
                    && candidate.LicenseId != keepLicenseId
                    && candidate.License != null
                    && candidate.License.ProductId == productId)
                .Select(candidate => candidate.Id)
                .OrderBy(candidate => candidate)
                .ToListAsync();
            var conflictingSeats = await _db.LicenseSeats
                .Where(candidate => conflictingSeatIds.Contains(candidate.Id))
                .OrderBy(candidate => candidate.LicenseId)
                .ThenBy(candidate => candidate.Id)
                .ToListAsync();

            var scopes = new List<SeatRuntimeReleaseAuthority.SeatReleaseScope>();
            var losingLicenses = new Dictionary<Guid, License>();
            foreach (var group in conflictingSeats.GroupBy(candidate => candidate.LicenseId)
                         .OrderBy(candidate => candidate.Key))
            {
                var license = _db.Database.IsNpgsql()
                    ? await _db.Licenses.FromSqlInterpolated(
                            $"SELECT * FROM public.\"Licenses\" WHERE \"Id\" = {group.Key} FOR UPDATE")
                        .SingleOrDefaultAsync()
                    : await _db.Licenses.SingleOrDefaultAsync(candidate => candidate.Id == group.Key);
                if (license == null || license.ProductId != productId)
                    throw Unavailable("product_scope_loser_license_missing");
                losingLicenses.Add(license.Id, license);
                scopes.Add(await SeatRuntimeReleaseAuthority.PrepareAsync(
                    _db, productId, license, group.ToArray(), DateTime.UtcNow));
            }

            if (conflictingSeats.Any(seat => !seat.IsActive
                || seat.LicenseId == keepLicenseId
                || !string.Equals(seat.HardwareId, hardwareId, StringComparison.Ordinal)))
            {
                throw Unavailable("product_scope_loser_seat_changed");
            }

            var now = _db.Database.IsRelational()
                ? (await RuntimeEnrollmentService.DatabaseNowAsync(_db, CancellationToken.None)).UtcDateTime
                : DateTime.UtcNow;
            if (!winningLicense.IsActive || winningLicense.RevokedAt != null)
            {
                throw Unavailable("product_scope_winner_ineligible");
            }
            if (winningLicense.ExpirationDate.HasValue
                && winningLicense.ExpirationDate.Value <= now)
            {
                throw Unavailable("product_scope_winner_expired");
            }

            var unlinkedFromKeys = new List<string>(conflictingSeats.Count);
            foreach (var seat in conflictingSeats.OrderBy(candidate => candidate.Id))
            {
                seat.IsActive = false;
                seat.UnlinkedAt = now;
                unlinkedFromKeys.Add(losingLicenses[seat.LicenseId].LicenseKey);

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

            var releaseScope = new SeatRuntimeReleaseAuthority.SeatReleaseScope(
                now,
                scopes.SelectMany(candidate => candidate.Assignments).ToArray());
            await SeatRuntimeReleaseAuthority.CompleteAsync(
                _db, releaseScope, conflictingSeats);

            if (ownedTransaction != null)
                await ownedTransaction.CommitAsync();

            return unlinkedFromKeys;
        }
    }

    /// <summary>Creates the bounded infrastructure failure used for an unsafe product-scope graph.</summary>
    /// <param name="diagnosticCode">The internal bounded reason; it never contains hardware data.</param>
    /// <returns>A public authority failure with the internal diagnostic attached.</returns>
    private static DistributionOperationException Unavailable(string diagnosticCode) =>
        new("authority_unavailable", StatusCodes.Status503ServiceUnavailable, diagnosticCode);
}
