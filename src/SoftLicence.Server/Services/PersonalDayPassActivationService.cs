using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Starts an initially purchased personal pass at its first successful seat activation.
/// Later payments remain anchored to the resulting FIFO horizon and never replace the licence key.
/// </summary>
public static class PersonalDayPassActivationService
{
    /// <summary>
    /// Proves a never-activated paid pass while the caller holds the global and licence locks. A null
    /// expiry alone is not authority: an immutable payment receipt must still match the current CAS
    /// and ledger horizon. Any administrative licence mutation, historical seat (including released),
    /// changed ownership or invalid type denies this state. No record is repaired or written here.
    /// </summary>
    public static async Task<bool> IsPendingAsync(LicenseDbContext db, PersonalDayPass pass, License license,
        CancellationToken cancellationToken)
    {
        if (pass.LicenseId != license.Id || pass.ProductId != license.ProductId
            || !license.IsActive || license.RevokedAt.HasValue || license.RevocationReason is not null
            || license.ExpirationDate.HasValue || pass.InitialPaidThroughUtc.HasValue
            || license.ActivationDate.HasValue || license.HardwareId is not null
            || await db.LicenseSeats.AsNoTracking().AnyAsync(s => s.LicenseId == license.Id, cancellationToken))
            return false;
        var type = await db.LicenseTypes.AsNoTracking().Include(t => t.CustomParams)
            .SingleOrDefaultAsync(t => t.Id == license.LicenseTypeId && t.ProductId == license.ProductId, cancellationToken);
        if (type is null || !PersonalDayPassPolicy.IsValidPassType(type)) return false;
        var owners = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .Where(o => o.ProductId == license.ProductId && o.LicenseId == license.Id && o.State == "ACTIVE")
            .ToListAsync(cancellationToken);
        if (owners.Count != 1 || owners[0].EndedAtUtc.HasValue || owners[0].OwnerSubjectId != pass.CommercialSubjectId)
            return false;
        return await db.PersonalDayPassOperations.AsNoTracking()
            .Join(db.PersonalDayPassPayments.AsNoTracking().Where(p => p.PassId == pass.Id),
                o => o.PaymentId, p => p.Id, (o, p) => o)
            .AnyAsync(o => o.ResultAuthorityVersion == license.AuthorityVersion
                && o.PaidThroughUtc == pass.PaidThroughUtc, cancellationToken);
    }

    /// <summary>
    /// Materializes the deferred first-activation anchor while the caller owns the licence and Runtime-global locks.
    /// </summary>
    /// <param name="db">The transaction-scoped PostgreSQL context tracking <paramref name="license"/>.</param>
    /// <param name="license">The exact paid licence whose first seat is about to be accepted.</param>
    /// <param name="activatedAtUtc">The authoritative UTC activation instant.</param>
    /// <param name="performedBy">The authenticated server actor recorded in licence history.</param>
    /// <param name="cancellationToken">Cancels before the surrounding transaction commits.</param>
    /// <returns><see langword="true"/> only when this call started a previously deferred pass.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a pass ledger is incomplete or contradicts current licence authority.
    /// The caller must roll back rather than inventing paid time.
    /// </exception>
    public static async Task<bool> StartPendingAsync(
        LicenseDbContext db,
        License license,
        DateTime activatedAtUtc,
        string performedBy,
        CancellationToken cancellationToken)
    {
        if (activatedAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The activation instant must be UTC.", nameof(activatedAtUtc));

        // Production uses a row lock because payment and activation can race. Test and diagnostic
        // providers cannot translate PostgreSQL's FOR UPDATE, so they use the same identity query
        // under their provider-specific transaction semantics.
        var passQuery = db.Database.IsNpgsql()
            ? db.PersonalDayPasses.FromSqlInterpolated($"""
                SELECT * FROM public."PersonalDayPasses"
                WHERE "ProductId" = {license.ProductId} AND "LicenseId" = {license.Id}
                FOR UPDATE
                """)
            : db.PersonalDayPasses.Where(candidate =>
                candidate.ProductId == license.ProductId && candidate.LicenseId == license.Id);
        var pass = await passQuery.SingleOrDefaultAsync(cancellationToken);
        if (pass is null)
            return false;

        if (license.ExpirationDate.HasValue)
        {
            if (license.ExpirationDate.Value != pass.PaidThroughUtc)
                throw new InvalidOperationException("The paid-pass horizon contradicts licence authority.");
            return false;
        }
        if (!await IsPendingAsync(db, pass, license, cancellationToken))
        {
            throw new InvalidOperationException("The deferred paid-pass authority is inconsistent.");
        }

        var payments = await db.PersonalDayPassPayments.AsNoTracking()
            .Where(payment => payment.PassId == pass.Id)
            .ToListAsync(cancellationToken);
        if (payments.Count == 0)
            throw new InvalidOperationException("The deferred paid pass has no confirmed payment.");

        // PostgreSQL clock timestamps may carry microseconds while the commercial wire contract is milliseconds.
        var anchor = new DateTime(
            activatedAtUtc.Ticks - activatedAtUtc.Ticks % TimeSpan.TicksPerMillisecond,
            DateTimeKind.Utc);
        var paymentInputs = payments.Select(payment => new PersonalDayPassPolicy.Payment(
                PersonalDayPassPolicy.Identity(
                    payment.Provider, payment.ProviderAccount, payment.Environment, payment.PaymentId),
                payment.PaidAtUtc,
                payment.MaxSeats,
                payment.DurationSeconds,
                payment.PrioritySupport)).ToArray();
        var provisionalPeriods = PersonalDayPassPolicy.Allocate(paymentInputs);
        if (provisionalPeriods.Count == 0 || pass.PaidThroughUtc < provisionalPeriods[^1].ExpiresAtUtc)
            throw new InvalidOperationException("The deferred paid-pass horizon is incomplete.");
        var trailingPaidTime = pass.PaidThroughUtc - provisionalPeriods[^1].ExpiresAtUtc;
        var periods = PersonalDayPassPolicy.Allocate(paymentInputs, anchor);
        if (periods.Count == 0)
            throw new InvalidOperationException("The deferred paid pass has no allocatable period.");
        if (periods[^1].ExpiresAtUtc > DateTime.MaxValue - trailingPaidTime)
            throw new InvalidOperationException("The deferred paid-pass horizon overflows UTC.");

        pass.InitialPaidThroughUtc = anchor;
        pass.PaidThroughUtc = periods[^1].ExpiresAtUtc + trailingPaidTime;
        pass.CurrentPrioritySupport = periods[0].PrioritySupport;
        license.ExpirationDate = pass.PaidThroughUtc;
        license.MaxSeats = periods[0].MaxSeats;
        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = license.Id,
            Timestamp = anchor,
            Action = "PERSONAL_PASS_FIRST_ACTIVATION_STARTED",
            Details = $"Deferred paid time started at {anchor:O} and now expires at {pass.PaidThroughUtc:O}.",
            PerformedBy = performedBy
        });
        return true;
    }
}
