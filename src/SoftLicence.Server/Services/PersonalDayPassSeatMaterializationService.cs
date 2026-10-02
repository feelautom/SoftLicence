using System.Data;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Applies the seat count belonging to the currently active paid pass period. Paid expiry is
/// already persisted when money is accepted; this worker changes only the seat variable when a
/// queued period reaches its exact boundary.
/// </summary>
public sealed class PersonalDayPassSeatMaterializationService(
    IDbContextFactory<LicenseDbContext> dbFactory,
    ILogger<PersonalDayPassSeatMaterializationService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    /// <summary>Runs the bounded materialization continuously without allowing one failed iteration to stop the server.</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await MaterializeAsync(DateTime.UtcNow, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) { logger.LogError(error, "Personal day-pass seat materialization failed."); }
            await Task.Delay(Interval, stoppingToken);
        }
    }

    /// <summary>
    /// Resolves one deterministic current period per license under the common commercial authority
    /// lock, then persists only a changed seat count and its audit history.
    /// </summary>
    public async Task<int> MaterializeAsync(DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        if (nowUtc.Kind != DateTimeKind.Utc) throw new ArgumentException("UTC required.", nameof(nowUtc));
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms'; SELECT pg_advisory_xact_lock(999831, 1);", cancellationToken);
        var evidence = await (from pass in db.PersonalDayPasses.AsNoTracking()
            join payment in db.PersonalDayPassPayments.AsNoTracking() on pass.Id equals payment.PassId
            join operation in db.PersonalDayPassOperations.AsNoTracking() on payment.Id equals operation.PaymentId
            select new { Pass = pass, Payment = payment, operation.PeriodStartsAtUtc }).ToListAsync(cancellationToken);
        var current = new List<(Guid PassId, Guid LicenseId, int MaxSeats, bool PrioritySupport, DateTime PeriodStartsAtUtc)>();
        foreach (var account in evidence.GroupBy(row => row.Pass.Id))
        {
            var pass = account.First().Pass;
            // Transport replays may create multiple immutable receipts for one payment. They must
            // neither duplicate paid time nor determine which seat period is currently active.
            var payments = account.GroupBy(row => row.Payment.Id).Select(group => group.First().Payment).ToArray();
            var floors = account.GroupBy(row => PersonalDayPassPolicy.Identity(row.Payment.Provider,
                    row.Payment.ProviderAccount, row.Payment.Environment, row.Payment.PaymentId), StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.Min(row => row.PeriodStartsAtUtc), StringComparer.Ordinal);
            var periods = PersonalDayPassPolicy.Allocate(payments.Select(payment => new PersonalDayPassPolicy.Payment(
                PersonalDayPassPolicy.Identity(payment.Provider, payment.ProviderAccount, payment.Environment, payment.PaymentId),
                payment.PaidAtUtc, payment.MaxSeats, payment.DurationSeconds, payment.PrioritySupport)), pass.InitialPaidThroughUtc);
            DateTime? horizon = pass.InitialPaidThroughUtc;
            foreach (var period in periods)
            {
                // Legacy renewals can insert paid time between pass purchases. A historical start is
                // only a lower bound preserving that acquired gap, never a current-period selector.
                // Earlier evidence can move a later payment forward; its old receipt remains unchanged.
                var start = period.StartsAtUtc;
                if (floors[period.Identity] > start) start = floors[period.Identity];
                if (horizon.HasValue && horizon.Value > start) start = horizon.Value;
                var duration = period.ExpiresAtUtc - period.StartsAtUtc;
                if (start > DateTime.MaxValue - duration)
                    throw new InvalidOperationException("Paid seat projection overflows UTC.");
                horizon = start + duration;
                if (horizon > pass.PaidThroughUtc)
                    throw new InvalidOperationException("Paid seat projection exceeds acquired authority.");
                if (start <= nowUtc && nowUtc < horizon.Value)
                    current.Add((pass.Id, pass.LicenseId, period.MaxSeats, period.PrioritySupport, start));
            }
        }
        var changed = 0;
        foreach (var term in current)
        {
            var license = await db.Licenses.FromSqlInterpolated($"SELECT * FROM public.\"Licenses\" WHERE \"Id\" = {term.LicenseId} FOR UPDATE")
                .SingleOrDefaultAsync(cancellationToken);
            var pass = await db.PersonalDayPasses.SingleAsync(row => row.Id == term.PassId, cancellationToken);
            // A newly purchased pass has no live horizon until its first accepted software activation.
            // Its provisional payment-time periods must never materialize seats or support early.
            if (license is null || !license.ExpirationDate.HasValue
                || license.MaxSeats == term.MaxSeats && pass.CurrentPrioritySupport == term.PrioritySupport) continue;
            license.MaxSeats = term.MaxSeats;
            pass.CurrentPrioritySupport = term.PrioritySupport;
            db.LicenseHistories.Add(new LicenseHistory { LicenseId = license.Id, Action = "PERSONAL_PASS_SEATS_APPLIED_V1",
                Details = $"Paid period starting {term.PeriodStartsAtUtc:O}: {term.MaxSeats} seat(s), priority support={term.PrioritySupport}.", PerformedBy = "System" });
            changed++;
        }
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return changed;
    }
}
