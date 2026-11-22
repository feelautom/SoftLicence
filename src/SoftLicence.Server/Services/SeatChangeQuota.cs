using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Describes the daily hardware quota of one licence key for the current UTC day.
/// </summary>
/// <param name="Limit">
/// Daily limit of the whole licence computed by <see cref="SeatChangeQuota.GetDailyLimit"/>
/// (<see cref="LicenseType.MaxActivationsPerDay"/> per seat); zero means unlimited.
/// </param>
/// <param name="UsedToday">
/// Units used since UTC midnight: distinct hardware identifiers the key was activated on, plus guided clone-guard
/// reactivations of its seats (TKT-003615).
/// </param>
/// <param name="ResetAtUtc">Next UTC midnight, when the counter starts again from zero.</param>
public sealed record SeatChangeQuotaStatus(int Limit, int UsedToday, DateTime ResetAtUtc)
{
    /// <summary>Gets whether the licence type imposes no daily limit.</summary>
    public bool IsUnlimited => Limit <= 0;

    /// <summary>Gets how many further distinct identifiers the key may still be activated on today, or <see langword="null"/> when unlimited.</summary>
    public int? Remaining => IsUnlimited ? null : Math.Max(0, Limit - UsedToday);

    /// <summary>
    /// Gets whether the day's distinct identifiers already reach the limit. Only an activation on an identifier not
    /// yet activated today is refused then (<see cref="SeatChangeQuota.IsActivationRefusedAsync"/>); a seat release
    /// is never refused on this basis.
    /// </summary>
    public bool IsExhausted => !IsUnlimited && UsedToday >= Limit;
}

/// <summary>
/// Single provider authority for the daily hardware quota of one licence key, shared by the Website dashboard,
/// every seat admission path and the licence read model.
/// </summary>
/// <remarks>
/// <para>
/// Owner rule (TKT-003751, 13/11/2026, definitive): « Une même clé de licence ne peut pas être activée sur plus
/// de N identifiants matériels différents dans la même journée. Tout le reste est libre. » N is
/// <see cref="GetDailyLimit"/>, read from <see cref="LicenseType.MaxActivationsPerDay"/> on every call, never a
/// constant. Signing out, deactivating, unlinking from the dashboard, a reset code, an administrator unlink,
/// reactivating the same machine any number of times, and another key of the same product taking the same machine
/// are never counted and never refused. Cases and expected results: <c>docs/schema/licence-dates.md</c>.
/// </para>
/// <para>
/// The count is the number of distinct <see cref="LicenseSeat.HardwareId"/> values of the licence whose
/// <see cref="LicenseSeat.LastActivatedAt"/> falls within [UTC midnight, next UTC midnight). The context stamps
/// that column whenever a seat becomes active (created active, reactivated, or moved in place to another
/// identifier), whatever the path (key, WebSetup, Runtime, transfer, migration, administrator), so no path can
/// forget it. Seat rows are kept on release and reused when an identifier comes back, so the same machine never
/// counts twice in a day. An in-place identifier migration stamps only the new identifier. Each guided reactivation
/// of a copied installation (<see cref="SeatCloneGuardEventKinds.Reactivated"/>, TKT-003615) adds one more unit.
/// </para>
/// <para>
/// Enforcement belongs to the admission paths, which call <see cref="IsActivationRefusedAsync"/> before activating
/// a seat, inside the same transaction and lock scope; this helper takes no lock. Every caller already holds the
/// exclusive item2 commercial write barrier (advisory lock 1312, or the exclusive global Runtime mutation lock for the
/// identifier migration) before the check: key activation, identifier switch and automatic switch, WebSetup
/// installation and transfer, identifier migration and the Runtime resolver. All admissions are therefore
/// serialized, so two concurrent activations on two new identifiers, even on a multi-seat licence, cannot both pass
/// the last slot of the day (review of PR #554, remark 4). A new admission path must take that barrier first. The identifier comparison is
/// ordinal (PostgreSQL text equality) on canonical server values, as everywhere seats are matched, and runs under
/// the existing <c>LicenseSeats(LicenseId)</c> index.
/// </para>
/// </remarks>
public static class SeatChangeQuota
{
    /// <summary>
    /// Computes the daily limit of one licence: <see cref="LicenseType.MaxActivationsPerDay"/> applies
    /// per seat, so the licence allows that value multiplied by <see cref="License.MaxSeats"/>.
    /// </summary>
    /// <remarks>
    /// Shared by every seat admission path (historical activation, WebSetup installation, Runtime transfer) so that
    /// a licence of N seats can install its N machines on the first day (TKT-002030). A single-seat licence keeps
    /// exactly the configured value. A non-positive seat count counts as one seat.
    /// </remarks>
    /// <param name="license">Licence with its <see cref="License.Type"/> loaded; a missing type is unlimited.</param>
    /// <returns>The daily limit, or zero when the licence type imposes none.</returns>
    public static int GetDailyLimit(License license)
    {
        var perSeat = license.Type?.MaxActivationsPerDay ?? 0;
        if (perSeat <= 0)
            return 0;
        // Saturate instead of overflowing for an extreme administrator-entered seat count.
        return (int)Math.Min(int.MaxValue, (long)perSeat * Math.Max(1, license.MaxSeats));
    }

    /// <summary>
    /// Reads the live limit and counts the units the key used during the current UTC day: the distinct hardware
    /// identifiers it was activated on, plus every guided clone-guard reactivation of one of its seats
    /// (<see cref="SeatCloneGuardEventKinds.Reactivated"/>, TKT-003615).
    /// </summary>
    /// <remarks>
    /// Product decision (16/11/2026): reactivating a copied installation is one more change of machine, counted in
    /// this same daily quota, with no separate per-seat counter. Two copies of a VM share one hardware identifier, so
    /// without the reactivation term they would count once and could take the seat from each other without limit.
    /// Because the reactivation term only grows, an exhausted quota also blocks every new identifier that day, as
    /// for any other change of machine. Both terms are read in the caller's transaction; callers that admit or
    /// reactivate hold the exclusive commercial barrier (advisory lock 1312), so reads and the following write cannot
    /// interleave with another admission or reactivation.
    /// </remarks>
    /// <param name="db">Context whose transaction, when present, scopes the read; pending changes are not seen.</param>
    /// <param name="license">
    /// Licence with its <see cref="License.Type"/> loaded; a missing type is treated as unlimited,
    /// matching the previous enforcement.
    /// </param>
    /// <param name="nowUtc">Current instant with <see cref="DateTimeKind.Utc"/>; defines the UTC day.</param>
    /// <param name="cancellationToken">Cancels the database read.</param>
    /// <returns>The quota status; it performs no write and no locking.</returns>
    /// <exception cref="ArgumentException"><paramref name="nowUtc"/> is not a UTC instant.</exception>
    public static async Task<SeatChangeQuotaStatus> GetStatusAsync(
        LicenseDbContext db,
        License license,
        DateTime nowUtc,
        CancellationToken cancellationToken = default)
    {
        var (dayStart, resetAt) = Day(nowUtc);
        var licenseId = license.Id;
        var used = await db.LicenseSeats
            .Where(seat => seat.LicenseId == licenseId
                && seat.LastActivatedAt >= dayStart
                && seat.LastActivatedAt < resetAt)
            .Select(seat => seat.HardwareId)
            .Distinct()
            .CountAsync(cancellationToken);
        var reactivations = await db.SeatCloneGuardEvents
            .Where(row => row.LicenseId == licenseId
                && row.Kind == SeatCloneGuardEventKinds.Reactivated
                && row.OccurredAt >= dayStart
                && row.OccurredAt < resetAt)
            .CountAsync(cancellationToken);
        return new SeatChangeQuotaStatus(GetDailyLimit(license), used + reactivations, resetAt);
    }

    /// <summary>
    /// Decides whether activating the key on <paramref name="hardwareId"/> now must be refused: true only when the
    /// day's distinct identifiers already reach the limit, the identifier was not already activated today, and it is
    /// not the last PC where the key was successfully activated. Reactivating an identifier already activated today,
    /// or the last PC, is always allowed and adds nothing to the count beyond its own identifier.
    /// </summary>
    /// <param name="db">Context in the caller's admission transaction.</param>
    /// <param name="license">Licence with its <see cref="License.Type"/> loaded; a missing type is unlimited.</param>
    /// <param name="hardwareId">Canonical identifier about to be activated, compared ordinally.</param>
    /// <param name="nowUtc">Current instant with <see cref="DateTimeKind.Utc"/>.</param>
    /// <param name="cancellationToken">Cancels the database reads.</param>
    /// <returns>True when the caller must refuse with its daily-limit error before writing anything.</returns>
    /// <exception cref="ArgumentException"><paramref name="nowUtc"/> is not a UTC instant.</exception>
    public static async Task<bool> IsActivationRefusedAsync(
        LicenseDbContext db,
        License license,
        string hardwareId,
        DateTime nowUtc,
        CancellationToken cancellationToken = default)
    {
        var status = await GetStatusAsync(db, license, nowUtc, cancellationToken);
        if (!status.IsExhausted)
            return false;
        var (dayStart, resetAt) = Day(nowUtc);
        var licenseId = license.Id;
        var alreadyToday = await db.LicenseSeats.AnyAsync(seat =>
            seat.LicenseId == licenseId
            && seat.HardwareId == hardwareId
            && seat.LastActivatedAt >= dayStart
            && seat.LastActivatedAt < resetAt, cancellationToken);
        if (alreadyToday)
            return false;
        // Owner rule: a quota refusal never blocks the licence. The last PC where the key was successfully
        // activated stays usable even when today's quota is exhausted, after any unlink, deactivation or sign-out,
        // as often as wanted. Most recent activation first; seats never activated since the column exists fall back
        // to their last check-in, which an activation also sets.
        var lastHardwareId = await db.LicenseSeats.AsNoTracking()
            .Where(seat => seat.LicenseId == licenseId)
            .OrderByDescending(seat => seat.LastActivatedAt.HasValue)
            .ThenByDescending(seat => seat.LastActivatedAt)
            .ThenByDescending(seat => seat.LastCheckInAt)
            .ThenBy(seat => seat.Id)
            .Select(seat => seat.HardwareId)
            .FirstOrDefaultAsync(cancellationToken);
        return !string.Equals(lastHardwareId, hardwareId, StringComparison.Ordinal);
    }

    /// <summary>Returns the UTC day [start, next midnight) containing <paramref name="nowUtc"/>.</summary>
    /// <param name="nowUtc">Instant that must carry <see cref="DateTimeKind.Utc"/>.</param>
    /// <returns>The inclusive start and exclusive end of the day.</returns>
    /// <exception cref="ArgumentException"><paramref name="nowUtc"/> is not a UTC instant.</exception>
    private static (DateTime Start, DateTime End) Day(DateTime nowUtc)
    {
        // The day boundary and PostgreSQL timestamptz parameters both require a UTC instant;
        // a local or unspecified value would silently shift the counting window.
        if (nowUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The quota clock must be a UTC instant.", nameof(nowUtc));
        var start = nowUtc.Date;
        return (start, start.AddDays(1));
    }
}
