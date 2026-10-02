using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Describes the customer seat-change quota of one licence for the current UTC day.
/// </summary>
/// <param name="Limit">
/// Daily limit read live from <see cref="LicenseType.MaxActivationsPerDay"/>; zero or a negative
/// configured value means unlimited and is reported as zero.
/// </param>
/// <param name="UsedToday">Customer seat releases already counted since UTC midnight.</param>
/// <param name="ResetAtUtc">Next UTC midnight, when the counter starts again from zero.</param>
public sealed record SeatChangeQuotaStatus(int Limit, int UsedToday, DateTime ResetAtUtc)
{
    /// <summary>Gets whether the licence type imposes no daily seat-change limit.</summary>
    public bool IsUnlimited => Limit <= 0;

    /// <summary>Gets the releases still allowed today, or <see langword="null"/> when unlimited.</summary>
    public int? Remaining => IsUnlimited ? null : Math.Max(0, Limit - UsedToday);

    /// <summary>Gets whether a new customer seat release must be refused until <see cref="ResetAtUtc"/>.</summary>
    public bool IsExhausted => !IsUnlimited && UsedToday >= Limit;
}

/// <summary>
/// Single provider authority for the daily customer seat-change quota shared by the Website
/// dashboard, the Desktop deactivation endpoint and the licence read model.
/// </summary>
/// <remarks>
/// <para>
/// A licence is one seat; moving it to another machine is an exceptional, rate-limited customer
/// action. The limit is never cached or hard-coded: every call reads the licence type, so an
/// administrator change in SoftLicence applies to the next request without any client release.
/// </para>
/// <para>
/// The count is event-based. Counting only seats that are still inactive let a customer unlink,
/// reactivate the same seat row and unlink again without ever reaching the limit, because the
/// reactivated row left the count. Durable events cannot disappear that way. The legacy
/// inactive-seat count is kept as a floor so the new rule is never less strict than the previous
/// one, for example for administrator unlinks that have no customer event.
/// </para>
/// <para>
/// Counted events, all on the exact licence and within [UTC midnight, next UTC midnight):
/// portal operations whose outcome is <c>deactivated</c> and whose reason is not the
/// server-owned <c>subscription_termination</c> cleanup; and <c>UNLINKED_API</c> history rows
/// written by customer-facing endpoints (Desktop deactivation, reset code). Portal history rows
/// (<c>S2S:</c> performer) are excluded because their operation row is already counted, and
/// <c>Admin (API)</c> rows are excluded because they are not customer actions. Exact portal
/// replays and <c>already_inactive</c> outcomes create no counted event.
/// </para>
/// <para>
/// Callers that enforce the quota must evaluate it inside the same transaction and lock scope
/// that performs the release, as they already do for the previous count; this helper takes no lock.
/// All string predicates compare server-written constants ordinally and are translated by
/// PostgreSQL as case-sensitive equality and <c>LIKE 'S2S:%'</c> filters under the existing
/// <c>LicenseId</c> indexes.
/// </para>
/// </remarks>
public static class SeatChangeQuota
{
    /// <summary>Server-owned portal cleanup reason that never consumes the customer quota.</summary>
    internal const string SubscriptionTerminationReason = "subscription_termination";

    /// <summary>Performer written by the administrator unlink API; not a customer action.</summary>
    internal const string AdminApiPerformer = "Admin (API)";

    /// <summary>Performer prefix of portal history rows, already counted through their operation row.</summary>
    internal const string PortalPerformerPrefix = "S2S:";

    /// <summary>Terminal portal outcome that released an active seat.</summary>
    internal const string DeactivatedOutcome = "deactivated";

    /// <summary>
    /// Reads the live limit and counts the customer seat releases of the current UTC day.
    /// </summary>
    /// <param name="db">Context whose transaction, when present, scopes the read.</param>
    /// <param name="license">
    /// Licence with its <see cref="License.Type"/> loaded; a missing type is treated as unlimited,
    /// matching the previous enforcement.
    /// </param>
    /// <param name="nowUtc">Current instant with <see cref="DateTimeKind.Utc"/>; defines the UTC day.</param>
    /// <param name="cancellationToken">Cancels the database reads.</param>
    /// <returns>The quota status; it performs no write and no locking.</returns>
    /// <exception cref="ArgumentException"><paramref name="nowUtc"/> is not a UTC instant.</exception>
    public static async Task<SeatChangeQuotaStatus> GetStatusAsync(
        LicenseDbContext db,
        License license,
        DateTime nowUtc,
        CancellationToken cancellationToken = default)
    {
        // The day boundary and PostgreSQL timestamptz parameters both require a UTC instant;
        // a local or unspecified value would silently shift the counting window.
        if (nowUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The quota clock must be a UTC instant.", nameof(nowUtc));

        var dayStart = nowUtc.Date;
        var resetAt = dayStart.AddDays(1);
        var configured = license.Type?.MaxActivationsPerDay ?? 0;
        var limit = configured > 0 ? configured : 0;
        var licenseId = license.Id;

        var portalReleases = await db.PortalDeactivationOperations.CountAsync(operation =>
            operation.LicenseId == licenseId
            && operation.Outcome == DeactivatedOutcome
            && operation.Reason != SubscriptionTerminationReason
            && operation.CreatedAtUtc >= dayStart
            && operation.CreatedAtUtc < resetAt, cancellationToken);

        var clientReleases = await db.LicenseHistories.CountAsync(history =>
            history.LicenseId == licenseId
            && history.Action == HistoryActions.UnlinkedApi
            && history.Timestamp >= dayStart
            && history.Timestamp < resetAt
            && (history.PerformedBy == null
                || (history.PerformedBy != AdminApiPerformer
                    && !history.PerformedBy.StartsWith(PortalPerformerPrefix))), cancellationToken);

        // Previous rule, kept as a floor so no licence becomes less restricted by this change.
        var inactiveSeatsUnlinkedToday = await db.LicenseSeats.CountAsync(seat =>
            seat.LicenseId == licenseId
            && !seat.IsActive
            && seat.UnlinkedAt >= dayStart, cancellationToken);

        var used = Math.Max(portalReleases + clientReleases, inactiveSeatsUnlinkedToday);
        return new SeatChangeQuotaStatus(limit, used, resetAt);
    }
}
