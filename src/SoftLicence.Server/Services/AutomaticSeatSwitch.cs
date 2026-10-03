using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Applies the customer-authorized automatic replacement of a full single-seat licence.
/// Entry points authenticate the request and all target policy before calling this authority;
/// they retain the transaction until the new seat and signed response are durable.
/// </summary>
internal static class AutomaticSeatSwitch
{
    /// <summary>Identifies automatic replacements in the existing customer unlink history.</summary>
    internal const string Source = "automatic_seat_switch";

    /// <summary>Snapshots the observed S2S transport, not an end-user PC address or an untrusted request header.</summary>
    /// <param name="context">The server-owned HTTP context, or null for non-HTTP execution.</param>
    /// <returns>Immutable observations with explicit absence when transport metadata is unavailable.</returns>
    internal static TransportObservation CaptureTransport(HttpContext? context) => new(
        context?.Connection.RemoteIpAddress?.ToString(),
        context?.TraceIdentifier is { Length: > 0 and <= 200 } correlation ? correlation : null);

    /// <summary>Observational metadata only; never participates in licensing, quota or authentication decisions.</summary>
    /// <param name="RemoteAddress">Server-observed transport address; null means unavailable, not loopback.</param>
    /// <param name="CorrelationId">Exact bounded server trace identifier, never a submitted correlation header.</param>
    internal sealed record TransportObservation(string? RemoteAddress, string? CorrelationId);

    /// <summary>
    /// Captures the one losing seat and checks the live daily change quota without releasing it.
    /// Multi-seat licences, free seats and the already active machine require no replacement.
    /// </summary>
    /// <remarks>
    /// The caller must already hold the exclusive Runtime and commercial barriers. PrepareAsync
    /// adds the losing hardware and row locks, then reads PostgreSQL time after all waits.
    /// Exact canonical hardware strings come from the authenticated entry point, not an inferred
    /// alias pair. The quota is event-based; activation/creation alone never consumes it.
    /// </remarks>
    /// <param name="db">Tracked context in the activation transaction.</param>
    /// <param name="license">Authenticated licence with type and seats loaded.</param>
    /// <param name="hardwareId">Canonical target hardware identity.</param>
    /// <param name="fallbackNowUtc">UTC clock for non-relational tests only.</param>
    /// <param name="cancellationToken">Cancels before commit.</param>
    /// <returns>A release plan, or null when no automatic replacement applies.</returns>
    /// <exception cref="DistributionOperationException">The licence, graph or quota refuses replacement.</exception>
    internal static async Task<Plan?> PrepareAsync(
        LicenseDbContext db, License license, string hardwareId, DateTime fallbackNowUtc,
        CancellationToken cancellationToken)
    {
        if (license.MaxSeats != 1)
            return null;
        var active = license.Seats.Where(seat => seat.IsActive).ToArray();
        if (active.Length == 0 || active.Length == 1
            && string.Equals(active[0].HardwareId, hardwareId, StringComparison.Ordinal))
            return null;
        if (active.Length != 1)
            throw new DistributionOperationException("seat_limit_reached", 422);

        var scope = await SeatRuntimeReleaseAuthority.PrepareAsync(
            db, license.ProductId, license, active, fallbackNowUtc, cancellationToken);
        if (!license.IsActive || license.RevokedAt != null
            || license.ExpirationDate is { } expiry && expiry <= scope.ObservedAtUtc
            || license.MaxSeats != 1 || !active[0].IsActive)
            throw new DistributionOperationException("entitlement_ineligible", 422);
        if (license.Type != null)
            await db.Entry(license.Type).ReloadAsync(cancellationToken);
        if (license.Type?.DisableNewActivations == true)
            throw new DistributionOperationException("new_activations_disabled", 422);
        var quota = await SeatChangeQuota.GetStatusAsync(db, license, scope.ObservedAtUtc, cancellationToken);
        if (quota.IsExhausted)
            throw new DistributionOperationException("activation_rate_limited", 422, "seat_change_quota_exhausted");
        return new Plan(active[0], scope);
    }

    /// <summary>
    /// Releases the captured seat through the existing assignment authority and records exactly
    /// one counted unlink. It never commits, deletes historical rows, or changes Runtime identity.
    /// </summary>
    /// <param name="db">The same transaction/context used to prepare the plan.</param>
    /// <param name="license">Licence receiving the new machine in this transaction.</param>
    /// <param name="plan">Locked server-owned losing seat and original assignment snapshot.</param>
    /// <param name="hardwareId">Canonical replacement hardware recorded for history only.</param>
    /// <param name="actor">Authenticated caller or observed request address, never quota-exempt S2S attribution.</param>
    /// <param name="cancellationToken">Cancels the release; the caller must roll back on failure.</param>
    /// <param name="transport">S2S server observation; null preserves the classic entry point's observed actor address.</param>
    internal static async Task CompleteAsync(
        LicenseDbContext db, License license, Plan plan, string hardwareId, string actor,
        CancellationToken cancellationToken, TransportObservation? transport = null)
    {
        plan.Seat.IsActive = false;
        plan.Seat.UnlinkedAt = plan.Scope.ObservedAtUtc;
        license.HardwareId = null;
        license.ActivationDate = null;
        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = license.Id,
            Timestamp = plan.Scope.ObservedAtUtc,
            Action = HistoryActions.UnlinkedApi,
            Details = $"{Source}: {plan.Seat.HardwareId} -> {hardwareId}; actor={actor}"
                + (transport == null ? string.Empty
                    : $"; transport=s2s; remote_address={transport.RemoteAddress ?? "unavailable"}"),
            DecisionCorrelationId = transport?.CorrelationId,
            // Portal's S2S prefix is excluded from this counter because it has a separate
            // operation ledger. Automatic replacement has no such ledger and must count once.
            PerformedBy = Source
        });
        await SeatRuntimeReleaseAuthority.CompleteAsync(db, plan.Scope, [plan.Seat], cancellationToken);
    }

    /// <summary>Immutable release evidence retained under the caller's transaction locks.</summary>
    /// <param name="Seat">Tracked losing seat; FirstActivatedAt remains unchanged.</param>
    /// <param name="Scope">Original assignment snapshot and fresh provider timestamp.</param>
    internal sealed record Plan(LicenseSeat Seat, SeatRuntimeReleaseAuthority.SeatReleaseScope Scope);
}
