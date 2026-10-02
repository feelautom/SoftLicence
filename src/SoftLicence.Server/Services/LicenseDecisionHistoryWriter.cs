using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Builds immutable licence history decisions inside the caller's existing authority transaction.</summary>
/// <remarks>Never commits, retries, changes licensing predicates, or resolves authority. Callers own locks, rollback and durability. Historical rows are not backfilled.</remarks>
internal static class LicenseDecisionHistoryWriter
{
    /// <summary>Closed history action marking JSON version-one decision content in Details.</summary>
    internal const string Action = "ACTIVATION_DECISION_V1";

    /// <summary>Uses stable web JSON property names and exact string bytes for stored content and digest input.</summary>
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>Captures counts and state versions before business mutation while the caller holds existing authority locks.</summary>
    /// <param name="db">Request-owned context and transaction; its complete licence seat collection must be loaded.</param>
    /// <param name="license">Authoritatively established licence with seats and type, never a telemetry-derived identity.</param>
    /// <param name="now">UTC decision time defining the existing daily activation quota boundary.</param>
    /// <param name="cancellationToken">Cancels observation before a decision is captured.</param>
    /// <param name="resolvedHardwareId">Provider-resolved identity for exact active-seat membership, or null when unresolved.</param>
    /// <param name="observationGuarantee">Explicit existing lock guarantee; legacy callers must use hardware_lock_observation, without claiming global seat serialization.</param>
    /// <returns>Detached immutable values. The global epoch intentionally prevents ABA conflation and can distinguish unrelated authority updates.</returns>
    internal static async Task<LicenseDecisionSnapshot> CaptureAsync(
        LicenseDbContext db, License license, DateTimeOffset now, CancellationToken cancellationToken,
        string? resolvedHardwareId = null, string observationGuarantee = "ordered_authority_locks")
    {
        var epoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(row => row.Id == 1).Select(row => (long?)row.Epoch)
            .SingleOrDefaultAsync(cancellationToken);
        return CaptureObserved(license, now, resolvedHardwareId, observationGuarantee, epoch);
    }

    /// <summary>Freezes already-observed producer values without any post-decision database reread.</summary>
    /// <param name="license">Loaded licence/type/seat values used by the caller's actual predicate.</param>
    /// <param name="now">UTC date defining the producer's observed daily quota window.</param>
    /// <param name="resolvedHardwareId">Provider-resolved identity, or null when not established.</param>
    /// <param name="observationGuarantee">Explicit existing lock guarantee; defaults to legacy observation, not global atomicity.</param>
    /// <param name="authorityEpoch">Epoch already read under authority locks; null for legacy observations.</param>
    /// <returns>Detached snapshot. Callers with a later quota query must replace those counts/details with the exact values used by that predicate.</returns>
    internal static LicenseDecisionSnapshot CaptureObserved(
        License license, DateTimeOffset now, string? resolvedHardwareId,
        string observationGuarantee = "hardware_lock_observation", long? authorityEpoch = null)
    {
        // Ordered anonymous values preserve exact existing HWID strings. Timestamps used by
        // business quota predicates participate; observation time and LastCheckIn do not.
        var seats = license.Seats.OrderBy(row => row.Id)
            .Select(row => new { row.Id, row.HardwareId, row.IsActive, row.FirstActivatedAt, row.UnlinkedAt });
        var activeSeats = license.Seats.Where(row => row.IsActive).OrderBy(row => row.Id).ToArray();
        return new LicenseDecisionSnapshot(license.ProductId, license.Id, license.AuthorityVersion,
            authorityEpoch, license.Seats.Count(row => row.IsActive), license.MaxSeats,
            license.Seats.Count(row => row.FirstActivatedAt >= now.UtcDateTime.Date),
            license.Type?.MaxActivationsPerDay ?? 0, Digest(JsonSerializer.Serialize(seats, JsonOptions)),
            activeSeats.Take(64).Select(row => new LicenseDecisionSeat(
                row.Id, row.HardwareId, row.FirstActivatedAt, row.AppVersion)).ToArray(),
            activeSeats.Length > 64,
            resolvedHardwareId == null ? null : activeSeats.Any(row =>
                string.Equals(row.HardwareId, resolvedHardwareId, StringComparison.Ordinal)),
            observationGuarantee);
    }

    /// <summary>Updates a legacy observation with the exact rows used by its unchanged active-seat quota predicate.</summary>
    /// <remarks>No SQL is issued. Counts and bounded HWID details share the same statement snapshot; hardware_lock_observation still does not prove global serialization across different HWIDs.</remarks>
    /// <param name="snapshot">Previously captured licence context; its commercial limit remains unchanged.</param>
    /// <param name="activeSeats">Complete active rows returned by the producer's exact quota predicate before refusal.</param>
    /// <param name="resolvedHardwareId">Provider-resolved identity used by that predicate, compared ordinally.</param>
    /// <returns>New immutable facts; the seat digest now describes this active predicate set, not unobserved inactive seats.</returns>
    internal static LicenseDecisionSnapshot WithObservedActiveSeats(
        LicenseDecisionSnapshot snapshot, IReadOnlyCollection<LicenseSeat> activeSeats, string resolvedHardwareId)
    {
        var ordered = activeSeats.OrderBy(row => row.Id).ToArray();
        var details = ordered.Take(64).Select(row => new LicenseDecisionSeat(
            row.Id, row.HardwareId, row.FirstActivatedAt, row.AppVersion)).ToArray();
        return snapshot with
        {
            ActiveSeats = activeSeats.Count,
            ActiveSeatDetails = details,
            ActiveSeatDetailsTruncated = activeSeats.Count > 64,
            ResolvedHardwareAlreadyActive = activeSeats.Any(row =>
                string.Equals(row.HardwareId, resolvedHardwareId, StringComparison.Ordinal)),
            SeatStateDigest = Digest(JsonSerializer.Serialize(ordered.Select(row =>
                new { row.Id, row.HardwareId, row.IsActive, row.FirstActivatedAt, row.UnlinkedAt }), JsonOptions))
        };
    }

    /// <summary>Adds at most one event for an exact operation, payload, outcome and context without changing the producer's replay behavior.</summary>
    /// <param name="db">Caller-owned context; authority serialization and the unique database index protect concurrent persistence.</param>
    /// <param name="decision">Frozen version-one facts. Null identity observations remain unknown.</param>
    /// <param name="clientId">Exact authenticated producer namespace, kept only in the digest.</param>
    /// <param name="payloadDigest">Exact producer request digest; legacy callers use their independent server request identity.</param>
    /// <param name="occurredAt">UTC occurrence time, excluded from deduplication.</param>
    /// <param name="cancellationToken">Cancels the duplicate lookup; caller controls any bounded refusal finalization token.</param>
    /// <returns>The existing or newly tracked row. A newly tracked row is not durable until the caller saves and commits.</returns>
    internal static async Task<LicenseHistory> AddAsync(
        LicenseDbContext db, LicenseDecisionHistory decision, string clientId,
        string payloadDigest, DateTimeOffset occurredAt, CancellationToken cancellationToken)
    {
        var details = JsonSerializer.Serialize(decision, JsonOptions);
        // JSON framing prevents delimiter collisions; no casing/Unicode repair is applied to
        // opaque client/request identifiers or submitted/resolved hardware evidence.
        var identityDetails = JsonSerializer.Serialize(decision with { CorrelationId = null }, JsonOptions);
        var key = Digest(JsonSerializer.Serialize(new[] { clientId, payloadDigest, identityDetails }, JsonOptions));
        var tracked = db.LicenseHistories.Local.FirstOrDefault(row =>
            string.Equals(row.DecisionKey, key, StringComparison.Ordinal));
        var existing = tracked ?? await db.LicenseHistories.AsNoTracking()
            .SingleOrDefaultAsync(row => row.DecisionKey == key, cancellationToken);
        if (existing != null)
            return existing;
        var entry = new LicenseHistory
        {
            LicenseId = decision.Snapshot.LicenseId,
            Timestamp = occurredAt.UtcDateTime,
            Action = Action,
            Details = details,
            DecisionKey = key,
            DecisionOperationId = decision.OperationId,
            DecisionCorrelationId = decision.CorrelationId,
            DecisionSubmittedHardwareId = decision.SubmittedHardwareId,
            DecisionResolvedHardwareId = decision.ResolvedHardwareId,
            DecisionCorrelatedHardwareId = decision.CorrelatedHardwareId,
            PerformedBy = "System"
        };
        db.LicenseHistories.Add(entry);
        return entry;
    }

    /// <summary>Hashes exact UTF-8 content to canonical lowercase SHA-256 for ordinal in-memory and indexed SQL equality.</summary>
    private static string Digest(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
