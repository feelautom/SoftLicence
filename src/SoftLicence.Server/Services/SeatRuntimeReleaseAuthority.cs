using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Coordinates commercial seat release without changing Runtime cryptographic identity.
/// Callers authorize the operation and keep every mutation in the returned transaction.
/// </summary>
internal static class SeatRuntimeReleaseAuthority
{
    /// <summary>Historical terminal reason retained for persisted Runtime evidence and item2 assignments.</summary>
    internal const string Reason = "seat_released";

    /// <summary>
    /// Begins a read-committed transaction when needed, then acquires the global Runtime mutation
    /// lock and the item2 commercial-write barrier before any mutable authority row is read.
    /// </summary>
    /// <param name="db">The context that owns the release transaction.</param>
    /// <param name="cancellationToken">Stops the database operation.</param>
    /// <returns>The newly owned transaction, or <see langword="null"/> when the caller already owns one.</returns>
    internal static async Task<IDbContextTransaction?> BeginAsync(
        LicenseDbContext db, CancellationToken cancellationToken = default)
    {
        var transaction = await ProductHardwareSeatLockAuthority.BeginReadCommittedTransactionAsync(db, cancellationToken);
        try
        {
            if (db.Database.IsNpgsql())
            {
                await db.Database.ExecuteSqlRawAsync(
                    "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';",
                    cancellationToken);
                await db.Database.ExecuteSqlRawAsync(
                    "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1); " +
                    "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);",
                    cancellationToken);
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
    /// Locks one licence and its seats in deterministic order after the global barriers, captures
    /// every original ACTIVE assignment, and returns a fresh authoritative database timestamp.
    /// A live Runtime graph without its item2 assignment is reported as infrastructure failure.
    /// </summary>
    /// <param name="db">The context whose transaction already owns both global barriers.</param>
    /// <param name="productId">The exact product that owns the licence.</param>
    /// <param name="license">The tracked licence being released.</param>
    /// <param name="seats">The exact tracked seats that the caller intends to deactivate.</param>
    /// <param name="fallbackNowUtc">The time source used only by non-relational tests.</param>
    /// <param name="cancellationToken">Stops the database operation.</param>
    /// <returns>The authoritative release time and immutable assignment snapshots.</returns>
    /// <exception cref="DistributionOperationException">The commercial relation is missing, ambiguous, or divergent.</exception>
    internal static async Task<SeatReleaseScope> PrepareAsync(
        LicenseDbContext db,
        Guid productId,
        License license,
        IReadOnlyCollection<LicenseSeat> seats,
        DateTime fallbackNowUtc,
        CancellationToken cancellationToken = default)
    {
        if (license.ProductId != productId || seats.Any(seat => seat.LicenseId != license.Id))
            throw Unavailable("seat_release_scope_mismatch");

        var orderedSeats = seats.OrderBy(seat => seat.HardwareId, StringComparer.Ordinal)
            .ThenBy(seat => seat.Id).ToArray();
        foreach (var hardwareId in orderedSeats.Select(seat => seat.HardwareId).Distinct(StringComparer.Ordinal))
            await ProductHardwareSeatLockAuthority.AcquireAsync(db, productId, hardwareId, cancellationToken);

        if (db.Database.IsNpgsql())
        {
            var lockedLicense = await db.Licenses.FromSqlInterpolated(
                    $"SELECT * FROM public.\"Licenses\" WHERE \"Id\" = {license.Id} FOR UPDATE")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
            if (lockedLicense == null || lockedLicense.ProductId != productId)
                throw Unavailable("seat_release_license_missing");

            foreach (var seat in orderedSeats.OrderBy(candidate => candidate.Id))
            {
                var lockedSeat = await db.LicenseSeats.FromSqlInterpolated(
                        $"SELECT * FROM public.\"LicenseSeats\" WHERE \"Id\" = {seat.Id} FOR UPDATE")
                    .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
                if (lockedSeat == null || lockedSeat.LicenseId != license.Id)
                    throw Unavailable("seat_release_seat_missing");
            }
        }

        await db.Entry(license).ReloadAsync(cancellationToken);
        foreach (var seat in orderedSeats)
            await db.Entry(seat).ReloadAsync(cancellationToken);

        var snapshots = new List<SeatReleaseAssignment>();
        // TKT-001277 lot 2d: each assignment check below keeps its original refusal; with the switch open it
        // records "would have blocked" and releases the seat without that assignment snapshot instead.
        bool? switchOpen = null;
        async Task<bool> IsSwitchOpenAsync() =>
            switchOpen ??= await AssignmentEnforcement.IsOpenAsync(db, cancellationToken);
        foreach (var seat in orderedSeats.OrderBy(candidate => candidate.Id))
        {
            var assignments = db.Database.IsNpgsql()
                ? await db.EnrollmentLicenseAssignments.FromSqlInterpolated(
                        $"SELECT * FROM public.\"EnrollmentLicenseAssignments\" WHERE \"LicenseSeatId\" = {seat.Id} ORDER BY \"Revision\", \"Id\" FOR UPDATE")
                    .AsNoTracking().ToListAsync(cancellationToken)
                : await db.EnrollmentLicenseAssignments.AsNoTracking()
                    .Where(candidate => candidate.LicenseSeatId == seat.Id)
                    .OrderBy(candidate => candidate.Revision).ThenBy(candidate => candidate.Id)
                    .ToListAsync(cancellationToken);
            var activeAssignments = assignments.Where(candidate => candidate.State == "ACTIVE").ToArray();
            if (activeAssignments.Length > 1)
            {
                if (!await IsSwitchOpenAsync())
                    throw Unavailable("seat_release_assignment_ambiguous");
                AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_assignment_ambiguous",
                    "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_assignment_ambiguous");
                continue;
            }

            var liveEnrollmentIds = await db.RuntimeEnrollments.AsNoTracking()
                .Where(candidate => candidate.LicenseSeatId == seat.Id
                    && (candidate.State == "PENDING" || candidate.State == "ACTIVE"))
                .Select(candidate => candidate.Id).OrderBy(candidate => candidate).ToListAsync(cancellationToken);
            if (liveEnrollmentIds.Count > 1)
            {
                if (!await IsSwitchOpenAsync())
                    throw Unavailable("seat_release_enrollment_ambiguous");
                AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_enrollment_ambiguous",
                    "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_enrollment_ambiguous");
                continue;
            }
            if (liveEnrollmentIds.Count == 0)
            {
                if (assignments.Count != 0)
                {
                    if (!await IsSwitchOpenAsync())
                        throw Unavailable("seat_release_assignment_without_runtime");
                    AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_assignment_without_runtime",
                        "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_assignment_without_runtime");
                }
                continue;
            }

            EnrollmentLicenseAssignment assignment;
            string expectedEndReason;
            DateTime? expectedEndedAtUtc;
            if (activeAssignments.Length == 1)
            {
                assignment = activeAssignments[0];
                expectedEndReason = Reason;
                expectedEndedAtUtc = null;
            }
            else
            {
                var immutableLicenseRevocation = assignments.Where(candidate =>
                    candidate.State == "ENDED" && candidate.EndReason == "license_revoked").ToArray();
                if (assignments.Count != 1 || immutableLicenseRevocation.Length != 1)
                {
                    if (!await IsSwitchOpenAsync())
                        throw Unavailable("seat_release_assignment_missing");
                    AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_assignment_missing",
                        "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_assignment_missing");
                    continue;
                }
                assignment = immutableLicenseRevocation[0];
                expectedEndReason = "license_revoked";
                expectedEndedAtUtc = assignment.EndedAtUtc;
            }
            if (assignment.LicenseId != license.Id
                || assignment.EnrollmentId != liveEnrollmentIds[0])
            {
                if (!await IsSwitchOpenAsync())
                    throw Unavailable("seat_release_assignment_diverged");
                AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_assignment_diverged",
                    "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_assignment_diverged");
                continue;
            }
            snapshots.Add(new SeatReleaseAssignment(
                assignment.Id, assignment.EnrollmentId, assignment.LicenseId,
                assignment.LicenseSeatId, assignment.Revision, expectedEndReason, expectedEndedAtUtc));
        }

        var observedAtUtc = db.Database.IsRelational()
            ? (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime
            : DateTime.SpecifyKind(fallbackNowUtc, DateTimeKind.Utc);
        return new SeatReleaseScope(observedAtUtc, snapshots);
    }

    /// <summary>
    /// Persists the commercial release, forces the item2 seat trigger, and proves that each
    /// original assignment ended without revision or successor changes. Runtime rows are read only.
    /// </summary>
    /// <param name="db">The context containing the pending commercial mutations.</param>
    /// <param name="scope">The immutable authority captured before mutation.</param>
    /// <param name="seats">The exact seats whose ACTIVE successors must remain absent.</param>
    /// <param name="cancellationToken">Stops the database operation.</param>
    /// <exception cref="DistributionOperationException">The trigger result differs from the captured authority.</exception>
    internal static async Task CompleteAsync(
        LicenseDbContext db,
        SeatReleaseScope scope,
        IReadOnlyCollection<LicenseSeat> seats,
        CancellationToken cancellationToken = default)
    {
        await db.SaveChangesAsync(cancellationToken);
        if (db.Database.IsNpgsql())
        {
            await db.Database.ExecuteSqlRawAsync(
                "SET CONSTRAINTS \"TR_LicenseSeats_AssignmentDualWrite\" IMMEDIATE; " +
                "SET CONSTRAINTS \"TR_LicenseSeats_AssignmentDualWrite\" DEFERRED;",
                cancellationToken);
        }

        // TKT-001277 lot 2d: same switch as PrepareAsync. With the switch open the two post-release proofs record
        // "would have blocked" and the release stands.
        bool? switchOpen = null;
        var recorded = false;
        async Task<bool> IsSwitchOpenAsync() =>
            switchOpen ??= await AssignmentEnforcement.IsOpenAsync(db, cancellationToken);
        foreach (var original in scope.Assignments)
        {
            var ended = await db.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == original.AssignmentId, cancellationToken);
            if (ended == null || ended.EnrollmentId != original.EnrollmentId
                || ended.LicenseId != original.LicenseId || ended.LicenseSeatId != original.LicenseSeatId
                || ended.Revision != original.Revision || ended.State != "ENDED"
                || ended.EndReason != original.ExpectedEndReason || ended.EndedAtUtc == null
                || (original.ExpectedEndedAtUtc != null
                    && ended.EndedAtUtc != original.ExpectedEndedAtUtc))
            {
                if (!await IsSwitchOpenAsync())
                    throw Unavailable("seat_release_assignment_not_ended");
                AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl,
                    "seat_release_assignment_not_ended", "release_kept", original.LicenseId,
                    original.LicenseSeatId, original.EnrollmentId,
                    $"assignment={original.AssignmentId:D} reason=seat_release_assignment_not_ended");
                recorded = true;
            }
        }

        var seatIds = seats.Select(seat => seat.Id).ToArray();
        var enrollmentIds = scope.Assignments.Select(assignment => assignment.EnrollmentId).ToArray();
        if (await db.EnrollmentLicenseAssignments.AsNoTracking().AnyAsync(candidate =>
                candidate.State == "ACTIVE"
                && (seatIds.Contains(candidate.LicenseSeatId)
                    || enrollmentIds.Contains(candidate.EnrollmentId)), cancellationToken))
        {
            if (!await IsSwitchOpenAsync())
                throw Unavailable("seat_release_successor_active");
            AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl,
                "seat_release_successor_active", "release_kept", null, seatIds.FirstOrDefault(), null,
                $"seats={string.Join(',', seatIds)} reason=seat_release_successor_active");
            recorded = true;
        }
        if (recorded)
            await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Creates the bounded infrastructure failure used for an unsafe release graph.</summary>
    /// <param name="diagnosticCode">The internal bounded reason; it never contains hardware data.</param>
    /// <returns>A public 503 authority failure with the internal diagnostic attached.</returns>
    private static DistributionOperationException Unavailable(string diagnosticCode) =>
        new("authority_unavailable", StatusCodes.Status503ServiceUnavailable, diagnosticCode);

    /// <summary>Captures the authoritative release instant and original assignments.</summary>
    /// <param name="ObservedAtUtc">The fresh database time after all decisive waits.</param>
    /// <param name="Assignments">The exact assignment rows that completion must verify.</param>
    internal sealed record SeatReleaseScope(
        DateTime ObservedAtUtc,
        IReadOnlyList<SeatReleaseAssignment> Assignments);

    /// <summary>Captures immutable assignment fields that must survive commercial termination.</summary>
    /// <param name="AssignmentId">The original assignment identifier.</param>
    /// <param name="EnrollmentId">The original enrollment identifier.</param>
    /// <param name="LicenseId">The original licence identifier.</param>
    /// <param name="LicenseSeatId">The original seat identifier.</param>
    /// <param name="Revision">The original commercial revision.</param>
    /// <param name="ExpectedEndReason">The exact terminal reason allowed after completion.</param>
    /// <param name="ExpectedEndedAtUtc">The immutable terminal instant, or null for an ACTIVE capture.</param>
    internal sealed record SeatReleaseAssignment(
        Guid AssignmentId,
        Guid EnrollmentId,
        Guid LicenseId,
        Guid LicenseSeatId,
        int Revision,
        string ExpectedEndReason,
        DateTime? ExpectedEndedAtUtc);
}
