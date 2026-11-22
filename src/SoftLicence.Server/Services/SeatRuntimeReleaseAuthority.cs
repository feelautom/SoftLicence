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
    /// Row-locking read of every assignment revision of one seat; <c>{0}</c> is the seat identifier.
    /// PostgreSQL requires UPDATE privilege on at least one column for <c>FOR UPDATE</c>, while the
    /// application role is otherwise read-only on this table: the lock right is granted on
    /// <c>"Id"</c> only by the <c>GrantSeatReleaseAssignmentRowLock</c> migration.
    /// </summary>
    internal const string AssignmentRowLockSql =
        "SELECT * FROM public.\"EnrollmentLicenseAssignments\" WHERE \"LicenseSeatId\" = {0} ORDER BY \"Revision\", \"Id\" FOR UPDATE";

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
    /// A commercial assignment graph that only support can resolve (live Runtime graph without its item2 assignment,
    /// ambiguous or diverging rights) is refused with the named 409 <c>assignment_reconciliation_required</c>
    /// (TKT-004085); a scope mismatch or a row deleted under the lock stays a 503 <c>authority_unavailable</c>.
    /// </summary>
    /// <remarks>
    /// Per seat (TKT-001428): the live installation of a seat is the PENDING or ACTIVE enrollment holding the seat's
    /// ACTIVE right, or else an enrollment created on that seat whose ACTIVE right is not on another seat (an account
    /// relink moves the right without changing the enrollment's <c>LicenseSeatId</c>). A seat without a live
    /// installation is released without snapshot when none of its assignments is ACTIVE, and refused
    /// (<c>seat_release_assignment_without_runtime</c>) when one still is. A seat with one live installation and no
    /// ACTIVE assignment is accepted only when that installation's single
    /// assignment ended with <c>license_revoked</c>; ENDED rows of earlier installations are ignored. Every refusal
    /// is recorded and let through instead while the assignment switch is open (<see cref="AssignmentEnforcement"/>).
    /// </remarks>
    /// <param name="db">The context whose transaction already owns both global barriers.</param>
    /// <param name="productId">The exact product that owns the licence.</param>
    /// <param name="license">The tracked licence being released.</param>
    /// <param name="seats">The exact tracked seats that the caller intends to deactivate.</param>
    /// <param name="fallbackNowUtc">The time source used only by non-relational tests.</param>
    /// <param name="cancellationToken">Stops the database operation.</param>
    /// <returns>The authoritative release time and immutable assignment snapshots.</returns>
    /// <exception cref="DistributionOperationException">
    /// 409 <c>assignment_reconciliation_required</c> when the commercial relation is missing, ambiguous or divergent
    /// and the switch is closed (bounded <c>seat_release_*</c> reason); 503 <c>authority_unavailable</c> when the scope
    /// does not match or a locked row disappeared.
    /// </exception>
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
                ? await db.EnrollmentLicenseAssignments.FromSqlRaw(AssignmentRowLockSql, seat.Id)
                    .AsNoTracking().ToListAsync(cancellationToken)
                : await db.EnrollmentLicenseAssignments.AsNoTracking()
                    .Where(candidate => candidate.LicenseSeatId == seat.Id)
                    .OrderBy(candidate => candidate.Revision).ThenBy(candidate => candidate.Id)
                    .ToListAsync(cancellationToken);
            var activeAssignments = assignments.Where(candidate => candidate.State == "ACTIVE").ToArray();
            if (activeAssignments.Length > 1)
            {
                if (!await IsSwitchOpenAsync())
                    throw ReconciliationRequired("seat_release_assignment_ambiguous");
                AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_assignment_ambiguous",
                    "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_assignment_ambiguous");
                continue;
            }

            // TKT-001428 (c): a live installation belongs to the seat that holds its ACTIVE right. An account relink
            // moves the right to the seat of another licence while the enrollment keeps its original LicenseSeatId
            // (its Runtime identity never changes), so the lookup by LicenseSeatId alone missed the installation on
            // the new seat and refused the website sign-out, and counted it on the seat it had left. Rights of other
            // seats are read without row locks: both global barriers taken by BeginAsync already serialize every
            // Runtime and commercial-assignment mutation.
            var activeEnrollmentIdsOnSeat = activeAssignments.Select(candidate => candidate.EnrollmentId).ToArray();
            var liveEnrollmentIds = await db.RuntimeEnrollments.AsNoTracking()
                .Where(candidate => (candidate.State == "PENDING" || candidate.State == "ACTIVE")
                    && (activeEnrollmentIdsOnSeat.Contains(candidate.Id)
                        || (candidate.LicenseSeatId == seat.Id
                            && !db.EnrollmentLicenseAssignments.Any(right => right.EnrollmentId == candidate.Id
                                && right.State == "ACTIVE" && right.LicenseSeatId != seat.Id))))
                .Select(candidate => candidate.Id).OrderBy(candidate => candidate).ToListAsync(cancellationToken);
            if (liveEnrollmentIds.Count > 1)
            {
                if (!await IsSwitchOpenAsync())
                    throw ReconciliationRequired("seat_release_enrollment_ambiguous");
                AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl, "seat_release_enrollment_ambiguous",
                    "released_without_assignment_snapshot", license.Id, seat.Id, null, $"seat={seat.Id:D} reason=seat_release_enrollment_ambiguous");
                continue;
            }
            if (liveEnrollmentIds.Count == 0)
            {
                // TKT-001428: only an ACTIVE right without a live installation is inconsistent. A seat whose history
                // is entirely ENDED (enrollment invalidated by the UUID migration, a reinstall or an earlier release)
                // has nothing left to end and is the normal state of a seat being released or switched; refusing it
                // blocked three legitimate customers in production (portal deactivation, automatic seat switch).
                if (activeAssignments.Length != 0)
                {
                    if (!await IsSwitchOpenAsync())
                        throw ReconciliationRequired("seat_release_assignment_without_runtime");
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
                // TKT-001428: judge only the rights of the live installation. ENDED rows of earlier installations
                // of the same seat are closed history and cannot hold the seat (no ACTIVE row exists here); counting
                // them refused a seat whose live installation lost its right through a licence revocation.
                var liveEnrollmentAssignments = assignments
                    .Where(candidate => candidate.EnrollmentId == liveEnrollmentIds[0]).ToArray();
                var immutableLicenseRevocation = liveEnrollmentAssignments.Where(candidate =>
                    candidate.State == "ENDED" && candidate.EndReason == "license_revoked").ToArray();
                if (liveEnrollmentAssignments.Length != 1 || immutableLicenseRevocation.Length != 1)
                {
                    if (!await IsSwitchOpenAsync())
                        throw ReconciliationRequired("seat_release_assignment_missing");
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
                    throw ReconciliationRequired("seat_release_assignment_diverged");
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
    /// <exception cref="DistributionOperationException">
    /// 409 <c>assignment_reconciliation_required</c> when the trigger result differs from the captured authority, or
    /// when the assignment trigger itself refuses the release (quarantined installation, unresolved graph); 409
    /// <c>seat_assignment_busy</c> when it reports a concurrent claimant. The caller's transaction must then be rolled
    /// back, which leaves the seat exactly as it was.
    /// </exception>
    internal static async Task CompleteAsync(
        LicenseDbContext db,
        SeatReleaseScope scope,
        IReadOnlyCollection<LicenseSeat> seats,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            if (db.Database.IsNpgsql())
            {
                await db.Database.ExecuteSqlRawAsync(
                    "SET CONSTRAINTS \"TR_LicenseSeats_AssignmentDualWrite\" IMMEDIATE; " +
                    "SET CONSTRAINTS \"TR_LicenseSeats_AssignmentDualWrite\" DEFERRED;",
                    cancellationToken);
            }
        }
        catch (Exception exception) when (AssignmentRefusals.TryTranslate(exception, out var refusal))
        {
            // TKT-004085: the assignment trigger fires here (forced IMMEDIATE, or BEFORE triggers at SaveChanges). Its
            // refusal is a legitimate licence state, not an outage: every release caller receives the named code instead
            // of an unhandled PostgresException (empty HTTP 500). Any other database error propagates unchanged.
            throw refusal;
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
                    throw ReconciliationRequired("seat_release_assignment_not_ended");
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
                throw ReconciliationRequired("seat_release_successor_active");
            AssignmentEnforcement.Record(db, AssignmentEnforcement.SeatReleaseControl,
                "seat_release_successor_active", "release_kept", null, seatIds.FirstOrDefault(), null,
                $"seats={string.Join(',', seatIds)} reason=seat_release_successor_active");
            recorded = true;
        }
        if (recorded)
            await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Creates the bounded infrastructure failure kept for a release scope that does not match its caller or a row that
    /// disappeared under the lock: these are code invariants or concurrent deletions, not a licence state to explain.
    /// </summary>
    /// <param name="diagnosticCode">The internal bounded reason; it never contains hardware data.</param>
    /// <returns>A public 503 authority failure with the internal diagnostic attached.</returns>
    private static DistributionOperationException Unavailable(string diagnosticCode) =>
        new("authority_unavailable", StatusCodes.Status503ServiceUnavailable, diagnosticCode);

    /// <summary>
    /// Creates the named 409 refusal for an assignment graph that only a support reconciliation can resolve
    /// (TKT-004085). It replaced the former 503 <c>authority_unavailable</c>, which made clients report an outage.
    /// </summary>
    /// <param name="diagnosticCode">The bounded <c>seat_release_*</c> reason, returned as <c>reasonCode</c>; never hardware data.</param>
    /// <returns>The refusal to throw; the caller's transaction rolls back and nothing is released.</returns>
    private static DistributionOperationException ReconciliationRequired(string diagnosticCode) =>
        AssignmentRefusals.ReconciliationRequired(diagnosticCode);

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
