using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Restores the current commercial assignment of a cryptographically known Runtime enrollment.
/// Runtime identity and the historical distribution binding remain immutable; only licensing rows
/// and the append-only assignment ledger are changed.
/// </summary>
internal static class RuntimeCommercialAssignmentResolver
{
    /// <summary>
    /// Returns the unique current assignment or creates its next revision against the authenticated
    /// target licence. A seat already carrying the server-derived hardware identifier is reused
    /// without a customer change. Activating a seat (new or released) obeys the daily hardware quota of
    /// <see cref="SeatChangeQuota"/> (TKT-003751: at most N different identifiers per key and UTC day; an identifier
    /// already activated today and the key's last PC are always accepted), checked before any seat changes. After
    /// that check and before any seat of the target licence changes, an active seat that another licence of the same
    /// product holds on the same identifier is released without quota
    /// (<see cref="ReleaseOtherProductSeatsOnHardwareAsync"/>), so a machine never keeps two active seats of one
    /// product.
    /// </summary>
    /// <param name="db">Caller-owned transaction and tracked context.</param>
    /// <param name="enrollment">Cryptographically proved Runtime enrollment.</param>
    /// <param name="license">Authenticated target licence with its type, product and seats loaded.</param>
    /// <param name="subjectRefDigestSha256">Server-owned subject digest from the authenticated grant.</param>
    /// <param name="hardwareId">Canonical hardware identifier derived or selected by the server.</param>
    /// <param name="releaseVersion">Release version whose existing commercial policy remains applicable.</param>
    /// <param name="clientId">Authenticated S2S actor retained only in existing licensing audit rows.</param>
    /// <param name="authorityProof">Exact provider-owned grant row the database must revalidate.</param>
    /// <param name="now">Provider time sampled inside the caller transaction.</param>
    /// <param name="cancellationToken">Cancels without committing a partial seat or assignment transition.</param>
    /// <param name="countKnownSeatTakeover">
    /// TKT-003350, account relink only: when true and the target is a single-seat licence whose seat is held by
    /// another machine, taking it back for an identifier already known to the licence refuses with 503 when the type
    /// is not loaded and records one <see cref="HistoryActions.RuntimeAccountRelinkSeatTakeover"/> history row. Since
    /// TKT-003751 that row is audit only: the quota counts the activated identifier like on every other path.
    /// </param>
    /// <param name="sourceReleasePolicy">
    /// TKT-004062: <see cref="RuntimeCommercialEligibilityValidator.SourceReleaseVersionPolicy.NotJudged"/> only when
    /// <paramref name="releaseVersion"/> is the reinstallation source being replaced; every other licence, seat,
    /// quota and exclusion check still applies. The default keeps the release judged for every other caller.
    /// </param>
    /// <returns>The unique current assignment and whether this call appended it.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// Existing commercial policy refuses the target or the assignment graph is unavailable. Since TKT-004085 a reviewed
    /// refusal of the relink writer is named (<c>license_ineligible</c>, <c>seat_ineligible</c>,
    /// <c>seat_capacity_exceeded</c>, <c>enrollment_inactive</c> as 422, <c>assignment_conflict</c> as 409, the owner
    /// attestation refusal as the opaque 422 <c>authority_ineligible</c>), with the writer message as diagnostic; a
    /// seat-release refusal of another product's seat keeps the named 409 of <see cref="SeatRuntimeReleaseAuthority"/>.
    /// </exception>
    internal static async Task<Resolution> ResolveOrRelinkAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        License license,
        string subjectRefDigestSha256,
        string hardwareId,
        string releaseVersion,
        string clientId,
        AuthorityProof authorityProof,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        bool countKnownSeatTakeover = false,
        RuntimeCommercialEligibilityValidator.SourceReleaseVersionPolicy sourceReleasePolicy =
            RuntimeCommercialEligibilityValidator.SourceReleaseVersionPolicy.Judged)
    {
        if (!string.Equals(
                enrollment.SubjectRefDigestSha256,
                subjectRefDigestSha256,
                StringComparison.Ordinal))
            throw Denied("commercial_authority_ineligible");

        var activeAssignments = await db.EnrollmentLicenseAssignments
            .Where(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE")
            .OrderBy(row => row.Id)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (activeAssignments.Count > 1)
            throw Unavailable("assignment_duplicate_active");
        if (activeAssignments.Count == 1)
            return new Resolution(activeAssignments[0], false);

        // TKT-004158: the refusal names the commercial cause (revoked, inactive, expired, version) so that clients can
        // explain it; a licence of another product or without seats keeps the unpublished commercial_authority_ineligible.
        // The precedence mirrors RuntimeCommercialEligibilityValidator.ClassifyLicenseAndSeat. The public code stays
        // 422 authority_ineligible; callers that store this diagnostic (preflight) map it back to the historical value.
        if (LicenseRefusalReason(license, enrollment.ProductId, releaseVersion, sourceReleasePolicy, now.UtcDateTime)
            is { } licenseRefusal)
            throw Denied(licenseRefusal);

        var activeSeatCount = license.Seats.Count(row => row.IsActive);
        if (activeSeatCount > license.MaxSeats)
            throw Denied("seat_capacity_exceeded");

        // TKT-002041: refuse a licence-excluded machine before any seat reactivation, eviction
        // or quota consumption on the Runtime commercial reattachment path.
        try
        {
            await LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
                db, license.Id, hardwareId, hardwareId, cancellationToken);
        }
        catch (DistributionOperationException exception)
        {
            throw new RuntimeEnrollmentException(exception.ErrorCode, exception.StatusCode, exception.ReasonCode);
        }

        var seat = license.Seats.SingleOrDefault(row => row.IsActive
            && string.Equals(row.HardwareId, hardwareId, StringComparison.Ordinal));
        if (seat is null)
        {
            var knownSeat = license.Seats
                .Where(row => !row.IsActive
                    && string.Equals(row.HardwareId, hardwareId, StringComparison.Ordinal))
                .OrderByDescending(row => row.FirstActivatedAt)
                .ThenBy(row => row.Id)
                .FirstOrDefault();
            var identifierIsKnown = knownSeat is not null;
            var displacesOtherMachine = activeSeatCount >= license.MaxSeats && license.MaxSeats == 1;
            // TKT-003350: an account relink that takes the only seat back from another machine keeps its own history
            // row. A licence whose type is not loaded would read as unlimited on that path: refuse.
            var countedTakeover = countKnownSeatTakeover && displacesOtherMachine && identifierIsKnown;
            if (countedTakeover && license.Type is null)
                throw Unavailable("seat_change_quota_type_missing");
            // TKT-003751 (owner rule, supersedes the TKT-003350 counting): the key may not be activated on more
            // than N different identifiers in one UTC day, N read live from the type. Checked before any seat is
            // touched, so a refusal changes nothing; an identifier already activated today and the key's last PC
            // (its own released seat) are always accepted. The context stamps the activation, which is what counts.
            if (await SeatChangeQuota.IsActivationRefusedAsync(db, license, hardwareId, now.UtcDateTime, cancellationToken))
                throw new RuntimeEnrollmentException(
                    "activation_rate_limited",
                    StatusCodes.Status422UnprocessableEntity,
                    "seat_change_quota_exhausted");

            // TKT-003751: one machine never keeps two active seats of the same product. Release the other
            // licences' seats on this exact identifier after every refusal above and before this licence's
            // seats change (see ReleaseOtherProductSeatsOnHardwareAsync for the ordering constraint).
            await ReleaseOtherProductSeatsOnHardwareAsync(db, license, hardwareId, cancellationToken);
            if (displacesOtherMachine)
            {
                var losingSeat = license.Seats.Single(row => row.IsActive);
                losingSeat.IsActive = false;
                // Historical TKT-003350 shape kept for readers of UnlinkedAt (distribution binding
                // checks): a takeover for a known identifier leaves it null. The quota no longer
                // reads UnlinkedAt (TKT-003751).
                losingSeat.UnlinkedAt = identifierIsKnown ? null : now.UtcDateTime;
                license.HardwareId = null;
                license.ActivationDate = null;
            }

            activeSeatCount = license.Seats.Count(row => row.IsActive);
            if (activeSeatCount >= license.MaxSeats)
                throw Denied("seat_capacity_exceeded");

            if (!identifierIsKnown)
            {
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Timestamp = now.UtcDateTime,
                    Action = HistoryActions.RuntimeCommercialNewIdentifier,
                    Details = "Authenticated Runtime commercial assignment selected a new hardware identifier.",
                    PerformedBy = AutomaticSeatSwitch.Source
                });
            }
            else if (countedTakeover)
            {
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Timestamp = now.UtcDateTime,
                    Action = HistoryActions.RuntimeAccountRelinkSeatTakeover,
                    Details = "Account relink took the only seat back from another machine.",
                    PerformedBy = clientId
                });
            }

            seat = knownSeat;
            var historyAction = "RUNTIME_COMMERCIAL_SEAT_REACTIVATED";
            if (seat is null)
            {
                seat = new LicenseSeat
                {
                    LicenseId = license.Id,
                    HardwareId = hardwareId,
                    FirstActivatedAt = now.UtcDateTime
                };
                db.LicenseSeats.Add(seat);
                historyAction = "RUNTIME_COMMERCIAL_SEAT_CREATED";
            }

            seat.IsActive = true;
            seat.UnlinkedAt = null;
            seat.LastCheckInAt = now.UtcDateTime;
            seat.AppVersion = releaseVersion;
            if (activeSeatCount == 0 || string.IsNullOrEmpty(license.HardwareId))
            {
                license.HardwareId = hardwareId;
                license.ActivationDate = seat.FirstActivatedAt;
                if (license.ValidityDays.HasValue && !license.ExpirationDate.HasValue)
                    license.ExpirationDate = now.UtcDateTime.AddDays(license.ValidityDays.Value);
            }
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Timestamp = now.UtcDateTime,
                Action = historyAction,
                Details = "Authenticated Runtime commercial assignment selected the current seat.",
                PerformedBy = clientId
            });
        }
        else
        {
            // TKT-003751: heal a machine that still holds another licence of the same product (state of
            // 13/11/2026); nothing of this licence is pending yet, so the completion proof sees no target change.
            await ReleaseOtherProductSeatsOnHardwareAsync(db, license, hardwareId, cancellationToken);
            seat.LastCheckInAt = now.UtcDateTime;
            seat.AppVersion = releaseVersion;
        }

        if (license.Seats.Count(row => row.IsActive) > license.MaxSeats)
            throw Denied("seat_capacity_exceeded");

        EnrollmentLicenseAssignment assignment;
        if (db.Database.IsNpgsql())
        {
            if (db.Database.CurrentTransaction is null)
                throw Unavailable("assignment_transaction_missing");
            await db.SaveChangesAsync(cancellationToken);
            try
            {
                await db.Database.ExecuteSqlInterpolatedAsync($"""
                    SELECT public.relink_runtime_commercial_assignment(
                        {enrollment.Id}, {license.Id}, {seat.Id}, {subjectRefDigestSha256},
                        {authorityProof.AuthenticatedClientId}, {authorityProof.DistributionEntitlementId},
                        {authorityProof.RecoveryGrantDigestSha256}, {authorityProof.RecoveryOwnerSubjectId});
                    """, cancellationToken);
            }
            catch (PostgresException exception) when (
                exception.SqlState == PostgresErrorCodes.CheckViolation
                && exception.MessageText.StartsWith(
                    "runtime_commercial_relink_",
                    StringComparison.Ordinal))
            {
                // TKT-004085: a reviewed writer refusal is a licence state (licence or seat ineligible, no free seat,
                // conflicting right) and is named; the owner attestation refusal keeps the opaque authority_ineligible.
                // Only an unknown runtime_commercial_relink_* message stays the former 503 until it is reviewed.
                if (AssignmentRefusals.TryTranslateRelink(exception, out var named))
                    throw named;
                throw Unavailable(exception.MessageText);
            }
            assignment = await db.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleOrDefaultAsync(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE",
                    cancellationToken)
                ?? throw Unavailable("assignment_relation_missing");
            if (assignment.LicenseId != license.Id || assignment.LicenseSeatId != seat.Id)
                throw Unavailable("assignment_scope_conflict");
        }
        else
        {
            var revision = await db.EnrollmentLicenseAssignments
                .Where(row => row.EnrollmentId == enrollment.Id)
                .MaxAsync(row => (int?)row.Revision, cancellationToken) ?? 0;
            assignment = new EnrollmentLicenseAssignment
            {
                EnrollmentId = enrollment.Id,
                LicenseId = license.Id,
                LicenseSeatId = seat.Id,
                State = "ACTIVE",
                ActivatedAtUtc = now.UtcDateTime,
                Revision = checked(revision + 1)
            };
            db.EnrollmentLicenseAssignments.Add(assignment);
        }
        return new Resolution(assignment, true);
    }

    /// <summary>
    /// TKT-003751: deactivates every active seat that another licence of the same product holds on the exact
    /// hardware identifier the resolver is about to use, exactly as key activation does through
    /// <see cref="SeatCleanupService.UnlinkHwidFromOtherProductLicensesAsync"/>. Each released seat keeps its row and
    /// hardware identifier (they are what recognises the same machine later), receives <c>UnlinkedAt</c> and one
    /// <see cref="HistoryActions.AutoUnlinkedProductScope"/> row at the same instant, and its item2 assignment, if
    /// any, is ended by the seat trigger and proved by <see cref="SeatRuntimeReleaseAuthority.CompleteAsync"/>.
    /// Such a release is never a customer seat change: <see cref="SeatChangeQuota"/> ignores it.
    /// </summary>
    /// <remarks>
    /// Every caller already holds the item2 commercial write barrier (advisory lock 1312), which serializes all
    /// commercial seat writers; this method adds the product/hardware lock and the licence and seat row locks in
    /// the order used by <see cref="SeatRuntimeReleaseAuthority.PrepareAsync"/>, so it cannot invert a lock order of
    /// key activation. It runs before the target licence's own seat is changed, because the completion proof saves
    /// pending changes and forces the seat trigger; doing it later would evaluate the target seat before its
    /// assignment exists. Hardware identifiers are canonical server values compared ordinally, as in
    /// <see cref="SeatCleanupService"/> (PostgreSQL text equality, no case folding). History details never carry the
    /// hardware identifier. A refusal thrown later by the resolver rolls the release back with the caller's
    /// transaction.
    /// </remarks>
    /// <param name="db">Caller-owned transaction and tracked context.</param>
    /// <param name="license">The licence the resolver selects; its own seats are never touched here.</param>
    /// <param name="hardwareId">Canonical hardware identifier selected by the server.</param>
    /// <param name="cancellationToken">Cancels before commit.</param>
    /// <exception cref="RuntimeEnrollmentException">
    /// 503 <c>authority_unavailable</c> when a losing licence or seat changed under the locks, or when its
    /// assignment graph is ambiguous (diagnostic code of <see cref="SeatRuntimeReleaseAuthority"/> kept).
    /// </exception>
    private static async Task ReleaseOtherProductSeatsOnHardwareAsync(
        LicenseDbContext db,
        License license,
        string hardwareId,
        CancellationToken cancellationToken)
    {
        var conflictingSeatIds = await db.LicenseSeats.AsNoTracking()
            .Where(row => row.HardwareId == hardwareId
                && row.IsActive
                && row.LicenseId != license.Id
                && row.License != null
                && row.License.ProductId == license.ProductId)
            .OrderBy(row => row.Id)
            .Select(row => row.Id)
            .ToListAsync(cancellationToken);
        if (conflictingSeatIds.Count == 0)
            return;

        try
        {
            var conflictingSeats = await db.LicenseSeats
                .Where(row => conflictingSeatIds.Contains(row.Id))
                .OrderBy(row => row.LicenseId)
                .ThenBy(row => row.Id)
                .ToListAsync(cancellationToken);
            var assignments = new List<SeatRuntimeReleaseAuthority.SeatReleaseAssignment>();
            foreach (var group in conflictingSeats.GroupBy(row => row.LicenseId).OrderBy(group => group.Key))
            {
                var losingLicense = await db.Licenses.SingleOrDefaultAsync(row => row.Id == group.Key, cancellationToken);
                if (losingLicense is null || losingLicense.ProductId != license.ProductId)
                    throw Unavailable("product_scope_loser_license_missing");
                var scope = await SeatRuntimeReleaseAuthority.PrepareAsync(
                    db, license.ProductId, losingLicense, group.ToArray(), DateTime.UtcNow, cancellationToken);
                assignments.AddRange(scope.Assignments);
            }

            // PrepareAsync reloaded every seat under its row lock: a seat freed or moved meanwhile is a race that
            // must fail closed rather than release a seat this call did not observe.
            if (conflictingSeats.Any(row => !row.IsActive
                    || !string.Equals(row.HardwareId, hardwareId, StringComparison.Ordinal)))
                throw Unavailable("product_scope_loser_seat_changed");

            var releasedAt = db.Database.IsRelational()
                ? (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime
                : DateTime.UtcNow;
            foreach (var seat in conflictingSeats)
            {
                seat.IsActive = false;
                // The quota recognises this release by the history row written at this exact instant.
                seat.UnlinkedAt = releasedAt;
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = seat.LicenseId,
                    Action = HistoryActions.AutoUnlinkedProductScope,
                    Details = $"Hardware auto-unlinked: Runtime assignment selected licence {license.Id} (same product)",
                    PerformedBy = "System",
                    Timestamp = releasedAt
                });
            }
            await SeatRuntimeReleaseAuthority.CompleteAsync(
                db, new SeatRuntimeReleaseAuthority.SeatReleaseScope(releasedAt, assignments),
                conflictingSeats, cancellationToken);
        }
        catch (DistributionOperationException exception)
        {
            // TKT-004085: the release refusal keeps its public code, status and reason, and stays the inner cause so
            // that a translated trigger refusal remains traceable in logs.
            throw new RuntimeEnrollmentException(exception.ErrorCode, exception.StatusCode, exception.ReasonCode, exception);
        }
    }

    /// <summary>Resolved commercial assignment and whether a new ledger revision was appended.</summary>
    /// <param name="Assignment">Current assignment selected by server-owned authority.</param>
    /// <param name="Relinked">True only when this call appended a successor revision.</param>
    internal sealed record Resolution(EnrollmentLicenseAssignment Assignment, bool Relinked);

    /// <summary>
    /// Names the exact server-owned grant relation revalidated by the bounded PostgreSQL writer.
    /// Either one Distribution entitlement, one Recovery grant, or neither (TKT-002904 installation-owner
    /// proof, or TKT-002919 account relink proof, where the writer revalidates the client, machine and account
    /// owner itself).
    /// </summary>
    /// <param name="AuthenticatedClientId">Authenticated S2S client bound to the current grant.</param>
    /// <param name="DistributionEntitlementId">Exact current Distribution entitlement, when applicable.</param>
    /// <param name="RecoveryGrantDigestSha256">Exact current Recovery grant digest, when applicable.</param>
    /// <param name="RecoveryOwnerSubjectId">Exact current Recovery owner subject, when applicable.</param>
    internal sealed record AuthorityProof(
        string AuthenticatedClientId,
        Guid? DistributionEntitlementId,
        string? RecoveryGrantDigestSha256,
        Guid? RecoveryOwnerSubjectId)
    {
        /// <summary>Builds proof from one authenticated Distribution entitlement.</summary>
        internal static AuthorityProof Distribution(string clientId, Guid entitlementId) =>
            new(clientId, entitlementId, null, null);

        /// <summary>Builds proof from one authenticated Recovery grant and active owner.</summary>
        internal static AuthorityProof Recovery(
            string clientId,
            string grantDigestSha256,
            Guid ownerSubjectId) =>
            new(clientId, null, grantDigestSha256, ownerSubjectId);

        /// <summary>
        /// TKT-002904: builds proof for a capability request of the installation itself. The writer accepts it
        /// only for the enrollment's own client, for a seat on the enrollment's machine, and for a licence of
        /// the same active owner as the installation licence; a null owner limits the target to that licence.
        /// The caller must have checked the same rules before calling, the subject digest proving nothing here.
        /// </summary>
        /// <param name="enrollmentClientId">The client that created the enrollment.</param>
        /// <param name="ownerSubjectId">Active owner of the installation licence, or null when none is registered.</param>
        internal static AuthorityProof InstallationOwner(string enrollmentClientId, Guid? ownerSubjectId) =>
            new(enrollmentClientId, null, null, ownerSubjectId);

        /// <summary>
        /// TKT-002919: builds proof for an account relink requested by the dedicated relink identity. The writer
        /// accepts it only when a PENDING <c>RuntimeAccountRelinkRequests</c> row of this client, enrollment,
        /// licence, digest and owner exists, its enrollment client is the enrollment's own client, the owner is
        /// ACTIVE for the target and installation licences, and the seat carries the enrollment machine.
        /// TKT-003350: a null owner is accepted only when the target is the installation's own licence; the ledger
        /// row must then carry a null owner too, and no registry row is read.
        /// </summary>
        /// <param name="relinkClientId">Dedicated S2S identity that authenticated the request.</param>
        /// <param name="ownerSubjectId">
        /// Registry owner declared by the website and checked before the call, or null when the website knows no
        /// commercial owner and the target is the installation licence (checked before the call as well).
        /// </param>
        internal static AuthorityProof AccountRelink(string relinkClientId, Guid? ownerSubjectId) =>
            new(relinkClientId, null, null, ownerSubjectId);
    }

    /// <summary>
    /// Returns why the target licence cannot receive a new assignment, or null when it can (TKT-004158). Precedence:
    /// <c>license_revoked</c>, <c>license_inactive</c>, <c>license_expired</c>, then the unpublished
    /// <c>commercial_authority_ineligible</c> for a licence of another product or without seats, then
    /// <c>version_ineligible</c> when the release is judged. Pure function, no database access.
    /// </summary>
    /// <param name="license">Target licence with its product loaded.</param>
    /// <param name="enrollmentProductId">Product of the enrollment, which the licence must share.</param>
    /// <param name="releaseVersion">Release version of the enrollment.</param>
    /// <param name="sourceReleasePolicy">Whether the release version is judged (TKT-004062).</param>
    /// <param name="nowUtc">Provider UTC time; an expiry equal to it already counts as expired.</param>
    private static string? LicenseRefusalReason(
        License license,
        Guid enrollmentProductId,
        string releaseVersion,
        RuntimeCommercialEligibilityValidator.SourceReleaseVersionPolicy sourceReleasePolicy,
        DateTime nowUtc)
    {
        if (license.RevokedAt is not null)
            return RuntimeCommercialEligibilityValidator.LicenseRevokedReason;
        if (!license.IsActive)
            return RuntimeCommercialEligibilityValidator.LicenseInactiveReason;
        if (license.ExpirationDate is { } expiry && expiry <= nowUtc)
            return RuntimeCommercialEligibilityValidator.LicenseExpiredReason;
        if (license.ProductId != enrollmentProductId || license.MaxSeats < 1)
            return "commercial_authority_ineligible";
        if (sourceReleasePolicy == RuntimeCommercialEligibilityValidator.SourceReleaseVersionPolicy.Judged
            && (!RuntimeEnrollmentService.IsVersionAllowed(releaseVersion, license.AllowedVersions)
                || RuntimeEnrollmentService.IsVersionBelow(releaseVersion, license.Product?.MinimumAllowedVersion)))
            return "version_ineligible";
        return null;
    }

    /// <summary>Creates the existing bounded commercial denial without exposing authority data.</summary>
    private static RuntimeEnrollmentException Denied(string diagnosticCode) =>
        new("authority_ineligible", StatusCodes.Status422UnprocessableEntity, diagnosticCode);

    /// <summary>Creates the existing infrastructure outcome for an ambiguous assignment graph.</summary>
    private static RuntimeEnrollmentException Unavailable(string diagnosticCode) =>
        new("authority_unavailable", StatusCodes.Status503ServiceUnavailable, diagnosticCode);
}
