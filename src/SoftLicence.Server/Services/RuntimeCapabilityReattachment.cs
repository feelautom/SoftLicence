using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// TKT-002904: decides the capability outcome of a healthy Runtime installation whose seat was released
/// (sign out, unlink, exclusion, member removal, automatic seat switch). Such an installation is not
/// refused for good: it receives a non-terminal 409 until a seat of the same account owner is active on
/// the same machine, which is then reattached. A seat is never taken, created or switched here.
/// </summary>
/// <remarks>
/// <para>
/// Only <c>assignment_missing</c> is reconsidered. Every other commercial denial (ban, revocation,
/// quarantine, version, capacity) keeps its historical 422 <c>authority_ineligible</c> response.
/// </para>
/// <para>
/// The non-terminal signal requires all of: an ACTIVE enrollment on an active binding, no assignment
/// quarantine, a latest ENDED assignment whose reason is <c>seat_released</c>, a licence of that
/// assignment that is still active, unrevoked, unexpired and admits the installed version, and no live
/// hardware ban on that seat's machine nor component ban on the installed binaries.
/// </para>
/// <para>
/// Account identity is the ACTIVE row of <c>RuntimeRecoveryCommercialOwnerships</c>: the enrollment
/// subject digest depends on the licence and therefore cannot prove that two licences share an owner.
/// The PostgreSQL writer revalidates the owner, machine and client relation before appending the
/// assignment, so this class never grants authority on its own reads.
/// </para>
/// </remarks>
internal static class RuntimeCapabilityReattachment
{
    /// <summary>Public error of a healthy installation without a current seat; clients must not treat it as terminal.</summary>
    internal const string LicenseUnassignedError = "capability_license_unassigned";

    /// <summary>Public error when the only seat on this machine belongs to another account owner.</summary>
    internal const string OtherAccountError = "capability_license_other_account";

    /// <summary>Licence history action recorded when a capability request reattaches an existing seat.</summary>
    internal const string ReattachedHistoryAction = "RUNTIME_CAPABILITY_SEAT_REATTACHED";

    /// <summary>
    /// Returns the current eligible assignment, reattaching an existing same-owner seat on this machine when
    /// the previous seat was released. Throws the historical 422 for every other denial, and a 409 without
    /// any write when the installation is healthy but no reattachable seat exists.
    /// </summary>
    /// <param name="db">Context whose transaction holds the Runtime authority lease and the locked enrollment.</param>
    /// <param name="enrollment">Cryptographically proved enrollment, locked for update by the caller.</param>
    /// <param name="approvedBinaries">Validated binaries of the installed release, used for component bans.</param>
    /// <param name="now">Provider time sampled inside the caller transaction.</param>
    /// <param name="cancellationToken">Cancels without committing a partial reattachment.</param>
    /// <returns>The eligible assignment, either current or freshly reattached.</returns>
    /// <exception cref="RuntimeEnrollmentException">422 for policy denials, 409 for the two non-terminal outcomes.</exception>
    internal static async Task<RuntimeCommercialEligibilityValidator.EligibleAssignment> ValidateOrReattachAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var decision = await DecideAsync(db, enrollment, approvedBinaries, now, cancellationToken);
        if (decision.Eligible is not null)
            return decision.Eligible;
        if (decision.Target is null)
            throw decision.Refusal!;

        // A reattachment is a commercial write: take the exclusive item-2 barrier after the enrollment row
        // lock already held by the caller, then decide again so no concurrent release or ban is missed.
        await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
        now = await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken);
        decision = await DecideAsync(db, enrollment, approvedBinaries, now, cancellationToken);
        if (decision.Eligible is not null)
            return decision.Eligible;
        if (decision.Target is null)
            throw decision.Refusal!;

        var target = decision.Target;
        var license = await db.Licenses
            .Include(row => row.Product)
            .Include(row => row.Type)
            .Include(row => row.Seats)
            .SingleAsync(row => row.Id == target.LicenseId, cancellationToken);
        _ = await RuntimeCommercialAssignmentResolver.ResolveOrRelinkAsync(
            db,
            enrollment,
            license,
            enrollment.SubjectRefDigestSha256 ?? string.Empty,
            target.HardwareId,
            enrollment.ReleaseVersion,
            enrollment.ClientId,
            RuntimeCommercialAssignmentResolver.AuthorityProof.InstallationOwner(
                enrollment.ClientId, target.OwnerSubjectId),
            now,
            cancellationToken);
        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = license.Id,
            Timestamp = now.UtcDateTime,
            Action = ReattachedHistoryAction,
            Details = "A healthy Runtime installation of the same account owner reattached the seat already active on its machine.",
            PerformedBy = enrollment.ClientId
        });
        await db.SaveChangesAsync(cancellationToken);

        // The reattached assignment must pass the complete current policy, including bans and version.
        return await RuntimeCommercialEligibilityValidator.ValidateAsync(
            db, enrollment, approvedBinaries, now, cancellationToken);
    }

    /// <summary>Read-only outcome: an eligible assignment, a reattachment target, or the refusal to throw.</summary>
    /// <param name="Eligible">Current eligible assignment, when one exists.</param>
    /// <param name="Target">Same-owner seat on this machine that may be reattached.</param>
    /// <param name="Refusal">Exact refusal when neither of the above applies.</param>
    private sealed record Decision(
        RuntimeCommercialEligibilityValidator.EligibleAssignment? Eligible,
        ReattachTarget? Target,
        RuntimeEnrollmentException? Refusal);

    /// <summary>One active seat of a same-owner licence carrying this installation's machine identifier.</summary>
    /// <param name="LicenseId">Target licence.</param>
    /// <param name="SeatId">Existing active seat.</param>
    /// <param name="HardwareId">Exact seat hardware value whose digest equals the enrollment hardware digest.</param>
    /// <param name="OwnerSubjectId">
    /// Account owner shared by the installation licence and the target licence, or null when the installation
    /// licence has no registered owner, in which case the target is that same licence.
    /// </param>
    private sealed record ReattachTarget(Guid LicenseId, Guid SeatId, string HardwareId, Guid? OwnerSubjectId);

    /// <summary>
    /// Evaluates the current assignment, then the seat-released signal and the same-owner candidates, without writing.
    /// </summary>
    private static async Task<Decision> DecideAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
            db, enrollment, approvedBinaries, now, null, cancellationToken);
        if (assessment.IsEligible)
            return new Decision(assessment.Assignment, null, null);
        // TKT-004158: the refusal carries the finer licence reason; the assignment_missing test below still reads the
        // stored DenialReason, whose values are unchanged.
        var historical = Denied(assessment.RefusalReason);
        if (!string.Equals(assessment.DenialReason, "assignment_missing", StringComparison.Ordinal))
            return new Decision(null, null, historical);
        var released = await FindHealthyReleasedSeatAsync(
            db, enrollment, approvedBinaries, now, cancellationToken);
        if (released is null)
            return new Decision(null, null, historical);
        var releasedHardwareId = released.HardwareId;

        // The released seat names this machine only if its exact value hashes to the enrollment digest.
        if (!string.Equals(HardwareDigest(releasedHardwareId), enrollment.HardwareIdHash, StringComparison.Ordinal))
            return new Decision(null, null, Conflict(LicenseUnassignedError));

        var installationOwner = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .Where(row => row.ProductId == enrollment.ProductId
                && row.LicenseId == enrollment.LicenseId && row.State == "ACTIVE")
            .Select(row => (Guid?)row.OwnerSubjectId)
            .SingleOrDefaultAsync(cancellationToken);

        // Exact ordinal equality, as the resolver selects its seat. Seats already serving another enrollment
        // are not free: the ACTIVE assignment index is unique per seat.
        var onThisMachine = await db.LicenseSeats.AsNoTracking()
            .Where(seat => seat.IsActive && seat.HardwareId == releasedHardwareId
                && seat.License!.ProductId == enrollment.ProductId
                && !db.EnrollmentLicenseAssignments.Any(assignment =>
                    assignment.LicenseSeatId == seat.Id && assignment.State == "ACTIVE"))
            .OrderByDescending(seat => seat.FirstActivatedAt)
            .ThenBy(seat => seat.Id)
            .Select(seat => new
            {
                seat.Id,
                seat.LicenseId,
                seat.HardwareId,
                Owner = db.RuntimeRecoveryCommercialOwnerships
                    .Where(owner => owner.ProductId == enrollment.ProductId
                        && owner.LicenseId == seat.LicenseId && owner.State == "ACTIVE")
                    .Select(owner => (Guid?)owner.OwnerSubjectId)
                    .FirstOrDefault()
            })
            .ToListAsync(cancellationToken);
        // Same owner is proved by the registry. A licence without a known owner can only take back a seat of the
        // installation's own licence on this machine; the PostgreSQL writer revalidates both rules.
        // A licence whose seats are managed by its administrator (key activation disabled, TKT-002475, Team)
        // never moves to another licence: the registry owner is the organisation, not the member, and a
        // member's unlink must not be undone by another key of that organisation active on this machine.
        var ownLicenseOnly = installationOwner is null
            || await LicenseKeyActivationChecker.IsDisabledAsync(db, enrollment.LicenseId, cancellationToken)
            || released.LicenseId != enrollment.LicenseId
                && await LicenseKeyActivationChecker.IsDisabledAsync(db, released.LicenseId, cancellationToken);
        var sameOwner = ownLicenseOnly
            ? onThisMachine.FirstOrDefault(seat => seat.LicenseId == enrollment.LicenseId)
            : onThisMachine.FirstOrDefault(seat => seat.Owner == installationOwner);
        if (sameOwner is not null)
            return new Decision(null,
                new ReattachTarget(sameOwner.LicenseId, sameOwner.Id, sameOwner.HardwareId, installationOwner),
                null);
        if (installationOwner is not null
            && onThisMachine.Any(seat => seat.Owner is not null && seat.Owner != installationOwner))
            return new Decision(null, null, Conflict(OtherAccountError));
        return new Decision(null, null, Conflict(LicenseUnassignedError));
    }

    /// <summary>
    /// Returns the released seat's licence and exact hardware value when the installation is healthy and its latest ended
    /// assignment was a seat release on a licence still usable by this release; otherwise null, which keeps
    /// the historical terminal 422.
    /// </summary>
    private static async Task<ReleasedSeat?> FindHealthyReleasedSeatAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        (await AssessReleasedSeatAsync(db, enrollment, approvedBinaries, now, cancellationToken)).Seat;

    /// <summary>
    /// Shared entry condition of every seat-released repair path: the capability 409 of TKT-002904 and the account
    /// relink of TKT-002919 call this one predicate, never a copy. The seat is returned only when the enrollment is
    /// ACTIVE on an active binding, without assignment quarantine, its latest ENDED assignment ended with
    /// <c>seat_released</c>, that licence is of the same product, active, unrevoked, unexpired and admits the
    /// installed version, and no live hardware ban, licence exclusion or component ban applies. Read-only.
    /// </summary>
    /// <param name="db">Context of the caller transaction; nothing is written.</param>
    /// <param name="enrollment">Locked enrollment under evaluation.</param>
    /// <param name="approvedBinaries">Validated binaries of the installed release, for component bans.</param>
    /// <param name="now">Provider time sampled inside the caller transaction.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <returns>
    /// The healthy released seat, or no seat; <see cref="ReleasedSeatAssessment.Excluded"/> is true only when the
    /// sole failing condition reached is a licence exclusion of that machine, so a caller with its own public
    /// exclusion code can name it, while the capability keeps its historical 422.
    /// </returns>
    internal static async Task<ReleasedSeatAssessment> AssessReleasedSeatAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var none = new ReleasedSeatAssessment(null, false);
        if (!string.Equals(enrollment.State, "ACTIVE", StringComparison.Ordinal))
            return none;
        var bindingActive = await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(binding =>
            binding.Id == enrollment.BindingId && binding.State == "active"
            && binding.InvalidatedAtUtc == null && binding.InvalidationReason == null, cancellationToken);
        if (!bindingActive)
            return none;
        if (await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                .AnyAsync(row => row.EnrollmentId == enrollment.Id, cancellationToken))
            return none;

        var latest = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == enrollment.Id && row.State == "ENDED")
            .OrderByDescending(row => row.Revision)
            .ThenByDescending(row => row.Id)
            .FirstOrDefaultAsync(cancellationToken);
        if (latest is null
            || !string.Equals(latest.EndReason, SeatRuntimeReleaseAuthority.Reason, StringComparison.Ordinal))
            return none;

        var license = await db.Licenses.AsNoTracking().Include(row => row.Product)
            .SingleOrDefaultAsync(row => row.Id == latest.LicenseId, cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == latest.LicenseSeatId, cancellationToken);
        if (license is null || seat is null
            || license.ProductId != enrollment.ProductId
            || !license.IsActive || license.RevokedAt is not null
            || license.ExpirationDate is { } expiry && expiry <= now.UtcDateTime
            || !RuntimeEnrollmentService.IsVersionAllowed(enrollment.ReleaseVersion, license.AllowedVersions)
            || RuntimeEnrollmentService.IsVersionBelow(enrollment.ReleaseVersion, license.Product?.MinimumAllowedVersion))
            return none;

        if (string.IsNullOrWhiteSpace(seat.HardwareId))
            return none;
        var canonicalHardware = seat.HardwareId.ToUpperInvariant();
        if (await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == enrollment.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
                && ban.HardwareId.ToUpper() == canonicalHardware, cancellationToken))
            return none;

        // An excluded machine stays refused for good on that licence: exclusion releases the seat with the same
        // seat_released reason, and a non-terminal answer would make the client retry a reconnection that cannot succeed.
        try
        {
            await LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
                db, license.Id, seat.HardwareId, seat.HardwareId, cancellationToken);
        }
        catch (DistributionOperationException exception) when (
            string.Equals(exception.ErrorCode, LicenseHardwareExclusionChecker.PublicErrorCode, StringComparison.Ordinal))
        {
            return new ReleasedSeatAssessment(null, true);
        }

        var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == enrollment.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        var componentBanned = componentBans.Any(ban =>
            approvedBinaries.TryGetValue(ban.ComponentType, out var hash)
            && string.Equals(ApprovedBinaryService.NormalizeSha256(ban.ComponentHash),
                hash, StringComparison.OrdinalIgnoreCase));
        return componentBanned ? none : new ReleasedSeatAssessment(new ReleasedSeat(license.Id, seat.HardwareId), false);
    }

    /// <summary>Licence and exact machine value of the seat whose release ended the latest assignment.</summary>
    /// <param name="LicenseId">Licence of the latest ended assignment.</param>
    /// <param name="HardwareId">Exact hardware value of its released seat.</param>
    internal sealed record ReleasedSeat(Guid LicenseId, string HardwareId);

    /// <summary>Outcome of the shared seat-released entry condition.</summary>
    /// <param name="Seat">The healthy released seat, or null when the installation is not in the repairable state.</param>
    /// <param name="Excluded">True when the released machine is excluded from that licence (terminal).</param>
    internal sealed record ReleasedSeatAssessment(ReleasedSeat? Seat, bool Excluded);

    /// <summary>Lower-case SHA-256 of the exact UTF-8 value, the format of <see cref="RuntimeEnrollment.HardwareIdHash"/>.</summary>
    private static string HardwareDigest(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Historical stable public 422 for a commercial policy denial.</summary>
    private static RuntimeEnrollmentException Denied(string diagnosticCode) =>
        new("authority_ineligible", StatusCodes.Status422UnprocessableEntity, diagnosticCode);

    /// <summary>Non-terminal 409 whose body carries only the error code.</summary>
    private static RuntimeEnrollmentException Conflict(string error) =>
        new(error, StatusCodes.Status409Conflict);
}
