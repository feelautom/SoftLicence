using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Determines current commercial eligibility from the independent assignment ledger.
/// Historical binding and enrollment licence, seat and hardware copies grant no rights.
/// </summary>
internal static class RuntimeCommercialEligibilityValidator
{
    /// <summary>
    /// Holds a shared transaction-level commercial graph barrier while a bootstrap decision
    /// reads assignment, licence and seat rows. Item 2 writers take its exclusive counterpart
    /// before commit, so a concurrent commercial change cannot commit between those reads.
    /// Call before reading commercial graph rows, with an existing PostgreSQL transaction.
    /// A Runtime redeemer first locks its enrollment row to preserve deferred-writer ordering.
    /// A timeout or database failure propagates as infrastructure failure, never as denial.
    /// </summary>
    /// <param name="db">PostgreSQL context with the caller's active bootstrap transaction.</param>
    /// <param name="cancellationToken">Cancels lock acquisition without granting authority.</param>
    /// <returns>A task that completes only after the transaction holds the shared barrier.</returns>
    internal static Task AcquireReadBarrierAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken) => db.Database.ExecuteSqlRawAsync(
            "SELECT pg_catalog.pg_advisory_xact_lock_shared(1312, 1);", cancellationToken);

    /// <summary>
    /// Holds the exclusive transaction-level commercial graph barrier while a workflow creates or
    /// changes assignment-producing rows. Callers must lock their mutable enrollment and binding
    /// rows first, matching the deferred item-2 trigger order. A timeout or database failure remains
    /// infrastructure failure and must never be converted into commercial denial.
    /// </summary>
    /// <param name="db">PostgreSQL context with the caller's active mutation transaction.</param>
    /// <param name="cancellationToken">Cancels lock acquisition without persisting partial authority.</param>
    /// <returns>A task that completes only after the transaction owns the exclusive barrier.</returns>
    internal static Task AcquireWriteBarrierAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken) => db.Database.ExecuteSqlRawAsync(
            "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", cancellationToken);

    /// <summary>Current assignment scope and exact seat hardware returned only after every policy check passes.</summary>
    /// <param name="AssignmentId">Active assignment row.</param>
    /// <param name="Revision">Monotonic revision within the enrollment.</param>
    /// <param name="LicenseId">Current license.</param>
    /// <param name="SeatId">Current seat.</param>
    /// <param name="HardwareId">Exact seat hardware value validated under the commercial barrier.</param>
    internal sealed record EligibleAssignment(
        Guid AssignmentId, int Revision, Guid LicenseId, Guid SeatId, string HardwareId);

    /// <summary>Closed commercial outcome; database failures never become Denied.</summary>
    internal enum AssessmentOutcome
    {
        /// <summary>An active assignment and all current policy checks passed.</summary>
        Eligible,
        /// <summary>A known commercial rule denied access; database failures are exceptions.</summary>
        Denied
    }

    /// <summary>Controls whether the shared validator or its lock-owning caller decides hardware bans.</summary>
    internal enum HardwareBanAssessmentMode
    {
        /// <summary>Active seat hardware bans deny the assessment.</summary>
        Enforce,
        /// <summary>
        /// The caller evaluates the already locked hardware-ban rows and their allowlist after every other
        /// commercial check passes. This mode never suppresses licence, seat, quota, version, or component policy.
        /// </summary>
        DeferToCaller
    }

    /// <summary>
    /// Says whether the release frozen in the assessed enrollment is judged against the licence mask
    /// (<c>AllowedVersions</c>) and the product minimum (<c>MinimumAllowedVersion</c>).
    /// </summary>
    /// <remarks>
    /// TKT-004062: a reinstallation replaces the installed release, so judging the release it replaces refused
    /// every reinstallation of a machine still enrolled below a newly raised minimum (403 <c>not_eligible</c>,
    /// reason <c>version_ineligible</c>). Only reinstallation source checks may use <see cref="NotJudged"/>; the
    /// release that will actually run is judged later by Finalize. Startup, redeem, capability, upgrade and every
    /// other caller keep <see cref="Judged"/>, so an installed release below the minimum stays refused.
    /// </remarks>
    internal enum SourceReleaseVersionPolicy
    {
        /// <summary>The enrollment release must match the licence mask and reach the product minimum.</summary>
        Judged,
        /// <summary>
        /// The enrollment release is the one being replaced and is not judged. Licence, seat, quota, ban and
        /// component policy stay fully enforced.
        /// </summary>
        NotJudged
    }

    /// <summary>
    /// A commercial assessment keeps denial separate from a database or identity failure. Hardware flags
    /// describe only the reported value's current policy relationship; the independent active-ban signal
    /// covers every live ban that can be established even when another commercial rule denies eligibility.
    /// The optional eligible assignment carries the validated seat value, never the reported hardware value.
    /// </summary>
    /// <param name="Assignment">Active assignment when eligible.</param>
    /// <param name="DenialReason">Bounded closed reason for a policy denial.</param>
    /// <param name="ReportHardwareLinked">Current link of reported hardware, never historical proof.</param>
    /// <param name="ReportHardwareBanned">Whether a current active ban covers the reported hardware.</param>
    /// <param name="ActiveBanReason">Bounded recognized live-ban reason, independent of denial precedence.</param>
    internal sealed record Assessment(
        EligibleAssignment? Assignment,
        string? DenialReason,
        bool ReportHardwareLinked,
        bool ReportHardwareBanned,
        string? ActiveBanReason)
    {
        /// <summary>Closed business outcome; infrastructure failures remain exceptions.</summary>
        internal AssessmentOutcome Outcome => Assignment is not null && DenialReason is null
            ? AssessmentOutcome.Eligible : AssessmentOutcome.Denied;
        /// <summary>True only when the current assignment and every commercial policy check passed.</summary>
        internal bool IsEligible => Outcome == AssessmentOutcome.Eligible;
        /// <summary>True when a recognized live ban applies independently of commercial eligibility.</summary>
        internal bool ActiveBanDetected => ActiveBanReason is not null;
    }

    /// <summary>
    /// Reads one active assignment and its live licence, seat, quota and ban policy without mutation.
    /// The result carries the exact seat hardware value validated under the caller's barrier,
    /// so a signer need not read it again. Database failures propagate as infrastructure
    /// failures rather than business refusals.
    /// </summary>
    internal static async Task<EligibleAssignment> ValidateAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var assessment = await AssessAsync(db, enrollment, approvedBinaries, now, null, cancellationToken);
        return assessment.Assignment ?? throw Denied(assessment.DenialReason ?? "commercial_authority_ineligible");
    }

    /// <summary>
    /// Same contract as <see cref="ValidateAsync(LicenseDbContext, RuntimeEnrollment, IReadOnlyDictionary{string, string}, DateTimeOffset, CancellationToken)"/>
    /// with an explicit source-release policy, reserved for reinstallation source checks (TKT-004062).
    /// </summary>
    /// <param name="db">Current transaction database context, holding the caller's commercial barrier.</param>
    /// <param name="enrollment">Cryptographically validated enrollment.</param>
    /// <param name="approvedBinaries">Validated release binary map used for component bans.</param>
    /// <param name="now">Fresh provider database time.</param>
    /// <param name="sourceReleasePolicy">Whether the enrollment release is judged; see <see cref="SourceReleaseVersionPolicy"/>.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The eligible assignment with its exact seat hardware value.</returns>
    /// <exception cref="RuntimeEnrollmentException">422 <c>authority_ineligible</c> with the denial reason; 503 for a broken graph.</exception>
    internal static async Task<EligibleAssignment> ValidateAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        SourceReleaseVersionPolicy sourceReleasePolicy,
        CancellationToken cancellationToken)
    {
        var assessment = await AssessAsync(db, enrollment, approvedBinaries, now, null,
            HardwareBanAssessmentMode.Enforce, sourceReleasePolicy, cancellationToken);
        return assessment.Assignment ?? throw Denied(assessment.DenialReason ?? "commercial_authority_ineligible");
    }

    /// <summary>
    /// Assesses commercial authority without changing enrollment or throwing for a policy denial.
    /// A reported hardware identifier is compared only with the authoritative active assignment seat.
    /// An eligible result retains that seat's exact hardware value under the caller's read barrier.
    /// </summary>
    internal static async Task<Assessment> AssessAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        string? reportedHardwareId,
        CancellationToken cancellationToken) => await AssessAsync(
            db, enrollment, approvedBinaries, now, reportedHardwareId,
            HardwareBanAssessmentMode.Enforce, cancellationToken);

    /// <summary>
    /// Assesses commercial authority with an explicit hardware-ban policy. Deferral is reserved for a caller
    /// that holds the canonical ban mutation lock and applies the existing paid allowlist atomically.
    /// </summary>
    /// <param name="db">Current transaction database context.</param>
    /// <param name="enrollment">Cryptographically validated enrollment.</param>
    /// <param name="approvedBinaries">Validated release binary map used for component bans.</param>
    /// <param name="now">Fresh provider database time.</param>
    /// <param name="reportedHardwareId">Optional current hardware observation for linkage diagnostics.</param>
    /// <param name="hardwareBanMode">Exact owner of the hardware-ban decision.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A typed eligible or denied commercial result.</returns>
    internal static Task<Assessment> AssessAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        string? reportedHardwareId,
        HardwareBanAssessmentMode hardwareBanMode,
        CancellationToken cancellationToken) => AssessAsync(
            db, enrollment, approvedBinaries, now, reportedHardwareId, hardwareBanMode,
            SourceReleaseVersionPolicy.Judged, cancellationToken);

    /// <summary>
    /// Assesses commercial authority with explicit hardware-ban and source-release policies. Every licence,
    /// seat, quota, ban and component rule applies in both release policies, in the established denial order.
    /// </summary>
    /// <param name="db">Current transaction database context.</param>
    /// <param name="enrollment">Cryptographically validated enrollment.</param>
    /// <param name="approvedBinaries">Validated release binary map used for component bans.</param>
    /// <param name="now">Fresh provider database time.</param>
    /// <param name="reportedHardwareId">Optional current hardware observation for linkage diagnostics.</param>
    /// <param name="hardwareBanMode">Exact owner of the hardware-ban decision.</param>
    /// <param name="sourceReleasePolicy">
    /// <see cref="SourceReleaseVersionPolicy.NotJudged"/> only for a reinstallation source, whose release is replaced.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A typed eligible or denied commercial result; database failures propagate.</returns>
    /// <exception cref="RuntimeEnrollmentException">503 <c>authority_unavailable</c> for a duplicate or broken assignment graph.</exception>
    internal static async Task<Assessment> AssessAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now,
        string? reportedHardwareId,
        HardwareBanAssessmentMode hardwareBanMode,
        SourceReleaseVersionPolicy sourceReleasePolicy,
        CancellationToken cancellationToken)
    {
        var reportHardwareBanned = reportedHardwareId is not null && await db.BannedHardwareIds.AsNoTracking()
            .AnyAsync(ban => ban.IsActive && (ban.ProductId == null || ban.ProductId == enrollment.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
                && ban.HardwareId.ToUpper() == reportedHardwareId.ToUpper(), cancellationToken);
        var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == enrollment.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        var componentBanDetected = componentBans.Any(ban =>
            approvedBinaries.TryGetValue(ban.ComponentType, out var hash)
            && string.Equals(ApprovedBinaryService.NormalizeSha256(ban.ComponentHash),
                hash, StringComparison.OrdinalIgnoreCase));
        var assignments = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE")
            .Take(2).ToListAsync(cancellationToken);
        if (assignments.Count > 1)
            throw new RuntimeEnrollmentException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "assignment_duplicate_active");
        if (assignments.Count == 0)
        {
            var quarantined = await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                .AnyAsync(row => row.EnrollmentId == enrollment.Id, cancellationToken);
            return new Assessment(null, quarantined ? "assignment_quarantined" : "assignment_missing",
                false, reportHardwareBanned, reportHardwareBanned
                    ? "hardware_banned" : componentBanDetected ? "component_banned" : null);
        }

        var assignment = assignments[0];
        var license = await db.Licenses.AsNoTracking().Include(row => row.Product)
            .SingleOrDefaultAsync(row => row.Id == assignment.LicenseId, cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == assignment.LicenseSeatId, cancellationToken);
        if (license is null || seat is null)
            throw new RuntimeEnrollmentException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "assignment_relation_missing");
        var reportHardwareLinked = reportedHardwareId is not null
            && await IsReportHardwareLinkedAsync(
                db, enrollment, assignment, seat, reportedHardwareId, cancellationToken);
        var canonicalHardware = string.IsNullOrWhiteSpace(seat.HardwareId)
            ? null
            : seat.HardwareId.ToUpperInvariant();
        var canonicalHardwareBanned = hardwareBanMode == HardwareBanAssessmentMode.Enforce
            && canonicalHardware is not null
            && await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == enrollment.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
                && ban.HardwareId.ToUpper() == canonicalHardware, cancellationToken);
        var activeBanReason = reportHardwareBanned || canonicalHardwareBanned
            ? "hardware_banned"
            : componentBanDetected ? "component_banned" : null;

        // Keep the established denial reason precedence while carrying live-ban priority separately for SHADOW.
        // TKT-003647: the licence and seat rules live in ClassifyLicenseAndSeat, shared with the current-assignment
        // read; every finer reason it returns still maps to the single historical code here.
        if (ClassifyLicenseAndSeat(license, seat, enrollment.ProductId, now.UtcDateTime) is not null)
            return new Assessment(null, "commercial_authority_ineligible", reportHardwareLinked,
                reportHardwareBanned, activeBanReason);

        var activeSeats = await db.LicenseSeats.AsNoTracking()
            .CountAsync(row => row.LicenseId == license.Id && row.IsActive, cancellationToken);
        if (ExceedsSeatCapacity(license, activeSeats))
            return new Assessment(null, "seat_capacity_exceeded", reportHardwareLinked,
                reportHardwareBanned, activeBanReason);

        // TKT-004062: a reinstallation source is the release being replaced. Its version is skipped only under the
        // explicit NotJudged policy; the target release is judged by Finalize, and every other check stays above.
        if (sourceReleasePolicy == SourceReleaseVersionPolicy.Judged
            && (!RuntimeEnrollmentService.IsVersionAllowed(enrollment.ReleaseVersion, license.AllowedVersions)
                || RuntimeEnrollmentService.IsVersionBelow(
                    enrollment.ReleaseVersion, license.Product?.MinimumAllowedVersion)))
            return new Assessment(null, "version_ineligible", reportHardwareLinked,
                reportHardwareBanned, activeBanReason);

        if (canonicalHardwareBanned)
            return new Assessment(null, "hardware_banned", reportHardwareLinked,
                reportHardwareBanned, activeBanReason);

        if (componentBanDetected)
            return new Assessment(null, "component_banned", reportHardwareLinked,
                reportHardwareBanned, activeBanReason);

        return new Assessment(new EligibleAssignment(
                assignment.Id, assignment.Revision, license.Id, seat.Id, seat.HardwareId),
            null, reportHardwareLinked, reportHardwareBanned, activeBanReason);
    }

    /// <summary>Licence revoked (<see cref="License.RevokedAt"/> set); checked first because a revocation also deactivates.</summary>
    internal const string LicenseRevokedReason = "license_revoked";
    /// <summary>Licence deactivated without revocation.</summary>
    internal const string LicenseInactiveReason = "license_inactive";
    /// <summary>Key period over: <see cref="License.ExpirationDate"/> at or before the provider clock (not the commercial period).</summary>
    internal const string LicenseExpiredReason = "license_expired";
    /// <summary>Licence of another product or without any seat (<see cref="License.MaxSeats"/> below 1).</summary>
    internal const string LicenseUnusableReason = "license_unusable";
    /// <summary>Assigned seat inactive, attached to another licence, or without a hardware identifier.</summary>
    internal const string SeatUnavailableReason = "seat_unavailable";
    /// <summary>More active seats than <see cref="License.MaxSeats"/>; same code as the historical assessment.</summary>
    internal const string SeatCapacityExceededReason = "seat_capacity_exceeded";

    /// <summary>
    /// Classifies whether the licence and seat of an ACTIVE assignment are usable at <paramref name="nowUtc"/>,
    /// from their stored state only: no version, ban, price, offer or account right is considered. It is the single
    /// source of the licence and seat rules of <see cref="AssessAsync(LicenseDbContext, RuntimeEnrollment,
    /// IReadOnlyDictionary{string, string}, DateTimeOffset, string?, HardwareBanAssessmentMode, CancellationToken)"/>
    /// (which reports every reason as <c>commercial_authority_ineligible</c>) and of the TKT-003647 current-assignment
    /// read (which reports the finer reason). Pure function, no database access.
    /// </summary>
    /// <param name="license">Licence of the ACTIVE assignment.</param>
    /// <param name="seat">Seat of the ACTIVE assignment.</param>
    /// <param name="enrollmentProductId">Product of the enrollment, which the licence must share.</param>
    /// <param name="nowUtc">Provider (database) UTC time; an expiry equal to it already counts as expired.</param>
    /// <returns>
    /// Null when usable; otherwise the first matching reason in this precedence: <see cref="LicenseRevokedReason"/>,
    /// <see cref="LicenseInactiveReason"/>, <see cref="LicenseExpiredReason"/>, <see cref="LicenseUnusableReason"/>,
    /// <see cref="SeatUnavailableReason"/>. Seat capacity needs a count and is checked by
    /// <see cref="ExceedsSeatCapacity"/> afterwards.
    /// </returns>
    internal static string? ClassifyLicenseAndSeat(License license, LicenseSeat seat, Guid enrollmentProductId, DateTime nowUtc)
    {
        if (license.RevokedAt is not null)
            return LicenseRevokedReason;
        if (!license.IsActive)
            return LicenseInactiveReason;
        if (license.ExpirationDate is { } expiry && expiry <= nowUtc)
            return LicenseExpiredReason;
        if (license.ProductId != enrollmentProductId || license.MaxSeats < 1)
            return LicenseUnusableReason;
        if (!seat.IsActive || seat.LicenseId != license.Id || string.IsNullOrWhiteSpace(seat.HardwareId))
            return SeatUnavailableReason;
        return null;
    }

    /// <summary>
    /// True when the licence has more active seats than it allows. Equality is allowed: the assigned seat itself is
    /// one of the counted active seats. Shared by the assessment and the TKT-003647 current-assignment read.
    /// </summary>
    /// <param name="license">Licence whose <see cref="License.MaxSeats"/> applies.</param>
    /// <param name="activeSeatCount">Number of active seats of that licence, counted by the caller in its transaction.</param>
    internal static bool ExceedsSeatCapacity(License license, int activeSeatCount) => activeSeatCount > license.MaxSeats;

    /// <summary>Converts a bounded business reason to the stable public 422 response.</summary>
    private static RuntimeEnrollmentException Denied(string diagnosticCode) =>
        new("authority_ineligible", StatusCodes.Status422UnprocessableEntity, diagnosticCode);

    /// <summary>
    /// Links reported hardware only to the active assignment's seat or an authenticated, server-authoritative active legacy alias
    /// for that exact enrollment, binding, licence and seat. No copied enrollment hash grants a link.
    /// </summary>
    internal static async Task<bool> IsReportHardwareLinkedAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        EnrollmentLicenseAssignment assignment,
        LicenseSeat seat,
        string reportedHardwareId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(seat.HardwareId) || !seat.IsActive
            || seat.LicenseId != assignment.LicenseId
            || assignment.EnrollmentId != enrollment.Id || assignment.State != "ACTIVE")
            return false;
        return await MatchesReportedHardwareAsync(
            db, enrollment, assignment, seat, reportedHardwareId, cancellationToken);
    }

    /// <summary>
    /// Compares reported hardware to the current seat or its currently active authenticated alias.
    /// This must never be used to justify a historical admin BAN; that uses the frozen report proof.
    /// </summary>
    /// <param name="db">Current database context.</param>
    /// <param name="enrollment">Authenticated enrollment.</param>
    /// <param name="assignment">Current active assignment.</param>
    /// <param name="seat">Assignment's current active seat.</param>
    /// <param name="reportedHardwareId">Canonical reported hardware evidence.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    private static async Task<bool> MatchesReportedHardwareAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        EnrollmentLicenseAssignment assignment,
        LicenseSeat seat,
        string reportedHardwareId,
        CancellationToken cancellationToken)
    {
        if (string.Equals(seat.HardwareId, reportedHardwareId, StringComparison.OrdinalIgnoreCase))
            return true;
        var legacyDigest = HardwareDigest(reportedHardwareId);
        var seatDigest = HardwareDigest(seat.HardwareId);
        return await db.HardwareAuthorityAliases.AsNoTracking().AnyAsync(alias =>
            alias.ProductId == enrollment.ProductId
            && alias.LicenseId == assignment.LicenseId && alias.LicenseSeatId == seat.Id
            && alias.RuntimeEnrollmentId == enrollment.Id && alias.BindingId == enrollment.BindingId
            && alias.LegacyHardwareIdSha256 == legacyDigest
            && alias.CanonicalHardwareIdSha256 == seatDigest
            && alias.SecurityEpoch <= enrollment.SecurityEpoch
            && alias.IsActive, cancellationToken);
    }

    /// <summary>Hashes the exact canonical identifier for digest-only alias comparison.</summary>
    private static string HardwareDigest(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
