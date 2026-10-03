using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Classifies persisted Runtime authority history before a new installation generation is created.
/// See DevBrain DOC-324 for the complete transition matrix and its fail-closed invariants.
/// </summary>
internal static class RuntimeAuthorityTransitionResolver
{
    internal const string ActiveState = "ACTIVE";
    internal const string InvalidatedState = "INVALIDATED";

    /// <summary>Terminal enrollment reason recorded when a Runtime call finds its binding no longer active.</summary>
    internal const string BindingIneligibleReason = "binding_ineligible";

    /// <summary>
    /// Recognizes one exact released generation, not a globally recoverable reason. The sole
    /// enrollment may have been terminalized by the release itself, may have followed an already
    /// terminal <c>authority_ineligible</c> business decision, or may carry a later
    /// <c>binding_ineligible</c> refusal recorded by a stale Runtime call after the release.
    /// Callers must additionally authorize the target licence, grant, client and hardware under
    /// their locks. The old credential remains terminal; this proof permits only a fresh successor
    /// generation. Reason codes are exact persisted protocol values compared ordinally.
    /// <see cref="HardwareAuthorityAliasResolver"/> additionally requires the exact
    /// <c>seat_released</c> enrollment reason before reusing a signed hardware correspondence.
    /// </summary>
    /// <param name="binding">The candidate binding; it must be invalidated as <c>seat_released</c>.</param>
    /// <param name="enrollments">Every enrollment persisted for that binding; exactly one is required.</param>
    /// <param name="now">The database clock used to refuse terminal instants in the future.</param>
    /// <returns>
    /// <see langword="true"/> only when the non-hardware Runtime identity graph and exact terminal
    /// timeline match; retained enrollment HWID compatibility data is not an identity predicate.
    /// </returns>
    internal static bool IsCoherentSeatRelease(
        DistributionInstallationBinding binding, IReadOnlyList<RuntimeEnrollment> enrollments, DateTime now)
    {
        if (enrollments.Count != 1 || binding.State != "invalidated"
            || binding.InvalidationReason != SeatRuntimeReleaseAuthority.Reason
            || !binding.InvalidatedAtUtc.HasValue
            || binding.InvalidatedAtUtc < binding.BoundAtUtc || binding.InvalidatedAtUtc > now
            || binding.SubjectRefDigestSha256 is not { Length: 64 })
            return false;
        var enrollment = enrollments[0];
        var releaseTerminalizedEnrollment =
            enrollment.InvalidationReason == SeatRuntimeReleaseAuthority.Reason
            && enrollment.InvalidatedAtUtc == binding.InvalidatedAtUtc;
        var releaseFollowedBusinessTerminal =
            enrollment.InvalidationReason is "authority_ineligible" or "version_ineligible"
            && enrollment.InvalidatedAtUtc.HasValue
            && enrollment.InvalidatedAtUtc >= enrollment.CreatedAtUtc
            && (!enrollment.ActivatedAtUtc.HasValue
                || enrollment.InvalidatedAtUtc >= enrollment.ActivatedAtUtc)
            && (!enrollment.ChallengeConsumedAtUtc.HasValue
                || enrollment.InvalidatedAtUtc >= enrollment.ChallengeConsumedAtUtc)
            && enrollment.InvalidatedAtUtc <= binding.InvalidatedAtUtc;
        // Once the binding is released, every Runtime call on the old credential fails its binding
        // check first and records binding_ineligible. Before TKT-001198 such a stale call could also
        // overwrite the release's own seat_released terminal reason and instant. Accepting only a
        // strictly later refusal, bounded by the database clock, repairs those historical graphs
        // without trusting an earlier or unrelated binding refusal as release evidence.
        var releaseFollowedByStaleRuntimeRefusal =
            enrollment.InvalidationReason == BindingIneligibleReason
            && enrollment.InvalidatedAtUtc.HasValue
            && enrollment.InvalidatedAtUtc > binding.InvalidatedAtUtc
            && enrollment.InvalidatedAtUtc <= now
            && enrollment.InvalidatedAtUtc >= enrollment.CreatedAtUtc
            && (!enrollment.ActivatedAtUtc.HasValue
                || enrollment.InvalidatedAtUtc >= enrollment.ActivatedAtUtc);
        return enrollment.State == InvalidatedState
            && (releaseTerminalizedEnrollment || releaseFollowedBusinessTerminal
                || releaseFollowedByStaleRuntimeRefusal)
            && enrollment.BindingId == binding.Id
            && enrollment.ProductId == binding.ProductId
            && enrollment.LicenseId == binding.LicenseId
            && enrollment.LicenseSeatId == binding.LicenseSeatId
            && enrollment.InstallationId == binding.InstallationId
            && enrollment.SubjectRefDigestSha256 == binding.SubjectRefDigestSha256
            && enrollment.HandoffDigestSha256 == binding.HandoffDigestSha256
            && enrollment.ReleaseVersion == binding.Version
            && enrollment.ProtocolVersion == RuntimeEnrollmentService.ProtocolVersion
            && enrollment.Epoch == 1 && enrollment.SecurityEpoch >= binding.InitialSecurityEpoch;
    }

    private static readonly HashSet<string> RecoverableBusinessReasons = new(StringComparer.Ordinal)
    {
        "authority_ineligible",
        "binding_superseded",
        "challenge_expired",
        "license_ineligible",
        "release_changed",
        "seat_ineligible",
        "seat_reassigned_product_scope",
        "version_ineligible"
    };

    private static readonly HashSet<string> RecoverableBindingReasons = new(StringComparer.Ordinal)
    {
        "installation_superseded",
        "license_ineligible",
        "release_changed",
        "seat_ineligible",
        "seat_reassigned_product_scope",
        "version_ineligible"
    };

    internal static RuntimeAuthorityEnrollmentDecision ClassifyEnrollments(
        IReadOnlyList<RuntimeAuthorityEnrollmentSnapshot> enrollments,
        DateTime utcNow)
    {
        var live = enrollments.Where(enrollment =>
                enrollment.State is "PENDING" or ActiveState)
            .ToList();
        if (live.Count > 1 || (live.Count == 1 && live[0].State != ActiveState))
            return RuntimeAuthorityEnrollmentDecision.RejectAmbiguous;
        if (live.Count == 1)
            return RuntimeAuthorityEnrollmentDecision.UseActive;
        if (enrollments.Count != 1)
            return RuntimeAuthorityEnrollmentDecision.RejectAmbiguous;

        var terminal = enrollments[0];
        if (terminal.State != InvalidatedState
            || terminal.InvalidationReason == null
            || !RecoverableBusinessReasons.Contains(terminal.InvalidationReason))
        {
            return RuntimeAuthorityEnrollmentDecision.RejectSecurity;
        }

        if (terminal.InvalidationReason != "challenge_expired")
            return RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal;

        var isAbandonedChallenge = terminal.ActivatedAtUtc == null
            && terminal.ChallengeConsumedAtUtc == null
            && terminal.InvalidatedAtUtc.HasValue
            && terminal.ChallengeExpiresAtUtc <= utcNow
            && terminal.InvalidatedAtUtc.Value <= utcNow
            && terminal.InvalidatedAtUtc.Value >= terminal.ChallengeExpiresAtUtc;
        return isAbandonedChallenge
            ? RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal
            : RuntimeAuthorityEnrollmentDecision.RejectSecurity;
    }

    internal static bool IsRecoverableBinding(string state, string? invalidationReason) =>
        state == "active"
        || (state == "invalidated"
            && invalidationReason != null
            && RecoverableBindingReasons.Contains(invalidationReason));

    /// <summary>
    /// Selects a unique authorized leaf without creating rights. Explicit coherent-release
    /// evidence can nominate a terminal leaf, but ambiguity and successor history still refuse.
    /// The caller must revalidate the selected full graph and target authority before mutation.
    /// </summary>
    internal static RuntimeAuthorityBindingDecision ResolveBinding(
        IReadOnlyList<RuntimeAuthorityBindingSnapshot> bindings)
    {
        var active = bindings.Where(binding => binding.State == "active").ToList();
        if (active.Count > 1)
            return new(RuntimeAuthorityBindingDecisionKind.RejectAmbiguous, null);
        if (active.Count == 1)
            return new(RuntimeAuthorityBindingDecisionKind.UseActive, active[0].Id);

        var leaves = bindings.Where(binding =>
                binding.IsAuthorizedCandidate
                && (IsRecoverableBinding(binding.State, binding.InvalidationReason) || binding.HasCoherentSeatRelease)
                && !bindings.Any(successor => successor.SupersededBindingId == binding.Id))
            .ToList();
        return leaves.Count switch
        {
            1 => new(RuntimeAuthorityBindingDecisionKind.UseBusinessTerminal, leaves[0].Id),
            > 1 => new(RuntimeAuthorityBindingDecisionKind.RejectAmbiguous, null),
            _ => new(RuntimeAuthorityBindingDecisionKind.RejectMissing, null)
        };
    }
}

internal enum RuntimeAuthorityEnrollmentDecision
{
    UseActive,
    UseBusinessTerminal,
    RejectSecurity,
    RejectAmbiguous
}

internal sealed record RuntimeAuthorityEnrollmentSnapshot(
    string State,
    string? InvalidationReason,
    DateTime ChallengeExpiresAtUtc,
    DateTime? ChallengeConsumedAtUtc,
    DateTime? ActivatedAtUtc,
    DateTime? InvalidatedAtUtc);

internal enum RuntimeAuthorityBindingDecisionKind
{
    UseActive,
    UseBusinessTerminal,
    RejectMissing,
    RejectAmbiguous
}

internal sealed record RuntimeAuthorityBindingDecision(
    RuntimeAuthorityBindingDecisionKind Kind,
    Guid? BindingId);

/// <summary>
/// Classifies the complete provider-owned Runtime binding graph while keeping a version-only
/// execution refusal distinct from every licence, seat, ban and binary-integrity refusal.
/// </summary>
internal enum RuntimeBindingEligibility
{
    Eligible,
    VersionIneligible,
    AuthorityIneligible
}

/// <summary>
/// Re-evaluates one persisted Runtime binding from relational provider evidence. This evaluator is
/// shared by live execution validation and forced-update alias recovery so a historical terminal
/// reason cannot grant authority without the same current checks that protect Runtime execution.
/// </summary>
internal static class RuntimeBindingEligibilityEvaluator
{
    /// <summary>
    /// Evaluates licence, seat, quota, version, ban and approved-binary evidence without mutating it.
    /// </summary>
    /// <param name="db">Authority-scoped database context.</param>
    /// <param name="binding">Persisted binding whose exact evidence is evaluated.</param>
    /// <param name="now">Database-aligned decision time.</param>
    /// <param name="allowIneligibleSourceLicense">Preserves the bounded transfer-source exception.</param>
    /// <param name="cancellationToken">Cancels database reads.</param>
    /// <param name="migrationCrypto">Authenticates server migration receipts when historical and current digests differ.</param>
    /// <returns>A version-only outcome only when every non-version predicate remains eligible.</returns>
    internal static async Task<RuntimeBindingEligibility> EvaluateAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        DateTimeOffset now,
        bool allowIneligibleSourceLicense,
        CancellationToken cancellationToken,
        IRuntimeEnrollmentCryptoService? migrationCrypto = null)
    {
        var license = await db.Licenses.AsNoTracking().Include(candidate => candidate.Product)
            .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseId, cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseSeatId, cancellationToken);
        if (license == null || seat == null
            || license.ProductId != binding.ProductId
            || (!allowIneligibleSourceLicense && (!license.IsActive || license.RevokedAt != null
                || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now.UtcDateTime)
                || license.MaxSeats < 1))
            || !seat.IsActive || seat.LicenseId != license.Id)
        {
            return RuntimeBindingEligibility.AuthorityIneligible;
        }

        var seatDigest = HardwareAuthorityAliasResolver.Sha256(seat.HardwareId);
        // A receipt establishes identity continuity only. Every current policy below still applies,
        // including the version-only refusal that prevents obsolete Runtime execution.
        if (seatDigest != binding.HardwareIdHash
            && !await RuntimeEnrollmentService.HasAcceptedBindingHardwareAsync(
                db, binding, seatDigest, migrationCrypto, cancellationToken))
            return RuntimeBindingEligibility.AuthorityIneligible;

        var activeSeatCount = await db.LicenseSeats.AsNoTracking()
            .CountAsync(candidate => candidate.LicenseId == license.Id && candidate.IsActive, cancellationToken);
        if (!allowIneligibleSourceLicense && activeSeatCount > license.MaxSeats)
            return RuntimeBindingEligibility.AuthorityIneligible;

        var canonicalHardwareId = seat.HardwareId.ToUpperInvariant();
        if (await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == binding.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
                && ban.HardwareId.ToUpper() == canonicalHardwareId,
                cancellationToken))
        {
            return RuntimeBindingEligibility.AuthorityIneligible;
        }

        var evidence = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FP_EXE"] = binding.ExecutableSha256,
            ["FP_DLL"] = binding.NativeDllSha256,
            ["FP_CORE"] = binding.CoreSha256
        };
        var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == binding.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        if (componentBans.Any(ban => evidence.TryGetValue(ban.ComponentType, out var hash)
            && string.Equals(
                ApprovedBinaryService.NormalizeSha256(ban.ComponentHash),
                hash,
                StringComparison.OrdinalIgnoreCase)))
        {
            return RuntimeBindingEligibility.AuthorityIneligible;
        }

        var baselines = await db.ApprovedBinaries.AsNoTracking().Where(row =>
                row.ProductId == binding.ProductId && row.Version == binding.Version)
            .ToListAsync(cancellationToken);
        if (baselines.Count != evidence.Count || baselines.Any(row =>
            row.Source != ApprovedBinaryService.ReleaseSource
            || !evidence.TryGetValue(row.Key, out var expected)
            || !string.Equals(row.Hash, expected, StringComparison.OrdinalIgnoreCase)))
        {
            return RuntimeBindingEligibility.AuthorityIneligible;
        }

        if (!allowIneligibleSourceLicense
            && (!RuntimeEnrollmentService.IsVersionAllowed(binding.Version, license.AllowedVersions)
                || RuntimeEnrollmentService.IsVersionBelow(
                    binding.Version,
                    license.Product?.MinimumAllowedVersion)))
        {
            return RuntimeBindingEligibility.VersionIneligible;
        }

        return RuntimeBindingEligibility.Eligible;
    }
}

/// <summary>
/// Candidate history with separate authorization and full terminal-graph evidence. A bare
/// seat_released reason does not set HasCoherentSeatRelease and remains fail-closed.
/// </summary>
internal sealed record RuntimeAuthorityBindingSnapshot(
    Guid Id,
    Guid? SupersededBindingId,
    string State,
    string? InvalidationReason,
    bool IsAuthorizedCandidate,
    bool HasCoherentSeatRelease = false);
