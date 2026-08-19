namespace SoftLicence.Server.Services;

/// <summary>
/// Classifies persisted Runtime authority history before a new installation generation is created.
/// See DevBrain DOC-324 for the complete transition matrix and its fail-closed invariants.
/// </summary>
internal static class RuntimeAuthorityTransitionResolver
{
    internal const string ActiveState = "ACTIVE";
    internal const string InvalidatedState = "INVALIDATED";

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
                && IsRecoverableBinding(binding.State, binding.InvalidationReason)
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

internal sealed record RuntimeAuthorityBindingSnapshot(
    Guid Id,
    Guid? SupersededBindingId,
    string State,
    string? InvalidationReason,
    bool IsAuthorizedCandidate);
