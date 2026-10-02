namespace SoftLicence.Server.Services;

/// <summary>
/// Carries the fixed, non-sensitive predicates evaluated before a Finalize hardware-authority refusal.
/// </summary>
/// <remarks>
/// DOC-508 defines the cross-repository diagnostic contract. Every field is deliberately boolean;
/// authority identifiers, digests, licence data, and arbitrary request content are forbidden here.
/// A false downstream predicate means it was not established before the selected guard rejected.
/// </remarks>
public sealed record HardwareAuthorityDecisionMatrix(
    bool AliasResolutionRefused = false,
    bool AliasUsed = false,
    bool SeatReconciliationRequired = false,
    bool BindingIdentityPresent = false,
    bool SeatIdentityPresent = false,
    bool CanonicalSeatPresent = false,
    bool SingleLegacySeatPresent = false,
    bool RecoverySourcePresent = false,
    bool RecoverySourceMatchesBinding = false);

/// <summary>
/// Describes one final <c>hardware_authority_refused</c> decision using only closed diagnostics.
/// </summary>
/// <param name="ReasonCode">Stable ASCII reason returned through the existing S2S error contract.</param>
/// <param name="Guard">Stable provider-owned guard name used only by structured diagnostics.</param>
/// <param name="RequestId">Canonical request UUID already validated at the S2S boundary.</param>
/// <param name="Decision">Fixed boolean decision matrix with no authority identifiers.</param>
public sealed record HardwareAuthorityRefusalEvent(
    string ReasonCode,
    string Guard,
    string RequestId,
    HardwareAuthorityDecisionMatrix Decision);

/// <summary>Owns the closed TKT-000579 reason and guard vocabulary.</summary>
internal static class HardwareAuthorityRefusalDiagnostics
{
    internal const string AliasResolutionAmbiguous = "alias_resolution_ambiguous";
    internal const string AliasResolutionUnavailable = "alias_resolution_unavailable";
    internal const string AuthorityGraphMissing = "authority_graph_missing";
    internal const string AuthorityGraphDiverged = "authority_graph_diverged";
    internal const string AliasReconciliationIdentityMissing = "alias_reconciliation_identity_missing";
    internal const string CanonicalSeatCardinalityMismatch = "canonical_seat_cardinality_mismatch";
    internal const string RecoverySourceMissing = "recovery_source_missing";
    internal const string RecoverySourceBindingMismatch = "recovery_source_binding_mismatch";

    internal static (string ReasonCode, string Guard) DescribeAliasRefusal(
        HardwareAuthorityRefusalReason? refusalReason) => refusalReason switch
        {
            HardwareAuthorityRefusalReason.AmbiguousAlias =>
                (AliasResolutionAmbiguous, "alias_resolution_ambiguous_guard"),
            HardwareAuthorityRefusalReason.AliasUnavailable =>
                (AliasResolutionUnavailable, "alias_resolution_unavailable_guard"),
            HardwareAuthorityRefusalReason.AuthorityGraphMissing =>
                (AuthorityGraphMissing, "authority_graph_missing_guard"),
            HardwareAuthorityRefusalReason.AuthorityGraphDiverged =>
                (AuthorityGraphDiverged, "authority_graph_diverged_guard"),
            _ => (AuthorityGraphDiverged, "authority_graph_diverged_guard")
        };
}
