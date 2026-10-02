using System.Text.Json;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Provides internal, privacy-bounded explanations of Distribution authority recovery refusals.</summary>
public sealed partial class DistributionInstallationBindingService
{
    /// <summary>
    /// Explains an already-rejected recovery using fixed predicate names and nullable booleans only.
    /// Required predicates identify blockers; alternative groups explain why no acceptable route exists.
    /// A null group is inapplicable and a null leaf lacks its prerequisite record, not an observed mismatch.
    /// </summary>
    /// <param name="clientId">Authenticated caller, compared exactly but never written to the log.</param>
    /// <param name="source">Locked historical binding used by the original decision.</param>
    /// <param name="replacement">Optional modern replacement proof.</param>
    /// <param name="legacyReplacement">Optional legacy replacement proof.</param>
    /// <param name="request">Validated request; only its canonical request UUID may be emitted.</param>
    /// <param name="entitlement">Verified target entitlement.</param>
    /// <param name="seatId">Target seat identity selected by the decision.</param>
    /// <param name="grantRefDigestSha256">Target grant digest, compared without logging it.</param>
    /// <param name="hardwareIdHash">Target hardware digest, compared without logging it.</param>
    /// <param name="previousEntitlement">Historical entitlement as read by the original decision.</param>
    /// <param name="previousGrantOwner">Historical grant ownership as read by the original decision.</param>
    /// <param name="sourceLicense">Optional source licence used only for renewal eligibility.</param>
    /// <param name="sourceSeat">Historical seat; null means absent from the decision's query.</param>
    /// <param name="targetSeat">Resolved target seat, including the exact server-created Added entity; null means neither is available.</param>
    /// <param name="finalizeOwners">Distinct historical finalize callers, never emitted.</param>
    /// <param name="now">The decision's frozen time; diagnostics do not perform a later state lookup.</param>
    /// <remarks>
    /// This deliberately mirrors the decision for explanation only. Keep it synchronized with
    /// RecoverSameAuthorityInstallationAsync, but never use these results to grant authority.
    /// There are no new database reads, writes, normalizations or public response fields.
    /// The standard warning sink is independent of a database rollback; its configured retention
    /// still applies and this is not the durable licence history owned by TKT-000976.
    /// </remarks>
    private void WriteSameAuthorityRefusalDiagnostics(
        string clientId,
        DistributionInstallationBinding source,
        LicenseReplacementValidated? replacement,
        LegacyLicenseReplacementValidated? legacyReplacement,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId,
        string grantRefDigestSha256,
        string hardwareIdHash,
        DistributionEntitlement? previousEntitlement,
        DistributionGrantOwnership? previousGrantOwner,
        License? sourceLicense,
        LicenseSeat? sourceSeat,
        LicenseSeat? targetSeat,
        IReadOnlyList<string> finalizeOwners,
        DateTimeOffset now)
    {
        try
        {
            var checks = new Dictionary<string, bool?>(StringComparer.Ordinal);

            // All keys below are source-controlled ASCII literals. No caller value can become
            // a property name or a diagnostic string. Nullable prerequisites remain explicit.
            // Records one conjunction; disabled alternatives are null, not failed requirements.
            bool All(string group, bool applicable, params (string Name, bool? Passed)[] predicates)
            {
                if (!applicable)
                {
                    checks.Add(group, null);
                    return false;
                }

                foreach (var (name, passed) in predicates)
                    checks.Add(group + "." + name, passed);
                var accepted = predicates.All(predicate => predicate.Passed == true);
                checks.Add(group, accepted);
                return accepted;
            }

            var sameLicense = All("same_license", true,
                ("license_matches", source.LicenseId == entitlement.LicenseId),
                ("seat_matches", source.LicenseSeatId == seatId),
                ("subject_matches", source.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256));
            var seatTransition = All("seat_transition", replacement == null,
                ("license_matches", source.LicenseId == entitlement.LicenseId),
                ("seat_differs", source.LicenseSeatId != seatId),
                ("subject_matches", source.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256),
                ("hardware_differs", source.HardwareIdHash != hardwareIdHash),
                ("source_seat_present", sourceSeat != null),
                ("source_seat_license_matches", sourceSeat == null ? null : sourceSeat.LicenseId == source.LicenseId),
                ("source_seat_inactive", sourceSeat == null ? null : !sourceSeat.IsActive),
                ("source_seat_unlinked", sourceSeat == null ? null : sourceSeat.UnlinkedAt != null),
                ("source_seat_hardware_matches", sourceSeat == null ? null : Sha256(sourceSeat.HardwareId) == source.HardwareIdHash),
                ("target_seat_present", targetSeat != null),
                ("target_seat_license_matches", targetSeat == null ? null : targetSeat.LicenseId == entitlement.LicenseId),
                ("target_seat_active", targetSeat == null ? null : targetSeat.IsActive),
                ("target_seat_hardware_matches_request", targetSeat == null ? null : string.Equals(targetSeat.HardwareId, request.HardwareId, StringComparison.Ordinal)),
                ("target_seat_hardware_matches_digest", targetSeat == null ? null : Sha256(targetSeat.HardwareId) == hardwareIdHash));
            var renewal = All("renewal", replacement != null,
                ("binding_matches", replacement?.SourceBindingId == source.Id),
                ("license_matches", replacement?.SourceLicenseId == source.LicenseId),
                ("subject_matches", replacement?.SourceSubjectRefDigestSha256 == source.SubjectRefDigestSha256),
                ("license_differs", source.LicenseId != entitlement.LicenseId),
                ("seat_differs", source.LicenseSeatId != seatId),
                ("source_license_present", sourceLicense != null),
                ("source_license_ineligible", sourceLicense == null ? null : IsReplacementSourceIneligible(sourceLicense, now)));
            var legacyRenewal = All("legacy_renewal", legacyReplacement != null,
                ("source_license_matches", legacyReplacement?.SourceLicenseId == source.LicenseId),
                ("target_license_matches", legacyReplacement?.TargetLicenseId == entitlement.LicenseId),
                ("license_differs", source.LicenseId != entitlement.LicenseId),
                ("seat_differs", source.LicenseSeatId != seatId),
                ("source_license_present", sourceLicense != null),
                ("source_license_ineligible", sourceLicense == null ? null : IsReplacementSourceIneligible(sourceLicense, now)));
            var modernSource = All("modern_source", legacyReplacement == null,
                ("entitlement_present", previousEntitlement != null),
                ("entitlement_finalized", previousEntitlement == null ? null : previousEntitlement.State == "finalized"),
                ("subject_length_valid", previousEntitlement == null ? null : previousEntitlement.SubjectRefDigestSha256 is { Length: 64 }),
                ("contract_modern", previousEntitlement == null ? null : IsModernEntitlementContractVersion(previousEntitlement.ContractVersion)),
                ("entitlement_matches", previousEntitlement == null ? null : previousEntitlement.Id == source.EntitlementId),
                ("client_matches", previousEntitlement == null ? null : previousEntitlement.ClientId == clientId),
                ("product_matches", previousEntitlement == null ? null : previousEntitlement.ProductId == source.ProductId),
                ("license_matches", previousEntitlement == null ? null : previousEntitlement.LicenseId == source.LicenseId),
                ("grant_matches", previousEntitlement == null ? null : previousEntitlement.GrantRefDigestSha256 == source.GrantRefDigestSha256),
                ("subject_matches", previousEntitlement == null ? null : previousEntitlement.SubjectRefDigestSha256 == source.SubjectRefDigestSha256),
                ("grant_owner_present", previousGrantOwner != null),
                ("grant_owner_client_matches", previousGrantOwner == null ? null : previousGrantOwner.ClientId == clientId),
                ("grant_owner_source_matches", previousEntitlement == null || previousGrantOwner == null ? null : IsMatchingModernIssueSource(previousEntitlement.ContractVersion, previousGrantOwner.Source)));
            var grantlessSource = All("grantless_source", legacyReplacement != null,
                ("entitlement_absent", previousEntitlement == null),
                ("grant_owner_absent", previousGrantOwner == null));

            All("required", true,
                ("target_contract_modern", IsModernEntitlementContractVersion(entitlement.ContractVersion)),
                ("target_subject_length_valid", entitlement.SubjectRefDigestSha256 is { Length: 64 }),
                ("source_binding_recoverable", RuntimeAuthorityTransitionResolver.IsRecoverableBinding(source.State, source.InvalidationReason)),
                ("product_matches", source.ProductId == request.ProductId),
                ("authority_route_matches", sameLicense || seatTransition || renewal || legacyRenewal),
                ("installation_differs", source.InstallationId != request.InstallationId),
                ("hardware_matches_or_seat_transition", source.HardwareIdHash == hardwareIdHash || seatTransition),
                ("historical_authority_matches", modernSource || grantlessSource),
                ("finalize_owner_unique", finalizeOwners.Count == 1),
                ("finalize_owner_matches", finalizeOwners.Count == 1 ? finalizeOwners[0] == clientId : null),
                ("source_grant_digest_valid", source.GrantRefDigestSha256 == Sha256(source.GrantRef)),
                ("grant_differs", source.GrantRefDigestSha256 != grantRefDigestSha256),
                ("source_handoff_present", source.HandoffIssuedAtUtc.HasValue),
                ("handoff_newer", source.HandoffIssuedAtUtc.HasValue ? request.HandoffIssuedAtUtc.UtcDateTime > source.HandoffIssuedAtUtc.Value : null),
                ("version_not_below", !IsVersionBelow(request.Version, source.Version)));

            var failedChecks = string.Join(",", checks.Where(check =>
                    check.Key.StartsWith("required.", StringComparison.Ordinal) && check.Value == false)
                .Select(check => check.Key));
            var reason = replacement == null && legacyReplacement == null
                ? "same_authority_mismatch"
                : "replacement_source_authority_mismatch";
            _logger.LogWarning(new EventId(1215, "DistributionAuthorityRecoveryRefused"),
                "Distribution authority recovery refused. RequestId={RequestId} ReasonCode={ReasonCode} FailedChecks={FailedChecks} Checks={Checks}",
                request.RequestId, reason, failedChecks, JsonSerializer.Serialize(checks));
        }
        catch (Exception)
        {
            // A diagnostic/sink failure must not replace the existing 409 authority refusal,
            // cause a retry with different semantics, or expose private exception details.
        }
    }
}
