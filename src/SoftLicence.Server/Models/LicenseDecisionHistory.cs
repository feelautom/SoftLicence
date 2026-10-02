namespace SoftLicence.Server.Models;

/// <summary>Freezes one active seat's provider-owned identity at decision time; never infer hardware equivalence from its display format.</summary>
/// <param name="SeatId">Exact persistent seat UUID.</param>
/// <param name="HardwareId">Exact stored hardware identity, without normalization or telemetry substitution.</param>
/// <param name="FirstActivatedAtUtc">Stored UTC first-activation instant.</param>
/// <param name="AppVersion">Stored seat version at observation, or null if absent.</param>
public sealed record LicenseDecisionSeat(Guid SeatId, string HardwareId, DateTime FirstActivatedAtUtc, string? AppVersion);

/// <summary>Stores immutable, provider-observed licence context before a decision's business effects.</summary>
/// <param name="ProductId">Server-established product UUID; never inferred from telemetry.</param>
/// <param name="LicenseId">Server-established licence UUID owning this history.</param>
/// <param name="LicenseAuthorityVersion">Opaque database version, or null when no locked licence snapshot was available.</param>
/// <param name="AuthorityEpoch">Runtime database epoch observed under existing locks; detects state cycles, including seat deletion/recreation. Unrelated authority changes may also distinguish observations.</param>
/// <param name="ActiveSeats">Occupied seats before business effects, or null when unobserved.</param>
/// <param name="SeatLimit">Commercial seat limit at observation, or null when unobserved.</param>
/// <param name="ActivationsToday">Seats first activated since UTC midnight, using the existing quota predicate; null when unobserved.</param>
/// <param name="DailyActivationLimit">Existing daily limit; zero means unlimited, null means unobserved.</param>
/// <param name="SeatStateDigest">Lowercase SHA-256 of the ordered observed set: complete loaded seats for Finalize, active predicate rows for legacy quota. Not a hardware authority proof.</param>
/// <param name="ActiveSeatDetails">At most 64 active seats ordered by UUID; null means unobserved, empty means observed empty.</param>
/// <param name="ActiveSeatDetailsTruncated">True when additional active seats were omitted from display details; counts and digest still cover the complete observed set.</param>
/// <param name="ResolvedHardwareAlreadyActive">Exact ordinal membership of resolved HWID in the complete observed active set; null when unresolved.</param>
/// <param name="ObservationGuarantee">ordered_authority_locks for Finalize; runtime_authority_locks for authenticated Runtime transfer; hardware_lock_observation for legacy, which does not assert global atomicity across different HWIDs. authenticated_entitlement_identity_only and authenticated_source_identity_only retain identity without quota observations; authorized_offline_precheck_observation precedes the existing predicate and does not assert a ban remains active after its independent maintenance transaction. Each label describes existing observation boundaries, not stronger authorization.</param>
public sealed record LicenseDecisionSnapshot(
    Guid ProductId, Guid LicenseId, Guid? LicenseAuthorityVersion, long? AuthorityEpoch,
    int? ActiveSeats, int? SeatLimit, int? ActivationsToday, int? DailyActivationLimit,
    string? SeatStateDigest, IReadOnlyList<LicenseDecisionSeat>? ActiveSeatDetails,
    bool ActiveSeatDetailsTruncated, bool? ResolvedHardwareAlreadyActive, string ObservationGuarantee);

/// <summary>Captures one submitted replacement candidate and the provider-owned reasons it was accepted or rejected.</summary>
/// <param name="SourceBindingId">Exact submitted source binding UUID.</param>
/// <param name="SourceLicenseId">Exact submitted source licence UUID.</param>
/// <param name="Outcome">selected, rejected or not_evaluated.</param>
/// <param name="ReasonCodes">Closed provider reason codes; no subject digest or raw proof is exposed.</param>
public sealed record LicenseReplacementCandidateDecision(
    Guid SourceBindingId, Guid SourceLicenseId, string Outcome, IReadOnlyList<string> ReasonCodes);

/// <summary>Version-one structured content for an existing LicenseHistories row, without raw requests, keys, tokens, or inferred historical identities.</summary>
/// <param name="Version">Closed schema version, currently one.</param>
/// <param name="Phase">Exact producer phase, such as distribution_finalize or legacy_activation.</param>
/// <param name="OperationId">Exact authenticated S2S request identifier; a server-generated per-request identifier for legacy calls.</param>
/// <param name="Outcome">Exact accepted or refused outcome; does not assert persistence before outer commit.</param>
/// <param name="Code">Existing canonical business error code, or accepted for a successful decision.</param>
/// <param name="ReasonCode">Existing narrower canonical reason, when the producer supplies one.</param>
/// <param name="HttpStatus">Business decision status for the called surface, including the existing offline wrapper mapping. Commit acknowledgement loss can instead produce a technical response after this row committed; this field never proves client receipt.</param>
/// <param name="SubmittedHardwareId">Validated submitted identity, preserved with existing producer normalization only.</param>
/// <param name="ResolvedHardwareId">Identity established by the provider's resolver; null means unresolved, not equal by inference.</param>
/// <param name="CorrelatedHardwareId">Observation-only correlation; null unless a separate provenance source exists. Never used as authority.</param>
/// <param name="ResolutionSource">Exact provenance label for the resolved identity, or null when unresolved.</param>
/// <param name="Snapshot">Frozen facts for an authoritatively identified licence, subject to the explicit observation guarantee; missing observations stay null.</param>
/// <param name="AppVersion">Validated producer application version, or null when absent; not reconstructed from later telemetry.</param>
/// <param name="CorrelationId">Exact bounded HTTP correlation when observed, otherwise null. Excluded from decision deduplication; the first stored event preserves its original correlation and never claims a retry's transport receipt.</param>
public sealed record LicenseDecisionHistory(
    int Version, string Phase, string OperationId, string Outcome, string Code,
    string? ReasonCode, int HttpStatus, string? SubmittedHardwareId, string? ResolvedHardwareId,
    string? CorrelatedHardwareId, string? ResolutionSource, LicenseDecisionSnapshot Snapshot, string? AppVersion,
    string? CorrelationId = null,
    IReadOnlyList<LicenseReplacementCandidateDecision>? ReplacementCandidates = null,
    string? SelectionOutcome = null);
