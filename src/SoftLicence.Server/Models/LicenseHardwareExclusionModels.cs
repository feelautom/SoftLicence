namespace SoftLicence.Server.Models;

/// <summary>
/// Carries the exact closed Website-to-provider licence hardware exclusion contract. The
/// <see cref="HardwareId"/> must already be the canonical uppercase 16-character identifier;
/// the provider never normalizes it.
/// </summary>
/// <param name="Schema">Exact contract schema identifier.</param>
/// <param name="RequestId">Canonical lowercase UUID used for durable idempotency and correlation.</param>
/// <param name="ProductId">Canonical lowercase provider product UUID.</param>
/// <param name="LicenseId">Canonical lowercase provider licence UUID.</param>
/// <param name="HardwareId">Canonical uppercase ASCII hardware authority (16 hexadecimal characters).</param>
/// <param name="ReleaseActiveSeat">Releases the active seat with the provider-authority reason in the same transaction.</param>
public sealed record LicenseHardwareExclusionRequest(
    string? Schema,
    string? RequestId,
    string? ProductId,
    string? LicenseId,
    string? HardwareId,
    bool? ReleaseActiveSeat);

/// <summary>Carries the closed lift contract; lifting never reactivates anything.</summary>
/// <param name="Schema">Exact contract schema identifier.</param>
/// <param name="RequestId">Canonical lowercase UUID used for durable idempotency and correlation.</param>
/// <param name="ProductId">Canonical lowercase provider product UUID.</param>
/// <param name="LicenseId">Canonical lowercase provider licence UUID.</param>
/// <param name="HardwareId">Canonical uppercase ASCII hardware authority (16 hexadecimal characters).</param>
public sealed record LicenseHardwareExclusionLiftRequest(
    string? Schema,
    string? RequestId,
    string? ProductId,
    string? LicenseId,
    string? HardwareId);

/// <summary>Carries the closed bounded list contract for one licence.</summary>
/// <param name="Schema">Exact contract schema identifier.</param>
/// <param name="RequestId">Canonical lowercase UUID used for correlation and logging only.</param>
/// <param name="ProductId">Canonical lowercase provider product UUID.</param>
/// <param name="LicenseId">Canonical lowercase provider licence UUID.</param>
/// <param name="IncludeLifted">Includes lifted exclusions after the active ones, oldest first.</param>
public sealed record LicenseHardwareExclusionListRequest(
    string? Schema,
    string? RequestId,
    string? ProductId,
    string? LicenseId,
    bool? IncludeLifted);

/// <summary>One bounded exclusion line returned by the list contract.</summary>
/// <param name="HardwareId">Canonical hardware authority of the excluded machine.</param>
/// <param name="CreatedAtUtc">Exclusion commit time in UTC.</param>
/// <param name="LiftedAtUtc">Lift time in UTC, or null while the exclusion is active.</param>
/// <param name="Actor">Closed actor that created the exclusion.</param>
/// <param name="LiftedByActor">Closed actor that lifted the exclusion, or null.</param>
public sealed record LicenseHardwareExclusionEntry(
    string HardwareId,
    DateTime CreatedAtUtc,
    DateTime? LiftedAtUtc,
    string Actor,
    string? LiftedByActor);

/// <summary>Returns the bounded terminal result accepted by the Website contract.</summary>
/// <param name="Schema">Exact response schema identifier.</param>
/// <param name="RequestId">Canonical correlation UUID copied from the authenticated request.</param>
/// <param name="Outcome">Terminal <c>excluded</c> or <c>already_excluded</c> outcome.</param>
/// <param name="ReleaseOutcome"><c>deactivated</c>, <c>already_inactive</c> or <c>none</c>.</param>
public sealed record LicenseHardwareExclusionResponse(
    string Schema,
    string RequestId,
    string Outcome,
    string ReleaseOutcome);

/// <summary>Returns the bounded terminal result of a lift request.</summary>
/// <param name="Schema">Exact response schema identifier.</param>
/// <param name="RequestId">Canonical correlation UUID copied from the authenticated request.</param>
/// <param name="Outcome">Terminal <c>lifted</c> or <c>already_lifted</c> outcome.</param>
public sealed record LicenseHardwareExclusionLiftResponse(
    string Schema,
    string RequestId,
    string Outcome);

/// <summary>Returns one bounded list page; lines carry no free text and no client identifiers.</summary>
/// <param name="Schema">Exact response schema identifier.</param>
/// <param name="RequestId">Canonical correlation UUID copied from the authenticated request.</param>
/// <param name="Entries">Bounded exclusion lines, active ones first.</param>
public sealed record LicenseHardwareExclusionListResponse(
    string Schema,
    string RequestId,
    IReadOnlyList<LicenseHardwareExclusionEntry> Entries);

/// <summary>Wraps an add-exclusion response and its exact-replay state.</summary>
/// <param name="Response">Bounded terminal response.</param>
/// <param name="Idempotent">True when the response was recovered from durable request storage.</param>
public sealed record LicenseHardwareExclusionResult(
    LicenseHardwareExclusionResponse Response,
    bool Idempotent);
