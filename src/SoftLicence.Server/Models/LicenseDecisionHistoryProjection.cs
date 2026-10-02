using System.Text.Json;
using System.Text;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Models;

/// <summary>Projects a stored event without exposing raw JSON, licence keys or reconstructed historical facts.</summary>
/// <param name="Id">Persistent history UUID.</param>
/// <param name="LicenseId">Owning licence UUID, scoped by the authenticated reader before projection.</param>
/// <param name="TimestampUtc">Stored event instant in UTC, not proof of client receipt.</param>
/// <param name="Decision">Validated version-one facts, or null when unavailable.</param>
/// <param name="ParseStatus">available, legacy or unavailable; malformed content is never returned as raw text.</param>
/// <param name="AdminPath">Relative authenticated administrator history link.</param>
public sealed record LicenseDecisionHistoryProjection(
    Guid Id, Guid LicenseId, DateTime TimestampUtc, LicenseDecisionHistory? Decision,
    string ParseStatus, string AdminPath)
{
    /// <summary>Separates structurally safe evidence from a contradictory producer selection.</summary>
    public bool? SelectionConsistent => Decision == null
        ? null : ValidCandidateSelection(Decision.ReplacementCandidates, Decision.SelectionOutcome);

    private static readonly HashSet<string> ReplacementCandidateReasonCodes = new(StringComparer.Ordinal)
    {
        "selection_not_reached",
        "source_binding_not_found_for_hardware",
        "source_license_mismatch",
        "source_subject_mismatch",
        "security_terminal_binding",
        "not_selected_recovery_source"
    };

    /// <summary>Reads the writer's version-one camel-case JSON without normalizing evidence.</summary>
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>Classifies only stored facts; another-HWID quota refusal requires serialized authority, a resolved identity, observed nonmembership and a full positive seat limit.</summary>
    /// <remarks>Legacy hardware-lock observations, missing facts and unknown codes never establish another environment. This does not compare hardware fingerprints or infer a second physical computer.</remarks>
    public string Classification => Decision switch
    {
        { Outcome: "accepted" } => "accepted",
        { Outcome: "refused", Code: "seat_limit_reached" or "SEAT_LIMIT", ResolvedHardwareId: not null,
            Snapshot: { ObservationGuarantee: "ordered_authority_locks" or "runtime_authority_locks",
                ResolvedHardwareAlreadyActive: false, ActiveSeats: { } occupied, SeatLimit: > 0 } snapshot }
            when occupied >= snapshot.SeatLimit => "expected_other_hwid_seat_limit",
        { Outcome: "refused" } => "refusal_observed",
        _ => "indeterminate"
    };

    /// <summary>Parses at most 256 KiB of structured content and checks its owning licence and bounded seat details.</summary>
    /// <param name="row">Stored history already selected through the caller's licence authorization.</param>
    /// <param name="expectedProductId">Authorized owning product, or the loaded licence navigation when omitted. Targeted API and UI callers supply this explicitly.</param>
    /// <param name="expectedRequestId">Exact request selector for request-scoped reads. When supplied, both persisted index columns must agree with their JSON counterparts and one must carry this exact value.</param>
    /// <remarks>This is presentation validation, not fresh authority resolution. The limit counts UTF8 bytes; required identity/code/phase/guarantee fields and nested seat shapes must be valid. Text limits are128 characters for labels,200 for operation/correlation and512 for HWID/version; unknown optional values stay null. Unknown versions, malformed JSON and mismatched licence/product facts remain unavailable without exposing raw content.</remarks>
    public static LicenseDecisionHistoryProjection FromHistory(
        LicenseHistory row, Guid? expectedProductId = null, string? expectedRequestId = null)
    {
        LicenseDecisionHistory? decision = null;
        var status = row.Action == "ACTIVATION_DECISION_V1" ? "unavailable" : "legacy";
        var authorizedProductId = expectedProductId ?? row.License?.ProductId;
        if (status == "unavailable" && row.Details is { Length: > 0 and <= 262144 }
            && Encoding.UTF8.GetByteCount(row.Details) <= 262144)
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<LicenseDecisionHistory>(row.Details, JsonOptions);
                if (parsed is { Version: 1, Snapshot: not null }
                    && parsed.Snapshot.LicenseId == row.LicenseId
                    && row.LicenseId != Guid.Empty && parsed.Snapshot.ProductId != Guid.Empty
                    && (!authorizedProductId.HasValue || parsed.Snapshot.ProductId == authorizedProductId.Value)
                    && RequiredText(parsed.Phase, 128) && RequiredText(parsed.OperationId, 200)
                    && RequiredText(parsed.Code, 128) && RequiredText(parsed.Snapshot.ObservationGuarantee, 128)
                    && OptionalText(parsed.ReasonCode, 128) && OptionalText(parsed.ResolutionSource, 128)
                    && OptionalText(parsed.SubmittedHardwareId, 512) && OptionalText(parsed.ResolvedHardwareId, 512)
                    && OptionalText(parsed.CorrelatedHardwareId, 512) && OptionalText(parsed.CorrelationId, 200)
                    && OptionalText(parsed.AppVersion, 512)
                    && (expectedRequestId == null || ExactIndexedRequestIdentity(row, parsed, expectedRequestId))
                    && (parsed.SelectionOutcome == null
                        || parsed.SelectionOutcome is "selected" or "none" or "not_evaluated")
                    && parsed.ReplacementCandidates?.Count is not > 16
                    && (parsed.ReplacementCandidates == null || parsed.ReplacementCandidates.All(candidate =>
                        candidate != null && candidate.SourceBindingId != Guid.Empty
                        && candidate.SourceLicenseId != Guid.Empty
                        && candidate.Outcome is "selected" or "rejected" or "not_evaluated"
                        && candidate.ReasonCodes is { Count: <= 8 }
                        && candidate.ReasonCodes.All(reason => RequiredText(reason, 128)
                            && ReplacementCandidateReasonCodes.Contains(reason))))
                    && (parsed.ReplacementCandidates == null
                        || parsed.ReplacementCandidates.Select(candidate => candidate.SourceBindingId)
                            .Distinct().Count() == parsed.ReplacementCandidates.Count)
                    && parsed.Snapshot.ActiveSeatDetails?.Count is not > 64
                    && (parsed.Snapshot.ActiveSeatDetails == null || parsed.Snapshot.ActiveSeatDetails.All(seat =>
                        seat != null && seat.SeatId != Guid.Empty && RequiredText(seat.HardwareId, 512)
                        && OptionalText(seat.AppVersion, 512)))
                    && parsed.Outcome is "accepted" or "refused"
                    && parsed.HttpStatus is >= 100 and <= 599)
                {
                    decision = parsed;
                    status = "available";
                }
            }
            catch (JsonException) { /* Preserve the row identity without exposing malformed content. */ }
        }
        return new(row.Id, row.LicenseId, DateTime.SpecifyKind(row.Timestamp, DateTimeKind.Utc),
            decision, status, $"/licenses?licenseId={row.LicenseId:D}#history-{row.Id:D}");
    }

    /// <summary>Requires bounded nonempty stored evidence without control characters; casing, Unicode and whitespace are preserved.</summary>
    private static bool RequiredText(string? value, int maximum) => value is { Length: > 0 }
        && value.Length <= maximum && !value.Any(char.IsControl);

    /// <summary>Accepts unknown optional evidence or a bounded value under the same non-normalizing presentation rule.</summary>
    private static bool OptionalText(string? value, int maximum) => value == null || RequiredText(value, maximum);

    /// <summary>Prevents an indexed request selector from authenticating unrelated or drifted JSON evidence.</summary>
    private static bool ExactIndexedRequestIdentity(
        LicenseHistory row, LicenseDecisionHistory decision, string expectedRequestId) =>
        string.Equals(row.DecisionOperationId, decision.OperationId, StringComparison.Ordinal)
        && string.Equals(row.DecisionCorrelationId, decision.CorrelationId, StringComparison.Ordinal)
        && string.Equals(row.DecisionSubmittedHardwareId, decision.SubmittedHardwareId, StringComparison.Ordinal)
        && string.Equals(row.DecisionResolvedHardwareId, decision.ResolvedHardwareId, StringComparison.Ordinal)
        && string.Equals(row.DecisionCorrelatedHardwareId, decision.CorrelatedHardwareId, StringComparison.Ordinal)
        && (string.Equals(decision.OperationId, expectedRequestId, StringComparison.Ordinal)
            || string.Equals(decision.CorrelationId, expectedRequestId, StringComparison.Ordinal));

    /// <summary>Rejects internally contradictory candidate outcomes instead of presenting syntactically valid drift as authority evidence.</summary>
    private static bool ValidCandidateSelection(
        IReadOnlyList<LicenseReplacementCandidateDecision>? candidates,
        string? selectionOutcome)
    {
        if (candidates == null) return selectionOutcome == null;
        if (candidates.Select(candidate => candidate.SourceBindingId).Distinct().Count() != candidates.Count)
            return false;
        var selected = candidates.Count(candidate => candidate.Outcome == "selected");
        if (candidates.Any(candidate => candidate.Outcome switch
        {
            "selected" => candidate.ReasonCodes.Count != 0,
            "rejected" => candidate.ReasonCodes.Count == 0
                || candidate.ReasonCodes.Contains("selection_not_reached", StringComparer.Ordinal),
            "not_evaluated" => candidate.ReasonCodes.Count != 1
                || candidate.ReasonCodes[0] != "selection_not_reached",
            _ => true
        })) return false;
        return selectionOutcome switch
        {
            "selected" => selected == 1 && candidates.All(candidate => candidate.Outcome is "selected" or "rejected"),
            "none" => candidates.Count == 0
                || (selected == 0 && candidates.All(candidate => candidate.Outcome == "rejected")),
            "not_evaluated" => candidates.Count > 0
                && candidates.All(candidate => candidate.Outcome == "not_evaluated"),
            _ => false
        };
    }
}
