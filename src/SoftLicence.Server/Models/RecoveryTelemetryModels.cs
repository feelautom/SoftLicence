using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SoftLicence.Server.Models;

/// <summary>
/// Represents a strictly parsed Recovery v1 event whose strings retain exact ordinal protocol semantics.
/// </summary>
public sealed record RecoveryTelemetryEnvelope(
    int SchemaVersion,
    string ProductCode,
    Guid EventId,
    Guid RecoveryRunId,
    int Sequence,
    DateTime OccurredAtUtc,
    string OccurredAtText,
    string ClientVersion,
    string ProcessRole,
    string Stage,
    string Outcome,
    string? SourceVersion,
    string? TargetVersion,
    string? VerifiedRestoredVersion,
    int? DurationMs,
    string? ErrorCode,
    int? MsiExitCode);

/// <summary>
/// Carries either one validated envelope or one closed rejection code plus only canonical identifiers safe to retain.
/// </summary>
public sealed record RecoveryTelemetryParseResult(
    RecoveryTelemetryEnvelope? Envelope,
    string? RejectionCode,
    Guid? RecoveryRunId,
    Guid? EventId,
    string? ProductCode)
{
    /// <summary>Gets whether parsing and all field-level contract checks succeeded.</summary>
    public bool IsSuccess => Envelope is not null;
}

/// <summary>
/// Parses and canonicalizes the closed Recovery v1 JSON contract without model-binding coercion, trimming, case folding, or unknown-field tolerance.
/// </summary>
public static partial class RecoveryTelemetryParser
{
    /// <summary>Defines the maximum accepted UTF-8 body length.</summary>
    public const int MaximumBodyBytes = 4096;

    private static readonly string[] PropertyOrder =
    [
        "schemaVersion", "productCode", "eventId", "recoveryRunId", "sequence", "occurredAtUtc",
        "clientVersion", "processRole", "stage", "outcome", "sourceVersion", "targetVersion",
        "verifiedRestoredVersion", "durationMs", "errorCode", "msiExitCode"
    ];

    private static readonly HashSet<string> ProcessRoles = new(StringComparer.Ordinal) { "unelevated", "elevated" };
    private static readonly HashSet<int> MsiExitCodes = [0, 3010, 1602, 1603, 1618, 1641];
    private static readonly IReadOnlyDictionary<string, HashSet<string>> OutcomesByStage =
        new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        {
            ["run"] = new(StringComparer.Ordinal) { "started" },
            ["preflight"] = new(StringComparer.Ordinal) { "succeeded", "failed" },
            ["confirmation"] = new(StringComparer.Ordinal) { "accepted", "cancelled", "skipped" },
            ["process_stop"] = new(StringComparer.Ordinal) { "started", "succeeded", "failed", "skipped" },
            ["backup"] = new(StringComparer.Ordinal) { "started", "succeeded", "failed", "skipped" },
            ["elevation"] = new(StringComparer.Ordinal) { "requested", "accepted", "cancelled", "failed", "not_required" },
            ["elevated_preflight"] = new(StringComparer.Ordinal) { "succeeded", "failed" },
            ["rollback"] = new(StringComparer.Ordinal) { "started", "succeeded", "failed" },
            ["version_verification"] = new(StringComparer.Ordinal) { "succeeded", "failed" },
            ["secure_commit"] = new(StringComparer.Ordinal) { "succeeded", "failed" },
            ["relaunch"] = new(StringComparer.Ordinal) { "attempted", "succeeded", "failed", "skipped" },
            ["terminal"] = new(StringComparer.Ordinal) { "completed", "failed", "cancelled" }
        };

    private static readonly IReadOnlyDictionary<string, HashSet<string>> ErrorCodesByStage = BuildErrorCodesByStage();

    /// <summary>
    /// Parses exact UTF-8 bytes and rejects duplicate keys, unknown fields, non-canonical values, and non-canonical serialization.
    /// </summary>
    /// <param name="utf8Body">The complete request bytes; they are never logged or retained on rejection.</param>
    /// <returns>A validated envelope or one privacy-safe closed rejection.</returns>
    public static RecoveryTelemetryParseResult Parse(ReadOnlySpan<byte> utf8Body)
    {
        if (utf8Body.Length > MaximumBodyBytes)
            return Reject(RecoveryTelemetryCodes.PayloadTooLarge);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(utf8Body.ToArray(), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
        }
        catch (JsonException)
        {
            return Reject(RecoveryTelemetryCodes.InvalidFieldValue);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue);

            var properties = document.RootElement.EnumerateObject().ToList();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var hasDuplicate = false;
            var hasUnknown = false;
            foreach (var property in properties)
            {
                if (!seen.Add(property.Name)) hasDuplicate = true;
                if (Array.IndexOf(PropertyOrder, property.Name) < 0) hasUnknown = true;
            }

            var safeEventId = ParseCanonicalGuid(GetUnique(properties, "eventId"));
            var safeRunId = ParseCanonicalGuid(GetUnique(properties, "recoveryRunId"));
            var safeProductCode = TryGetString(GetUnique(properties, "productCode"), out var productCandidate)
                && productCandidate == "TIA_CONNECT" ? productCandidate : null;
            if (hasDuplicate)
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, safeProductCode);
            if (hasUnknown)
                return Reject(RecoveryTelemetryCodes.UnknownField, safeRunId, safeEventId, safeProductCode);

            if (!HasRequiredFields(seen))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue);

            if (!TryGetInt32(Get(document, "schemaVersion"), out var schemaVersion) || schemaVersion != 1)
                return Reject(RecoveryTelemetryCodes.UnknownSchemaVersion, safeRunId, safeEventId);
            if (!TryGetString(Get(document, "productCode"), out var productCode) || productCode != "TIA_CONNECT")
                return Reject(RecoveryTelemetryCodes.MalformedProductCode, safeRunId, safeEventId);
            if (!safeEventId.HasValue)
                return Reject(RecoveryTelemetryCodes.MalformedEventId, safeRunId, null, productCode);
            if (!safeRunId.HasValue)
                return Reject(RecoveryTelemetryCodes.MalformedRunId, null, safeEventId, productCode);
            if (!TryGetInt32(Get(document, "sequence"), out var sequence) || sequence is < 1 or > 32)
                return Reject(RecoveryTelemetryCodes.SequenceOutOfRange, safeRunId, safeEventId, productCode);
            if (!TryGetString(Get(document, "occurredAtUtc"), out var occurredAtText)
                || !DateTime.TryParseExact(occurredAtText, "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var occurredAtUtc))
                return Reject(RecoveryTelemetryCodes.InvalidTimestamp, safeRunId, safeEventId, productCode);
            if (!TryGetString(Get(document, "clientVersion"), out var clientVersion) || !VersionRegex().IsMatch(clientVersion))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);
            if (!TryGetString(Get(document, "processRole"), out var processRole) || !ProcessRoles.Contains(processRole))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);
            if (!TryGetString(Get(document, "stage"), out var stage) || !OutcomesByStage.ContainsKey(stage))
                return Reject(RecoveryTelemetryCodes.UnknownStage, safeRunId, safeEventId, productCode);
            if (!TryGetString(Get(document, "outcome"), out var outcome))
                return Reject(RecoveryTelemetryCodes.UnknownOutcome, safeRunId, safeEventId, productCode);
            if (!OutcomesByStage[stage].Contains(outcome))
                return Reject(OutcomesByStage.Values.Any(values => values.Contains(outcome))
                    ? RecoveryTelemetryCodes.InvalidStageOutcome
                    : RecoveryTelemetryCodes.UnknownOutcome, safeRunId, safeEventId, productCode);

            var sourceVersion = GetOptionalVersion(document, "sourceVersion", out var sourceValid);
            var targetVersion = GetOptionalVersion(document, "targetVersion", out var targetValid);
            var verifiedVersion = GetOptionalVersion(document, "verifiedRestoredVersion", out var verifiedValid);
            if (!sourceValid || !targetValid || !verifiedValid)
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);
            if ((stage == "version_verification" && outcome == "succeeded")
                ? verifiedVersion is null || targetVersion is null || verifiedVersion != targetVersion
                : verifiedVersion is not null)
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);

            var durationMs = GetOptionalInt32(document, "durationMs", out var durationValid);
            if (!durationValid || durationMs is < 0 or > 3_600_000 || (durationMs.HasValue && IsStartLike(outcome)))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);
            var errorCode = GetOptionalString(document, "errorCode", out var errorValid);
            var requiresError = outcome is "failed" or "cancelled";
            if (!errorValid || requiresError != (errorCode is not null)
                || (errorCode is not null && !IsAllowedErrorCode(stage, outcome, errorCode)))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);
            var msiExitCode = GetOptionalInt32(document, "msiExitCode", out var msiValid);
            if (!msiValid || (msiExitCode.HasValue && (stage != "rollback" || outcome is not ("succeeded" or "failed") || !MsiExitCodes.Contains(msiExitCode.Value))))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);

            var envelope = new RecoveryTelemetryEnvelope(schemaVersion, productCode, safeEventId.Value, safeRunId.Value,
                sequence, DateTime.SpecifyKind(occurredAtUtc, DateTimeKind.Utc), occurredAtText, clientVersion, processRole,
                stage, outcome, sourceVersion, targetVersion, verifiedVersion, durationMs, errorCode, msiExitCode);

            // Exact-byte replay is meaningful only when every accepted request uses the frozen canonical representation.
            if (!utf8Body.SequenceEqual(SerializeCanonical(envelope)))
                return Reject(RecoveryTelemetryCodes.InvalidFieldValue, safeRunId, safeEventId, productCode);

            return new RecoveryTelemetryParseResult(envelope, null, safeRunId, safeEventId, productCode);
        }
    }

    /// <summary>
    /// Serializes one already validated envelope using the frozen property order, omission rules, compact UTF-8, and no BOM.
    /// </summary>
    /// <param name="envelope">The envelope whose values already satisfy the v1 grammar.</param>
    /// <returns>The canonical bytes used for payload hashing and exact replay.</returns>
    public static byte[] SerializeCanonical(RecoveryTelemetryEnvelope envelope)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", envelope.SchemaVersion);
            writer.WriteString("productCode", envelope.ProductCode);
            writer.WriteString("eventId", envelope.EventId.ToString("D"));
            writer.WriteString("recoveryRunId", envelope.RecoveryRunId.ToString("D"));
            writer.WriteNumber("sequence", envelope.Sequence);
            writer.WriteString("occurredAtUtc", envelope.OccurredAtText);
            writer.WriteString("clientVersion", envelope.ClientVersion);
            writer.WriteString("processRole", envelope.ProcessRole);
            writer.WriteString("stage", envelope.Stage);
            writer.WriteString("outcome", envelope.Outcome);
            WriteOptional(writer, "sourceVersion", envelope.SourceVersion);
            WriteOptional(writer, "targetVersion", envelope.TargetVersion);
            WriteOptional(writer, "verifiedRestoredVersion", envelope.VerifiedRestoredVersion);
            if (envelope.DurationMs.HasValue) writer.WriteNumber("durationMs", envelope.DurationMs.Value);
            WriteOptional(writer, "errorCode", envelope.ErrorCode);
            if (envelope.MsiExitCode.HasValue) writer.WriteNumber("msiExitCode", envelope.MsiExitCode.Value);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    /// <summary>Returns whether a stage/outcome pair belongs to the frozen v1 vocabulary.</summary>
    public static bool IsAllowedStageOutcome(string stage, string outcome) =>
        OutcomesByStage.TryGetValue(stage, out var outcomes) && outcomes.Contains(outcome);

    /// <summary>Builds immutable ordinal stage-specific error allowlists without accepting exception-derived values.</summary>
    private static IReadOnlyDictionary<string, HashSet<string>> BuildErrorCodesByStage()
    {
        var allTechnical = new HashSet<string>(StringComparer.Ordinal)
        {
            "transaction_missing", "transaction_invalid", "receipt_invalid", "package_missing", "package_hash_invalid",
            "package_signature_invalid", "package_version_mismatch", "recovery_not_authorized", "process_identity_unavailable",
            "process_stop_timeout", "backup_source_untrusted", "backup_io_failed", "elevation_start_failed", "handoff_state_mismatch",
            "transaction_changed", "machine_lock_timeout", "elevated_revalidation_failed", "staging_failed", "uninstall_failed",
            "install_failed", "msi_busy", "msi_cancelled", "msi_reboot_initiated", "msi_other", "installed_product_missing",
            "restored_version_mismatch", "marker_write_failed", "lockdown_clear_failed", "application_start_failed",
            "outbox_io_failed", "unexpected_failure"
        };
        return new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        {
            ["preflight"] = new(StringComparer.Ordinal) { "transaction_missing", "transaction_invalid", "receipt_invalid", "package_missing", "package_hash_invalid", "package_signature_invalid", "package_version_mismatch", "recovery_not_authorized", "unexpected_failure" },
            ["confirmation"] = new(StringComparer.Ordinal) { "user_cancelled" },
            ["process_stop"] = new(StringComparer.Ordinal) { "process_identity_unavailable", "process_stop_timeout", "unexpected_failure" },
            ["backup"] = new(StringComparer.Ordinal) { "backup_source_untrusted", "backup_io_failed", "unexpected_failure" },
            ["elevation"] = new(StringComparer.Ordinal) { "uac_cancelled", "elevation_start_failed", "handoff_state_mismatch", "transaction_changed", "unexpected_failure" },
            ["elevated_preflight"] = new(StringComparer.Ordinal) { "handoff_state_mismatch", "transaction_changed", "machine_lock_timeout", "elevated_revalidation_failed", "unexpected_failure" },
            ["rollback"] = new(StringComparer.Ordinal) { "staging_failed", "uninstall_failed", "install_failed", "msi_busy", "msi_cancelled", "msi_reboot_initiated", "msi_other", "unexpected_failure" },
            ["version_verification"] = new(StringComparer.Ordinal) { "installed_product_missing", "restored_version_mismatch", "unexpected_failure" },
            ["secure_commit"] = new(StringComparer.Ordinal) { "marker_write_failed", "lockdown_clear_failed", "unexpected_failure" },
            ["relaunch"] = new(StringComparer.Ordinal) { "application_start_failed", "unexpected_failure" },
            ["terminal"] = new(allTechnical.Concat(["user_cancelled", "uac_cancelled"]), StringComparer.Ordinal)
        };
    }

    /// <summary>Checks cancellation-specific codes before the broader failure allowlists.</summary>
    private static bool IsAllowedErrorCode(string stage, string outcome, string code)
    {
        if (outcome == "cancelled" && stage == "elevation") return code == "uac_cancelled";
        if (outcome == "cancelled" && stage == "confirmation") return code == "user_cancelled";
        if (outcome == "cancelled" && stage == "terminal") return code is "user_cancelled" or "uac_cancelled";
        if (code == "outbox_io_failed") return true;
        return ErrorCodesByStage.TryGetValue(stage, out var codes) && codes.Contains(code);
    }

    /// <summary>Checks presence only; kind and value validation remain separate and fail closed.</summary>
    private static bool HasRequiredFields(HashSet<string> fields) =>
        new[] { "schemaVersion", "productCode", "eventId", "recoveryRunId", "sequence", "occurredAtUtc", "clientVersion", "processRole", "stage", "outcome" }.All(fields.Contains);

    /// <summary>Returns a required property after the required-field gate has succeeded.</summary>
    private static JsonElement Get(JsonDocument document, string name) => document.RootElement.GetProperty(name);
    /// <summary>Returns a value only when exactly one property with the ordinal name exists.</summary>
    private static JsonElement GetUnique(IReadOnlyList<JsonProperty> properties, string name)
    {
        var matches = properties.Where(property => property.Name == name).Take(2).ToList();
        return matches.Count == 1 ? matches[0].Value : default;
    }
    /// <summary>Reads an exact JSON string without trimming, normalization, or conversion.</summary>
    private static bool TryGetString(JsonElement element, out string value) { value = element.ValueKind == JsonValueKind.String ? element.GetString() ?? string.Empty : string.Empty; return element.ValueKind == JsonValueKind.String; }
    /// <summary>Reads an exact JSON integer without accepting numeric strings or fractions.</summary>
    private static bool TryGetInt32(JsonElement element, out int value)
    {
        value = default;
        return element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out value);
    }
    /// <summary>Accepts only lowercase unbraced UUID D text and returns no invalid candidate.</summary>
    private static Guid? ParseCanonicalGuid(JsonElement element) => TryGetString(element, out var value) && Guid.TryParseExact(value, "D", out var parsed) && value == parsed.ToString("D") ? parsed : null;
    /// <summary>Reads an omitted-or-canonical three-component version.</summary>
    private static string? GetOptionalVersion(JsonDocument document, string name, out bool valid) { var value = GetOptionalString(document, name, out valid); valid = valid && (value is null || VersionRegex().IsMatch(value)); return value; }
    /// <summary>Reads an omitted-or-string field while rejecting explicit null.</summary>
    private static string? GetOptionalString(JsonDocument document, string name, out bool valid) { if (!document.RootElement.TryGetProperty(name, out var element)) { valid = true; return null; } valid = TryGetString(element, out var value); return valid ? value : null; }
    /// <summary>Reads an omitted-or-integer field while rejecting explicit null and coercion.</summary>
    private static int? GetOptionalInt32(JsonDocument document, string name, out bool valid) { if (!document.RootElement.TryGetProperty(name, out var element)) { valid = true; return null; } valid = TryGetInt32(element, out var value); return valid ? value : null; }
    /// <summary>Identifies non-result outcomes on which duration is forbidden.</summary>
    private static bool IsStartLike(string outcome) => outcome is "started" or "requested" or "attempted";
    /// <summary>Writes an optional string only when present so canonical JSON never contains null.</summary>
    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value) { if (value is not null) writer.WriteString(name, value); }
    /// <summary>Creates a rejection containing only identifiers that already passed canonical validation.</summary>
    private static RecoveryTelemetryParseResult Reject(string code, Guid? runId = null, Guid? eventId = null, string? productCode = null) => new(null, code, runId, eventId, productCode);

    [GeneratedRegex("^(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})$", RegexOptions.CultureInvariant)]
    /// <summary>Gets the invariant compiled grammar for exactly three non-zero-padded numeric components.</summary>
    private static partial Regex VersionRegex();
}

/// <summary>Defines the closed Recovery v1 success and rejection codes exposed by the API.</summary>
public static class RecoveryTelemetryCodes
{
    /// <summary>Indicates a newly durable event.</summary>
    public const string Accepted = "accepted";
    /// <summary>Indicates a byte-identical durable replay.</summary>
    public const string ExactReplay = "exact_replay";
    /// <summary>Rejects any schema version other than integer one.</summary>
    public const string UnknownSchemaVersion = "unknown_schema_version";
    /// <summary>Rejects a non-exact product code.</summary>
    public const string MalformedProductCode = "malformed_product_code";
    /// <summary>Rejects a non-canonical run UUID.</summary>
    public const string MalformedRunId = "malformed_run_id";
    /// <summary>Rejects a non-canonical event UUID.</summary>
    public const string MalformedEventId = "malformed_event_id";
    /// <summary>Rejects a sequence outside 1 through 32.</summary>
    public const string SequenceOutOfRange = "sequence_out_of_range";
    /// <summary>Rejects a timestamp outside the fixed UTC microsecond grammar.</summary>
    public const string InvalidTimestamp = "invalid_timestamp";
    /// <summary>Rejects a stage outside the closed vocabulary.</summary>
    public const string UnknownStage = "unknown_stage";
    /// <summary>Rejects an outcome outside the closed vocabulary.</summary>
    public const string UnknownOutcome = "unknown_outcome";
    /// <summary>Rejects a known outcome paired with the wrong stage.</summary>
    public const string InvalidStageOutcome = "invalid_stage_outcome";
    /// <summary>Rejects an impossible predecessor/successor relation.</summary>
    public const string InvalidTransition = "invalid_transition";
    /// <summary>Rejects an event that arrived before its required predecessor.</summary>
    public const string OutOfOrder = "out_of_order";
    /// <summary>Rejects a competing terminal or any event after terminal.</summary>
    public const string TerminalConflict = "terminal_conflict";
    /// <summary>Rejects reuse of event or sequence identity with different canonical bytes.</summary>
    public const string IdempotencyConflict = "idempotency_conflict";
    /// <summary>Rejects any non-allowlisted property; duplicate properties use invalid_field_value.</summary>
    public const string UnknownField = "unknown_field";
    /// <summary>Rejects invalid JSON kinds, values, conditionals, or canonical serialization.</summary>
    public const string InvalidFieldValue = "invalid_field_value";
    /// <summary>Rejects a request exceeding 4,096 UTF-8 bytes.</summary>
    public const string PayloadTooLarge = "payload_too_large";
    /// <summary>Rejects the valid product code when its exact server product does not exist.</summary>
    public const string ProductUnresolved = "product_unresolved";
}

/// <summary>Defines the minimal response body returned for every Recovery v1 ingestion outcome.</summary>
public sealed record RecoveryTelemetryResponse(string Code, Guid CorrelationId);
