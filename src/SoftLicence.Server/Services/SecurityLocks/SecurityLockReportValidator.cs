using System.Globalization;
using System.Text.RegularExpressions;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>Validated, canonical lock report.</summary>
/// <param name="ReportId">Canonical lower-case UUID.</param>
/// <param name="SentAtUtc">Client send time.</param>
/// <param name="HardwareId">Upper-case hardware identifier.</param>
/// <param name="AppVersion">Exact release version.</param>
/// <param name="LockId">32 lower-case hexadecimal characters.</param>
/// <param name="Cause">Catalogued cause.</param>
/// <param name="Level">Catalogued level.</param>
/// <param name="ClientMode">Client enforcement mode.</param>
/// <param name="EvidenceDigestSha256">64 lower-case hexadecimal characters.</param>
/// <param name="FirstSeenUtc">First local detection.</param>
public sealed record SecurityLockValidatedReport(
    string ReportId,
    DateTimeOffset SentAtUtc,
    string HardwareId,
    string AppVersion,
    string LockId,
    string Cause,
    int Level,
    string ClientMode,
    string EvidenceDigestSha256,
    DateTimeOffset FirstSeenUtc);

/// <summary>Rejected lock report with a closed error code.</summary>
/// <param name="errorCode">Stable error code returned to the client.</param>
public sealed class SecurityLockReportValidationException(string errorCode) : Exception(errorCode)
{
    /// <summary>Stable error code.</summary>
    public string ErrorCode { get; } = errorCode;
}

/// <summary>
/// Strict validator for <see cref="SecurityLockReportRequest"/>. Security contract: identifiers are validated
/// against their canonical alphabet and never case-folded or trimmed, so a look-alike or padded value is a
/// failure instead of being silently mapped onto another installation's lock.
/// </summary>
public static partial class SecurityLockReportValidator
{
    /// <summary>Exact request schema.</summary>
    public const string RequestSchema = "tia-security-lock-report-v1";
    /// <summary>Maximum accepted clock distance between client send time and server time.</summary>
    public static readonly TimeSpan MaximumClockDistance = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Validates the request. Failures throw <see cref="SecurityLockReportValidationException"/>; nothing is
    /// persisted before this contract succeeds.
    /// </summary>
    /// <param name="request">Deserialized request.</param>
    /// <param name="now">Authoritative server time.</param>
    /// <returns>The canonical validated report.</returns>
    public static SecurityLockValidatedReport Validate(SecurityLockReportRequest request, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!string.Equals(request.Schema, RequestSchema, StringComparison.Ordinal)) throw Fail("schema_invalid");
        if (request.ExtensionData is { Count: > 0 }) throw Fail("unexpected_field");
        if (!TryCanonicalUuid(request.ReportId, out var reportId)) throw Fail("report_id_invalid");
        if (!TryCanonicalUtc(request.SentAtUtc, out var sentAt)) throw Fail("sent_at_invalid");
        if (sentAt < now - MaximumClockDistance || sentAt > now + MaximumClockDistance) throw Fail("sent_at_outside_window");
        if (request.HardwareId is null || !HardwareIdRegex().IsMatch(request.HardwareId)) throw Fail("hardware_id_invalid");
        if (request.AppVersion is null || !AppVersionRegex().IsMatch(request.AppVersion)) throw Fail("app_version_invalid");
        if (request.LockId is null || !LockIdRegex().IsMatch(request.LockId)) throw Fail("lock_id_invalid");
        if (!SecurityLockCauseCatalog.TryGetLevel(request.Cause, out var level)) throw Fail("cause_unknown");
        if (request.Level != level) throw Fail("level_mismatch");
        if (!SecurityLockCauseCatalog.IsMode(request.Mode)) throw Fail("mode_invalid");
        var irreversible = SecurityLockCauseCatalog.IsIrreversibleCandidate(level);
        if (irreversible == string.Equals(request.Mode, SecurityLockCauseCatalog.ModeNotApplicable, StringComparison.Ordinal))
            throw Fail("mode_mismatch");
        if (request.EvidenceDigestSha256 is null || !Sha256Regex().IsMatch(request.EvidenceDigestSha256)) throw Fail("evidence_digest_invalid");
        if (!TryCanonicalUtc(request.FirstSeenUtc, out var firstSeen) || firstSeen > now + MaximumClockDistance)
            throw Fail("first_seen_invalid");

        return new SecurityLockValidatedReport(reportId, sentAt, request.HardwareId, request.AppVersion,
            request.LockId, request.Cause!, level, request.Mode!, request.EvidenceDigestSha256, firstSeen);
    }

    /// <summary>Formats a UTC instant in the canonical seven-digit form used by requests and verdicts.</summary>
    /// <param name="value">Instant to format.</param>
    public static string FormatUtc(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

    private static SecurityLockReportValidationException Fail(string code) => new(code);

    private static bool TryCanonicalUuid(string? value, out string canonical)
    {
        canonical = string.Empty;
        if (!Guid.TryParseExact(value, "D", out var parsed)) return false;
        canonical = parsed.ToString("D", CultureInfo.InvariantCulture);
        return string.Equals(value, canonical, StringComparison.Ordinal);
    }

    private static bool TryCanonicalUtc(string? value, out DateTimeOffset parsed)
    {
        parsed = default;
        return value != null
            && DateTimeOffset.TryParseExact(value, "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed)
            && string.Equals(FormatUtc(parsed), value, StringComparison.Ordinal);
    }

    [GeneratedRegex(@"\A[A-Z0-9_.-]{1,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex HardwareIdRegex();

    [GeneratedRegex(@"\A[0-9A-Za-z.+-]{1,64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex AppVersionRegex();

    [GeneratedRegex(@"\A[0-9a-f]{32}\z", RegexOptions.CultureInvariant)]
    private static partial Regex LockIdRegex();

    [GeneratedRegex(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Regex();
}
