using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Services.CloneGuard;

/// <summary>
/// Optional <c>cloneGuard</c> member of a managed <c>POST /api/activation/check</c> request (TKT-003615). Absent for
/// installed versions and for the native heartbeat, which keep the historical behavior. Contract:
/// <c>docs/schema/jeton-anti-clonage.md</c>.
/// </summary>
public sealed class CloneGuardCheckRequest
{
    /// <summary>Gets or sets the protocol version; only <c>1</c> is evaluated, any other value is answered <c>UNSUPPORTED_PROTOCOL</c>.</summary>
    public int? ProtocolVersion { get; set; }

    /// <summary>
    /// Gets or sets the current token held by the installation (unpadded base64url of 32 bytes, 43 characters), or
    /// <see langword="null"/> when the installation has none yet. Opaque: never trimmed nor case-folded.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>Gets or sets the next token drawn by the installation and persisted before sending; same format as <see cref="Token"/>.</summary>
    public string? NextToken { get; set; }

    /// <summary>Gets or sets the VM Generation ID exposed by Windows (32 hexadecimal characters), or <see langword="null"/>.</summary>
    public string? VmGenerationId { get; set; }
}

/// <summary>
/// Body of <c>POST /api/activation/clone-guard/reactivate</c> (TKT-003615): the copy that was answered
/// <c>DUPLICATE_DETECTED</c> asks to become the single active copy of its seat.
/// </summary>
public sealed class CloneGuardReactivationRequest
{
    /// <summary>Gets or sets the licence key; trimmed and upper-cased like every other activation route.</summary>
    public required string LicenseKey { get; set; }

    /// <summary>Gets or sets the canonical hardware identifier of the caller (same validation as the check).</summary>
    public required string HardwareId { get; set; }

    /// <summary>Gets or sets the product name, matched case-insensitively like the check.</summary>
    public required string AppName { get; set; }

    /// <summary>Gets or sets the optional product identifier.</summary>
    public string? AppId { get; set; }

    /// <summary>Gets or sets the client version, checked against the product minimum version like the check.</summary>
    public string? AppVersion { get; set; }

    /// <summary>
    /// Gets or sets the raw system UUID, as on the check: the same machine-identity rule applies, so a refused device is
    /// refused here too. <see langword="null"/> keeps the historical behavior of the check (no UUID rule).
    /// </summary>
    public string? SystemUuid { get; set; }

    /// <summary>Gets or sets the current machine observations, as on the check; never an authority by themselves.</summary>
    public System.Text.Json.JsonElement? MachineEvidence { get; set; }

    /// <summary>Gets or sets the next token drawn and persisted by the caller (unpadded base64url of 32 bytes).</summary>
    public string? NextToken { get; set; }

    /// <summary>Gets or sets the VM Generation ID exposed by Windows, or <see langword="null"/>.</summary>
    public string? VmGenerationId { get; set; }
}

/// <summary>
/// <c>cloneGuard</c> member of the check and reactivation responses. Serialized only when the request carried a
/// clone guard member, so the response of an installed version is byte-for-byte unchanged.
/// </summary>
/// <param name="Outcome">One of <see cref="CloneGuardOutcomes"/>.</param>
/// <param name="Reason">Machine-readable cause (<see cref="CloneGuardReasons"/>), or <see langword="null"/>.</param>
/// <param name="EnvironmentChanged">True when an accepted check reported a VM Generation ID different from the known one.</param>
public sealed record CloneGuardResponse(
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("environmentChanged")] bool EnvironmentChanged);

/// <summary>Closed vocabulary of <see cref="CloneGuardResponse.Outcome"/>; ASCII upper-case, compared ordinally by clients.</summary>
public static class CloneGuardOutcomes
{
    /// <summary>The guard was created (or re-armed after an activation) with the caller's next token.</summary>
    public const string Armed = "ARMED";
    /// <summary>The current token was consumed and the next token became current.</summary>
    public const string Accepted = "ACCEPTED";
    /// <summary>Exact replay of the last accepted pair after a lost response; nothing changed.</summary>
    public const string Replayed = "REPLAYED";
    /// <summary>The caller holds a consumed, unknown or missing token: another copy runs; the caller is suspended.</summary>
    public const string DuplicateDetected = "DUPLICATE_DETECTED";
    /// <summary>The logical status is not VALID, so no token was consumed and the caller keeps its token.</summary>
    public const string NotEvaluated = "NOT_EVALUATED";
    /// <summary>Valid licence without an active seat row for the caller (historical single-field licence).</summary>
    public const string NotApplicable = "NOT_APPLICABLE";
    /// <summary>The clone guard member was present but invalid; nothing was consumed.</summary>
    public const string Malformed = "MALFORMED";
    /// <summary>Unknown protocol version; the request was evaluated as if it had no clone guard member.</summary>
    public const string UnsupportedProtocol = "UNSUPPORTED_PROTOCOL";
    /// <summary>Guided reactivation applied: the caller is the single active copy of the seat.</summary>
    public const string Reactivated = "REACTIVATED";
    /// <summary>Guided reactivation refused: the licence's daily quota is exhausted; the active copy stays usable.</summary>
    public const string ReactivationLimitReached = "REACTIVATION_LIMIT_REACHED";
}

/// <summary>Closed vocabulary of <see cref="CloneGuardResponse.Reason"/> and of collision journal reasons.</summary>
public static class CloneGuardReasons
{
    /// <summary>The presented token is consumed (with a different next token) or unknown.</summary>
    public const string StaleToken = "stale_token";
    /// <summary>A guard-aware client sent no token while the seat is armed and was not re-activated since.</summary>
    public const string TokenMissing = "token_missing";
    /// <summary>The licence already used its whole daily quota (machine changes plus reactivations).</summary>
    public const string DailyQuotaExhausted = "daily_quota_exhausted";
    /// <summary>
    /// Journal reason of a reactivation accepted although the daily quota is exhausted, because the copy holding the
    /// current token has not beaten for two intervals: a paid licence always keeps one working machine.
    /// </summary>
    public const string QuotaExhaustedHolderInactive = "quota_exhausted_holder_inactive";
}

/// <summary>
/// Strict parsing of the clone guard wire values (string-normalization contract of TKT-003615). Tokens are opaque
/// bytes: no trimming, no case change, canonical unpadded base64url only, hashed from their decoded bytes. The VM
/// Generation ID is a canonical machine identifier: exactly 32 ASCII hexadecimal characters, stored lower-case.
/// </summary>
public static class CloneGuardCodec
{
    /// <summary>Number of random bytes in one token.</summary>
    public const int TokenByteLength = 32;

    /// <summary>Length of the unpadded base64url encoding of <see cref="TokenByteLength"/> bytes.</summary>
    public const int TokenTextLength = 43;

    /// <summary>
    /// Decodes a token and returns the SHA-256 digest of its 32 bytes, the only form the server stores or compares.
    /// </summary>
    /// <param name="token">Candidate token text; <see langword="null"/> is refused.</param>
    /// <param name="digest">The 32-byte digest when the method returns <see langword="true"/>.</param>
    /// <returns>
    /// <see langword="false"/> when the text is not exactly 43 base64url characters (<c>A-Z a-z 0-9 - _</c>) or is a
    /// non-canonical encoding (non-zero trailing bits), so two spellings can never designate the same token.
    /// </returns>
    public static bool TryHashToken(string? token, out byte[] digest)
    {
        digest = Array.Empty<byte>();
        if (token is null || token.Length != TokenTextLength)
            return false;
        foreach (var character in token)
        {
            var allowed = character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_';
            if (!allowed)
                return false;
        }
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + "=");
        }
        catch (FormatException)
        {
            return false;
        }
        // Convert ignores the low bits of the last character; re-encoding rejects every alias of a canonical token.
        if (bytes.Length != TokenByteLength || !string.Equals(Encode(bytes), token, StringComparison.Ordinal))
            return false;
        digest = SHA256.HashData(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        return true;
    }

    /// <summary>Encodes bytes as unpadded base64url; used by tests and by the canonical-form check.</summary>
    /// <param name="bytes">Bytes to encode.</param>
    /// <returns>The RFC 4648 section 5 text without padding.</returns>
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Validates a VM Generation ID and returns its canonical lower-case form.
    /// </summary>
    /// <param name="value">Candidate value; <see langword="null"/> or empty means "not provided".</param>
    /// <param name="canonical">Lower-case value when valid, otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the value was absent or valid; <see langword="false"/> when present but not exactly
    /// 32 ASCII hexadecimal characters. An invalid value is ignored by the caller, never a refusal.
    /// </returns>
    public static bool TryCanonicalVmGenerationId(string? value, out string? canonical)
    {
        canonical = null;
        if (string.IsNullOrEmpty(value))
            return true;
        if (value.Length != 32 || !value.All(char.IsAsciiHexDigit))
            return false;
        canonical = value.ToLowerInvariant();
        return true;
    }
}
