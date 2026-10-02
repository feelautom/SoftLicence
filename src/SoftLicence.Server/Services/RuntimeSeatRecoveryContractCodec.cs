using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Owns strict W5/W9 Runtime seat-recovery parsing, canonical bytes, digests, and readback classification.</summary>
public static class RuntimeSeatRecoveryContractCodec
{
    private static readonly byte[] AuthorizationDigestDomain = "SOFTLICENCE\0RUNTIME-SEAT-RECOVERY-AUTHORIZATION\0V1"u8.ToArray();
    private static readonly byte[] ConfirmationDomain = "SOFTLICENCE\0RUNTIME-RECOVERY-KEY-CONFIRMATION\0V1"u8.ToArray();
    private static readonly byte[] ActivationDigestDomain = "SOFTLICENCE\0RUNTIME-SEAT-RECOVERY-ACTIVATION\0V1"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = null,
        WriteIndented = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    /// <summary>Returns the parsed request, its exact canonical bytes, and its domain-separated digest.</summary>
    public sealed record AuthorizationParseResult(
        RuntimeSeatRecoveryAuthorizationRequest? Request,
        byte[] CanonicalUtf8,
        string? RequestDigestSha256,
        string? ErrorCode)
    {
        /// <summary>Gets whether the wire request established a canonical business identity.</summary>
        public bool IsSuccess => Request is not null && ErrorCode is null;
    }

    /// <summary>Returns one canonical W10 preparation request and its exact bytes.</summary>
    public sealed record KeyPreparationParseResult(
        RuntimeSeatRecoveryKeyPreparationRequest? Request,
        byte[] CanonicalUtf8,
        string? ErrorCode)
    {
        /// <summary>Gets whether the complete canonical preparation identity was established.</summary>
        public bool IsSuccess => Request is not null && ErrorCode is null;
    }

    /// <summary>Returns one canonical W10 confirmation outer and its untouched signed statement bytes.</summary>
    public sealed record KeyConfirmationParseResult(
        RuntimeSeatRecoveryKeyConfirmationRequest? Request,
        byte[] CanonicalUtf8,
        byte[] ConfirmationStatementUtf8,
        string? ConfirmationRequestSha256,
        string? ErrorCode)
    {
        /// <summary>Gets whether the outer and raw signed statement are canonical and complete.</summary>
        public bool IsSuccess => Request is not null && ErrorCode is null;
    }

    /// <summary>Returns one canonical activation command, its exact bytes, and its domain-separated digest.</summary>
    public sealed record ActivationParseResult(
        RuntimeSeatRecoveryActivationRequest? Request,
        byte[] CanonicalUtf8,
        string? ActivationRequestDigestSha256,
        string? ErrorCode)
    {
        /// <summary>Gets whether the complete canonical activation identity was established.</summary>
        public bool IsSuccess => Request is not null && ErrorCode is null;
    }

    /// <summary>Returns one canonical activation readback identity or a closed parse failure.</summary>
    public sealed record ActivationReadbackParseResult(
        RuntimeSeatRecoveryActivationReadbackRequest? Request,
        string? ErrorCode)
    {
        /// <summary>Gets whether canonical activation receipt identity was established.</summary>
        public bool IsSuccess => Request is not null && ErrorCode is null;
    }

    /// <summary>
    /// Parses one bounded request and rejects every byte representation outside the closed W5 writer,
    /// scalar grammar, seat-claim grammar, and W9 request shape.
    /// </summary>
    public static AuthorizationParseResult ParseAuthorizationRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length is < 1 or > 4096
            || (utf8.Length >= 3 && utf8[0] == 0xef && utf8[1] == 0xbb && utf8[2] == 0xbf))
            return Invalid();
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var request = JsonSerializer.Deserialize<RuntimeSeatRecoveryAuthorizationRequest>(utf8, JsonOptions);
            if (request is null || !Validate(request) || !HasCanonicalAuthorizationShape(request, utf8))
                return Invalid();
            var canonical = utf8.ToArray();
            var input = new byte[AuthorizationDigestDomain.Length + 1 + canonical.Length];
            AuthorizationDigestDomain.CopyTo(input, 0);
            canonical.CopyTo(input, AuthorizationDigestDomain.Length + 1);
            var digest = Convert.ToHexStringLower(SHA256.HashData(input));
            CryptographicOperations.ZeroMemory(input);
            return new(request, canonical, digest, null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return Invalid();
        }
    }

    /// <summary>Serializes one validated seat-claim plaintext in its declared closed property order.</summary>
    internal static byte[] SerializeSeatClaimPlaintext(RuntimeSeatRecoverySeatClaimPlaintext claim) =>
        JsonSerializer.SerializeToUtf8Bytes(claim, JsonOptions);

    /// <summary>Parses one closed canonical seat-claim plaintext after successful AEAD authentication.</summary>
    internal static RuntimeSeatRecoverySeatClaimPlaintext? ParseSeatClaimPlaintext(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length is < 1 or > 2048 || ContainsWhitespaceOutsideStrings(utf8)
            || utf8.IndexOf("\\u"u8) >= 0 || utf8.IndexOf("\\U"u8) >= 0) return null;
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var claim = JsonSerializer.Deserialize<RuntimeSeatRecoverySeatClaimPlaintext>(utf8, JsonOptions);
            using var document = JsonDocument.Parse(utf8.ToArray());
            if (claim is null || !HasProperties(document.RootElement, "version", "purpose",
                    "ownerSubjectRefDigestSha256", "productId", "licenseId", "seatId", "seatRevision",
                    "issuedAtUtc", "expiresAtUtc", "nonce")
                || claim.Version != 1 || claim.Purpose != "runtime_identity_recovery_seat_selection"
                || !LowerHex(claim.OwnerSubjectRefDigestSha256) || !CanonicalUuid(claim.ProductId)
                || !CanonicalUuid(claim.LicenseId) || !CanonicalUuid(claim.SeatId) || claim.SeatRevision < 1
                || !CanonicalTimestamp(claim.IssuedAtUtc) || !CanonicalTimestamp(claim.ExpiresAtUtc)
                || !CanonicalUuid(claim.Nonce)) return null;
            return CryptographicOperations.FixedTimeEquals(SerializeSeatClaimPlaintext(claim), utf8) ? claim : null;
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Writes one already validated opaque string with the exact W5 escape table. Quote and backslash
    /// are escaped, slash stays literal, U+0085/U+2028/U+2029 use lowercase Unicode escapes, and all
    /// other valid Unicode scalars retain their literal UTF-8 bytes without normalization or repair.
    /// </summary>
    internal static void WriteCanonicalOpaqueString(Utf8JsonWriter writer, string propertyName, string value)
    {
        var literal = new StringBuilder(value.Length + 2).Append('"');
        var remaining = value.AsSpan();
        while (!remaining.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(remaining, out var rune, out var consumed) != OperationStatus.Done)
                throw new InvalidOperationException("Opaque recovery text contains an invalid Unicode scalar.");
            switch (rune.Value)
            {
                case '"':
                    literal.Append("\\\"");
                    break;
                case '\\':
                    literal.Append("\\\\");
                    break;
                case 0x0085:
                    literal.Append("\\u0085");
                    break;
                case 0x2028:
                    literal.Append("\\u2028");
                    break;
                case 0x2029:
                    literal.Append("\\u2029");
                    break;
                default:
                    literal.Append(rune.ToString());
                    break;
            }
            remaining = remaining[consumed..];
        }
        literal.Append('"');
        writer.WritePropertyName(propertyName);
        writer.WriteRawValue(StrictUtf8.GetBytes(literal.ToString()), skipInputValidation: false);
    }

    /// <summary>Parses the bounded W8 current-readback request and enforces its exact property sequence.</summary>
    internal static RuntimeSeatRecoveryReadbackParseResult ParseCurrentReadbackRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length is < 1 or > 4096 || ContainsWhitespaceOutsideStrings(utf8)
            || utf8.IndexOf("\\u"u8) >= 0 || utf8.IndexOf("\\U"u8) >= 0)
            return new(null, "invalid_request");
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var request = JsonSerializer.Deserialize<RuntimeSeatRecoveryCurrentReadbackRequest>(utf8, JsonOptions);
            using var document = JsonDocument.Parse(utf8.ToArray());
            if (request is null
                || !HasProperties(document.RootElement, "schema", "contractVersion", "productId", "requestId",
                    "requestDigestSha256", "recoveryOperationRef", "reservationRef")
                || request.Schema != "runtime-seat-recovery-current-readback-v1" || request.ContractVersion != 1
                || !CanonicalUuid(request.ProductId) || !CanonicalUuid(request.RequestId)
                || !LowerHex(request.RequestDigestSha256) || !CanonicalUuid(request.RecoveryOperationRef)
                || !CanonicalUuid(request.ReservationRef))
                return new(null, "invalid_request");
            return new(request, null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return new(null, "invalid_request");
        }
    }

    /// <summary>Parses the exact 1078-byte RSA-3072 W10 preparation outer without string normalization or repair.</summary>
    internal static KeyPreparationParseResult ParseKeyPreparationRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length != 1078 || InvalidCanonicalEnvelope(utf8)) return new(null, [], "invalid_request");
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var request = JsonSerializer.Deserialize<RuntimeSeatRecoveryKeyPreparationRequest>(utf8, JsonOptions);
            using var document = JsonDocument.Parse(utf8.ToArray());
            if (request is null
                || !HasProperties(document.RootElement, "schema", "contractVersion", "productId", "requestId",
                    "requestDigestSha256", "recoveryOperationRef", "reservationRef", "enrollmentId",
                    "authorityGenerationId", "publicKeySpki")
                || request.Schema != "runtime-seat-recovery-key-prepare-v1" || request.ContractVersion != 1
                || !CanonicalUuid(request.ProductId) || !CanonicalUuid(request.RequestId)
                || !LowerHex(request.RequestDigestSha256) || !CanonicalUuid(request.RecoveryOperationRef)
                || !CanonicalUuid(request.ReservationRef) || !CanonicalUuid(request.EnrollmentId)
                || !CanonicalUuid(request.AuthorityGenerationId) || !CanonicalPaddedBase64(request.PublicKeySpki)
                || !utf8.SequenceEqual(SerializeKeyPreparation(request)))
                return new(null, [], "invalid_request");
            return new(request, utf8.ToArray(), null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return new(null, [], "invalid_request");
        }
    }

    /// <summary>
    /// Parses the exact 1873-byte RSA-3072 W10 confirmation outer, preserves the 628 raw statement bytes, and
    /// rejects every unknown member including <c>jti</c> before any one-shot provider effect.
    /// </summary>
    internal static KeyConfirmationParseResult ParseKeyConfirmationRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length != 1873 || InvalidCanonicalEnvelope(utf8)) return InvalidConfirmation();
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var request = JsonSerializer.Deserialize<RuntimeSeatRecoveryKeyConfirmationRequest>(utf8, JsonOptions);
            using var document = JsonDocument.Parse(utf8.ToArray());
            if (request is null
                || !HasProperties(document.RootElement, "schema", "contractVersion", "productId", "requestId",
                    "requestDigestSha256", "recoveryOperationRef", "reservationRef", "prepareRef", "enrollmentId",
                    "authorityGenerationId", "publicKeySpkiSha256", "confirmationStatement",
                    "confirmationAlgorithm", "confirmationSignature")
                || !ValidateConfirmationOuter(request)
                || !HasProperties(document.RootElement.GetProperty("confirmationStatement"), "schema",
                    "contractVersion", "prepareRef", "requestId", "requestDigestSha256", "recoveryOperationRef",
                    "reservationRef", "enrollmentId", "authorityGenerationId", "challenge", "confirmAudience")
                || !TryCaptureStatement(utf8, out var statement)
                || statement.Length != 628 || !utf8.SequenceEqual(SerializeKeyConfirmation(request)))
                return InvalidConfirmation();
            return new(request, utf8.ToArray(), statement,
                Convert.ToHexStringLower(SHA256.HashData(utf8)), null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return InvalidConfirmation();
        }
    }

    /// <summary>Parses the exact 524-byte activation command and derives its separated digest.</summary>
    internal static ActivationParseResult ParseActivationRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length != 524 || InvalidCanonicalEnvelope(utf8)) return InvalidActivation();
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var request = JsonSerializer.Deserialize<RuntimeSeatRecoveryActivationRequest>(utf8, JsonOptions);
            using var document = JsonDocument.Parse(utf8.ToArray());
            if (request is null
                || !HasProperties(document.RootElement, "schema", "contractVersion", "productId", "requestId",
                    "requestDigestSha256", "recoveryOperationRef", "reservationRef", "prepareRef",
                    "confirmationRequestSha256")
                || request.Schema != "runtime-seat-recovery-activation-v1" || request.ContractVersion != 1
                || !CanonicalUuid(request.ProductId) || !CanonicalUuid(request.RequestId)
                || !LowerHex(request.RequestDigestSha256) || !CanonicalUuid(request.RecoveryOperationRef)
                || !CanonicalUuid(request.ReservationRef) || !CanonicalUuid(request.PrepareRef)
                || !LowerHex(request.ConfirmationRequestSha256)
                || !utf8.SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions)))
                return InvalidActivation();
            var canonical = utf8.ToArray();
            var input = new byte[ActivationDigestDomain.Length + 1 + canonical.Length];
            ActivationDigestDomain.CopyTo(input, 0);
            canonical.CopyTo(input, ActivationDigestDomain.Length + 1);
            var digest = Convert.ToHexStringLower(SHA256.HashData(input));
            CryptographicOperations.ZeroMemory(input);
            return new(request, canonical, digest, null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return InvalidActivation();
        }
    }

    /// <summary>Parses the exact 278-byte activation receipt readback identity.</summary>
    internal static ActivationReadbackParseResult ParseActivationReadbackRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length != 278 || InvalidCanonicalEnvelope(utf8)) return new(null, "invalid_request");
        try
        {
            _ = StrictUtf8.GetString(utf8);
            var request = JsonSerializer.Deserialize<RuntimeSeatRecoveryActivationReadbackRequest>(utf8, JsonOptions);
            using var document = JsonDocument.Parse(utf8.ToArray());
            if (request is null
                || !HasProperties(document.RootElement, "schema", "contractVersion", "productId", "requestId",
                    "activationRequestDigestSha256")
                || request.Schema != "runtime-seat-recovery-activation-readback-v1" || request.ContractVersion != 1
                || !CanonicalUuid(request.ProductId) || !CanonicalUuid(request.RequestId)
                || !LowerHex(request.ActivationRequestDigestSha256)
                || !utf8.SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions)))
                return new(null, "invalid_request");
            return new(request, null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or NotSupportedException)
        {
            return new(null, "invalid_request");
        }
    }

    /// <summary>Builds the exact PS256 input from the fixed domain, one LF, and untouched statement bytes.</summary>
    internal static byte[] BuildConfirmationSignatureInput(ReadOnlySpan<byte> statementUtf8)
    {
        var input = new byte[ConfirmationDomain.Length + 1 + statementUtf8.Length];
        ConfirmationDomain.CopyTo(input, 0);
        input[ConfirmationDomain.Length] = 0x0a;
        statementUtf8.CopyTo(input.AsSpan(ConfirmationDomain.Length + 1));
        return input;
    }

    /// <summary>Classifies one allowlisted provider tuple using the complete W9 predicate order.</summary>
    internal static string ClassifyCurrentReadback(
        string reservationState,
        string newAuthorityState,
        bool isCurrentHead,
        string previousAuthorityState,
        bool isExpired)
    {
        if (newAuthorityState == "superseded" && !isCurrentHead && previousAuthorityState == "active")
            return "superseded";
        if (reservationState == "reserved" && newAuthorityState == "prepared" && isCurrentHead
            && previousAuthorityState == "active")
            return isExpired ? "expired" : "compatible";
        if (reservationState == "committed" && newAuthorityState == "active" && isCurrentHead
            && previousAuthorityState == "superseded")
            return "committed";
        if (reservationState == "abandoned" && newAuthorityState == "abandoned" && !isCurrentHead
            && previousAuthorityState == "active")
            return "abandoned";
        return "conflict";
    }

    /// <summary>Returns a closed transport-invalid result without synthesizing request identity.</summary>
    private static AuthorizationParseResult Invalid() => new(null, [], null, "invalid_request");

    private static KeyConfirmationParseResult InvalidConfirmation() =>
        new(null, [], [], null, "invalid_request");

    private static ActivationParseResult InvalidActivation() =>
        new(null, [], null, "invalid_request");

    /// <summary>Validates every scalar without trimming, case folding, Unicode normalization, or repair.</summary>
    private static bool Validate(RuntimeSeatRecoveryAuthorizationRequest request)
    {
        if (request.Schema != "runtime-seat-recovery-authorization-v1" || request.ContractVersion != 1
            || request.Provider != "softlicence" || request.NewKeyCommitment.Algorithm != "PS256"
            || !CanonicalUuid(request.RequestId) || !CanonicalUuid(request.RecoveryOperationRef)
            || !CanonicalUuid(request.ProductId) || !CanonicalUuid(request.LicenseId)
            || !CanonicalUuid(request.Installation.InstallationId)
            || !LowerHex(request.RecoveryDigestSha256) || !LowerHex(request.Installation.HardwareIdDigestSha256)
            || !LowerHex(request.Release.ArtifactSetDigestSha256)
            || !LowerHex(request.NewKeyCommitment.PublicKeySpkiSha256)
            || !CanonicalTimestamp(request.ExpiresAtUtc) || !OpaqueGrant(request.ProviderGrantRef)
            || !CanonicalReleaseVersion(request.Release.Version)
            || request.SeatClaim is not null && !CanonicalBase64Url(request.SeatClaim, 43, 2048)) return false;
        byte[] digest;
        try { digest = Convert.FromHexString(request.NewKeyCommitment.PublicKeySpkiSha256); }
        catch (FormatException) { return false; }
        try
        {
            var thumbprint = Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return string.Equals(thumbprint, request.NewKeyCommitment.KeyThumbprint, StringComparison.Ordinal);
        }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }

    /// <summary>Checks canonical lowercase UUID D text without accepting equivalent spellings.</summary>
    private static bool CanonicalUuid(string value) => Guid.TryParseExact(value, "D", out var parsed)
        && value == parsed.ToString("D", CultureInfo.InvariantCulture);

    /// <summary>Checks an exact lowercase 32-byte SHA-256 hexadecimal representation.</summary>
    private static bool LowerHex(string value) => value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>Checks the six-fractional-digit UTC contract timestamp without offset repair.</summary>
    private static bool CanonicalTimestamp(string value) => DateTime.TryParseExact(value,
        "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
        && value == parsed.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Accepts exactly three canonical non-negative Int32 decimal components and no aliases.</summary>
    private static bool CanonicalReleaseVersion(string value)
    {
        var components = value.Split('.', StringSplitOptions.None);
        return components.Length == 3 && components.All(component => component.Length > 0
            && (component == "0" || component[0] != '0')
            && component.All(character => character is >= '0' and <= '9')
            && int.TryParse(component, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    /// <summary>
    /// Accepts only an unpadded Base64Url spelling whose decoded bytes re-encode identically within
    /// the declared ASCII character bounds; aliases with padding or non-zero unused bits fail closed.
    /// </summary>
    private static bool CanonicalBase64Url(string value, int minimumLength, int maximumLength)
    {
        if (value.Length < minimumLength || value.Length > maximumLength || value.Length % 4 == 1
            || value.Any(character => character is not (>= 'A' and <= 'Z'
                or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            return false;
        var standard = value.Replace('-', '+').Replace('_', '/');
        standard += new string('=', (4 - standard.Length % 4) % 4);
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(standard);
        }
        catch (FormatException)
        {
            return false;
        }
        try
        {
            var canonical = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return string.Equals(value, canonical, StringComparison.Ordinal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    /// <summary>Accepts only padded standard Base64 whose bytes re-encode identically.</summary>
    private static bool CanonicalPaddedBase64(string value)
    {
        if (value.Length is < 4 or > 2048 || value.Length % 4 != 0 || value.Any(character =>
                character is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '=')))
            return false;
        try
        {
            var decoded = Convert.FromBase64String(value);
            try { return Convert.ToBase64String(decoded) == value; }
            finally { CryptographicOperations.ZeroMemory(decoded); }
        }
        catch (FormatException) { return false; }
    }

    private static bool ValidateConfirmationOuter(RuntimeSeatRecoveryKeyConfirmationRequest request)
    {
        var statement = request.ConfirmationStatement;
        return request.Schema == "runtime-seat-recovery-key-confirmation-request-v1"
            && request.ContractVersion == 1 && request.ConfirmationAlgorithm == "PS256"
            && CanonicalUuid(request.ProductId) && CanonicalUuid(request.RequestId)
            && LowerHex(request.RequestDigestSha256) && CanonicalUuid(request.RecoveryOperationRef)
            && CanonicalUuid(request.ReservationRef) && CanonicalUuid(request.PrepareRef)
            && CanonicalUuid(request.EnrollmentId) && CanonicalUuid(request.AuthorityGenerationId)
            && LowerHex(request.PublicKeySpkiSha256)
            && CanonicalBase64Url(request.ConfirmationSignature, 512, 512)
            && statement.Schema == "runtime-seat-recovery-key-confirmation-v1"
            && statement.ContractVersion == 1 && CanonicalUuid(statement.PrepareRef)
            && CanonicalUuid(statement.RequestId) && LowerHex(statement.RequestDigestSha256)
            && CanonicalUuid(statement.RecoveryOperationRef) && CanonicalUuid(statement.ReservationRef)
            && CanonicalUuid(statement.EnrollmentId) && CanonicalUuid(statement.AuthorityGenerationId)
            && CanonicalBase64Url(statement.Challenge, 43, 43)
            && IsThirtyTwoByteBase64Url(statement.Challenge)
            && statement.ConfirmAudience == "softlicence:runtime-identity-recovery:confirm:v1";
    }

    /// <summary>Checks the decoded challenge length without retaining one-time challenge material.</summary>
    private static bool IsThirtyTwoByteBase64Url(string value)
    {
        var decoded = DecodeBase64Url(value);
        if (decoded is null) return false;
        try { return decoded.Length == 32; }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }

    /// <summary>Decodes one already canonical unpadded Base64Url value.</summary>
    internal static byte[]? DecodeBase64Url(string value)
    {
        if (!CanonicalBase64Url(value, 1, 4096)) return null;
        try
        {
            var standard = value.Replace('-', '+').Replace('_', '/');
            standard += new string('=', (4 - standard.Length % 4) % 4);
            return Convert.FromBase64String(standard);
        }
        catch (FormatException) { return null; }
    }

    private static bool InvalidCanonicalEnvelope(ReadOnlySpan<byte> utf8) =>
        utf8.Length >= 3 && utf8[0] == 0xef && utf8[1] == 0xbb && utf8[2] == 0xbf
        || ContainsWhitespaceOutsideStrings(utf8) || utf8.IndexOf("\\u"u8) >= 0 || utf8.IndexOf("\\U"u8) >= 0;

    private static byte[] SerializeKeyPreparation(RuntimeSeatRecoveryKeyPreparationRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);

    private static byte[] SerializeKeyConfirmation(RuntimeSeatRecoveryKeyConfirmationRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);

    private static bool TryCaptureStatement(ReadOnlySpan<byte> utf8, out byte[] statement)
    {
        statement = [];
        var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow });
        while (reader.Read())
        {
            if (reader.TokenType != JsonTokenType.PropertyName
                || !reader.ValueTextEquals("confirmationStatement"u8)) continue;
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) return false;
            var start = checked((int)reader.TokenStartIndex);
            reader.Skip();
            var end = checked((int)reader.BytesConsumed);
            statement = utf8[start..end].ToArray();
            return true;
        }
        return false;
    }

    /// <summary>Checks the opaque scalar range while preserving every accepted code point exactly.</summary>
    private static bool OpaqueGrant(string value)
    {
        var count = 0;
        var remaining = value.AsSpan();
        while (!remaining.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(remaining, out var rune, out var consumed) != OperationStatus.Done)
                return false;
            if (rune.Value <= 0x1f || rune.Value == 0x7f) return false;
            count++;
            remaining = remaining[consumed..];
        }
        return count is >= 1 and <= 256;
    }

    /// <summary>
    /// Rebuilds the closed request with the W5 writer and requires byte identity, thereby rejecting
    /// duplicate/order changes and alternate JSON escapes while preserving opaque scalar distinctions.
    /// </summary>
    private static bool HasCanonicalAuthorizationShape(
        RuntimeSeatRecoveryAuthorizationRequest request,
        ReadOnlySpan<byte> utf8)
    {
        if (ContainsWhitespaceOutsideStrings(utf8)) return false;
        return utf8.SequenceEqual(SerializeCanonicalAuthorization(request));
    }

    /// <summary>
    /// Serializes the complete authorization request in its closed property order, using the shared
    /// W5 opaque-scalar table and explicit null semantics for the optional seat claim.
    /// </summary>
    private static byte[] SerializeCanonicalAuthorization(RuntimeSeatRecoveryAuthorizationRequest request)
    {
        var output = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(output,
            new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        writer.WriteStartObject();
        writer.WriteString("schema", request.Schema);
        writer.WriteNumber("contractVersion", request.ContractVersion);
        writer.WriteString("requestId", request.RequestId);
        writer.WriteString("recoveryOperationRef", request.RecoveryOperationRef);
        writer.WriteString("recoveryDigestSha256", request.RecoveryDigestSha256);
        writer.WriteString("provider", request.Provider);
        WriteCanonicalOpaqueString(writer, "providerGrantRef", request.ProviderGrantRef);
        writer.WriteString("productId", request.ProductId);
        writer.WriteString("licenseId", request.LicenseId);
        if (request.SeatClaim is null) writer.WriteNull("seatClaim");
        else writer.WriteString("seatClaim", request.SeatClaim);
        writer.WriteStartObject("installation");
        writer.WriteString("installationId", request.Installation.InstallationId);
        writer.WriteString("hardwareIdDigestSha256", request.Installation.HardwareIdDigestSha256);
        writer.WriteEndObject();
        writer.WriteStartObject("release");
        writer.WriteString("version", request.Release.Version);
        writer.WriteString("artifactSetDigestSha256", request.Release.ArtifactSetDigestSha256);
        writer.WriteEndObject();
        writer.WriteStartObject("newKeyCommitment");
        writer.WriteString("algorithm", request.NewKeyCommitment.Algorithm);
        writer.WriteString("publicKeySpkiSha256", request.NewKeyCommitment.PublicKeySpkiSha256);
        writer.WriteString("keyThumbprint", request.NewKeyCommitment.KeyThumbprint);
        writer.WriteEndObject();
        writer.WriteString("expiresAtUtc", request.ExpiresAtUtc);
        writer.WriteEndObject();
        writer.Flush();
        return output.WrittenSpan.ToArray();
    }

    /// <summary>Requires one object to expose exactly the declared member sequence, including no duplicate.</summary>
    private static bool HasProperties(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object) return false;
        var actual = element.EnumerateObject().Select(property => property.Name).ToArray();
        return actual.SequenceEqual(expected, StringComparer.Ordinal);
    }

    /// <summary>Detects any JSON whitespace outside string contents while respecting escaped quotes.</summary>
    private static bool ContainsWhitespaceOutsideStrings(ReadOnlySpan<byte> utf8)
    {
        var insideString = false;
        var escaped = false;
        foreach (var value in utf8)
        {
            if (insideString)
            {
                if (escaped) escaped = false;
                else if (value == (byte)'\\') escaped = true;
                else if (value == (byte)'"') insideString = false;
            }
            else if (value == (byte)'"') insideString = true;
            else if (value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') return true;
        }
        return insideString || escaped;
    }
}
