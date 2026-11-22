using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SoftLicence.Server.Services;

/// <summary>
/// TKT-002919 wire contract of <c>POST /api/internal/v1/runtime-account-relinks</c>, frozen with the website
/// (TKT-002920). The website authenticates the account signed in inside the application, then relays the
/// installation's own PS256 proof together with its account evidence; neither party alone can relink.
/// </summary>
/// <remarks>
/// <para>
/// String semantics: every UUID is canonical lowercase <c>D</c> format and compared ordinally; the hardware
/// identifier is the canonical 16-character uppercase hexadecimal value
/// (<see cref="HardwareAuthorityAliasResolver.IsCanonicalHardwareId"/>), never rewritten; digests are 64
/// lowercase hexadecimal characters. No case folding, trimming or Unicode normalization is applied: a
/// non-canonical value is an invalid request, not something to repair.
/// </para>
/// <para>
/// The installation proof is parsed loosely on purpose: an absent or malformed proof is answered 403
/// <c>installation_proof_invalid</c> by the service (contract), not 400, so the website can tell an
/// application that must sign again from a website bug.
/// </para>
/// </remarks>
internal static class RuntimeAccountRelinkContract
{
    /// <summary>Exact request route, also bound into the installation proof.</summary>
    internal const string Path = "/api/internal/v1/runtime-account-relinks";

    /// <summary>Request schema discriminator.</summary>
    internal const string RequestSchema = "softlicence.runtime-account-relink.request.v1";

    /// <summary>Success response schema discriminator.</summary>
    internal const string ResponseSchema = "softlicence.runtime-account-relink.response.v1";

    /// <summary>First line of the statement signed by the installation.</summary>
    internal const string StatementSchema = "softlicence.runtime-account-relink.statement.v1";

    /// <summary>Proof operation recorded in the enrollment proof registry.</summary>
    internal const string ProofOperation = "account-relink";

    /// <summary>Proof audience, product-agnostic like the other Runtime enrollment audiences.</summary>
    internal const string Audience = "https://softlicence.app/runtime-enrollment/account-relink";

    /// <summary>
    /// TKT-003753: the only accepted value of the optional <c>ownerAttestation</c> field, frozen with the website
    /// (TKT-003752). The website sends it only with a null <c>ownerSubjectId</c>, for a target licence other than the
    /// installation licence, after checking that the signed-in account owns both licences. Compared ordinally.
    /// </summary>
    internal const string WebsiteSameAccountAttestation = "website_same_account_v1";

    /// <summary>Maximum accepted request size in bytes.</summary>
    internal const int MaximumRequestBytes = 4096;

    /// <summary>Exact property set of the request; any other property is refused.</summary>
    private static readonly string[] RequestProperties =
    [
        "schema", "requestId", "productId", "enrollmentId", "installationId", "licenseId", "hardwareId",
        "releaseVersion", "securityEpoch", "installationSubjectRefDigestSha256", "ownerSubjectId", "ownerAttestation", "installationProof"
    ];

    /// <summary>Properties that may be absent; every other request property is mandatory.</summary>
    private static readonly string[] OptionalRequestProperties = ["ownerAttestation", "installationProof"];

    /// <summary>Exact property set of the installation proof object.</summary>
    private static readonly string[] ProofProperties = ["timestamp", "jti", "signature"];

    /// <summary>
    /// Parses the exact request bytes. Returns null for any shape violation: invalid UTF-8 or JSON, duplicate or
    /// unknown property, missing mandatory field (<c>ownerSubjectId</c> must be present, but may be JSON null since
    /// TKT-003350), an <c>ownerAttestation</c> other than the frozen value or beside an owner (TKT-003753), wrong JSON
    /// type, non-canonical UUID, hardware identifier,
    /// digest or version, or a security epoch outside 1..int.MaxValue. The proof is returned as found (possibly
    /// null) and validated later by the service.
    /// </summary>
    /// <param name="exactBody">Exact request bytes, at most <see cref="MaximumRequestBytes"/>.</param>
    /// <returns>The parsed command, or null when the request is invalid (400 <c>invalid_request</c>).</returns>
    internal static RuntimeAccountRelinkCommand? Parse(ReadOnlySpan<byte> exactBody)
    {
        if (exactBody.Length is 0 or > MaximumRequestBytes)
            return null;
        try
        {
            using var document = JsonDocument.Parse(exactBody.ToArray());
            var root = document.RootElement;
            if (!HasExactProperties(root, RequestProperties, OptionalRequestProperties))
                return null;
            if (!TryString(root, "schema", out var schema) || schema != RequestSchema
                || !TryUuid(root, "requestId", out var requestId)
                || !TryUuid(root, "productId", out var productId)
                || !TryUuid(root, "enrollmentId", out var enrollmentId)
                || !TryUuid(root, "installationId", out var installationId)
                || !TryUuid(root, "licenseId", out var licenseId)
                || !TryNullableUuid(root, "ownerSubjectId", out var ownerSubjectId)
                || !TryString(root, "hardwareId", out var hardwareId)
                || !HardwareAuthorityAliasResolver.IsCanonicalHardwareId(hardwareId)
                || !TryString(root, "releaseVersion", out var releaseVersion)
                || releaseVersion.Length > 64
                || !RuntimeEnrollmentService.IsCanonicalReleaseVersion(releaseVersion)
                || !TryString(root, "installationSubjectRefDigestSha256", out var subjectDigest)
                || !IsLowerSha256(subjectDigest)
                || root.GetProperty("securityEpoch").ValueKind != JsonValueKind.Number
                || !root.GetProperty("securityEpoch").TryGetInt32(out var securityEpoch)
                || securityEpoch < 1)
                return null;

            // TKT-003753: optional attestation; when present it must be exactly the frozen value and only without
            // an owner. JSON null, another type, another value or an attestation beside an owner is invalid.
            string? ownerAttestation = null;
            if (root.TryGetProperty("ownerAttestation", out var attestationElement))
            {
                if (attestationElement.ValueKind != JsonValueKind.String
                    || !string.Equals(attestationElement.GetString(), WebsiteSameAccountAttestation, StringComparison.Ordinal)
                    || ownerSubjectId is not null)
                    return null;
                ownerAttestation = WebsiteSameAccountAttestation;
            }

            RuntimeAccountRelinkProof? proof = null;
            if (root.TryGetProperty("installationProof", out var proofElement)
                && HasExactProperties(proofElement, ProofProperties, [])
                && TryString(proofElement, "timestamp", out var timestamp)
                && TryString(proofElement, "jti", out var jti)
                && TryString(proofElement, "signature", out var signature))
                proof = new RuntimeAccountRelinkProof(timestamp, jti, signature);

            return new RuntimeAccountRelinkCommand(
                requestId, productId, enrollmentId, installationId.ToString("D"), licenseId, hardwareId,
                releaseVersion, securityEpoch, subjectDigest, ownerSubjectId, proof,
                Convert.ToHexStringLower(SHA256.HashData(exactBody)), ownerAttestation);
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Builds the statement the installation signs: the schema line, then request, product, enrollment and
    /// installation identifiers, the lowercase SHA-256 of the exact UTF-8 hardware identifier, the target licence
    /// and the release version, joined by <c>\n</c> without a trailing newline. A website that changes any of
    /// these values invalidates the proof.
    /// </summary>
    /// <param name="command">Parsed request.</param>
    /// <returns>The exact statement text.</returns>
    internal static string BuildStatement(RuntimeAccountRelinkCommand command) => string.Join('\n',
        StatementSchema,
        command.RequestId.ToString("D"),
        command.ProductId.ToString("D"),
        command.EnrollmentId.ToString("D"),
        command.InstallationId,
        HardwareDigest(command.HardwareId),
        command.LicenseId.ToString("D"),
        command.ReleaseVersion);

    /// <summary>
    /// Builds the exact PS256 payload signed with the installation key, reusing the Runtime enrollment proof
    /// format with operation <c>account-relink</c>, the request security epoch, this route, the account-relink
    /// audience, no challenge, and the statement digest in place of a body digest.
    /// </summary>
    /// <param name="command">Parsed request.</param>
    /// <param name="timestamp">Exact proof timestamp text.</param>
    /// <param name="jti">Exact canonical proof identifier.</param>
    /// <returns>The UTF-8 text to sign or verify.</returns>
    internal static string BuildProofPayload(RuntimeAccountRelinkCommand command, string timestamp, string jti) =>
        RuntimeEnrollmentService.BuildProofPayload(
            ProofOperation, command.EnrollmentId, command.SecurityEpoch, Path, Audience,
            timestamp, jti, "-", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(BuildStatement(command)))));

    /// <summary>Builds the exact success body; field order is part of the frozen contract.</summary>
    /// <param name="enrollmentId">Relinked enrollment.</param>
    /// <param name="licenseId">Licence of the current assignment.</param>
    /// <param name="assignmentRevision">Revision of the current assignment.</param>
    /// <param name="relinked">True when this request appended the assignment, false when it already existed.</param>
    /// <returns>The UTF-8 JSON text.</returns>
    internal static string BuildResponse(Guid enrollmentId, Guid licenseId, int assignmentRevision, bool relinked) =>
        string.Create(CultureInfo.InvariantCulture,
            $"{{\"schema\":\"{ResponseSchema}\",\"enrollmentId\":\"{enrollmentId:D}\",\"licenseId\":\"{licenseId:D}\",\"assignmentRevision\":{assignmentRevision},\"relinked\":{(relinked ? "true" : "false")}}}");

    /// <summary>Builds the exact refusal body <c>{"error":"code"}</c>.</summary>
    /// <param name="errorCode">Closed public error code.</param>
    /// <returns>The UTF-8 bytes of the refusal.</returns>
    internal static byte[] ErrorBody(string errorCode) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Models.RuntimeEnrollmentApiError(errorCode),
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));

    /// <summary>Lowercase SHA-256 of the exact UTF-8 identifier, the format of the enrollment hardware digest.</summary>
    /// <param name="hardwareId">Canonical hardware identifier, hashed without rewriting.</param>
    /// <returns>64 lowercase hexadecimal characters.</returns>
    internal static string HardwareDigest(string hardwareId) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId)));

    /// <summary>
    /// True when the element is an object whose properties are exactly <paramref name="expected"/>, each once,
    /// the names of <paramref name="optional"/> excepted, which may be absent.
    /// </summary>
    private static bool HasExactProperties(JsonElement element, string[] expected, string[] optional)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
                return false;
        return expected.All(name => seen.Contains(name) || optional.Contains(name, StringComparer.Ordinal));
    }

    /// <summary>Reads a JSON string property; false for any other type.</summary>
    private static bool TryString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
            return false;
        value = property.GetString() ?? string.Empty;
        return true;
    }

    /// <summary>Reads a canonical lowercase UUID string property; uppercase or braces are refused, not repaired.</summary>
    private static bool TryUuid(JsonElement element, string name, out Guid value)
    {
        value = Guid.Empty;
        return TryString(element, name, out var text)
            && Guid.TryParseExact(text, "D", out value)
            && value != Guid.Empty
            && string.Equals(text, value.ToString("D"), StringComparison.Ordinal);
    }

    /// <summary>
    /// TKT-003350: reads a property that must be present and is either JSON <c>null</c> (no commercial owner known
    /// to the website) or a canonical lowercase UUID. An absent property, another JSON type, an empty string, the
    /// nil UUID or a non-canonical spelling is refused, never repaired.
    /// </summary>
    /// <param name="element">Request object; the exact property set was already checked.</param>
    /// <param name="name">Property name.</param>
    /// <param name="value">The UUID, or null for an explicit JSON null.</param>
    /// <returns>True for a present JSON null or canonical UUID.</returns>
    private static bool TryNullableUuid(JsonElement element, string name, out Guid? value)
    {
        value = null;
        if (!element.TryGetProperty(name, out var property))
            return false;
        if (property.ValueKind == JsonValueKind.Null)
            return true;
        if (!TryUuid(element, name, out var uuid))
            return false;
        value = uuid;
        return true;
    }

    /// <summary>64 lowercase hexadecimal characters.</summary>
    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

/// <summary>Installation proof relayed unchanged by the website; validated by the service.</summary>
/// <param name="Timestamp">Exact UTC timestamp text, Runtime proof format.</param>
/// <param name="Jti">Single-use proof identifier, canonical lowercase UUID.</param>
/// <param name="Signature">Base64url PS256 signature by the installation key.</param>
public sealed record RuntimeAccountRelinkProof(string Timestamp, string Jti, string Signature);

/// <summary>Parsed account relink request; see <see cref="RuntimeAccountRelinkContract"/> for field semantics.</summary>
/// <param name="RequestId">Idempotency key created by the application and reused by the website on retries.</param>
/// <param name="ProductId">Product scope, authenticated by S2S and equal to the enrollment product.</param>
/// <param name="EnrollmentId">Installation enrollment.</param>
/// <param name="InstallationId">Installation identifier; must equal the enrollment's.</param>
/// <param name="LicenseId">Target licence chosen by the signed-in account.</param>
/// <param name="HardwareId">Canonical machine identifier; its digest must equal the enrollment hardware digest.</param>
/// <param name="ReleaseVersion">Installed release as reported by the application; must equal the enrollment's.</param>
/// <param name="SecurityEpoch">Security epoch known by the application; must equal the enrollment's.</param>
/// <param name="InstallationSubjectRefDigestSha256">Account digest computed by the website; must equal the enrollment's.</param>
/// <param name="OwnerSubjectId">
/// Registry owner of the target and installation licences according to the website, or null (explicit JSON null)
/// when the website knows no commercial owner; a null owner is accepted for the installation's own licence
/// (TKT-003350), or for another licence of the same product when <paramref name="OwnerAttestation"/> is set (TKT-003753).
/// </param>
/// <param name="Proof">Installation proof, or null when absent or malformed.</param>
/// <param name="BodyDigestSha256">Lowercase SHA-256 of the exact request bytes; it covers the attestation too.</param>
/// <param name="OwnerAttestation">
/// TKT-003753: <see cref="RuntimeAccountRelinkContract.WebsiteSameAccountAttestation"/> when the website attests that
/// the signed-in account owns both licences while no registry owner exists (always with a null
/// <paramref name="OwnerSubjectId"/>); null when the field is absent.
/// </param>
public sealed record RuntimeAccountRelinkCommand(
    Guid RequestId,
    Guid ProductId,
    Guid EnrollmentId,
    string InstallationId,
    Guid LicenseId,
    string HardwareId,
    string ReleaseVersion,
    int SecurityEpoch,
    string InstallationSubjectRefDigestSha256,
    Guid? OwnerSubjectId,
    RuntimeAccountRelinkProof? Proof,
    string BodyDigestSha256,
    string? OwnerAttestation = null);
