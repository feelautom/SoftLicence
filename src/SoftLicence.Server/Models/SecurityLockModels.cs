using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

/// <summary>
/// Lock report sent by an authenticated Desktop installation (TKT-001177). Every field is a canonical machine
/// identifier; the server validates and never normalizes them, so a non-canonical form is rejected.
/// </summary>
public sealed class SecurityLockReportRequest
{
    /// <summary>Exact schema identifier.</summary>
    public string? Schema { get; set; }
    /// <summary>Client-generated canonical UUID ("D", lower-case), also bound into the proof.</summary>
    public string? ReportId { get; set; }
    /// <summary>Client send time, canonical UTC with seven fractional digits.</summary>
    public string? SentAtUtc { get; set; }
    /// <summary>Upper-case hardware identifier bound to the enrollment.</summary>
    public string? HardwareId { get; set; }
    /// <summary>Exact release version bound to the enrollment.</summary>
    public string? AppVersion { get; set; }
    /// <summary>Client lock identifier: 32 lower-case hexadecimal characters.</summary>
    public string? LockId { get; set; }
    /// <summary>Exact catalogued cause code.</summary>
    public string? Cause { get; set; }
    /// <summary>Level claimed by the client; must equal the catalogue.</summary>
    public int Level { get; set; }
    /// <summary>Client enforcement mode: NOT_APPLICABLE, SHADOW, REVIEW or ENFORCE.</summary>
    public string? Mode { get; set; }
    /// <summary>SHA-256 of the client evidence: 64 lower-case hexadecimal characters.</summary>
    public string? EvidenceDigestSha256 { get; set; }
    /// <summary>First local detection, canonical UTC.</summary>
    public string? FirstSeenUtc { get; set; }

    /// <summary>Unknown members are rejected.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Signed server verdict for one lock report. The Desktop releases a lock only after verifying the signature
/// with the pinned Canary ACK keys, the report binding and the three-minute lifetime.
/// </summary>
public sealed record SecurityLockVerdictResponse
{
    /// <summary>Exact schema identifier.</summary>
    public required string Schema { get; init; }
    /// <summary>Signature algorithm (RS256).</summary>
    public required string Alg { get; init; }
    /// <summary>Canary ACK key identifier used to sign.</summary>
    public required string KeyId { get; init; }
    /// <summary>Authenticated enrollment the verdict belongs to.</summary>
    public required string EnrollmentId { get; init; }
    /// <summary>Echo of the request identifier (one-use binding).</summary>
    public required string ReportId { get; init; }
    /// <summary>Echo of the client lock identifier.</summary>
    public required string LockId { get; init; }
    /// <summary>Echo of the hardware identifier.</summary>
    public required string HardwareId { get; init; }
    /// <summary>Echo of the release version.</summary>
    public required string AppVersion { get; init; }
    /// <summary>MAINTAIN, RELEASE or BAN.</summary>
    public required string Verdict { get; init; }
    /// <summary>Issue time, canonical UTC.</summary>
    public required string IssuedAtUtc { get; init; }
    /// <summary>Expiry, three minutes after issue.</summary>
    public required string ExpiresAtUtc { get; init; }
    /// <summary>Unique verdict identifier.</summary>
    public required string VerdictId { get; init; }
    /// <summary>Base64url RSA PKCS#1 SHA-256 signature over the canonical payload.</summary>
    public required string Signature { get; init; }
}
