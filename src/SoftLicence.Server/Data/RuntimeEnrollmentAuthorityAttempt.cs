namespace SoftLicence.Server.Data;

using System.Globalization;
using SoftLicence.Server.Models;

/// <summary>Persists one immutable terminal v2 authority attempt independently of transport telemetry.</summary>
public sealed class RuntimeEnrollmentAuthorityAttempt
{
    /// <summary>Gets or sets the canonical attempt identifier supplied by the authenticated ingress.</summary>
    public Guid AttemptId { get; set; }
    /// <summary>Gets or sets the canonical idempotency request identifier.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the exact lowercase SHA-256 request digest.</summary>
    public string RequestDigest { get; set; } = string.Empty;
    /// <summary>Gets or sets the terminal lineage identifier, or null for refusal.</summary>
    public Guid? AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the terminal generation identifier, or null for refusal.</summary>
    public Guid? AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the closed ACCEPTED or REFUSED status.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed refusal code, or null for acceptance.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the frozen HTTP status used by refused replay; accepted replay is always 200.</summary>
    public int HttpStatusCode { get; set; }
    /// <summary>Gets or sets the UTC creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the UTC terminal instant.</summary>
    public DateTime CompletedAtUtc { get; set; }
    /// <summary>Gets or sets an owned copy of the exact terminal response bytes.</summary>
    public byte[] ExactResponseUtf8 { get; set; } = [];
    /// <summary>Gets or sets the immutable owning request result.</summary>
    public RuntimeEnrollmentAuthorityRequest? Request { get; set; }

    /// <summary>Projects immutable storage into the closed discovery-attempt v2 contract.</summary>
    /// <returns>A new DTO whose opaque digest/error text is copied without normalization.</returns>
    /// <exception cref="InvalidOperationException">The stored status is outside the closed registry.</exception>
    internal RuntimeEnrollmentAuthorityDiscoveryAttemptV2 ToContract() => new()
    {
        Schema = "runtime-enrollment-authority-discovery-attempt-v2",
        ContractVersion = 2,
        AttemptId = AttemptId.ToString("D"),
        RequestId = RequestId.ToString("D"),
        RequestDigest = RequestDigest,
        AuthorityLineageId = AuthorityLineageId?.ToString("D"),
        Status = Status switch
        {
            "ACCEPTED" => "accepted",
            "REFUSED" => "refused",
            _ => throw new InvalidOperationException("Unknown authority attempt status.")
        },
        AuthorityGenerationId = AuthorityGenerationId?.ToString("D"),
        ErrorCode = ErrorCode,
        CreatedAtUtc = CreatedAtUtc.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture),
        CompletedAtUtc = CompletedAtUtc.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture)
    };
}
