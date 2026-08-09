using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeCanaryProofNonce
{
    public Guid EnrollmentId { get; set; }
    public RuntimeEnrollment? Enrollment { get; set; }

    [MaxLength(36)]
    public string Jti { get; set; } = string.Empty;

    [MaxLength(36)]
    public string EventId { get; set; } = string.Empty;

    public Guid BindingId { get; set; }

    [MaxLength(36)]
    public string InstallationId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string HardwareIdHash { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ReleaseVersion { get; set; } = string.Empty;

    [MaxLength(64)]
    public string BodyDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ProofDigestSha256 { get; set; } = string.Empty;

    [MaxLength(8192)]
    public string ResponseCiphertext { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ResponseKeyId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string ResponseKeyPurpose { get; set; } = "encryption";

    public long AuthorityEpoch { get; set; }
    public DateTime SentAtUtc { get; set; }
    public DateTime ReservedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
