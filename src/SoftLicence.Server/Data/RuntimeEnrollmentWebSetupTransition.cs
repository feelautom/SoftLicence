using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentWebSetupTransition
{
    public Guid Id { get; set; }
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    public Guid ProductId { get; set; }
    public Guid BindingId { get; set; }
    public Guid EnrollmentId { get; set; }
    [MaxLength(36)] public string InstallationId { get; set; } = string.Empty;
    [MaxLength(64)] public string SourceVersion { get; set; } = string.Empty;
    [MaxLength(64)] public string TargetVersion { get; set; } = string.Empty;
    [MaxLength(200)] public string TargetInstallerFilename { get; set; } = string.Empty;
    [MaxLength(64)] public string TargetInstallerSha256 { get; set; } = string.Empty;
    [MaxLength(64)] public string CapabilityDigestSha256 { get; set; } = string.Empty;
    public int SourceSecurityEpoch { get; set; }
    public long AuthorityEpoch { get; set; }
    [MaxLength(16)] public string State { get; set; } = "ISSUED";
    public DateTime IssuedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? ConsumedAtUtc { get; set; }
    [MaxLength(64)] public string? ConsumedPayloadDigestSha256 { get; set; }
}

public sealed class RuntimeEnrollmentWebSetupTransitionRequest
{
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    [MaxLength(36)] public string RequestId { get; set; } = string.Empty;
    [MaxLength(16)] public string Operation { get; set; } = string.Empty;
    [MaxLength(64)] public string PayloadDigestSha256 { get; set; } = string.Empty;
    public Guid TransitionId { get; set; }
    public byte[] ExactResponseCiphertext { get; set; } = [];
    [MaxLength(64)] public string ResponseKeyId { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
