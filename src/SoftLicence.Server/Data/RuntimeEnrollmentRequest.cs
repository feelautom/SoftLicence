using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [MaxLength(64)]
    public string ClientId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string RequestId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Operation { get; set; } = string.Empty;

    [MaxLength(64)]
    public string PayloadDigestSha256 { get; set; } = string.Empty;

    public Guid EnrollmentId { get; set; }
    public RuntimeEnrollment? Enrollment { get; set; }

    [MaxLength(8192)]
    public string ResponseCiphertext { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ResponseKeyId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string ResponseKeyPurpose { get; set; } = "encryption";

    public DateTime CreatedAtUtc { get; set; }
}
