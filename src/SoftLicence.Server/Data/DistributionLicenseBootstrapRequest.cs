using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionLicenseBootstrapRequest
{
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    [MaxLength(36)] public string RequestId { get; set; } = string.Empty;
    [MaxLength(16)] public string Operation { get; set; } = string.Empty;
    [MaxLength(64)] public string PayloadDigestSha256 { get; set; } = string.Empty;
    public Guid AuthorizationId { get; set; }
    public Guid CapabilityId { get; set; }
    public byte[] ExactResponseCiphertext { get; set; } = [];
    [MaxLength(64)] public string ResponseKeyId { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
