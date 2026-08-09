using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionLicenseBootstrapCapability
{
    public Guid Id { get; set; }
    public Guid AuthorizationId { get; set; }
    [MaxLength(64)] public string CapabilityDigestSha256 { get; set; } = string.Empty;
    [MaxLength(16)] public string State { get; set; } = "ISSUED";
    public DateTime MintedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? ConsumedAtUtc { get; set; }
}
