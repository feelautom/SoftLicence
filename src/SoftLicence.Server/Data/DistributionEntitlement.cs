using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionEntitlement
{
    public Guid Id { get; set; }
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    public Guid ProductId { get; set; }
    public Guid LicenseId { get; set; }
    [MaxLength(64)] public string GrantRefDigestSha256 { get; set; } = string.Empty;
    [MaxLength(64)] public string SubjectRefDigestSha256 { get; set; } = string.Empty;
    public int ContractVersion { get; set; }
    [MaxLength(16)] public string State { get; set; } = "issued";
    public DateTime IssuedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? FinalizedAtUtc { get; set; }
}
