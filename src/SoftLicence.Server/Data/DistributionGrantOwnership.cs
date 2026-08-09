using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionGrantOwnership
{
    public Guid ProductId { get; set; }

    [MaxLength(64)]
    public string GrantRefDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ClientId { get; set; } = string.Empty;

    [MaxLength(16)]
    public string Source { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }
}
