using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionS2SNonce
{
    [MaxLength(64)]
    public string ClientId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string Nonce { get; set; } = string.Empty;

    public DateTime SentAtUtc { get; set; }
    public DateTime ReservedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
