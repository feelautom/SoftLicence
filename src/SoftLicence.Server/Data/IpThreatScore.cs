using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class IpThreatScore
{
    [Key]
    public string IpAddress { get; set; } = string.Empty;

    public int Score { get; set; }

    public DateTime LastHit { get; set; } = DateTime.UtcNow;

    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
}
