using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class BannedIp
{
    [Key]
    public string IpAddress { get; set; } = string.Empty;
    
    public DateTime BannedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? ExpiresAt { get; set; }
    
    public string Reason { get; set; } = string.Empty;

    public int BanCount { get; set; } = 1;

    public bool IsActive { get; set; } = true;
}
