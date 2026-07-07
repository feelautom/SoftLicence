using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class HardwareFingerprint
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(200)]
    public string HardwareId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string? CpuHash { get; set; }

    [MaxLength(64)]
    public string? MotherboardHash { get; set; }

    [MaxLength(64)]
    public string? BiosHash { get; set; }

    [MaxLength(64)]
    public string? DiskHash { get; set; }

    [MaxLength(64)]
    public string? HostHash { get; set; }

    public DateTime FirstSeenAt { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;

    public Guid? ClusterId { get; set; }

    [MaxLength(500)]
    public string? Note { get; set; }

    [MaxLength(10)]
    public string? ListType { get; set; } // null=normal, "white"=whitelist, "grey"=greylist
}
