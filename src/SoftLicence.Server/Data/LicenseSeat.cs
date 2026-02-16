using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class LicenseSeat
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid LicenseId { get; set; }
    public License? License { get; set; }

    [Required]
    public string HardwareId { get; set; } = string.Empty;

    public DateTime FirstActivatedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastCheckInAt { get; set; } = DateTime.UtcNow;
    
    public string? MachineName { get; set; }

    public bool IsActive { get; set; } = true;
    public DateTime? UnlinkedAt { get; set; }
}
