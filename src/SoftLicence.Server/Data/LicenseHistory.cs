using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class LicenseHistory
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid LicenseId { get; set; }
    public License? License { get; set; }

    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [Required]
    public string Action { get; set; } = string.Empty; // CREATED, REVOKED, REACTIVATED, UNLINKED, RESET...

    public string? Details { get; set; } // Motif, HWID, etc.
    
    public string? PerformedBy { get; set; } // "Admin", "User", "System" or IP
}
