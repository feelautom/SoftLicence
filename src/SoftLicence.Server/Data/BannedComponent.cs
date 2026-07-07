using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class BannedComponent
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(10)]
    public string ComponentType { get; set; } = string.Empty; // CPU, MB, BIOS, DISK, HOST, FP_EXE, FP_DLL, FP_CORE

    [Required]
    [MaxLength(64)]
    public string ComponentHash { get; set; } = string.Empty;

    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }

    [MaxLength(500)]
    public string Reason { get; set; } = string.Empty;

    public DateTime BannedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public bool IsActive { get; set; } = true;
}
