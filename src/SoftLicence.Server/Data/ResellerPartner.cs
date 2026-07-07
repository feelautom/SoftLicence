using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class ResellerPartner
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(50)]
    public string Code { get; set; } = string.Empty; // Ex: AARONLIU-4M0Q

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty; // Ex: Lingshi / Suzhou Lingshi

    [MaxLength(500)]
    public string? ContactEmail { get; set; }

    [MaxLength(100)]
    public string? Country { get; set; }

    [MaxLength(1000)]
    public string? Notes { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
