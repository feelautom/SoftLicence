using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class LicenseProvisioningRequest
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProductId { get; set; }
    public Product? Product { get; set; }

    [Required]
    [MaxLength(512)]
    public string Reference { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string RequestHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<License> Licenses { get; set; } = new List<License>();
}
