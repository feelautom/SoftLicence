using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class LicenseProvisioningRequest
{
    /// <summary>Canonical durable provenance for batches created by the authenticated provider API.</summary>
    public const string ProviderAdminApiProvenance = "PROVIDER_ADMIN_API_V1";

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

    /// <summary>
    /// Gets or sets the exact opaque commercial-subject UUID supplied by the provider.
    /// Null is reserved for provisioning rows created before the TKT-000780 contract.
    /// </summary>
    public Guid? CommercialSubjectId { get; set; }

    /// <summary>Gets or sets the server-owned authority provenance; callers cannot select it.</summary>
    [MaxLength(32)]
    public string? AuthorityProvenance { get; set; }

    /// <summary>Gets or sets the exact product-scoped commercial subject for this batch.</summary>
    public RuntimeRecoveryCommercialSubject? CommercialSubject { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<License> Licenses { get; set; } = new List<License>();
}
