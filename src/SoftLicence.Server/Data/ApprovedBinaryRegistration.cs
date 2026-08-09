using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Immutable provider identity for one release-origin ApprovedBinaries baseline.
/// Artifact filenames and sizes are deliberately outside this contract.
/// </summary>
public sealed class ApprovedBinaryRegistration
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProductId { get; set; }
    public Product? Product { get; set; }

    [Required, MaxLength(64)]
    public string Version { get; set; } = string.Empty;

    [Required, MaxLength(128)]
    public string RegistrationKey { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string ManifestDigestSha256 { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string BaselineDigestSha256 { get; set; } = string.Empty;

    [Required, MaxLength(16)]
    public string Source { get; set; } = "release";

    public DateTime RegisteredAtUtc { get; set; } = DateTime.UtcNow;

    public ICollection<ApprovedBinary> Artifacts { get; set; } = new List<ApprovedBinary>();
}
