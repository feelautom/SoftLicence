using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Stores approved binary hashes (FP_EXE, FP_DLL, FP_CORE) per product+version.
/// On first telemetry reception, the hash is stored as baseline (Source = "auto").
/// Mismatches on subsequent events trigger an immediate ban.
/// Admins can override hashes manually (Source = "admin").
/// </summary>
public class ApprovedBinary
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid ProductId { get; set; }
    public Product? Product { get; set; }

    /// <summary>Application version string (e.g. "2.1.781")</summary>
    [Required]
    [MaxLength(64)]
    public string Version { get; set; } = string.Empty;

    /// <summary>Fingerprint key: "FP_EXE", "FP_DLL", "FP_CORE"</summary>
    [Required]
    [MaxLength(64)]
    public string Key { get; set; } = string.Empty;

    /// <summary>Expected SHA256 hash (hex lowercase)</summary>
    [Required]
    [MaxLength(128)]
    public string Hash { get; set; } = string.Empty;

    public DateTime ApprovedAt { get; set; } = DateTime.UtcNow;

    /// <summary>"auto" = baseline from first trusted client, "admin" = manually set</summary>
    [MaxLength(16)]
    public string Source { get; set; } = "auto";

    [MaxLength(128)]
    public string? ApprovedBy { get; set; }
}
