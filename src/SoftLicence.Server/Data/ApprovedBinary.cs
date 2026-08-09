using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Stores authoritative binary hashes (FP_EXE, FP_DLL, FP_CORE) per product+version.
/// Client telemetry is evidence only and must never create or promote a baseline.
/// Runtime-authoritative baselines are registered only by the authenticated release API.
/// Root-admin rows remain manual administrative state and are not Runtime-eligible.
/// </summary>
public class ApprovedBinary
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid ProductId { get; set; }
    public Product? Product { get; set; }

    /// <summary>
    /// Release registration owning this row. Null identifies legacy or manual administrative state,
    /// which is intentionally not runtime-authoritative.
    /// </summary>
    public Guid? ApprovedBinaryRegistrationId { get; set; }
    public ApprovedBinaryRegistration? Registration { get; set; }

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

    /// <summary>Authoritative origin: "release" or "admin". Legacy "auto" rows are untrusted.</summary>
    [MaxLength(16)]
    public string Source { get; set; } = "admin";

    [MaxLength(128)]
    public string? ApprovedBy { get; set; }
}
