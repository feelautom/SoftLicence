using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Stores the relational entitlement authority; contract v3 is generationless and contract v4
/// freezes one provider-issued Runtime Enrollment lineage, generation, and artifact-set digest.
/// </summary>
public sealed class DistributionEntitlement
{
    public Guid Id { get; set; }
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    public Guid ProductId { get; set; }
    public Guid LicenseId { get; set; }
    [MaxLength(64)] public string GrantRefDigestSha256 { get; set; } = string.Empty;
    [MaxLength(64)] public string SubjectRefDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the immutable Runtime Enrollment lineage for contract v4.</summary>
    public Guid? AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the immutable provider-issued Runtime Enrollment generation for contract v4.</summary>
    public Guid? AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the immutable lowercase release artifact-set digest for contract v4.</summary>
    [MaxLength(64)] public string? ArtifactSetDigestSha256 { get; set; }
    public int ContractVersion { get; set; }
    [MaxLength(16)] public string State { get; set; } = "issued";
    public DateTime IssuedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? FinalizedAtUtc { get; set; }
}
