namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable Runtime Enrollment v2 lineage descriptor and its atomic mutable head.</summary>
public sealed class RuntimeEnrollmentAuthorityLineage
{
    /// <summary>Gets or sets the stable lineage identifier.</summary>
    public Guid AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the exact provider code.</summary>
    public string Provider { get; set; } = string.Empty;
    /// <summary>Gets or sets the product identifier.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the exact commercial seat that owns this authority lineage.</summary>
    public Guid LicenseSeatId { get; set; }
    /// <summary>Gets or sets the opaque exact provider grant reference.</summary>
    public string ProviderGrantRef { get; set; } = string.Empty;
    /// <summary>Gets or sets the validated Unicode scalar count of the provider grant reference.</summary>
    public int ProviderGrantRefScalarCount { get; set; }
    /// <summary>Gets or sets the authoritative lineage creation timestamp.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the current immutable generation identifier.</summary>
    public Guid HeadGenerationId { get; set; }
    /// <summary>Gets or sets the current lineage-local generation sequence.</summary>
    public long HeadSequence { get; set; }
    /// <summary>Gets or sets the current head navigation.</summary>
    public RuntimeEnrollmentAuthorityGeneration? HeadGeneration { get; set; }
    /// <summary>Gets or sets the append-only lineage generations.</summary>
    public ICollection<RuntimeEnrollmentAuthorityGeneration> Generations { get; set; } = [];
}
