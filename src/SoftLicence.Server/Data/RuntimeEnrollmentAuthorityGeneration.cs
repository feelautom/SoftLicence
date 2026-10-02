namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable, already validated Runtime Enrollment v2 generation.</summary>
public sealed class RuntimeEnrollmentAuthorityGeneration
{
    /// <summary>Gets or sets the immutable generation identifier.</summary>
    public Guid AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the owning lineage identifier.</summary>
    public Guid AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the lineage-local sequence.</summary>
    public long Sequence { get; set; }
    /// <summary>Gets or sets the explicit predecessor, or null for genesis.</summary>
    public Guid? PreviousGenerationId { get; set; }
    /// <summary>Gets or sets the request identifier frozen into this result.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the already validated canonical payload UTF-8 bytes.</summary>
    public byte[] CanonicalPayloadUtf8 { get; set; } = [];
    /// <summary>Gets or sets the already validated signed-statement UTF-8 bytes.</summary>
    public byte[] SignedStatementUtf8 { get; set; } = [];
    /// <summary>Gets or sets the already validated lowercase authority digest.</summary>
    public string AuthorityDigest { get; set; } = string.Empty;
    /// <summary>Gets or sets the already validated signature algorithm.</summary>
    public string SignatureAlgorithm { get; set; } = string.Empty;
    /// <summary>Gets or sets the already validated signing key identifier.</summary>
    public string SignatureKeyId { get; set; } = string.Empty;
    /// <summary>Gets or sets the already validated canonical signature value.</summary>
    public string SignatureValue { get; set; } = string.Empty;
    /// <summary>Gets or sets the authoritative transition timestamp.</summary>
    public DateTime OccurredAtUtc { get; set; }
    /// <summary>Gets or sets the immutable persistence timestamp.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the owning lineage navigation.</summary>
    public RuntimeEnrollmentAuthorityLineage? Lineage { get; set; }
    /// <summary>Gets or sets the same-lineage predecessor navigation.</summary>
    public RuntimeEnrollmentAuthorityGeneration? PreviousGeneration { get; set; }
}
