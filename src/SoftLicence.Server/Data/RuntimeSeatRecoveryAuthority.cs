namespace SoftLicence.Server.Data;

/// <summary>Stores the mutable recovery lifecycle around one immutable signed-generation-v2 genesis.</summary>
public sealed class RuntimeSeatRecoveryAuthority
{
    /// <summary>Gets or sets the reservation that owns this prepared authority.</summary>
    public Guid ReservationRef { get; set; }
    /// <summary>Gets or sets the immutable new authority lineage.</summary>
    public Guid AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the immutable new authority generation.</summary>
    public Guid AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the lineage that owned the previous active generation at preparation.</summary>
    public Guid PreviousAuthorityLineageId { get; set; }
    /// <summary>Gets or sets the previous active generation within its exact persisted lineage.</summary>
    public Guid PreviousAuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the provider-allocated future binding identifier.</summary>
    public Guid BindingId { get; set; }
    /// <summary>Gets or sets the provider-allocated future enrollment identifier.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Gets or sets the provider-owned seat used by the ACTIVE uniqueness constraint.</summary>
    public Guid LicenseSeatId { get; set; }
    /// <summary>Gets or sets the canonical future installation identifier.</summary>
    public Guid InstallationId { get; set; }
    /// <summary>Gets or sets the lowercase SHA-256 hardware digest retained only as immutable signed evidence.</summary>
    public string HardwareIdDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact release version frozen into the generation.</summary>
    public string ReleaseVersion { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact artifact-set digest frozen into the generation.</summary>
    public string ArtifactSetDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the future Runtime SPKI digest commitment.</summary>
    public string PublicKeySpkiSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the equivalent Base64Url key thumbprint.</summary>
    public string KeyThumbprint { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed prepared, active, abandoned, or superseded lifecycle state.</summary>
    public string State { get; set; } = "PREPARED";
    /// <summary>Gets or sets whether the new generation remains the current head of its lineage.</summary>
    public bool IsCurrentHead { get; set; } = true;
    /// <summary>Gets or sets the separately tracked previous-authority lifecycle state.</summary>
    public string PreviousAuthorityState { get; set; } = "ACTIVE";
    /// <summary>Gets or sets the provider-derived owner subject digest exposed to consumers.</summary>
    public string SubjectRefDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the authoritative creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
