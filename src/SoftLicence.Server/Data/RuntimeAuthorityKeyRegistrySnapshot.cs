namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable authenticated public Runtime authority key-registry snapshot.</summary>
public sealed class RuntimeAuthorityKeyRegistrySnapshot
{
    /// <summary>Gets or sets the provider-owned unique snapshot identifier.</summary>
    public string SnapshotId { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact provider-owned registry namespace.</summary>
    public string RegistryId { get; set; } = string.Empty;
    /// <summary>Gets or sets the positive durable global snapshot version.</summary>
    public long SnapshotVersion { get; set; }
    /// <summary>Gets or sets SHA-256 of the exact authenticated metadata encoding.</summary>
    public string MetadataDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets SHA-256 of the exact registry authentication input.</summary>
    public string RegistryAuthenticationInputDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the lossless canonical UTC observation text authenticated into the response.</summary>
    public string ObservedAtUtc { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed current, superseded, or revoked publication state.</summary>
    public string PublicationState { get; set; } = string.Empty;
    /// <summary>Gets or sets the authoritative revocation instant only for a revoked snapshot.</summary>
    public DateTime? RevokedAtUtc { get; set; }
    /// <summary>Gets or sets the exact frozen public response bytes.</summary>
    public byte[] ExactResponseBody { get; set; } = [];
    /// <summary>Gets or sets SHA-256 of the exact frozen public response bytes.</summary>
    public string ExactResponseBodySha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the canonical unpadded PS256 registry signature.</summary>
    public string RegistrySignatureBase64Url { get; set; } = string.Empty;
    /// <summary>Gets or sets the authoritative PostgreSQL creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
