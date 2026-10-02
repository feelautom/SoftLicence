namespace SoftLicence.Server.Data;

/// <summary>Stores the sole durable current tuple for one Runtime authority key registry.</summary>
public sealed class RuntimeAuthorityKeyRegistryHead
{
    /// <summary>Gets or sets the exact provider-owned registry namespace.</summary>
    public string RegistryId { get; set; } = string.Empty;
    /// <summary>Gets or sets the current snapshot identifier.</summary>
    public string CurrentSnapshotId { get; set; } = string.Empty;
    /// <summary>Gets or sets the positive current snapshot version.</summary>
    public long CurrentSnapshotVersion { get; set; }
    /// <summary>Gets or sets the current metadata digest.</summary>
    public string CurrentMetadataDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the current authentication-input digest.</summary>
    public string CurrentRegistryAuthenticationInputDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the literal current publication state required by the composite foreign key.</summary>
    public string CurrentPublicationState { get; set; } = "current";
    /// <summary>Gets or sets the authoritative PostgreSQL head update instant.</summary>
    public DateTime UpdatedAtUtc { get; set; }
}
