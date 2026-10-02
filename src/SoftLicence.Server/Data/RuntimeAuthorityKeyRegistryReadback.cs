namespace SoftLicence.Server.Data;

/// <summary>Stores one semantic S2S readback binding without duplicating frozen response bytes.</summary>
public sealed class RuntimeAuthorityKeyRegistryReadback
{
    /// <summary>Gets or sets the authenticated Distribution S2S client namespace.</summary>
    public string ClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the canonical semantic request identifier.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets SHA-256 of the exact canonical request bytes.</summary>
    public string RequestDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the referenced immutable snapshot identifier.</summary>
    public string SnapshotId { get; set; } = string.Empty;
    /// <summary>Gets or sets the referenced immutable response body digest.</summary>
    public string ExactResponseBodySha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the authoritative PostgreSQL creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
