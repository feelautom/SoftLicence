namespace SoftLicence.Server.Data;

/// <summary>
/// Binds one exact opaque recovery grant to a client, commercial-ownership version, operation, and request.
/// Historical rows may lack the version identifier, but such rows are never authoritative for new recovery work.
/// </summary>
public sealed class RuntimeRecoveryGrantOwnership
{
    /// <summary>Gets or sets the exact product scope.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the lowercase digest of the exact UTF-8 grant reference.</summary>
    public string ProviderGrantRefDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the authenticated S2S client that first established the binding.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact license scope.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>
    /// Gets or sets the exact commercial-ownership version that authorized the grant. A null value exists only
    /// for pre-migration rows and must fail closed instead of being inferred from current or historical state.
    /// </summary>
    public Guid? CommercialOwnershipId { get; set; }
    /// <summary>Gets or sets the provider-private owner subject identifier.</summary>
    public Guid OwnerSubjectId { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation identifier.</summary>
    public Guid RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation digest.</summary>
    public string RecoveryDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the first request that established the grant ownership.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the authoritative creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
