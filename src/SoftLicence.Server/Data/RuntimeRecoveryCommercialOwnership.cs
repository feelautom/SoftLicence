namespace SoftLicence.Server.Data;

/// <summary>Versions the provider-owned commercial subject controlling one product and license.</summary>
public sealed class RuntimeRecoveryCommercialOwnership
{
    /// <summary>Gets or sets the ownership version identifier.</summary>
    public Guid Id { get; set; }
    /// <summary>Gets or sets the exact product scope.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the exact license scope.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>
    /// Gets or sets the immediately preceding ownership-version UUID within the same product and license.
    /// Null identifies an initial version, created by provisioning or an explicitly receipted historical return.
    /// </summary>
    public Guid? PreviousOwnershipId { get; set; }
    /// <summary>Gets or sets the provider-private subject identifier never emitted on the wire.</summary>
    public Guid OwnerSubjectId { get; set; }
    /// <summary>Gets or sets the closed pending-transfer, active, transferred, or revoked state.</summary>
    public string State { get; set; } = "ACTIVE";
    /// <summary>Gets or sets the inclusive version creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the terminal instant for a non-active version.</summary>
    public DateTime? EndedAtUtc { get; set; }
}
