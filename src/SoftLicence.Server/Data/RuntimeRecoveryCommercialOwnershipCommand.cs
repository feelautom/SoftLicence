namespace SoftLicence.Server.Data;

/// <summary>
/// Freezes one authenticated provider command and its exact response for idempotent readback.
/// The command UUID is global, while every referenced authority remains product and license scoped.
/// </summary>
public sealed class RuntimeRecoveryCommercialOwnershipCommand
{
    /// <summary>Gets or sets the caller-generated opaque command UUID.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the exact product authorization scope.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the exact license whose commercial authority was changed.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>Gets or sets the closed TRANSFER_OWNERSHIP or REVOKE_OWNERSHIP operation.</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>Gets or sets the lowercase SHA-256 of the canonical typed command tuple.</summary>
    public string RequestDigestSha256 { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact ownership-version UUID used as the compare-and-swap token.</summary>
    public Guid ExpectedOwnershipId { get; set; }

    /// <summary>Gets or sets the explicit same-product target subject for a transfer, or null for revocation.</summary>
    public Guid? TargetCommercialSubjectId { get; set; }

    /// <summary>Gets or sets the successor ACTIVE ownership UUID, or null for terminal revocation.</summary>
    public Guid? ResultOwnershipId { get; set; }

    /// <summary>Gets or sets the single PostgreSQL decision instant shared by the transition and terminal.</summary>
    public DateTime OccurredAtUtc { get; set; }

    /// <summary>Gets or sets the exact canonical JSON returned for both first execution and replay.</summary>
    public string ResponseJson { get; set; } = string.Empty;
}
