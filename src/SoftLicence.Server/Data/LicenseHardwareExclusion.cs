using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Persists one licence-scoped machine exclusion. This is a commercial admission refusal, never a
/// security ban: it blocks seat creation and reactivation on exactly one licence while the machine
/// stays free for every other licence and product.
/// </summary>
public sealed class LicenseHardwareExclusion
{
    /// <summary>Gets or sets the exclusion row identity.</summary>
    [Key]
    public Guid Id { get; set; }

    /// <summary>Gets or sets the exact provider product UUID covered by S2S product scope.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the exact provider licence UUID this exclusion applies to.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>
    /// Gets or sets the canonical hardware identifier: exactly 16 uppercase hexadecimal characters,
    /// compared with exact ordinal equality and never normalized.
    /// </summary>
    public string HardwareId { get; set; } = string.Empty;

    /// <summary>Gets or sets the provider commit time of the exclusion in UTC.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Gets or sets the lift time in UTC; null means the exclusion is active.</summary>
    public DateTime? LiftedAtUtc { get; set; }

    /// <summary>Gets or sets the canonical add-request UUID; unique idempotency key of the add.</summary>
    public Guid CreatedByRequestId { get; set; }

    /// <summary>Gets or sets the canonical lift-request UUID; unique idempotency key of the lift.</summary>
    public Guid? LiftedByRequestId { get; set; }

    /// <summary>Gets or sets the exact authenticated client identifier that created the exclusion.</summary>
    public string CreatedByClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the lowercase SHA-256 digest of the exact signed add body.</summary>
    public string CreatedByRequestFingerprintSha256 { get; set; } = string.Empty;

    /// <summary>Gets or sets the closed actor that created the exclusion.</summary>
    public string Actor { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact authenticated client identifier that lifted the exclusion.</summary>
    public string? LiftedByClientId { get; set; }

    /// <summary>Gets or sets the closed actor that lifted the exclusion.</summary>
    public string? LiftedByActor { get; set; }

    /// <summary>
    /// Gets or sets whether the add request also released an active seat with the
    /// provider-authority release reason inside the same transaction.
    /// </summary>
    public bool ReleaseActiveSeat { get; set; }

    /// <summary>Gets or sets the frozen release outcome: deactivated, already_inactive or none.</summary>
    public string ReleaseOutcome { get; set; } = string.Empty;
}
