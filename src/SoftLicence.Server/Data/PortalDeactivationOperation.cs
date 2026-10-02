using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Persists one provider-owned portal-deactivation terminal for exact PostgreSQL replay.
/// </summary>
public sealed class PortalDeactivationOperation
{
    /// <summary>Gets or sets the canonical request UUID and primary idempotency key.</summary>
    [Key]
    public Guid RequestId { get; set; }

    /// <summary>Gets or sets the exact authenticated S2S client identifier.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the lowercase SHA-256 digest of the exact signed body.</summary>
    public string RequestFingerprintSha256 { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact product UUID covered by S2S product scope.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the exact provider licence UUID.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>Gets or sets the canonical hardware authority supplied by Website.</summary>
    public string HardwareId { get; set; } = string.Empty;

    /// <summary>Gets or sets the closed deactivation reason.</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>Gets or sets the frozen terminal outcome.</summary>
    public string Outcome { get; set; } = string.Empty;

    /// <summary>Gets or sets the provider commit time in UTC.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
