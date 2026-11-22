using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Persists one frozen key-activation-setting terminal per request UUID (TKT-002475), on the model of
/// <see cref="PortalDeactivationOperation"/>. A replay is answered from this receipt only, so an old
/// request can never undo a more recent decision on the same license.
/// </summary>
public sealed class LicenseKeyActivationOperation
{
    /// <summary>Gets or sets the canonical request UUID and primary idempotency key.</summary>
    [Key]
    public Guid RequestId { get; set; }

    /// <summary>Gets or sets the exact product UUID owning the license.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the exact license UUID targeted by the request.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>Gets or sets the closed request intent: <c>disable</c> or <c>lift</c>.</summary>
    public string Intent { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the frozen terminal outcome: <c>disabled</c>, <c>already_disabled</c>, <c>lifted</c>
    /// or <c>already_lifted</c>.
    /// </summary>
    public string Outcome { get; set; } = string.Empty;

    /// <summary>Gets or sets the closed actor: <c>s2s</c> or <c>admin</c>.</summary>
    public string Actor { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact authenticated S2S client identifier, or <c>admin</c>.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the provider commit time in UTC.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
