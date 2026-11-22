using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Stores the optional per-license setting that disables key-based activation for one exact license.
/// The row is absent by default; once present it keeps the memory of the last disable and lift requests.
/// </summary>
public sealed class LicenseKeyActivationSetting
{
    /// <summary>Gets or sets the surrogate primary key.</summary>
    [Key]
    public Guid Id { get; set; }

    /// <summary>Gets or sets the exact product UUID owning the license.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the exact license UUID; at most one row exists per license.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>Gets or sets whether key-based activation is currently disabled.</summary>
    public bool Disabled { get; set; }

    /// <summary>Gets or sets when the setting was last disabled, in UTC.</summary>
    public DateTime DisabledAtUtc { get; set; }

    /// <summary>Gets or sets when the setting was last lifted, in UTC; null while disabled.</summary>
    public DateTime? LiftedAtUtc { get; set; }

    /// <summary>Gets or sets the unique request UUID of the last disable, for durable idempotency.</summary>
    public Guid DisabledByRequestId { get; set; }

    /// <summary>Gets or sets the unique request UUID of the last lift; null while disabled.</summary>
    public Guid? LiftedByRequestId { get; set; }

    /// <summary>Gets or sets the closed actor of the last disable: <c>s2s</c> or <c>admin</c>.</summary>
    public string DisabledByActor { get; set; } = string.Empty;

    /// <summary>Gets or sets the closed actor of the last lift; null while disabled.</summary>
    public string? LiftedByActor { get; set; }

    /// <summary>Gets or sets the exact authenticated S2S client identifier, or <c>admin</c>.</summary>
    public string DisabledByClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact authenticated S2S client identifier, or <c>admin</c>; null while disabled.</summary>
    public string? LiftedByClientId { get; set; }

    /// <summary>Gets or sets the row creation time in UTC.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Gets or sets the last mutation time in UTC.</summary>
    public DateTime UpdatedAtUtc { get; set; }
}
