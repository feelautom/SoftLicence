using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Persists a one-way legacy hardware identifier alias created by an authenticated Runtime authority migration.
/// The legacy identifier is stored only as a SHA-256 digest, while the authoritative identifier remains owned by the linked seat.
/// </summary>
public sealed class HardwareAuthorityAlias
{
    /// <summary>Gets or sets the database identifier.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Gets or sets the product security boundary in which the alias may be resolved.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the product navigation that owns the compatibility policy.</summary>
    public Product? Product { get; set; }

    /// <summary>Gets or sets the only license for which the alias may be resolved.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>Gets or sets the seat that owns the authoritative V2 hardware identifier.</summary>
    public Guid LicenseSeatId { get; set; }

    /// <summary>Gets or sets the authenticated Runtime enrollment that proved the migration.</summary>
    public Guid RuntimeEnrollmentId { get; set; }

    /// <summary>Gets or sets the installation binding proven by the same Runtime migration.</summary>
    public Guid BindingId { get; set; }

    /// <summary>Gets or sets the canonical request identifier of the signed migration operation.</summary>
    public Guid? MigrationRequestId { get; set; }

    /// <summary>Gets or sets the lowercase SHA-256 digest of the exact canonical legacy hardware identifier.</summary>
    [MaxLength(64)]
    public string LegacyHardwareIdSha256 { get; set; } = string.Empty;

    /// <summary>Gets or sets the lowercase SHA-256 digest of the authoritative V2 identifier.</summary>
    [MaxLength(64)]
    public string CanonicalHardwareIdSha256 { get; set; } = string.Empty;

    /// <summary>Gets or sets the Runtime security epoch established by the migration.</summary>
    public int SecurityEpoch { get; set; }

    /// <summary>Gets or sets the server authority generation committed with the migration.</summary>
    public long AuthorityEpoch { get; set; }

    /// <summary>Gets or sets whether compatibility resolution remains authorized.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Gets or sets when the authenticated migration created the alias.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Gets or sets when an operator or policy disabled compatibility resolution.</summary>
    public DateTime? DisabledAtUtc { get; set; }

    /// <summary>Gets or sets the last hourly-bounded compatibility observation.</summary>
    public DateTime? LastObservedAtUtc { get; set; }

    /// <summary>Gets or sets the bounded count of persisted compatibility observations.</summary>
    public long ObservationCount { get; set; }

    /// <summary>Gets or sets the linked license.</summary>
    public License? License { get; set; }

    /// <summary>Gets or sets the linked authoritative seat.</summary>
    public LicenseSeat? LicenseSeat { get; set; }

    /// <summary>Gets or sets the Runtime enrollment that established the trust relationship.</summary>
    public RuntimeEnrollment? RuntimeEnrollment { get; set; }

    /// <summary>Gets or sets the installation binding that must remain authoritative.</summary>
    public DistributionInstallationBinding? Binding { get; set; }
}
