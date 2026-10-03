using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Preserves an unresolved legacy enrollment graph without granting commercial authority.
/// An operator must resolve these rows explicitly before a later validator cutover.
/// </summary>
public sealed class EnrollmentLicenseAssignmentQuarantine
{
    /// <summary>Unresolved enrollment; the primary key permits one migration verdict per row.</summary>
    [Key]
    public Guid EnrollmentId { get; set; }
    /// <summary>Legacy binding reference, retained only for operator reconciliation.</summary>
    public Guid? BindingId { get; set; }
    /// <summary>Legacy license reference; it is not trusted as an assignment.</summary>
    public Guid? LicenseId { get; set; }
    /// <summary>Legacy seat reference; it is not trusted as an assignment.</summary>
    public Guid? LicenseSeatId { get; set; }

    /// <summary>Closed migration diagnostic code explaining why no right was granted.</summary>
    [MaxLength(48)]
    public string Reason { get; set; } = string.Empty;

    /// <summary>UTC migration observation time, without a copied hardware identifier.</summary>
    public DateTime ObservedAtUtc { get; set; }
}
