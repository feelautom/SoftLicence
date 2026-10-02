using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftLicence.Server.Data;

/// <summary>
/// Records the immutable result and canonical request identity for one billing renewal transaction.
/// Historical rows intentionally keep a null fingerprint and must never be treated as verified replays.
/// </summary>
public class LicenseRenewal
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid LicenseId { get; set; }
    
    [ForeignKey("LicenseId")]
    public License? License { get; set; }

    [Required]
    public string TransactionId { get; set; } = string.Empty; // ID Stripe/PayPal pour éviter les doublons

    public DateTime RenewalDate { get; set; } = DateTime.UtcNow;

    public int DaysAdded { get; set; }

    public DateTime? ResultingExpirationDate { get; set; }

    public string? ResultingReference { get; set; }

    /// <summary>
    /// Gets or sets the version of the canonical request representation protected by the fingerprint.
    /// A null value identifies a historical row whose request identity cannot be reconstructed.
    /// </summary>
    public int? RequestFingerprintVersion { get; set; }

    /// <summary>
    /// Gets or sets the lowercase ASCII hexadecimal SHA-256 digest of the complete canonical request.
    /// The value is null only for historical rows and is never synthesized by a migration.
    /// </summary>
    public string? RequestFingerprint { get; set; }
}
