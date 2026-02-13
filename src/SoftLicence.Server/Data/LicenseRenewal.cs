using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftLicence.Server.Data;

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
}
