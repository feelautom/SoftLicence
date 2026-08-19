using SoftLicence.SDK;
using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data
{
    public class License
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        public string LicenseKey { get; set; } = string.Empty; // Le code entré par l'utilisateur "AAAA-BBBB..."

        public string CustomerName { get; set; } = string.Empty;
        public string CustomerEmail { get; set; } = string.Empty;
        public string? Reference { get; set; } // Champ personnalisé

        // Relation avec le Type Dynamique
        public Guid LicenseTypeId { get; set; }
        public LicenseType? Type { get; set; }
        
        public DateTime CreationDate { get; set; } = DateTime.UtcNow;
        public int? ValidityDays { get; set; } // Durée de validité en jours (décompte à l'activation)
        public DateTime? ExpirationDate { get; set; } // Null = Lifetime (calculée à l'activation si ValidityDays est défini)

        // Verrouillage (Rempli lors de l'activation)
        public string? HardwareId { get; set; }
        public DateTime? ActivationDate { get; set; }

        public int RecoveryCount { get; set; } = 0;

        public bool IsActive { get; set; } = true;
        public string? RevocationReason { get; set; }
        public DateTime? RevokedAt { get; set; }

        // Système de Reset (Self-Service)
        public string? ResetCode { get; set; }
        public DateTime? ResetCodeExpiry { get; set; }

        public string AllowedVersions { get; set; } = "*"; // Masque de version (ex: 1.*, 2.1.0, *)

        public string? PartnerCode { get; set; } // Reseller/wholesale code (ex: AARONLIU-4M0Q)

        public Guid? ProvisioningRequestId { get; set; }
        public LicenseProvisioningRequest? ProvisioningRequest { get; set; }
        public int? ProvisioningSequence { get; set; }

        public int MaxSeats { get; set; } = 1; // Nombre de postes autorisés
        public ICollection<LicenseSeat> Seats { get; set; } = new List<LicenseSeat>();
        public ICollection<LicenseHistory> History { get; set; } = new List<LicenseHistory>();

        // Legacy presentation fields retained for schema compatibility. Public telemetry is
        // observation-only and must not mutate licensing authority or these global fields.
        public bool HasUninstallEvent { get; set; } = false;
        public DateTime? LastUninstallAt { get; set; }

        // Relation
        public Guid ProductId { get; set; }
        public Product? Product { get; set; }
    }
}
