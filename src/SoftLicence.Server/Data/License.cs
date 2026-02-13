using SoftLicence.Core;
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
        public DateTime? ExpirationDate { get; set; } // Null = Lifetime

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

        public int MaxSeats { get; set; } = 1; // Nombre de postes autorisés
        public ICollection<LicenseSeat> Seats { get; set; } = new List<LicenseSeat>();

        // Relation
        public Guid ProductId { get; set; }
        public Product? Product { get; set; }
    }
}
