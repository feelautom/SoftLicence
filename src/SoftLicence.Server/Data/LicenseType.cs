using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data
{
    public class LicenseType
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        public string Name { get; set; } = string.Empty; // Nom d'affichage (ex: "Version Professionnelle")

        [Required]
        public string Slug { get; set; } = string.Empty; // Identifiant technique (ex: "PRO")

        public string Description { get; set; } = string.Empty;

        public int DefaultDurationDays { get; set; } = 30;

        public bool IsRecurring { get; set; } = false;

        public string DefaultAllowedVersions { get; set; } = "*";

        public int DefaultMaxSeats { get; set; } = 1;

        public int MaxActivationsPerDay { get; set; } = 0; // 0 = illimité

        public bool AllowAnonymous { get; set; } = false; // Clés distribuables sans email/nom client

        public bool IsFree { get; set; } = false; // Type gratuit/essai/étudiant → exclu du calcul de conversion

        public bool EnforceSingleUsePerHardwareId { get; set; } = false; // Un HWID ne peut consommer ce type qu'une seule fois

        public bool DisableNewActivations { get; set; } = false; // Bloque uniquement les nouvelles activations, pas les recoveries/checks existants

        // Produit propriétaire
        public Guid ProductId { get; set; }
        public Product? Product { get; set; }

        // Navigation
        public ICollection<License> Licenses { get; set; } = new List<License>();
        public ICollection<LicenseTypeCustomParam> CustomParams { get; set; } = new List<LicenseTypeCustomParam>();
    }
}
