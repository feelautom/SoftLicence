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

        // Produit propriétaire
        public Guid ProductId { get; set; }
        public Product? Product { get; set; }

        // Navigation
        public ICollection<License> Licenses { get; set; } = new List<License>();
        public ICollection<LicenseTypeCustomParam> CustomParams { get; set; } = new List<LicenseTypeCustomParam>();
    }
}
