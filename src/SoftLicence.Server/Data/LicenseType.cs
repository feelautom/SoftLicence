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

        /// <summary>
        /// Gets or sets whether the anonymous public trial routes (<c>POST /api/activation/trial</c> and the
        /// AUTO-TRIAL key interception of <c>POST /api/activation</c>) may create a licence of this type or
        /// automatically renew an expired one. Defaults to <c>false</c>: every type is refused unless an
        /// administrator opts it in (TKT-002466). Returning a licence the hardware already holds and that is
        /// still valid never requires this setting.
        /// </summary>
        public bool AllowPublicTrial { get; set; } = false;

        /// <summary>
        /// Gets or sets whether an external client may treat a licence of this type as able to carry a team
        /// (TKT-002717). SoftLicence only stores and exposes this flag: no key, activation, quota or rule reads it.
        /// Defaults to <c>false</c>.
        /// </summary>
        public bool TeamEligible { get; set; } = false;

        // Produit propriétaire
        public Guid ProductId { get; set; }
        public Product? Product { get; set; }

        // Navigation
        public ICollection<License> Licenses { get; set; } = new List<License>();
        public ICollection<LicenseTypeCustomParam> CustomParams { get; set; } = new List<LicenseTypeCustomParam>();
    }
}
