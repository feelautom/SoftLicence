using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data
{
    public class LicenseTypeCustomParam
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        public Guid LicenseTypeId { get; set; }
        public LicenseType? LicenseType { get; set; }

        /// <summary>Clé technique — alphanumérique + underscore uniquement. Unique par LicenseType.</summary>
        [Required]
        public string Key { get; set; } = string.Empty;

        /// <summary>Nom lisible (ex: "Comptes maximum").</summary>
        [Required]
        public string Name { get; set; } = string.Empty;

        /// <summary>Valeur associée (ex: "50").</summary>
        public string Value { get; set; } = string.Empty;
    }
}
