using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data
{
    public class Product
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        public string Name { get; set; } = string.Empty; // ex: "SpecKit"

        // Clés RSA propres à ce produit
        [Required]
        public string PrivateKeyXml { get; set; } = string.Empty;
        
        [Required]
        public string PublicKeyXml { get; set; } = string.Empty;

        // Secret pour l'Admin API (optionnel si on gère l'auth autrement, mais utile pour simple API Key)
        public string ApiSecret { get; set; } = Guid.NewGuid().ToString("N");

        // Relation
        public ICollection<License> Licenses { get; set; } = new List<License>();
        public ICollection<TelemetryRecord> TelemetryRecords { get; set; } = new List<TelemetryRecord>();
    }
}
