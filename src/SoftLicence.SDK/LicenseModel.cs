namespace SoftLicence.SDK
{
    // L'énumération est supprimée au profit d'un système de Slugs dynamiques (ex: "PRO", "TRIAL_15D")

    public class LicenseModel
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string LicenseKey { get; set; } = string.Empty;
        public string CustomerName { get; set; } = string.Empty;
        public string CustomerEmail { get; set; } = string.Empty;
        
        public string TypeSlug { get; set; } = "STANDARD"; // Le slug choisi par l'admin
        public string? Reference { get; set; } // Champ personnalisé (ex: ID Commande, Ref Client)
        
        public DateTime CreationDate { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string HardwareId { get; set; } = string.Empty;
        public Dictionary<string, string> Features { get; set; } = new();
        
        public string Signature { get; set; } = string.Empty;

        public bool IsExpired => ExpirationDate.HasValue && DateTime.UtcNow > ExpirationDate.Value;
    }
}