using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data
{
    public class Webhook
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;

        [Required]
        [Url]
        public string Url { get; set; } = string.Empty;

        // Liste des événements abonnés (séparés par virgule, ex: "Security.IpBanned,License.Created")
        public string EnabledEvents { get; set; } = string.Empty;

        public bool IsEnabled { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastTriggeredAt { get; set; }
        public string? LastError { get; set; }
    }
}
