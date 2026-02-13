using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data
{
    public class AccessLog
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        
        public string ClientIp { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty; // GET, POST...
        public string Path { get; set; } = string.Empty;   // /api/activation...
        
        public string Endpoint { get; set; } = string.Empty; // Tag métier
        
        public string LicenseKey { get; set; } = string.Empty;
        public string HardwareId { get; set; } = string.Empty;
        public string AppName { get; set; } = string.Empty;
        public string? UserAgent { get; set; }
        public string? CountryCode { get; set; }
        public string? Isp { get; set; }
        public bool IsProxy { get; set; }
        public int ThreatScore { get; set; }
        
        public int StatusCode { get; set; } // 200, 404, 500...
        public string ResultStatus { get; set; } = string.Empty; 
        public string? RequestBody { get; set; } // Données brutes reçues
        public string? ErrorDetails { get; set; } // Réponse d'erreur du serveur
        public bool IsSuccess { get; set; }
        public long DurationMs { get; set; }
    }
}
