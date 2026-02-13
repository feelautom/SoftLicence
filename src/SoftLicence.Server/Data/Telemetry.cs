using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftLicence.Server.Data;

public enum TelemetryType
{
    Event,
    Diagnostic,
    Error
}

public class TelemetryRecord
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    [Required]
    public string HardwareId { get; set; } = string.Empty;
    
    [Required]
    public string AppName { get; set; } = string.Empty;
    
    public string? Version { get; set; }
    
    [Required]
    public string EventName { get; set; } = string.Empty;
    
    [Required]
    public TelemetryType Type { get; set; }
    
    // Liaison optionnelle avec un produit
    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }

    // Navigation properties for specialized data
    public TelemetryEvent? EventData { get; set; }
    public TelemetryDiagnostic? DiagnosticData { get; set; }
    public TelemetryError? ErrorData { get; set; }
}

public class TelemetryEvent
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public Guid TelemetryRecordId { get; set; }
    [ForeignKey("TelemetryRecordId")]
    public TelemetryRecord? Record { get; set; }
    
    /// <summary>
    /// Stocké en JSON pour la flexibilité des propriétés d'événements
    /// </summary>
    public string? PropertiesJson { get; set; }
}

public class TelemetryDiagnostic
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public Guid TelemetryRecordId { get; set; }
    [ForeignKey("TelemetryRecordId")]
    public TelemetryRecord? Record { get; set; }
    
    public int Score { get; set; }
    
    public ICollection<TelemetryDiagnosticResult> Results { get; set; } = new List<TelemetryDiagnosticResult>();
    public ICollection<TelemetryDiagnosticPort> Ports { get; set; } = new List<TelemetryDiagnosticPort>();
}

public class TelemetryDiagnosticResult
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public Guid TelemetryDiagnosticId { get; set; }
    [ForeignKey("TelemetryDiagnosticId")]
    public TelemetryDiagnostic? Diagnostic { get; set; }
    
    public string? ModuleName { get; set; }
    public bool Success { get; set; }
    public string? Severity { get; set; }
    public string? Message { get; set; }
}

public class TelemetryDiagnosticPort
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public Guid TelemetryDiagnosticId { get; set; }
    [ForeignKey("TelemetryDiagnosticId")]
    public TelemetryDiagnostic? Diagnostic { get; set; }
    
    public string? Name { get; set; }
    public int ExternalPort { get; set; }
    public string? Protocol { get; set; }
}

public class TelemetryError
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public Guid TelemetryRecordId { get; set; }
    [ForeignKey("TelemetryRecordId")]
    public TelemetryRecord? Record { get; set; }
    
    public string? ErrorType { get; set; }
    public string? Message { get; set; }
    public string? StackTrace { get; set; }
}
