using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class TelemetryIngestionRejection
{
    [Key] public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    [MaxLength(160)] public string Route { get; set; } = string.Empty;
    [MaxLength(64)] public string ValidationCode { get; set; } = string.Empty;
    [MaxLength(500)] public string InvalidFields { get; set; } = string.Empty;
    [MaxLength(120)] public string? AppName { get; set; }
    [MaxLength(80)] public string? Version { get; set; }
    [MaxLength(160)] public string? EventName { get; set; }
    [MaxLength(64)] public string? HardwareIdHash { get; set; }
    [MaxLength(32)] public string? HardwareIdMasked { get; set; }
    [MaxLength(80)] public string? ClientIpMasked { get; set; }
    [MaxLength(160)] public string? ClientName { get; set; }
    [MaxLength(80)] public string CorrelationId { get; set; } = string.Empty;
    public bool Alerted { get; set; }
}

public sealed class ActivationIncident
{
    [Key] public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }
    [MaxLength(64)] public string HardwareIdHash { get; set; } = string.Empty;
    [MaxLength(32)] public string HardwareIdMasked { get; set; } = string.Empty;
    [MaxLength(64)] public string Category { get; set; } = "network";
    [MaxLength(24)] public string Status { get; set; } = "OPEN";
    [MaxLength(24)] public string Severity { get; set; } = "INFO";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int RepeatCount { get; set; }
    [MaxLength(80)] public string? Version { get; set; }
    [MaxLength(8)] public string? CountryCode { get; set; }
    [MaxLength(160)] public string? Isp { get; set; }
    [MaxLength(80)] public string? ClientIpMasked { get; set; }
    [MaxLength(24)] public string? LastNotifiedSeverity { get; set; }
    public DateTime? RecoveredAtUtc { get; set; }
}
