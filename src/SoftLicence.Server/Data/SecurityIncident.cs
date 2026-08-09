using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class SecurityIncident
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProductId { get; set; }
    public Product? Product { get; set; }

    [Required]
    [MaxLength(200)]
    public string HardwareId { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string Family { get; set; } = string.Empty;

    public int Severity { get; set; } = 3;
    public DateTime WindowStartUtc { get; set; }
    public DateTime WindowEndUtc { get; set; }
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int OccurrenceCount { get; set; }

    [MaxLength(80)]
    public string? Version { get; set; }

    [MaxLength(50)]
    public string? ClientIp { get; set; }

    public bool IsHardwareBanned { get; set; }
    public DateTime? InitialNotificationSentAtUtc { get; set; }

    public List<SecurityIncidentEvidence> Evidence { get; set; } = [];
}

public sealed class SecurityIncidentEvidence
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid SecurityIncidentId { get; set; }
    public SecurityIncident? SecurityIncident { get; set; }

    [Required]
    [MaxLength(10)]
    public string ComponentType { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string ComponentHash { get; set; } = string.Empty;

    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int OccurrenceCount { get; set; }
}
