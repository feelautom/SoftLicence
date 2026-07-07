using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class CanaryAlert
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(200)]
    public string HardwareId { get; set; } = string.Empty;

    [MaxLength(100)]
    public string? MachineName { get; set; }

    [MaxLength(100)]
    public string? UserName { get; set; }

    [MaxLength(50)]
    public string? ClientIp { get; set; }

    [MaxLength(50)]
    public string? AppVersion { get; set; }

    [MaxLength(100)]
    public string Trigger { get; set; } = string.Empty;

    public string? Details { get; set; }

    /// <summary>1=Info (heuristic), 2=Warning, 3=Critical (kernel-level detection).</summary>
    public int Severity { get; set; } = 1;

    public string? OsVersion { get; set; }

    [MaxLength(32)]
    public string? BuildConfiguration { get; set; }

    [MaxLength(500)]
    public string? BaseDirectory { get; set; }

    [MaxLength(500)]
    public string? ProcessPath { get; set; }

    [MaxLength(500)]
    public string? AssemblyLocation { get; set; }

    public bool? IsLocalDevBuild { get; set; }

    [MaxLength(500)]
    public string? LocalDevBuildReason { get; set; }

    public string? BinaryFingerprintsJson { get; set; }

    [MaxLength(64)]
    public string? ServerAction { get; set; }

    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Number of duplicate pings (same HWID+Trigger+Details) after the initial one.</summary>
    public int RepeatCount { get; set; }

    /// <summary>Last time a duplicate ping was received (null if never repeated).</summary>
    public DateTime? LastSeenAt { get; set; }

    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }
}
