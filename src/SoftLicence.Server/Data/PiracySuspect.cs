using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftLicence.Server.Data;

public static class PiracyStatus
{
    public const string New = "New";
    public const string Confirmed = "Confirmed";
    public const string Monitoring = "Monitoring";
    public const string Dismissed = "Dismissed";
    public const string Blocked = "Blocked";
}

public class PiracySuspect
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string HardwareId { get; set; } = string.Empty;

    public Guid ProductId { get; set; }
    [ForeignKey("ProductId")]
    public Product? Product { get; set; }

    public string Status { get; set; } = PiracyStatus.New;
    public string? AdminNotes { get; set; }

    // Cached detection stats (updated on each scan)
    public int TotalEvents { get; set; }
    public int FeatureEvents { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public string? Culture { get; set; }
    public string? OS { get; set; }
    public string? Versions { get; set; }
    public string? IpAddresses { get; set; }
    public int DistinctIpCount { get; set; }

    // Top event names (JSON array for quick display)
    public string? TopEvents { get; set; }

    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastScanAt { get; set; } = DateTime.UtcNow;
}
