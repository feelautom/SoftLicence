using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class BannedHardwareId
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(200)]
    public string HardwareId { get; set; } = string.Empty;

    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }

    public DateTime BannedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }

    [MaxLength(500)]
    public string Reason { get; set; } = string.Empty;

    /// <summary>
    /// Ban category: quota_abuse, outdated_version, debugger, piracy, manual.
    /// Null treated as "manual" for backwards compatibility.
    /// </summary>
    [MaxLength(50)]
    public string? BanCategory { get; set; }

    public bool IsActive { get; set; } = true;

    // Link to PiracySuspect if banned from piracy detection
    public Guid? PiracySuspectId { get; set; }

    public static class Categories
    {
        public const string QuotaAbuse = "quota_abuse";
        public const string OutdatedVersion = "outdated_version";
        public const string Debugger = "debugger";
        public const string Piracy = "piracy";
        public const string Manual = "manual";
        public const string DevCanaryQuarantine = "dev_canary_quarantine";

        public static readonly string[] Permanent = { Debugger, Piracy };
        public static readonly string[] AutoUnbannable = { QuotaAbuse, OutdatedVersion };
    }
}
