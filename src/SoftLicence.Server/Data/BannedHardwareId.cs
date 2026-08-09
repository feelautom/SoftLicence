using System.Collections.Frozen;
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
    /// Ban category: quota_abuse, outdated_version, debugger, piracy, manual,
    /// or dev_canary_quarantine. Null is treated as manual for historical rows.
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

        public static readonly FrozenSet<string> Permanent =
            new[] { Debugger, Piracy }.ToFrozenSet(StringComparer.Ordinal);
        public static readonly FrozenSet<string> AutoUnbannable =
            new[] { QuotaAbuse, OutdatedVersion }.ToFrozenSet(StringComparer.Ordinal);

        public static bool IsKnown(string? category) => category is
            QuotaAbuse or OutdatedVersion or Debugger or Piracy or Manual or DevCanaryQuarantine;

        public static bool IsPermanent(string? category) => category is Debugger or Piracy;

        public static bool IsAutoUnbannable(string? category) => category is QuotaAbuse or OutdatedVersion;
    }
}
