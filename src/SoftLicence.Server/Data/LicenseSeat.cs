using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class LicenseSeat
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid LicenseId { get; set; }
    public License? License { get; set; }

    [Required]
    public string HardwareId { get; set; } = string.Empty;

    public DateTime FirstActivatedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastCheckInAt { get; set; } = DateTime.UtcNow;
    
    public string? MachineName { get; set; }

    public string? AppVersion { get; set; }

    public bool IsActive { get; set; } = true;
    public DateTime? UnlinkedAt { get; set; }

    /// <summary>
    /// UTC instant of the last time this seat became active on its <see cref="HardwareId"/>: created active,
    /// reactivated after a release, or moved in place to another identifier. Null for a seat never activated since
    /// the column exists (TKT-003751). Stamped only by <see cref="LicenseDbContext"/> when changes are saved, never
    /// by callers, so every admission path records it; a check-in of an already active seat does not change it.
    /// Read by <see cref="Services.SeatChangeQuota"/>, which counts the distinct identifiers activated in one UTC day.
    /// </summary>
    public DateTime? LastActivatedAt { get; set; }
}
