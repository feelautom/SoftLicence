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

    /// <summary>
    /// Licence of the product that the incident's hardware identifier is attached to (seat or primary hardware),
    /// resolved by the server when a per-hardware ApprovedBinaries incident is recorded (TKT-003674).
    /// <see langword="null"/> for public aggregates and every other family, for hardware unknown to every licence of
    /// the product, and after the licence row is deleted (the foreign key clears it so the security evidence survives).
    /// </summary>
    public Guid? LicenseId { get; set; }

    /// <summary>Licence navigation for <see cref="LicenseId"/>; loaded only on demand.</summary>
    public License? License { get; set; }

    public List<SecurityIncidentEvidence> Evidence { get; set; } = [];

    /// <summary>
    /// Counted application starts of a per-hardware ApprovedBinaries incident, one row per distinct start
    /// (TKT-003674). They back the sliding 24-hour alert threshold and keep the IP and version of every counted start.
    /// Empty for every other incident family.
    /// </summary>
    public List<SecurityIncidentObservation> Observations { get; set; } = [];
}

/// <summary>
/// One counted start of an application whose binary fingerprints match no approved build of its product, attached
/// to the per-hardware incident of that machine (TKT-003674). Several telemetry events of the same start (for
/// example <c>Startup_AppStarted</c> and <c>Startup_PrereqSnapshot</c>) produce a single row: a row is written only
/// when no other row of the incident lies within <see cref="Services.SecurityIncidentService.SameStartupGap"/>.
/// Rows are evidence only and never drive a sanction.
/// </summary>
public sealed class SecurityIncidentObservation
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Owning per-hardware incident; rows are deleted with it.</summary>
    public Guid SecurityIncidentId { get; set; }

    /// <summary>Owning incident navigation.</summary>
    public SecurityIncident? SecurityIncident { get; set; }

    /// <summary>Server reception time of the telemetry event (UTC), used by the 24-hour threshold window.</summary>
    public DateTime ObservedAtUtc { get; set; }

    /// <summary>Server-observed client IP of that start, stored as received (truncated to 50 characters), or null.</summary>
    [MaxLength(50)]
    public string? ClientIp { get; set; }

    /// <summary>Application version announced by the client for that start, as validated by the baseline lookup.</summary>
    [MaxLength(80)]
    public string? Version { get; set; }
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
