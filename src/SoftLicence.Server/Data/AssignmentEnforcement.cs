using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Single-row switch of the commercial-assignment controls (TKT-001277 lot 2d, decided by Franck on 29/09/2026).
/// <c>open</c>: every control keeps its blocking code but, where it would block, records an
/// <see cref="AssignmentEnforcementEvent"/> and lets the operation through. <c>closed</c>: every control blocks
/// exactly as originally written. Read by the PostgreSQL assignment trigger and by the application; written at
/// application startup from the <c>SOFTLICENCE_ASSIGNMENT_ENFORCEMENT</c> environment variable.
/// </summary>
public sealed class AssignmentEnforcementSetting
{
    /// <summary>Mode that records instead of blocking.</summary>
    public const string Open = "open";

    /// <summary>Mode that blocks as originally written.</summary>
    public const string Closed = "closed";

    /// <summary>Gets or sets the fixed row identifier (always 1).</summary>
    [Key]
    public int Id { get; set; } = 1;

    /// <summary>Gets or sets the mode, <see cref="Open"/> or <see cref="Closed"/>.</summary>
    [MaxLength(16)]
    public string Mode { get; set; } = Open;

    /// <summary>Gets or sets when the mode was last written (UTC).</summary>
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>Gets or sets who wrote the mode last (for example <c>startup:env</c>).</summary>
    [MaxLength(64)]
    public string UpdatedBy { get; set; } = string.Empty;
}

/// <summary>
/// One place where a commercial-assignment control would have blocked but let the operation through because the
/// switch was open (TKT-001277 lot 2d). Written by the PostgreSQL trigger (<c>Source = database</c>) and by the
/// application (<c>Source = application</c>); grouped into admin alerts by the alert worker.
/// </summary>
public sealed class AssignmentEnforcementEvent
{
    /// <summary>Gets or sets the database-generated identifier.</summary>
    [Key]
    public long Id { get; set; }

    /// <summary>Gets or sets where the control runs: <c>database</c> or <c>application</c>.</summary>
    [MaxLength(16)]
    public string Source { get; set; } = string.Empty;

    /// <summary>Gets or sets the control name (for example <c>assignment_trigger</c>, <c>seat_release</c>).</summary>
    [MaxLength(64)]
    public string Control { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the trigger case: 1 graph inconsistent, 2 enrollment quarantined, 3 terminal resurrection,
    /// 4 terminal time before activation, 5 predecessor badly terminated, 6 two live claimants on one seat,
    /// 7 seat held by another active assignment, 8 unexpected error; <c>null</c> for application controls.
    /// </summary>
    public int? CaseNumber { get; set; }

    /// <summary>Gets or sets the stable reason the control would have blocked with.</summary>
    [MaxLength(64)]
    public string Reason { get; set; } = string.Empty;

    /// <summary>Gets or sets what was done instead of blocking (for example <c>granted_from_binding</c>).</summary>
    [MaxLength(64)]
    public string Action { get; set; } = string.Empty;

    /// <summary>Gets or sets the Runtime enrollment concerned, when known.</summary>
    public Guid? EnrollmentId { get; set; }

    /// <summary>Gets or sets the licence concerned, when known.</summary>
    public Guid? LicenseId { get; set; }

    /// <summary>Gets or sets the seat concerned, when known.</summary>
    public Guid? LicenseSeatId { get; set; }

    /// <summary>Gets or sets the bounded diagnostic detail.</summary>
    [MaxLength(512)]
    public string Detail { get; set; } = string.Empty;

    /// <summary>Gets or sets when the control would have blocked (UTC).</summary>
    public DateTime ObservedAtUtc { get; set; }

    /// <summary>Gets or sets when the event was included in an admin alert; <c>null</c> until then.</summary>
    public DateTime? AlertedAtUtc { get; set; }
}
