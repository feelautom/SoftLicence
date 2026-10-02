using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>Owns an existing licence audit row; structured decision metadata is nullable for legacy actions and inherits the unchanged licence deletion cascade.</summary>
public class LicenseHistory
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid LicenseId { get; set; }
    public License? License { get; set; }

    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [Required]
    public string Action { get; set; } = string.Empty; // CREATED, REVOKED, REACTIVATED, UNLINKED, RESET...

    /// <summary>Legacy action text or the versioned activation-decision envelope; consumers must validate its schema and licence/product ownership before displaying it, without reconstructing missing historical facts.</summary>
    public string? Details { get; set; } // Motif, HWID, etc.

    /// <summary>Lowercase SHA-256 of an exact operation, decision and authoritative context; null for legacy history. The unique index prevents duplicate internal writes without caching business refusals.</summary>
    [MaxLength(64)]
    public string? DecisionKey { get; set; }

    /// <summary>Exact producer operation identifier for targeted administrator reads; null for pre-existing history. Case and whitespace are not repaired here.</summary>
    [MaxLength(200)]
    public string? DecisionOperationId { get; set; }

    /// <summary>Exact bounded HTTP correlation identifier when observed; null for unavailable or historical correlation. Indexed lookup does not reconstruct transport history.</summary>
    [MaxLength(200)]
    public string? DecisionCorrelationId { get; set; }

    /// <summary>Exact submitted HWID copied from the decision, never inferred from active seats; null when unavailable.</summary>
    [MaxLength(512)]
    public string? DecisionSubmittedHardwareId { get; set; }

    /// <summary>Exact provider-resolved HWID copied from the decision; null is unknown rather than equal to submitted by inference.</summary>
    [MaxLength(512)]
    public string? DecisionResolvedHardwareId { get; set; }

    /// <summary>Exact observation-only correlated HWID if a producer supplies provenance; never an authority fallback.</summary>
    [MaxLength(512)]
    public string? DecisionCorrelatedHardwareId { get; set; }
    
    public string? PerformedBy { get; set; } // "Admin", "User", "System" or IP
}
