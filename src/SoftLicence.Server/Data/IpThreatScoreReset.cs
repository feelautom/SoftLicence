using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Append-only journal of operator threat-score resets (TKT-002685). One row per reset request,
/// written in the same transaction as the score deletion so an erased score always has a trace.
/// </summary>
public class IpThreatScoreReset
{
    /// <summary>Row identifier.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>IP key as the operator supplied it, after IP parsing (canonical text form).</summary>
    [MaxLength(64)]
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>Sum of the persisted scores erased by this reset; zero when nothing was stored.</summary>
    public int PreviousScore { get; set; }

    /// <summary>UTC time of the reset.</summary>
    public DateTime ResetAtUtc { get; set; }

    /// <summary>Who asked for the reset (admin user, MCP actor, API caller).</summary>
    [MaxLength(200)]
    public string ResetBy { get; set; } = string.Empty;

    /// <summary>Operator reason, mandatory.</summary>
    [MaxLength(1000)]
    public string Reason { get; set; } = string.Empty;
}
