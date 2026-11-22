using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class LlmTipFeedbackEvent
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    [MaxLength(32)]
    public string SchemaVersion { get; set; } = "1";

    [MaxLength(120)]
    public string AppName { get; set; } = string.Empty;

    [MaxLength(64)]
    public string? AppVersion { get; set; }

    [MaxLength(160)]
    public string EventName { get; set; } = string.Empty;

    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }

    [MaxLength(120)]
    public string? Category { get; set; }

    [MaxLength(120)]
    public string? ToolName { get; set; }

    [MaxLength(80)]
    public string? LicenseEdition { get; set; }

    [MaxLength(80)]
    public string? RequestSource { get; set; }

    [MaxLength(80)]
    public string? RuntimeMode { get; set; }

    [MaxLength(80)]
    public string? UiMode { get; set; }

    public string PayloadJson { get; set; } = "{}";
}

public sealed class LlmTipFeedbackTip
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime FirstSeenAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? SubmittedAtUtc { get; set; }

    [MaxLength(32)]
    public string SchemaVersion { get; set; } = "1";

    [MaxLength(120)]
    public string AppName { get; set; } = string.Empty;

    [MaxLength(64)]
    public string? AppVersion { get; set; }

    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }

    [MaxLength(128)]
    public string ContentHash { get; set; } = string.Empty;

    [MaxLength(120)]
    public string? Category { get; set; }

    [MaxLength(240)]
    public string Title { get; set; } = string.Empty;

    [MaxLength(4000)]
    public string? Description { get; set; }

    [MaxLength(80)]
    public string? Severity { get; set; }

    [MaxLength(80)]
    public string? Confidence { get; set; }

    /// <summary>
    /// Approval flag reported by the client (T-IA Connect sets it locally after three upvotes). Informational only:
    /// it never publishes the tip. Publication is the administrator decision <see cref="SharedWithClients"/> (TKT-003574).
    /// </summary>
    public bool Approved { get; set; }

    /// <summary>
    /// Administrator decision to publish this tip to every client through the public read route (TKT-003574).
    /// Set and cleared only by <c>LlmTipFeedbackService.SetSharingAsync</c>, never by ingestion, so a client cannot
    /// publish a tip nor undo a retraction. Every change is journaled in <see cref="LlmTipFeedbackSharingDecision"/>.
    /// </summary>
    public bool SharedWithClients { get; set; }

    /// <summary>UTC instant of the last sharing decision (share or retraction); null while no decision was ever made.</summary>
    public DateTime? SharingChangedAtUtc { get; set; }

    /// <summary>
    /// Who made the last sharing decision, built by the server (<c>admin-ui:&lt;user&gt;</c> or
    /// <c>analytics-key:&lt;key id&gt;</c>); never a secret.
    /// </summary>
    [MaxLength(160)]
    public string? SharingChangedBy { get; set; }

    public int Upvotes { get; set; }
    public int OccurrenceCount { get; set; } = 1;

    [MaxLength(80)]
    public string? LicenseEdition { get; set; }

    [MaxLength(80)]
    public string? RequestSource { get; set; }

    [MaxLength(80)]
    public string? RuntimeMode { get; set; }

    [MaxLength(80)]
    public string? UiMode { get; set; }

    [MaxLength(80)]
    public string ReviewStatus { get; set; } = "new";

    [MaxLength(160)]
    public string? PromotedTo { get; set; }

    [MaxLength(64)]
    public string? FixedInVersion { get; set; }

    [MaxLength(32)]
    public string? BugTraceTicketRef { get; set; }

    public string PayloadJson { get; set; } = "{}";
}

/// <summary>
/// Append-only journal of the administrator decisions that publish an LLM tip to every client or retract it
/// (TKT-003574). One row per effective change: repeating the current state writes nothing. Rows are never updated
/// nor deleted; the foreign key to the tip is RESTRICT so the history cannot vanish with its tip.
/// </summary>
public sealed class LlmTipFeedbackSharingDecision
{
    /// <summary>Value of <see cref="Action"/> for a publication.</summary>
    public const string SharedAction = "shared";

    /// <summary>Value of <see cref="Action"/> for a retraction, which always carries a reason.</summary>
    public const string RetractedAction = "retracted";

    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Tip the decision applies to.</summary>
    public Guid TipId { get; set; }
    public LlmTipFeedbackTip? Tip { get; set; }

    /// <summary><see cref="SharedAction"/> or <see cref="RetractedAction"/>; a CHECK constraint closes the list.</summary>
    [MaxLength(16)]
    public string Action { get; set; } = SharedAction;

    /// <summary>
    /// Operator reason, trimmed, at most 1000 characters. Mandatory for a retraction (owner decision, 21/11/2026: a shared tip
    /// goes back only through a reasoned retraction), optional for a publication.
    /// </summary>
    [MaxLength(1000)]
    public string? Reason { get; set; }

    /// <summary>Who decided, built by the server; same format as <see cref="LlmTipFeedbackTip.SharingChangedBy"/>.</summary>
    [MaxLength(160)]
    public string DecidedBy { get; set; } = string.Empty;

    /// <summary>Path used: <c>admin-ui</c>, <c>api</c> or <c>mcp</c> (closed list, CHECK constraint).</summary>
    [MaxLength(16)]
    public string Channel { get; set; } = "admin-ui";

    /// <summary>Caller address for the API and MCP paths; null from the administration screen.</summary>
    [MaxLength(64)]
    public string? CallerIp { get; set; }

    /// <summary>UTC instant of the decision.</summary>
    public DateTime DecidedAtUtc { get; set; } = DateTime.UtcNow;
}
