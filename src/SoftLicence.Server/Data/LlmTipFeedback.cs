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

    public bool Approved { get; set; }
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
