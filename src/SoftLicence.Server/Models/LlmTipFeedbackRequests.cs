using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public sealed class LlmTipFeedbackUsageRequest
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string AppName { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string SchemaVersion { get; set; } = "1";
    public string EventName { get; set; } = string.Empty;
    public Dictionary<string, string>? Properties { get; set; }
    public Dictionary<string, string>? Context { get; set; }
}

public sealed class LlmTipFeedbackTipRequest
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string AppName { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string SchemaVersion { get; set; } = "1";
    public bool Anonymized { get; set; }
    public string ContentHash { get; set; } = string.Empty;
    public string? Category { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? Severity { get; set; }
    public string? Confidence { get; set; }
    public bool Approved { get; set; }
    public int Upvotes { get; set; }
    public DateTime? SubmittedAt { get; set; }
    public Dictionary<string, string>? Context { get; set; }
}

public sealed record LlmTipFeedbackIngestResponse(Guid Id, string Status, int OccurrenceCount);

/// <summary>
/// One tip as listed to analytics keys and administrators. <c>Approved</c> is the client's local flag (informational);
/// <c>SharedWithClients</c> and <c>SharingChangedAtUtc</c> are the administrator sharing decision (TKT-003574), never
/// exposed by the public read route.
/// </summary>
public sealed record LlmTipFeedbackTipListItem(
    Guid Id,
    string ContentHash,
    Guid? ProductId,
    string? AppName,
    string? Category,
    string Title,
    string? Severity,
    string? Confidence,
    bool Approved,
    int Upvotes,
    int OccurrenceCount,
    DateTime FirstSeenAtUtc,
    DateTime LastSeenAtUtc,
    string ReviewStatus,
    string? AppVersion,
    string? LicenseEdition,
    string? RequestSource,
    string? RuntimeMode,
    string? UiMode,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? BugTraceTicketRef = null,
    bool SharedWithClients = false,
    DateTime? SharingChangedAtUtc = null);

/// <summary>
/// Filters, sort and paging of the admin tip list and overview. Null or blank filters are ignored; <c>Days</c> sets a
/// rolling window when <c>FromUtc</c> is absent (0 disables it).
/// </summary>
public sealed class LlmTipFeedbackAdminQuery
{
    public Guid? ProductId { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public string? Category { get; set; }
    public string? Severity { get; set; }
    public string? AppVersion { get; set; }
    public string? ReviewStatus { get; set; }
    public string? Search { get; set; }

    /// <summary>
    /// Sharing filter (TKT-003574): true keeps only tips published to every client, false only the unpublished ones,
    /// null keeps both.
    /// </summary>
    public bool? Shared { get; set; }

    public string? SortBy { get; set; }
    public string? SortDir { get; set; }
    public int Days { get; set; } = 30;
    public int Take { get; set; } = 100;
    public int Limit { get; set; } = 100;
    public int Offset { get; set; }
}

public sealed class LlmTipFeedbackReviewStatusRequest
{
    public Guid? Id { get; set; }
    public string? ContentHash { get; set; }
    public string ReviewStatus { get; set; } = string.Empty;
}

public sealed class LlmTipFeedbackBugTraceConversionRequest
{
    public Guid? Id { get; set; }
    public string? ContentHash { get; set; }
    public string? Priority { get; set; }
    public string? Type { get; set; }
}

public sealed record LlmTipFeedbackBugTraceConversionResult(
    Guid Id,
    string ContentHash,
    string ReviewStatus,
    string BugTraceTicketRef,
    bool Created);

public sealed record LlmTipFeedbackPagedResult<T>(
    int Total,
    int Limit,
    int Offset,
    IReadOnlyList<T> Items);

/// <summary>
/// Aggregates of the admin screen for the filtered tips. <c>ApprovedTips</c> counts the client-side approvals,
/// <c>SharedTips</c> the tips an administrator shared with every client (TKT-003574); both are kept because they mean
/// different things.
/// </summary>
public sealed record LlmTipFeedbackAdminOverview(
    int TotalTips,
    int TotalEvents,
    int TotalOccurrences,
    int NewTips,
    int NeedsReview,
    int ApprovedTips,
    int TotalUpvotes,
    int UpvotedUsageEvents,
    IReadOnlyList<LlmTipFeedbackGroupedCount> TopCategories,
    IReadOnlyList<LlmTipFeedbackGroupedCount> TopVersions,
    IReadOnlyList<LlmTipFeedbackGroupedCount> TopSeverities,
    IReadOnlyList<LlmTipFeedbackTipListItem> TopTipsByOccurrences,
    IReadOnlyList<LlmTipFeedbackTipListItem> TopTipsByUpvotes,
    IReadOnlyList<LlmTipFeedbackDailyCount> DailyTips,
    IReadOnlyList<LlmTipFeedbackTipListItem> Tips,
    int SharedTips = 0);

public sealed record LlmTipFeedbackGroupedCount(string Name, int Count);

public sealed record LlmTipFeedbackDailyCount(DateTime Date, int Tips, int Events);

/// <summary>
/// Full anonymized detail of one tip for administrators, with the sharing state, the last decision's instant and
/// actor, and the sharing journal newest first (<c>SharingDecisions</c>, null only when not loaded) (TKT-003574).
/// </summary>
public sealed record LlmTipFeedbackTipDetail(
    Guid Id,
    string ContentHash,
    string? Category,
    string Title,
    string? Description,
    string? Severity,
    string? Confidence,
    bool Approved,
    int Upvotes,
    int OccurrenceCount,
    DateTime FirstSeenAtUtc,
    DateTime LastSeenAtUtc,
    DateTime? SubmittedAtUtc,
    string ReviewStatus,
    string? AppName,
    Guid? ProductId,
    string? AppVersion,
    string? LicenseEdition,
    string? RequestSource,
    string? RuntimeMode,
    string? UiMode,
    string PayloadJson,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? BugTraceTicketRef = null,
    bool SharedWithClients = false,
    DateTime? SharingChangedAtUtc = null,
    string? SharingChangedBy = null,
    IReadOnlyList<LlmTipFeedbackSharingDecisionItem>? SharingDecisions = null);

/// <summary>
/// Administrator request publishing a tip to every client or retracting it (TKT-003574), sent to
/// <c>POST api/llm-tips-feedback/admin/tips/sharing</c> or by the MCP tool <c>set_llm_tip_feedback_sharing</c>.
/// </summary>
public sealed class LlmTipFeedbackSharingRequest
{
    /// <summary>Tip UUID; optional when <see cref="ContentHash"/> is given.</summary>
    public Guid? Id { get; set; }

    /// <summary>Tip content hash, matched exactly as stored; optional when <see cref="Id"/> is given.</summary>
    public string? ContentHash { get; set; }

    /// <summary>True to publish the tip to every client, false to retract it.</summary>
    public bool Shared { get; set; }

    /// <summary>Operator reason; mandatory (non blank) for a retraction, optional for a publication, 1000 characters at most.</summary>
    public string? Reason { get; set; }

    /// <summary>Calling path recorded in the journal: <c>api</c> (default) or <c>mcp</c>.</summary>
    public string? Source { get; set; }

    /// <summary>Optional product UUID; global analytics keys must give it or <see cref="ProductName"/>.</summary>
    public string? ProductId { get; set; }

    /// <summary>Optional exact product name; global analytics keys must give it or <see cref="ProductId"/>.</summary>
    public string? ProductName { get; set; }
}

/// <summary>
/// Outcome of a sharing decision. <see cref="Changed"/> is false when the tip was already in the requested state:
/// nothing was written and no journal row was added (idempotent repeat).
/// </summary>
public sealed record LlmTipFeedbackSharingResult(
    Guid Id,
    string ContentHash,
    bool SharedWithClients,
    bool Changed,
    DateTime? SharingChangedAtUtc,
    string? SharingChangedBy);

/// <summary>One row of the sharing journal as shown to administrators (newest first).</summary>
public sealed record LlmTipFeedbackSharingDecisionItem(
    string Action,
    string? Reason,
    string DecidedBy,
    string Channel,
    DateTime DecidedAtUtc);

/// <summary>
/// Body of the public read route <c>GET api/llm-tips-feedback/shared</c> (TKT-003574). A complete snapshot of the tips
/// an administrator shared for one product: a tip absent from <see cref="Items"/> was retracted and clients drop it.
/// </summary>
public sealed record LlmTipSharedTipsResponse(
    string SchemaVersion,
    DateTime GeneratedAtUtc,
    int Count,
    IReadOnlyList<LlmTipSharedTip> Items);

/// <summary>
/// One shared tip as exposed publicly: only the anonymized content an administrator reviewed. Never internal
/// identifiers, counters, votes, versions, licence edition, request context, product or raw payload.
/// </summary>
public sealed record LlmTipSharedTip(
    string ContentHash,
    string? Category,
    string Title,
    string? Description,
    string? Severity,
    string? Confidence,
    DateTime SharedAtUtc);
