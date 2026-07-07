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
    string? UiMode);

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

public sealed record LlmTipFeedbackPagedResult<T>(
    int Total,
    int Limit,
    int Offset,
    IReadOnlyList<T> Items);

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
    IReadOnlyList<LlmTipFeedbackTipListItem> Tips);

public sealed record LlmTipFeedbackGroupedCount(string Name, int Count);

public sealed record LlmTipFeedbackDailyCount(DateTime Date, int Tips, int Events);

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
    string PayloadJson);
