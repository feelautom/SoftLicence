using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class LlmTipFeedbackService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly Regex EmailRegex = new(@"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex WindowsPathRegex = new(@"[A-Z]:\\(?:[^\\/:*?""<>|\r\n]+\\?)+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PrivateIpRegex = new(@"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", RegexOptions.Compiled);
    private static readonly Regex LongSecretLikeRegex = new(@"\b[A-Za-z0-9+/=]{80,}\b", RegexOptions.Compiled);
    private static readonly string[] SensitiveKeyFragments =
    [
        "password",
        "token",
        "secret",
        "apikey",
        "api_key",
        "licensekey",
        "license_key",
        "hardwareid",
        "hwid",
        "projectname",
        "project_name",
        "customerproject",
        "customer_project",
        "sourcecode",
        "source_code",
        "code"
    ];
    public static readonly string[] ReviewStatuses =
    [
        "new",
        "ignored",
        "needs-product-fix",
        "needs-doc",
        "needs-mcp-guide",
        "needs-regression-test",
        "converted-to-bugtrace",
        "fixed-in-product"
    ];

    /// <summary>Longest operator reason accepted for a sharing decision; matches the journal column.</summary>
    public const int MaxSharingReasonLength = 1000;

    /// <summary>
    /// Most tips returned by one public snapshot. Bounds the response size of an unauthenticated route; far above the
    /// few tips an administrator is expected to share.
    /// </summary>
    public const int MaxSharedTipsPerSnapshot = 500;

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IBugTraceProxyService? _bugTrace;
    private readonly LlmTipProductIdCache _productIdCache;
    /// <summary>Product to BugTrace project mapping for tip conversion (TKT-003093); never null, empty means "refuse all".</summary>
    private readonly LlmTipBugTraceRouting _bugTraceRouting;

    /// <summary>
    /// Creates the LLM tips feedback service.
    /// </summary>
    /// <param name="dbFactory">Factory of short-lived database contexts, one per operation.</param>
    /// <param name="bugTrace">BugTrace proxy used only by the tip-to-ticket conversion; null disables it.</param>
    /// <param name="productIdCache">
    /// Shared product-identifier cache (TKT-003573). The service is transient, so production injects
    /// the singleton; when null (unit tests) a private cache is used for this instance only.
    /// </param>
    /// <param name="bugTraceRouting">
    /// Product to BugTrace project mapping for tip conversion (TKT-003093). Production injects the
    /// configuration singleton; when null the mapping is empty, so every conversion is refused rather
    /// than sent to a default project.
    /// </param>
    public LlmTipFeedbackService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IBugTraceProxyService? bugTrace = null,
        LlmTipProductIdCache? productIdCache = null,
        LlmTipBugTraceRouting? bugTraceRouting = null)
    {
        _dbFactory = dbFactory;
        _bugTrace = bugTrace;
        _productIdCache = productIdCache ?? new LlmTipProductIdCache();
        _bugTraceRouting = bugTraceRouting ?? new LlmTipBugTraceRouting((string?)null);
    }

    /// <summary>
    /// Validates and stores one anonymized usage event (for example a tip search) sent by a client
    /// application, linked to the product whose name matches <c>appName</c> when one exists.
    /// </summary>
    /// <param name="request">Usage event; <c>appName</c>, <c>schemaVersion</c> and <c>eventName</c> are required.</param>
    /// <param name="cancellationToken">
    /// Stops the work. The HTTP endpoint passes a server-side persistence deadline, not the client
    /// connection token, so an event already received is stored even if the client stops waiting.
    /// </param>
    /// <returns>The stored event identifier with status <c>accepted</c>.</returns>
    /// <exception cref="ArgumentException">Missing field or payload carrying sensitive raw data; nothing is stored.</exception>
    /// <exception cref="OperationCanceledException">The token fired; the event may or may not have been committed.</exception>
    public async Task<LlmTipFeedbackIngestResponse> SaveUsageAsync(
        LlmTipFeedbackUsageRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateCommon(request.AppName, request.SchemaVersion);
        if (string.IsNullOrWhiteSpace(request.EventName))
            throw new ArgumentException("eventName is required.");

        ValidatePayload(request);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productId = await ResolveProductIdAsync(db, request.AppName, cancellationToken);
        var context = request.Context ?? [];
        var properties = request.Properties ?? [];

        var entity = new LlmTipFeedbackEvent
        {
            TimestampUtc = ToUtc(request.Timestamp),
            SchemaVersion = Trim(request.SchemaVersion, 32) ?? "1",
            AppName = Trim(request.AppName, 120) ?? string.Empty,
            AppVersion = Trim(request.Version, 64),
            ProductId = productId,
            EventName = Trim(request.EventName, 160) ?? string.Empty,
            Category = FirstValue(properties, "Category", "category"),
            ToolName = FirstValue(properties, "ToolName", "toolName", "Tool", "tool"),
            LicenseEdition = FirstValue(context, "licenseEdition", "LicenseEdition"),
            RequestSource = FirstValue(context, "requestSource", "RequestSource"),
            RuntimeMode = FirstValue(context, "runtimeMode", "RuntimeMode"),
            UiMode = FirstValue(context, "uiMode", "UiMode"),
            PayloadJson = JsonSerializer.Serialize(request, JsonOptions)
        };

        db.LlmTipFeedbackEvents.Add(entity);
        await db.SaveChangesAsync(cancellationToken);
        return new LlmTipFeedbackIngestResponse(entity.Id, "accepted", 1);
    }

    /// <summary>
    /// Validates and stores one anonymized tip, or increments the occurrence count of the tip that
    /// already has the same <c>contentHash</c>.
    /// </summary>
    /// <param name="request">Tip; must be anonymized and carry <c>contentHash</c> and <c>title</c>.</param>
    /// <param name="cancellationToken">
    /// Server-side persistence deadline from the HTTP endpoint, not the client connection token (TKT-003573).
    /// </param>
    /// <returns><c>accepted</c> for a new tip, <c>deduplicated</c> with the new count otherwise.</returns>
    /// <exception cref="ArgumentException">Missing field, non-anonymized or sensitive payload; nothing is stored.</exception>
    /// <exception cref="OperationCanceledException">The token fired; the write may or may not have been committed.</exception>
    public async Task<LlmTipFeedbackIngestResponse> SaveTipAsync(
        LlmTipFeedbackTipRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateCommon(request.AppName, request.SchemaVersion);
        if (!request.Anonymized)
            throw new ArgumentException("tips payload must be anonymized.");
        if (string.IsNullOrWhiteSpace(request.ContentHash))
            throw new ArgumentException("contentHash is required.");
        if (string.IsNullOrWhiteSpace(request.Title))
            throw new ArgumentException("title is required.");

        ValidatePayload(request);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var contentHash = Trim(request.ContentHash, 128) ?? string.Empty;
        var now = DateTime.UtcNow;
        var existing = await db.LlmTipFeedbackTips
            .FirstOrDefaultAsync(t => t.ContentHash == contentHash, cancellationToken);

        if (existing != null)
        {
            existing.LastSeenAtUtc = now;
            existing.OccurrenceCount++;
            existing.Upvotes = Math.Max(existing.Upvotes, request.Upvotes);
            existing.Approved = existing.Approved || request.Approved;
            existing.PayloadJson = JsonSerializer.Serialize(request, JsonOptions);
            await db.SaveChangesAsync(cancellationToken);
            return new LlmTipFeedbackIngestResponse(existing.Id, "deduplicated", existing.OccurrenceCount);
        }

        var context = request.Context ?? [];
        var entity = new LlmTipFeedbackTip
        {
            CreatedAtUtc = now,
            FirstSeenAtUtc = now,
            LastSeenAtUtc = now,
            SubmittedAtUtc = request.SubmittedAt.HasValue ? ToUtc(request.SubmittedAt.Value) : null,
            SchemaVersion = Trim(request.SchemaVersion, 32) ?? "1",
            AppName = Trim(request.AppName, 120) ?? string.Empty,
            AppVersion = Trim(request.Version, 64),
            ProductId = await ResolveProductIdAsync(db, request.AppName, cancellationToken),
            ContentHash = contentHash,
            Category = Trim(request.Category, 120),
            Title = Trim(request.Title, 240) ?? string.Empty,
            Description = Trim(request.Description, 4000),
            Severity = Trim(request.Severity, 80),
            Confidence = Trim(request.Confidence, 80),
            Approved = request.Approved,
            Upvotes = Math.Max(0, request.Upvotes),
            LicenseEdition = FirstValue(context, "licenseEdition", "LicenseEdition"),
            RequestSource = FirstValue(context, "requestSource", "RequestSource"),
            RuntimeMode = FirstValue(context, "runtimeMode", "RuntimeMode"),
            UiMode = FirstValue(context, "uiMode", "UiMode"),
            PayloadJson = JsonSerializer.Serialize(request, JsonOptions)
        };

        db.LlmTipFeedbackTips.Add(entity);
        await db.SaveChangesAsync(cancellationToken);
        return new LlmTipFeedbackIngestResponse(entity.Id, "accepted", entity.OccurrenceCount);
    }

    /// <summary>
    /// Lists the tips of one product for a product-scoped analytics key, filtered by exact category and sorted by
    /// occurrences (default), upvotes, title or first sighting, at most 200 rows. Includes the sharing state.
    /// </summary>
    /// <param name="productId">Product of the calling key.</param>
    /// <param name="category">Exact stored category, or null for every category.</param>
    /// <param name="sortBy"><c>upvotes</c>, <c>title</c>, <c>firstseen</c>, anything else sorts by occurrences.</param>
    /// <param name="take">Row count, clamped to 1..200.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public async Task<IReadOnlyList<LlmTipFeedbackTipListItem>> ListTipsAsync(
        Guid productId,
        string? category,
        string? sortBy,
        int take,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.LlmTipFeedbackTips
            .AsNoTracking()
            .Where(t => t.ProductId == productId);

        if (!string.IsNullOrWhiteSpace(category))
        {
            query = query.Where(t => t.Category == category);
        }

        query = sortBy?.ToLowerInvariant() switch
        {
            "upvotes" => query.OrderByDescending(t => t.Upvotes).ThenByDescending(t => t.LastSeenAtUtc),
            "title" => query.OrderBy(t => t.Title),
            "firstseen" => query.OrderByDescending(t => t.FirstSeenAtUtc),
            _ => query.OrderByDescending(t => t.OccurrenceCount).ThenByDescending(t => t.LastSeenAtUtc)
        };

        return await query
            .Take(Math.Clamp(take, 1, 200))
            .Select(t => new LlmTipFeedbackTipListItem(
                t.Id,
                t.ContentHash,
                t.ProductId,
                t.AppName,
                t.Category,
                t.Title,
                t.Severity,
                t.Confidence,
                t.Approved,
                t.Upvotes,
                t.OccurrenceCount,
                t.FirstSeenAtUtc,
                t.LastSeenAtUtc,
                t.ReviewStatus,
                t.AppVersion,
                t.LicenseEdition,
                t.RequestSource,
                t.RuntimeMode,
                t.UiMode,
                null,
                t.SharedWithClients,
                t.SharingChangedAtUtc))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Computes the admin screen aggregates (counts, top categories, versions, severities, daily series, top tips and
    /// the sorted list) for the filtered tips, including the number of tips shared with every client (TKT-003574).
    /// </summary>
    /// <param name="query">Filters; see <see cref="LlmTipFeedbackAdminQuery"/>.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <exception cref="ArgumentException"><c>FromUtc</c> after <c>ToUtc</c>.</exception>
    public async Task<LlmTipFeedbackAdminOverview> GetAdminOverviewAsync(
        LlmTipFeedbackAdminQuery query,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var period = BuildPeriod(query);
        var tipsQuery = ApplyAdminFilters(db.LlmTipFeedbackTips.AsNoTracking(), query, period.FromUtc, period.ToUtc);
        var eventsQuery = ApplyEventFilters(db.LlmTipFeedbackEvents.AsNoTracking(), query, period.FromUtc, period.ToUtc);

        var totalTips = await tipsQuery.CountAsync(cancellationToken);
        var totalEvents = await eventsQuery.CountAsync(cancellationToken);
        var totalOccurrences = await tipsQuery.SumAsync(t => (int?)t.OccurrenceCount, cancellationToken) ?? 0;
        var newTips = await tipsQuery.CountAsync(t => t.ReviewStatus == "new", cancellationToken);
        var needsReview = await tipsQuery.CountAsync(t => t.ReviewStatus != "ignored" && t.ReviewStatus != "fixed-in-product", cancellationToken);
        var approvedTips = await tipsQuery.CountAsync(t => t.Approved, cancellationToken);
        var sharedTips = await tipsQuery.CountAsync(t => t.SharedWithClients, cancellationToken);
        var totalUpvotes = await tipsQuery.SumAsync(t => (int?)t.Upvotes, cancellationToken) ?? 0;
        var upvotedUsageEvents = await eventsQuery.CountAsync(e => e.EventName == "llm_tip_upvoted", cancellationToken);

        var topCategoryRows = await tipsQuery
            .GroupBy(t => t.Category ?? "(none)")
            .Select(g => new { Name = g.Key, Count = g.Sum(t => t.OccurrenceCount) })
            .OrderByDescending(g => g.Count)
            .ThenBy(g => g.Name)
            .Take(10)
            .ToListAsync(cancellationToken);
        var topCategories = topCategoryRows
            .Select(g => new LlmTipFeedbackGroupedCount(g.Name, g.Count))
            .ToList();

        var topVersionRows = await tipsQuery
            .GroupBy(t => t.AppVersion ?? "(unknown)")
            .Select(g => new { Name = g.Key, Count = g.Sum(t => t.OccurrenceCount) })
            .OrderByDescending(g => g.Count)
            .ThenBy(g => g.Name)
            .Take(10)
            .ToListAsync(cancellationToken);
        var topVersions = topVersionRows
            .Select(g => new LlmTipFeedbackGroupedCount(g.Name, g.Count))
            .ToList();

        var topSeverityRows = await tipsQuery
            .GroupBy(t => t.Severity ?? "(unknown)")
            .Select(g => new { Name = g.Key, Count = g.Sum(t => t.OccurrenceCount) })
            .OrderByDescending(g => g.Count)
            .ThenBy(g => g.Name)
            .Take(10)
            .ToListAsync(cancellationToken);
        var topSeverities = topSeverityRows
            .Select(g => new LlmTipFeedbackGroupedCount(g.Name, g.Count))
            .ToList();

        var dailyTipRows = await tipsQuery
            .GroupBy(t => t.LastSeenAtUtc.Date)
            .Select(g => new { Date = g.Key, Tips = g.Count() })
            .ToListAsync(cancellationToken);
        var dailyEventRows = await eventsQuery
            .GroupBy(e => e.CreatedAtUtc.Date)
            .Select(g => new { Date = g.Key, Events = g.Count() })
            .ToListAsync(cancellationToken);
        var dailyEventsByDate = dailyEventRows.ToDictionary(x => x.Date, x => x.Events);
        var dailyTips = dailyTipRows
            .Select(t => new LlmTipFeedbackDailyCount(t.Date, t.Tips, dailyEventsByDate.GetValueOrDefault(t.Date)))
            .OrderBy(d => d.Date)
            .ToList();

        foreach (var eventOnly in dailyEventRows.Where(e => dailyTipRows.All(t => t.Date != e.Date)))
            dailyTips.Add(new LlmTipFeedbackDailyCount(eventOnly.Date, 0, eventOnly.Events));

        dailyTips = dailyTips.OrderBy(d => d.Date).ToList();
        var topTipsByOccurrences = await ProjectTipList(
                tipsQuery.OrderByDescending(t => t.OccurrenceCount).ThenByDescending(t => t.LastSeenAtUtc))
            .Take(10)
            .ToListAsync(cancellationToken);
        var topTipsByUpvotes = await ProjectTipList(
                tipsQuery.OrderByDescending(t => t.Upvotes).ThenByDescending(t => t.OccurrenceCount))
            .Take(10)
            .ToListAsync(cancellationToken);
        var tips = await ProjectTipList(ApplyAdminSort(tipsQuery, query.SortBy, query.SortDir))
            .Take(Math.Clamp(query.Take > 0 ? query.Take : query.Limit, 1, 500))
            .ToListAsync(cancellationToken);

        return new LlmTipFeedbackAdminOverview(
            totalTips,
            totalEvents,
            totalOccurrences,
            newTips,
            needsReview,
            approvedTips,
            totalUpvotes,
            upvotedUsageEvents,
            topCategories,
            topVersions,
            topSeverities,
            topTipsByOccurrences,
            topTipsByUpvotes,
            dailyTips,
            tips,
            sharedTips);
    }

    /// <summary>
    /// Returns one page of the filtered admin tip list (sharing filter included, TKT-003574) with the total count.
    /// </summary>
    /// <param name="query">Filters, sort and paging; the page size is clamped to 1..200.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <exception cref="ArgumentException"><c>FromUtc</c> after <c>ToUtc</c>.</exception>
    public async Task<LlmTipFeedbackPagedResult<LlmTipFeedbackTipListItem>> ListAdminTipsAsync(
        LlmTipFeedbackAdminQuery query,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var period = BuildPeriod(query);
        var filtered = ApplyAdminFilters(db.LlmTipFeedbackTips.AsNoTracking(), query, period.FromUtc, period.ToUtc);
        var total = await filtered.CountAsync(cancellationToken);
        var limit = Math.Clamp(query.Limit > 0 ? query.Limit : query.Take, 1, 200);
        var offset = Math.Max(0, query.Offset);
        var items = await ProjectTipList(ApplyAdminSort(filtered, query.SortBy, query.SortDir))
            .Skip(offset)
            .Take(limit)
            .ToListAsync(cancellationToken);

        return new LlmTipFeedbackPagedResult<LlmTipFeedbackTipListItem>(total, limit, offset, items);
    }

    /// <summary>
    /// Returns the full anonymized detail of one tip for the administration screen, with its sharing journal
    /// (newest first, TKT-003574), or null when no tip has this identifier.
    /// </summary>
    /// <param name="id">Tip UUID.</param>
    /// <param name="cancellationToken">Cancels both database reads.</param>
    public async Task<LlmTipFeedbackTipDetail?> GetTipDetailAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var detail = await db.LlmTipFeedbackTips
            .AsNoTracking()
            .Where(t => t.Id == id)
            .Select(t => new LlmTipFeedbackTipDetail(
                t.Id,
                t.ContentHash,
                t.Category,
                t.Title,
                t.Description,
                t.Severity,
                t.Confidence,
                t.Approved,
                t.Upvotes,
                t.OccurrenceCount,
                t.FirstSeenAtUtc,
                t.LastSeenAtUtc,
                t.SubmittedAtUtc,
                t.ReviewStatus,
                t.AppName,
                t.ProductId,
                t.AppVersion,
                t.LicenseEdition,
                t.RequestSource,
                t.RuntimeMode,
                t.UiMode,
                t.PayloadJson,
                t.BugTraceTicketRef,
                t.SharedWithClients,
                t.SharingChangedAtUtc,
                t.SharingChangedBy,
                null))
            .FirstOrDefaultAsync(cancellationToken);
        return detail == null ? null : await WithSharingDecisionsAsync(db, detail, cancellationToken);
    }

    /// <summary>
    /// Returns the detail of one tip found by UUID or exact content hash, restricted to <paramref name="productId"/>
    /// when given, with its sharing journal (TKT-003574); null when nothing matches or the lookup is blank.
    /// </summary>
    /// <param name="idOrContentHash">Tip UUID, or content hash compared ordinally after trimming (as stored).</param>
    /// <param name="productId">Product the analytics key may reach; null for an administrator screen.</param>
    /// <param name="cancellationToken">Cancels the database reads.</param>
    public async Task<LlmTipFeedbackTipDetail?> GetTipDetailAsync(
        string idOrContentHash,
        Guid? productId,
        CancellationToken cancellationToken = default)
    {
        var lookup = Trim(idOrContentHash, 128);
        if (string.IsNullOrWhiteSpace(lookup))
            return null;

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.LlmTipFeedbackTips.AsNoTracking();
        if (productId.HasValue)
            query = query.Where(t => t.ProductId == productId);

        if (Guid.TryParse(lookup, out var id))
            query = query.Where(t => t.Id == id);
        else
            query = query.Where(t => t.ContentHash == lookup);

        var detail = await ProjectTipDetail(query).FirstOrDefaultAsync(cancellationToken);
        return detail == null ? null : await WithSharingDecisionsAsync(db, detail, cancellationToken);
    }

    /// <summary>
    /// Publishes a tip to every client (<paramref name="shared"/> true) or retracts it (false), as an administrator
    /// decision journaled in <c>LlmTipFeedbackSharingDecisions</c> (TKT-003574). Used by the administration screen, the
    /// admin API and, through that API, the MCP.
    /// </summary>
    /// <param name="id">Tip UUID; takes precedence over <paramref name="contentHash"/>.</param>
    /// <param name="contentHash">Exact stored content hash (trimmed, ordinal), used when <paramref name="id"/> is null.</param>
    /// <param name="productId">Product the caller may reach; null only for the administration screen.</param>
    /// <param name="shared">Requested state.</param>
    /// <param name="reason">Operator reason, trimmed; mandatory for a retraction, at most 1000 characters.</param>
    /// <param name="decidedBy">Server-built actor (<c>admin-ui:&lt;user&gt;</c> or <c>analytics-key:&lt;id&gt;</c>), never a secret.</param>
    /// <param name="channel"><c>admin-ui</c>, <c>api</c> or <c>mcp</c>, compared case-insensitively then stored lower-case.</param>
    /// <param name="callerIp">Caller address for API and MCP calls; null from the screen.</param>
    /// <param name="cancellationToken">Cancels the read and the write.</param>
    /// <returns>
    /// The resulting state, with <c>Changed</c> false when the tip already had the requested state (nothing written,
    /// no journal row: repeating a decision is harmless); null when no tip matches inside the product scope.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// No identifier, unknown channel, blank actor, reason longer than 1000 characters, or retraction without a reason.
    /// Validation happens before any database access, so nothing is written.
    /// </exception>
    /// <remarks>
    /// Only this method writes the sharing columns; ingestion never does, so a client can neither publish a tip (its
    /// local approval is the informational <c>Approved</c> flag) nor undo a retraction. The read and the write use
    /// the tracked entity: two concurrent opposite decisions both land in the journal and the last one wins, which
    /// the journal shows in order. A retraction is refused without a reason even when the tip is not shared, so the
    /// rule does not depend on a state the caller may not have seen.
    /// </remarks>
    public async Task<LlmTipFeedbackSharingResult?> SetSharingAsync(
        Guid? id,
        string? contentHash,
        Guid? productId,
        bool shared,
        string? reason,
        string decidedBy,
        string channel,
        string? callerIp,
        CancellationToken cancellationToken = default)
    {
        if (!id.HasValue && string.IsNullOrWhiteSpace(contentHash))
            throw new ArgumentException("id or contentHash is required.");
        var normalizedChannel = (channel ?? string.Empty).Trim().ToLowerInvariant();
        if (normalizedChannel is not ("admin-ui" or "api" or "mcp"))
            throw new ArgumentException("channel must be admin-ui, api or mcp.");
        var actor = Trim(decidedBy, 160);
        if (string.IsNullOrWhiteSpace(actor))
            throw new ArgumentException("decidedBy is required.");
        var normalizedReason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim();
        if (normalizedReason is { Length: > MaxSharingReasonLength })
            throw new ArgumentException($"reason must not exceed {MaxSharingReasonLength} characters.");
        if (!shared && normalizedReason == null)
            throw new ArgumentException("reason is required to retract a shared tip.");

        var normalizedHash = Trim(contentHash, 128);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.LlmTipFeedbackTips.AsQueryable();
        if (productId.HasValue)
            query = query.Where(t => t.ProductId == productId);

        var tip = id.HasValue
            ? await query.FirstOrDefaultAsync(t => t.Id == id.Value, cancellationToken)
            : await query.FirstOrDefaultAsync(t => t.ContentHash == normalizedHash, cancellationToken);
        if (tip == null)
            return null;

        if (tip.SharedWithClients == shared)
        {
            return new LlmTipFeedbackSharingResult(
                tip.Id, tip.ContentHash, tip.SharedWithClients, Changed: false, tip.SharingChangedAtUtc, tip.SharingChangedBy);
        }

        var now = DateTime.UtcNow;
        tip.SharedWithClients = shared;
        tip.SharingChangedAtUtc = now;
        tip.SharingChangedBy = actor;
        db.LlmTipFeedbackSharingDecisions.Add(new LlmTipFeedbackSharingDecision
        {
            TipId = tip.Id,
            Action = shared ? LlmTipFeedbackSharingDecision.SharedAction : LlmTipFeedbackSharingDecision.RetractedAction,
            Reason = normalizedReason,
            DecidedBy = actor,
            Channel = normalizedChannel,
            CallerIp = Trim(callerIp, 64),
            DecidedAtUtc = now
        });
        await db.SaveChangesAsync(cancellationToken);

        return new LlmTipFeedbackSharingResult(tip.Id, tip.ContentHash, shared, Changed: true, now, actor);
    }

    /// <summary>
    /// Returns the complete snapshot of the tips an administrator shared for the product named
    /// <paramref name="appName"/>, for the public read route (TKT-003574).
    /// </summary>
    /// <param name="appName">
    /// Product name, trimmed, 1 to 120 characters, matched with the same case-insensitive relational rule as ingestion
    /// (<c>lower(Name) = lower(@appName)</c>, cached by <see cref="LlmTipProductIdCache"/>).
    /// </param>
    /// <param name="category">Optional category, trimmed and compared lower-case on both sides (clients send lower-case).</param>
    /// <param name="cancellationToken">Cancels the database reads.</param>
    /// <returns>
    /// At most <see cref="MaxSharedTipsPerSnapshot"/> tips, newest decision first then by content hash so the order is
    /// stable for the ETag. An unknown product yields an empty list rather than an error, so the route does not reveal
    /// which product names exist.
    /// </returns>
    /// <exception cref="ArgumentException">Blank or longer than 120 characters <paramref name="appName"/>.</exception>
    /// <remarks>
    /// Exposes only the reviewed anonymized content (hash, category, title, description, severity, confidence, sharing
    /// instant). A tip retracted or never shared is absent. Tips not linked to a product (unknown appName at ingestion)
    /// are never exposed.
    /// </remarks>
    public async Task<IReadOnlyList<LlmTipSharedTip>> ListSharedTipsAsync(
        string? appName,
        string? category,
        CancellationToken cancellationToken = default)
    {
        var normalizedAppName = string.IsNullOrWhiteSpace(appName) ? null : appName.Trim();
        if (normalizedAppName == null || normalizedAppName.Length > 120)
            throw new ArgumentException("appName is required and must not exceed 120 characters.");
        var normalizedCategory = string.IsNullOrWhiteSpace(category) ? null : category.Trim().ToLowerInvariant();

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productId = await ResolveProductIdAsync(db, normalizedAppName, cancellationToken);
        if (!productId.HasValue)
            return [];

        var query = db.LlmTipFeedbackTips.AsNoTracking()
            .Where(t => t.ProductId == productId.Value && t.SharedWithClients);
        // Lower-casing the column keeps historical rows stored with another case; a product holds a few hundred tips
        // and the (ProductId, SharedWithClients) index narrows the rows first, so the per-row lower() stays cheap.
        if (normalizedCategory != null)
            query = query.Where(t => t.Category != null && t.Category.ToLower() == normalizedCategory);

        return await query
            .OrderByDescending(t => t.SharingChangedAtUtc)
            .ThenBy(t => t.ContentHash)
            .Take(MaxSharedTipsPerSnapshot)
            .Select(t => new LlmTipSharedTip(
                t.ContentHash,
                t.Category,
                t.Title,
                t.Description,
                t.Severity,
                t.Confidence,
                t.SharingChangedAtUtc ?? t.LastSeenAtUtc))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Adds the sharing journal of <paramref name="detail"/>'s tip, newest first, read from the same context.
    /// </summary>
    /// <param name="db">Context of the current operation.</param>
    /// <param name="detail">Projected detail without journal.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The same detail with <c>SharingDecisions</c> filled (empty when no decision was ever made).</returns>
    private static async Task<LlmTipFeedbackTipDetail> WithSharingDecisionsAsync(
        LicenseDbContext db,
        LlmTipFeedbackTipDetail detail,
        CancellationToken cancellationToken)
    {
        var decisions = await db.LlmTipFeedbackSharingDecisions.AsNoTracking()
            .Where(d => d.TipId == detail.Id)
            .OrderByDescending(d => d.DecidedAtUtc)
            .Select(d => new LlmTipFeedbackSharingDecisionItem(d.Action, d.Reason, d.DecidedBy, d.Channel, d.DecidedAtUtc))
            .ToListAsync(cancellationToken);
        return detail with { SharingDecisions = decisions };
    }

    public async Task<bool> UpdateReviewStatusAsync(
        Guid id,
        string reviewStatus,
        CancellationToken cancellationToken = default)
    {
        var normalized = Trim(reviewStatus, 80) ?? string.Empty;
        if (!ReviewStatuses.Contains(normalized, StringComparer.Ordinal))
            throw new ArgumentException("reviewStatus is not supported.");

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var tip = await db.LlmTipFeedbackTips.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
        if (tip == null)
            return false;

        tip.ReviewStatus = normalized;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> UpdateReviewStatusAsync(
        Guid? id,
        string? contentHash,
        Guid? productId,
        string reviewStatus,
        CancellationToken cancellationToken = default)
    {
        var normalized = Trim(reviewStatus, 80) ?? string.Empty;
        if (!ReviewStatuses.Contains(normalized, StringComparer.Ordinal))
            throw new ArgumentException("reviewStatus is not supported.");
        if (!id.HasValue && string.IsNullOrWhiteSpace(contentHash))
            throw new ArgumentException("id or contentHash is required.");

        var normalizedHash = Trim(contentHash, 128);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.LlmTipFeedbackTips.AsQueryable();
        if (productId.HasValue)
            query = query.Where(t => t.ProductId == productId);

        var tip = id.HasValue
            ? await query.FirstOrDefaultAsync(t => t.Id == id.Value, cancellationToken)
            : await query.FirstOrDefaultAsync(t => t.ContentHash == normalizedHash, cancellationToken);
        if (tip == null)
            return false;

        tip.ReviewStatus = normalized;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <summary>
    /// Converts one stored LLM tip into an internal BugTrace ticket in the project of the tip's product
    /// (TKT-003093), and marks the tip <c>converted-to-bugtrace</c> with the returned ticket reference.
    /// Used by the admin page and by <c>POST api/llm-tips-feedback/admin/tips/convert-to-bugtrace</c>.
    /// </summary>
    /// <remarks>
    /// Order matters and must be preserved:
    /// <list type="number">
    /// <item>A tip that already carries a ticket reference returns that reference with
    /// <c>Created = false</c>, without contacting BugTrace, even when BugTrace or the mapping is unavailable.</item>
    /// <item>The destination comes only from <see cref="LlmTipBugTraceRouting"/>; an unmapped product is
    /// refused before any provider call, never sent to the legacy SoftLicence project.</item>
    /// <item>The ticket is relayed through the dedicated, provider-verified T-IA authority with the tip
    /// identifier (lowercase D format) as idempotency key, so two concurrent conversions of the same tip
    /// (double click, page plus API) replay one provider ticket instead of creating two.</item>
    /// </list>
    /// The local status is saved only after the provider returned a reference. If the call fails after
    /// BugTrace committed the ticket, the tip stays unconverted and a retry replays the same ticket
    /// through the idempotency key.
    /// </remarks>
    /// <param name="id">Tip identifier; takes precedence over <paramref name="contentHash"/>.</param>
    /// <param name="contentHash">Tip content hash, trimmed to 128 characters and compared exactly.</param>
    /// <param name="productId">When set, restricts the lookup to that product (product-scoped API keys).</param>
    /// <param name="priority">Optional BugTrace priority (LOW, NORMAL, HIGH, CRITICAL); otherwise derived from severity.</param>
    /// <param name="type">Optional BugTrace type (BUG, IMPROVEMENT, TASK); otherwise IMPROVEMENT.</param>
    /// <param name="cancellationToken">Cancels database work and the provider call; a provider mutation may still commit.</param>
    /// <returns>The conversion result, or null when no matching tip exists.</returns>
    /// <exception cref="ArgumentException">Neither <paramref name="id"/> nor <paramref name="contentHash"/> was supplied.</exception>
    /// <exception cref="LlmTipBugTraceProjectNotConfiguredException">No BugTrace project is configured for the tip's product.</exception>
    /// <exception cref="InvalidOperationException">The BugTrace proxy or its T-IA authority is not configured, or BugTrace returned no reference.</exception>
    /// <exception cref="BugTraceTiaAuthorityException">The T-IA token's project identity could not be verified.</exception>
    /// <exception cref="HttpRequestException">BugTrace rejected the ticket or could not be reached.</exception>
    public async Task<LlmTipFeedbackBugTraceConversionResult?> ConvertToBugTraceAsync(
        Guid? id,
        string? contentHash,
        Guid? productId,
        string? priority = null,
        string? type = null,
        CancellationToken cancellationToken = default)
    {
        if (!id.HasValue && string.IsNullOrWhiteSpace(contentHash))
            throw new ArgumentException("id or contentHash is required.");

        var normalizedHash = Trim(contentHash, 128);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.LlmTipFeedbackTips.AsQueryable();
        if (productId.HasValue)
            query = query.Where(t => t.ProductId == productId);

        var tip = id.HasValue
            ? await query.FirstOrDefaultAsync(t => t.Id == id.Value, cancellationToken)
            : await query.FirstOrDefaultAsync(t => t.ContentHash == normalizedHash, cancellationToken);
        if (tip == null)
            return null;

        if (!string.IsNullOrWhiteSpace(tip.BugTraceTicketRef))
        {
            tip.ReviewStatus = "converted-to-bugtrace";
            await db.SaveChangesAsync(cancellationToken);
            return new LlmTipFeedbackBugTraceConversionResult(
                tip.Id,
                tip.ContentHash,
                tip.ReviewStatus,
                tip.BugTraceTicketRef,
                Created: false);
        }

        // Destination first, availability second: an unmapped product is a configuration decision the
        // operator must see as such, even while BugTrace happens to be unavailable.
        var project = _bugTraceRouting.Resolve(tip.ProductId);
        if (project == LlmTipBugTraceProject.None)
            throw new LlmTipBugTraceProjectNotConfiguredException(tip.ProductId, !_bugTraceRouting.IsValid);

        if (_bugTrace == null || !_bugTrace.IsTiaConfigured)
            throw new InvalidOperationException("BugTrace T-IA authority is not configured.");

        // Never the legacy SubmitTicketAsync: its token files tickets in the SoftLicence project (TKT-003093).
        var result = await _bugTrace.SubmitTiaTicketAsync(
            BuildBugTraceTicket(tip, priority, type),
            tip.Id.ToString("D"),
            cancellationToken);
        var ticketRef = Trim(
            TryGetJsonString(result, "ticketNumber")
                ?? TryGetJsonString(result, "number")
                ?? TryGetJsonString(result, "id"),
            32);
        if (string.IsNullOrWhiteSpace(ticketRef))
            throw new InvalidOperationException("BugTrace did not return a ticket reference.");

        tip.ReviewStatus = "converted-to-bugtrace";
        tip.BugTraceTicketRef = ticketRef;
        await db.SaveChangesAsync(cancellationToken);

        return new LlmTipFeedbackBugTraceConversionResult(
            tip.Id,
            tip.ContentHash,
            tip.ReviewStatus,
            ticketRef,
            Created: true);
    }

    /// <summary>
    /// Applies the admin filters to a relational query: product, last-seen window, exact category, severity, version
    /// and review status, sharing state (TKT-003574), and a case-insensitive search in title, description and hash.
    /// </summary>
    /// <param name="query">Source query, not yet filtered.</param>
    /// <param name="filters">Requested filters; null or blank values are ignored.</param>
    /// <param name="fromUtc">Inclusive lower bound on <c>LastSeenAtUtc</c>, already converted to UTC.</param>
    /// <param name="toUtc">Inclusive upper bound on <c>LastSeenAtUtc</c>, already converted to UTC.</param>
    /// <returns>The filtered query, still translated to SQL.</returns>
    private static IQueryable<LlmTipFeedbackTip> ApplyAdminFilters(
        IQueryable<LlmTipFeedbackTip> query,
        LlmTipFeedbackAdminQuery filters,
        DateTime? fromUtc,
        DateTime? toUtc)
    {
        if (filters.ProductId.HasValue)
            query = query.Where(t => t.ProductId == filters.ProductId);
        if (fromUtc.HasValue)
            query = query.Where(t => t.LastSeenAtUtc >= fromUtc.Value);
        if (toUtc.HasValue)
            query = query.Where(t => t.LastSeenAtUtc <= toUtc.Value);
        if (!string.IsNullOrWhiteSpace(filters.Category))
            query = query.Where(t => t.Category == filters.Category);
        if (!string.IsNullOrWhiteSpace(filters.Severity))
            query = query.Where(t => t.Severity == filters.Severity);
        if (!string.IsNullOrWhiteSpace(filters.AppVersion))
            query = query.Where(t => t.AppVersion == filters.AppVersion);
        if (!string.IsNullOrWhiteSpace(filters.ReviewStatus))
            query = query.Where(t => t.ReviewStatus == filters.ReviewStatus);
        if (filters.Shared.HasValue)
            query = query.Where(t => t.SharedWithClients == filters.Shared.Value);
        if (!string.IsNullOrWhiteSpace(filters.Search))
        {
            var search = filters.Search.Trim().ToLower();
            query = query.Where(t =>
                t.Title.ToLower().Contains(search)
                || (t.Description != null && t.Description.ToLower().Contains(search))
                || t.ContentHash.ToLower().Contains(search));
        }

        return query;
    }

    private static IQueryable<LlmTipFeedbackEvent> ApplyEventFilters(
        IQueryable<LlmTipFeedbackEvent> query,
        LlmTipFeedbackAdminQuery filters,
        DateTime? fromUtc,
        DateTime? toUtc)
    {
        if (filters.ProductId.HasValue)
            query = query.Where(e => e.ProductId == filters.ProductId);
        if (fromUtc.HasValue)
            query = query.Where(e => e.CreatedAtUtc >= fromUtc.Value);
        if (toUtc.HasValue)
            query = query.Where(e => e.CreatedAtUtc <= toUtc.Value);
        if (!string.IsNullOrWhiteSpace(filters.Category))
            query = query.Where(e => e.Category == filters.Category);
        if (!string.IsNullOrWhiteSpace(filters.AppVersion))
            query = query.Where(e => e.AppVersion == filters.AppVersion);

        return query;
    }

    private static IQueryable<LlmTipFeedbackTip> ApplyAdminSort(
        IQueryable<LlmTipFeedbackTip> query,
        string? sortBy,
        string? sortDir)
    {
        var descending = !string.Equals(sortDir, "asc", StringComparison.OrdinalIgnoreCase);
        return (sortBy?.ToLowerInvariant(), descending) switch
        {
            ("lastseen" or "lastseenatutc", true) => query.OrderByDescending(t => t.LastSeenAtUtc).ThenByDescending(t => t.OccurrenceCount),
            ("lastseen" or "lastseenatutc", false) => query.OrderBy(t => t.LastSeenAtUtc).ThenBy(t => t.OccurrenceCount),
            ("firstseen" or "firstseenatutc", true) => query.OrderByDescending(t => t.FirstSeenAtUtc).ThenByDescending(t => t.OccurrenceCount),
            ("firstseen" or "firstseenatutc", false) => query.OrderBy(t => t.FirstSeenAtUtc).ThenBy(t => t.OccurrenceCount),
            ("created" or "createdat" or "createdatutc", true) => query.OrderByDescending(t => t.CreatedAtUtc).ThenByDescending(t => t.OccurrenceCount),
            ("created" or "createdat" or "createdatutc", false) => query.OrderBy(t => t.CreatedAtUtc).ThenBy(t => t.OccurrenceCount),
            ("upvotes", true) => query.OrderByDescending(t => t.Upvotes).ThenByDescending(t => t.OccurrenceCount),
            ("upvotes", false) => query.OrderBy(t => t.Upvotes).ThenBy(t => t.OccurrenceCount),
            ("title", true) => query.OrderByDescending(t => t.Title).ThenByDescending(t => t.OccurrenceCount),
            ("title", false) => query.OrderBy(t => t.Title).ThenByDescending(t => t.OccurrenceCount),
            ("occurrencecount" or "occurrences", false) => query.OrderBy(t => t.OccurrenceCount).ThenBy(t => t.LastSeenAtUtc),
            _ => query.OrderByDescending(t => t.OccurrenceCount).ThenByDescending(t => t.LastSeenAtUtc)
        };
    }

    /// <summary>Projects tips to admin list items in SQL, sharing state included (TKT-003574).</summary>
    /// <param name="query">Filtered and sorted tip query.</param>
    private static IQueryable<LlmTipFeedbackTipListItem> ProjectTipList(IQueryable<LlmTipFeedbackTip> query)
    {
        return query.Select(t => new LlmTipFeedbackTipListItem(
            t.Id,
            t.ContentHash,
            t.ProductId,
            t.AppName,
            t.Category,
            t.Title,
            t.Severity,
            t.Confidence,
            t.Approved,
            t.Upvotes,
            t.OccurrenceCount,
            t.FirstSeenAtUtc,
            t.LastSeenAtUtc,
            t.ReviewStatus,
            t.AppVersion,
            t.LicenseEdition,
            t.RequestSource,
            t.RuntimeMode,
            t.UiMode,
            t.BugTraceTicketRef,
            t.SharedWithClients,
            t.SharingChangedAtUtc));
    }

    /// <summary>
    /// Projects tips to admin details in SQL with the sharing state; the journal is added afterwards by
    /// <see cref="WithSharingDecisionsAsync"/> because it is a separate table.
    /// </summary>
    /// <param name="query">Tip query narrowed to the requested tip.</param>
    private static IQueryable<LlmTipFeedbackTipDetail> ProjectTipDetail(IQueryable<LlmTipFeedbackTip> query)
    {
        return query.Select(t => new LlmTipFeedbackTipDetail(
            t.Id,
            t.ContentHash,
            t.Category,
            t.Title,
            t.Description,
            t.Severity,
            t.Confidence,
            t.Approved,
            t.Upvotes,
            t.OccurrenceCount,
            t.FirstSeenAtUtc,
            t.LastSeenAtUtc,
            t.SubmittedAtUtc,
            t.ReviewStatus,
            t.AppName,
            t.ProductId,
            t.AppVersion,
            t.LicenseEdition,
            t.RequestSource,
            t.RuntimeMode,
            t.UiMode,
            t.PayloadJson,
            t.BugTraceTicketRef,
            t.SharedWithClients,
            t.SharingChangedAtUtc,
            t.SharingChangedBy,
            null));
    }

    private static object BuildBugTraceTicket(LlmTipFeedbackTip tip, string? priority, string? type)
    {
        return new
        {
            version = Trim(tip.AppVersion, 64) ?? "main",
            type = NormalizeBugTraceType(type),
            priority = NormalizeBugTracePriority(priority, tip.Severity),
            title = $"LLM tip review: {Trim(tip.Title, 180)}",
            description = BuildBugTraceDescription(tip),
            reporterEmail = "internal@feelautom.local",
            isInternal = true,
            tags = BuildBugTraceTags(tip)
        };
    }

    private static string BuildBugTraceDescription(LlmTipFeedbackTip tip)
    {
        return string.Join(Environment.NewLine, new[]
        {
            "Anonymized LLM Tips feedback item promoted from the SoftLicence admin inbox.",
            string.Empty,
            $"Title: {tip.Title}",
            $"Description: {tip.Description ?? "-"}",
            $"Category: {tip.Category ?? "-"}",
            $"Severity: {tip.Severity ?? "-"}",
            $"Confidence: {tip.Confidence ?? "-"}",
            $"Approved: {tip.Approved}",
            $"Upvotes: {tip.Upvotes}",
            $"Occurrences: {tip.OccurrenceCount}",
            $"FirstSeenAtUtc: {tip.FirstSeenAtUtc:O}",
            $"LastSeenAtUtc: {tip.LastSeenAtUtc:O}",
            $"SubmittedAtUtc: {(tip.SubmittedAtUtc.HasValue ? tip.SubmittedAtUtc.Value.ToString("O") : "-")}",
            $"App: {tip.AppName} {tip.AppVersion ?? "-"}",
            $"Context: license={tip.LicenseEdition ?? "-"} source={tip.RequestSource ?? "-"} runtime={tip.RuntimeMode ?? "-"} ui={tip.UiMode ?? "-"}",
            $"ContentHash: {tip.ContentHash}"
        });
    }

    private static string[] BuildBugTraceTags(LlmTipFeedbackTip tip)
    {
        var tags = new List<string>
        {
            "softlicence",
            "llm-tip-feedback",
            "product-review",
            "manual-promotion",
            $"hash:{ShortHash(tip.ContentHash)}"
        };

        AddTag(tags, tip.Category);
        AddTag(tags, tip.Severity);
        AddTag(tags, tip.AppName);
        return tags.ToArray();
    }

    private static string NormalizeBugTracePriority(string? priority, string? severity)
    {
        var candidate = Trim(priority, 20);
        if (!string.IsNullOrWhiteSpace(candidate))
        {
            var upper = candidate.ToUpperInvariant();
            if (upper is "LOW" or "NORMAL" or "HIGH" or "CRITICAL")
                return upper;
        }

        return severity?.ToLowerInvariant() switch
        {
            "critical" => "CRITICAL",
            "error" => "HIGH",
            _ => "NORMAL"
        };
    }

    private static string NormalizeBugTraceType(string? type)
    {
        var candidate = Trim(type, 20)?.ToUpperInvariant();
        return candidate is "BUG" or "IMPROVEMENT" or "TASK" ? candidate : "IMPROVEMENT";
    }

    private static void AddTag(List<string> tags, string? value)
    {
        var normalized = Trim(value, 40)?.ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(normalized))
            tags.Add(normalized);
    }

    private static string ShortHash(string hash) => hash.Length <= 12 ? hash : hash[..12];

    private static string? TryGetJsonString(JsonElement element, string propertyName)
    {
        return element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static void ValidateCommon(string appName, string schemaVersion)
    {
        if (string.IsNullOrWhiteSpace(appName))
            throw new ArgumentException("appName is required.");
        if (string.IsNullOrWhiteSpace(schemaVersion))
            throw new ArgumentException("schemaVersion is required.");
    }

    private static void ValidatePayload(object payload)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        if (EmailRegex.IsMatch(json)
            || WindowsPathRegex.IsMatch(json)
            || PrivateIpRegex.IsMatch(json)
            || LongSecretLikeRegex.IsMatch(json))
        {
            throw new ArgumentException("payload contains sensitive raw data.");
        }

        using var document = JsonDocument.Parse(json);
        ValidateElement(document.RootElement);
    }

    private static void ValidateElement(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    var normalizedName = property.Name.Replace("-", "", StringComparison.Ordinal)
                        .Replace("_", "", StringComparison.Ordinal)
                        .ToLowerInvariant();
                    if (SensitiveKeyFragments.Any(fragment => normalizedName.Contains(fragment, StringComparison.Ordinal)))
                        throw new ArgumentException("payload contains sensitive raw data.");
                    ValidateElement(property.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    ValidateElement(item);
                break;
            case JsonValueKind.String:
                var value = element.GetString();
                if (!string.IsNullOrWhiteSpace(value)
                    && (EmailRegex.IsMatch(value)
                        || WindowsPathRegex.IsMatch(value)
                        || PrivateIpRegex.IsMatch(value)
                        || LongSecretLikeRegex.IsMatch(value)))
                {
                    throw new ArgumentException("payload contains sensitive raw data.");
                }
                break;
        }
    }

    /// <summary>
    /// Returns the product whose name matches <paramref name="appName"/> case-insensitively, or null,
    /// answering from <see cref="LlmTipProductIdCache"/> when it can (TKT-003573).
    /// </summary>
    /// <param name="db">Context of the current operation, used only on a cache miss.</param>
    /// <param name="appName">Client-supplied application name, already validated as non-blank.</param>
    /// <param name="cancellationToken">Cancels the database lookup on a cache miss.</param>
    /// <returns>The product identifier, or null when no product has that name.</returns>
    /// <remarks>
    /// The relational predicate <c>lower(Name) = lower(@appName)</c> remains the only matching rule;
    /// the cache is keyed by the raw name and stores that answer, null included. Concurrent misses for
    /// the same name may each query once; that is harmless and avoids a lock on the ingestion path.
    /// </remarks>
    private async Task<Guid?> ResolveProductIdAsync(
        LicenseDbContext db,
        string appName,
        CancellationToken cancellationToken)
    {
        if (_productIdCache.TryGet(appName, out var cachedProductId))
            return cachedProductId;

        var productId = await db.Products.AsNoTracking()
            .Where(p => p.Name.ToLower() == appName.ToLower())
            .Select(p => (Guid?)p.Id)
            .FirstOrDefaultAsync(cancellationToken);
        _productIdCache.Set(appName, productId);
        return productId;
    }

    private static string? FirstValue(Dictionary<string, string> values, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (values.TryGetValue(key, out var value))
                return Trim(value, 120);
        }

        return null;
    }

    private static string? Trim(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
    }

    private static (DateTime? FromUtc, DateTime? ToUtc) BuildPeriod(LlmTipFeedbackAdminQuery query)
    {
        var fromUtc = query.FromUtc.HasValue ? ToUtc(query.FromUtc.Value) : (DateTime?)null;
        var toUtc = query.ToUtc.HasValue ? ToUtc(query.ToUtc.Value) : (DateTime?)null;
        if (!fromUtc.HasValue && query.Days > 0)
            fromUtc = DateTime.UtcNow.AddDays(-Math.Clamp(query.Days, 1, 365));
        if (fromUtc.HasValue && toUtc.HasValue && fromUtc > toUtc)
            throw new ArgumentException("fromUtc must be before toUtc.");

        return (fromUtc, toUtc);
    }

    private static DateTime ToUtc(DateTime value)
    {
        return value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };
    }
}
