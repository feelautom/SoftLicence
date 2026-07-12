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

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IBugTraceProxyService? _bugTrace;

    public LlmTipFeedbackService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IBugTraceProxyService? bugTrace = null)
    {
        _dbFactory = dbFactory;
        _bugTrace = bugTrace;
    }

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
                null))
            .ToListAsync(cancellationToken);
    }

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
            tips);
    }

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

    public async Task<LlmTipFeedbackTipDetail?> GetTipDetailAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.LlmTipFeedbackTips
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
                t.BugTraceTicketRef))
            .FirstOrDefaultAsync(cancellationToken);
    }

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

        return await ProjectTipDetail(query).FirstOrDefaultAsync(cancellationToken);
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

    public async Task<LlmTipFeedbackBugTraceConversionResult?> ConvertToBugTraceAsync(
        Guid? id,
        string? contentHash,
        Guid? productId,
        string? priority = null,
        string? type = null,
        CancellationToken cancellationToken = default)
    {
        if (_bugTrace == null || !_bugTrace.IsConfigured)
            throw new InvalidOperationException("BugTrace proxy is not configured.");
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

        var result = await _bugTrace.SubmitTicketAsync(BuildBugTraceTicket(tip, priority, type), cancellationToken);
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
            t.BugTraceTicketRef));
    }

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
            t.BugTraceTicketRef));
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

    private static async Task<Guid?> ResolveProductIdAsync(
        LicenseDbContext db,
        string appName,
        CancellationToken cancellationToken)
    {
        return await db.Products.AsNoTracking()
            .Where(p => p.Name.ToLower() == appName.ToLower())
            .Select(p => (Guid?)p.Id)
            .FirstOrDefaultAsync(cancellationToken);
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
