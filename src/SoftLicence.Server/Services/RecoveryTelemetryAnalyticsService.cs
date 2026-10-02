using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Represents a product-scoped Recovery timeline and its authoritative derived run status.</summary>
public sealed record RecoveryTimelineResult(
    Guid RecoveryRunId,
    string Status,
    string? ErrorCode,
    string? SourceVersion,
    string? TargetVersion,
    string? VerifiedRestoredVersion,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc,
    IReadOnlyList<RecoveryTimelineEventResult> Events);

/// <summary>Represents one ordered privacy-safe event in a support timeline.</summary>
public sealed record RecoveryTimelineEventResult(
    int Sequence,
    DateTime OccurredAtUtc,
    DateTime ReceivedAtUtc,
    string ClientVersion,
    string ProcessRole,
    string Stage,
    string Outcome,
    string? SourceVersion,
    string? TargetVersion,
    string? VerifiedRestoredVersion,
    int? DurationMs,
    string? ErrorCode,
    int? MsiExitCode);

/// <summary>Represents one bounded privacy-safe ingestion rejection for support analytics.</summary>
public sealed record RecoveryRejectionResult(
    Guid? RecoveryRunId,
    Guid? EventId,
    string Code,
    Guid CorrelationId,
    DateTime ReceivedAtUtc);

/// <summary>
/// Reads Recovery v1 timelines and rejections only after a controller has resolved one authorized product.
/// </summary>
public sealed class RecoveryTelemetryAnalyticsService
{
    private readonly IDbContextFactory<LicenseDbContext> dbFactory;

    /// <summary>Creates the read-only service with a context factory suitable for MCP/API request scopes.</summary>
    public RecoveryTelemetryAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        this.dbFactory = dbFactory;
    }

    /// <summary>Returns one deterministic sequence-ordered timeline or null when the product has no matching run.</summary>
    public async Task<RecoveryTimelineResult?> GetTimelineAsync(Guid productId, Guid runId, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var run = await db.RecoveryTelemetryRuns.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ProductId == productId && item.RecoveryRunId == runId, cancellationToken);
        if (run is null)
            return null;

        var events = await db.RecoveryTelemetryEvents.AsNoTracking()
            .Where(item => item.ProductId == productId && item.RecoveryRunId == runId)
            .OrderBy(item => item.Sequence)
            .Select(item => new RecoveryTimelineEventResult(
                item.Sequence, item.OccurredAtUtc, item.ReceivedAtUtc, item.ClientVersion, item.ProcessRole,
                item.Stage, item.Outcome, item.SourceVersion, item.TargetVersion, item.VerifiedRestoredVersion,
                item.DurationMs, item.ErrorCode, item.MsiExitCode))
            .ToListAsync(cancellationToken);
        return new(run.RecoveryRunId, run.Status, run.ErrorCode, run.SourceVersion, run.TargetVersion,
            run.VerifiedRestoredVersion, run.CreatedAtUtc, run.UpdatedAtUtc, events);
    }

    /// <summary>Returns newest-first bounded rejections for one authorized product and optional exact run.</summary>
    public async Task<IReadOnlyList<RecoveryRejectionResult>> GetRejectionsAsync(
        Guid productId,
        Guid? runId,
        int take,
        CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.RecoveryTelemetryRejections.AsNoTracking().Where(item => item.ProductId == productId);
        if (runId.HasValue)
            query = query.Where(item => item.RecoveryRunId == runId.Value);
        return await query.OrderByDescending(item => item.ReceivedAtUtc).ThenByDescending(item => item.Id)
            .Take(Math.Clamp(take, 1, 200))
            .Select(item => new RecoveryRejectionResult(item.RecoveryRunId, item.EventId, item.Code, item.CorrelationId, item.ReceivedAtUtc))
            .ToListAsync(cancellationToken);
    }
}
