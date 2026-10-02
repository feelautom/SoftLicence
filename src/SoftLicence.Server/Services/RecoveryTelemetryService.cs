using System.Data;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Represents one transactional ingestion decision and its HTTP status.</summary>
public sealed record RecoveryTelemetryIngestionResult(string Code, int StatusCode);

/// <summary>
/// Persists Recovery v1 events with exact replay, monotonic sequence, closed transition, and unique terminal guarantees.
/// </summary>
public sealed class RecoveryTelemetryService
{
    private const string ProductName = "TIAConnect";
    private static long lastRetentionSweepTicks;
    private readonly LicenseDbContext db;
    private readonly TimeProvider timeProvider;

    /// <summary>Creates a scoped ingestion service over one EF unit of work.</summary>
    public RecoveryTelemetryService(LicenseDbContext db, TimeProvider timeProvider)
    {
        this.db = db;
        this.timeProvider = timeProvider;
    }

    /// <summary>
    /// Resolves the product by exact indexed name and accepts or rejects one event atomically.
    /// </summary>
    /// <param name="envelope">A field-valid, canonical Recovery v1 envelope.</param>
    /// <param name="canonicalBody">The exact canonical bytes used to derive replay identity.</param>
    /// <param name="correlationId">The server-generated correlation ID used only in the response and bounded rejection.</param>
    /// <param name="cancellationToken">Cancels database work before commit; a committed event remains durable.</param>
    public async Task<RecoveryTelemetryIngestionResult> IngestAsync(
        RecoveryTelemetryEnvelope envelope,
        ReadOnlyMemory<byte> canonicalBody,
        Guid correlationId,
        CancellationToken cancellationToken)
    {
        var product = await db.Products.SingleOrDefaultAsync(product => product.Name == ProductName, cancellationToken);
        if (product is null)
        {
            await RecordRejectionAsync(null, envelope.RecoveryRunId, envelope.EventId,
                RecoveryTelemetryCodes.ProductUnresolved, correlationId, cancellationToken);
            return new(RecoveryTelemetryCodes.ProductUnresolved, StatusCodes.Status404NotFound);
        }

        // A future event is rejected against the state visible when it arrived; it must not become valid merely by waiting behind its predecessor's lock.
        var observedLastSequence = await db.RecoveryTelemetryRuns.AsNoTracking()
            .Where(item => item.ProductId == product.Id && item.RecoveryRunId == envelope.RecoveryRunId)
            .Select(item => (int?)item.LastSequence)
            .SingleOrDefaultAsync(cancellationToken) ?? 0;
        if (envelope.Sequence > observedLastSequence + 1)
            return await RejectAfterTransactionAsync(product.Id, envelope, RecoveryTelemetryCodes.OutOfOrder, correlationId, cancellationToken);

        var isolation = db.Database.IsNpgsql() ? IsolationLevel.ReadCommitted : IsolationLevel.Serializable;
        await using var transaction = await db.Database.BeginTransactionAsync(isolation, cancellationToken);
        if (db.Database.IsNpgsql())
            await AcquirePostgreSqlLocksAsync(product.Id, envelope, cancellationToken);

        var payloadHash = Convert.ToHexStringLower(SHA256.HashData(canonicalBody.Span));
        var existingByEvent = await db.RecoveryTelemetryEvents
            .SingleOrDefaultAsync(item => item.ProductId == product.Id && item.EventId == envelope.EventId, cancellationToken);
        if (existingByEvent is not null)
        {
            var replay = IsExactReplay(existingByEvent, envelope, payloadHash);
            await transaction.CommitAsync(cancellationToken);
            return replay
                ? new(RecoveryTelemetryCodes.ExactReplay, StatusCodes.Status200OK)
                : await RejectAfterTransactionAsync(product.Id, envelope, RecoveryTelemetryCodes.IdempotencyConflict, correlationId, cancellationToken);
        }

        var existingBySequence = await db.RecoveryTelemetryEvents
            .SingleOrDefaultAsync(item => item.ProductId == product.Id
                && item.RecoveryRunId == envelope.RecoveryRunId && item.Sequence == envelope.Sequence, cancellationToken);
        if (existingBySequence is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            var code = existingBySequence.IsTerminal
                ? RecoveryTelemetryCodes.TerminalConflict
                : RecoveryTelemetryCodes.IdempotencyConflict;
            return await RejectAfterTransactionAsync(product.Id, envelope, code, correlationId, cancellationToken);
        }

        var run = await db.RecoveryTelemetryRuns
            .SingleOrDefaultAsync(item => item.ProductId == product.Id && item.RecoveryRunId == envelope.RecoveryRunId, cancellationToken);
        var expectedSequence = run is null ? 1 : run.LastSequence + 1;
        if (envelope.Sequence != expectedSequence)
        {
            var code = envelope.Sequence > expectedSequence ? RecoveryTelemetryCodes.OutOfOrder : RecoveryTelemetryCodes.IdempotencyConflict;
            await transaction.CommitAsync(cancellationToken);
            return await RejectAfterTransactionAsync(product.Id, envelope, code, correlationId, cancellationToken);
        }

        if (run?.IsTerminal == true)
        {
            await transaction.CommitAsync(cancellationToken);
            return await RejectAfterTransactionAsync(product.Id, envelope, RecoveryTelemetryCodes.TerminalConflict, correlationId, cancellationToken);
        }

        if (run is not null && envelope.Stage == "terminal" && run.LastStage == "relaunch" && envelope.Outcome != "completed")
        {
            await transaction.CommitAsync(cancellationToken);
            return await RejectAfterTransactionAsync(product.Id, envelope, RecoveryTelemetryCodes.TerminalConflict, correlationId, cancellationToken);
        }

        if (!RecoveryTelemetryStateMachine.IsAllowed(run, envelope))
        {
            await transaction.CommitAsync(cancellationToken);
            return await RejectAfterTransactionAsync(product.Id, envelope, RecoveryTelemetryCodes.InvalidTransition, correlationId, cancellationToken);
        }

        var receivedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        run ??= new RecoveryTelemetryRun
        {
            ProductId = product.Id,
            RecoveryRunId = envelope.RecoveryRunId,
            CreatedAtUtc = receivedAtUtc
        };
        if (db.Entry(run).State == EntityState.Detached)
            db.RecoveryTelemetryRuns.Add(run);

        var isTerminal = envelope.Stage == "terminal";
        var acceptedEvent = new RecoveryTelemetryEvent
        {
            ProductId = product.Id,
            Run = run,
            RecoveryRunId = envelope.RecoveryRunId,
            EventId = envelope.EventId,
            Sequence = envelope.Sequence,
            PayloadSha256 = payloadHash,
            OccurredAtUtc = envelope.OccurredAtUtc,
            ReceivedAtUtc = receivedAtUtc,
            ClientVersion = envelope.ClientVersion,
            ProcessRole = envelope.ProcessRole,
            Stage = envelope.Stage,
            Outcome = envelope.Outcome,
            SourceVersion = envelope.SourceVersion,
            TargetVersion = envelope.TargetVersion,
            VerifiedRestoredVersion = envelope.VerifiedRestoredVersion,
            DurationMs = envelope.DurationMs,
            ErrorCode = envelope.ErrorCode,
            MsiExitCode = envelope.MsiExitCode,
            IsTerminal = isTerminal
        };
        db.RecoveryTelemetryEvents.Add(acceptedEvent);

        run.LastSequence = envelope.Sequence;
        run.LastStage = envelope.Stage;
        run.LastOutcome = envelope.Outcome;
        run.IsTerminal = isTerminal;
        run.Status = isTerminal ? envelope.Outcome : RecoveryTelemetryStatuses.Incomplete;
        run.ErrorCode = envelope.ErrorCode;
        run.SourceVersion = envelope.SourceVersion ?? run.SourceVersion;
        run.TargetVersion = envelope.TargetVersion ?? run.TargetVersion;
        run.VerifiedRestoredVersion = envelope.VerifiedRestoredVersion ?? run.VerifiedRestoredVersion;
        run.UpdatedAtUtc = receivedAtUtc;

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        await TrySweepRetentionAsync(receivedAtUtc, cancellationToken);
        return new(RecoveryTelemetryCodes.Accepted, StatusCodes.Status201Created);
    }

    /// <summary>
    /// Persists a privacy-safe rejection independently of an aborted ingestion transaction.
    /// </summary>
    public async Task RecordRejectionAsync(Guid? productId, Guid? runId, Guid? eventId, string code, Guid correlationId, CancellationToken cancellationToken)
    {
        db.RecoveryTelemetryRejections.Add(new RecoveryTelemetryRejection
        {
            ProductId = productId,
            RecoveryRunId = runId,
            EventId = eventId,
            Code = code,
            CorrelationId = correlationId,
            ReceivedAtUtc = timeProvider.GetUtcNow().UtcDateTime
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Resolves the sole v1 product code through an exact ordinal protocol check and an index-eligible database equality predicate.
    /// </summary>
    public async Task<Guid?> ResolveProductIdAsync(string? productCode, CancellationToken cancellationToken)
    {
        if (productCode != "TIA_CONNECT")
            return null;
        return await db.Products
            .Where(product => product.Name == ProductName)
            .Select(product => (Guid?)product.Id)
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <summary>Serializes product/event and product/run identities in stable order for the current PostgreSQL transaction.</summary>
    private async Task AcquirePostgreSqlLocksAsync(Guid productId, RecoveryTelemetryEnvelope envelope, CancellationToken cancellationToken)
    {
        var lockKeys = new[]
        {
            $"recovery:event:{productId:D}:{envelope.EventId:D}",
            $"recovery:run:{productId:D}:{envelope.RecoveryRunId:D}"
        };
        foreach (var key in lockKeys.Order(StringComparer.Ordinal))
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({key}, 0))", cancellationToken);
    }

    /// <summary>Compares immutable identifiers and exact canonical-byte hash using ordinal persisted semantics.</summary>
    private static bool IsExactReplay(RecoveryTelemetryEvent existing, RecoveryTelemetryEnvelope incoming, string payloadHash) =>
        existing.RecoveryRunId == incoming.RecoveryRunId
        && existing.Sequence == incoming.Sequence
        && existing.PayloadSha256 == payloadHash;

    /// <summary>Records one bounded post-validation rejection after the ingestion transaction no longer owns mutable state.</summary>
    private async Task<RecoveryTelemetryIngestionResult> RejectAfterTransactionAsync(
        Guid productId, RecoveryTelemetryEnvelope envelope, string code, Guid correlationId, CancellationToken cancellationToken)
    {
        await RecordRejectionAsync(productId, envelope.RecoveryRunId, envelope.EventId, code, correlationId, cancellationToken);
        var status = code == RecoveryTelemetryCodes.InvalidTransition
            ? StatusCodes.Status422UnprocessableEntity
            : StatusCodes.Status409Conflict;
        return new(code, status);
    }

    /// <summary>Runs a process-bounded privacy retention sweep at most once per hour.</summary>
    private async Task TrySweepRetentionAsync(DateTime nowUtc, CancellationToken cancellationToken)
    {
        var nowTicks = nowUtc.Ticks;
        var prior = Interlocked.Read(ref lastRetentionSweepTicks);
        if (prior != 0 && nowTicks - prior < TimeSpan.FromHours(1).Ticks)
            return;
        if (Interlocked.CompareExchange(ref lastRetentionSweepTicks, nowTicks, prior) != prior)
            return;

        await db.RecoveryTelemetryRejections
            .Where(item => item.ReceivedAtUtc < nowUtc.AddDays(-7))
            .ExecuteDeleteAsync(cancellationToken);
        await db.RecoveryTelemetryRuns
            .Where(item => item.UpdatedAtUtc < nowUtc.AddDays(-30))
            .ExecuteDeleteAsync(cancellationToken);
    }
}

/// <summary>
/// Evaluates the frozen Recovery v1 predecessor grammar using only authoritative accepted state.
/// </summary>
public static class RecoveryTelemetryStateMachine
{
    /// <summary>
    /// Returns whether an event is the one allowed successor, including process-role and terminal error continuity rules.
    /// </summary>
    public static bool IsAllowed(RecoveryTelemetryRun? run, RecoveryTelemetryEnvelope next)
    {
        if (run is null)
            return next.Sequence == 1 && Is(next, "run", "started");
        if (next.Sequence != run.LastSequence + 1 || run.IsTerminal)
            return false;

        if (!IsRoleAllowed(next))
            return false;

        var allowed = (run.LastStage, run.LastOutcome) switch
        {
            ("run", "started") => IsStage(next, "preflight", "succeeded", "failed"),
            ("preflight", "succeeded") => IsStage(next, "confirmation", "accepted", "cancelled", "skipped"),
            ("preflight", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("confirmation", "accepted" or "skipped") => IsStage(next, "process_stop", "started", "skipped"),
            ("confirmation", "cancelled") => IsTerminal(next, "cancelled", run.ErrorCode),
            ("process_stop", "started") => IsStage(next, "process_stop", "succeeded", "failed"),
            ("process_stop", "succeeded" or "skipped") => IsStage(next, "backup", "started", "skipped"),
            ("process_stop", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("backup", "started") => IsStage(next, "backup", "succeeded", "failed"),
            ("backup", "succeeded" or "skipped") => IsStage(next, "elevation", "requested", "not_required"),
            ("backup", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("elevation", "requested") => IsStage(next, "elevation", "accepted", "cancelled", "failed"),
            ("elevation", "accepted" or "not_required") => IsStage(next, "elevated_preflight", "succeeded", "failed"),
            ("elevation", "cancelled") => IsTerminal(next, "cancelled", run.ErrorCode),
            ("elevation", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("elevated_preflight", "succeeded") => Is(next, "rollback", "started"),
            ("elevated_preflight", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("rollback", "started") => IsStage(next, "rollback", "succeeded", "failed"),
            ("rollback", "succeeded") => IsStage(next, "version_verification", "succeeded", "failed"),
            ("rollback", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("version_verification", "succeeded") => IsStage(next, "secure_commit", "succeeded", "failed"),
            ("version_verification", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("secure_commit", "succeeded") => IsStage(next, "relaunch", "attempted", "skipped"),
            ("secure_commit", "failed") => IsTerminal(next, "failed", run.ErrorCode),
            ("relaunch", "attempted") => IsStage(next, "relaunch", "succeeded", "failed"),
            ("relaunch", "succeeded" or "failed" or "skipped") => IsTerminal(next, "completed", null),
            _ => false
        };
        return allowed;
    }

    /// <summary>Enforces the UAC process boundary for elevation and elevated-only stages.</summary>
    private static bool IsRoleAllowed(RecoveryTelemetryEnvelope next)
    {
        if (next.Stage == "elevation" && next.Outcome is "requested" or "accepted" or "cancelled" or "failed")
            return next.ProcessRole == "unelevated";
        if (next.Stage == "elevation" && next.Outcome == "not_required") return next.ProcessRole == "elevated";
        if (next.Stage is "elevated_preflight" or "rollback" or "version_verification" or "secure_commit") return next.ProcessRole == "elevated";
        return true;
    }

    /// <summary>Matches one exact closed stage/outcome pair.</summary>
    private static bool Is(RecoveryTelemetryEnvelope next, string stage, string outcome) => next.Stage == stage && next.Outcome == outcome;
    /// <summary>Matches one exact stage and an ordinal allowlist of outcomes.</summary>
    private static bool IsStage(RecoveryTelemetryEnvelope next, string stage, params string[] outcomes) => next.Stage == stage && outcomes.Contains(next.Outcome, StringComparer.Ordinal);
    /// <summary>Matches a terminal whose error code exactly continues the immediate failed/cancelled predecessor.</summary>
    private static bool IsTerminal(RecoveryTelemetryEnvelope next, string outcome, string? priorError) => Is(next, "terminal", outcome) && next.ErrorCode == priorError;
}
