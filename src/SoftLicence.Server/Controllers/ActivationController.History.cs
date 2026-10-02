using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Records legacy activation observations without strengthening existing hardware locks or changing licensing predicates.</summary>
public partial class ActivationController
{
    /// <summary>Business checkpoint created only after the legacy path's existing submitted/canonical hardware locks.</summary>
    private const string LegacyHistorySavepoint = "legacy_decision_business";

    /// <summary>Commits one generic offline refusal using only a previously authorized snapshot and a new private history context.</summary>
    /// <remarks>No activation business transaction has begun. Existing ban-expiry maintenance may already have committed independently and is neither rolled back nor repeated. Five seconds linked to host shutdown, independent of client abort after decision, cover this history-only transaction. Failure returns the existing redacted500; lost commit acknowledgement is indeterminate. No key, request code, inferred HWID or finer refusal reason is stored.</remarks>
    private async Task<IActionResult> PersistOfflinePrecheckRefusalAsync(LicenseDecisionSnapshot snapshot, string submittedHardwareId)
    {
        using var finalization = CancellationTokenSource.CreateLinkedTokenSource(_legacyApplicationStopping);
        finalization.CancelAfter(TimeSpan.FromSeconds(5));
        var committing = false;
        try
        {
            var factory = HttpContext.RequestServices.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
            await using var historyDb = await factory.CreateDbContextAsync(finalization.Token);
            await using var transaction = await ProductHardwareSeatLockAuthority.BeginReadCommittedTransactionAsync(historyDb, finalization.Token);
            var operationId = Guid.NewGuid().ToString("D");
            var correlation = HttpContext.TraceIdentifier is { Length: > 0 and <= 200 } value
                && !value.Any(char.IsControl) ? value : null;
            var decision = new LicenseDecisionHistory(1, "offline_precheck", operationId, "refused",
                "offline_activation_denied", null, 403, submittedHardwareId, null, null, null,
                snapshot, null, correlation);
            await LicenseDecisionHistoryWriter.AddAsync(historyDb, decision, "legacy_request", operationId,
                DateTimeOffset.UtcNow, finalization.Token);
            await historyDb.SaveChangesAsync(finalization.Token);
            committing = true;
            if (transaction != null) await transaction.CommitAsync(finalization.Token);
            return OfflineActivationDenied();
        }
        catch (Exception)
        {
            _logger.LogError("LicenseDecisionPersistenceFailed Phase=offline_precheck ObservedBusinessCode=offline_activation_denied CommitOutcome={CommitOutcome}",
                committing ? "indeterminate" : "not_confirmed");
            return StatusCode(StatusCodes.Status500InternalServerError, new { error = "offline_activation_failed" });
        }
    }

    /// <summary>Holds one independent legacy request's immutable observations and transaction ownership; never shared between HTTP requests.</summary>
    private sealed class LegacyHistoryObservation
    {
        /// <summary>Fresh server request identity; identical subsequent HTTP bodies are independent attempts.</summary>
        internal string OperationId { get; } = Guid.NewGuid().ToString("D");
        /// <summary>Frozen values last observed at an actual predicate, never read after rollback.</summary>
        internal required LicenseDecisionSnapshot Snapshot { get; set; }
        /// <summary>Caller-owned transaction disposed by ActivateCoreAsync; this scope never creates a fallback transaction.</summary>
        internal IDbContextTransaction? Transaction { get; init; }
        /// <summary>Existing validated submitted HWID, preserved exactly.</summary>
        internal required string SubmittedHardwareId { get; init; }
        /// <summary>Provider-resolved identity, or null until resolution succeeds.</summary>
        internal string? ResolvedHardwareId { get; set; }
        /// <summary>provider_direct or provider_alias, never inferred from format or IP.</summary>
        internal string? ResolutionSource { get; set; }
        /// <summary>Actual legacy or offline producer phase; Website correlation is unavailable.</summary>
        internal required string Phase { get; init; }
        /// <summary>Application version supplied to the current predicate, or null if absent.</summary>
        internal string? AppVersion { get; init; }
        /// <summary>True only after the business savepoint was created; earlier alias refusals have no SQL business effects to undo.</summary>
        internal bool HasSavepoint { get; set; }
        /// <summary>Identity of the tracked accepted event, usable for notification only after confirmed business commit.</summary>
        internal Guid? AcceptedEventId { get; set; }
    }

    /// <summary>Creates the business checkpoint after the existing hardware locks and before any legacy business write.</summary>
    private static async Task BeginLegacyHistorySavepointAsync(LegacyHistoryObservation observation)
    {
        if (observation.Transaction != null)
            await observation.Transaction.CreateSavepointAsync(LegacyHistorySavepoint);
        observation.HasSavepoint = true;
    }

    /// <summary>Captures a selected trial licence's observed active seats before its first business predicate or mutation.</summary>
    /// <remarks>The caller already holds the existing hardware lock. No global quota authority or hardware alias resolution is inferred. New server-created licences have an observed empty pre-activation set; their history is saved only with successful creation. Existing rows are read without changing the business entity graph.</remarks>
    private async Task<LegacyHistoryObservation> CaptureTrialHistoryAsync(License license,
        IDbContextTransaction? transaction, string submittedHardwareId, string? appVersion, string phase, bool newlyCreated = false)
    {
        var activeSeats = newlyCreated ? new List<LicenseSeat>() : await _db.LicenseSeats.AsNoTracking()
            .Where(row => row.LicenseId == license.Id && row.IsActive).ToListAsync(HttpContext.RequestAborted);
        var initial = new LicenseDecisionSnapshot(license.ProductId, license.Id, null, null,
            activeSeats.Count, license.MaxSeats, null, license.Type?.MaxActivationsPerDay,
            null, null, false, null, "hardware_lock_observation");
        var snapshot = LicenseDecisionHistoryWriter.WithObservedActiveSeats(initial, activeSeats, submittedHardwareId)
            with { ResolvedHardwareAlreadyActive = null };
        return new LegacyHistoryObservation
        {
            Snapshot = snapshot, Transaction = transaction, SubmittedHardwareId = submittedHardwareId,
            AppVersion = appVersion, Phase = phase
        };
    }

    /// <summary>Tracks and saves a trial acceptance only after its actual signing operation succeeded, before the existing transaction commit.</summary>
    /// <remarks>The effective signing identity is a stored licence value, not an alias or telemetry inference. Failure propagates to the producer's existing technical error path and transaction disposal; no success notification is introduced.</remarks>
    private async Task SaveTrialAcceptanceAsync(LegacyHistoryObservation observation, string? signingHardwareId)
    {
        observation.ResolvedHardwareId = string.IsNullOrEmpty(signingHardwareId) ? null : signingHardwareId;
        observation.ResolutionSource = observation.ResolvedHardwareId == null ? null : "trial_license_signing_identity";
        await AddLegacyDecisionAsync(observation, "accepted", "accepted", 200, HttpContext.RequestAborted);
        await _db.SaveChangesAsync(HttpContext.RequestAborted);
    }

    /// <summary>Enriches only the existing accepted-activation notification after confirmed commit with a bounded event link and exact observed identities.</summary>
    /// <remarks>No refusal channel or Website support code is created. Relative links require the existing authenticated administrator UI. Controls are omitted from notification display without changing stored facts; each field is limited to 200 characters. No licence key or raw request is included.</remarks>
    private static string BuildAcceptedDecisionNotificationContext(LegacyHistoryObservation observation)
    {
        if (observation.AcceptedEventId is not { } eventId) return string.Empty;
        /// <summary>Bounds one accepted-notification display value and removes line breaks without converting it into an authorization identity.</summary>
        static string Display(string? value) => value == null ? "inconnu"
            : new string(value.Where(character => !char.IsControl(character)).Take(200).ToArray());
        return $"\nDécision: accepted\nHWID soumis: {Display(observation.SubmittedHardwareId)}"
            + $"\nHWID résolu: {Display(observation.ResolvedHardwareId)}\nHWID corrélé: inconnu"
            + $"\nOccupation observée avant activation: {observation.Snapshot.ActiveSeats?.ToString() ?? "inconnue"}/{observation.Snapshot.SeatLimit?.ToString() ?? "inconnue"}"
            + $"\nObservation: {observation.Snapshot.ObservationGuarantee}"
            + $"\nOpération: {observation.OperationId}\nÉvénement: /licenses?licenseId={observation.Snapshot.LicenseId:D}#history-{eventId:D}";
    }

    /// <summary>Tracks a decision from previously captured facts without saving or changing the caller's business transaction.</summary>
    /// <remarks>Legacy has no client operation ID. Only duplicate internal writes within this scope can deduplicate; a new request always has a new identity.</remarks>
    private Task<LicenseHistory> AddLegacyDecisionAsync(LegacyHistoryObservation observation,
        string outcome, string code, int status, CancellationToken cancellationToken)
    {
        var decision = new LicenseDecisionHistory(1, observation.Phase, observation.OperationId,
            outcome, code, null, status, observation.SubmittedHardwareId, observation.ResolvedHardwareId,
            null, observation.ResolutionSource, observation.Snapshot, observation.AppVersion,
            HttpContext.TraceIdentifier is { Length: > 0 and <= 200 } correlation
                && !correlation.Any(char.IsControl) ? correlation : null);
        return LicenseDecisionHistoryWriter.AddAsync(_db, decision, "legacy_request",
            observation.OperationId, DateTimeOffset.UtcNow, cancellationToken);
    }

    /// <summary>Returns the original refusal only after its observation commits independently of rolled-back business effects.</summary>
    /// <remarks>
    /// Snapshot values were captured before calling this method; no quota/identity reread occurs here.
    /// The scoped controller context immediately exits after this return. Clear discards pending licence,
    /// seat, auto-unban, cleanup and history changes; no later business path uses detached objects. The
    /// outer caller disposes the transaction, and unrelated factory-owned telemetry contexts are untouched.
    /// Five seconds linked to application shutdown cover rollback, history save and commit. Client
    /// cancellation does not interrupt an already-decided refusal. Failure keeps the existing localized
    /// HTTP500 mapping without provisional business-error headers; commit acknowledgement loss remains
    /// indeterminate. No retry, fire-and-forget, external notification or fallback transaction is used.
    /// </remarks>
    private async Task<IActionResult> PersistLegacyRefusalAsync(LegacyHistoryObservation observation, IActionResult response)
    {
        var status = (response as IStatusCodeActionResult)?.StatusCode ?? StatusCodes.Status200OK;
        // The offline surface preserves OkObjectResult but maps all other business
        // refusals to 403. Record that existing wrapper mapping, not the core's 400;
        // never change the response merely to make it match the audit projection.
        if (observation.Phase == "offline_activation" && response is not OkObjectResult && status < 500)
            status = StatusCodes.Status403Forbidden;
        var code = HttpContext.Items[LogKeys.ResultStatusOverride] as string ?? "unknown";
        using var finalization = CancellationTokenSource.CreateLinkedTokenSource(_legacyApplicationStopping);
        finalization.CancelAfter(TimeSpan.FromSeconds(5));
        var committing = false;
        try
        {
            if (observation.Transaction != null && observation.HasSavepoint)
                await observation.Transaction.RollbackToSavepointAsync(LegacyHistorySavepoint, finalization.Token);
            _db.ChangeTracker.Clear();
            await AddLegacyDecisionAsync(observation, "refused", code, status, finalization.Token);
            await _db.SaveChangesAsync(finalization.Token);
            committing = true;
            if (observation.Transaction != null)
                await observation.Transaction.CommitAsync(finalization.Token);
            return response;
        }
        catch (Exception)
        {
            _logger.LogError("LicenseDecisionPersistenceFailed Phase=legacy_activation ObservedBusinessCode={ObservedBusinessCode} CommitOutcome={CommitOutcome}",
                code, committing ? "indeterminate" : "not_confirmed");
            HttpContext.Items.Remove(LogKeys.ResultStatusOverride);
            Response.Headers.Remove(ActivationErrorCodeHeader);
            Response.Headers.Remove(ActivationErrorContractVersionHeader);
            return StatusCode(StatusCodes.Status500InternalServerError, _localizer["Api_InternalErrorSignature"].Value);
        }
    }
}
