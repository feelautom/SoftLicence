using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Persists licence-transfer observations without changing Runtime authorization, lease ownership or business replay.</summary>
public sealed partial class RuntimeEnrollmentService
{
    /// <summary>Checkpoint after existing locks and target authority checks, before source-seat mutation or encryption nonce SQL.</summary>
    private const string RuntimeHistorySavepoint = "runtime_transfer_decision_business";

    /// <summary>Checkpoint after existing source row locks and authenticated source identity, before any later transfer mutation.</summary>
    private const string RuntimeSourceHistorySavepoint = "runtime_source_decision_identity";

    /// <summary>Persists one pre-effect refusal for the established source, or for a fully validated target that replaced it.</summary>
    /// <remarks>Source facts are identity-only and omit all claimed target identifiers and HWIDs. SQL inspection proves the checkpoint follows the original locks and precedes business DML. Rollback plus terminal Clear affects only this private delegate context; the lease owns no tracked entities. Target business history uses its original later savepoint and cannot enter this handler. Five seconds linked to host shutdown cover rollback/save/commit; no fallback or internal retry follows failure or uncertain commit. Public500 from invalid target entitlement is retained, with its internal canonical refusal in ReasonCode.</remarks>
    private async Task PersistRuntimeIdentityRefusalAsync(LicenseDbContext db, RuntimeAuthorityLease lease,
        LicenseDecisionSnapshot snapshot, string phase, RuntimeWebSetupTransitionIssueRequest request,
        string clientId, string payloadDigest, string code, string? reasonCode, int status, DateTimeOffset occurredAt)
    {
        using var finalization = CancellationTokenSource.CreateLinkedTokenSource(_historyApplicationStopping);
        finalization.CancelAfter(TimeSpan.FromSeconds(5));
        var committing = false;
        try
        {
            await db.Database.CurrentTransaction!.RollbackToSavepointAsync(RuntimeSourceHistorySavepoint, finalization.Token);
            db.ChangeTracker.Clear();
            var decision = new LicenseDecisionHistory(1, phase, request.RequestId!, "refused", code, reasonCode,
                status, null, null, null, null, snapshot,
                phase == "runtime_license_transfer" ? request.TargetVersion : request.SourceVersion);
            await LicenseDecisionHistoryWriter.AddAsync(db, decision, clientId, payloadDigest, occurredAt, finalization.Token);
            await db.SaveChangesAsync(finalization.Token);
            committing = true;
            await lease.CommitAsync(finalization.Token);
        }
        catch (Exception)
        {
            _historyLogger?.LogError("LicenseDecisionPersistenceFailed Phase={Phase} ObservedBusinessCode={Code} CommitOutcome={CommitOutcome}",
                phase, code, committing ? "indeterminate" : "not_confirmed");
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                committing ? "decision_history_commit_indeterminate" : "decision_history_not_confirmed");
        }
    }

    /// <summary>Holds immutable observed target facts and the source seat's provider-validated identity for one operation only.</summary>
    /// <param name="snapshot">Loaded target licence/seat facts under the existing Runtime authority locks.</param>
    /// <param name="hardwareId">Exact source-seat identity validated through binding authority; no submitted or correlated HWID is inferred.</param>
    private sealed class RuntimeTransferHistoryObservation(LicenseDecisionSnapshot snapshot, string hardwareId)
    {
        /// <summary>Frozen predicate facts; only a later actual daily-quota query may replace its observed count.</summary>
        internal LicenseDecisionSnapshot Snapshot { get; set; } = snapshot;
        /// <summary>Exact provider source-seat identity, preserved without casing, trimming or telemetry reconstruction.</summary>
        internal string HardwareId { get; } = hardwareId;
    }

    /// <summary>Tracks an authenticated transfer decision in the caller's transaction without saving, committing or altering replay.</summary>
    /// <remarks>The request carries no submitted HWID. Only the validated source seat supplies resolved identity. Exact client/request/payload/context bytes define deduplication; occurrence time is excluded. A returned tracked event is not yet durable.</remarks>
    private static Task<LicenseHistory> AddRuntimeTransferDecisionAsync(
        LicenseDbContext db, RuntimeTransferHistoryObservation observation,
        RuntimeWebSetupTransitionIssueRequest request, string clientId, string payloadDigest,
        string outcome, string code, int status, DateTimeOffset occurredAt, CancellationToken cancellationToken)
    {
        var decision = new LicenseDecisionHistory(1, "runtime_license_transfer", request.RequestId!,
            outcome, code, null, status, null, observation.HardwareId, null, "provider_binding",
            observation.Snapshot, request.TargetVersion);
        return LicenseDecisionHistoryWriter.AddAsync(db, decision, clientId, payloadDigest, occurredAt, cancellationToken);
    }

    /// <summary>Commits only the captured refusal after undoing every transfer effect; failure never falls back to another transaction.</summary>
    /// <remarks>
    /// The savepoint precedes sourceSeat, binding/enrollment/entitlement changes, target ownership/seat,
    /// encryption nonce SQL, transition/receipt inserts and epoch updates. SQL rollback plus Clear removes
    /// saved and pending effects. This context is created inside one retry delegate and is disposed on the
    /// terminal refusal; no later branch consumes detached objects. RuntimeAuthorityLease owns only its
    /// transaction and epoch; its finally disposal does not require tracked entities. Existing lock order is
    /// unchanged. Five seconds independent of client abort but linked to host shutdown cover rollback/save/
    /// commit. Persistence faults become the existing technical503 without a retryable inner SQL exception;
    /// an uncertain commit is explicitly diagnosed, never asserted absent or retried here.
    /// </remarks>
    private async Task PersistRuntimeTransferRefusalAsync(
        LicenseDbContext db, RuntimeAuthorityLease lease, RuntimeTransferHistoryObservation observation,
        RuntimeWebSetupTransitionIssueRequest request, string clientId, string payloadDigest,
        RuntimeEnrollmentException refusal, DateTimeOffset occurredAt)
    {
        using var finalization = CancellationTokenSource.CreateLinkedTokenSource(_historyApplicationStopping);
        finalization.CancelAfter(TimeSpan.FromSeconds(5));
        var committing = false;
        try
        {
            await db.Database.CurrentTransaction!.RollbackToSavepointAsync(RuntimeHistorySavepoint, finalization.Token);
            db.ChangeTracker.Clear();
            await AddRuntimeTransferDecisionAsync(db, observation, request, clientId, payloadDigest,
                "refused", refusal.ErrorCode, refusal.StatusCode, occurredAt, finalization.Token);
            await db.SaveChangesAsync(finalization.Token);
            committing = true;
            await lease.CommitAsync(finalization.Token);
        }
        catch (Exception)
        {
            var outcome = committing ? "indeterminate" : "not_confirmed";
            _historyLogger?.LogError(
                "LicenseDecisionPersistenceFailed Phase=runtime_license_transfer ObservedBusinessCode={ObservedBusinessCode} CommitOutcome={CommitOutcome}",
                refusal.ErrorCode, outcome);
            // Preserve the established technical response and keep diagnostic state internal.
            // Omitting a SQL inner exception prevents the business retry loop from replaying
            // an operation whose history commit acknowledgement may have been lost.
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                committing ? "decision_history_commit_indeterminate" : "decision_history_not_confirmed");
        }
    }
}
