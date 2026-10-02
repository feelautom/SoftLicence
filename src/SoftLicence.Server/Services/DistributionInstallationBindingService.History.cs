using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Owns finalization history persistence only; hardware recovery diagnostics remain in their separate owner surface.</summary>
public sealed partial class DistributionInstallationBindingService
{
    /// <summary>Outer-transaction checkpoint after existing authority locks and before the first finalization SQL write.</summary>
    private const string FinalizeHistorySavepoint = "license_decision_business";

    /// <summary>Captures only the existing licence identity authenticated by the entitlement before any early business predicate.</summary>
    /// <remarks>No claimed replacement licence is consulted. Counts, limits, resolved/correlated hardware and seat facts stay unknown. The observed epoch distinguishes changed authority context without claiming quota serialization. Missing/deleted provider licences cannot own a new event.</remarks>
    private static async Task<LicenseDecisionSnapshot?> CaptureEarlyFinalizeIdentityAsync(
        LicenseDbContext db, EntitlementIdentity entitlement, Guid productId, CancellationToken cancellationToken)
    {
        if (!await db.Licenses.AsNoTracking().AnyAsync(row => row.Id == entitlement.LicenseId
            && row.ProductId == productId, cancellationToken)) return null;
        var epoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(row => row.Id == 1).Select(row => (long?)row.Epoch).SingleOrDefaultAsync(cancellationToken);
        return new(productId, entitlement.LicenseId, null, epoch, null, null, null, null,
            null, null, false, null, "authenticated_entitlement_identity_only");
    }

    /// <summary>Commits only a pre-write refusal in its healthy existing transaction, preserving the original business response when commit is confirmed.</summary>
    /// <remarks>
    /// Only the pending v1 grant-owner Add may be discarded. Other pending mutations reject this path.
    /// PostgreSQL must not yet have assigned an XID: writes, row locks, explicit XID assignment or an
    /// aborted transaction fail closed before history insertion. This conservative check never repairs
    /// an aborted transaction or falls back after a full rollback. Clear is terminal in this private
    /// context; there is no RuntimeAuthorityLease and only context/transaction disposal follows.
    /// Five seconds linked to application stopping cover all checks, history persistence and commit;
    /// client cancellation cannot erase an already captured decision. Commit errors remain indeterminate.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Pre-write safety or persistence could not be confirmed; existing redacted internal_error mapping applies.</exception>
    private async Task PersistEarlyFinalizeRefusalAsync(
        LicenseDbContext db, IDbContextTransaction? transaction, LicenseDecisionSnapshot snapshot,
        string clientId, string payloadDigest, FinalizeValidated request, DateTimeOffset now,
        DistributionOperationException refusal)
    {
        using var finalization = CancellationTokenSource.CreateLinkedTokenSource(_applicationStopping);
        finalization.CancelAfter(TimeSpan.FromSeconds(5));
        var committing = false;
        try
        {
            if (db.ChangeTracker.Entries().Any(entry =>
                entry.State is EntityState.Added or EntityState.Modified or EntityState.Deleted
                && !(entry.State == EntityState.Added && entry.Entity is DistributionGrantOwnership)))
                throw new InvalidOperationException("Early decision has pending business effects.");
            if (db.Database.IsNpgsql())
            {
                if (transaction == null || !await db.Database.SqlQueryRaw<bool>(
                    "SELECT pg_current_xact_id_if_assigned() IS NULL AS \"Value\"").SingleAsync(finalization.Token))
                    throw new InvalidOperationException("Early decision transaction is not proven write-free.");
            }
            else if (db.Database.IsRelational())
                throw new InvalidOperationException("Early decision transaction provider is unsupported.");
            db.ChangeTracker.Clear();
            var replacementCandidates = CaptureUnevaluatedReplacementCandidates(request.LicenseReplacementCandidates);
            var decision = new LicenseDecisionHistory(1, "distribution_finalize", request.RequestId,
                "refused", refusal.ErrorCode, refusal.ReasonCode, refusal.StatusCode,
                request.HardwareId, null, null, null, snapshot, request.Version,
                ReplacementCandidates: replacementCandidates,
                SelectionOutcome: replacementCandidates.Count == 0 ? "none" : "not_evaluated");
            await LicenseDecisionHistoryWriter.AddAsync(db, decision, clientId, payloadDigest, now, finalization.Token);
            await db.SaveChangesAsync(finalization.Token);
            committing = true;
            if (transaction != null) await transaction.CommitAsync(finalization.Token);
        }
        catch (Exception)
        {
            _logger.LogError("LicenseDecisionPersistenceFailed Phase=distribution_finalize_early CommitOutcome={CommitOutcome}",
                committing ? "indeterminate" : "not_confirmed");
            throw new InvalidOperationException(committing
                ? "Licence decision commit outcome is indeterminate."
                : "Licence decision persistence was not confirmed.");
        }
    }

    /// <summary>Captures only validated candidate identities before authority resolution can refuse the request.</summary>
    /// <remarks>Candidate subjects are deliberately omitted. Every submitted candidate starts as not evaluated until the later binding-selection phase records a stronger outcome.</remarks>
    private static IReadOnlyList<LicenseReplacementCandidateDecision> CaptureUnevaluatedReplacementCandidates(
        IReadOnlyList<LicenseReplacementValidated> candidates) =>
        candidates.Select(candidate => new LicenseReplacementCandidateDecision(
            candidate.SourceBindingId, candidate.SourceLicenseId, "not_evaluated", ["selection_not_reached"])).ToArray();

    /// <summary>Maps already-established finalization facts to immutable history without changing the response or reconstructing Website correlation.</summary>
    /// <remarks>All strings retain existing producer semantics. Resolved HWID comes only from the provider resolver. This only tracks an event; the caller must save and commit.</remarks>
    private static Task<LicenseHistory> AddFinalizeDecisionAsync(
        LicenseDbContext db, LicenseDecisionSnapshot snapshot, string clientId, string payloadDigest,
        FinalizeValidated request, string submittedHardwareId, HardwareAuthorityResolution authority,
        DateTimeOffset now, string outcome, string code, string? reason, int status,
        IReadOnlyList<LicenseReplacementCandidateDecision>? replacementCandidates,
        string? selectionOutcome, CancellationToken cancellationToken)
    {
        var decision = new LicenseDecisionHistory(1, "distribution_finalize", request.RequestId,
            outcome, code, reason, status, submittedHardwareId, authority.EffectiveHardwareId,
            null, authority.UsedAlias || authority.Refused ? "provider_alias" : "provider_direct", snapshot, request.Version,
            ReplacementCandidates: replacementCandidates, SelectionOutcome: selectionOutcome);
        return LicenseDecisionHistoryWriter.AddAsync(db, decision, clientId, payloadDigest, now, cancellationToken);
    }

    /// <summary>Commits only an already-captured refusal after undoing business effects in the same outer transaction.</summary>
    /// <remarks>
    /// The request-owned context is about to unwind and has no RuntimeAuthorityLease or shared owner.
    /// Clear detaches pre-savepoint reads and the pending v1 grant-ownership add, plus any saved seat,
    /// binding, entitlement, enrollment and receipt changes. No subsequent business path uses those objects:
    /// after this method the original refusal is rethrown and only transaction/context disposal remains.
    /// A five-second token covers rollback, lookup, save and commit, independent of client cancellation
    /// but linked to host shutdown. No background work or fallback transaction exists. Commit exceptions
    /// leave persistence indeterminate; they never prove absence or produce a durable-refusal claim.
    /// </remarks>
    /// <exception cref="InvalidOperationException">History persistence could not be confirmed; the controller's existing internal_error mapping applies.</exception>
    private async Task PersistFinalizeRefusalAsync(
        LicenseDbContext db, IDbContextTransaction? transaction, LicenseDecisionSnapshot snapshot,
        string clientId, string payloadDigest, FinalizeValidated request, string submittedHardwareId,
        HardwareAuthorityResolution authority, DateTimeOffset now, DistributionOperationException refusal,
        IReadOnlyList<LicenseReplacementCandidateDecision>? replacementCandidates, string? selectionOutcome)
    {
        using var finalization = CancellationTokenSource.CreateLinkedTokenSource(_applicationStopping);
        finalization.CancelAfter(TimeSpan.FromSeconds(5));
        var committing = false;
        try
        {
            if (transaction != null)
                await transaction.RollbackToSavepointAsync(FinalizeHistorySavepoint, finalization.Token);
            db.ChangeTracker.Clear();
            await AddFinalizeDecisionAsync(db, snapshot, clientId, payloadDigest, request,
                submittedHardwareId, authority, now, "refused", refusal.ErrorCode,
                refusal.ReasonCode, refusal.StatusCode, replacementCandidates, selectionOutcome, finalization.Token);
            await db.SaveChangesAsync(finalization.Token);
            committing = true;
            if (transaction != null)
                await transaction.CommitAsync(finalization.Token);
        }
        catch (Exception)
        {
            // Do not log SQL, request evidence, HWIDs or exception messages. A lost commit
            // acknowledgement is explicitly indeterminate and must be resolved by exact replay.
            _logger.LogError("LicenseDecisionPersistenceFailed Phase=distribution_finalize CommitOutcome={CommitOutcome}",
                committing ? "indeterminate" : "not_confirmed");
            throw new InvalidOperationException(committing
                ? "Licence decision commit outcome is indeterminate."
                : "Licence decision persistence was not confirmed.");
        }
    }

    /// <summary>Prevents a history insert fault from entering the existing business-receipt concurrency reload path.</summary>
    /// <remarks>Database update entries provide attribution; no SQL text or error-message matching determines behavior.</remarks>
    private static bool IsHistoryWriteFailure(Exception exception) =>
        exception is DbUpdateException update && update.Entries.Any(entry => entry.Entity is LicenseHistory);

    /// <summary>Explains candidate selection from the exact submitted identities and provider-loaded bindings.</summary>
    /// <remarks>Subject digests participate only in equality checks and are never returned. A missing selected source is an explicit rejection reason, not a guessed replacement.</remarks>
    private static IReadOnlyList<LicenseReplacementCandidateDecision> DiagnoseReplacementCandidates(
        IReadOnlyList<LicenseReplacementValidated> candidates,
        IReadOnlyList<DistributionInstallationBinding> bindings,
        IReadOnlySet<Guid> coherentReleasedBindings,
        DistributionInstallationBinding? selectedSource)
    {
        return candidates.Select(candidate =>
        {
            var binding = bindings.SingleOrDefault(row => row.Id == candidate.SourceBindingId);
            var reasons = new List<string>();
            if (binding == null) reasons.Add("source_binding_not_found_for_hardware");
            else
            {
                if (binding.LicenseId != candidate.SourceLicenseId) reasons.Add("source_license_mismatch");
                if (!string.Equals(binding.SubjectRefDigestSha256,
                    candidate.SourceSubjectRefDigestSha256, StringComparison.Ordinal))
                    reasons.Add("source_subject_mismatch");
                if (binding.State != "active" && !coherentReleasedBindings.Contains(binding.Id)
                    && !RuntimeAuthorityTransitionResolver.IsRecoverableBinding(
                        binding.State, binding.InvalidationReason))
                    reasons.Add("security_terminal_binding");
                if (selectedSource == null || selectedSource.Id != binding.Id)
                    reasons.Add("not_selected_recovery_source");
            }
            return new LicenseReplacementCandidateDecision(candidate.SourceBindingId,
                candidate.SourceLicenseId, reasons.Count == 0 ? "selected" : "rejected", reasons);
        }).ToArray();
    }
}
