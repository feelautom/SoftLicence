using System.Data;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// TKT-003647: read-only answer to "which licence is attached today to this installed Runtime enrollment?".
/// The Website approval page of a WebSetup update uses it to keep the licence of the machine instead of offering
/// every licence of the account, which SoftLicence would later refuse with <c>assignment_scope_mismatch</c>.
/// The current licence is the ACTIVE row of the append-only <see cref="EnrollmentLicenseAssignment"/> ledger;
/// <see cref="DistributionInstallationBinding.LicenseId"/> and <see cref="RuntimeEnrollment.LicenseId"/> are history
/// and are never returned. SoftLicence decides nothing commercial here: which licence the account may use stays with
/// the Website.
/// </summary>
public sealed partial class RuntimeEnrollmentService
{
    /// <summary>Exact request schema of the current-assignment read.</summary>
    public const string CurrentAssignmentRequestSchema = "runtime-current-assignment-request-v1";
    /// <summary>Exact response schema of the current-assignment read.</summary>
    public const string CurrentAssignmentResponseSchema = "runtime-current-assignment-result-v1";
    /// <summary>An ACTIVE assignment exists; the response names its licence UUID and usability.</summary>
    public const string CurrentAssignmentAssigned = "assigned";
    /// <summary>ACTIVE enrollment without ACTIVE assignment nor quarantine (seat released, licence revoked, never assigned).</summary>
    public const string CurrentAssignmentUnassigned = "unassigned";
    /// <summary>ACTIVE enrollment without ACTIVE assignment whose legacy graph is quarantined for an operator.</summary>
    public const string CurrentAssignmentQuarantined = "quarantined";
    /// <summary>Every other case, answered identically so another client's enrollment is never disclosed.</summary>
    public const string CurrentAssignmentNone = "none";

    /// <summary>
    /// Returns the closed current-assignment answer of one enrollment owned by <paramref name="clientId"/>.
    /// <para>
    /// The enrollment must exist, be ACTIVE, belong to the caller and match the request product, binding,
    /// installation and key thumbprint exactly (ordinal); any difference answers <c>none</c>, the same as an unknown
    /// enrollment. Without ACTIVE assignment the answer is <c>quarantined</c> when a quarantine row exists, otherwise
    /// <c>unassigned</c>. With one ACTIVE assignment the answer is <c>assigned</c> with the licence UUID only (never
    /// its type, name or key) and <c>eligible</c> computed by
    /// <see cref="RuntimeCommercialEligibilityValidator.ClassifyLicenseAndSeat"/> and
    /// <see cref="RuntimeCommercialEligibilityValidator.ExceedsSeatCapacity"/>: key and seat state only, never the
    /// release version (the update installs another one) nor bans (decided later by hardware-authority).
    /// </para>
    /// <para>
    /// Nothing is written: no lease, quota, ledger, history or audit row. The reads run in one READ COMMITTED
    /// transaction holding the shared commercial barrier, so a relink or seat release (exclusive barrier) cannot
    /// commit between the assignment, licence and seat reads. The answer is a snapshot; the later hardware-authority
    /// step still enforces the assignment.
    /// </para>
    /// </summary>
    /// <param name="clientId">Authenticated Distribution client; must equal the enrollment owner exactly.</param>
    /// <param name="request">Closed request; see <see cref="RuntimeCurrentAssignmentRequest"/>.</param>
    /// <param name="cancellationToken">Cancels the database work; the transaction is rolled back.</param>
    /// <returns>The closed answer echoing the request identifier.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// 503 <c>runtime_enrollment_unavailable</c> when Runtime enrollment is disabled; 400 <c>invalid_request</c> for a
    /// malformed or non-canonical request; 503 <c>authority_unavailable</c> (diagnostic
    /// <c>assignment_duplicate_active</c> or <c>assignment_relation_missing</c>) for a corrupt assignment graph, which
    /// must never be reported as <c>unassigned</c>.
    /// </exception>
    public async Task<RuntimeCurrentAssignmentResponse> ResolveCurrentAssignmentAsync(
        string clientId,
        RuntimeCurrentAssignmentRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateCurrentAssignment(request);
        var requestId = validated.RequestId.ToString("D");
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        // Shared barrier before the first commercial read: writers of assignments take its exclusive counterpart,
        // so the three reads below see one consistent commercial graph.
        await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);

        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == validated.EnrollmentId, cancellationToken);
        // Exact ordinal comparisons in memory: the stored values are canonical (lowercase UUID text, exact
        // Base64Url thumbprint), so no case folding may make a different key or installation match.
        if (enrollment is null
            || !string.Equals(enrollment.State, "ACTIVE", StringComparison.Ordinal)
            || !string.Equals(enrollment.ClientId, clientId, StringComparison.Ordinal)
            || enrollment.ProductId != validated.ProductId
            || enrollment.BindingId != validated.BindingId
            || !string.Equals(enrollment.InstallationId, validated.InstallationId, StringComparison.Ordinal)
            || !string.Equals(enrollment.KeyThumbprint, validated.KeyThumbprint, StringComparison.Ordinal))
            return await FinishCurrentAssignmentAsync(transaction, CurrentAssignment(requestId, CurrentAssignmentNone),
                cancellationToken);

        var assignments = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE")
            .OrderBy(row => row.Id)
            .Take(2)
            .ToListAsync(cancellationToken);
        // Two ACTIVE rows or a dangling relation are corruption: 503 like every other assignment reader, never a
        // guess that would let the Website offer a selector the hardware step then refuses.
        if (assignments.Count > 1)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "assignment_duplicate_active");
        if (assignments.Count == 0)
        {
            var quarantined = await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                .AnyAsync(row => row.EnrollmentId == enrollment.Id, cancellationToken);
            return await FinishCurrentAssignmentAsync(transaction, CurrentAssignment(requestId,
                quarantined ? CurrentAssignmentQuarantined : CurrentAssignmentUnassigned), cancellationToken);
        }

        var assignment = assignments[0];
        var license = await db.Licenses.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == assignment.LicenseId, cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == assignment.LicenseSeatId, cancellationToken);
        if (license is null || seat is null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "assignment_relation_missing");

        var now = await DatabaseNowAsync(db, cancellationToken);
        var reason = RuntimeCommercialEligibilityValidator.ClassifyLicenseAndSeat(
            license, seat, enrollment.ProductId, now.UtcDateTime);
        if (reason is null)
        {
            var activeSeats = await db.LicenseSeats.AsNoTracking()
                .CountAsync(row => row.LicenseId == license.Id && row.IsActive, cancellationToken);
            if (RuntimeCommercialEligibilityValidator.ExceedsSeatCapacity(license, activeSeats))
                reason = RuntimeCommercialEligibilityValidator.SeatCapacityExceededReason;
        }

        // Only the opaque licence UUID leaves SoftLicence: the type, name and key are deliberately not read into the
        // response (owner decision, 12/11/2026).
        return await FinishCurrentAssignmentAsync(transaction, new RuntimeCurrentAssignmentResponse(
            CurrentAssignmentResponseSchema, CurrentAssignmentAssigned, requestId,
            license.Id.ToString("D"), reason is null, reason), cancellationToken);
    }

    /// <summary>Builds an answer without licence member (<c>unassigned</c>, <c>quarantined</c> or <c>none</c>).</summary>
    /// <param name="requestId">Canonical echo of the caller correlation identifier.</param>
    /// <param name="outcome">One of the three outcomes that carry no licence.</param>
    private static RuntimeCurrentAssignmentResponse CurrentAssignment(string requestId, string outcome) =>
        new(CurrentAssignmentResponseSchema, outcome, requestId, null, null, null);

    /// <summary>
    /// Rolls the read-only transaction back, which releases the shared barrier, and returns the answer. Rollback
    /// rather than commit states that the read never writes; it has the same effect on a transaction without writes.
    /// </summary>
    /// <param name="transaction">The transaction opened by <see cref="ResolveCurrentAssignmentAsync"/>.</param>
    /// <param name="response">Answer to return unchanged.</param>
    /// <param name="cancellationToken">Cancels the rollback round trip.</param>
    private static async Task<RuntimeCurrentAssignmentResponse> FinishCurrentAssignmentAsync(
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction,
        RuntimeCurrentAssignmentResponse response,
        CancellationToken cancellationToken)
    {
        await transaction.RollbackAsync(cancellationToken);
        return response;
    }

    /// <summary>
    /// Validates the closed request: exact schema, no unknown member, canonical lowercase "D" UUIDs (the same rule as
    /// every Runtime route, so a differently written UUID is refused instead of silently matched) and a
    /// 43-character Base64Url thumbprint kept as is (it is an opaque, case-sensitive value).
    /// </summary>
    /// <param name="request">Deserialized request body.</param>
    /// <returns>The parsed identifiers.</returns>
    /// <exception cref="RuntimeEnrollmentException">400 <c>invalid_request</c> for any violation.</exception>
    private static CurrentAssignmentValidated ValidateCurrentAssignment(RuntimeCurrentAssignmentRequest request)
    {
        if (request.ExtensionData is { Count: > 0 }
            || !string.Equals(request.Schema, CurrentAssignmentRequestSchema, StringComparison.Ordinal)
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.InstallationId, out var installationId)
            || !Base64Url43Pattern.IsMatch(request.KeyThumbprint ?? string.Empty))
            throw Invalid();
        return new CurrentAssignmentValidated(requestId, productId, enrollmentId, bindingId,
            installationId.ToString("D"), request.KeyThumbprint!);
    }

    /// <summary>Parsed current-assignment request; <paramref name="InstallationId"/> is canonical lowercase "D" text.</summary>
    /// <param name="RequestId">Caller correlation identifier.</param>
    /// <param name="ProductId">Requested product.</param>
    /// <param name="EnrollmentId">Requested enrollment.</param>
    /// <param name="BindingId">Expected historical binding of the enrollment.</param>
    /// <param name="InstallationId">Expected installation, compared ordinally with the stored canonical text.</param>
    /// <param name="KeyThumbprint">Expected key thumbprint, compared ordinally.</param>
    private sealed record CurrentAssignmentValidated(
        Guid RequestId, Guid ProductId, Guid EnrollmentId, Guid BindingId, string InstallationId, string KeyThumbprint);
}
