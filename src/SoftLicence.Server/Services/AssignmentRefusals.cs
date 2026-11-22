using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using Npgsql;

namespace SoftLicence.Server.Services;

/// <summary>
/// Names the legitimate commercial-assignment refusals that clients used to receive as a server failure
/// (TKT-004085, product decision of 20/11/2026: every legitimate refusal is named, only anti-piracy refusals stay
/// opaque). It owns the two public codes, their English messages, and the closed translation of the refusals raised
/// by the PostgreSQL assignment trigger (<c>sync_enrollment_license_assignment</c> and its wrapper) and by the
/// account relink writer (<c>relink_runtime_commercial_assignment</c>).
/// </summary>
/// <remarks>
/// <para>
/// None of these refusals is a security decision: they describe a commercial assignment graph that the server itself
/// cannot resolve (quarantined installation, missing or duplicated right) or a concurrent write. Their bounded internal
/// reason never contains hardware data, keys or customer data, so it is returned as <c>reasonCode</c> to help support.
/// </para>
/// <para>
/// String contract: the trigger offers no structured code of its own and reuses SQLSTATE 23514 and 40001, which other
/// constraints and serialization failures also use. A refusal is therefore recognised only when both the SQLSTATE and
/// the exact, ordinal, case-sensitive message text written by the migrations match a closed table; anything else is
/// left untouched and keeps its previous handling. The message texts are part of the migrations and change only with
/// a new migration, which must update this table.
/// </para>
/// </remarks>
internal static class AssignmentRefusals
{
    /// <summary>
    /// Public code for an assignment graph that only a support reconciliation can resolve. HTTP 409: the request is
    /// valid, the licence state conflicts with it, nothing was changed, and retrying does not help.
    /// </summary>
    internal const string ReconciliationRequiredCode = "assignment_reconciliation_required";

    /// <summary>
    /// Public code for a concurrent write on the same seat. HTTP 409 with <c>Retry-After</c>: nothing was changed and
    /// the same request may be sent again after <see cref="BusyRetryAfterSeconds"/>.
    /// </summary>
    internal const string BusyCode = "seat_assignment_busy";

    /// <summary>Seconds a client waits before resending a request refused with <see cref="BusyCode"/>.</summary>
    internal const int BusyRetryAfterSeconds = 5;

    /// <summary>English message of <see cref="ReconciliationRequiredCode"/>; clients render their own localized text.</summary>
    internal const string ReconciliationRequiredMessage =
        "This device's licence assignment needs a check by support before this operation can be done. " +
        "Nothing was changed. Contact support and give the reference shown with this message.";

    /// <summary>English message of <see cref="BusyCode"/>; clients render their own localized text.</summary>
    internal const string BusyMessage =
        "Another operation is changing this licence right now. Nothing was changed. Retry in a few seconds.";

    /// <summary>Exact message prefix of the trigger's unresolved-graph refusal; the suffix is the quarantine reason.</summary>
    private const string UnresolvedGraphPrefix = "unresolved commercial assignment graph: ";

    /// <summary>Exact message prefix shared by every refusal of the account relink writer.</summary>
    private const string RelinkPrefix = "runtime_commercial_relink_";

    /// <summary>
    /// Exact trigger messages mapped to their SQLSTATE, public code and bounded reason. Only
    /// <c>concurrent commercial seat claimant</c> is a real race; the other 40001 message describes a seat whose
    /// active right is unresolved, which the trigger raises as retryable but which persists after every retry.
    /// </summary>
    private static readonly FrozenDictionary<string, (string SqlState, string Code, string Reason)> TriggerMessages =
        new Dictionary<string, (string, string, string)>(StringComparer.Ordinal)
        {
            ["commercial assignment remains quarantined"] =
                (PostgresErrorCodes.CheckViolation, ReconciliationRequiredCode, "enrollment_quarantined"),
            ["terminal enrollment cannot regain commercial authority"] =
                (PostgresErrorCodes.CheckViolation, ReconciliationRequiredCode, "terminal_enrollment_regain"),
            ["terminal time precedes assignment activation"] =
                (PostgresErrorCodes.CheckViolation, ReconciliationRequiredCode, "terminal_time_invalid"),
            ["predecessor terminal time is invalid"] =
                (PostgresErrorCodes.CheckViolation, ReconciliationRequiredCode, "predecessor_terminal_time_invalid"),
            ["commercial seat has an unresolved active assignment"] =
                (PostgresErrorCodes.SerializationFailure, ReconciliationRequiredCode, "seat_assignment_unresolved"),
            ["concurrent commercial seat claimant"] =
                (PostgresErrorCodes.SerializationFailure, BusyCode, "concurrent_seat_claimant"),
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>
    /// Closed set of quarantine reasons the trigger writes after <see cref="UnresolvedGraphPrefix"/>
    /// (<c>Migrations/20260929190522_AddAssignmentEnforcementSwitch.cs</c> and
    /// <c>20261006110000_PreserveRelinkedEnrollmentAssignments.cs</c>). An unknown suffix maps to the generic
    /// <c>assignment_graph_unresolved</c> reason so that no unreviewed text is ever echoed to a client.
    /// </summary>
    private static readonly FrozenSet<string> GraphReasons = new[]
    {
        "binding_missing", "binding_mismatch", "license_missing", "license_mismatch", "seat_missing",
        "seat_mismatch", "terminal_time_invalid", "live_state_mismatch", "live_seat_ambiguous",
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Relink writer refusals mapped to the public code and HTTP status of the Runtime contract. The owner
    /// attestation refusal (<c>authority_ineligible</c>) is an anti-piracy decision of TKT-003753 and keeps the
    /// existing opaque <c>authority_ineligible</c> code without any public reason.
    /// </summary>
    private static readonly FrozenDictionary<string, (string Code, int Status)> RelinkMessages =
        new Dictionary<string, (string, int)>(StringComparer.Ordinal)
        {
            ["runtime_commercial_relink_license_ineligible"] = ("license_ineligible", StatusCodes.Status422UnprocessableEntity),
            ["runtime_commercial_relink_seat_ineligible"] = ("seat_ineligible", StatusCodes.Status422UnprocessableEntity),
            ["runtime_commercial_relink_seat_capacity_exceeded"] = ("seat_capacity_exceeded", StatusCodes.Status422UnprocessableEntity),
            ["runtime_commercial_relink_enrollment_ineligible"] = ("enrollment_inactive", StatusCodes.Status422UnprocessableEntity),
            ["runtime_commercial_relink_assignment_conflict"] = ("assignment_conflict", StatusCodes.Status409Conflict),
            ["runtime_commercial_relink_authority_ineligible"] = ("authority_ineligible", StatusCodes.Status422UnprocessableEntity),
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>
    /// Returns whether <paramref name="errorCode"/> is one of the two public assignment codes owned here, whose bounded
    /// reason and English message are returned to clients. Every other code keeps its historical body shape.
    /// </summary>
    /// <param name="errorCode">Public error code, compared ordinally.</param>
    internal static bool IsNamed(string? errorCode) =>
        string.Equals(errorCode, ReconciliationRequiredCode, StringComparison.Ordinal)
        || string.Equals(errorCode, BusyCode, StringComparison.Ordinal);

    /// <summary>
    /// Closed set of assignment-state reasons that may be published under any public code (TKT-004106, product decision of
    /// 21/11/2026: keep each route's public code and status, add a bounded reason). They describe a
    /// commercial assignment graph that support must reconcile, never a ban, a binary, an identity or a proof, so
    /// they reveal nothing an attacker could use. The plain released-seat reason <c>assignment_missing</c> is not part of
    /// it, nor the generic <c>assignment_trigger_refused</c> of an unreviewed trigger message.
    /// </summary>
    private static readonly FrozenSet<string> PublishableAssignmentReasons = new[]
        {
            "assignment_quarantined", "assignment_relation_missing", "assignment_duplicate_active",
            "assignment_scope_conflict", "assignment_graph_unresolved",
        }
        .Concat(TriggerMessages.Values.Select(mapped => mapped.Reason))
        .Concat(GraphReasons.Select(reason => "assignment_graph_" + reason))
        .ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Returns the reason a response may publish for <paramref name="errorCode"/>: the bounded reason of a named
    /// assignment code; since TKT-004106 also an assignment-state reason of <see cref="PublishableAssignmentReasons"/>
    /// under any code (for example <c>authority_unavailable</c> with <c>assignment_relation_missing</c>); otherwise
    /// <see langword="null"/>, so ban, binary, identity and commercial diagnostics stay server-side.
    /// </summary>
    /// <param name="errorCode">Public error code, compared ordinally.</param>
    /// <param name="reasonCode">Internal bounded reason carried by the exception, compared ordinally; null publishes nothing.</param>
    internal static string? PublicReasonCode(string? errorCode, string? reasonCode) =>
        reasonCode is not null && (IsNamed(errorCode) || PublishableAssignmentReasons.Contains(reasonCode))
            ? reasonCode
            : null;

    /// <summary>
    /// Returns whether <paramref name="exception"/> is a recognised assignment-trigger refusal. Controller catch-alls use
    /// it to let that refusal reach <c>ApiExceptionSafetyNetMiddleware</c>, which answers the named code, instead of
    /// turning it into <c>internal_error</c>.
    /// </summary>
    /// <param name="exception">The caught exception.</param>
    internal static bool IsTriggerRefusal(Exception exception) => TryTranslate(exception, out _);

    /// <summary>Returns the English message of a named code, or <see langword="null"/> for any other code.</summary>
    /// <param name="errorCode">Public error code, compared ordinally.</param>
    internal static string? MessageFor(string? errorCode) => errorCode switch
    {
        ReconciliationRequiredCode => ReconciliationRequiredMessage,
        BusyCode => BusyMessage,
        _ => null
    };

    /// <summary>
    /// Creates the 409 refusal for an assignment graph that needs a support reconciliation.
    /// </summary>
    /// <param name="reasonCode">Bounded internal reason, for example <c>seat_release_assignment_without_runtime</c>.</param>
    /// <returns>The refusal; callers throw it so that their transaction is rolled back and nothing is changed.</returns>
    internal static DistributionOperationException ReconciliationRequired(string reasonCode) =>
        new(ReconciliationRequiredCode, StatusCodes.Status409Conflict, reasonCode);

    /// <summary>
    /// Translates a refusal raised by the PostgreSQL assignment trigger, found anywhere in the exception chain
    /// (directly, or wrapped by EF Core in a <see cref="Microsoft.EntityFrameworkCore.DbUpdateException"/>).
    /// </summary>
    /// <param name="exception">The caught exception; <see langword="null"/> is accepted and never matches.</param>
    /// <param name="refusal">
    /// The named 409 refusal when the method returns <see langword="true"/>; the PostgreSQL exception is kept as its
    /// <see cref="Exception.InnerException"/> for logs, never for the response.
    /// </param>
    /// <returns>
    /// <see langword="true"/> only for an exact trigger message with its expected SQLSTATE. Any other exception,
    /// including a different 23514 or 40001, returns <see langword="false"/> and must keep its existing handling. An
    /// exception that is already a public refusal (<see cref="DistributionOperationException"/> or
    /// <see cref="RuntimeEnrollmentException"/>) also returns <see langword="false"/>, even when it keeps a trigger
    /// refusal as inner cause: it was classified on purpose (for example 422 <c>binding_ineligible</c> at Prepare) and
    /// must never be reclassified into a 409 by a retry wrapper, a controller or the API safety net (TKT-004106).
    /// </returns>
    internal static bool TryTranslate(Exception? exception, [NotNullWhen(true)] out DistributionOperationException? refusal)
    {
        refusal = null;
        if (exception is DistributionOperationException or RuntimeEnrollmentException)
            return false;
        var postgres = FindPostgresException(exception);
        if (postgres is null)
            return false;
        if (TriggerMessages.TryGetValue(postgres.MessageText, out var mapped))
        {
            if (!string.Equals(postgres.SqlState, mapped.SqlState, StringComparison.Ordinal))
                return false;
            refusal = new DistributionOperationException(
                mapped.Code, StatusCodes.Status409Conflict, mapped.Reason, innerException: postgres);
            return true;
        }
        if (string.Equals(postgres.SqlState, PostgresErrorCodes.CheckViolation, StringComparison.Ordinal)
            && postgres.MessageText.StartsWith(UnresolvedGraphPrefix, StringComparison.Ordinal))
        {
            var suffix = postgres.MessageText[UnresolvedGraphPrefix.Length..];
            // Echo only a reviewed quarantine reason; an unknown suffix stays generic rather than leaking text.
            refusal = new DistributionOperationException(
                ReconciliationRequiredCode, StatusCodes.Status409Conflict,
                GraphReasons.Contains(suffix) ? "assignment_graph_" + suffix : "assignment_graph_unresolved",
                innerException: postgres);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Same translation as <see cref="TryTranslate"/>, expressed in the Runtime contract exception so that Runtime
    /// controllers return the named code instead of <c>internal_error</c> or <c>authority_unavailable</c>.
    /// </summary>
    /// <param name="exception">The caught exception; <see langword="null"/> never matches.</param>
    /// <param name="refusal">The Runtime refusal (code, 409, bounded reason) when the method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> only for a recognised trigger refusal.</returns>
    internal static bool TryTranslateRuntime(Exception? exception, [NotNullWhen(true)] out RuntimeEnrollmentException? refusal)
    {
        refusal = null;
        if (!TryTranslate(exception, out var translated))
            return false;
        refusal = ToRuntime(translated);
        return true;
    }

    /// <summary>
    /// Translates one refusal of the account relink writer (<c>runtime_commercial_relink_*</c>, SQLSTATE 23514) into its
    /// named Runtime refusal. The writer's transaction statement failed, so nothing was relinked.
    /// </summary>
    /// <param name="exception">The PostgreSQL exception raised by <c>relink_runtime_commercial_assignment</c>.</param>
    /// <param name="refusal">The named refusal, carrying the exact writer message as server-only diagnostic.</param>
    /// <returns>
    /// <see langword="false"/> for any other SQLSTATE or message, including an unknown <c>runtime_commercial_relink_*</c>
    /// suffix, which the caller keeps as a 503 infrastructure outcome until it is reviewed.
    /// </returns>
    internal static bool TryTranslateRelink(PostgresException exception, [NotNullWhen(true)] out RuntimeEnrollmentException? refusal)
    {
        refusal = null;
        if (!string.Equals(exception.SqlState, PostgresErrorCodes.CheckViolation, StringComparison.Ordinal)
            || !exception.MessageText.StartsWith(RelinkPrefix, StringComparison.Ordinal)
            || !RelinkMessages.TryGetValue(exception.MessageText, out var mapped))
            return false;
        refusal = new RuntimeEnrollmentException(mapped.Code, mapped.Status, exception.MessageText, exception);
        return true;
    }

    /// <summary>
    /// Copies a named distribution refusal into the Runtime contract exception, keeping code, status, reason and the
    /// original cause.
    /// </summary>
    /// <param name="refusal">A refusal created by this class.</param>
    internal static RuntimeEnrollmentException ToRuntime(DistributionOperationException refusal) =>
        new(refusal.ErrorCode, refusal.StatusCode, refusal.ReasonCode, refusal.InnerException);

    /// <summary>
    /// Adds <c>Retry-After</c> to a response refused with <see cref="BusyCode"/>; any other code leaves the headers unchanged.
    /// </summary>
    /// <param name="response">The response being written; headers must not have been sent yet.</param>
    /// <param name="errorCode">The public error code of the refusal.</param>
    internal static void ApplyRetryAfter(HttpResponse response, string? errorCode)
    {
        if (string.Equals(errorCode, BusyCode, StringComparison.Ordinal) && !response.HasStarted)
            response.Headers.RetryAfter = BusyRetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Returns the first <see cref="PostgresException"/> of the inner-exception chain, or <see langword="null"/>.</summary>
    /// <param name="exception">The outermost exception.</param>
    private static PostgresException? FindPostgresException(Exception? exception)
    {
        for (var current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres)
                return postgres;
        return null;
    }
}
