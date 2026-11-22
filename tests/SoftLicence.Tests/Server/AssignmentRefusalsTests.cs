using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-004085: the closed translation table of <see cref="AssignmentRefusals"/>. These cases need no database: they
/// build <see cref="PostgresException"/> instances with the exact SQLSTATE and message text written by the migrations,
/// and prove that only those exact pairs are named while every other database error keeps its previous handling.
/// The same messages raised by the real trigger are covered by <c>NamedAssignmentRefusalPostgreSqlTests</c>.
/// </summary>
public sealed class AssignmentRefusalsTests
{
    /// <summary>Every exact trigger message maps to its public code, 409, and bounded reason.</summary>
    [Theory]
    [InlineData("23514", "commercial assignment remains quarantined", AssignmentRefusals.ReconciliationRequiredCode, "enrollment_quarantined")]
    [InlineData("23514", "terminal enrollment cannot regain commercial authority", AssignmentRefusals.ReconciliationRequiredCode, "terminal_enrollment_regain")]
    [InlineData("23514", "terminal time precedes assignment activation", AssignmentRefusals.ReconciliationRequiredCode, "terminal_time_invalid")]
    [InlineData("23514", "predecessor terminal time is invalid", AssignmentRefusals.ReconciliationRequiredCode, "predecessor_terminal_time_invalid")]
    [InlineData("40001", "commercial seat has an unresolved active assignment", AssignmentRefusals.ReconciliationRequiredCode, "seat_assignment_unresolved")]
    [InlineData("40001", "concurrent commercial seat claimant", AssignmentRefusals.BusyCode, "concurrent_seat_claimant")]
    [InlineData("23514", "unresolved commercial assignment graph: binding_mismatch", AssignmentRefusals.ReconciliationRequiredCode, "assignment_graph_binding_mismatch")]
    [InlineData("23514", "unresolved commercial assignment graph: live_state_mismatch", AssignmentRefusals.ReconciliationRequiredCode, "assignment_graph_live_state_mismatch")]
    [InlineData("23514", "unresolved commercial assignment graph: something_new", AssignmentRefusals.ReconciliationRequiredCode, "assignment_graph_unresolved")]
    public void TryTranslate_ExactTriggerMessage_IsNamed(string sqlState, string message, string code, string reason)
    {
        Assert.True(AssignmentRefusals.TryTranslate(Postgres(sqlState, message), out var refusal));
        Assert.Equal(code, refusal.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, refusal.StatusCode);
        Assert.Equal(reason, refusal.ReasonCode);
        Assert.True(AssignmentRefusals.IsNamed(refusal.ErrorCode));
        Assert.NotNull(AssignmentRefusals.MessageFor(refusal.ErrorCode));
    }

    /// <summary>
    /// A trigger message with another SQLSTATE, another check violation, a case variant, or a non-database exception
    /// is never named: SQLSTATE 23514 and 40001 are shared with other constraints and serialization failures.
    /// </summary>
    [Theory]
    [InlineData("40001", "commercial assignment remains quarantined")]
    [InlineData("23514", "concurrent commercial seat claimant")]
    [InlineData("23514", "new row for relation \"AssignmentEnforcementSettings\" violates check constraint")]
    [InlineData("40001", "could not serialize access due to concurrent update")]
    [InlineData("23514", "Commercial assignment remains quarantined")]
    [InlineData("23514", " unresolved commercial assignment graph: binding_mismatch")]
    [InlineData("P0001", "unresolved commercial assignment graph: binding_mismatch")]
    public void TryTranslate_OtherDatabaseError_IsNotNamed(string sqlState, string message)
    {
        Assert.False(AssignmentRefusals.TryTranslate(Postgres(sqlState, message), out var refusal));
        Assert.Null(refusal);
    }

    /// <summary>
    /// Review 2498: every translation keeps the original PostgreSQL exception as its inner cause, for logs only, and
    /// the Runtime copy keeps it too.
    /// </summary>
    [Fact]
    public void Translations_KeepThePostgreSqlCauseAsInnerException()
    {
        var quarantined = Postgres("23514", "commercial assignment remains quarantined");
        Assert.True(AssignmentRefusals.TryTranslate(quarantined, out var named));
        Assert.Same(quarantined, named.InnerException);
        Assert.Same(quarantined, AssignmentRefusals.ToRuntime(named).InnerException);

        var graph = Postgres("23514", "unresolved commercial assignment graph: binding_missing");
        Assert.True(AssignmentRefusals.TryTranslate(graph, out var graphRefusal));
        Assert.Same(graph, graphRefusal.InnerException);

        var relink = Postgres("23514", "runtime_commercial_relink_seat_ineligible");
        Assert.True(AssignmentRefusals.TryTranslateRelink(relink, out var relinkRefusal));
        Assert.Same(relink, relinkRefusal.InnerException);
    }

    /// <summary>A trigger refusal wrapped by EF Core at <c>SaveChanges</c> is found in the inner-exception chain.</summary>
    [Fact]
    public void TryTranslate_RefusalWrappedByDbUpdateException_IsNamed()
    {
        var wrapped = new DbUpdateException("save failed", Postgres("23514", "commercial assignment remains quarantined"));

        Assert.True(AssignmentRefusals.TryTranslate(wrapped, out var refusal));
        Assert.Equal("enrollment_quarantined", refusal.ReasonCode);
        Assert.False(AssignmentRefusals.TryTranslate(new InvalidOperationException("no database"), out _));
        Assert.False(AssignmentRefusals.TryTranslate(null, out _));
    }

    /// <summary>The Runtime translation keeps the code, the 409 status and the reason as diagnostic.</summary>
    [Fact]
    public void TryTranslateRuntime_KeepsCodeStatusAndReason()
    {
        Assert.True(AssignmentRefusals.TryTranslateRuntime(
            Postgres("40001", "concurrent commercial seat claimant"), out var refusal));
        Assert.Equal(AssignmentRefusals.BusyCode, refusal.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, refusal.StatusCode);
        Assert.Equal("concurrent_seat_claimant", refusal.DiagnosticCode);
    }

    /// <summary>
    /// Each account relink writer refusal maps to its named Runtime code; the owner attestation refusal keeps the
    /// opaque <c>authority_ineligible</c> code of TKT-003753.
    /// </summary>
    [Theory]
    [InlineData("runtime_commercial_relink_license_ineligible", "license_ineligible", StatusCodes.Status422UnprocessableEntity)]
    [InlineData("runtime_commercial_relink_seat_ineligible", "seat_ineligible", StatusCodes.Status422UnprocessableEntity)]
    [InlineData("runtime_commercial_relink_seat_capacity_exceeded", "seat_capacity_exceeded", StatusCodes.Status422UnprocessableEntity)]
    [InlineData("runtime_commercial_relink_enrollment_ineligible", "enrollment_inactive", StatusCodes.Status422UnprocessableEntity)]
    [InlineData("runtime_commercial_relink_assignment_conflict", "assignment_conflict", StatusCodes.Status409Conflict)]
    [InlineData("runtime_commercial_relink_authority_ineligible", "authority_ineligible", StatusCodes.Status422UnprocessableEntity)]
    public void TryTranslateRelink_WriterRefusal_IsNamed(string message, string code, int status)
    {
        Assert.True(AssignmentRefusals.TryTranslateRelink(Postgres("23514", message), out var refusal));
        Assert.Equal(code, refusal.ErrorCode);
        Assert.Equal(status, refusal.StatusCode);
        Assert.Equal(message, refusal.DiagnosticCode);
    }

    /// <summary>An unknown relink suffix or another SQLSTATE is left to the caller's 503 handling.</summary>
    [Theory]
    [InlineData("23514", "runtime_commercial_relink_something_new")]
    [InlineData("40001", "runtime_commercial_relink_license_ineligible")]
    [InlineData("23514", "commercial assignment remains quarantined")]
    public void TryTranslateRelink_UnknownRefusal_IsNotNamed(string sqlState, string message)
    {
        Assert.False(AssignmentRefusals.TryTranslateRelink(Postgres(sqlState, message), out var refusal));
        Assert.Null(refusal);
    }

    /// <summary>
    /// TKT-004106: an assignment-state reason is published whatever the public code (the code and status stay those of
    /// the route), while security, identity and plain commercial diagnostics stay server-side.
    /// </summary>
    [Theory]
    [InlineData("authority_unavailable", "assignment_relation_missing", "assignment_relation_missing")]
    [InlineData("authority_unavailable", "assignment_duplicate_active", "assignment_duplicate_active")]
    [InlineData("authority_unavailable", "assignment_scope_conflict", "assignment_scope_conflict")]
    [InlineData("authority_ineligible", "assignment_quarantined", "assignment_quarantined")]
    [InlineData("bootstrap_ineligible", "assignment_quarantined", "assignment_quarantined")]
    [InlineData("binding_ineligible", "enrollment_quarantined", "enrollment_quarantined")]
    [InlineData("binding_ineligible", "assignment_graph_seat_mismatch", "assignment_graph_seat_mismatch")]
    [InlineData("binding_ineligible", "assignment_graph_unresolved", "assignment_graph_unresolved")]
    [InlineData("assignment_reconciliation_required", "seat_release_assignment_missing", "seat_release_assignment_missing")]
    [InlineData("authority_ineligible", "hardware_banned", null)]
    [InlineData("authority_ineligible", "component_banned", null)]
    [InlineData("authority_ineligible", "release_unapproved", null)]
    [InlineData("authority_ineligible", "commercial_authority_ineligible", null)]
    [InlineData("authority_ineligible", "assignment_missing", null)]
    [InlineData("binding_ineligible", "assignment_trigger_refused", null)]
    [InlineData("binding_ineligible", "assignment_graph_something_new", null)]
    [InlineData("authority_unavailable", null, null)]
    public void PublicReasonCode_PublishesOnlyAssignmentStateReasons(string code, string? reason, string? expected)
    {
        Assert.Equal(expected, AssignmentRefusals.PublicReasonCode(code, reason));
    }

    /// <summary>
    /// TKT-004106: a refusal already classified by the server (for example 422 <c>binding_ineligible</c> at Prepare, or
    /// a distribution refusal) keeps its code even when it carries a trigger refusal as inner cause.
    /// </summary>
    [Fact]
    public void TryTranslate_AlreadyClassifiedRefusalWithTriggerCause_IsNeverReclassified()
    {
        var cause = Postgres("23514", "unresolved commercial assignment graph: seat_mismatch");

        Assert.False(AssignmentRefusals.TryTranslate(
            new RuntimeEnrollmentException("binding_ineligible", 422, "assignment_graph_seat_mismatch", cause), out _));
        Assert.False(AssignmentRefusals.TryTranslate(
            new DistributionOperationException("bootstrap_ineligible", 422, "assignment_quarantined", innerException: cause),
            out _));
        Assert.False(AssignmentRefusals.TryTranslateRuntime(
            new RuntimeEnrollmentException("binding_ineligible", 422, "assignment_graph_seat_mismatch", cause), out _));
        Assert.True(AssignmentRefusals.TryTranslate(new DbUpdateException("save failed", cause), out _));
    }

    /// <summary>
    /// TKT-004158: the five commercial reasons are published under any code, while the unpublished licence-structure
    /// reasons, the identity refusal and every ban stay server-side.
    /// </summary>
    [Theory]
    [InlineData("authority_ineligible", "license_revoked", "license_revoked")]
    [InlineData("authority_ineligible", "license_expired", "license_expired")]
    [InlineData("refresh_ineligible", "license_inactive", "license_inactive")]
    [InlineData("bootstrap_ineligible", "version_ineligible", "version_ineligible")]
    [InlineData("entitlement_ineligible", "seat_capacity_exceeded", "seat_capacity_exceeded")]
    [InlineData("reinstall_authority_ineligible", "license_revoked", "license_revoked")]
    [InlineData("authority_ineligible", "license_unusable", null)]
    [InlineData("authority_ineligible", "seat_unavailable", null)]
    [InlineData("entitlement_ineligible", "license_missing", null)]
    [InlineData("authority_ineligible", "commercial_authority_ineligible", null)]
    [InlineData("entitlement_ineligible", "hardware_banned", null)]
    public void PublicReasonCode_PublishesOnlyCommercialReasons(string code, string reason, string? expected)
    {
        Assert.Equal(expected, AssignmentRefusals.PublicReasonCode(code, reason));
    }

    /// <summary>
    /// TKT-004158: the preflight stores the historical <c>commercial_authority_ineligible</c> for the resolver's finer
    /// commercial reasons, so stored and replayed hardware decisions keep their vocabulary; other reasons are unchanged.
    /// </summary>
    [Theory]
    [InlineData("license_revoked", "commercial_authority_ineligible")]
    [InlineData("license_inactive", "commercial_authority_ineligible")]
    [InlineData("license_expired", "commercial_authority_ineligible")]
    [InlineData("version_ineligible", "commercial_authority_ineligible")]
    [InlineData(null, "commercial_authority_ineligible")]
    [InlineData("seat_capacity_exceeded", "seat_capacity_exceeded")]
    [InlineData("assignment_scope_mismatch", "assignment_scope_mismatch")]
    public void PreflightStoredResolverReason_KeepsTheHistoricalVocabulary(string? diagnostic, string stored)
    {
        Assert.Equal(stored, RuntimeDistributionPreflightService.StoredResolverReason(diagnostic));
    }

    /// <summary>Only the busy code carries <c>Retry-After</c>; other codes leave the headers untouched.</summary>
    [Fact]
    public void ApplyRetryAfter_OnlyForBusy()
    {
        var busy = new DefaultHttpContext().Response;
        AssignmentRefusals.ApplyRetryAfter(busy, AssignmentRefusals.BusyCode);
        Assert.Equal("5", busy.Headers.RetryAfter.ToString());

        var other = new DefaultHttpContext().Response;
        AssignmentRefusals.ApplyRetryAfter(other, AssignmentRefusals.ReconciliationRequiredCode);
        Assert.False(other.Headers.ContainsKey("Retry-After"));
    }

    /// <summary>Builds a PostgreSQL error with the exact SQLSTATE and primary message a trigger raises.</summary>
    /// <param name="sqlState">Five-character SQLSTATE.</param>
    /// <param name="message">Exact primary message text.</param>
    private static PostgresException Postgres(string sqlState, string message) =>
        new(message, "ERROR", "ERROR", sqlState);
}
