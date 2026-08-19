using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeAuthorityTransitionResolverTests
{
    public static TheoryData<string> RecoverableBusinessReasons => new()
    {
        "authority_ineligible",
        "binding_superseded",
        "license_ineligible",
        "release_changed",
        "seat_ineligible",
        "seat_reassigned_product_scope",
        "version_ineligible"
    };

    [Theory]
    [MemberData(nameof(RecoverableBusinessReasons))]
    public void ClassifyEnrollments_SoleBusinessTerminal_AllowsSuccessor(string reason)
    {
        var now = DateTime.UtcNow;

        var decision = RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
            [Terminal(reason, now)], now);

        Assert.Equal(RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal, decision);
    }

    [Theory]
    [InlineData("security_lockdown")]
    [InlineData("runtime_critical_incident")]
    [InlineData("unknown_future_reason")]
    public void ClassifyEnrollments_SecurityOrUnknownTerminal_FailsClosed(string reason)
    {
        var now = DateTime.UtcNow;

        var decision = RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
            [Terminal(reason, now)], now);

        Assert.Equal(RuntimeAuthorityEnrollmentDecision.RejectSecurity, decision);
    }

    [Fact]
    public void ClassifyEnrollments_MultipleTerminalRows_IsAmbiguous()
    {
        var now = DateTime.UtcNow;

        var decision = RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
            [Terminal("seat_reassigned_product_scope", now), Terminal("binding_superseded", now)], now);

        Assert.Equal(RuntimeAuthorityEnrollmentDecision.RejectAmbiguous, decision);
    }

    [Fact]
    public void ClassifyEnrollments_ConsumedExpiredChallenge_FailsClosed()
    {
        var now = DateTime.UtcNow;
        var terminal = Terminal("challenge_expired", now) with { ChallengeConsumedAtUtc = now.AddMinutes(-2) };

        var decision = RuntimeAuthorityTransitionResolver.ClassifyEnrollments([terminal], now);

        Assert.Equal(RuntimeAuthorityEnrollmentDecision.RejectSecurity, decision);
    }

    [Theory]
    [InlineData("active", null, true)]
    [InlineData("invalidated", "seat_reassigned_product_scope", true)]
    [InlineData("invalidated", "installation_superseded", true)]
    [InlineData("invalidated", "security_lockdown", false)]
    [InlineData("invalidated", "unknown_future_reason", false)]
    public void IsRecoverableBinding_UsesExplicitFailClosedMatrix(
        string state,
        string? reason,
        bool expected)
    {
        Assert.Equal(expected, RuntimeAuthorityTransitionResolver.IsRecoverableBinding(state, reason));
    }

    [Fact]
    public void ResolveBinding_UniqueAuthorizedTerminalLeaf_FollowsCurrentGeneration()
    {
        var predecessorId = Guid.NewGuid();
        var leafId = Guid.NewGuid();
        var decision = RuntimeAuthorityTransitionResolver.ResolveBinding(
        [
            Binding(predecessorId, null, "invalidated", "installation_superseded", true),
            Binding(leafId, predecessorId, "invalidated", "seat_reassigned_product_scope", true)
        ]);

        Assert.Equal(RuntimeAuthorityBindingDecisionKind.UseBusinessTerminal, decision.Kind);
        Assert.Equal(leafId, decision.BindingId);
    }

    [Fact]
    public void ResolveBinding_MultipleAuthorizedTerminalLeaves_IsAmbiguous()
    {
        var decision = RuntimeAuthorityTransitionResolver.ResolveBinding(
        [
            Binding(Guid.NewGuid(), null, "invalidated", "seat_reassigned_product_scope", true),
            Binding(Guid.NewGuid(), null, "invalidated", "license_ineligible", true)
        ]);

        Assert.Equal(RuntimeAuthorityBindingDecisionKind.RejectAmbiguous, decision.Kind);
        Assert.Null(decision.BindingId);
    }

    [Fact]
    public void ResolveBinding_SecurityTerminalOrUnprovenLeaf_IsMissing()
    {
        var decision = RuntimeAuthorityTransitionResolver.ResolveBinding(
        [
            Binding(Guid.NewGuid(), null, "invalidated", "security_lockdown", true),
            Binding(Guid.NewGuid(), null, "invalidated", "seat_reassigned_product_scope", false)
        ]);

        Assert.Equal(RuntimeAuthorityBindingDecisionKind.RejectMissing, decision.Kind);
        Assert.Null(decision.BindingId);
    }

    [Fact]
    public void ResolveBinding_MultipleActiveRows_IsAmbiguousEvenWithOneProof()
    {
        var decision = RuntimeAuthorityTransitionResolver.ResolveBinding(
        [
            Binding(Guid.NewGuid(), null, "active", null, true),
            Binding(Guid.NewGuid(), null, "active", null, false)
        ]);

        Assert.Equal(RuntimeAuthorityBindingDecisionKind.RejectAmbiguous, decision.Kind);
    }

    private static RuntimeAuthorityEnrollmentSnapshot Terminal(string reason, DateTime now) => new(
        RuntimeAuthorityTransitionResolver.InvalidatedState,
        reason,
        now.AddMinutes(-5),
        null,
        null,
        now.AddMinutes(-4));

    private static RuntimeAuthorityBindingSnapshot Binding(
        Guid id,
        Guid? supersededBindingId,
        string state,
        string? reason,
        bool authorized) => new(id, supersededBindingId, state, reason, authorized);
}
