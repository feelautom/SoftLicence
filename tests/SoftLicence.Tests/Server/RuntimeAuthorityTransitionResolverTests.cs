using SoftLicence.Server.Data;
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
    [InlineData("seat_released")]
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
    [InlineData("invalidated", "seat_released", false)]
    public void IsRecoverableBinding_UsesExplicitFailClosedMatrix(
        string state,
        string? reason,
        bool expected)
    {
        Assert.Equal(expected, RuntimeAuthorityTransitionResolver.IsRecoverableBinding(state, reason));
    }

    /// <summary>
    /// Proves that a later seat release can nominate an exact enrollment already rejected for a
    /// business reason, that a stale Runtime call's binding_ineligible refusal strictly after the
    /// release still proves it (TKT-001198), while simultaneous, earlier or future refusals and every
    /// other terminal reason stay fail-closed. Offsets are seconds from a release one minute ago.
    /// </summary>
    [Theory]
    [InlineData("seat_released", 0, true)]
    [InlineData("authority_ineligible", -1, true)]
    [InlineData("authority_ineligible", 1, false)]
    [InlineData("version_ineligible", -1, true)]
    [InlineData("version_ineligible", 1, false)]
    [InlineData("binding_ineligible", 1, true)]
    [InlineData("binding_ineligible", 0, false)]
    [InlineData("binding_ineligible", -1, false)]
    [InlineData("binding_ineligible", 120, false)]
    [InlineData("binding_superseded", -1, false)]
    [InlineData("security_lockdown", -1, false)]
    [InlineData("unknown_future_reason", -1, false)]
    public void IsCoherentSeatRelease_UsesExactMixedTerminalMatrix(
        string enrollmentReason,
        int enrollmentOffsetSeconds,
        bool expected)
    {
        var releasedAt = DateTime.UtcNow.AddMinutes(-1);
        var binding = ReleasedBinding(releasedAt);
        var enrollment = MatchingEnrollment(binding, enrollmentReason,
            releasedAt.AddSeconds(enrollmentOffsetSeconds));

        var coherent = RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
            binding, [enrollment], DateTime.UtcNow);

        Assert.Equal(expected, coherent);
    }

    [Fact]
    public void IsCoherentSeatRelease_MismatchedAuthorityOrMultipleEnrollments_FailsClosed()
    {
        var releasedAt = DateTime.UtcNow.AddMinutes(-1);
        var binding = ReleasedBinding(releasedAt);
        var enrollment = MatchingEnrollment(binding, "authority_ineligible", releasedAt.AddSeconds(-1));

        enrollment.HardwareIdHash = new string('f', 64);
        Assert.False(RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
            binding, [enrollment], DateTime.UtcNow));
        enrollment.HardwareIdHash = binding.HardwareIdHash;
        Assert.False(RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
            binding,
            [enrollment, MatchingEnrollment(binding, "authority_ineligible", releasedAt.AddSeconds(-1))],
            DateTime.UtcNow));
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

    private static DistributionInstallationBinding ReleasedBinding(DateTime releasedAt) => new()
    {
        Id = Guid.NewGuid(),
        ProductId = Guid.NewGuid(),
        LicenseId = Guid.NewGuid(),
        LicenseSeatId = Guid.NewGuid(),
        InstallationId = Guid.NewGuid().ToString("D"),
        HardwareIdHash = new string('a', 64),
        Version = "2.3.986",
        HandoffDigestSha256 = new string('b', 64),
        SubjectRefDigestSha256 = new string('c', 64),
        State = "invalidated",
        BoundAtUtc = releasedAt.AddHours(-1),
        InvalidatedAtUtc = releasedAt,
        InvalidationReason = "seat_released",
        InitialSecurityEpoch = 15
    };

    private static RuntimeEnrollment MatchingEnrollment(
        DistributionInstallationBinding binding,
        string reason,
        DateTime invalidatedAt) => new()
    {
        Id = Guid.NewGuid(),
        BindingId = binding.Id,
        ProductId = binding.ProductId,
        LicenseId = binding.LicenseId,
        LicenseSeatId = binding.LicenseSeatId,
        InstallationId = binding.InstallationId,
        HardwareIdHash = binding.HardwareIdHash,
        ReleaseVersion = binding.Version,
        HandoffDigestSha256 = binding.HandoffDigestSha256,
        SubjectRefDigestSha256 = binding.SubjectRefDigestSha256,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        State = RuntimeAuthorityTransitionResolver.InvalidatedState,
        Epoch = 1,
        SecurityEpoch = binding.InitialSecurityEpoch,
        CreatedAtUtc = binding.BoundAtUtc.AddMinutes(1),
        ActivatedAtUtc = binding.BoundAtUtc.AddMinutes(2),
        ChallengeConsumedAtUtc = binding.BoundAtUtc.AddMinutes(2),
        InvalidatedAtUtc = invalidatedAt,
        InvalidationReason = reason
    };
}
