using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Locks the closed provider reason vocabulary independently from relational fixtures.</summary>
public sealed class HardwareAuthorityRefusalDiagnosticsTests
{
    [Theory]
    [InlineData(HardwareAuthorityRefusalReason.AmbiguousAlias, "alias_resolution_ambiguous", "alias_resolution_ambiguous_guard")]
    [InlineData(HardwareAuthorityRefusalReason.AliasUnavailable, "alias_resolution_unavailable", "alias_resolution_unavailable_guard")]
    [InlineData(HardwareAuthorityRefusalReason.AuthorityGraphMissing, "authority_graph_missing", "authority_graph_missing_guard")]
    [InlineData(HardwareAuthorityRefusalReason.AuthorityGraphDiverged, "authority_graph_diverged", "authority_graph_diverged_guard")]
    public void DescribeAliasRefusal_MapsEachResolverGuardExactly(
        HardwareAuthorityRefusalReason refusalReason,
        string expectedReasonCode,
        string expectedGuard)
    {
        var diagnostic = HardwareAuthorityRefusalDiagnostics.DescribeAliasRefusal(refusalReason);

        Assert.Equal(expectedReasonCode, diagnostic.ReasonCode);
        Assert.Equal(expectedGuard, diagnostic.Guard);
    }

    [Fact]
    public void ReasonVocabulary_ContainsEightDistinctExactCodes()
    {
        string[] reasonCodes =
        [
            HardwareAuthorityRefusalDiagnostics.AliasResolutionAmbiguous,
            HardwareAuthorityRefusalDiagnostics.AliasResolutionUnavailable,
            HardwareAuthorityRefusalDiagnostics.AuthorityGraphMissing,
            HardwareAuthorityRefusalDiagnostics.AuthorityGraphDiverged,
            HardwareAuthorityRefusalDiagnostics.AliasReconciliationIdentityMissing,
            HardwareAuthorityRefusalDiagnostics.CanonicalSeatCardinalityMismatch,
            HardwareAuthorityRefusalDiagnostics.RecoverySourceMissing,
            HardwareAuthorityRefusalDiagnostics.RecoverySourceBindingMismatch
        ];

        Assert.Equal(8, reasonCodes.Distinct(StringComparer.Ordinal).Count());
        Assert.All(reasonCodes, reasonCode =>
            Assert.Matches("^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$", reasonCode));
    }
}
