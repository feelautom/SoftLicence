using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// Produces only the closed reinstall-authorization v1 response. This boundary deliberately has
/// no lineage, generation, digest, transition, or signature inputs; those belong exclusively to
/// the signed authority-generation v2 producer.
/// </summary>
internal static class RuntimeReinstallAuthorityV1Producer
{
    /// <summary>Gets the exact v1 response schema emitted by this producer.</summary>
    internal const string ResponseSchema = "runtime-enrollment-reinstall-authority-response-v1";

    /// <summary>
    /// Creates one provider assertion from already authenticated and authority-locked state.
    /// Opaque and canonical identifiers are copied exactly without trimming or normalization.
    /// </summary>
    /// <param name="input">The complete closed v1 response scope.</param>
    /// <returns>The exact reinstall-authorization v1 response.</returns>
    /// <exception cref="InvalidOperationException">The decision is outside the closed v1 vocabulary.</exception>
    internal static RuntimeReinstallAuthorityResponse Produce(RuntimeReinstallAuthorityV1Scope input)
    {
        var semantics = RuntimeReinstallAuthorityV1DecisionPolicy.Describe(input.Decision);

        return new RuntimeReinstallAuthorityResponse(
            ResponseSchema,
            input.ProtocolVersion,
            semantics.WireValue,
            input.RequestId,
            input.CorrelationId,
            input.ProductId,
            input.EnrollmentId,
            input.BindingId,
            input.InstallationId,
            input.ReleaseVersion,
            input.KeyThumbprint,
            input.SecurityEpoch,
            input.GrantRef,
            input.SubjectRefDigestSha256,
            input.SoftLicenceLicenseId,
            input.SoftLicenceSeatId);
    }
}

/// <summary>
/// Contains only the provider-owned fields of one reinstall-authorization v1 assertion.
/// Signed-generation v2 authority material cannot be represented by this type.
/// </summary>
/// <param name="ProtocolVersion">The canonical Runtime Enrollment protocol version.</param>
/// <param name="Decision">The closed provider decision to serialize.</param>
/// <param name="RequestId">The canonical identifier of the signed Runtime request.</param>
/// <param name="CorrelationId">The canonical bootstrap correlation identifier.</param>
/// <param name="ProductId">The canonical identifier of the bound product.</param>
/// <param name="EnrollmentId">The canonical identifier of the active Runtime enrollment.</param>
/// <param name="BindingId">The canonical identifier of the verified installation binding.</param>
/// <param name="InstallationId">The exact opaque installation identifier.</param>
/// <param name="ReleaseVersion">The exact release version bound by the verified request.</param>
/// <param name="KeyThumbprint">The exact thumbprint of the enrolled Runtime key.</param>
/// <param name="SecurityEpoch">The verified Runtime security epoch.</param>
/// <param name="GrantRef">The exact opaque provider grant reference.</param>
/// <param name="SubjectRefDigestSha256">The lowercase SHA-256 digest of the verified subject.</param>
/// <param name="SoftLicenceLicenseId">The canonical identifier of the source licence.</param>
/// <param name="SoftLicenceSeatId">The canonical identifier of the bound source seat.</param>
internal sealed record RuntimeReinstallAuthorityV1Scope(
    string ProtocolVersion,
    RuntimeReinstallAuthorityV1Decision Decision,
    string RequestId,
    string CorrelationId,
    string ProductId,
    string EnrollmentId,
    string BindingId,
    string InstallationId,
    string ReleaseVersion,
    string KeyThumbprint,
    int SecurityEpoch,
    string GrantRef,
    string SubjectRefDigestSha256,
    string SoftLicenceLicenseId,
    string SoftLicenceSeatId);

/// <summary>
/// Defines the complete closed decision vocabulary of the reinstall-authorization v1 contract.
/// The legacy wire remains available only as non-authorizing identity evidence.
/// </summary>
internal enum RuntimeReinstallAuthorityV1Decision
{
    /// <summary>Confirms only the bound Runtime identity and grants no reinstall authority.</summary>
    IdentityConfirmed
}

/// <summary>
/// Defines the only provider-owned capability that a v1 decision can communicate.
/// The capability remains bound to the exact identifiers serialized in the same response.
/// </summary>
internal enum RuntimeReinstallAuthorityV1Capability
{
    /// <summary>Confirms the Runtime identity represented by the exact response scope.</summary>
    ConfirmBoundRuntimeIdentity
}

/// <summary>
/// Resolves each closed decision to its exact wire value and bounded capabilities.
/// </summary>
internal static class RuntimeReinstallAuthorityV1DecisionPolicy
{
    /// <summary>Classifies a verified Runtime identity without granting decision authority.</summary>
    /// <param name="sourceLicenseEligible">
    /// Whether the source licence, seat quota, and bound version would otherwise permit reinstall.
    /// The observation is deliberately non-authorizing because v1 has no audience, expiry, or
    /// atomic-consumption guarantee.
    /// </param>
    /// <returns>The only closed, non-authorizing v1 decision.</returns>
    internal static RuntimeReinstallAuthorityV1Decision Classify(bool sourceLicenseEligible) =>
        RuntimeReinstallAuthorityV1Decision.IdentityConfirmed;

    /// <summary>Returns the immutable semantics of a closed decision.</summary>
    /// <param name="decision">The closed decision to describe.</param>
    /// <returns>The exact wire value and bounded capabilities of the decision.</returns>
    /// <exception cref="InvalidOperationException">The decision is outside the closed vocabulary.</exception>
    internal static RuntimeReinstallAuthorityV1DecisionSemantics Describe(
        RuntimeReinstallAuthorityV1Decision decision) => decision switch
        {
            RuntimeReinstallAuthorityV1Decision.IdentityConfirmed => new(
                "identity_confirmed", IdentityConfirmed: true),
            _ => throw new InvalidOperationException(
                "The reinstall-authorization v1 decision is invalid.")
        };

    /// <summary>Checks one exact provider-owned capability without implicit elevation.</summary>
    /// <param name="decision">The closed decision whose authority is being queried.</param>
    /// <param name="capability">The exact provider-owned capability being queried.</param>
    /// <returns><see langword="true"/> only when the closed decision explicitly permits the capability.</returns>
    /// <exception cref="InvalidOperationException">The decision or capability is outside the closed vocabulary.</exception>
    internal static bool Permits(
        RuntimeReinstallAuthorityV1Decision decision,
        RuntimeReinstallAuthorityV1Capability capability)
    {
        var semantics = Describe(decision);
        return capability switch
        {
            RuntimeReinstallAuthorityV1Capability.ConfirmBoundRuntimeIdentity =>
                semantics.IdentityConfirmed,
            _ => throw new InvalidOperationException(
                "The reinstall-authorization v1 capability is invalid.")
        };
    }
}

/// <summary>Contains the exact immutable meaning of one closed v1 decision.</summary>
/// <param name="WireValue">The exact lowercase value serialized on the v1 wire.</param>
/// <param name="IdentityConfirmed">Whether the exact response scope confirms the bound Runtime identity.</param>
internal readonly record struct RuntimeReinstallAuthorityV1DecisionSemantics(
    string WireValue,
    bool IdentityConfirmed);
