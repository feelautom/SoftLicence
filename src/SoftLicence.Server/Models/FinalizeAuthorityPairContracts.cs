using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

/// <summary>
/// Exact-body S2S request asking the provider whether the hardware identifier a Desktop presents at
/// Finalize and the digest the Website froze on the grant designate the same machine through one
/// server-authenticated alias pair (TKT-001296). Nothing here is client authority: the provider
/// evaluates its own alias graph, and the response is digest-only.
/// </summary>
public sealed class FinalizeAuthorityPairRequest
{
    /// <summary>Gets or sets the closed request schema identifier.</summary>
    public string? Schema { get; set; }

    /// <summary>Gets or sets the caller request UUID echoed verbatim; the same inputs always yield the same answer.</summary>
    public string? RequestId { get; set; }

    /// <summary>Gets or sets the product boundary.</summary>
    public string? ProductId { get; set; }

    /// <summary>Gets or sets the licence boundary.</summary>
    public string? SoftLicenceLicenseId { get; set; }

    /// <summary>Gets or sets the SHA-256 digest of the Website grant reference bound to the entitlement.</summary>
    public string? GrantRefDigestSha256 { get; set; }

    /// <summary>Gets or sets the exact hardware identifier presented by the Desktop at Finalize.</summary>
    public string? SubmittedHardwareId { get; set; }

    /// <summary>Gets or sets the SHA-256 digest frozen on the grant before download.</summary>
    public string? ExpectedHardwareIdHash { get; set; }

    /// <summary>Captures unknown members so the contract fails closed instead of ignoring them.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Closed digest-only answer. Contract: <c>SubmittedHardwareIdHash</c>, <c>GrantExpectedHardwareIdHash</c> and
/// <c>CanonicalEffectiveHardwareIdHash</c> are never conflated; seat, quota, binding and enforcement stay on the
/// canonical stable identity, while the client licence file follows the submitted identity through the
/// existing alias mechanism. <c>CanonicalEffectiveHardwareIdHash</c> is null on mismatch and refusal.
/// <c>PayloadDigestSha256</c> binds the answer to the exact authenticated request bytes.
/// </summary>
public sealed record FinalizeAuthorityPairResponse(
    string Schema,
    string RequestId,
    string PayloadDigestSha256,
    Guid ProductId,
    Guid LicenseId,
    Guid? EntitlementId,
    string GrantRefDigestSha256,
    string Outcome,
    string SubmittedHardwareIdHash,
    string GrantExpectedHardwareIdHash,
    string? CanonicalEffectiveHardwareIdHash,
    string PairMatchedDirection,
    Guid? AliasId,
    Guid? BindingId,
    Guid? LicenseSeatId,
    string? RefusalReason);
