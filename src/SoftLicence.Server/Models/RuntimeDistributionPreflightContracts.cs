using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

/// <summary>Carries one closed provider-owned pre-download hardware decision request.</summary>
public sealed class RuntimeDistributionPreflightRequest
{
    /// <summary>Gets or sets the exact unversioned authority schema identifier.</summary>
    public string? Schema { get; set; }
    /// <summary>Gets or sets the caller-generated canonical UUID used for request correlation.</summary>
    public string? RequestId { get; set; }
    /// <summary>Gets or sets the canonical product UUID whose ban scope is evaluated.</summary>
    public string? ProductId { get; set; }
    /// <summary>Gets or sets the canonical provider licence UUID selected by the authenticated Website grant.</summary>
    public string? SoftLicenceLicenseId { get; set; }
    /// <summary>Gets or sets the lowercase SHA-256 digest of the Website grant reference.</summary>
    public string? GrantRefDigestSha256 { get; set; }
    /// <summary>Gets or sets the canonical installation UUID for possession-bound evaluation.</summary>
    public string? InstallationId { get; set; }
    /// <summary>Gets or sets the base64url SHA-256 thumbprint of the installation CNG key.</summary>
    public string? KeyThumbprint { get; set; }
    /// <summary>Gets or sets current observations; a known installation must prove UUID concordance with its locked assignment.</summary>
    public RuntimeDistributionHardwareEvidence? HardwareEvidence { get; set; }
    /// <summary>Gets or sets an existing lowercase digest for post-authorization ban revalidation.</summary>
    public string? HardwareIdHash { get; set; }
    /// <summary>
    /// Gets or sets the optional seat-admission request (TKT-001720). Absent keeps the historical decision;
    /// the exact value <c>initial</c> asks the provider to predict the finalize seat-capacity refusal of a
    /// fresh initial installation before any download. Every other value is a malformed contract.
    /// </summary>
    public string? SeatAdmission { get; set; }

    /// <summary>Captures unknown JSON members so the service can reject contract widening.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Machine observations sent by the WebSetup for an installation not yet enrolled (TKT-001277 lot 2c). The server
/// alone derives the licence identifier from <see cref="SystemUuid"/> with the SDK rule; the WebSetup computes and
/// decides nothing. The authenticated request's <see cref="MachineEvidence"/> is classified for restricted
/// commercial offers. The separate investigation observation table never supplies authority.
/// </summary>
public sealed class RuntimeDistributionHardwareEvidence
{
    /// <summary>Gets or sets the raw <c>Win32_ComputerSystemProduct.UUID</c>, or <c>null</c> when the machine exposes none.</summary>
    public string? SystemUuid { get; set; }
    /// <summary>Gets or sets the raw machine evidence object collected by the SDK, or <c>null</c>.</summary>
    public JsonElement? MachineEvidence { get; set; }

    /// <summary>Captures unknown JSON members so the service can reject contract widening.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>Returns no reusable machine identifier, only the accepted digest and decision mode.</summary>
/// <param name="Schema">Exact unversioned response schema.</param>
/// <param name="RequestId">Canonical UUID copied from the authenticated request.</param>
/// <param name="Decision">Exact accepted decision; refusals use bounded HTTP errors instead.</param>
/// <param name="HardwareIdHash">Lowercase SHA-256 digest safe for Website persistence.</param>
/// <param name="AuthorityMode">Closed provenance describing enrollment, derivation, or revalidation.</param>
public sealed record RuntimeDistributionPreflightResponse(
    string Schema,
    string RequestId,
    string Decision,
    string HardwareIdHash,
    string AuthorityMode);
