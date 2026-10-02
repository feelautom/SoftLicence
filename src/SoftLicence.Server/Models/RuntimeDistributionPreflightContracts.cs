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
    /// <summary>Gets or sets transient raw observations for an installation not yet enrolled.</summary>
    public RuntimeDistributionHardwareEvidence? HardwareEvidence { get; set; }
    /// <summary>Gets or sets an existing lowercase digest for post-authorization ban revalidation.</summary>
    public string? HardwareIdHash { get; set; }

    /// <summary>Captures unknown JSON members so the service can reject contract widening.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Contains bounded observations used to reproduce the pinned SDK identities on the server.
/// These transient values must never be logged or persisted.
/// </summary>
public sealed class RuntimeDistributionHardwareEvidence
{
    /// <summary>Gets or sets the trimmed processor identifier or UNKNOWN sentinel.</summary>
    public string? CpuId { get; set; }
    /// <summary>Gets or sets the trimmed baseboard serial or UNKNOWN sentinel.</summary>
    public string? MotherboardId { get; set; }
    /// <summary>Gets or sets the trimmed BIOS serial or UNKNOWN sentinel.</summary>
    public string? BiosId { get; set; }
    /// <summary>Gets or sets the first non-empty disk serial used by the contractual identity.</summary>
    public string? LegacyDiskId { get; set; }
    /// <summary>Gets or sets the index-zero disk serial used only as a secondary ban signal.</summary>
    public string? StableDiskId { get; set; }
    /// <summary>Gets or sets the exact Windows machine name used by the pinned SDK algorithm.</summary>
    public string? MachineName { get; set; }

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
