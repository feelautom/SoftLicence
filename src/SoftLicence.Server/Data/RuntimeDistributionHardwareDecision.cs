using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Stores one immutable provider decision for an authenticated pre-download hardware request.
/// Raw hardware observations, reusable HWIDs, licence keys, tokens, and customer data are excluded.
/// </summary>
public sealed class RuntimeDistributionHardwareDecision
{
    /// <summary>Gets or sets the server-generated audit identifier.</summary>
    public Guid Id { get; set; }
    /// <summary>Gets or sets the authenticated S2S client identifier.</summary>
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the canonical caller request UUID.</summary>
    [MaxLength(36)] public string RequestId { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact digest of the authenticated request body for replay detection.</summary>
    [MaxLength(64)] public string PayloadDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the provider-owned product scope.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the submitted provider licence identifier used for the authority lookup.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>Gets or sets the digest that binds the Website grant to its provider entitlement.</summary>
    [MaxLength(64)] public string GrantRefDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the irreversible accepted or evaluated hardware digest.</summary>
    [MaxLength(64)] public string? HardwareIdHash { get; set; }
    /// <summary>Gets or sets the irreversible installation UUID digest when an installation was submitted.</summary>
    [MaxLength(64)] public string? InstallationIdHash { get; set; }
    /// <summary>Gets or sets the exact public-key thumbprint when supplied; it is a correlation value, not a secret.</summary>
    [MaxLength(43)] public string? KeyThumbprint { get; set; }
    /// <summary>Gets or sets server-derived, known-enrollment, or digest-revalidation.</summary>
    [MaxLength(32)] public string AuthorityMode { get; set; } = string.Empty;
    /// <summary>Gets or sets accepted, auto-unbanned, or refused.</summary>
    [MaxLength(24)] public string Outcome { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed internal reason code; public responses remain opaque.</summary>
    [MaxLength(64)] public string ReasonCode { get; set; } = string.Empty;
    /// <summary>Gets or sets the ordered JSON array of exact active ban categories observed before the decision.</summary>
    [MaxLength(512)] public string BanCategoriesJson { get; set; } = "[]";
    /// <summary>Gets or sets whether the licence was active at the decision boundary.</summary>
    public bool LicenseActive { get; set; }
    /// <summary>Gets or sets whether the licence was revoked at the decision boundary.</summary>
    public bool LicenseRevoked { get; set; }
    /// <summary>Gets or sets whether the licence was expired at the decision boundary.</summary>
    public bool LicenseExpired { get; set; }
    /// <summary>Gets or sets whether the licence passed the complete paid auto-unban policy.</summary>
    public bool PaidAutoUnbanEligible { get; set; }
    /// <summary>Gets or sets the number of active auto-unbannable rows staged inactive by this decision.</summary>
    public int AutoUnbannedCount { get; set; }
    /// <summary>Gets or sets the number of exact authenticated deliveries of this logical request.</summary>
    public int AttemptCount { get; set; } = 1;
    /// <summary>Gets or sets the provider UTC decision timestamp.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the provider UTC timestamp of the latest exact replay.</summary>
    public DateTime LastSeenAtUtc { get; set; }
}
