using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

/// <summary>
/// Carries one closed entitlement issue request; schema v4 additionally requires member-presence
/// proof for the exact provider-issued authority generation identifier.
/// </summary>
public sealed class DistributionEntitlementIssueRequest
{
    private string? _authorityGenerationId;

    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? SoftLicenceLicenseId { get; set; }
    public string? GrantRefDigestSha256 { get; set; }
    public string? SubjectRef { get; set; }
    /// <summary>
    /// Gets or sets the provider-issued Runtime Enrollment generation selected by the caller.
    /// Presence is tracked separately so legacy contracts reject even an explicitly null member.
    /// </summary>
    public string? AuthorityGenerationId
    {
        get => _authorityGenerationId;
        set
        {
            AuthorityGenerationIdPresent = true;
            _authorityGenerationId = value;
        }
    }

    /// <summary>Indicates whether the exact JSON request contained <c>authorityGenerationId</c>.</summary>
    [JsonIgnore]
    public bool AuthorityGenerationIdPresent { get; private set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>Returns the frozen entitlement reference and the v4 generation projection when applicable.</summary>
/// <param name="Schema">Exact response schema selected by the request contract.</param>
/// <param name="EntitlementRef">Opaque protected entitlement token.</param>
/// <param name="ExpiresAtUtc">Canonical UTC expiry.</param>
/// <param name="AuthorityGenerationId">Exact provider-issued UUID for v2 responses; absent from v1 JSON.</param>
public sealed record DistributionEntitlementIssueResponse(
    string Schema,
    string EntitlementRef,
    string ExpiresAtUtc,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AuthorityGenerationId = null);

public sealed class DistributionInstallationFinalizeRequest
{
    private bool? _allowSameAuthorityRecovery;
    private DistributionLicenseReplacementProof? _licenseReplacement;
    private DistributionLicenseReplacementCandidateSet? _licenseReplacementCandidates;
    private DistributionLegacyLicenseReplacementProof? _legacyLicenseReplacement;

    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? GrantRef { get; set; }
    public string? HandoffDigestSha256 { get; set; }
    public string? HandoffIssuedAtUtc { get; set; }
    public string? HandoffExpiresAtUtc { get; set; }
    public string? DownloadCompletedAtUtc { get; set; }
    public string? ProductId { get; set; }
    public string? EntitlementRef { get; set; }
    public string? InstallationId { get; set; }
    public string? HardwareId { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? AllowSameAuthorityRecovery
    {
        get => _allowSameAuthorityRecovery;
        set
        {
            AllowSameAuthorityRecoveryPresent = true;
            _allowSameAuthorityRecovery = value;
        }
    }

    [JsonIgnore]
    public bool AllowSameAuthorityRecoveryPresent { get; private set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DistributionLicenseReplacementProof? LicenseReplacement
    {
        get => _licenseReplacement;
        set
        {
            LicenseReplacementPresent = true;
            _licenseReplacement = value;
        }
    }

    [JsonIgnore]
    public bool LicenseReplacementPresent { get; private set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DistributionLicenseReplacementCandidateSet? LicenseReplacementCandidates
    {
        get => _licenseReplacementCandidates;
        set
        {
            LicenseReplacementCandidatesPresent = true;
            _licenseReplacementCandidates = value;
        }
    }

    [JsonIgnore]
    public bool LicenseReplacementCandidatesPresent { get; private set; }
    /// <summary>
    /// Carries the authenticated Website assertion that the exact legacy source and entitlement-bound
    /// target licences belong to the same account. SoftLicence derives all binding and seat authority.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DistributionLegacyLicenseReplacementProof? LegacyLicenseReplacement
    {
        get => _legacyLicenseReplacement;
        set
        {
            LegacyLicenseReplacementPresent = true;
            _legacyLicenseReplacement = value;
        }
    }

    /// <summary>
    /// Distinguishes an absent v5 proof from an explicitly null member so both fail closed.
    /// </summary>
    [JsonIgnore]
    public bool LegacyLicenseReplacementPresent { get; private set; }
    public DistributionReleaseEvidence? Release { get; set; }
    public List<DistributionBinaryEvidence>? Binaries { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Carries an exact Website authority assertion for replacing a historical license during renewal.
/// The containing finalize payload is authenticated by the authorized server-to-server client.
/// </summary>
public sealed class DistributionLicenseReplacementProof
{
    public string? Schema { get; set; }
    public string? SourceBindingId { get; set; }
    public string? SourceLicenseId { get; set; }
    public string? SourceSubjectRef { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Carries a bounded set of Website-owned historical authorities when legacy Website rows do not
/// contain a hardware hash. SoftLicence remains the sole authority that may match one source to the
/// hardware supplied by the installed client; callers must not order this set by preference.
/// </summary>
public sealed class DistributionLicenseReplacementCandidateSet
{
    public string? Schema { get; set; }
    public List<DistributionLicenseReplacementProof>? Sources { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Identifies the exact source and target licence pair whose common Website ownership is asserted by
/// the authenticated exact-body S2S request. It deliberately carries no binding, seat, hardware,
/// customer, grant, key, or historical subject authority.
/// </summary>
public sealed class DistributionLegacyLicenseReplacementProof
{
    /// <summary>Identifies the strict additive proof contract.</summary>
    public string? Schema { get; set; }

    /// <summary>Identifies the legacy source licence in canonical lowercase UUID form.</summary>
    public string? SourceLicenseId { get; set; }

    /// <summary>Identifies the target licence already authenticated by the target entitlement.</summary>
    public string? TargetLicenseId { get; set; }

    /// <summary>Captures unknown members so service validation can reject non-exact proof shapes.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class DistributionReleaseEvidence
{
    public string? Version { get; set; }
    public string? InstallerFilename { get; set; }
    public string? InstallerSha256 { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class DistributionBinaryEvidence
{
    public string? Key { get; set; }
    public string? Sha256 { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record DistributionInstallationBindingResponse(
    string Schema,
    string BindingId,
    string State,
    string InstallationId,
    string HardwareIdHash,
    string Version,
    string ReleaseSource,
    string BoundAtUtc,
    string? InvalidatedAtUtc);

/// <summary>
/// Requests the unique Runtime-owned source licence for one product, target licence, and exact hardware identifier.
/// </summary>
public sealed class DistributionRuntimeSourceResolutionRequest
{
    /// <summary>Gets or sets the exact versioned request schema.</summary>
    public string? Schema { get; set; }

    /// <summary>Gets or sets the canonical lowercase request UUID.</summary>
    public string? RequestId { get; set; }

    /// <summary>Gets or sets the canonical lowercase product UUID.</summary>
    public string? ProductId { get; set; }

    /// <summary>Gets or sets the canonical lowercase target licence UUID.</summary>
    public string? TargetLicenseId { get; set; }

    /// <summary>Gets or sets the exact opaque hardware identifier submitted to Finalize.</summary>
    public string? HardwareId { get; set; }

    /// <summary>Captures unknown members so validation can reject every non-exact request shape.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Returns only the bounded source classification required to construct an unchanged Finalize contract.
/// </summary>
/// <param name="Schema">Exact versioned response schema.</param>
/// <param name="Outcome">Either <c>source</c> or <c>none</c>.</param>
/// <param name="SourceLicenseId">Canonical source licence UUID when a unique source exists.</param>
/// <param name="SourceKind">Either <c>legacy</c> or <c>modern</c> when a unique source exists.</param>
public sealed record DistributionRuntimeSourceResolutionResponse(
    string Schema,
    string Outcome,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SourceLicenseId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SourceKind);

public sealed class DistributionInstallationInvalidationRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? BindingId { get; set; }
    public string? GrantRefDigestSha256 { get; set; }
    public string? Reason { get; set; }
    public string? OccurredAtUtc { get; set; }
    public long? Epoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record DistributionInstallationInvalidationResponse(
    string Schema,
    string? BindingId,
    string State,
    string GrantRefDigestSha256,
    string Reason,
    string OccurredAtUtc,
    long Epoch,
    string InvalidatedAtUtc);

public sealed record DistributionOperationResult<T>(T Response, bool Idempotent);

public sealed record DistributionApiError(
    string Error,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ReasonCode = null);
