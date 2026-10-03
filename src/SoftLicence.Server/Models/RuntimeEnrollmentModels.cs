using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public sealed class RuntimeEnrollmentPrepareRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? ProductId { get; set; }
    public string? BindingId { get; set; }
    public string? HandoffDigestSha256 { get; set; }
    public string? InstallationId { get; set; }
    public string? ReleaseVersion { get; set; }
    public int? Epoch { get; set; }
    public RuntimeEnrollmentKeyRequest? Key { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeEnrollmentRefreshRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? ProductId { get; set; }
    public string? BindingId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? ExpectedChallengeDigestSha256 { get; set; }
    public int? ExpectedSecurityEpoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeEnrollmentKeyRequest
{
    public string? Alg { get; set; }
    public string? PublicKeySpkiBase64 { get; set; }
    public string? PublicKeySpkiSha256 { get; set; }
    public string? KeyThumbprint { get; set; }
    public string? Backend { get; set; }
    public string? Attestation { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeEnrollmentConfirmRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? EnrollmentId { get; set; }
    public int? Epoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Requests an authenticated, in-place transition from the legacy hardware identifier
/// bound to the current Runtime enrollment to the deterministic V2 identifier.
/// </summary>
public sealed class RuntimeHardwareAuthorityMigrationRequest
{
    /// <summary>Gets or sets the exact request schema identifier.</summary>
    public string? Schema { get; set; }
    /// <summary>Gets or sets the Runtime enrollment protocol version.</summary>
    public string? ProtocolVersion { get; set; }
    /// <summary>Gets or sets the canonical idempotency request UUID.</summary>
    public string? RequestId { get; set; }
    /// <summary>Gets or sets the canonical enrollment UUID bound into the request path.</summary>
    public string? EnrollmentId { get; set; }
    /// <summary>Gets or sets the immutable enrollment epoch.</summary>
    public int? Epoch { get; set; }
    /// <summary>Gets or sets the current security generation observed by the Runtime.</summary>
    public int? SecurityEpoch { get; set; }
    /// <summary>Gets or sets the uppercase legacy hardware identifier currently owning the seat.</summary>
    public string? LegacyHardwareId { get; set; }
    /// <summary>Gets or sets the uppercase deterministic V2 hardware identifier.</summary>
    public string? HardwareIdV2 { get; set; }
    /// <summary>Gets or sets the exact reviewed legacy identity algorithm identifier.</summary>
    public string? LegacyAlgorithm { get; set; }
    /// <summary>Gets or sets the exact reviewed V2 identity algorithm identifier.</summary>
    public string? HardwareIdV2Algorithm { get; set; }
    /// <summary>Gets or sets the SDK semantic version that produced both identifiers.</summary>
    public string? SdkVersion { get; set; }
    /// <summary>
    /// Gets or sets the raw <c>Win32_ComputerSystemProduct.UUID</c> from which <see cref="HardwareIdV2"/> must be
    /// derived with the SDK 2.0 rule (TKT-001277 lot 5); a refused or non-derived value is refused with its AR code.
    /// </summary>
    public string? SystemUuid { get; set; }

    /// <summary>Captures unknown JSON members so strict validation can reject them.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeEnrollmentCapabilityRequest
{
    private string? _installationId;
    private string? _releaseVersion;
    private string? _sessionId;
    private List<RuntimeEnrollmentBinaryEvidenceRequest>? _binaries;

    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? EnrollmentId { get; set; }
    public int? Epoch { get; set; }
    public int? SecurityEpoch { get; set; }
    public string? InstallationId
    {
        get => _installationId;
        set { _installationId = value; InstallationIdPresent = true; }
    }
    public string? ReleaseVersion
    {
        get => _releaseVersion;
        set { _releaseVersion = value; ReleaseVersionPresent = true; }
    }
    public string? SessionId
    {
        get => _sessionId;
        set { _sessionId = value; SessionIdPresent = true; }
    }
    public string? Audience { get; set; }
    public List<string>? Scope { get; set; }
    public List<RuntimeEnrollmentBinaryEvidenceRequest>? Binaries
    {
        get => _binaries;
        set { _binaries = value; BinariesPresent = true; }
    }

    [JsonIgnore]
    internal bool InstallationIdPresent { get; private set; }
    [JsonIgnore]
    internal bool ReleaseVersionPresent { get; private set; }
    [JsonIgnore]
    internal bool SessionIdPresent { get; private set; }
    [JsonIgnore]
    internal bool BinariesPresent { get; private set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeEnrollmentBinaryEvidenceRequest
{
    public string? Key { get; set; }
    public string? Sha256 { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeCriticalRecoveryClientRefetchRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? RequestId { get; set; }
    public string? EnrollmentId { get; set; }
    public int? Epoch { get; set; }
    public int? SecurityEpoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeMilestoneRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? EnrollmentId { get; set; }
    public int? Epoch { get; set; }
    public int? SecurityEpoch { get; set; }
    public string? SessionId { get; set; }
    public long? Sequence { get; set; }
    public string? EventId { get; set; }
    public string? Code { get; set; }
    public string? OccurredAtUtc { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeEnrollmentPrepareResponse(
    string Schema,
    string ProtocolVersion,
    string Status,
    string EnrollmentId,
    int Epoch,
    string Challenge,
    string ExpiresAtUtc,
    string ConfirmAudience)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? SecurityEpoch { get; init; }

}

public sealed record RuntimeEnrollmentConfirmResponse(
    string Schema,
    string ProtocolVersion,
    string Status,
    string EnrollmentId,
    int Epoch,
    string ActivatedAtUtc);

/// <summary>
/// Returns the authoritative hardware identity generation and a newly signed license file
/// after a replay-safe Runtime hardware authority transition.
/// </summary>
/// <param name="Schema">Exact response schema identifier.</param>
/// <param name="ProtocolVersion">Runtime enrollment protocol version.</param>
/// <param name="Decision">Bounded migration decision.</param>
/// <param name="RequestId">Canonical idempotency request UUID.</param>
/// <param name="EnrollmentId">Canonical enrollment UUID.</param>
/// <param name="BindingId">Canonical distribution binding UUID.</param>
/// <param name="LicenseSeatId">Canonical license seat UUID updated in place.</param>
/// <param name="OldSecurityEpoch">Security generation before the transition.</param>
/// <param name="NewSecurityEpoch">Authoritative security generation after the transition.</param>
/// <param name="HardwareIdV2">Uppercase deterministic V2 hardware identifier.</param>
/// <param name="LicenseFile">Newly signed license file bound to the V2 identifier.</param>
/// <param name="CompletedAtUtc">Authoritative PostgreSQL completion timestamp.</param>
public sealed record RuntimeHardwareAuthorityMigrationResponse(
    string Schema,
    string ProtocolVersion,
    string Decision,
    string RequestId,
    string EnrollmentId,
    string BindingId,
    string LicenseSeatId,
    int OldSecurityEpoch,
    int NewSecurityEpoch,
    string HardwareIdV2,
    string LicenseFile,
    string CompletedAtUtc);

public sealed record RuntimeEnrollmentCapabilityResponse(
    string Schema,
    string ProtocolVersion,
    string CapabilityToken,
    string ExpiresAtUtc);

public sealed class RuntimeWebSetupTransitionIssueRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? ProductId { get; set; }
    public string? BindingId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? SourceLicenseId { get; set; }
    public string? SourceSubjectRef { get; set; }
    public string? TargetGrantRef { get; set; }
    public string? TargetLicenseId { get; set; }
    public string? TargetSubjectRef { get; set; }
    public string? TargetEntitlementRef { get; set; }
    public string? SourceVersion { get; set; }
    public string? TargetVersion { get; set; }
    public string? TargetInstallerFilename { get; set; }
    public string? TargetInstallerSha256 { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeWebSetupTransitionIssuedResponse(
    string Schema,
    string ProtocolVersion,
    string TransitionId,
    string Capability,
    string ExpiresAtUtc);

public sealed class RuntimeReinstallAuthorityRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? BootstrapId { get; set; }
    public string? InstallationId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? ReleaseVersion { get; set; }
    public string? KeyThumbprint { get; set; }
    public int? SecurityEpoch { get; set; }
    public string? GrantRef { get; set; }
    public string? SubjectRef { get; set; }
    public string? Challenge { get; set; }
    public string? Signature { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeReinstallAuthorityResponse(
    string Schema,
    string ProtocolVersion,
    string Decision,
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
/// Provides the canonical production serializer configuration for Runtime Enrollment authority
/// v2 contracts. The configuration rejects case aliases and unknown members, enforces required
/// nullable annotations, emits explicit nulls, and performs no string normalization or repair.
/// </summary>
public static class RuntimeEnrollmentAuthorityJsonV2
{
    /// <summary>
    /// Creates an isolated serializer configuration for v2 authority DTOs. Callers may use the
    /// returned instance without changing the canonical policy applied to other operations.
    /// </summary>
    /// <returns>A new strict serializer configuration for v2 authority contracts.</returns>
    public static JsonSerializerOptions CreateSerializerOptions() => new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        PropertyNameCaseInsensitive = false,
        RespectNullableAnnotations = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
}

/// <summary>Represents the closed v2 lineage root. Opaque strings are preserved ordinally without normalization.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityLineageV2
{
    /// <summary>Gets or sets the required exact lineage schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the required contract version, which is 2 for this root.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the required canonical authority lineage identifier.</summary>
    [JsonPropertyName("authorityLineageId")] public required string AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the required exact provider code.</summary>
    [JsonPropertyName("provider")] public required string Provider { get; set; }
    /// <summary>Gets or sets the required canonical product identifier.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the required opaque provider grant reference without trimming or normalization.</summary>
    [JsonPropertyName("providerGrantRef")] public required string ProviderGrantRef { get; set; }
    /// <summary>Gets or sets the required canonical UTC creation timestamp.</summary>
    [JsonPropertyName("createdAtUtc")] public required string CreatedAtUtc { get; set; }
}

/// <summary>Represents the closed v2 authority request root with explicit nullable predecessor expectations.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityRequestV2
{
    /// <summary>Gets or sets the required exact request schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the required contract version, which is 2.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the required canonical idempotency request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the required exact provider code.</summary>
    [JsonPropertyName("provider")] public required string Provider { get; set; }
    /// <summary>Gets or sets the required canonical product identifier.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the required opaque provider grant reference.</summary>
    [JsonPropertyName("providerGrantRef")] public required string ProviderGrantRef { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable expected lineage identifier.</summary>
    [JsonPropertyName("expectedAuthorityLineageId")] public required string? ExpectedAuthorityLineageId { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable expected current generation identifier.</summary>
    [JsonPropertyName("expectedCurrentGenerationId")] public required string? ExpectedCurrentGenerationId { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable expected predecessor generation identifier.</summary>
    [JsonPropertyName("expectedPredecessorGenerationId")] public required string? ExpectedPredecessorGenerationId { get; set; }
    /// <summary>Gets or sets the required closed requested-authority child object.</summary>
    [JsonPropertyName("requestedAuthority")] public required RuntimeEnrollmentAuthorityRequestedRequestV2 RequestedAuthority { get; set; }
    /// <summary>Gets or sets the required request transition containing requestedAtUtc only.</summary>
    [JsonPropertyName("transition")] public required RuntimeEnrollmentAuthorityRequestTransitionV2 Transition { get; set; }
}

/// <summary>Represents the closed immutable v2 generation payload root.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityGenerationPayloadV2
{
    /// <summary>Gets or sets the required exact generation schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the required contract version, which is 2.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the required canonical lineage identifier.</summary>
    [JsonPropertyName("authorityLineageId")] public required string AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the required canonical generation identifier.</summary>
    [JsonPropertyName("authorityGenerationId")] public required string AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable predecessor generation identifier.</summary>
    [JsonPropertyName("previousGenerationId")] public required string? PreviousGenerationId { get; set; }
    /// <summary>Gets or sets the required zero-based lineage-local sequence assigned by SoftLicence.</summary>
    [JsonPropertyName("sequence")] public required long Sequence { get; set; }
    /// <summary>Gets or sets the required exact provider code.</summary>
    [JsonPropertyName("provider")] public required string Provider { get; set; }
    /// <summary>Gets or sets the required canonical product identifier.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the required opaque provider grant reference.</summary>
    [JsonPropertyName("providerGrantRef")] public required string ProviderGrantRef { get; set; }
    /// <summary>Gets or sets the required closed release authority.</summary>
    [JsonPropertyName("release")] public required RuntimeEnrollmentAuthorityReleaseV2 Release { get; set; }
    /// <summary>Gets or sets the required closed binding authority.</summary>
    [JsonPropertyName("binding")] public required RuntimeEnrollmentAuthorityBindingV2 Binding { get; set; }
    /// <summary>Gets or sets the required closed enrollment authority.</summary>
    [JsonPropertyName("enrollment")] public required RuntimeEnrollmentAuthorityEnrollmentV2 Enrollment { get; set; }
    /// <summary>Gets or sets the required closed key authority.</summary>
    [JsonPropertyName("key")] public required RuntimeEnrollmentAuthorityKeyV2 Key { get; set; }
    /// <summary>Gets or sets the required closed installation authority.</summary>
    [JsonPropertyName("installation")] public required RuntimeEnrollmentAuthorityInstallationV2 Installation { get; set; }
    /// <summary>Gets or sets the required generation transition containing requestId and occurredAtUtc only.</summary>
    [JsonPropertyName("transition")] public required RuntimeEnrollmentAuthorityGenerationTransitionV2 Transition { get; set; }
}

/// <summary>Represents the closed signed-generation root and preserves signature metadata exactly.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentSignedGenerationStatementV2
{
    /// <summary>Gets or sets the required exact signed-statement schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the required closed generation payload.</summary>
    [JsonPropertyName("payload")] public required RuntimeEnrollmentAuthorityGenerationPayloadV2 Payload { get; set; }
    /// <summary>Gets or sets the required lowercase SHA-256 authority digest.</summary>
    [JsonPropertyName("authorityDigest")] public required string AuthorityDigest { get; set; }
    /// <summary>Gets or sets the required closed PS256 signature envelope.</summary>
    [JsonPropertyName("signature")] public required RuntimeEnrollmentAuthoritySignatureV2 Signature { get; set; }
}

/// <summary>Represents the closed discovery-attempt root; outcome fields are present even when explicitly null.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityDiscoveryAttemptV2
{
    /// <summary>Gets or sets the required exact discovery schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the required contract version, which is 2.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the required canonical attempt identifier.</summary>
    [JsonPropertyName("attemptId")] public required string AttemptId { get; set; }
    /// <summary>Gets or sets the required canonical request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the required lowercase SHA-256 request digest.</summary>
    [JsonPropertyName("requestDigest")] public required string RequestDigest { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable lineage outcome identifier.</summary>
    [JsonPropertyName("authorityLineageId")] public required string? AuthorityLineageId { get; set; }
    /// <summary>Gets or sets the required exact accepted or refused status.</summary>
    [JsonPropertyName("status")] public required string Status { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable generation outcome identifier.</summary>
    [JsonPropertyName("authorityGenerationId")] public required string? AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable closed-registry error code.</summary>
    [JsonPropertyName("errorCode")] public required string? ErrorCode { get; set; }
    /// <summary>Gets or sets the required canonical UTC creation timestamp.</summary>
    [JsonPropertyName("createdAtUtc")] public required string CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the required canonical UTC completion timestamp.</summary>
    [JsonPropertyName("completedAtUtc")] public required string CompletedAtUtc { get; set; }
}

/// <summary>Represents the closed legacy compatibility root; it remains contract version 1 and source legacy_projection.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityLegacyProjectionV2
{
    /// <summary>Gets or sets the required exact legacy compatibility schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the required legacy contract version, which is 1.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the required exact provider code.</summary>
    [JsonPropertyName("provider")] public required string Provider { get; set; }
    /// <summary>Gets or sets the required canonical product identifier.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the required opaque provider grant reference.</summary>
    [JsonPropertyName("providerGrantRef")] public required string ProviderGrantRef { get; set; }
    /// <summary>Gets or sets the required lowercase SHA-256 authority digest.</summary>
    [JsonPropertyName("authorityDigest")] public required string AuthorityDigest { get; set; }
    /// <summary>Gets or sets the required exact legacy_projection source marker.</summary>
    [JsonPropertyName("source")] public required string Source { get; set; }
}

/// <summary>Represents the closed release-authority child.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityReleaseV2
{
    /// <summary>Gets or sets the required canonical release version.</summary>
    [JsonPropertyName("version")] public required string Version { get; set; }
    /// <summary>Gets or sets the required lowercase SHA-256 artifact-set digest.</summary>
    [JsonPropertyName("artifactSetDigest")] public required string ArtifactSetDigest { get; set; }
}

/// <summary>Represents the closed binding-authority child.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityBindingV2
{
    /// <summary>Gets or sets the required canonical binding identifier.</summary>
    [JsonPropertyName("bindingId")] public required string BindingId { get; set; }
    /// <summary>Gets or sets the required lowercase SHA-256 hardware identifier digest.</summary>
    [JsonPropertyName("hardwareIdDigest")] public required string HardwareIdDigest { get; set; }
}

/// <summary>Represents the closed enrollment-authority child with an explicitly nullable expiry.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityEnrollmentV2
{
    /// <summary>Gets or sets the required canonical enrollment identifier.</summary>
    [JsonPropertyName("enrollmentId")] public required string EnrollmentId { get; set; }
    /// <summary>Gets or sets the required exact enrollment state.</summary>
    [JsonPropertyName("state")] public required string State { get; set; }
    /// <summary>Gets or sets the required canonical UTC issue timestamp.</summary>
    [JsonPropertyName("issuedAtUtc")] public required string IssuedAtUtc { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable canonical UTC expiry timestamp.</summary>
    [JsonPropertyName("expiresAtUtc")] public required string? ExpiresAtUtc { get; set; }
}

/// <summary>Represents the closed key-authority child.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityKeyV2
{
    /// <summary>Gets or sets the required exact authority key identifier.</summary>
    [JsonPropertyName("authorityKeyId")] public required string AuthorityKeyId { get; set; }
    /// <summary>Gets or sets the required non-negative security epoch.</summary>
    [JsonPropertyName("securityEpoch")] public required int SecurityEpoch { get; set; }
}

/// <summary>Represents the closed installation-authority child with a required nullable seat identifier.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityInstallationV2
{
    /// <summary>Gets or sets the required canonical installation identifier.</summary>
    [JsonPropertyName("installationId")] public required string InstallationId { get; set; }
    /// <summary>Gets or sets the required, explicitly nullable canonical seat identifier.</summary>
    [JsonPropertyName("seatId")] public required string? SeatId { get; set; }
}

/// <summary>Represents the closed requested-authority child containing all five required authority blocks.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityRequestedRequestV2
{
    /// <summary>Gets or sets the required release authority.</summary>
    [JsonPropertyName("release")] public required RuntimeEnrollmentAuthorityReleaseV2 Release { get; set; }
    /// <summary>Gets or sets the required binding authority.</summary>
    [JsonPropertyName("binding")] public required RuntimeEnrollmentAuthorityBindingV2 Binding { get; set; }
    /// <summary>Gets or sets the required enrollment authority.</summary>
    [JsonPropertyName("enrollment")] public required RuntimeEnrollmentAuthorityEnrollmentV2 Enrollment { get; set; }
    /// <summary>Gets or sets the required key authority.</summary>
    [JsonPropertyName("key")] public required RuntimeEnrollmentAuthorityKeyV2 Key { get; set; }
    /// <summary>Gets or sets the required installation authority.</summary>
    [JsonPropertyName("installation")] public required RuntimeEnrollmentAuthorityInstallationV2 Installation { get; set; }
}

/// <summary>Represents the closed generation transition containing only requestId and occurredAtUtc timing metadata.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityGenerationTransitionV2
{
    /// <summary>Gets or sets the required exact transition kind.</summary>
    [JsonPropertyName("kind")] public required string Kind { get; set; }
    /// <summary>Gets or sets the required exact transition reason code.</summary>
    [JsonPropertyName("reasonCode")] public required string ReasonCode { get; set; }
    /// <summary>Gets or sets the required canonical idempotency request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the required canonical UTC occurrence timestamp.</summary>
    [JsonPropertyName("occurredAtUtc")] public required string OccurredAtUtc { get; set; }
}

/// <summary>Represents the closed request transition containing only requestedAtUtc timing metadata.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthorityRequestTransitionV2
{
    /// <summary>Gets or sets the required exact transition kind.</summary>
    [JsonPropertyName("kind")] public required string Kind { get; set; }
    /// <summary>Gets or sets the required exact transition reason code.</summary>
    [JsonPropertyName("reasonCode")] public required string ReasonCode { get; set; }
    /// <summary>Gets or sets the required canonical UTC request timestamp.</summary>
    [JsonPropertyName("requestedAtUtc")] public required string RequestedAtUtc { get; set; }
}

/// <summary>Represents the closed PS256 signature envelope; its value is canonical unpadded Base64Url.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeEnrollmentAuthoritySignatureV2
{
    /// <summary>Gets or sets the required exact PS256 algorithm identifier.</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; set; }
    /// <summary>Gets or sets the required exact signing key identifier.</summary>
    [JsonPropertyName("keyId")] public required string KeyId { get; set; }
    /// <summary>Gets or sets the required 342-character canonical unpadded Base64Url signature.</summary>
    [JsonPropertyName("value")] public required string Value { get; set; }
}

/// <summary>
/// Requests provider-owned resolution of an installed Runtime lineage when Website no longer has
/// the historical DistributionGrant. Every identity field and the exact WebSetup proof remain
/// byte-for-byte inputs to the provider verification boundary.
/// </summary>
public sealed class RuntimeReinstallSourceResolutionRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? BootstrapId { get; set; }
    public string? InstallationId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? ReleaseVersion { get; set; }
    public string? KeyThumbprint { get; set; }
    public int? SecurityEpoch { get; set; }
    public string? AttemptId { get; set; }
    public string? AuthoritySchema { get; set; }
    public string? Challenge { get; set; }
    public string? Signature { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Returns only the provider identifiers Website needs to bind one local licence to the exact
/// Runtime authority. A negotiated v2 response may also carry the exact provider-signed generation
/// statement. Subject material is never returned; only its stored digest may cross S2S.
/// </summary>
public sealed record RuntimeReinstallSourceResolutionResponse(
    string Schema,
    string Outcome,
    string RequestId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SourceLicenseId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SourceKind,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GrantRef,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? BindingId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SubjectRefDigestSha256,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] RuntimeReinstallSourceAuthorityProvenance? Authority);

/// <summary>
/// Carries one exact provider-issued authority tuple and its immutable signed-statement bytes.
/// The statement uses canonical unpadded Base64Url so transport never rewrites signed UTF-8 bytes.
/// </summary>
public sealed record RuntimeReinstallSourceAuthorityProvenance(
    string AuthorityLineageId,
    string AuthorityGenerationId,
    string SignedStatementBase64Url);

public sealed class RuntimeWebSetupUpgradeRelayRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? AuthorizationBodyBase64Url { get; set; }
    public string? ProofTimestamp { get; set; }
    public string? ProofJti { get; set; }
    public string? ProofSignature { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeWebSetupUpgradeAuthorization
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? ProductId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? TransitionId { get; set; }
    public string? Capability { get; set; }
    public string? SourceVersion { get; set; }
    public string? TargetVersion { get; set; }
    public List<RuntimeEnrollmentBinaryEvidenceRequest>? Binaries { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeWebSetupUpgradeResponse
{
    public required string Schema { get; init; }
    public required string ProtocolVersion { get; init; }
    public required string Alg { get; init; }
    public required string KeyId { get; init; }
    public required string Audience { get; init; }
    public required string Use { get; init; }
    public required string RequestId { get; init; }
    public required string ProductId { get; init; }
    public required string EnrollmentId { get; init; }
    public required string BindingId { get; init; }
    public required string InstallationId { get; init; }
    public required string SourceVersion { get; init; }
    public required string TargetVersion { get; init; }
    public required int OldSecurityEpoch { get; init; }
    public required int NewSecurityEpoch { get; init; }
    public required string TransitionId { get; init; }
    public required string TransitionDigestSha256 { get; init; }
    public required string Decision { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public required string Signature { get; init; }
}

public sealed class RuntimeEnrollmentUpgradeRelayRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? AuthorizationBodyBase64Url { get; set; }
    public string? ProofTimestamp { get; set; }
    public string? ProofJti { get; set; }
    public string? ProofSignature { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeEnrollmentUpgradeAuthorization
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? ProductId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? InstallationId { get; set; }
    public int? Epoch { get; set; }
    public int? SecurityEpoch { get; set; }
    public string? SourceVersion { get; set; }
    public string? TargetVersion { get; set; }
    public string? TargetInstallerFilename { get; set; }
    public string? TargetInstallerSha256 { get; set; }
    public string? RecoveryReceiptId { get; set; }
    public string? RecoveryReceiptDigestSha256 { get; set; }
    public string? RecoveryHardwareIdHash { get; set; }
    public List<RuntimeEnrollmentBinaryEvidenceRequest>? Binaries { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeEnrollmentUpgradeResponse
{
    public required string Schema { get; init; }
    public required string ProtocolVersion { get; init; }
    public required string Alg { get; init; }
    public required string KeyId { get; init; }
    public required string Audience { get; init; }
    public required string Use { get; init; }
    public required string RequestId { get; init; }
    public required string ProductId { get; init; }
    public required string EnrollmentId { get; init; }
    public required string BindingId { get; init; }
    public required string InstallationId { get; init; }
    public required string SourceVersion { get; init; }
    public required string TargetVersion { get; init; }
    public required int OldSecurityEpoch { get; init; }
    public required int NewSecurityEpoch { get; init; }
    public required string RecoveryReceiptId { get; init; }
    public required string RecoveryReceiptDigestSha256 { get; init; }
    public required string Decision { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public required string Signature { get; init; }
}

public sealed record RuntimeMilestoneAckResponse(
    string Schema,
    string ProtocolVersion,
    string EnrollmentId,
    string SessionId,
    long Sequence,
    string EventId,
    string EvidenceClass,
    string AcceptedAtUtc);

public sealed class RuntimeCriticalRecoveryRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? EnrollmentId { get; set; }
    public string? BindingId { get; set; }
    public string? InstallationId { get; set; }
    public string? EventId { get; set; }
    public int? OldSecurityEpoch { get; set; }
    public int? NewSecurityEpoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RuntimeCriticalRecoveryRefetchRequest
{
    public string? Schema { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? RecoveryId { get; set; }
    public string? BindingId { get; set; }
    public string? InstallationId { get; set; }
    public string? EventId { get; set; }
    public int? NewSecurityEpoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeCriticalRecoveryResponse
{
    public required string Schema { get; init; }
    public required string ProtocolVersion { get; init; }
    public required string Alg { get; init; }
    public required string KeyId { get; init; }
    public required string Audience { get; init; }
    public required string Use { get; init; }
    public required string RecoveryId { get; init; }
    public required string RequestId { get; init; }
    public required string ProductId { get; init; }
    public required string EnrollmentId { get; init; }
    public required string BindingId { get; init; }
    public required string InstallationId { get; init; }
    public required string EventId { get; init; }
    public required int OldSecurityEpoch { get; init; }
    public required int NewSecurityEpoch { get; init; }
    public required string Decision { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public required string Signature { get; init; }
}

public sealed record RuntimeEnrollmentOperationResult<T>(T Response, bool Idempotent, byte[] ExactResponseBody);
public sealed record RuntimeEnrollmentApiError(string Error);

public sealed record RuntimeProofHeaders(string Timestamp, string Jti, string Signature);
