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
