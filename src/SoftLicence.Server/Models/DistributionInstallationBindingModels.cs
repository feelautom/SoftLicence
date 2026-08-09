using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public sealed class DistributionEntitlementIssueRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? SoftLicenceLicenseId { get; set; }
    public string? GrantRefDigestSha256 { get; set; }
    public string? SubjectRef { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record DistributionEntitlementIssueResponse(
    string Schema,
    string EntitlementRef,
    string ExpiresAtUtc);

public sealed class DistributionInstallationFinalizeRequest
{
    private bool? _allowSameAuthorityRecovery;

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
    public DistributionReleaseEvidence? Release { get; set; }
    public List<DistributionBinaryEvidence>? Binaries { get; set; }

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

public sealed record DistributionApiError(string Error);
