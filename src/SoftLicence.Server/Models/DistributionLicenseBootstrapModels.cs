using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public class DistributionLicenseBootstrapIssueRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? BindingId { get; set; }
    public string? EnrollmentId { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class DistributionLicenseBootstrapRemintRequest : DistributionLicenseBootstrapIssueRequest
{
    public string? BootstrapId { get; set; }
}

public sealed class DistributionLicenseBootstrapRecoverRequest : DistributionLicenseBootstrapIssueRequest;

public sealed record DistributionLicenseBootstrapIssuedResponse(
    string Schema, string BootstrapId, string Capability,
    string CapabilityExpiresAtUtc, string AuthorizationExpiresAtUtc);

public sealed class RuntimeLicenseBootstrapRedeemRequest
{
    public string? Schema { get; set; }
    public string? RequestId { get; set; }
    public string? ProductId { get; set; }
    public string? BindingId { get; set; }
    public string? InstallationId { get; set; }
    public string? BootstrapId { get; set; }
    public string? Capability { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record RuntimeLicenseBootstrapResultResponse(
    string Schema, string RequestId, string BootstrapId, string LicenseFile);

public sealed record DistributionLicenseBootstrapOperationResult<T>(
    T Response, bool Idempotent, byte[] ExactResponseBody);
