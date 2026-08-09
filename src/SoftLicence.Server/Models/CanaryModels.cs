using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public class CanaryPingRequest
{
    public string? Schema { get; set; }
    public string? EventId { get; set; }
    public string? SentAtUtc { get; set; }
    public string HardwareId { get; set; } = string.Empty;
    public string? MachineName { get; set; }
    public string? UserName { get; set; }
    public string? AppVersion { get; set; }
    public string Trigger { get; set; } = string.Empty;
    public string? Details { get; set; }

    // Enriched fields (v2.1.740+)
    public int Severity { get; set; } = 1; // 1=Info, 2=Warning, 3=Critical
    public string? Timestamp { get; set; }
    public string? OsVersion { get; set; }
    public string? ClrVersion { get; set; }
    public bool? DebuggerAttached { get; set; }

    // Audit-only client context. These fields must never be trusted alone for bypass decisions.
    public string? BuildConfiguration { get; set; }
    public string? BaseDirectory { get; set; }
    public string? ProcessPath { get; set; }
    public string? AssemblyLocation { get; set; }
    public bool? IsLocalDevBuild { get; set; }
    public string? LocalDevBuildReason { get; set; }
    public string? FpExe { get; set; }
    public string? FpDll { get; set; }
    public string? FpCore { get; set; }
    public Dictionary<string, string>? BinaryFingerprints { get; set; }
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed record CanaryAckResponse
{
    public required string Schema { get; init; }
    public required string Alg { get; init; }
    public required string KeyId { get; init; }
    public required string EventId { get; init; }
    public required string HardwareId { get; init; }
    public required string AppVersion { get; init; }
    public required string Decision { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public required string ReceiptId { get; init; }
    public required string Signature { get; init; }
}

public sealed class CanaryAckPublicKeyResponse
{
    public required string Schema { get; init; }
    public required string Alg { get; init; }
    public required string KeyId { get; init; }
    public required string PublicKeySpkiBase64 { get; init; }
}

public class SecurityPolicy
{
    public int Level { get; set; }
    public int IntervalMinutes { get; set; } = 15;
    public bool CollectProcesses { get; set; }
    public bool CollectNetwork { get; set; }
}
