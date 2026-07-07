namespace SoftLicence.Server.Models;

public class CanaryPingRequest
{
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
}

public class SecurityPolicy
{
    public int Level { get; set; }
    public int IntervalMinutes { get; set; } = 15;
    public bool CollectProcesses { get; set; }
    public bool CollectNetwork { get; set; }
}
