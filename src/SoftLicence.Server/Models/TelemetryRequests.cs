using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public class TelemetryBaseRequest
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public required string HardwareId { get; set; }
    public required string AppName { get; set; }
    public string? Version { get; set; }
    public required string EventName { get; set; }
}

public class TelemetryEventRequest : TelemetryBaseRequest
{
    public Dictionary<string, string>? Properties { get; set; }
}

public class TelemetryDiagnosticRequest : TelemetryBaseRequest
{
    public int Score { get; set; }
    public List<DiagnosticResult>? Results { get; set; }
    public List<DiagnosticPort>? Ports { get; set; }
}

public class DiagnosticResult
{
    public string? ModuleName { get; set; }
    public bool Success { get; set; }
    public string? Severity { get; set; } // Info, Warning, Error
    public string? Message { get; set; }
}

public class DiagnosticPort
{
    public string? Name { get; set; }
    public int ExternalPort { get; set; }
    public string? Protocol { get; set; }
}

public class TelemetryErrorRequest : TelemetryBaseRequest
{
    public string? ErrorType { get; set; }
    public string? Message { get; set; }
    public string? StackTrace { get; set; }
}

public class TelemetryResponse
{
    public Guid Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string HardwareId { get; set; } = string.Empty;
    public string AppName { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string EventName { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public object? Data { get; set; }
}
