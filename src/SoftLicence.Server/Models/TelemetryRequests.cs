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
    /// <summary>
    /// Gets or sets the optional wire classification. The ingestion service recognizes only the
    /// exact ordinal value <c>Error</c>; every other value remains an event unless the legacy name
    /// fallback applies.
    /// </summary>
    public string? Type { get; set; }

    public Dictionary<string, string>? Properties { get; set; }

    /// <summary>
    /// Gets or sets the compatibility envelope emitted by clients that serialize the telemetry
    /// request beneath <c>req</c>. Outer routing identity remains authoritative while type and
    /// properties may be recovered from this envelope. Producers such as YOUR_APP_NAME send a plain
    /// string here; any value that is not an object is ignored and never rejects the request.
    /// </summary>
    [JsonConverter(typeof(TelemetryEventCompatibilityEnvelopeConverter))]
    public TelemetryEventCompatibilityEnvelope? Req { get; set; }
}

/// <summary>
/// Represents the bounded compatibility payload accepted beneath the event request's <c>req</c>
/// property. It intentionally excludes routing identity and recursive envelopes.
/// </summary>
public sealed class TelemetryEventCompatibilityEnvelope
{
    /// <summary>
    /// Gets or sets the optional nested wire classification.
    /// </summary>
    public string? Type { get; set; }

    /// <summary>
    /// Gets or sets the nested event properties retained by legacy client serializers.
    /// </summary>
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
