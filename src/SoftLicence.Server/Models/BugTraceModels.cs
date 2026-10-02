using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

public sealed class BugTraceSubmitRequest
{
    public string? LicenseKey { get; set; }
    public string? HardwareId { get; set; }
    public string ProjectId { get; set; } = string.Empty;
    public BugTraceTicketBody Ticket { get; set; } = new();
}

public sealed class BugTraceTicketBody
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string Type { get; set; } = "BUG";
    public string Priority { get; set; } = "NORMAL";
    public string? ReporterEmail { get; set; }
    public List<string>? Tags { get; set; }
}

public sealed class BugTraceCommentRequest
{
    public string? LicenseKey { get; set; }
    public string? HardwareId { get; set; }
    public string ProjectId { get; set; } = string.Empty;
    public string TicketNumber { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string? AuthorName { get; set; }
    public string? AuthorEmail { get; set; }
}

public sealed class BugTraceTicketsRequest
{
    public string Email { get; set; } = string.Empty;
    public string? LicenseKey { get; set; }
    public string? HardwareId { get; set; }
    public string ProjectId { get; set; } = string.Empty;
}

/// <summary>
/// Carries one identified automatic crash or error report to the dedicated report-only endpoint.
/// The license key is used only to resolve server-side authority and is never forwarded to BugTrace.
/// </summary>
public sealed class BugTraceAutoReportRequest
{
    public string Schema { get; set; } = string.Empty;
    public string ReportId { get; set; } = string.Empty;
    public string LicenseKey { get; set; } = string.Empty;
    public string HardwareId { get; set; } = string.Empty;
    public string ProjectId { get; set; } = string.Empty;
    public BugTraceAutoReportBody Report { get; set; } = new();

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Defines the closed, client-supplied diagnostic envelope accepted for automatic reports.
/// Server-owned BugTrace metadata is deliberately absent from this type.
/// </summary>
public sealed class BugTraceAutoReportBody
{
    public string Kind { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public string ErrorType { get; set; } = string.Empty;
    public string ErrorSource { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string? StackTrace { get; set; }
    public string Fingerprint { get; set; } = string.Empty;

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// Acknowledges durable server acceptance without granting access to the resulting BugTrace ticket.
/// </summary>
public sealed record BugTraceAutoReportAcceptedResponse(
    string Schema,
    string ReportId,
    string Status,
    bool Duplicate,
    string? TicketNumber);

/// <summary>
/// Returns a stable machine-readable failure code without reflecting sensitive request fields.
/// </summary>
public sealed record BugTraceAutoReportErrorResponse(string ErrorCode);

/// <summary>Identity envelope shared by Desktop SupportCase proxy operations.</summary>
public class BugTraceSupportIdentityRequest
{
    /// <summary>Plaintext established licence key, nonempty and at most 256 UTF-16 units; Trim/UpperInvariant selects server authority, and the value is never forwarded.</summary>
    public string? LicenseKey { get; set; }
    /// <summary>Current client hardware identity, nonempty, at most 256 UTF-16 units and not the unknown marker; mismatch is allowed only for this human support policy.</summary>
    public string? HardwareId { get; set; }
    /// <summary>Public project identifier that must match the configured server boundary.</summary>
    public string ProjectId { get; set; } = string.Empty;
}

/// <summary>Requests creation of one customer-owned SupportCase through the Desktop proxy.</summary>
public sealed class BugTraceSupportCaseCreateRequest : BugTraceSupportIdentityRequest
{
    /// <summary>Claimed reporter that must match the authoritative licence customer.</summary>
    public string ReporterEmail { get; set; } = string.Empty;
    /// <summary>Legacy optional body field; only the exact Idempotency-Key header controls provider replay.</summary>
    public string? IdempotencyKey { get; set; }
    /// <summary>Bounded human-authored case fields; identity and source are selected by the server.</summary>
    public BugTraceSupportCaseBody SupportCase { get; set; } = new();
}

/// <summary>Contains the provider-safe fields accepted for a Desktop SupportCase.</summary>
public sealed class BugTraceSupportCaseBody
{
    /// <summary>Human-readable case title, preserved verbatim with a 240 UTF-16 code-unit limit.</summary>
    public string Title { get; set; } = string.Empty;
    /// <summary>Human support details, preserved verbatim up to 50000 UTF-16 code units and excluded from access logs.</summary>
    public string Description { get; set; } = string.Empty;
    /// <summary>Provider category; provider validation remains authoritative.</summary>
    public string Category { get; set; } = "GENERAL";
    /// <summary>Provider priority; provider validation remains authoritative.</summary>
    public string Priority { get; set; } = "NORMAL";
    /// <summary>Compatibility input; the server always sends DESKTOP regardless of this value.</summary>
    public string Source { get; set; } = "DESKTOP";
    /// <summary>Optional list of at most five distinct lowercase D-form UUIDs; null or empty means no attachments. Provider checks owner, project, scan and binding.</summary>
    public List<string>? AttachmentIds { get; set; }
}

/// <summary>Requests the bounded SupportCase history owned by one licence customer.</summary>
public sealed class BugTraceSupportCaseListRequest : BugTraceSupportIdentityRequest
{
    /// <summary>Claimed reporter that must match the authoritative licence customer.</summary>
    public string ReporterEmail { get; set; } = string.Empty;
    /// <summary>Requested page size, clamped to 1–200 inclusive; default 200.</summary>
    public int Limit { get; set; } = 200;
    /// <summary>Zero-based provider history offset, clamped to 0–100000 inclusive; default zero.</summary>
    public int Offset { get; set; }
}

/// <summary>Requests one customer-authored message on an owned SupportCase.</summary>
public sealed class BugTraceSupportCaseMessageRequest : BugTraceSupportIdentityRequest
{
    /// <summary>Human-authored reply; nonempty, limited to 50000 UTF-16 code units and excluded from access logs.</summary>
    public string Content { get; set; } = string.Empty;
    /// <summary>Optional list of at most five distinct lowercase D-form UUIDs; null or empty means no attachments. Provider checks owner, project, scan and binding.</summary>
    public List<string>? AttachmentIds { get; set; }
}
