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
