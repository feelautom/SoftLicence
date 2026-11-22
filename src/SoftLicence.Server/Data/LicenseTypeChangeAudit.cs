using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Append-only journal of licence-type changes applied through the analytics write route (TKT-002781). One row per
/// applied batch, written in the same transaction as the changes, so a changed catalogue always has a trace of who
/// changed what, before and after. It never contains a private key, an API secret or a certificate.
/// </summary>
public class LicenseTypeChangeAudit
{
    /// <summary>Row identifier.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>UTC time of the commit.</summary>
    public DateTime AppliedAtUtc { get; set; }

    /// <summary>Product the batch targeted (the parent product for a plugin creation).</summary>
    public Guid ProductId { get; set; }

    /// <summary>Analytics key that applied the batch.</summary>
    public Guid AnalyticsKeyId { get; set; }

    /// <summary>Caller address as resolved by the server, when known.</summary>
    [MaxLength(64)]
    public string? CallerIp { get; set; }

    /// <summary>Optional free reference given by the caller (ticket, instance), never trusted for authorization.</summary>
    [MaxLength(200)]
    public string? RequestedBy { get; set; }

    /// <summary>Preview fingerprint the batch was applied with.</summary>
    [MaxLength(64)]
    public string PreviewHash { get; set; } = string.Empty;

    /// <summary>Number of operations in the batch.</summary>
    public int OperationCount { get; set; }

    /// <summary>JSON of the normalized operations with their before and after values (no secret).</summary>
    public string ChangesJson { get; set; } = "[]";
}
