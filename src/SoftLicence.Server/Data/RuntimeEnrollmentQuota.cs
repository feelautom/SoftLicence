using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentQuota
{
    [MaxLength(48)]
    public string Scope { get; set; } = string.Empty;

    [MaxLength(128)]
    public string SubjectPseudonym { get; set; } = string.Empty;

    public DateTime WindowStartedAtUtc { get; set; }
    public int Count { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
