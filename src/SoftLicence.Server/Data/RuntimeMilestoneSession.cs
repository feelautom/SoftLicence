using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeMilestoneSession
{
    public Guid EnrollmentId { get; set; }
    public RuntimeEnrollment? Enrollment { get; set; }

    [MaxLength(36)]
    public string SessionId { get; set; } = string.Empty;

    public int SecurityEpoch { get; set; }
    public long LastSequence { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime LastAcceptedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
