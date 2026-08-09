using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeCriticalIncident
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnrollmentId { get; set; }
    public RuntimeEnrollment? Enrollment { get; set; }
    public Guid BindingId { get; set; }
    public Guid ProductId { get; set; }

    [MaxLength(36)]
    public string InstallationId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string EventId { get; set; } = string.Empty;

    [MaxLength(128)]
    public string Trigger { get; set; } = string.Empty;

    [MaxLength(16)]
    public string State { get; set; } = "OPEN";

    public int OpenedSecurityEpoch { get; set; }
    public long OpenedAuthorityEpoch { get; set; }
    public DateTime OpenedAtUtc { get; set; }

    public Guid? RecoveryId { get; set; }
    public RuntimeCriticalRecovery? Recovery { get; set; }
    public int? RecoveredSecurityEpoch { get; set; }
    public long? RecoveredAuthorityEpoch { get; set; }
    public DateTime? RecoveredAtUtc { get; set; }
}
