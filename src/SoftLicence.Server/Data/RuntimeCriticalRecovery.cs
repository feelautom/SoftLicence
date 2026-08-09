using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeCriticalRecovery
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnrollmentId { get; set; }
    public Guid BindingId { get; set; }
    public Guid ProductId { get; set; }

    [MaxLength(36)]
    public string InstallationId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string RequestedEventId { get; set; } = string.Empty;

    public int OldSecurityEpoch { get; set; }
    public int NewSecurityEpoch { get; set; }
    public int ResolvedIncidentCount { get; set; }
    public long AuthorityEpoch { get; set; }

    [MaxLength(64)]
    public string RecoveredByClientId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string RecoveredByKeyId { get; set; } = string.Empty;

    public DateTime RecoveredAtUtc { get; set; }
}

public sealed class RuntimeCriticalRecoveryReceipt
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RecoveryId { get; set; }
    public RuntimeCriticalRecovery? Recovery { get; set; }

    [MaxLength(36)]
    public string RequestId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string RequestDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string RequestedByClientId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string RequestedByKeyId { get; set; } = string.Empty;

    public DateTime IssuedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? DeliveryPurgedAtUtc { get; set; }
    public byte[]? ExactResponseBody { get; set; }
}
