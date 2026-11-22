using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Durable administrative RELEASE remembered for one exact product, licence, authoritative seat hardware and cause.
/// The unique scope is never normalized; PostgreSQL ordinal text equality is the authority.
/// </summary>
public sealed class SecurityLockReleaseDecision
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProductId { get; set; }
    public Guid LicenseId { get; set; }

    [MaxLength(128)]
    public string HardwareId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string Cause { get; set; } = string.Empty;

    public bool IsActive { get; set; }
    public DateTime CreatedAtUtc { get; set; }

    [MaxLength(100)]
    public string CreatedBy { get; set; } = string.Empty;

    public Guid SourceSecurityLockReportId { get; set; }
    public DateTime ActivatedAtUtc { get; set; }

    [MaxLength(100)]
    public string ActivatedBy { get; set; } = string.Empty;

    public int ActivationCount { get; set; }
    public DateTime? RevokedAtUtc { get; set; }

    [MaxLength(100)]
    public string? RevokedBy { get; set; }

    public int CoveredDetectionCount { get; set; }
    public DateTime? LastCoveredAtUtc { get; set; }
}
