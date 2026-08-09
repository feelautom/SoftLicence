using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionInstallationBinding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProductId { get; set; }
    public Guid LicenseId { get; set; }
    public Guid LicenseSeatId { get; set; }
    public Guid EntitlementId { get; set; }

    [MaxLength(64)]
    public string? SubjectRefDigestSha256 { get; set; }

    [MaxLength(36)]
    public string GrantRef { get; set; } = string.Empty;

    [MaxLength(64)]
    public string GrantRefDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string HandoffDigestSha256 { get; set; } = string.Empty;

    public DateTime? HandoffIssuedAtUtc { get; set; }
    public DateTime? HandoffExpiresAtUtc { get; set; }
    public DateTime? DownloadCompletedAtUtc { get; set; }

    [MaxLength(36)]
    public string InstallationId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string HardwareIdHash { get; set; } = string.Empty;

    [MaxLength(64)]
    public string Version { get; set; } = string.Empty;

    [MaxLength(200)]
    public string InstallerFilename { get; set; } = string.Empty;

    [MaxLength(64)]
    public string InstallerSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ExecutableSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string NativeDllSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string CoreSha256 { get; set; } = string.Empty;

    [MaxLength(16)]
    public string ApprovedBinariesSource { get; set; } = string.Empty;

    [MaxLength(16)]
    public string State { get; set; } = "active";

    public DateTime BoundAtUtc { get; set; }
    public Guid? SupersededBindingId { get; set; }
    public int InitialSecurityEpoch { get; set; } = 1;
    public DateTime? InvalidatedAtUtc { get; set; }

    [MaxLength(64)]
    public string? InvalidationReason { get; set; }

}
