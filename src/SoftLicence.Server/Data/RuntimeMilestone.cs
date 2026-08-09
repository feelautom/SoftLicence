using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeMilestone
{
    public Guid EnrollmentId { get; set; }

    [MaxLength(36)]
    public string SessionId { get; set; } = string.Empty;

    public RuntimeMilestoneSession? Session { get; set; }
    public long Sequence { get; set; }

    [MaxLength(36)]
    public string EventId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string Jti { get; set; } = string.Empty;

    [MaxLength(64)]
    public string Code { get; set; } = string.Empty;

    [MaxLength(24)]
    public string EvidenceClass { get; set; } = "client_declared";

    [MaxLength(64)]
    public string BodyDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ProofDigestSha256 { get; set; } = string.Empty;

    public long AuthorityEpoch { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public DateTime AcceptedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
