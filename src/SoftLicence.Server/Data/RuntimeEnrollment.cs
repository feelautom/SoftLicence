using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollment
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [MaxLength(64)]
    public string ClientId { get; set; } = string.Empty;

    public Guid BindingId { get; set; }
    public DistributionInstallationBinding? Binding { get; set; }
    public Guid ProductId { get; set; }
    public Guid LicenseId { get; set; }
    public Guid LicenseSeatId { get; set; }

    [MaxLength(36)]
    public string InstallationId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string HardwareIdHash { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ReleaseVersion { get; set; } = string.Empty;

    [MaxLength(64)]
    public string HandoffDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string? SubjectRefDigestSha256 { get; set; }

    [MaxLength(24)]
    public string ProtocolVersion { get; set; } = string.Empty;

    [MaxLength(16)]
    public string Algorithm { get; set; } = string.Empty;

    [MaxLength(48)]
    public string KeyBackend { get; set; } = string.Empty;

    [MaxLength(16)]
    public string AttestationLevel { get; set; } = string.Empty;

    [MaxLength(4096)]
    public string PublicKeySpkiCiphertext { get; set; } = string.Empty;

    [MaxLength(64)]
    public string PublicKeySpkiKeyId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string PublicKeySpkiKeyPurpose { get; set; } = "encryption";

    [MaxLength(64)]
    public string PublicKeySpkiSha256 { get; set; } = string.Empty;

    [MaxLength(43)]
    public string KeyThumbprint { get; set; } = string.Empty;

    [MaxLength(4096)]
    public string ChallengeCiphertext { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ChallengeKeyId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string ChallengeKeyPurpose { get; set; } = "encryption";

    [MaxLength(64)]
    public string ChallengeDigestSha256 { get; set; } = string.Empty;

    [MaxLength(16)]
    public string State { get; set; } = "PENDING";

    public int Epoch { get; set; } = 1;
    public int SecurityEpoch { get; set; } = 1;
    public DateTime ChallengeExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? ActivatedAtUtc { get; set; }
    public DateTime? ChallengeConsumedAtUtc { get; set; }
    public DateTime? InvalidatedAtUtc { get; set; }
    public long AuthorityEpoch { get; set; }

    [MaxLength(64)]
    public string? InvalidationReason { get; set; }
}
