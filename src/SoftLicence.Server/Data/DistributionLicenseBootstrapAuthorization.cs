using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionLicenseBootstrapAuthorization
{
    public Guid Id { get; set; }
    public Guid ProductId { get; set; }
    public Guid LicenseId { get; set; }
    public Guid LicenseSeatId { get; set; }
    public Guid EntitlementId { get; set; }
    public Guid BindingId { get; set; }
    public Guid RuntimeEnrollmentId { get; set; }
    [MaxLength(64)] public string ClientId { get; set; } = string.Empty;
    [MaxLength(64)] public string GrantRefDigestSha256 { get; set; } = string.Empty;
    [MaxLength(64)] public string SubjectRefDigestSha256 { get; set; } = string.Empty;
    [MaxLength(64)] public string HandoffDigestSha256 { get; set; } = string.Empty;
    [MaxLength(36)] public string InstallationId { get; set; } = string.Empty;
    [MaxLength(64)] public string HardwareIdHash { get; set; } = string.Empty;
    [MaxLength(64)] public string ReleaseVersion { get; set; } = string.Empty;
    [MaxLength(64)] public string ApprovedBinariesDigestSha256 { get; set; } = string.Empty;
    [MaxLength(64)] public string RuntimePublicKeySpkiSha256 { get; set; } = string.Empty;
    [MaxLength(43)] public string RuntimeKeyThumbprint { get; set; } = string.Empty;
    public int RuntimeEpoch { get; set; }
    public int SecurityEpoch { get; set; }
    public long AuthorityEpoch { get; set; }
    [MaxLength(64)] public string Audience { get; set; } = string.Empty;
    [MaxLength(32)] public string Use { get; set; } = string.Empty;
    [MaxLength(16)] public string State { get; set; } = "ISSUED";
    public DateTime IssuedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? ConsumedAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    [MaxLength(36)] public string? ConsumedRequestId { get; set; }
    [MaxLength(36)] public string? ConsumedJti { get; set; }
    [MaxLength(64)] public string? ConsumedBodyDigestSha256 { get; set; }
    [MaxLength(64)] public string? ConsumedProofDigestSha256 { get; set; }
    public byte[]? ResponseCiphertext { get; set; }
    [MaxLength(64)] public string? ResponseKeyId { get; set; }
    public int? ResponsePlaintextLength { get; set; }
    public int? ResponseCiphertextLength { get; set; }
    public DateTime? ReplayExpiresAtUtc { get; set; }
}
