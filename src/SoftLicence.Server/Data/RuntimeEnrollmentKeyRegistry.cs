using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentKeyRegistry
{
    [MaxLength(32)]
    public string Purpose { get; set; } = string.Empty;

    [MaxLength(64)]
    public string KeyId { get; set; } = string.Empty;

    [MaxLength(64)]
    public string MaterialDigestSha256 { get; set; } = string.Empty;

    [MaxLength(16)]
    public string State { get; set; } = string.Empty;

    public int Epoch { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? RetainUntilUtc { get; set; }
    public DateTime? RetiredAtUtc { get; set; }
}
