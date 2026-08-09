using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class CanaryAckKeyRegistry
{
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

public sealed class CanaryAckKeyRegistryState
{
    public int Id { get; set; }
    public int RegistryVersion { get; set; }

    [MaxLength(64)]
    public string ContentDigestSha256 { get; set; } = string.Empty;

    public DateTime UpdatedAtUtc { get; set; }
}
