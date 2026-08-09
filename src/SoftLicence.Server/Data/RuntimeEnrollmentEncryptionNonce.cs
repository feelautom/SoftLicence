using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentEncryptionNonce
{
    [MaxLength(32)]
    public string Purpose { get; set; } = "encryption";

    [MaxLength(64)]
    public string KeyId { get; set; } = string.Empty;

    [MaxLength(12)]
    public byte[] Nonce { get; set; } = [];

    [MaxLength(32)]
    public string OwnerType { get; set; } = string.Empty;

    public Guid OwnerId { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
