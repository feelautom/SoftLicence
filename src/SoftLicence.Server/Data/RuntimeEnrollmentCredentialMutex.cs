using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentCredentialMutex
{
    public Guid BindingId { get; set; }

    [MaxLength(16)]
    public string TransitionKind { get; set; } = string.Empty;

    [MaxLength(64)]
    public string OwnerReference { get; set; } = string.Empty;

    public int ExpectedEpoch { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}
