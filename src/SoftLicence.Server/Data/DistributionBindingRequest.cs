using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionBindingRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [MaxLength(64)]
    public string ClientId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string RequestId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Operation { get; set; } = string.Empty;

    [MaxLength(64)]
    public string PayloadDigest { get; set; } = string.Empty;

    public Guid? BindingId { get; set; }
    public DistributionInstallationBinding? Binding { get; set; }

    [MaxLength(8192)]
    public string ResponseJson { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }
}
