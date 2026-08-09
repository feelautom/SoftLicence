using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public sealed class DistributionBindingInvalidation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProductId { get; set; }

    [MaxLength(64)]
    public string GrantRefDigestSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string ClientId { get; set; } = string.Empty;

    [MaxLength(36)]
    public string RequestId { get; set; } = string.Empty;

    public Guid? BindingId { get; set; }
    public DistributionInstallationBinding? Binding { get; set; }

    [MaxLength(32)]
    public string Reason { get; set; } = string.Empty;

    public DateTime OccurredAtUtc { get; set; }
    public long Epoch { get; set; }
    public DateTime ReceivedAtUtc { get; set; }
}
