namespace SoftLicence.Server.Data;

public sealed class RuntimeEnrollmentAuthorityState
{
    public short Id { get; set; } = 1;
    public long Epoch { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}
