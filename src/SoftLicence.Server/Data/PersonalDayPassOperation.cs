namespace SoftLicence.Server.Data;

/// <summary>Historical successful operation receipt. A replay must also return separately observed current authority.</summary>
public sealed class PersonalDayPassOperation
{
    /// <summary>Caller-generated UUID retained across identical retries; changed payload needs a new operation.</summary>
    public Guid Id { get; set; }
    /// <summary>Payment evidence to which this receipt belongs.</summary>
    public Guid PaymentId { get; set; }
    /// <summary>Lowercase SHA-256 of the complete typed request, including observed CAS values.</summary>
    public string RequestDigest { get; set; } = string.Empty;
    /// <summary>License authority version observed after this operation committed, not a current authorization.</summary>
    public Guid ResultAuthorityVersion { get; set; }
    /// <summary>Historical start of this payment's projection when the operation succeeded.</summary>
    public DateTime PeriodStartsAtUtc { get; set; }
    /// <summary>Historical end of this payment's exact elapsed paid projection.</summary>
    public DateTime PeriodExpiresAtUtc { get; set; }
    /// <summary>Historical support choice for this receipt's exact paid period.</summary>
    public bool PeriodPrioritySupport { get; set; }
    /// <summary>Historical aggregate paid horizon after the successful operation.</summary>
    public DateTime PaidThroughUtc { get; set; }
}
