namespace SoftLicence.Server.Data;

/// <summary>Stable paid-pass identity. One product/subject owns one key; current expiry remains on License.</summary>
public sealed class PersonalDayPass
{
    /// <summary>Server-generated immutable pass UUID.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Product scope shared by the subject and license foreign keys.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Exact commercial subject UUID, never inferred from customer email.</summary>
    public Guid CommercialSubjectId { get; set; }
    /// <summary>Stable license UUID; repurchase never replaces the key.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>
    /// Most recently reconciled paid horizon. Before the first activation of a newly issued pass this is
    /// a provisional payment-time projection; activation reanchors it once and then it matches licence expiry.
    /// </summary>
    public DateTime PaidThroughUtc { get; set; }
    /// <summary>
    /// Expiry that existed before the first pass, or the first activation instant for a newly issued pass.
    /// Null may represent deferred paid time only after the shared current-receipt, ownership, type and activation-history proof.
    /// </summary>
    public DateTime? InitialPaidThroughUtc { get; set; }
    /// <summary>Priority-support entitlement for the currently materialized paid period.</summary>
    public bool CurrentPrioritySupport { get; set; }
}
