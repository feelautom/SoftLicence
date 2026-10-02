namespace SoftLicence.Server.Data;

/// <summary>Confirmed-payment evidence, append-only through the paid-pass store; projections live in operation receipts.</summary>
public sealed class PersonalDayPassPayment
{
    /// <summary>Server-generated evidence UUID.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Stable pass to which this payment was applied exactly once.</summary>
    public Guid PassId { get; set; }
    /// <summary>Exact payment-provider name, compared ordinally and persisted with C collation.</summary>
    public string Provider { get; set; } = string.Empty;
    /// <summary>Exact provider account, part of the global payment uniqueness scope.</summary>
    public string ProviderAccount { get; set; } = string.Empty;
    /// <summary>Exact environment identifier; test and live cannot collide.</summary>
    public string Environment { get; set; } = string.Empty;
    /// <summary>Canonical provider payment ID, shared across checkout and invoice events.</summary>
    public string PaymentId { get; set; } = string.Empty;
    /// <summary>Lowercase SHA-256 of immutable payment and pass attribution fields, excluding retry CAS.</summary>
    public string EvidenceDigest { get; set; } = string.Empty;
    /// <summary>Authoritative confirmed purchase time, UTC at millisecond precision.</summary>
    public DateTime PaidAtUtc { get; set; }
    /// <summary>Paid minor units, constrained to EUR 10 multiplied by MaxSeats.</summary>
    public int AmountMinor { get; set; }
    /// <summary>Seat entitlement that becomes active only during this payment's exact period.</summary>
    public int MaxSeats { get; set; }
    /// <summary>Paid priority-support choice for this exact period; false never receives a support extension.</summary>
    public bool PrioritySupport { get; set; }
    /// <summary>Exact elapsed paid duration; 86,400 for a day pass and the Stripe period duration for subscriptions.</summary>
    public int DurationSeconds { get; set; } = 86_400;
    /// <summary>Closed commercial cadence identifier retained with the payment evidence.</summary>
    public string Offer { get; set; } = "day_pass";
    /// <summary>Exact lowercase ISO currency code, constrained to eur.</summary>
    public string Currency { get; set; } = string.Empty;
}
