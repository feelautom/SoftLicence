namespace SoftLicence.Server.Data;

/// <summary>One immutable acquired order. Failed CAS attempts never insert this row.</summary>
public sealed class CommercialOrderEvidence
{
    /// <summary>Internal evidence identity shared by all transport attempts.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Effective licensed product, including plugin resolution.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Opaque Website order identity, unique within the product.</summary>
    public string OrderId { get; set; } = "";
    /// <summary>Immutable attributed license.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>Subject proven by the ownership version at attribution.</summary>
    public Guid CommercialSubjectId { get; set; }
    /// <summary>Wire contract version.</summary>
    public int Version { get; set; } = 2;
    /// <summary>Explicit purchase classification, never inferred from price.</summary>
    public string Nature { get; set; } = "";
    /// <summary>Actual payment in minor currency units, independent of catalogue.</summary>
    public int PaidAmountMinor { get; set; }
    /// <summary>Exact currency code.</summary>
    public string Currency { get; set; } = "eur";
    /// <summary>Producer route discriminator preventing cross-route double attribution.</summary>
    public string Producer { get; set; } = "";
    /// <summary>Route receipt identity, stable across transport attempts.</summary>
    public string ReceiptKey { get; set; } = "";
    /// <summary>Canonical immutable purchase and entitlement terms, excluding operation and CAS.</summary>
    public string AttributionDigest { get; set; } = "";
}

/// <summary>Globally unique V2 attempt tied to exactly one acquired order and exact request digest.</summary>
public sealed class CommercialEvidenceOperation
{
    /// <summary>Website operation identity across every producer.</summary>
    public Guid Id { get; set; }
    /// <summary>Acquired order; multiple attempts may share one immutable attribution.</summary>
    public Guid OrderEvidenceId { get; set; }
    /// <summary>Exact canonical request digest including operation and CAS.</summary>
    public string RequestDigest { get; set; } = "";
}
