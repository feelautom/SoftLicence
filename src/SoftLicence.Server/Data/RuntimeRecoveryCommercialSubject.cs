namespace SoftLicence.Server.Data;

/// <summary>
/// Identifies one provider-owned contractual holder inside an exact product scope.
/// The UUID is opaque and must never be derived from customer, license, seat, binding, or Website data.
/// </summary>
public sealed class RuntimeRecoveryCommercialSubject
{
    /// <summary>Gets or sets the provider-private UUID, interpreted only together with <see cref="ProductId"/>.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the exact product boundary in which the opaque subject exists.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the product authority protected from deletion while this subject exists.</summary>
    public Product? Product { get; set; }

    /// <summary>Gets or sets the UTC instant at which SoftLicence explicitly persisted the subject.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
