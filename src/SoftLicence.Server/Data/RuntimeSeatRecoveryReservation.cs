namespace SoftLicence.Server.Data;

/// <summary>Stores the provider-owned seat reservation prepared by TKT-000763 for later CAS activation.</summary>
public sealed class RuntimeSeatRecoveryReservation
{
    /// <summary>Gets or sets the opaque provider reservation identifier.</summary>
    public Guid ReservationRef { get; set; }
    /// <summary>Gets or sets the authenticated client owning the request namespace.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the request identifier within that namespace.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the exact product scope.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the exact license scope.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>Gets or sets the exact provider-selected seat.</summary>
    public Guid LicenseSeatId { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation identifier.</summary>
    public Guid RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact opaque provider grant reference.</summary>
    public string ProviderGrantRef { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed reserved, committed, or abandoned lifecycle state.</summary>
    public string State { get; set; } = "RESERVED";
    /// <summary>Gets or sets the authoritative creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the exclusive reservation expiry.</summary>
    public DateTime ExpiresAtUtc { get; set; }
}
