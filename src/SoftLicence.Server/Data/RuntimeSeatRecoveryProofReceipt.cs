namespace SoftLicence.Server.Data;

/// <summary>Stores the immutable provider proof fact consumed later by TKT-000767.</summary>
public sealed class RuntimeSeatRecoveryProofReceipt
{
    /// <summary>Gets or sets the authenticated S2S client namespace.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the proven preparation reference.</summary>
    public Guid PrepareRef { get; set; }
    /// <summary>Gets or sets the exact product scope.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the authorization request identifier.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the authorization request digest.</summary>
    public string RequestDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the immutable recovery-operation reference.</summary>
    public Guid RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact reservation reference.</summary>
    public Guid ReservationRef { get; set; }
    /// <summary>Gets or sets the prepared enrollment identifier.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Gets or sets the prepared authority-generation identifier.</summary>
    public Guid AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the proven public-key digest.</summary>
    public string PublicKeySpkiSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the digest of the exact confirmation request.</summary>
    public string ConfirmationRequestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the only state emitted by TKT-000773.</summary>
    public string State { get; set; } = "PROVED";
    /// <summary>Gets or sets the authoritative proof instant.</summary>
    public DateTime ProvedAtUtc { get; set; }
    /// <summary>Gets or sets the preparation expiry snapshot used in the minimum.</summary>
    public DateTime PreparationExpiresAtUtc { get; set; }
    /// <summary>Gets or sets the reservation expiry snapshot used in the minimum.</summary>
    public DateTime ReservationExpiresAtUtc { get; set; }
    /// <summary>Gets or sets the exact minimum of preparation and reservation expiries.</summary>
    public DateTime ExpiresAtUtc { get; set; }
}
