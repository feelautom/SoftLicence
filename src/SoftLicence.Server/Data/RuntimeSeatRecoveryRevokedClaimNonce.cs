namespace SoftLicence.Server.Data;

/// <summary>Records a provider-revoked plaintext seat-claim nonce independently from AEAD frame nonces.</summary>
public sealed class RuntimeSeatRecoveryRevokedClaimNonce
{
    /// <summary>Gets or sets the globally unique canonical nonce carried inside the authenticated plaintext.</summary>
    public Guid Nonce { get; set; }

    /// <summary>Gets or sets the provider time at which future use became forbidden.</summary>
    public DateTime RevokedAtUtc { get; set; }

    /// <summary>Gets or sets the bounded internal reason without customer or claim material.</summary>
    public string ReasonCode { get; set; } = string.Empty;
}
