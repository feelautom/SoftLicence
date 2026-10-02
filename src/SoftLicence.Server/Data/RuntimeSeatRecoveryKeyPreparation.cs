namespace SoftLicence.Server.Data;

/// <summary>Stores one provider-protected Runtime recovery key preparation and its frozen response.</summary>
public sealed class RuntimeSeatRecoveryKeyPreparation
{
    /// <summary>Gets or sets the opaque provider preparation reference.</summary>
    public Guid PrepareRef { get; set; }
    /// <summary>Gets or sets the authenticated S2S client namespace.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact product scope carried only by the authenticated outer.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the original authorization request identifier.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the original authorization digest.</summary>
    public string RequestDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the immutable Website recovery-operation reference.</summary>
    public Guid RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the reserved provider resource.</summary>
    public Guid ReservationRef { get; set; }
    /// <summary>Gets or sets the prepared Runtime enrollment identifier.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Gets or sets the prepared signed-generation identifier.</summary>
    public Guid AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the exact canonical preparation request bytes.</summary>
    public byte[] CanonicalRequestUtf8 { get; set; } = [];
    /// <summary>Gets or sets the lowercase SHA-256 digest of the canonical DER SPKI.</summary>
    public string PublicKeySpkiSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the provider-protected canonical DER SPKI.</summary>
    public string PublicKeySpkiCiphertext { get; set; } = string.Empty;
    /// <summary>Gets or sets the encryption key identifier protecting the SPKI.</summary>
    public string PublicKeySpkiKeyId { get; set; } = string.Empty;
    /// <summary>Gets or sets the lowercase SHA-256 digest of the 32-byte challenge.</summary>
    public string ChallengeDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the provider-protected 32-byte challenge.</summary>
    public string ChallengeCiphertext { get; set; } = string.Empty;
    /// <summary>Gets or sets the encryption key identifier protecting the challenge.</summary>
    public string ChallengeKeyId { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact confirmation audience.</summary>
    public string ConfirmAudience { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact frozen HTTP response bytes.</summary>
    public byte[] ExactResponseUtf8 { get; set; } = [];
    /// <summary>Gets or sets the provider creation instant.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the exclusive preparation expiry.</summary>
    public DateTime ExpiresAtUtc { get; set; }
    /// <summary>Gets or sets the atomic one-shot consumption instant, if consumed.</summary>
    public DateTime? ChallengeConsumedAtUtc { get; set; }
}
