using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Retains a server-authenticated migration acceptance independently of expiring replay nonces.
/// Rows are append-only; their encrypted payload binds all authority and chain dimensions.
/// </summary>
public sealed class HardwareAuthorityMigrationReceipt
{
    /// <summary>Gets or sets the immutable envelope owner identifier.</summary>
    public Guid Id { get; set; }
    /// <summary>Gets or sets the enrollment whose key signed the accepted migration.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Gets or sets the exact accepted request identifier within that enrollment.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the signed proof nonce, retained for uniqueness rather than replay admission.</summary>
    public Guid Jti { get; set; }
    /// <summary>Gets or sets the authenticated predecessor edge, never inferred from matching digests.</summary>
    public Guid? ParentReceiptId { get; set; }
    /// <summary>Gets or sets the enrollment epoch used as authenticated envelope context.</summary>
    public int EnrollmentEpoch { get; set; }
    /// <summary>Gets or sets the immutable encryption domain required by the registry foreign key.</summary>
    [MaxLength(32)]
    public string KeyPurpose { get; set; } = "encryption";
    /// <summary>Gets or sets the encryption key that must remain available while this receipt exists.</summary>
    [MaxLength(64)]
    public string KeyId { get; set; } = string.Empty;
    /// <summary>Gets or sets the authenticated envelope containing the exact server acceptance fact.</summary>
    public string Ciphertext { get; set; } = string.Empty;
}
