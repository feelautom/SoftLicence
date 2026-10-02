namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable activation terminal and its exact replay bytes.</summary>
public sealed class RuntimeSeatRecoveryActivationReceipt
{
    /// <summary>Gets or sets the authenticated S2S client namespace.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the existing authorization request identity reused for activation idempotence.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the exact activation command digest.</summary>
    public string ActivationRequestDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact canonical activation request bytes.</summary>
    public byte[] CanonicalRequestUtf8 { get; set; } = [];
    /// <summary>Gets or sets the exact product scope.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the original authorization request digest.</summary>
    public string RequestDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the immutable recovery-operation reference.</summary>
    public Guid RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the committed reservation reference.</summary>
    public Guid ReservationRef { get; set; }
    /// <summary>Gets or sets the uniquely consumed PROVED preparation reference.</summary>
    public Guid PrepareRef { get; set; }
    /// <summary>Gets or sets the exact W10.2 confirmation request digest.</summary>
    public string ConfirmationRequestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the previous authority lineage frozen by the cutover.</summary>
    public Guid PreviousAuthorityLineageId { get; set; }
    /// <summary>Gets or sets the previous authority generation frozen by the cutover.</summary>
    public Guid PreviousAuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the newly active authority lineage.</summary>
    public Guid NewAuthorityLineageId { get; set; }
    /// <summary>Gets or sets the newly active authority generation.</summary>
    public Guid NewAuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the prepared enrollment identifier frozen by the authority.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Gets or sets the closed COMMITTED or REFUSED terminal state.</summary>
    public string State { get; set; } = string.Empty;
    /// <summary>Gets or sets the terminal HTTP status.</summary>
    public int HttpStatusCode { get; set; }
    /// <summary>Gets or sets the exact terminal media type.</summary>
    public string ContentType { get; set; } = "application/json; charset=utf-8";
    /// <summary>Gets or sets the closed error code for a refusal, or null for committed activation.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the exact frozen response bytes.</summary>
    public byte[] ExactResponseUtf8 { get; set; } = [];
    /// <summary>Gets or sets the authoritative PostgreSQL terminal instant.</summary>
    public DateTime CompletedAtUtc { get; set; }
}
