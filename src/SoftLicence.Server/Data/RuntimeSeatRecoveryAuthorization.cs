namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable client-scoped terminal recovery authorization result for exact replay.</summary>
public sealed class RuntimeSeatRecoveryAuthorization
{
    /// <summary>Gets or sets the authenticated S2S client namespace.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the canonical client-scoped request identifier.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the domain-separated lowercase request digest.</summary>
    public string RequestDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the immutable Website recovery-operation identifier.</summary>
    public Guid RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the immutable Website recovery-operation digest.</summary>
    public string RecoveryDigestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact canonical request bytes retained for audit equality.</summary>
    public byte[] CanonicalRequestUtf8 { get; set; } = [];
    /// <summary>Gets or sets the selected reservation, or null for a terminal refusal before reservation.</summary>
    public Guid? ReservationRef { get; set; }
    /// <summary>Gets or sets the closed authorized or refused decision.</summary>
    public string Decision { get; set; } = string.Empty;
    /// <summary>Gets or sets the terminal HTTP status code.</summary>
    public int HttpStatusCode { get; set; }
    /// <summary>Gets or sets the exact terminal media type.</summary>
    public string ContentType { get; set; } = "application/json; charset=utf-8";
    /// <summary>Gets or sets the closed refusal code, or null for authorized.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the exact terminal UTF-8 bytes returned for every replay.</summary>
    public byte[] ExactResponseUtf8 { get; set; } = [];
    /// <summary>Gets or sets the authoritative terminal completion instant.</summary>
    public DateTime CompletedAtUtc { get; set; }
}
