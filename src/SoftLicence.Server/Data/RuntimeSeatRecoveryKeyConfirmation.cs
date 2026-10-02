namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable client-scoped key-confirmation terminal for exact replay.</summary>
public sealed class RuntimeSeatRecoveryKeyConfirmation
{
    /// <summary>Gets or sets the authenticated S2S client namespace.</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the preparation identity within the authenticated client namespace.</summary>
    public Guid PrepareRef { get; set; }
    /// <summary>Gets or sets the SHA-256 digest of the exact confirmation request bytes.</summary>
    public string ConfirmationRequestSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact canonical confirmation request bytes.</summary>
    public byte[] CanonicalRequestUtf8 { get; set; } = [];
    /// <summary>Gets or sets the closed PROVED or REFUSED terminal state.</summary>
    public string State { get; set; } = string.Empty;
    /// <summary>Gets or sets the terminal HTTP status.</summary>
    public int HttpStatusCode { get; set; }
    /// <summary>Gets or sets the terminal response media type.</summary>
    public string ContentType { get; set; } = "application/json; charset=utf-8";
    /// <summary>Gets or sets a closed refusal code, or null for PROVED.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the exact frozen terminal response bytes.</summary>
    public byte[] ExactResponseUtf8 { get; set; } = [];
    /// <summary>Gets or sets the authoritative terminal instant.</summary>
    public DateTime CompletedAtUtc { get; set; }
}
