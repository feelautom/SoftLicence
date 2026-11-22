using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// One distinct machine-identity observation reported by a UUID-aware client (TKT-001277 lot 2a).
/// Investigation evidence only: nothing here grants or removes a licence right. A row is unique per
/// product, submitted hardware identifier and exact evidence digest; repeated identical reports only
/// advance <see cref="LastSeenAtUtc"/> and <see cref="ObservationCount"/>.
/// </summary>
public sealed class MachineEvidenceObservation
{
    /// <summary>Gets or sets the row identifier.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Gets or sets the product that received the report.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the submitted 16-character uppercase hexadecimal identifier, already validated as canonical.</summary>
    [MaxLength(16)]
    public string HardwareId { get; set; } = string.Empty;

    /// <summary>Gets or sets the system UUID exactly as submitted (at most 128 characters), or <c>null</c> when absent or oversized.</summary>
    [MaxLength(128)]
    public string? SystemUuidRaw { get; set; }

    /// <summary>Gets or sets the canonical uppercase UUID when the SDK rule accepted it; otherwise <c>null</c>.</summary>
    [MaxLength(36)]
    public string? SystemUuidCanonical { get; set; }

    /// <summary>Gets or sets the identifier the SDK rule derives from the UUID, kept to diagnose client mismatches.</summary>
    [MaxLength(16)]
    public string? DerivedHardwareId { get; set; }

    /// <summary>Gets or sets the stable refusal code (<c>UUID_*</c>) when the UUID was refused; otherwise <c>null</c>.</summary>
    [MaxLength(32)]
    public string? RefusalCode { get; set; }

    /// <summary>Gets or sets the client evidence JSON object exactly as received (bounded), or <c>null</c> when absent or rejected.</summary>
    public string? EvidenceJson { get; set; }

    /// <summary>Gets or sets the lowercase SHA-256 of the raw UUID and evidence text, used as the deduplication key.</summary>
    [MaxLength(64)]
    public string EvidenceSha256 { get; set; } = string.Empty;

    /// <summary>
    /// Maximum length of <see cref="LastEndpoint"/>, shared by the column, the model and the label guard test.
    /// </summary>
    /// <remarks>
    /// Was 16 until TKT-004112: the clone-guard reactivation label (22 characters) then failed on PostgreSQL with
    /// 22001 and the reactivation's evidence was lost. Every label in <see cref="Services.MachineEvidenceEndpoints"/>
    /// must fit; a test enforces it, so a new longer label fails in CI instead of in production storage.
    /// </remarks>
    public const int MaxEndpointLength = 32;

    /// <summary>
    /// Gets or sets the endpoint label of the latest report, one of <see cref="Services.MachineEvidenceEndpoints"/>
    /// (for example <c>CHECK</c> or <c>CLONE_GUARD_REACTIVATE</c>), stored exactly as given (upper-case ASCII).
    /// </summary>
    [MaxLength(MaxEndpointLength)]
    public string LastEndpoint { get; set; } = string.Empty;

    /// <summary>Gets or sets the client application version of the latest report, truncated to 64 characters.</summary>
    [MaxLength(64)]
    public string? LastAppVersion { get; set; }

    /// <summary>Gets or sets the first report time (UTC).</summary>
    public DateTime FirstSeenAtUtc { get; set; }

    /// <summary>Gets or sets the latest report time (UTC).</summary>
    public DateTime LastSeenAtUtc { get; set; }

    /// <summary>Gets or sets the number of identical reports received.</summary>
    public long ObservationCount { get; set; }
}
