namespace SoftLicence.Server.Data;

/// <summary>Stores one immutable accepted or refused v2 request result for semantic replay.</summary>
public sealed class RuntimeEnrollmentAuthorityRequest
{
    /// <summary>Gets or sets the immutable request identifier.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Gets or sets the already validated lowercase request digest.</summary>
    public string RequestDigest { get; set; } = string.Empty;
    /// <summary>Gets or sets the accepted lineage identifier, or null for a refused terminal result.</summary>
    public Guid? AuthorityLineageId { get; set; }

    /// <summary>Gets or sets the accepted generation identifier, or null for a refused terminal result.</summary>
    public Guid? AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the closed persistence result code.</summary>
    public string ResultCode { get; set; } = "ACCEPTED";

    /// <summary>Gets or sets the closed internal refusal code, or null for an accepted result.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the frozen HTTP status used by refused semantic replay; accepted replay is always 200.</summary>
    public int HttpStatusCode { get; set; }
    /// <summary>Gets or sets the immutable persistence timestamp.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Gets or sets the UTC instant at which the terminal result was frozen.</summary>
    public DateTime CompletedAtUtc { get; set; }

    /// <summary>Gets or sets the exact owned UTF-8 response returned by semantic replay.</summary>
    public byte[] ExactResponseUtf8 { get; set; } = [];
    /// <summary>Gets or sets the accepted generation navigation.</summary>
    public RuntimeEnrollmentAuthorityGeneration? Generation { get; set; }
}
