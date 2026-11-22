namespace SoftLicence.Server.Data;

/// <summary>
/// TKT-002919: one accepted account relink of a Runtime installation, requested server to server by the
/// dedicated relink identity after the account was signed in inside the application.
/// </summary>
/// <remarks>
/// <para>
/// The row is inserted <c>PENDING</c> inside the transaction that reattaches the seat, so the PostgreSQL
/// relink writer can revalidate it as its fourth authority proof, then moved to <c>COMPLETED</c> with the
/// frozen response before that same transaction commits. A refused request writes no row: a
/// <c>PENDING</c> row never survives a commit.
/// </para>
/// <para>
/// <c>COMPLETED</c> rows are the idempotency ledger: the same authenticated client and request identifier
/// with the same body digest returns the frozen bytes. They are purged 30 days after completion by
/// <see cref="Services.RuntimeEnrollmentCleanupService"/>.
/// </para>
/// <para>
/// Every identifier string is canonical and compared ordinally: client identifiers match
/// <c>^[a-z0-9][a-z0-9._-]{2,63}$</c>, digests are 64 lowercase hexadecimal characters.
/// </para>
/// </remarks>
public sealed class RuntimeAccountRelinkRequest
{
    /// <summary>Server-generated primary key.</summary>
    public Guid Id { get; set; }

    /// <summary>Dedicated S2S client that authenticated the request (the identity holding the relink right).</summary>
    public string AuthenticatedClientId { get; set; } = string.Empty;

    /// <summary>
    /// Distribution client that created the enrollment, listed in the dedicated identity's
    /// <c>AccountRelinkForClientIds</c>; the relink writer requires it to equal the enrollment client.
    /// </summary>
    public string EnrollmentClientId { get; set; } = string.Empty;

    /// <summary>Caller idempotency key, unique per authenticated client.</summary>
    public Guid RequestId { get; set; }

    /// <summary>Lowercase SHA-256 of the exact request bytes; a different body for the same request is a conflict.</summary>
    public string BodyDigestSha256 { get; set; } = string.Empty;

    /// <summary>Product of the enrollment and of the target licence.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Relinked Runtime enrollment.</summary>
    public Guid EnrollmentId { get; set; }

    /// <summary>Target licence chosen by the signed-in account.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>
    /// Registry owner declared by the website; it was the ACTIVE owner of both the target licence and the
    /// installation licence when the row was written, and the writer checks it again. Null (TKT-003350) when the
    /// website knows no commercial owner: the row then targets the installation's own licence, which the writer
    /// requires, and no registry row is read.
    /// </summary>
    public Guid? OwnerSubjectId { get; set; }

    /// <summary>
    /// TKT-003753: exact website attestation <see cref="Services.RuntimeAccountRelinkContract.WebsiteSameAccountAttestation"/>
    /// when the website, authenticated by its S2S identity (trust boundary), states that the signed-in account owns
    /// both the installation licence and the target licence although no registry owner exists (null
    /// <see cref="OwnerSubjectId"/>). It lets the relink writer accept another licence of the same product without
    /// reading the registry. Null otherwise; never set together with an owner (database check constraint).
    /// </summary>
    public string? OwnerAttestation { get; set; }

    /// <summary>Subject digest of the signed-in account, equal to the enrollment digest.</summary>
    public string SubjectRefDigestSha256 { get; set; } = string.Empty;

    /// <summary><c>PENDING</c> inside the relink transaction, <c>COMPLETED</c> once committed.</summary>
    public string State { get; set; } = string.Empty;

    /// <summary>Exact UTF-8 JSON response returned to every replay; null only while <c>PENDING</c>.</summary>
    public string? ResponseBody { get; set; }

    /// <summary>Provider time at insertion (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Provider time of completion (UTC); the 30-day retention runs from it.</summary>
    public DateTime? CompletedAtUtc { get; set; }
}
