using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Single-use control token state of one licence seat (TKT-003615, design TKT-001461): detects a copied or restored
/// installation that keeps running next to the original one. Contract: <c>docs/schema/jeton-anti-clonage.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// The client draws the next token itself and presents the pair (current token, next token) on every managed
/// <c>POST /api/activation/check</c>. The server keeps only SHA-256 digests of the 32 decoded token bytes, never a
/// token, so a database leak cannot be replayed. Two copies of one installation share the licence key, the hardware
/// identifier and therefore this seat: the first one consumes the current token, the second presents a consumed or
/// unknown token and is answered <c>DUPLICATE_DETECTED</c>.
/// </para>
/// <para>
/// One row per seat (unique <see cref="LicenseSeatId"/>), created on the first guarded check and never deleted: the
/// guard follows the seat through in-place hardware migrations (TKT-003614) and survives releases, so a machine that
/// comes back keeps its token. Every write is a single conditional SQL statement issued by
/// <c>Services.CloneGuard.SeatCloneGuardService</c>; EF only reads and creates the mapping.
/// </para>
/// </remarks>
public class SeatCloneGuard
{
    /// <summary>Gets or sets the row identifier.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Gets or sets the guarded seat; unique, the guard of a seat is never moved to another seat.</summary>
    public Guid LicenseSeatId { get; set; }

    /// <summary>Gets or sets the guarded seat navigation.</summary>
    public LicenseSeat? LicenseSeat { get; set; }

    /// <summary>
    /// Gets or sets the SHA-256 digest (exactly 32 bytes) of the decoded current token, the only token that a check
    /// may consume. Compared as raw <c>bytea</c>: no collation, casing or encoding applies.
    /// </summary>
    public byte[] CurrentTokenHash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Gets or sets the SHA-256 digest of the token consumed by the last accepted rotation, or <see langword="null"/>
    /// after arming or a guided reactivation. Only an exact replay of the pair (previous, current) is accepted with it.
    /// </summary>
    public byte[]? PreviousTokenHash { get; set; }

    /// <summary>Gets or sets the UTC instant the guard was first armed.</summary>
    public DateTime ArmedAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC instant of the last accepted guarded check, arming or reactivation. Compared with
    /// <see cref="LicenseSeat.LastActivatedAt"/> to allow a silent re-arm after an explicit activation.
    /// </summary>
    public DateTime LastAcceptedAt { get; set; }

    /// <summary>Gets or sets the transport address of the last accepted guarded check (bounded to 50 characters).</summary>
    [MaxLength(50)]
    public string? LastAcceptedIp { get; set; }

    /// <summary>
    /// Gets or sets the last VM Generation ID received on an accepted check: 32 lowercase hexadecimal characters, or
    /// <see langword="null"/> when the client never sent a valid one. A change is a signal only, never a refusal.
    /// </summary>
    [MaxLength(32)]
    public string? LastVmGenerationId { get; set; }

    /// <summary>Gets or sets the total number of collisions (stale or missing token) recorded for the seat.</summary>
    public int CollisionCount { get; set; }

    /// <summary>Gets or sets the UTC instant of the last collision, or <see langword="null"/> when none occurred.</summary>
    public DateTime? LastCollisionAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC instant of the last <c>Security.CloneSuspected</c> alert sent for repeated collisions or
    /// reactivations; bounds that alert to one per seat per 24 hours.
    /// </summary>
    public DateTime? LastAlertAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC instant of the last <c>Security.CloneSuspected</c> alert sent because a reactivation hit the
    /// daily quota; bounds that alert to one per seat per 24 hours, independently of <see cref="LastAlertAt"/>.
    /// </summary>
    public DateTime? LastLimitAlertAt { get; set; }
}

/// <summary>
/// Append-only journal of the clone guard of one seat (TKT-003615): arming, collisions, VM Generation ID changes and
/// guided reactivations. Routine rotations and replays are not journaled (one row every five minutes per machine would
/// be noise); they only move <see cref="SeatCloneGuard.LastAcceptedAt"/>. Rows are never updated nor deleted.
/// </summary>
/// <remarks>
/// <see cref="SeatCloneGuardEventKinds.Reactivated"/> rows are also counted by <c>Services.SeatChangeQuota</c>: a
/// guided reactivation consumes one unit of the licence's daily quota (product decision, 16/11/2026).
/// </remarks>
public class SeatCloneGuardEvent
{
    /// <summary>Gets or sets the row identifier.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Gets or sets the seat whose guard produced the event.</summary>
    public Guid LicenseSeatId { get; set; }

    /// <summary>Gets or sets the licence owning the seat, copied so that daily quota counting needs no join.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>Gets or sets the event kind, one of <see cref="SeatCloneGuardEventKinds"/> (ASCII, compared ordinally).</summary>
    [MaxLength(40)]
    public string Kind { get; set; } = string.Empty;

    /// <summary>Gets or sets the machine-readable reason (for example <c>stale_token</c>), or <see langword="null"/>.</summary>
    [MaxLength(80)]
    public string? Reason { get; set; }

    /// <summary>Gets or sets the UTC instant of the event.</summary>
    public DateTime OccurredAt { get; set; }

    /// <summary>Gets or sets the transport address of the request (bounded to 50 characters), or <see langword="null"/>.</summary>
    [MaxLength(50)]
    public string? IpAddress { get; set; }

    /// <summary>Gets or sets the client version announced by the request (bounded to 80 characters), or <see langword="null"/>.</summary>
    [MaxLength(80)]
    public string? AppVersion { get; set; }

    /// <summary>Gets or sets the valid VM Generation ID sent with the request (lowercase hexadecimal), or <see langword="null"/>.</summary>
    [MaxLength(32)]
    public string? VmGenerationId { get; set; }

    /// <summary>Gets or sets the VM Generation ID the guard knew before the request, or <see langword="null"/>.</summary>
    [MaxLength(32)]
    public string? KnownVmGenerationId { get; set; }

    /// <summary>Gets or sets the server correlation of the request (<c>TraceIdentifier</c>, bounded to 200 characters).</summary>
    [MaxLength(200)]
    public string? CorrelationId { get; set; }
}

/// <summary>Closed set of <see cref="SeatCloneGuardEvent.Kind"/> values, enforced by a database CHECK constraint.</summary>
public static class SeatCloneGuardEventKinds
{
    /// <summary>First guarded check of the seat: the guard was created with the client's next token.</summary>
    public const string Armed = "ARMED";

    /// <summary>A compatible client without token re-armed the guard after an explicit activation of the seat.</summary>
    public const string RearmedAfterActivation = "REARMED_AFTER_ACTIVATION";

    /// <summary>A stale, unknown or missing token proved a second copy; that copy was answered <c>DUPLICATE_DETECTED</c>.</summary>
    public const string Collision = "COLLISION";

    /// <summary>An accepted check reported a VM Generation ID different from the known one (copy or snapshot restore).</summary>
    public const string VmGenerationChanged = "VM_GENERATION_CHANGED";

    /// <summary>A guided reactivation made the caller's next token current; counts in the licence's daily quota.</summary>
    public const string Reactivated = "REACTIVATED";

    /// <summary>A guided reactivation was refused because the licence's daily quota was exhausted.</summary>
    public const string ReactivationRefused = "REACTIVATION_REFUSED";

    /// <summary>All allowed kinds, in the order of the CHECK constraint.</summary>
    public static readonly IReadOnlyList<string> All =
        [Armed, RearmedAfterActivation, Collision, VmGenerationChanged, Reactivated, ReactivationRefused];
}
