using System.Data;
using System.Data.Common;
using System.Net;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using NpgsqlTypes;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services.CloneGuard;

/// <summary>Request facts copied from the HTTP layer into the clone guard journal.</summary>
/// <param name="IpAddress">Transport address of the request (never a forwarded header read here), bounded to 50 characters.</param>
/// <param name="AppVersion">Client version announced by the request, bounded to 80 characters.</param>
/// <param name="CorrelationId">Server correlation (<c>TraceIdentifier</c>), bounded to 200 characters.</param>
public sealed record CloneGuardRequestContext(string? IpAddress, string? AppVersion, string? CorrelationId);

/// <summary>
/// Server authority of the single-use control token (TKT-003615, design TKT-001461). Decides, for a managed check whose
/// logical status is already <c>VALID</c>, whether the caller is the live copy of its seat or a second copy, and
/// applies guided reactivations inside the licence's daily quota. Contract: <c>docs/schema/jeton-anti-clonage.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// Every state change is one conditional SQL statement (compare-and-swap on the current token digest, or
/// <c>INSERT ... ON CONFLICT</c> on the unique seat index), so two copies beating at the same instant can never both
/// consume the same token: PostgreSQL row locking serializes the two statements and the loser sees a changed current
/// digest. Journal rows are written in the same statement as the guard change they describe (data-modifying CTE),
/// so a guard change is never committed without its event.
/// </para>
/// <para>
/// Never bans, never revokes, never releases a seat and never scores the caller's IP: a collision only suspends the
/// copy holding the stale token, through a logical status answered with HTTP 200 by the controller. Database failures
/// propagate to the caller as exceptions; they are never converted into a collision or a refusal.
/// </para>
/// </remarks>
public sealed class SeatCloneGuardService
{
    /// <summary>Window of the repeated-collision and repeated-reactivation alert, and of its deduplication.</summary>
    internal static readonly TimeSpan AlertWindow = TimeSpan.FromHours(24);

    /// <summary>
    /// Period of the managed licence check of T-IA Connect (fixed at five minutes in the client, product decision of
    /// 16/11/2026: no server-driven interval).
    /// </summary>
    internal static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The copy holding the current token counts as alive when its last accepted check is younger than two heartbeat
    /// intervals (one beat may be lost or delayed). Only an alive holder can make the daily quota refuse a reactivation.
    /// </summary>
    internal static readonly TimeSpan HolderAliveWindow = HeartbeatInterval * 2;

    /// <summary>
    /// Request-scoped context shared with the calling controller (same DI scope). Raw statements run on its connection
    /// and current transaction; the service never disposes it, the scope does.
    /// </summary>
    private readonly LicenseDbContext _db;

    /// <summary>Singleton webhook notifier; delivery is fire-and-forget and never changes a check answer.</summary>
    private readonly NotificationService _notifier;

    /// <summary>Structured logger; receives seat, licence and correlation identifiers only, never tokens or digests.</summary>
    private readonly ILogger<SeatCloneGuardService> _logger;

    /// <summary>Creates the service on the request-scoped context shared with the calling controller.</summary>
    /// <param name="db">Request-scoped PostgreSQL context; the service uses its connection and transaction.</param>
    /// <param name="notifier">Webhook notifier used for <see cref="NotificationService.Triggers.SecurityCloneSuspected"/>.</param>
    /// <param name="logger">Structured logger; never receives tokens, digests or full licence keys.</param>
    public SeatCloneGuardService(LicenseDbContext db, NotificationService notifier, ILogger<SeatCloneGuardService> logger)
    {
        _db = db;
        _notifier = notifier;
        _logger = logger;
    }

    /// <summary>Guard columns read back from the database for one seat.</summary>
    /// <param name="Id">Guard row identifier.</param>
    /// <param name="CurrentTokenHash">Digest of the current token.</param>
    /// <param name="PreviousTokenHash">Digest of the last consumed token, or <see langword="null"/>.</param>
    /// <param name="LastAcceptedAt">Last accepted instant (UTC).</param>
    /// <param name="LastAcceptedIp">Transport address of the last accepted check, or <see langword="null"/>.</param>
    private sealed record GuardSnapshot(
        Guid Id, byte[] CurrentTokenHash, byte[]? PreviousTokenHash, DateTime LastAcceptedAt, string? LastAcceptedIp);

    /// <summary>
    /// Evaluates the clone guard member of a managed check whose logical status is <c>VALID</c> for the active seat
    /// <paramref name="seat"/>, and applies the resulting atomic change.
    /// </summary>
    /// <param name="license">Licence of the seat (used for the journal and the alert text).</param>
    /// <param name="seat">Active seat of the caller's authoritative hardware identifier.</param>
    /// <param name="request">Clone guard member exactly as received.</param>
    /// <param name="context">Request facts for the journal.</param>
    /// <param name="cancellationToken">Cancels the database work; a cancelled statement changes nothing.</param>
    /// <returns>
    /// The response member. <see cref="CloneGuardOutcomes.DuplicateDetected"/> means the controller must answer the
    /// logical status <c>DUPLICATE_DETECTED</c> without a licence file. Malformed input and unknown protocol versions
    /// consume nothing.
    /// </returns>
    /// <exception cref="DbException">Database failure; the caller must not turn it into a collision.</exception>
    public async Task<CloneGuardResponse> EvaluateCheckAsync(
        License license, LicenseSeat seat, CloneGuardCheckRequest request, CloneGuardRequestContext context,
        CancellationToken cancellationToken)
    {
        if (request.ProtocolVersion != 1)
            return new CloneGuardResponse(CloneGuardOutcomes.UnsupportedProtocol, null, false);
        if (!CloneGuardCodec.TryHashToken(request.NextToken, out var next))
            return new CloneGuardResponse(CloneGuardOutcomes.Malformed, null, false);
        byte[]? presented = null;
        if (request.Token is not null)
        {
            if (!CloneGuardCodec.TryHashToken(request.Token, out var presentedDigest)
                || CryptographicOperations.FixedTimeEquals(presentedDigest, next))
                return new CloneGuardResponse(CloneGuardOutcomes.Malformed, null, false);
            presented = presentedDigest;
        }
        // An invalid VM Generation ID is dropped, never a refusal: it is a secondary signal only.
        CloneGuardCodec.TryCanonicalVmGenerationId(request.VmGenerationId, out var vmGenerationId);
        var now = DateTime.UtcNow;

        if (presented is not null)
        {
            var rotated = await TryRotateAsync(seat.Id, presented, next, vmGenerationId, context, now, cancellationToken);
            if (rotated.Applied)
            {
                var changed = vmGenerationId is not null && rotated.KnownVmGenerationId is not null
                    && !string.Equals(rotated.KnownVmGenerationId, vmGenerationId, StringComparison.Ordinal);
                if (changed)
                    await InsertEventAsync(seat, license.Id, SeatCloneGuardEventKinds.VmGenerationChanged, null, now,
                        context, vmGenerationId, rotated.KnownVmGenerationId, cancellationToken);
                return new CloneGuardResponse(CloneGuardOutcomes.Accepted, null, changed);
            }
        }

        // Two passes at most: a concurrent arming between our read and our insert is resolved by re-reading once.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var guard = await ReadGuardAsync(seat.Id, forUpdate: false, cancellationToken);
            if (guard is null)
            {
                if (await TryArmAsync(seat, license.Id, next, vmGenerationId, context, now, cancellationToken))
                    return new CloneGuardResponse(CloneGuardOutcomes.Armed, null, false);
                continue;
            }

            // Exact replay of the last accepted pair (lost response): answer the same way, change nothing. A second copy
            // holding the same consumed token draws its own next token, so it can never match here.
            if (CryptographicOperations.FixedTimeEquals(guard.CurrentTokenHash, next)
                && (presented is null && guard.PreviousTokenHash is null
                    || presented is not null && guard.PreviousTokenHash is not null
                        && CryptographicOperations.FixedTimeEquals(guard.PreviousTokenHash, presented)))
                return new CloneGuardResponse(CloneGuardOutcomes.Replayed, null, false);

            if (presented is null)
            {
                // Decision Q2 (owner decision, 16/11/2026): a compatible client without token re-arms silently only when the seat
                // was explicitly re-activated after the last accepted check (sign-out then sign-in, reinstall); any
                // other missing token is a copy that lost or never had the live token.
                if (seat.LastActivatedAt is { } activatedAt && activatedAt > guard.LastAcceptedAt)
                {
                    if (await TryRearmAsync(seat, license.Id, guard, next, vmGenerationId, context, now, cancellationToken))
                        return new CloneGuardResponse(CloneGuardOutcomes.Armed, null, false);
                    continue;
                }
                return await RecordCollisionAsync(license, seat, guard, CloneGuardReasons.TokenMissing, vmGenerationId,
                    context, now, cancellationToken);
            }

            return await RecordCollisionAsync(license, seat, guard, CloneGuardReasons.StaleToken, vmGenerationId,
                context, now, cancellationToken);
        }

        // Unreachable in practice (a guard row is never deleted once it exists); refuse to guess rather than accept.
        throw new InvalidOperationException("Clone guard state changed twice during one evaluation.");
    }

    /// <summary>Result of a token rotation attempt.</summary>
    /// <param name="Applied">True when the presented token was current and has been consumed.</param>
    /// <param name="KnownVmGenerationId">VM Generation ID stored before the rotation, or <see langword="null"/>.</param>
    private readonly record struct RotationResult(bool Applied, string? KnownVmGenerationId);

    /// <summary>
    /// Consumes <paramref name="presented"/> if and only if it is the current digest of the seat's guard, in one
    /// statement: the current digest becomes the previous one and <paramref name="next"/> becomes current.
    /// </summary>
    /// <remarks>
    /// The sub-select locks the guard row (<c>FOR UPDATE</c>) so a concurrent rotation of another copy waits; after it
    /// commits PostgreSQL re-evaluates the <c>CurrentTokenHash = presented</c> predicate on the new row version, which
    /// then fails. This is the atomic single consumption the design requires.
    /// </remarks>
    private async Task<RotationResult> TryRotateAsync(
        Guid seatId, byte[] presented, byte[] next, string? vmGenerationId, CloneGuardRequestContext context,
        DateTime now, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE "SeatCloneGuards" AS g
            SET "PreviousTokenHash" = g."CurrentTokenHash",
                "CurrentTokenHash" = @next,
                "LastAcceptedAt" = @now,
                "LastAcceptedIp" = @ip,
                "LastVmGenerationId" = COALESCE(@vm, g."LastVmGenerationId")
            FROM (SELECT "Id", "LastVmGenerationId" AS known
                  FROM "SeatCloneGuards" WHERE "LicenseSeatId" = @seat FOR UPDATE) AS o
            WHERE g."Id" = o."Id" AND g."CurrentTokenHash" = @presented
            RETURNING o.known
            """;
        var rows = await QueryAsync(sql, cancellationToken,
            Bytes("next", next), Bytes("presented", presented), Uuid("seat", seatId), Time("now", now),
            Text("ip", context.IpAddress), Text("vm", vmGenerationId));
        return rows.Count == 1
            ? new RotationResult(true, rows[0][0] as string)
            : new RotationResult(false, null);
    }

    /// <summary>
    /// Creates the guard of a seat with <paramref name="next"/> as current token and journals <c>ARMED</c>, unless a
    /// guard already exists (concurrent first check of a second copy).
    /// </summary>
    /// <returns><see langword="true"/> when this call created the guard; <see langword="false"/> when one existed.</returns>
    private async Task<bool> TryArmAsync(
        LicenseSeat seat, Guid licenseId, byte[] next, string? vmGenerationId, CloneGuardRequestContext context,
        DateTime now, CancellationToken cancellationToken)
    {
        const string sql = """
            WITH g AS (
                INSERT INTO "SeatCloneGuards" ("Id", "LicenseSeatId", "CurrentTokenHash", "PreviousTokenHash", "ArmedAt",
                    "LastAcceptedAt", "LastAcceptedIp", "LastVmGenerationId", "CollisionCount")
                VALUES (@gid, @seat, @next, NULL, @now, @now, @ip, @vm, 0)
                ON CONFLICT ("LicenseSeatId") DO NOTHING
                RETURNING "Id")
            INSERT INTO "SeatCloneGuardEvents" ("Id", "LicenseSeatId", "LicenseId", "Kind", "Reason", "OccurredAt",
                "IpAddress", "AppVersion", "VmGenerationId", "KnownVmGenerationId", "CorrelationId")
            SELECT @eid, @seat, @license, 'ARMED', NULL, @now, @ip, @version, @vm, NULL, @correlation FROM g
            """;
        var inserted = await ExecuteAsync(sql, cancellationToken,
            Uuid("gid", Guid.NewGuid()), Uuid("eid", Guid.NewGuid()), Uuid("seat", seat.Id), Uuid("license", licenseId),
            Bytes("next", next), Time("now", now), Text("ip", context.IpAddress), Text("vm", vmGenerationId),
            Text("version", context.AppVersion), Text("correlation", context.CorrelationId));
        return inserted == 1;
    }

    /// <summary>
    /// Re-arms the guard with <paramref name="next"/> after an explicit seat activation, only if the current digest
    /// is still the one observed in <paramref name="guard"/> (compare-and-swap), and journals
    /// <c>REARMED_AFTER_ACTIVATION</c> in the same statement.
    /// </summary>
    /// <returns><see langword="false"/> when another copy changed the guard meanwhile; the caller re-evaluates.</returns>
    private async Task<bool> TryRearmAsync(
        LicenseSeat seat, Guid licenseId, GuardSnapshot guard, byte[] next, string? vmGenerationId,
        CloneGuardRequestContext context, DateTime now, CancellationToken cancellationToken)
    {
        const string sql = """
            WITH g AS (
                UPDATE "SeatCloneGuards"
                SET "CurrentTokenHash" = @next, "PreviousTokenHash" = NULL, "LastAcceptedAt" = @now,
                    "LastAcceptedIp" = @ip, "LastVmGenerationId" = COALESCE(@vm, "LastVmGenerationId")
                WHERE "Id" = @gid AND "CurrentTokenHash" = @observed
                RETURNING "Id")
            INSERT INTO "SeatCloneGuardEvents" ("Id", "LicenseSeatId", "LicenseId", "Kind", "Reason", "OccurredAt",
                "IpAddress", "AppVersion", "VmGenerationId", "KnownVmGenerationId", "CorrelationId")
            SELECT @eid, @seat, @license, 'REARMED_AFTER_ACTIVATION', NULL, @now, @ip, @version, @vm, NULL, @correlation FROM g
            """;
        var updated = await ExecuteAsync(sql, cancellationToken,
            Uuid("gid", guard.Id), Uuid("eid", Guid.NewGuid()), Uuid("seat", seat.Id), Uuid("license", licenseId),
            Bytes("next", next), Bytes("observed", guard.CurrentTokenHash), Time("now", now),
            Text("ip", context.IpAddress), Text("vm", vmGenerationId), Text("version", context.AppVersion),
            Text("correlation", context.CorrelationId));
        return updated == 1;
    }

    /// <summary>
    /// Records one collision (counter, last instant and <c>COLLISION</c> event in one statement), evaluates the alert,
    /// and returns the suspension outcome. Consumes no token and touches no seat, licence, ban or threat score.
    /// </summary>
    private async Task<CloneGuardResponse> RecordCollisionAsync(
        License license, LicenseSeat seat, GuardSnapshot guard, string reason, string? vmGenerationId,
        CloneGuardRequestContext context, DateTime now, CancellationToken cancellationToken)
    {
        const string sql = """
            WITH g AS (
                UPDATE "SeatCloneGuards"
                SET "CollisionCount" = "CollisionCount" + 1, "LastCollisionAt" = @now
                WHERE "Id" = @gid
                RETURNING "LastVmGenerationId")
            INSERT INTO "SeatCloneGuardEvents" ("Id", "LicenseSeatId", "LicenseId", "Kind", "Reason", "OccurredAt",
                "IpAddress", "AppVersion", "VmGenerationId", "KnownVmGenerationId", "CorrelationId")
            SELECT @eid, @seat, @license, 'COLLISION', @reason, @now, @ip, @version, @vm, g."LastVmGenerationId", @correlation
            FROM g
            """;
        await ExecuteAsync(sql, cancellationToken,
            Uuid("gid", guard.Id), Uuid("eid", Guid.NewGuid()), Uuid("seat", seat.Id), Uuid("license", license.Id),
            Text("reason", reason), Time("now", now), Text("ip", context.IpAddress), Text("version", context.AppVersion),
            Text("vm", vmGenerationId), Text("correlation", context.CorrelationId));
        _logger.LogWarning(
            "Clone guard collision on seat {SeatId} of licence {LicenseId}: {Reason}, correlation {CorrelationId}.",
            seat.Id, license.Id, reason, context.CorrelationId);
        var otherNetwork = !SameNetwork(context.IpAddress, guard.LastAcceptedIp);
        await EvaluateRepetitionAlertAsync(license, seat, guard.Id, otherNetwork, context, now, cancellationToken);
        return new CloneGuardResponse(CloneGuardOutcomes.DuplicateDetected, reason, false);
    }

    /// <summary>
    /// Applies a guided reactivation: the caller's <paramref name="nextToken"/> becomes the only current token of the
    /// seat, so the other copy is answered <c>DUPLICATE_DETECTED</c> at its next check. Counts one unit of the licence's
    /// daily quota (product decision, 16/11/2026), refused when that quota is exhausted.
    /// </summary>
    /// <param name="license">Licence of the seat; its seat count and type are re-read under the barrier.</param>
    /// <param name="seat">Active seat of the caller's authoritative hardware identifier.</param>
    /// <param name="nextToken">Next token drawn and persisted by the caller.</param>
    /// <param name="vmGenerationIdInput">VM Generation ID as received; an invalid value is ignored.</param>
    /// <param name="context">Request facts for the journal.</param>
    /// <param name="cancellationToken">Cancels the transaction; nothing is committed then.</param>
    /// <returns>
    /// <see cref="CloneGuardOutcomes.Reactivated"/> (also for an exact retry, which counts nothing more),
    /// <see cref="CloneGuardOutcomes.ReactivationLimitReached"/> with reason
    /// <see cref="CloneGuardReasons.DailyQuotaExhausted"/> only when the quota is exhausted <b>and</b> the copy holding the
    /// current token beat within <see cref="HolderAliveWindow"/> (nothing changed, that copy stays usable), or
    /// <see cref="CloneGuardOutcomes.Malformed"/> for an invalid token. With an exhausted quota and a silent holder the
    /// reactivation is applied anyway (journal reason <see cref="CloneGuardReasons.QuotaExhaustedHolderInactive"/>), so a
    /// paid licence always keeps one working machine.
    /// </returns>
    /// <remarks>
    /// Runs in its own transaction that first takes the exclusive commercial barrier (advisory lock 1312), the same
    /// lock every seat admission holds before its quota check (<see cref="SeatChangeQuota"/>): quota read and
    /// <c>REACTIVATED</c> insert can therefore not interleave with another reactivation or a change of machine, so the
    /// last unit of the day is granted once. The limit is never a constant: <see cref="SeatChangeQuota.GetDailyLimit"/>
    /// multiplies <see cref="LicenseType.MaxActivationsPerDay"/> by <see cref="License.MaxSeats"/>, both re-read from the
    /// database under the barrier, so an administrator change applies to the next reactivation.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The context already has a transaction (programming error).</exception>
    public async Task<CloneGuardResponse> ReactivateAsync(
        License license, LicenseSeat seat, string? nextToken, string? vmGenerationIdInput,
        CloneGuardRequestContext context, CancellationToken cancellationToken)
    {
        if (!CloneGuardCodec.TryHashToken(nextToken, out var next))
            return new CloneGuardResponse(CloneGuardOutcomes.Malformed, null, false);
        CloneGuardCodec.TryCanonicalVmGenerationId(vmGenerationIdInput, out var vmGenerationId);
        if (_db.Database.CurrentTransaction is not null)
            throw new InvalidOperationException("Clone guard reactivation must own its transaction.");

        var now = DateTime.UtcNow;
        bool refused;
        bool holderAlive;
        bool beyondQuota;
        Guid guardId;
        await using (var transaction = await _db.Database.BeginTransactionAsync(cancellationToken))
        {
            await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(_db, cancellationToken);
            // Seat count and per-seat quota are read after the barrier, so a concurrent administrator change or
            // admission is either fully before or fully after this decision.
            await _db.Entry(license).ReloadAsync(cancellationToken);
            if (license.Type is not null)
                await _db.Entry(license.Type).ReloadAsync(cancellationToken);
            else
                await _db.Entry(license).Reference(row => row.Type).LoadAsync(cancellationToken);

            var guard = await ReadGuardAsync(seat.Id, forUpdate: true, cancellationToken);
            if (guard is not null && CryptographicOperations.FixedTimeEquals(guard.CurrentTokenHash, next))
            {
                // Exact retry after a lost response: already applied and already counted once.
                await transaction.CommitAsync(cancellationToken);
                return new CloneGuardResponse(CloneGuardOutcomes.Reactivated, null, false);
            }

            var quota = await SeatChangeQuota.GetStatusAsync(_db, license, now, cancellationToken);
            // Owner rule (16/11/2026): a paid licence always works on at least one machine. An exhausted quota
            // refuses only while another copy is provably running (the holder of the current token beat within two
            // intervals); if that copy is gone (deleted VM, only a restored copy left), the reactivation passes anyway,
            // is journaled with its reason, counted in the quota and the alert, and the administrator is told.
            holderAlive = guard is not null && guard.LastAcceptedAt > now - HolderAliveWindow;
            beyondQuota = quota.IsExhausted && !holderAlive;
            refused = quota.IsExhausted && holderAlive;
            guardId = guard?.Id ?? Guid.NewGuid();
            if (refused)
            {
                await InsertEventAsync(seat, license.Id, SeatCloneGuardEventKinds.ReactivationRefused,
                    CloneGuardReasons.DailyQuotaExhausted, now, context, vmGenerationId, null, cancellationToken);
            }
            else
            {
                const string upsert = """
                    INSERT INTO "SeatCloneGuards" ("Id", "LicenseSeatId", "CurrentTokenHash", "PreviousTokenHash", "ArmedAt",
                        "LastAcceptedAt", "LastAcceptedIp", "LastVmGenerationId", "CollisionCount")
                    VALUES (@gid, @seat, @next, NULL, @now, @now, @ip, @vm, 0)
                    ON CONFLICT ("LicenseSeatId") DO UPDATE
                    SET "CurrentTokenHash" = EXCLUDED."CurrentTokenHash", "PreviousTokenHash" = NULL,
                        "LastAcceptedAt" = EXCLUDED."LastAcceptedAt", "LastAcceptedIp" = EXCLUDED."LastAcceptedIp",
                        "LastVmGenerationId" = COALESCE(EXCLUDED."LastVmGenerationId", "SeatCloneGuards"."LastVmGenerationId")
                    """;
                await ExecuteAsync(upsert, cancellationToken,
                    Uuid("gid", guardId), Uuid("seat", seat.Id), Bytes("next", next), Time("now", now),
                    Text("ip", context.IpAddress), Text("vm", vmGenerationId));
                await InsertEventAsync(seat, license.Id, SeatCloneGuardEventKinds.Reactivated,
                    beyondQuota ? CloneGuardReasons.QuotaExhaustedHolderInactive : null, now, context,
                    vmGenerationId, null, cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
        }

        var persistedGuard = await ReadGuardAsync(seat.Id, forUpdate: false, cancellationToken);
        if (refused)
        {
            _logger.LogWarning(
                "Clone guard reactivation refused on seat {SeatId} of licence {LicenseId}: daily quota exhausted, correlation {CorrelationId}.",
                seat.Id, license.Id, context.CorrelationId);
            if (persistedGuard is not null)
                await SendLimitAlertAsync(license, seat, persistedGuard.Id, context, now, cancellationToken);
            return new CloneGuardResponse(CloneGuardOutcomes.ReactivationLimitReached, CloneGuardReasons.DailyQuotaExhausted, false);
        }

        _logger.LogInformation(
            "Clone guard reactivated on seat {SeatId} of licence {LicenseId} (beyond quota with inactive holder: {BeyondQuota}), correlation {CorrelationId}.",
            seat.Id, license.Id, beyondQuota, context.CorrelationId);
        if (beyondQuota && persistedGuard is not null)
            await SendLimitAlertAsync(license, seat, persistedGuard.Id, context, now, cancellationToken,
                "réactivation acceptée au-delà du quota journalier : la copie active ne bat plus (licence payée jamais bloquée)");
        await EvaluateRepetitionAlertAsync(license, seat, persistedGuard?.Id ?? guardId, false, context, now, cancellationToken);
        return new CloneGuardResponse(CloneGuardOutcomes.Reactivated, null, false);
    }

    /// <summary>
    /// Sends one <c>Security.CloneSuspected</c> alert per seat and 24 hours when, over the last 24 hours, the seat had at
    /// least two collisions, at least two reactivations, or the current collision came from another network than the
    /// last accepted check. Never sanctions anything.
    /// </summary>
    /// <param name="otherNetwork">True when the triggering collision came from another /24 (IPv4) or /48 (IPv6).</param>
    /// <remarks>
    /// Deduplication is a compare-and-swap on <see cref="SeatCloneGuard.LastAlertAt"/>, so two concurrent collisions
    /// send at most one alert. Delivery is fire-and-forget (<see cref="NotificationService.Notify"/>); a delivery
    /// failure is logged by the notifier and never changes the check answer.
    /// </remarks>
    private async Task EvaluateRepetitionAlertAsync(
        License license, LicenseSeat seat, Guid guardId, bool otherNetwork, CloneGuardRequestContext context,
        DateTime now, CancellationToken cancellationToken)
    {
        var since = now - AlertWindow;
        var seatId = seat.Id;
        var counts = await _db.SeatCloneGuardEvents.AsNoTracking()
            .Where(row => row.LicenseSeatId == seatId && row.OccurredAt > since
                && (row.Kind == SeatCloneGuardEventKinds.Collision || row.Kind == SeatCloneGuardEventKinds.Reactivated))
            .GroupBy(row => row.Kind)
            .Select(group => new { Kind = group.Key, Count = group.Count() })
            .ToListAsync(cancellationToken);
        var collisions = counts.FirstOrDefault(row => row.Kind == SeatCloneGuardEventKinds.Collision)?.Count ?? 0;
        var reactivations = counts.FirstOrDefault(row => row.Kind == SeatCloneGuardEventKinds.Reactivated)?.Count ?? 0;
        if (collisions < 2 && reactivations < 2 && !otherNetwork)
            return;
        if (!await TryClaimAlertAsync(guardId, "LastAlertAt", now, cancellationToken))
            return;
        var cause = otherNetwork && collisions < 2 && reactivations < 2
            ? "collision depuis un autre réseau que la copie active"
            : "collisions ou réactivations répétées";
        await NotifyAsync(license, seat, cause, collisions, reactivations, context, now, cancellationToken);
    }

    /// <summary>
    /// Sends one <c>Security.CloneSuspected</c> alert per seat and 24 hours when a reactivation hit the exhausted daily
    /// quota (product decision, 16/11/2026): refused while the holder is alive, or accepted beyond the quota because
    /// the holder stopped beating. Deduplicated on <see cref="SeatCloneGuard.LastLimitAlertAt"/>.
    /// </summary>
    /// <param name="cause">Cause line of the alert; defaults to the refusal.</param>
    private async Task SendLimitAlertAsync(
        License license, LicenseSeat seat, Guid guardId, CloneGuardRequestContext context, DateTime now,
        CancellationToken cancellationToken, string cause = "réactivation refusée : quota journalier de la licence atteint")
    {
        if (!await TryClaimAlertAsync(guardId, "LastLimitAlertAt", now, cancellationToken))
            return;
        await NotifyAsync(license, seat, cause, null, null, context, now, cancellationToken);
    }

    /// <summary>Claims the right to send one alert for the guard if none was sent in the last 24 hours (compare-and-swap).</summary>
    /// <param name="column">Either <c>LastAlertAt</c> or <c>LastLimitAlertAt</c>; a fixed identifier, never user input.</param>
    /// <returns><see langword="true"/> when this call claimed the alert.</returns>
    private async Task<bool> TryClaimAlertAsync(Guid guardId, string column, DateTime now, CancellationToken cancellationToken)
    {
        if (column is not ("LastAlertAt" or "LastLimitAlertAt"))
            throw new ArgumentOutOfRangeException(nameof(column));
        var sql = $"""
            UPDATE "SeatCloneGuards" SET "{column}" = @now
            WHERE "Id" = @gid AND ("{column}" IS NULL OR "{column}" <= @threshold)
            """;
        return await ExecuteAsync(sql, cancellationToken,
            Uuid("gid", guardId), Time("now", now), Time("threshold", now - AlertWindow)) == 1;
    }

    /// <summary>
    /// Formats and sends the alert: masked licence key, hardware identifier, cause, counts, transport address, client
    /// version and up to five distinct VM Generation IDs journaled for the seat over the alert window (contract
    /// section 7, review 2439 remark). No token, digest or full licence key is ever included.
    /// </summary>
    private async Task NotifyAsync(
        License license, LicenseSeat seat, string cause, int? collisions, int? reactivations, CloneGuardRequestContext context,
        DateTime now, CancellationToken cancellationToken)
    {
        var counts = collisions is null ? string.Empty : $"\nCollisions sur 24 h : {collisions}, réactivations : {reactivations}";
        var since = now - AlertWindow;
        var seatId = seat.Id;
        var vmGenerationIds = await _db.SeatCloneGuardEvents.AsNoTracking()
            .Where(row => row.LicenseSeatId == seatId && row.OccurredAt > since && row.VmGenerationId != null)
            .Select(row => row.VmGenerationId!)
            .Distinct()
            .Take(5)
            .ToListAsync(cancellationToken);
        var vmLine = vmGenerationIds.Count == 0 ? "aucun reçu" : string.Join(", ", vmGenerationIds);
        _notifier.Notify(
            NotificationService.Triggers.SecurityCloneSuspected,
            "Copie d'installation suspectée",
            $"Licence : {SecurityService.MaskLicenseKey(license.LicenseKey)}\nPoste : {seat.HardwareId}"
            + $"\nCause : {cause}{counts}\nIP : {context.IpAddress ?? "inconnue"}\nVersion : {context.AppVersion ?? "inconnue"}"
            + $"\nVM Generation ID (24 h) : {vmLine}"
            + "\nAucune sanction automatique : décision de l'administrateur.");
    }

    /// <summary>Inserts one journal row outside of any guard change (VM Generation ID signal, refused reactivation, reactivation).</summary>
    private Task InsertEventAsync(
        LicenseSeat seat, Guid licenseId, string kind, string? reason, DateTime now, CloneGuardRequestContext context,
        string? vmGenerationId, string? knownVmGenerationId, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO "SeatCloneGuardEvents" ("Id", "LicenseSeatId", "LicenseId", "Kind", "Reason", "OccurredAt",
                "IpAddress", "AppVersion", "VmGenerationId", "KnownVmGenerationId", "CorrelationId")
            VALUES (@eid, @seat, @license, @kind, @reason, @now, @ip, @version, @vm, @known, @correlation)
            """;
        return ExecuteAsync(sql, cancellationToken,
            Uuid("eid", Guid.NewGuid()), Uuid("seat", seat.Id), Uuid("license", licenseId), Text("kind", kind),
            Text("reason", reason), Time("now", now), Text("ip", context.IpAddress), Text("version", context.AppVersion),
            Text("vm", vmGenerationId), Text("known", knownVmGenerationId), Text("correlation", context.CorrelationId));
    }

    /// <summary>Reads the guard of a seat, optionally locking its row for the rest of the caller's transaction.</summary>
    /// <param name="forUpdate">True only inside the reactivation transaction.</param>
    /// <returns>The guard snapshot, or <see langword="null"/> when the seat was never armed.</returns>
    private async Task<GuardSnapshot?> ReadGuardAsync(Guid seatId, bool forUpdate, CancellationToken cancellationToken)
    {
        var sql = """
            SELECT "Id", "CurrentTokenHash", "PreviousTokenHash", "LastAcceptedAt", "LastAcceptedIp"
            FROM "SeatCloneGuards" WHERE "LicenseSeatId" = @seat
            """ + (forUpdate ? " FOR UPDATE" : string.Empty);
        var rows = await QueryAsync(sql, cancellationToken, Uuid("seat", seatId));
        if (rows.Count == 0)
            return null;
        var row = rows[0];
        return new GuardSnapshot(
            (Guid)row[0]!, (byte[])row[1]!, row[2] as byte[],
            DateTime.SpecifyKind((DateTime)row[3]!, DateTimeKind.Utc), row[4] as string);
    }

    /// <summary>
    /// Compares two transport addresses by network: same /24 for IPv4 (IPv4-mapped IPv6 is unmapped first), same /48
    /// for IPv6. An unknown or unparsable address on either side counts as the same network, so a missing address
    /// never raises an alert on its own.
    /// </summary>
    internal static bool SameNetwork(string? left, string? right)
    {
        if (!IPAddress.TryParse(left, out var a) || !IPAddress.TryParse(right, out var b))
            return true;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (b.IsIPv4MappedToIPv6) b = b.MapToIPv4();
        if (a.AddressFamily != b.AddressFamily)
            return false;
        var prefix = a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 3 : 6;
        return a.GetAddressBytes().AsSpan(0, prefix).SequenceEqual(b.GetAddressBytes().AsSpan(0, prefix));
    }

    /// <summary>Runs a statement on the context's connection and current transaction; returns the affected row count.</summary>
    private async Task<int> ExecuteAsync(string sql, CancellationToken cancellationToken, params NpgsqlParameter[] parameters)
    {
        await using var command = await CreateCommandAsync(sql, parameters, cancellationToken);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Runs a row-returning statement on the context's connection and current transaction.</summary>
    /// <returns>Every row as an array of column values, <see cref="DBNull"/> mapped to <see langword="null"/>.</returns>
    private async Task<List<object?[]>> QueryAsync(string sql, CancellationToken cancellationToken, params NpgsqlParameter[] parameters)
    {
        await using var command = await CreateCommandAsync(sql, parameters, cancellationToken);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<object?[]>();
        while (await reader.ReadAsync(cancellationToken))
        {
            var values = new object?[reader.FieldCount];
            for (var index = 0; index < values.Length; index++)
                values[index] = reader.IsDBNull(index) ? null : reader.GetValue(index);
            rows.Add(values);
        }
        return rows;
    }

    /// <summary>
    /// Builds a command bound to the context's connection (opened if needed; EF closes it with the context) and to its
    /// current transaction, so raw statements share the reactivation transaction and its advisory lock.
    /// </summary>
    private async Task<DbCommand> CreateCommandAsync(string sql, NpgsqlParameter[] parameters, CancellationToken cancellationToken)
    {
        var connection = _db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
            await _db.Database.OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = _db.Database.CurrentTransaction?.GetDbTransaction();
        command.Parameters.AddRange(parameters);
        return command;
    }

    /// <summary>Builds a <c>bytea</c> parameter.</summary>
    private static NpgsqlParameter Bytes(string name, byte[] value) => new(name, NpgsqlDbType.Bytea) { Value = value };

    /// <summary>Builds a <c>uuid</c> parameter.</summary>
    private static NpgsqlParameter Uuid(string name, Guid value) => new(name, NpgsqlDbType.Uuid) { Value = value };

    /// <summary>Builds a <c>timestamptz</c> parameter; the value must be UTC (Npgsql refuses other kinds).</summary>
    private static NpgsqlParameter Time(string name, DateTime value) => new(name, NpgsqlDbType.TimestampTz) { Value = value };

    /// <summary>Builds a nullable <c>text</c> parameter.</summary>
    private static NpgsqlParameter Text(string name, string? value) =>
        new(name, NpgsqlDbType.Text) { Value = (object?)value ?? DBNull.Value };
}
