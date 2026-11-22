using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

/// <summary>Administrator read model of the single-use control token (TKT-003615).</summary>
public partial class AdminController
{
    /// <summary>Number of most recent journal rows returned per seat.</summary>
    private const int CloneGuardEventsPerSeat = 20;

    /// <summary>
    /// Returns, for every seat of a licence, the clone guard state and its most recent journal rows, so an administrator
    /// can tell a legitimate snapshot restore from an actively running copy before deciding anything.
    /// </summary>
    /// <param name="licenseKey">Exact licence key, matched like <c>GET licenses/{licenseKey}</c> (ordinal, no trimming).</param>
    /// <returns>
    /// 401 without admin authentication or outside the caller's product scope, 404 for an unknown key, otherwise 200
    /// with one entry per seat (armed or not), newest events first. Read-only: never changes a guard, a seat or a ban,
    /// and never exposes token digests.
    /// </returns>
    [HttpGet("licenses/{licenseKey}/clone-guard")]
    public async Task<IActionResult> GetLicenseCloneGuard(string licenseKey)
    {
        TagLog("GET_LICENSE_CLONE_GUARD", licenseKey);
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();

        var license = await _db.Licenses.AsNoTracking()
            .Include(row => row.Seats)
            .FirstOrDefaultAsync(row => row.LicenseKey == licenseKey);
        if (license == null) return NotFound("Licence introuvable.");
        if (!await IsLicenseProductInScopeAsync(scopedProductId, license.ProductId, HttpContext.RequestAborted)) return Unauthorized();

        var seatIds = license.Seats.Select(seat => seat.Id).ToList();
        var guards = await _db.SeatCloneGuards.AsNoTracking()
            .Where(guard => seatIds.Contains(guard.LicenseSeatId))
            .ToDictionaryAsync(guard => guard.LicenseSeatId, HttpContext.RequestAborted);
        var since = DateTime.UtcNow - Services.CloneGuard.SeatCloneGuardService.AlertWindow;
        // Bounded reads (review 2439 remark): per seat, the newest CloneGuardEventsPerSeat rows plus two counts over the
        // alert window, so a seat with a long journal never loads it whole. A licence has few seats.
        var recent = new Dictionary<Guid, List<SeatCloneGuardEvent>>();
        var counts = new Dictionary<Guid, (int Collisions, int Reactivations)>();
        foreach (var seatId in seatIds)
        {
            recent[seatId] = await _db.SeatCloneGuardEvents.AsNoTracking()
                .Where(row => row.LicenseSeatId == seatId)
                .OrderByDescending(row => row.OccurredAt)
                .Take(CloneGuardEventsPerSeat)
                .ToListAsync(HttpContext.RequestAborted);
            var collisions = await _db.SeatCloneGuardEvents.CountAsync(row => row.LicenseSeatId == seatId
                && row.Kind == SeatCloneGuardEventKinds.Collision && row.OccurredAt > since, HttpContext.RequestAborted);
            var reactivations = await _db.SeatCloneGuardEvents.CountAsync(row => row.LicenseSeatId == seatId
                && row.Kind == SeatCloneGuardEventKinds.Reactivated && row.OccurredAt > since, HttpContext.RequestAborted);
            counts[seatId] = (collisions, reactivations);
        }

        return Ok(license.Seats.OrderByDescending(seat => seat.IsActive).ThenBy(seat => seat.FirstActivatedAt).Select(seat =>
        {
            guards.TryGetValue(seat.Id, out var guard);
            var seatEvents = recent[seat.Id];
            return new
            {
                SeatId = seat.Id,
                seat.HardwareId,
                seat.MachineName,
                seat.IsActive,
                Armed = guard != null,
                ArmedAt = guard?.ArmedAt,
                LastAcceptedAt = guard?.LastAcceptedAt,
                LastAcceptedIp = guard?.LastAcceptedIp,
                LastVmGenerationId = guard?.LastVmGenerationId,
                CollisionCount = guard?.CollisionCount ?? 0,
                LastCollisionAt = guard?.LastCollisionAt,
                DuplicateDetectedLast24h = (guard?.LastCollisionAt > since) == true,
                CollisionsLast24h = counts[seat.Id].Collisions,
                ReactivationsLast24h = counts[seat.Id].Reactivations,
                Events = seatEvents.Select(row => new
                {
                    row.Kind, row.Reason, row.OccurredAt, row.IpAddress, row.AppVersion, row.VmGenerationId,
                    row.KnownVmGenerationId, row.CorrelationId
                })
            };
        }));
    }
}
