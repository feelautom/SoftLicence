using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Protects only a new first-order gift against cross-subject reuse, under the existing product authority lock.</summary>
internal static class FirstOrderFreeActivationPolicy
{
    /// <summary>Stable refusal/revocation reason, independent of localized presentation.</summary>
    internal const string RefusalCode = "FIRST_ORDER_FREE_HARDWARE_CONFLICT";

    /// <summary>
    /// Requires a dated link observation within a proven commercial ownership. Same-license
    /// reactivation, same subject, other products, paid/trial/gift and unknown provenance remain eligible.
    /// Seat cleanup retains inactive links; no email, telemetry, IP or payment-name inference occurs.
    /// </summary>
    internal static async Task<bool> MustRefuseAsync(LicenseDbContext db, License license, string hardwareId,
        CancellationToken token)
    {
        if (license.CommercialNature != "FIRST_ORDER_FREE") return false;
        if (await db.LicenseSeats.AnyAsync(x => x.LicenseId == license.Id && x.HardwareId == hardwareId, token)
            || (license.HardwareId == hardwareId && license.ActivationDate.HasValue)) return false;
        var subjects = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .Where(x => x.ProductId == license.ProductId && x.LicenseId == license.Id && x.State == "ACTIVE")
            .Select(x => x.OwnerSubjectId).ToListAsync(token);
        if (subjects.Count != 1) return false;
        var subject = subjects[0];
        var now = DateTime.UtcNow;
        // Reused seat rows may span unlink/transfer gaps; never infer continuous ownership over that interval.
        var linked = from seat in db.LicenseSeats
                     join owner in db.RuntimeRecoveryCommercialOwnerships on seat.LicenseId equals owner.LicenseId
                     where owner.ProductId == license.ProductId && owner.LicenseId != license.Id
                         && owner.OwnerSubjectId != subject && seat.HardwareId == hardwareId
                         && ((owner.CreatedAtUtc <= seat.FirstActivatedAt && seat.FirstActivatedAt < (owner.EndedAtUtc ?? now))
                             || (owner.CreatedAtUtc <= seat.LastCheckInAt && seat.LastCheckInAt < (owner.EndedAtUtc ?? now)))
                     select seat.Id;
        if (await linked.AnyAsync(token)) return true;
        // A -> B -> A can overwrite both seat timestamps. Accepted immutable decisions preserve
        // B's actual intermediate activation without inventing a continuous link through an unlink gap.
        var decisions = from history in db.LicenseHistories.AsNoTracking()
                        join owner in db.RuntimeRecoveryCommercialOwnerships on history.LicenseId equals owner.LicenseId
                        where owner.ProductId == license.ProductId && owner.LicenseId != license.Id
                            && owner.OwnerSubjectId != subject && history.Action == "ACTIVATION_DECISION_V1"
                            && history.DecisionResolvedHardwareId == hardwareId
                            && owner.CreatedAtUtc <= history.Timestamp
                            && (owner.EndedAtUtc == null || history.Timestamp < owner.EndedAtUtc)
                        select history;
        await foreach (var history in decisions.AsAsyncEnumerable().WithCancellation(token))
        {
            var decision = LicenseDecisionHistoryProjection.FromHistory(history, license.ProductId, history.DecisionOperationId).Decision;
            // Historical offline decisions remain valid evidence even though TKT-002031 removed
            // the producer. Dropping this phase would silently weaken existing ownership history.
            if (decision is { Outcome: "accepted", HttpStatus: 200, Code: "accepted" }
                && decision.ResolvedHardwareId == hardwareId
                && decision.Phase is "legacy_activation" or "offline_activation" or "distribution_finalize" or "runtime_license_transfer")
                return true;
        }
        // Pre-seat schema licenses may still carry a proven activation instant. Unknown owners are not backfilled.
        return await (from old in db.Licenses
                      join owner in db.RuntimeRecoveryCommercialOwnerships on old.Id equals owner.LicenseId
                      where old.ProductId == license.ProductId && old.Id != license.Id && old.HardwareId == hardwareId
                          && old.ActivationDate.HasValue && owner.OwnerSubjectId != subject
                          && owner.CreatedAtUtc <= old.ActivationDate && (owner.EndedAtUtc == null || old.ActivationDate < owner.EndedAtUtc)
                      select old.Id).AnyAsync(token);
    }
}
