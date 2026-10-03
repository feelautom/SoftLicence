using System.Data;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>Separates short renewal continuity from the existing first-payment-failure grace.</summary>
    private const string ContinuityAction = "RENEWAL_CONTINUITY_V1";

    /// <summary>
    /// Website-authenticated recurring funding declaration with exact current authority. GRANT changes
    /// only expiry to PaidPeriodEndUtc+15 minutes; CANCEL restores the predecessor's original expiry.
    /// Nullable ownership is permitted only for an ownerless historical key, never a canonical key.
    /// All properties must be supplied. Opaque Stripe/local IDs retain ordinal spelling.
    /// </summary>
    public sealed record RenewalContinuityRequest(Guid OperationId, string Command, Guid LicenseId, Guid ProductId,
        Guid ExpectedAuthorityVersion, Guid? ExpectedOwnershipId, Guid? CommercialSubjectId,
        DateTime ExpectedExpirationUtc, BillingTypeSnapshot ExpectedType, int ExpectedMaxSeats,
        string LocalLicenseId, string LocalUserId, string CustomerId, string SubscriptionId,
        DateTime PaidPeriodEndUtc, Guid? PreviousOperationId);

    /// <summary>Immutable before/after receipt; retained even after a paid renewal supersedes continuity.</summary>
    private sealed record ContinuityReceipt(string Digest, RenewalContinuityRequest Request,
        Guid AuthorityVersion, DateTime ExpirationUtc, string TypeDigest, string AllowedVersions);

    /// <summary>
    /// Applies or observes an exact once-per-period renewal extension under the billing lock order.
    /// Requires authenticated product scope, live active authority and matching configuration/ownership.
    /// Unknown outcomes are retried with the same immutable body; replay never reapplies an old expiry.
    /// No seat, reference, customer, status or type is changed. A concurrent revocation or renewal wins
    /// through CAS. Website must prove its local user/subscription funding before this trusted S2S call.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/renewal-continuity")]
    public Task<IActionResult> ApplyRenewalContinuity(string licenseKey, [FromBody] JsonElement payload,
        CancellationToken cancellationToken) => ExecuteRenewalContinuity(licenseKey, payload, false, cancellationToken);

    /// <summary>Observes the original exact receipt under the same locks without applying an absent operation.</summary>
    [HttpPost("licenses/{licenseKey}/renewal-continuity/receipt")]
    public Task<IActionResult> ObserveRenewalContinuity(string licenseKey, [FromBody] JsonElement payload,
        CancellationToken cancellationToken) => ExecuteRenewalContinuity(licenseKey, payload, true, cancellationToken);

    /// <summary>Shared authenticated transaction; observeOnly returns proven absence and never writes authority/history.</summary>
    private async Task<IActionResult> ExecuteRenewalContinuity(string licenseKey, JsonElement payload,
        bool observeOnly, CancellationToken cancellationToken)
    {
        var (authorized, productScope) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        var request = ParseContinuity(payload);
        if (request is null) return BadRequest(new { error = "continuity_evidence_invalid" });
        if (productScope.HasValue && productScope != request.ProductId) return Unauthorized();
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "continuity_provider_unavailable" });
        var digest = BillingDigest(new { Version = 1, LicenseKey = licenseKey, Request = request });
        var decision = BillingDigest(new { Producer = ContinuityAction, request.LicenseId,
            request.SubscriptionId, request.PaidPeriodEndUtc, request.Command });
        await using var tx = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({$"license-reactivation-v1|{request.OperationId:D}"}, {LicenseAuthorityLockSalt}))", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("LOCK TABLE public.\"LicenseTypes\", public.\"LicenseTypeCustomParams\" IN SHARE MODE", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);
        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses" WHERE "Id"={request.LicenseId}
              AND "ProductId"={request.ProductId} AND "LicenseKey"={licenseKey} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });
        var owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships" WHERE "LicenseId"={license.Id}
              AND "ProductId"={license.ProductId} AND "State"='ACTIVE' ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (request.ExpectedOwnershipId.HasValue
            ? owners.Count != 1 || owners[0].Id != request.ExpectedOwnershipId || owners[0].OwnerSubjectId != request.CommercialSubjectId
            : owners.Count != 0) return Conflict(new { error = "continuity_ownership_conflict" });
        var type = await ReadBillingTypeAsync(license.LicenseTypeId, license.ProductId, cancellationToken);
        if (type is null || !EligibleBillingType(type) || !type.IsRecurring || license.PartnerCode is not null)
            return Conflict(new { error = "continuity_configuration_conflict" });
        var history = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == request.OperationId, cancellationToken);
        if (history is not null)
        {
            var receipt = ReadContinuity(history, license.Id);
            if (receipt is null || receipt.Digest != digest) return Conflict(new { error = "continuity_operation_conflict" });
            // An acknowledged historical write is not current entitlement. The caller must inspect MatchesCurrent.
            await tx.CommitAsync(cancellationToken);
            return Ok(ContinuityResponse(license, type, receipt, owners.Count == 1 ? owners[0].Id : null));
        }
        if (await _db.LicenseHistories.AnyAsync(h => h.DecisionKey == decision, cancellationToken))
            return Conflict(new { error = "continuity_period_conflict" });
        if (observeOnly) return NotFound(new { error = "continuity_receipt_absent" });
        var previousHistory = request.Command == "CANCEL" ? await _db.LicenseHistories.AsNoTracking()
            .SingleOrDefaultAsync(h => h.Id == request.PreviousOperationId, cancellationToken) : null;
        var previous = previousHistory is null ? null : ReadContinuity(previousHistory, license.Id);
        // A cancellation frozen before GRANT may arrive just after it. Only its exact original
        // predecessor can bridge that version change, never an arbitrary newer license snapshot.
        var cancelledRacingGrant = request.Command == "CANCEL" && previous is not null
            && previous.Request.Command == "GRANT" && SameContinuityIdentity(previous.Request, request)
            && previous.Request.ExpectedAuthorityVersion == request.ExpectedAuthorityVersion
            && request.ExpectedExpirationUtc == request.PaidPeriodEndUtc && MatchesContinuity(license, type, previous);
        if (!license.IsActive || license.RevocationReason is not null || license.RevokedAt is not null
            || (!cancelledRacingGrant && (license.AuthorityVersion != request.ExpectedAuthorityVersion || license.ExpirationDate != request.ExpectedExpirationUtc))
            || license.MaxSeats != request.ExpectedMaxSeats || BillingDigest(type) != BillingDigest(request.ExpectedType))
            return Conflict(new { error = "continuity_authority_changed" });
        var now = (HttpContext.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow().UtcDateTime;
        if (request.Command == "GRANT")
        {
            var cancelledDecision = BillingDigest(new { Producer = ContinuityAction, request.LicenseId,
                request.SubscriptionId, request.PaidPeriodEndUtc, Command = "CANCEL" });
            if (await _db.LicenseHistories.AnyAsync(h => h.DecisionKey == cancelledDecision, cancellationToken))
                return Conflict(new { error = "continuity_cancelled" });
            // Preparing before expiry closes the gap before invoice.created. A replay cannot restart this clock.
            if (request.ExpectedExpirationUtc != request.PaidPeriodEndUtc || request.PaidPeriodEndUtc <= now
                || request.PaidPeriodEndUtc > now.AddDays(1) || request.PreviousOperationId.HasValue)
                return Conflict(new { error = "continuity_window_conflict" });
            license.ExpirationDate = request.PaidPeriodEndUtc.AddMinutes(15);
        }
        else
        {
            if (previous is null && previousHistory is not null)
                return Conflict(new { error = "continuity_predecessor_conflict" });
            if (previous is null ? request.ExpectedExpirationUtc != request.PaidPeriodEndUtc
                : previous.Request.Command != "GRANT" || !SameContinuityIdentity(previous.Request, request)
                  || !MatchesContinuity(license, type, previous) || (!cancelledRacingGrant && request.ExpectedExpirationUtc != previous.ExpirationUtc))
                return Conflict(new { error = "continuity_predecessor_conflict" });
            // An absent grant receives a cancellation tombstone under the same license lock. A
            // concurrent delayed GRANT cannot escape an earlier cancellation and add fresh rights.
            license.ExpirationDate = request.PaidPeriodEndUtc;
        }
        await _db.SaveChangesAsync(cancellationToken);
        await _db.Entry(license).ReloadAsync(cancellationToken);
        var result = new ContinuityReceipt(digest, request, license.AuthorityVersion,
            license.ExpirationDate!.Value, BillingDigest(type), license.AllowedVersions);
        _db.LicenseHistories.Add(new LicenseHistory { Id = request.OperationId, LicenseId = license.Id,
            Action = ContinuityAction, DecisionKey = decision, PerformedBy = "Website (renewal continuity)", Details = JsonSerializer.Serialize(result) });
        await _db.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);
        return Ok(ContinuityResponse(license, type, result, owners.Count == 1 ? owners[0].Id : null));
    }

    /// <summary>Proves the exact predecessor extension before the existing H24 GRACE may replace it.</summary>
    private async Task<bool> HasBillingContinuityAsync(License license, BillingTypeSnapshot type,
        ConditionalLicenseBillingRequest request, CancellationToken cancellationToken)
    {
        var key = BillingDigest(new { Producer = ContinuityAction, request.LicenseId,
            request.SubscriptionId, PaidPeriodEndUtc = request.PeriodStartUtc, Command = "GRANT" });
        var history = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.DecisionKey == key, cancellationToken);
        var prior = history is null ? null : ReadContinuity(history, license.Id);
        return prior is not null && prior.Request.CustomerId == request.CustomerId
            && prior.Request.ExpectedOwnershipId == request.ExpectedOwnershipId && prior.Request.CommercialSubjectId == request.CommercialSubjectId
            && MatchesContinuity(license, type, prior);
    }

    /// <summary>Requires unchanged protected rights while allowing activation-only authority-version bookkeeping.</summary>
    private static bool MatchesContinuity(License license, BillingTypeSnapshot type, ContinuityReceipt receipt) =>
        license.IsActive && license.RevocationReason is null && license.RevokedAt is null
        && license.ExpirationDate == receipt.ExpirationUtc && license.MaxSeats == receipt.Request.ExpectedMaxSeats
        && license.AllowedVersions == receipt.AllowedVersions && BillingDigest(type) == receipt.TypeDigest;

    /// <summary>Returns the immutable result separately from current authority; a superseded receipt grants no rights.</summary>
    private static object ContinuityResponse(License license, BillingTypeSnapshot type, ContinuityReceipt receipt, Guid? owner) =>
        new { AppliedHistorically = true, receipt.Request, receipt.AuthorityVersion, receipt.ExpirationUtc,
            MatchesCurrent = owner == receipt.Request.ExpectedOwnershipId && MatchesContinuity(license, type, receipt),
            CurrentAuthorityVersion = license.AuthorityVersion, CurrentExpirationUtc = license.ExpirationDate };

    /// <summary>Reads only this contract's history; malformed or other-feature history never becomes continuity evidence.</summary>
    private static ContinuityReceipt? ReadContinuity(LicenseHistory history, Guid licenseId)
    {
        if (history.Action != ContinuityAction || history.LicenseId != licenseId) return null;
        try { return JsonSerializer.Deserialize<ContinuityReceipt>(history.Details ?? "null"); }
        catch (JsonException) { return null; }
    }

    /// <summary>Cancellation preserves every customer, product, owner and original period identity byte-for-byte.</summary>
    private static bool SameContinuityIdentity(RenewalContinuityRequest a, RenewalContinuityRequest b) =>
        a.LicenseId == b.LicenseId && a.ProductId == b.ProductId && a.ExpectedOwnershipId == b.ExpectedOwnershipId
        && a.CommercialSubjectId == b.CommercialSubjectId && a.LocalLicenseId == b.LocalLicenseId && a.LocalUserId == b.LocalUserId
        && a.CustomerId == b.CustomerId && a.SubscriptionId == b.SubscriptionId && a.PaidPeriodEndUtc == b.PaidPeriodEndUtc;

    /// <summary>Rejects missing/aliased fields and invalid clocks; canonicalizes only ordinal parameter ordering.</summary>
    private static RenewalContinuityRequest? ParseContinuity(JsonElement payload)
    {
        if (!CompleteBillingJson(payload, typeof(RenewalContinuityRequest))) return null;
        try
        {
            var r = payload.Deserialize<RenewalContinuityRequest>(new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (r is null || r.OperationId == Guid.Empty || r.LicenseId == Guid.Empty || r.ProductId == Guid.Empty
                || r.ExpectedAuthorityVersion == Guid.Empty || r.ExpectedOwnershipId == Guid.Empty || r.CommercialSubjectId == Guid.Empty
                || r.ExpectedOwnershipId.HasValue != r.CommercialSubjectId.HasValue || r.PreviousOperationId == Guid.Empty
                || r.PreviousOperationId == r.OperationId || r.Command is not ("GRANT" or "CANCEL")
                || (r.Command == "CANCEL" && !r.PreviousOperationId.HasValue)
                || !ValidBillingDate(r.ExpectedExpirationUtc) || !ValidBillingDate(r.PaidPeriodEndUtc)
                || r.ExpectedMaxSeats is < 1 or > 10000 || !ValidBillingType(r.ExpectedType)
                || !ValidBillingId(r.LocalLicenseId) || !ValidBillingId(r.LocalUserId)
                || !ValidBillingId(r.CustomerId) || !ValidBillingId(r.SubscriptionId)) return null;
            return r with { ExpectedType = r.ExpectedType with { Params = r.ExpectedType.Params.OrderBy(p => p.Key, StringComparer.Ordinal).ToArray() } };
        }
        catch (JsonException) { return null; }
    }
}
