using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

/// <summary>Adds exact conditional billing and read-only receipt observation to the existing authenticated admin surface.</summary>
public partial class AdminController
{
    /// <summary>Discriminates immutable billing receipts from administrative and self-service operations.</summary>
    private const string BillingReceiptAction = "BILLING_CONDITIONAL_V1";

    /// <summary>Exact machine cause prefix; only a matching suspension receipt can authorize its removal.</summary>
    private const string BillingSuspensionPrefix = "Billing unpaid renewal: ";

    /// <summary>One exact entitlement parameter. Keys and values are opaque, ordinal and never normalized.</summary>
    public sealed record BillingParameter(string Key, string Value);

    /// <summary>
    /// Complete rights-bearing type snapshot supplied from the existing type API. Descriptive names are
    /// excluded; parameter order is canonicalized ordinally, while duplicate keys and unknown fields fail.
    /// </summary>
    public sealed record BillingTypeSnapshot(
        Guid Id, string Slug, int DefaultDurationDays, bool IsRecurring, string DefaultAllowedVersions,
        int DefaultMaxSeats, int MaxActivationsPerDay, bool AllowAnonymous, bool IsFree,
        bool EnforceSingleUsePerHardwareId, bool DisableNewActivations, BillingParameter[] Params);

    /// <summary>
    /// Immutable command envelope. All fields, including nullable evidence, must be explicitly present.
    /// IDs other than UUIDs are bounded opaque ASCII strings. Dates are UTC at microsecond precision.
    /// PAID declares payment evidence already authenticated by Website; this API never contacts Stripe.
    /// PreviousOperationId binds suspension and recovery to the last provider billing receipt, preventing
    /// a business cause from being invented from a local flag. Period end replaces grace, never adds to it.
    /// PreviousCycleTerminatedAtUtc is null except for a distinct paid replacement after J7; Website
    /// must authenticate terminal void/cancellation of the predecessor invoice/subscription before declaring it.
    /// </summary>
    public sealed record ConditionalLicenseBillingRequest(
        Guid OperationId, string Command, Guid LicenseId, Guid ProductId, Guid CommercialSubjectId,
        Guid ExpectedOwnershipId, Guid ExpectedAuthorityVersion, bool ExpectedAuthorityIsActive,
        string? ExpectedRevocationReason, DateTime? ExpectedRevokedAt, DateTime? ExpectedExpirationUtc,
        int ExpectedMaxSeats, BillingTypeSnapshot ExpectedType, BillingTypeSnapshot DesiredType, int DesiredMaxSeats,
        string CycleId, string CustomerId, string SubscriptionId, string InvoiceId,
        DateTime PeriodStartUtc, DateTime PeriodEndUtc, DateTime? GraceStartedAtUtc,
        DateTime? PaidAtUtc, Guid? PreviousOperationId, DateTime? PreviousCycleTerminatedAtUtc);

    /// <summary>Provider result and predecessor context committed atomically with license authority.</summary>
    private sealed record BillingReceipt(string Digest, ConditionalLicenseBillingRequest Request,
        Guid AuthorityVersion, bool IsActive, string? Reason, DateTime? RevokedAt, DateTime? ExpirationUtc,
        int MaxSeats, string TypeDigest, string AllowedVersions);

    /// <summary>
    /// Applies a bounded grace, suspension or paid period to an existing commercially owned license.
    /// Requires exact authority/configuration evidence and rejects foreign revocations, transferred
    /// ownership, free/anonymous/single-use types, resellers, ambiguous inputs and expired paid periods.
    /// No legacy fallback, new key, seat restoration, email, reference overwrite or notification occurs.
    /// Locks serialize operation IDs, configuration tables (including parameter insert phantoms), global
    /// authority, license and ownership. Timeouts fail closed. Receipt failure rolls back all changes;
    /// retries are accepted only while the resulting authority and configuration remain current.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/billing-conditional")]
    public async Task<IActionResult> ApplyLicenseBillingConditionally(
        string licenseKey, [FromBody] JsonElement payload, CancellationToken cancellationToken)
    {
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        var request = ParseBillingRequest(payload);
        if (request is null || !ValidBillingRequest(request))
            return BadRequest(new { error = "billing_evidence_invalid" });
        if (scopedProductId.HasValue && scopedProductId != request.ProductId) return Unauthorized();
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "billing_provider_unavailable" });
        var digest = BillingDigest(new { Version = 1, Command = BillingReceiptAction, LicenseKey = licenseKey, Request = request });
        var decisionKey = BillingDigest(new { Version = 1, Producer = BillingReceiptAction,
            request.ProductId, request.InvoiceId, request.Command });
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        var operationLock = $"license-reactivation-v1|{request.OperationId:D}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({operationLock}, {LicenseAuthorityLockSalt}))", cancellationToken);
        // Existing type writers do not participate in the authority advisory lock. SHARE blocks
        // their DML, including insertion of a previously absent parameter. Take it before global
        // authority so a type deletion cascading to authority rows cannot reverse these two locks.
        await _db.Database.ExecuteSqlRawAsync(
            "LOCK TABLE public.\"LicenseTypes\", public.\"LicenseTypeCustomParams\" IN SHARE MODE", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);
        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses" WHERE "Id" = {request.LicenseId}
              AND "ProductId" = {request.ProductId} AND "LicenseKey" = {licenseKey} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });
        var owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {request.ProductId} AND "LicenseId" = {request.LicenseId} AND "State" = 'ACTIVE'
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (owners.Count != 1 || owners[0].Id != request.ExpectedOwnershipId
            || owners[0].OwnerSubjectId != request.CommercialSubjectId || license.PartnerCode is not null)
            return Conflict(new { error = "billing_ownership_conflict" });

        var currentType = await ReadBillingTypeAsync(license.LicenseTypeId, request.ProductId, cancellationToken);
        var desiredType = await ReadBillingTypeAsync(request.DesiredType.Id, request.ProductId, cancellationToken);
        if (currentType is null || desiredType is null || !EligibleBillingType(currentType) || !EligibleBillingType(desiredType)
            || BillingDigest(desiredType) != BillingDigest(request.DesiredType))
            return Conflict(new { error = "billing_configuration_conflict" });
        var history = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == request.OperationId, cancellationToken);
        if (history is not null)
        {
            var receipt = ReadBillingReceipt(history, request.LicenseId);
            if (receipt is null || receipt.Digest != digest || !MatchesBillingReceipt(license, currentType, receipt))
                return Conflict(new { error = "billing_operation_conflict" });
            await transaction.CommitAsync(cancellationToken);
            return Ok(BillingAcknowledgement(license, request, currentType, true));
        }
        // An alternative operation ID must not apply the same invoice phase a second time.
        // The existing unique decision index is the final arbiter for different-license races.
        if (await _db.LicenseHistories.AnyAsync(h => h.DecisionKey == decisionKey, cancellationToken))
            return Conflict(new { error = "billing_invoice_operation_conflict" });
        // Once this invoice has entered grace, omitting its predecessor must not bypass J7.
        var graceDecisionKey = BillingDigest(new { Version = 1, Producer = BillingReceiptAction,
            request.ProductId, request.InvoiceId, Command = "GRACE" });
        if (request.Command == "PAID")
        {
            var graceHistory = await _db.LicenseHistories.AsNoTracking()
                .SingleOrDefaultAsync(h => h.DecisionKey == graceDecisionKey, cancellationToken);
            if (graceHistory is not null)
            {
                var invoiceGrace = ReadBillingReceipt(graceHistory, license.Id);
                if (request.PreviousOperationId is null || invoiceGrace?.Request.Command != "GRACE"
                    || !SameBillingCycle(invoiceGrace.Request, request)
                    || request.PaidAtUtc >= invoiceGrace.Request.GraceStartedAtUtc!.Value.AddDays(7))
                    return Conflict(new { error = "billing_predecessor_required" });
            }
        }
        if (license.AuthorityVersion != request.ExpectedAuthorityVersion || license.IsActive != request.ExpectedAuthorityIsActive
            || license.RevocationReason != request.ExpectedRevocationReason || license.RevokedAt != request.ExpectedRevokedAt
            || license.ExpirationDate != request.ExpectedExpirationUtc || license.MaxSeats != request.ExpectedMaxSeats
            || BillingDigest(currentType) != BillingDigest(request.ExpectedType))
            return Conflict(new { error = "billing_authority_changed" });

        BillingReceipt? previous = null;
        if (request.PreviousOperationId.HasValue)
        {
            var row = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == request.PreviousOperationId, cancellationToken);
            previous = row is null ? null : ReadBillingReceipt(row, license.Id);
            // A fresh decision may observe an active GRACE result after activation bookkeeping
            // or a completed revoke/restore cycle. Its current CAS above is still mandatory:
            // SUSPEND removes rights and PAID requires current payment evidence. This exception
            // never accepts a stale replay or clears an outstanding foreign revocation.
            var requireHistoricalVersion = previous?.Request.Command != "GRACE" || !license.IsActive;
            if (previous is null || !MatchesBillingReceipt(license, currentType, previous, requireHistoricalVersion)
                || previous.Request.CommercialSubjectId != request.CommercialSubjectId
                || previous.Request.ExpectedOwnershipId != request.ExpectedOwnershipId
                || previous.Request.CustomerId != request.CustomerId)
                return Conflict(new { error = "billing_predecessor_conflict" });
        }
        var now = (HttpContext.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow().UtcDateTime;
        var sameCycle = previous is not null && SameBillingCycle(previous.Request, request);
        if (request.Command == "GRACE")
        {
            if (!license.IsActive || license.RevocationReason is not null || license.RevokedAt is not null
                || request.PreviousOperationId is not null || request.GraceStartedAtUtc > now
                || (license.ExpirationDate > request.PeriodStartUtc
                    && license.ExpirationDate != request.GraceStartedAtUtc!.Value.AddHours(24))
                || BillingDigest(currentType) != BillingDigest(desiredType) || request.DesiredMaxSeats != license.MaxSeats)
                return Conflict(new { error = "billing_grace_conflict" });
            // Delayed delivery must still materialize the original expiry, even when already
            // past. Otherwise a delivered license with NULL expiry could activate for ValidityDays.
            // The original-expiry guard above protects any newer acquired paid period.
            // An already exact H24 expiry may be adopted without changing it. The new atomic
            // receipt proves this current CAS decision, never an inferred legacy mutation.
            license.ExpirationDate = request.GraceStartedAtUtc!.Value.AddHours(24);
        }
        else if (request.Command == "SUSPEND")
        {
            if (previous?.Request.Command != "GRACE" || !sameCycle || !license.IsActive
                || request.GraceStartedAtUtc != previous.Request.GraceStartedAtUtc
                || now < request.GraceStartedAtUtc!.Value.AddHours(24)
                || BillingDigest(currentType) != BillingDigest(desiredType) || request.DesiredMaxSeats != license.MaxSeats)
                return Conflict(new { error = "billing_suspension_conflict" });
            license.IsActive = false;
            license.RevocationReason = BillingSuspensionPrefix + request.CycleId;
            license.RevokedAt = now;
        }
        else
        {
            // A paid replacement cycle can reuse a terminal unpaid suspension. Its old billed
            // period was never acquired: only the authenticated Website terminal declaration,
            // not that voided invoice's end date, bounds the new paid period.
            var recoverableSuspension = previous?.Request.Command == "SUSPEND"
                && license.RevocationReason == BillingSuspensionPrefix + previous.Request.CycleId;
            var validReplacementCycle = previous?.Request.Command == "SUSPEND"
                && request.PreviousCycleTerminatedAtUtc.HasValue
                && request.PreviousCycleTerminatedAtUtc >= previous.Request.GraceStartedAtUtc!.Value.AddDays(7)
                && request.PreviousCycleTerminatedAtUtc <= now
                && request.PeriodStartUtc >= request.PreviousCycleTerminatedAtUtc
                && request.CycleId != previous.Request.CycleId
                && request.SubscriptionId != previous.Request.SubscriptionId
                && request.InvoiceId != previous.Request.InvoiceId;
            if ((!license.IsActive && !recoverableSuspension)
                || (license.IsActive && (license.RevocationReason is not null || license.RevokedAt is not null))
                || request.PaidAtUtc > now || request.PeriodEndUtc <= now || request.PeriodStartUtc > now
                || (previous is not null && !sameCycle && !validReplacementCycle)
                || ((previous is null || sameCycle) && request.PreviousCycleTerminatedAtUtc.HasValue)
                || (sameCycle && previous!.Request.GraceStartedAtUtc.HasValue
                    && request.PaidAtUtc >= previous.Request.GraceStartedAtUtc.Value.AddDays(7))
                || (license.IsActive && (license.ExpirationDate > request.PeriodEndUtc
                    || (previous is null && license.ExpirationDate == request.PeriodEndUtc))))
                return Conflict(new { error = "billing_payment_conflict" });
            if (!await ApplyPaidEntitlementAsync(license, desiredType, request.DesiredMaxSeats, request.PeriodEndUtc, cancellationToken))
                return Conflict(new { error = "billing_active_seats_conflict" });
        }
        await _db.SaveChangesAsync(cancellationToken);
        // Reload PostgreSQL timestamp precision and trigger-produced authority before persisting
        // the immutable receipt. A failed receipt INSERT rolls back this mutation as well.
        await _db.Entry(license).ReloadAsync(cancellationToken);
        var resultType = request.Command == "PAID" ? desiredType : currentType;
        _db.LicenseHistories.Add(new LicenseHistory { Id = request.OperationId, LicenseId = license.Id,
            Action = BillingReceiptAction, DecisionKey = decisionKey, PerformedBy = "Website (conditional billing)",
            Details = JsonSerializer.Serialize(new BillingReceipt(digest, request, license.AuthorityVersion,
                license.IsActive, license.RevocationReason, license.RevokedAt, license.ExpirationDate,
                license.MaxSeats, BillingDigest(resultType), license.AllowedVersions)) });
        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Ok(BillingAcknowledgement(license, request, resultType, false));
    }

    /// <summary>
    /// Observes an immutable historical effect after an uncertain response without replaying it.
    /// The exact original envelope is required. Historical application and current authority are
    /// separate facts; callers must reobserve their business state and use their own current CAS.
    /// Configuration/authority locks give one coherent observation, never a future rights promise.
    /// Transferred ownership and changed revocation causes fail closed even for genuine receipts.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/billing-receipt")]
    public async Task<IActionResult> ObserveLicenseBillingReceipt(
        string licenseKey, [FromBody] JsonElement payload, CancellationToken cancellationToken)
    {
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        var request = ParseBillingRequest(payload);
        if (request is null || !ValidBillingRequest(request)) return BadRequest(new { error = "billing_evidence_invalid" });
        if (scopedProductId.HasValue && scopedProductId != request.ProductId) return Unauthorized();
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "billing_provider_unavailable" });
        var digest = BillingDigest(new { Version = 1, Command = BillingReceiptAction, LicenseKey = licenseKey, Request = request });
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        var operationLock = $"license-reactivation-v1|{request.OperationId:D}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({operationLock}, {LicenseAuthorityLockSalt}))", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync(
            "LOCK TABLE public.\"LicenseTypes\", public.\"LicenseTypeCustomParams\" IN SHARE MODE", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);
        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses" WHERE "Id" = {request.LicenseId}
              AND "ProductId" = {request.ProductId} AND "LicenseKey" = {licenseKey} FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });
        var owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {request.ProductId} AND "LicenseId" = {request.LicenseId} AND "State" = 'ACTIVE'
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (owners.Count != 1 || owners[0].Id != request.ExpectedOwnershipId
            || owners[0].OwnerSubjectId != request.CommercialSubjectId || license.PartnerCode is not null)
            return Conflict(new { error = "billing_ownership_conflict" });
        var history = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == request.OperationId, cancellationToken);
        var receipt = history is null ? null : ReadBillingReceipt(history, license.Id);
        if (receipt is null || receipt.Digest != digest) return Conflict(new { error = "billing_receipt_conflict" });
        if (license.RevocationReason != receipt.Reason || license.RevokedAt != receipt.RevokedAt)
            return Conflict(new { error = "billing_observation_cause_conflict" });
        var type = await ReadBillingTypeAsync(license.LicenseTypeId, request.ProductId, cancellationToken);
        var protectedResultMatches = type is not null && EligibleBillingType(type)
            && MatchesBillingReceipt(license, type, receipt, requireHistoricalVersion: false);
        await transaction.CommitAsync(cancellationToken);
        return Ok(new {
            AppliedHistorically = true, request.OperationId, request.Command,
            request.CycleId, request.CustomerId, request.SubscriptionId, request.InvoiceId,
            request.PeriodStartUtc, request.PeriodEndUtc,
            request.PreviousOperationId, request.PreviousCycleTerminatedAtUtc,
            HistoricalResult = new { receipt.AuthorityVersion, receipt.IsActive, receipt.Reason,
                receipt.RevokedAt, receipt.ExpirationUtc, receipt.MaxSeats, receipt.TypeDigest, receipt.AllowedVersions },
            CurrentAuthority = new { license.Id, license.ProductId, license.LicenseKey,
                request.CommercialSubjectId, CommercialOwnershipId = request.ExpectedOwnershipId,
                license.AuthorityVersion, license.IsActive, license.RevocationReason, license.RevokedAt,
                license.ExpirationDate, license.MaxSeats, license.AllowedVersions, Type = type },
            ResultVersionMatchesCurrent = license.AuthorityVersion == receipt.AuthorityVersion,
            ProtectedResultMatchesCurrent = protectedResultMatches });
    }

    /// <summary>Exact read-only authority evidence for an already issued commercial owner, including first delivery before billing receipts exist.</summary>
    public sealed record LicenseBillingAuthorityRequest(Guid LicenseId, Guid ProductId, Guid CommercialSubjectId,
        Guid ExpectedOwnershipId, Guid ExpectedAuthorityVersion);

    /// <summary>
    /// Verifies an exact current owner and version without creating an operation, history or entitlement.
    /// Configuration, license and ownership are observed under the billing lock order. The returned
    /// snapshot is not a payment receipt or a future rights promise; Website still enforces its own policy.
    /// Revoked, expired and otherwise ineligible states remain explicit observations rather than grants.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/billing-authority")]
    public async Task<IActionResult> ObserveLicenseBillingAuthority(
        string licenseKey, [FromBody] JsonElement payload, CancellationToken cancellationToken)
    {
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        if (!CompleteBillingJson(payload, typeof(LicenseBillingAuthorityRequest)))
            return BadRequest(new { error = "billing_authority_evidence_invalid" });
        LicenseBillingAuthorityRequest? request;
        try { request = payload.Deserialize<LicenseBillingAuthorityRequest>(new JsonSerializerOptions {
            PropertyNameCaseInsensitive = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }); }
        catch (JsonException) { return BadRequest(new { error = "billing_authority_evidence_invalid" }); }
        if (request is null || request.LicenseId == Guid.Empty || request.ProductId == Guid.Empty
            || request.CommercialSubjectId == Guid.Empty || request.ExpectedOwnershipId == Guid.Empty
            || request.ExpectedAuthorityVersion == Guid.Empty || !ValidBillingId(licenseKey))
            return BadRequest(new { error = "billing_authority_evidence_invalid" });
        if (scopedProductId.HasValue && scopedProductId != request.ProductId) return Unauthorized();
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "billing_provider_unavailable" });
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync(
            "LOCK TABLE public.\"LicenseTypes\", public.\"LicenseTypeCustomParams\" IN SHARE MODE", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);
        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses" WHERE "Id" = {request.LicenseId}
              AND "ProductId" = {request.ProductId} AND "LicenseKey" = {licenseKey} FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });
        var owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {request.ProductId} AND "LicenseId" = {request.LicenseId} AND "State" = 'ACTIVE'
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (owners.Count != 1 || owners[0].Id != request.ExpectedOwnershipId
            || owners[0].OwnerSubjectId != request.CommercialSubjectId || license.PartnerCode is not null)
            return Conflict(new { error = "billing_ownership_conflict" });
        if (license.AuthorityVersion != request.ExpectedAuthorityVersion)
            return Conflict(new { error = "billing_authority_changed" });
        var type = await ReadBillingTypeAsync(license.LicenseTypeId, request.ProductId, cancellationToken);
        if (type is null) return Conflict(new { error = "billing_configuration_unavailable" });
        await transaction.CommitAsync(cancellationToken);
        return Ok(new { CurrentAuthority = new { license.Id, license.ProductId, license.LicenseKey,
            request.CommercialSubjectId, CommercialOwnershipId = request.ExpectedOwnershipId,
            license.AuthorityVersion, license.IsActive, license.RevocationReason, license.RevokedAt,
            license.ExpirationDate, license.MaxSeats, license.AllowedVersions, Type = type,
            license.HardwareId, license.ActivationDate } });
    }

    /// <summary>Reads a complete type snapshot under the caller's configuration table locks.</summary>
    private async Task<BillingTypeSnapshot?> ReadBillingTypeAsync(Guid id, Guid productId, CancellationToken cancellationToken)
    {
        var type = await _db.LicenseTypes.AsNoTracking().Include(t => t.CustomParams)
            .SingleOrDefaultAsync(t => t.Id == id && t.ProductId == productId, cancellationToken);
        return type is null ? null : new BillingTypeSnapshot(type.Id, type.Slug, type.DefaultDurationDays,
            type.IsRecurring, type.DefaultAllowedVersions, type.DefaultMaxSeats, type.MaxActivationsPerDay,
            type.AllowAnonymous, type.IsFree, type.EnforceSingleUsePerHardwareId, type.DisableNewActivations,
            type.CustomParams.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new BillingParameter(p.Key, p.Value)).ToArray());
    }

    /// <summary>
    /// Applies the common absolute paid result only after the caller has locked and authorized its own provenance.
    /// Preserves existing seats, activation, keys and references; this helper never commits or creates authority proofs.
    /// </summary>
    private async Task<bool> ApplyPaidEntitlementAsync(License license, BillingTypeSnapshot type, int seats,
        DateTime periodEndUtc, CancellationToken cancellationToken)
    {
        var activeSeats = await _db.LicenseSeats.CountAsync(s => s.LicenseId == license.Id && s.IsActive, cancellationToken);
        if (seats < activeSeats) return false;
        license.IsActive = true;
        license.RevocationReason = null;
        license.RevokedAt = null;
        license.ExpirationDate = periodEndUtc;
        license.LicenseTypeId = type.Id;
        license.MaxSeats = seats;
        license.AllowedVersions = type.DefaultAllowedVersions;
        return true;
    }

    /// <summary>Returns a bound acknowledgement; clients must verify every identity and resulting authority.</summary>
    private static object BillingAcknowledgement(License license, ConditionalLicenseBillingRequest request,
        BillingTypeSnapshot type, bool idempotent) => new { request.OperationId, request.Command,
        LicenseId = license.Id, license.ProductId, request.CommercialSubjectId,
        CommercialOwnershipId = request.ExpectedOwnershipId, license.LicenseKey, license.AuthorityVersion,
        AuthorityIsActive = license.IsActive, license.RevocationReason, license.RevokedAt,
        license.ExpirationDate, license.MaxSeats, Type = type, license.AllowedVersions,
        request.CycleId, request.CustomerId, request.SubscriptionId, request.InvoiceId,
        request.PeriodStartUtc, request.PeriodEndUtc, request.PreviousOperationId,
        request.PreviousCycleTerminatedAtUtc, Idempotent = idempotent };

    /// <summary>Matches protected receipt state; only a fresh active GRACE successor may reobserve its historical version.</summary>
    private static bool MatchesBillingReceipt(License license, BillingTypeSnapshot type, BillingReceipt receipt,
        bool requireHistoricalVersion = true) =>
        (!requireHistoricalVersion || license.AuthorityVersion == receipt.AuthorityVersion) && license.IsActive == receipt.IsActive
        && license.RevocationReason == receipt.Reason && license.RevokedAt == receipt.RevokedAt
        && license.ExpirationDate == receipt.ExpirationUtc && license.MaxSeats == receipt.MaxSeats
        && license.AllowedVersions == receipt.AllowedVersions && BillingDigest(type) == receipt.TypeDigest;

    /// <summary>Refuses other commands and malformed history rather than synthesizing billing provenance.</summary>
    private static BillingReceipt? ReadBillingReceipt(LicenseHistory history, Guid licenseId)
    {
        if (history.Action != BillingReceiptAction || history.LicenseId != licenseId) return null;
        try { return JsonSerializer.Deserialize<BillingReceipt>(history.Details ?? "null"); }
        catch (JsonException) { return null; }
    }

    /// <summary>Compares all cycle identities and the absolute billed period with ordinal string semantics.</summary>
    private static bool SameBillingCycle(ConditionalLicenseBillingRequest left, ConditionalLicenseBillingRequest right) =>
        left.CycleId == right.CycleId && left.CustomerId == right.CustomerId && left.SubscriptionId == right.SubscriptionId
        && left.InvoiceId == right.InvoiceId && left.PeriodStartUtc == right.PeriodStartUtc && left.PeriodEndUtc == right.PeriodEndUtc;

    /// <summary>Excludes free, anonymous, single-use and disabled types; Website additionally proves canonical Pro provenance.</summary>
    private static bool EligibleBillingType(BillingTypeSnapshot type) => !type.IsFree && !type.AllowAnonymous
        && !type.EnforceSingleUsePerHardwareId && !type.DisableNewActivations && type.DefaultDurationDays > 0;

    /// <summary>Hashes versioned typed JSON using exact strings; callers sort parameter sets before hashing.</summary>
    private static string BillingDigest<T>(T value) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));

    /// <summary>Validates format and command-specific temporal evidence without repairing opaque inputs.</summary>
    private static bool ValidBillingRequest(ConditionalLicenseBillingRequest r) =>
        r.OperationId != Guid.Empty && r.LicenseId != Guid.Empty && r.ProductId != Guid.Empty
        && r.CommercialSubjectId != Guid.Empty && r.ExpectedOwnershipId != Guid.Empty && r.ExpectedAuthorityVersion != Guid.Empty
        && r.PreviousOperationId != Guid.Empty && r.PreviousOperationId != r.OperationId
        && r.Command is "GRACE" or "SUSPEND" or "PAID"
        && ValidBillingId(r.CycleId) && ValidBillingId(r.CustomerId) && ValidBillingId(r.SubscriptionId) && ValidBillingId(r.InvoiceId)
        && ValidBillingDate(r.PeriodStartUtc) && ValidBillingDate(r.PeriodEndUtc)
        && r.PeriodEndUtc > r.PeriodStartUtc && r.PeriodEndUtc - r.PeriodStartUtc <= TimeSpan.FromDays(3660)
        && (r.ExpectedRevokedAt is null || ValidBillingDate(r.ExpectedRevokedAt.Value))
        && (r.ExpectedExpirationUtc is null || ValidBillingDate(r.ExpectedExpirationUtc.Value))
        && (r.GraceStartedAtUtc is null || ValidBillingDate(r.GraceStartedAtUtc.Value))
        && (r.PreviousCycleTerminatedAtUtc is null || (r.Command == "PAID" && r.PreviousOperationId.HasValue
            && ValidBillingDate(r.PreviousCycleTerminatedAtUtc.Value)))
        && r.ExpectedRevocationReason?.Length is not > 512
        && r.ExpectedMaxSeats is >= 1 and <= 10000 && r.DesiredMaxSeats is >= 1 and <= 10000
        && ValidBillingType(r.ExpectedType) && ValidBillingType(r.DesiredType)
        && (r.Command == "PAID" ? r.PaidAtUtc.HasValue && ValidBillingDate(r.PaidAtUtc.Value)
            && r.PaidAtUtc >= r.PeriodStartUtc && r.PaidAtUtc < r.PeriodEndUtc
            : r.PaidAtUtc is null && r.GraceStartedAtUtc.HasValue
                && r.GraceStartedAtUtc >= r.PeriodStartUtc && r.GraceStartedAtUtc < r.PeriodEndUtc);

    /// <summary>Bounds opaque protocol IDs to printable ASCII without whitespace/case normalization.</summary>
    private static bool ValidBillingId(string? value) => value is { Length: > 0 and <= 255 }
        && value.All(c => c is >= '!' and <= '~');

    /// <summary>Requires UTC dates that round-trip exactly through PostgreSQL microsecond timestamps.</summary>
    private static bool ValidBillingDate(DateTime value) => value.Kind == DateTimeKind.Utc
        && value.Year is >= 2000 and <= 2200 && value.Ticks % 10 == 0;

    /// <summary>Bounds configuration data and rejects duplicate exact parameter keys before sorting.</summary>
    private static bool ValidBillingType(BillingTypeSnapshot? type) => type is not null && type.Id != Guid.Empty
        && ValidBillingId(type.Slug) && type.DefaultAllowedVersions is { Length: > 0 and <= 512 }
        && type.DefaultDurationDays is >= 1 and <= 3660 && type.DefaultMaxSeats is >= 1 and <= 10000
        && type.MaxActivationsPerDay >= 0 && type.Params is { Length: <= 128 }
        && type.Params.All(p => p is not null && ValidBillingId(p.Key) && p.Value is { Length: <= 4096 })
        && type.Params.Select(p => p.Key).Distinct(StringComparer.Ordinal).Count() == type.Params.Length;

    /// <summary>Rejects omitted/unknown/duplicate fields recursively and canonicalizes only parameter ordering.</summary>
    private static ConditionalLicenseBillingRequest? ParseBillingRequest(JsonElement payload)
    {
        if (!CompleteBillingJson(payload, typeof(ConditionalLicenseBillingRequest))) return null;
        try
        {
            var request = payload.Deserialize<ConditionalLicenseBillingRequest>(new JsonSerializerOptions {
                PropertyNameCaseInsensitive = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow });
            if (request is null || !ValidBillingType(request.ExpectedType) || !ValidBillingType(request.DesiredType)) return null;
            return request with {
                ExpectedType = request.ExpectedType with { Params = request.ExpectedType.Params.OrderBy(p => p.Key, StringComparer.Ordinal).ToArray() },
                DesiredType = request.DesiredType with { Params = request.DesiredType.Params.OrderBy(p => p.Key, StringComparer.Ordinal).ToArray() } };
        }
        catch (JsonException) { return null; }
    }

    /// <summary>Checks JSON member presence and aliases against the explicit record shape, including nested arrays.</summary>
    private static bool CompleteBillingJson(JsonElement value, Type shape)
    {
        if (value.ValueKind != JsonValueKind.Object) return false;
        var fields = shape.GetProperties().ToDictionary(p => p.Name, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in value.EnumerateObject())
        {
            if (!fields.TryGetValue(field.Name, out var property) || !seen.Add(field.Name)) return false;
            if (property.PropertyType == typeof(BillingTypeSnapshot) && !CompleteBillingJson(field.Value, typeof(BillingTypeSnapshot))) return false;
            if (property.PropertyType == typeof(BillingParameter[]) && (field.Value.ValueKind != JsonValueKind.Array
                || field.Value.GetArrayLength() > 128 || field.Value.EnumerateArray().Any(p => !CompleteBillingJson(p, typeof(BillingParameter))))) return false;
        }
        return seen.Count == fields.Count;
    }
}
