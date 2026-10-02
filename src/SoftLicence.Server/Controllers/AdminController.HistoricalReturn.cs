using System.Data;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>Present-day administrative attribution, never an inferred historical issuance.</summary>
    private const string HistoricalReturnProvenance = "WEBSITE_HISTORICAL_RETURN_V1";
    /// <summary>Separates return receipts from canonical provisioning and ordinary billing history.</summary>
    private const string HistoricalReturnAction = "HISTORICAL_RETURN_PAID_V1";
    /// <summary>Closed Website migration boundary; later licenses cannot enter this compatibility contract.</summary>
    private static readonly DateTime HistoricalReturnCutoff = new(2026, 9, 7, 21, 13, 4, 759, DateTimeKind.Utc);

    /// <summary>Exact frozen Website identity. The digest is its attested local snapshot, not provider issuance evidence.</summary>
    public sealed record HistoricalReturnIdentity(string LocalLicenseId, string UserId, string LicenseKey,
        Guid ProviderLicenseId, string SubscriptionId, DateTime LicenseCreatedAtUtc, DateTime RecordedAtUtc,
        string SnapshotSha256);

    /// <summary>Fresh authenticated Website payment declaration. This provider does not contact Stripe.</summary>
    public sealed record HistoricalReturnPayment(string OrderId, string CustomerId, string SubscriptionId,
        string InvoiceId, string PaymentIntentId, long AmountPaidCents, string Currency, DateTime PeriodStartUtc,
        DateTime PeriodEndUtc, DateTime PaidAtUtc, DateTime ObservedAtUtc, bool RefundFree, bool DisputeFree);

    /// <summary>
    /// Explicit administrative attestation of the old Website termination, not a reconstructed provider receipt.
    /// Website must re-read the exact void invoice and canceled subscription and prove its durable termination ledger.
    /// </summary>
    public sealed record HistoricalReturnTerminal(string InvoiceId, string SubscriptionId, string CustomerId,
        string LedgerId, string LedgerSha256, DateTime GraceStartedAtUtc, DateTime TerminatedAtUtc,
        DateTime InvoiceVoidedAtUtc, DateTime SubscriptionCanceledAtUtc, DateTime ProviderRevokedAtUtc,
        string DeactivationCorrelationId, bool InvoiceVoid, bool SubscriptionCanceled);

    /// <summary>Closed, omission-sensitive contract binding one historical identity, exact authority and paid replacement.</summary>
    public sealed record HistoricalReturnRequest(Guid OperationId, string Provenance, string Mode,
        Guid LicenseId, Guid ProductId, Guid CommercialSubjectId, string ExpectedOwnershipState,
        Guid ExpectedAuthorityVersion, bool ExpectedAuthorityIsActive, string? ExpectedRevocationReason,
        DateTime? ExpectedRevokedAt, DateTime? ExpectedExpirationUtc, int ExpectedMaxSeats,
        BillingTypeSnapshot ExpectedType, BillingTypeSnapshot DesiredType, int DesiredMaxSeats,
        HistoricalReturnIdentity Historical, HistoricalReturnPayment Payment, HistoricalReturnTerminal? Terminal);

    /// <summary>Exact committed attribution/payment result; replay must still match current ownership and authority.</summary>
    private sealed record HistoricalReturnReceipt(string Digest, HistoricalReturnRequest Request,
        Guid OwnershipId, Guid AuthorityVersion, string TypeDigest, string AllowedVersions);

    /// <summary>
    /// Atomically attributes an unowned pre-cutoff license and applies a verified paid period on the same key.
    /// The product-authenticated Website is the explicit authority for the historical linkage and payment declaration.
    /// No email inference, issuance, seat restoration, grant creation, generic reactivation or external side effect occurs.
    /// All-state ownership absence, license CAS and payment uniqueness are checked under transaction locks.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/historical-return-conditional")]
    public async Task<IActionResult> ReturnHistoricalLicenseConditionally(string licenseKey,
        [FromBody] JsonElement payload, CancellationToken cancellationToken)
    {
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        var request = ParseHistoricalReturn(payload);
        if (request is null) return BadRequest(new { error = "historical_return_evidence_invalid" });
        if (scopedProductId.HasValue && scopedProductId != request.ProductId) return Unauthorized();
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "historical_return_provider_unavailable" });
        if (licenseKey != request.Historical.LicenseKey) return Conflict(new { error = "historical_return_identity_conflict" });
        // Observation time belongs to the attempt, not the durable payment command. Website re-reads Stripe
        // on every new attempt; an outage can refresh this clock without changing operation or funding identity.
        var digest = BillingDigest(new { Version = 1, LicenseKey = licenseKey,
            Request = request with { Payment = request.Payment with { ObservedAtUtc = request.Payment.PaidAtUtc } } });
        // Reuse canonical invoice/PAID uniqueness, so changing producers cannot fund the same invoice twice.
        var decisionKey = BillingDigest(new { Version = 1, Producer = BillingReceiptAction,
            request.ProductId, request.Payment.InvoiceId, Command = "PAID" });
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        var operationLock = $"license-reactivation-v1|{request.OperationId:D}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({operationLock}, {LicenseAuthorityLockSalt}))", cancellationToken);
        var identityLock = $"historical-return-identity-v1|{request.ProductId:D}|{request.Historical.LocalLicenseId}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({identityLock}, {LicenseAuthorityLockSalt}))", cancellationToken);
        var paymentLock = $"historical-return-payment-v1|{request.ProductId:D}|{request.Payment.PaymentIntentId}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({paymentLock}, {LicenseAuthorityLockSalt}))", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync(
            "LOCK TABLE public.\"LicenseTypes\", public.\"LicenseTypeCustomParams\" IN SHARE MODE", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);
        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses" WHERE "Id" = {request.LicenseId}
              AND "ProductId" = {request.ProductId} AND "LicenseKey" = {licenseKey} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });
        // The parent row lock also conflicts with ownership FK insertion KEY SHARE. This protects absence,
        // including terminal rows, from SQL writers which do not participate in the advisory-lock protocol.
        var owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {request.ProductId} AND "LicenseId" = {request.LicenseId}
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        var currentType = await ReadBillingTypeAsync(license.LicenseTypeId, request.ProductId, cancellationToken);
        var desiredType = await ReadBillingTypeAsync(request.DesiredType.Id, request.ProductId, cancellationToken);
        if (license.PartnerCode is not null || license.ProvisioningRequestId is not null || license.ProvisioningSequence is not null
            || license.CreationDate >= HistoricalReturnCutoff || currentType is null || desiredType is null
            || !HistoricalPaidType(currentType) || !HistoricalPaidType(desiredType)
            || BillingDigest(desiredType) != BillingDigest(request.DesiredType))
            return Conflict(new { error = "historical_return_configuration_conflict" });
        var history = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == request.OperationId, cancellationToken);
        if (history is not null)
        {
            HistoricalReturnReceipt? receipt;
            try { receipt = history.Action == HistoricalReturnAction && history.LicenseId == license.Id
                    ? JsonSerializer.Deserialize<HistoricalReturnReceipt>(history.Details ?? "null") : null; }
            catch (JsonException) { receipt = null; }
            if (receipt is null || receipt.Digest != digest || owners.Count != 1 || owners[0].State != "ACTIVE"
                || owners[0].Id != receipt.OwnershipId || owners[0].OwnerSubjectId != request.CommercialSubjectId
                || owners[0].EndedAtUtc is not null || license.AuthorityVersion != receipt.AuthorityVersion
                || !license.IsActive || license.RevokedAt is not null || license.RevocationReason is not null
                || license.ExpirationDate != request.Payment.PeriodEndUtc || license.MaxSeats != request.DesiredMaxSeats
                || BillingDigest(currentType) != receipt.TypeDigest || license.AllowedVersions != receipt.AllowedVersions)
                return Conflict(new { error = "historical_return_replay_conflict" });
            await transaction.CommitAsync(cancellationToken);
            return Ok(HistoricalReturnAcknowledgement(license, request, receipt, currentType, true));
        }
        if (owners.Count != 0) return Conflict(new { error = "historical_return_ownership_conflict" });
        if (license.AuthorityVersion != request.ExpectedAuthorityVersion || license.IsActive != request.ExpectedAuthorityIsActive
            || license.RevocationReason != request.ExpectedRevocationReason || license.RevokedAt != request.ExpectedRevokedAt
            || license.ExpirationDate != request.ExpectedExpirationUtc || license.MaxSeats != request.ExpectedMaxSeats
            || BillingDigest(currentType) != BillingDigest(request.ExpectedType))
            return Conflict(new { error = "historical_return_authority_changed" });
        if (await _db.LicenseHistories.AnyAsync(h => h.DecisionKey == decisionKey, cancellationToken))
            return Conflict(new { error = "historical_return_payment_conflict" });
        // Payment-intent identity is an additional exact uniqueness boundary for alternate invoice declarations.
        var paymentUsed = await _db.LicenseHistories.FromSqlInterpolated($"""
            SELECT * FROM public."LicenseHistories" WHERE "Action" = {HistoricalReturnAction}
              AND (CASE WHEN "Action" = {HistoricalReturnAction} THEN "Details"::jsonb ELSE NULL END)->'Request'->>'ProductId' = {request.ProductId.ToString("D")}
              AND ((CASE WHEN "Action" = {HistoricalReturnAction} THEN "Details"::jsonb ELSE NULL END)->'Request'->'Payment'->>'PaymentIntentId' = {request.Payment.PaymentIntentId}
                OR (CASE WHEN "Action" = {HistoricalReturnAction} THEN "Details"::jsonb ELSE NULL END)->'Request'->'Historical'->>'LocalLicenseId' = {request.Historical.LocalLicenseId})
            """).AsNoTracking().AnyAsync(cancellationToken);
        if (paymentUsed) return Conflict(new { error = "historical_return_payment_conflict" });
        var now = (HttpContext.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow().UtcDateTime;
        if (request.Payment.ObservedAtUtc > now || request.Payment.ObservedAtUtc < now.AddSeconds(-30)
            || request.Historical.RecordedAtUtc > now || request.Payment.PaidAtUtc > now
            || request.Payment.PeriodStartUtc > now || request.Payment.PeriodEndUtc <= now
            || license.ExpirationDate is null || license.ExpirationDate > now)
            return Conflict(new { error = "historical_return_payment_conflict" });
        if (request.Mode == "ACTIVE_EXPIRED")
        {
            if (!license.IsActive || license.RevocationReason is not null || license.RevokedAt is not null)
                return Conflict(new { error = "historical_return_revocation_conflict" });
        }
        else if (!AdmissibleHistoricalTermination(request, license, now))
            return Conflict(new { error = "historical_return_revocation_unproven" });
        if (!await ApplyPaidEntitlementAsync(license, desiredType, request.DesiredMaxSeats, request.Payment.PeriodEndUtc, cancellationToken))
            return Conflict(new { error = "billing_active_seats_conflict" });
        await _db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeRecoveryCommercialSubjects" ("ProductId", "Id", "CreatedAtUtc")
            VALUES ({request.ProductId}, {request.CommercialSubjectId}, {now})
            ON CONFLICT ("ProductId", "Id") DO NOTHING
            """, cancellationToken);
        var ownership = new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = request.ProductId,
            LicenseId = license.Id, OwnerSubjectId = request.CommercialSubjectId, State = "ACTIVE", CreatedAtUtc = now };
        _db.RuntimeRecoveryCommercialOwnerships.Add(ownership);
        await _db.SaveChangesAsync(cancellationToken);
        await _db.Entry(license).ReloadAsync(cancellationToken);
        var result = new HistoricalReturnReceipt(digest, request, ownership.Id, license.AuthorityVersion,
            BillingDigest(desiredType), license.AllowedVersions);
        _db.LicenseHistories.Add(new LicenseHistory { Id = request.OperationId, LicenseId = license.Id,
            Action = HistoricalReturnAction, DecisionKey = decisionKey, PerformedBy = HistoricalReturnProvenance,
            Details = JsonSerializer.Serialize(result) });
        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Ok(HistoricalReturnAcknowledgement(license, request, result, desiredType, false));
    }

    /// <summary>Rejects unsupported free/trial/student types independently of a descriptive paid declaration.</summary>
    private static bool HistoricalPaidType(BillingTypeSnapshot type) => EligibleBillingType(type) && type.IsRecurring
        && !type.Slug.Contains("TRIAL", StringComparison.OrdinalIgnoreCase)
        && !type.Slug.Contains("STUDENT", StringComparison.OrdinalIgnoreCase)
        && !type.Slug.Contains("FREE", StringComparison.OrdinalIgnoreCase);

    /// <summary>Requires every link in an explicitly attested old termination; arbitrary or security causes stay refused.</summary>
    private static bool AdmissibleHistoricalTermination(HistoricalReturnRequest r, License license, DateTime now)
    {
        var t = r.Terminal;
        return t is not null && !license.IsActive && license.RevokedAt == t.ProviderRevokedAtUtc
            && license.RevocationReason == $"Stripe renewal failed (invoice {t.InvoiceId})"
            && t.DeactivationCorrelationId == HistoricalDeactivationCorrelation(t.InvoiceId)
            && t.InvoiceVoid && t.SubscriptionCanceled && t.SubscriptionId == r.Historical.SubscriptionId
            && t.CustomerId == r.Payment.CustomerId && t.InvoiceId != r.Payment.InvoiceId
            // This attests the legacy Website H24 cutoff, not the canonical billing J7 recovery window.
            && t.SubscriptionId != r.Payment.SubscriptionId && t.GraceStartedAtUtc.AddHours(24) <= t.TerminatedAtUtc
            && t.InvoiceVoidedAtUtc <= t.SubscriptionCanceledAtUtc && t.SubscriptionCanceledAtUtc <= t.TerminatedAtUtc
            && t.ProviderRevokedAtUtc >= t.TerminatedAtUtc && t.ProviderRevokedAtUtc <= r.Payment.PeriodStartUtc
            && t.TerminatedAtUtc <= r.Payment.PeriodStartUtc && t.TerminatedAtUtc <= now;
    }

    /// <summary>Matches the existing Website SHA-256 cleanup namespace byte-for-byte for the exact opaque invoice.</summary>
    private static string HistoricalDeactivationCorrelation(string invoiceId)
    {
        var bytes = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new[] { "stripe-renewal-portal-deactivation-v1", invoiceId },
            new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        bytes[6] = (byte)((bytes[6] & 15) | 80); bytes[8] = (byte)((bytes[8] & 63) | 128);
        var hex = Convert.ToHexStringLower(bytes.AsSpan(0,16));
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

    /// <summary>Returns identities and the complete paid result for exact caller verification and lost-response recovery.</summary>
    private static object HistoricalReturnAcknowledgement(License license, HistoricalReturnRequest request,
        HistoricalReturnReceipt receipt, BillingTypeSnapshot type, bool replay) => new {
            request.OperationId, request.Provenance, request.Mode, RequestDigest = receipt.Digest,
            LicenseId = license.Id, license.ProductId, license.LicenseKey, request.CommercialSubjectId,
            CommercialOwnershipId = receipt.OwnershipId, license.AuthorityVersion, AuthorityIsActive = license.IsActive,
            license.RevocationReason, license.RevokedAt, license.ExpirationDate, license.MaxSeats, license.AllowedVersions,
            Type = type, request.Historical, request.Payment, Idempotent = replay };

    /// <summary>Checks closed nested JSON before typed parsing; nullable fields must still be present explicitly.</summary>
    private static HistoricalReturnRequest? ParseHistoricalReturn(JsonElement payload)
    {
        if (!CompleteHistoricalJson(payload, typeof(HistoricalReturnRequest))) return null;
        try
        {
            var r = payload.Deserialize<HistoricalReturnRequest>(new JsonSerializerOptions {
                PropertyNameCaseInsensitive = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow });
            if (r is null || r.Historical is null || r.Payment is null || !ValidBillingType(r.ExpectedType) || !ValidBillingType(r.DesiredType)) return null;
            r = r with { ExpectedType = r.ExpectedType with { Params = r.ExpectedType.Params.OrderBy(p => p.Key, StringComparer.Ordinal).ToArray() },
                DesiredType = r.DesiredType with { Params = r.DesiredType.Params.OrderBy(p => p.Key, StringComparer.Ordinal).ToArray() } };
            var h = r.Historical; var p = r.Payment; var t = r.Terminal;
            // Reuse the existing PAID shape/time/type validation; this internal sentinel is never an ownership claim.
            var paid = new ConditionalLicenseBillingRequest(r.OperationId, "PAID", r.LicenseId, r.ProductId, r.CommercialSubjectId,
                r.OperationId, r.ExpectedAuthorityVersion, r.ExpectedAuthorityIsActive, r.ExpectedRevocationReason,
                r.ExpectedRevokedAt, r.ExpectedExpirationUtc, r.ExpectedMaxSeats, r.ExpectedType, r.DesiredType, r.DesiredMaxSeats,
                p.OrderId, p.CustomerId, p.SubscriptionId, p.InvoiceId, p.PeriodStartUtc, p.PeriodEndUtc, null, p.PaidAtUtc, null, null);
            return ValidBillingRequest(paid) && r.Provenance == HistoricalReturnProvenance && r.ExpectedOwnershipState == "ABSENT"
                && r.Mode is "ACTIVE_EXPIRED" or "LEGACY_TERMINATED" && ((r.Mode == "ACTIVE_EXPIRED") == (t is null))
                && h.ProviderLicenseId == r.LicenseId && ValidBillingId(h.LocalLicenseId) && ValidBillingId(h.UserId)
                && ValidBillingId(h.LicenseKey) && ValidBillingId(h.SubscriptionId) && h.SubscriptionId != p.SubscriptionId
                && ValidBillingDate(h.LicenseCreatedAtUtc) && h.LicenseCreatedAtUtc < HistoricalReturnCutoff
                && ValidBillingDate(h.RecordedAtUtc) && h.RecordedAtUtc >= h.LicenseCreatedAtUtc && HistoricalHash(h.SnapshotSha256)
                && ValidBillingId(p.PaymentIntentId) && p.AmountPaidCents is > 0 and <= 9007199254740991
                && p.Currency is { Length: 3 } && p.Currency.All(c => c is >= 'a' and <= 'z')
                && p.RefundFree && p.DisputeFree && ValidBillingDate(p.ObservedAtUtc) && p.ObservedAtUtc >= p.PaidAtUtc
                && (t is null || (ValidBillingId(t.InvoiceId) && ValidBillingId(t.SubscriptionId) && ValidBillingId(t.CustomerId)
                    && ValidBillingId(t.LedgerId) && HistoricalHash(t.LedgerSha256) && ValidBillingId(t.DeactivationCorrelationId)
                    && ValidBillingDate(t.GraceStartedAtUtc) && ValidBillingDate(t.TerminatedAtUtc)
                    && ValidBillingDate(t.InvoiceVoidedAtUtc) && ValidBillingDate(t.SubscriptionCanceledAtUtc)
                    && ValidBillingDate(t.ProviderRevokedAtUtc))) ? r : null;
        }
        catch (JsonException) { return null; }
    }

    /// <summary>Bounds exact SHA-256 declarations without case or whitespace repair.</summary>
    private static bool HistoricalHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>Recursively rejects omissions, duplicate aliases and unknown fields in this closed record graph.</summary>
    private static bool CompleteHistoricalJson(JsonElement value, Type type)
    {
        if (type == typeof(BillingTypeSnapshot)) return CompleteBillingJson(value, type);
        if (value.ValueKind != JsonValueKind.Object) return false;
        var fields = type.GetProperties().ToDictionary(p => p.Name, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in value.EnumerateObject())
        {
            if (!fields.TryGetValue(field.Name, out var property) || !seen.Add(field.Name)) return false;
            if (property.PropertyType.IsClass && property.PropertyType != typeof(string))
            {
                if (property.PropertyType == typeof(HistoricalReturnTerminal) && field.Value.ValueKind == JsonValueKind.Null) continue;
                if (!CompleteHistoricalJson(field.Value, property.PropertyType)) return false;
            }
        }
        return seen.Count == fields.Count;
    }
}
