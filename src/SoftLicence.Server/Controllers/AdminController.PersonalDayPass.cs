using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Product-scoped paid-pass payment commands, isolated from legacy renewal and activation issuance.</summary>
public partial class AdminController
{
    /// <summary>
    /// Authenticated provider evidence, never a browser payment assertion. Times are UTC milliseconds;
    /// provider tuple strings are exact opaque identities. Initial issuance has no Expected values;
    /// extension supplies the observed license, ownership and authority version. A null AllowedVersions
    /// delegates application policy to the existing licence or the type default for initial issuance.
    /// Non-null legacy assertions must match that authority for new money; historical replay stays exact.
    /// Seats are explicit paid terms. Customer identity is frozen by the
    /// trusted Website intent and retained for legacy activation/reset; it never establishes ownership.
    /// OperationId survives identical retries.
    /// </summary>
    public sealed record PersonalDayPassRequest(Guid OperationId, Guid ProductId, Guid CommercialSubjectId,
        Guid LicenseTypeId, string Provider, string ProviderAccount, string Environment, string PaymentId,
        DateTime PaidAtUtc, int AmountMinor, string Currency, int MaxSeats, string? AllowedVersions,
        string CustomerEmail, string CustomerName, bool PrioritySupport = false,
        Guid? ExpectedLicenseId = null, Guid? ExpectedOwnershipId = null, Guid? ExpectedAuthorityVersion = null,
        string Offer = "day_pass", int DurationSeconds = 86_400);

    /// <summary>
    /// Immutable historical receipt and separately locked current authority. CurrentPendingFirstActivation
    /// proves a never-activated, receipt-backed licence with null expiration and null ledger anchor;
    /// CurrentUsable is false until activation. CurrentLedgerAnchorUtc is the millisecond UTC first activation
    /// or the paid predecessor horizon for an existing licence. It never rewrites historical receipt periods.
    /// </summary>
    public sealed record PersonalDayPassResponse(Guid PassId, Guid LicenseId, string LicenseKey,
        Guid PaymentEvidenceId, Guid ReceiptOperationId, DateTime PeriodStartsAtUtc, DateTime PeriodExpiresAtUtc,
        DateTime HistoricalPaidThroughUtc, Guid HistoricalAuthorityVersion,
        DateTime? CurrentExpirationUtc, Guid CurrentAuthorityVersion, Guid? CurrentOwnershipId,
        Guid CurrentLicenseTypeId, int CurrentMaxSeats, bool CurrentPrioritySupport, bool PeriodPrioritySupport,
        bool CurrentPendingFirstActivation, DateTime? CurrentLedgerAnchorUtc,
        bool CurrentUsable, bool Idempotent);

    /// <summary>
    /// Applies one verified paid period once under PostgreSQL locks. A daily period must match the fixed
    /// EUR10-per-seat contract; a monthly or annual period carries its already verified duration and amount.
    /// Issuance, ownership and provenance commit atomically; extensions reuse the same license key and queue
    /// expiry and seat changes behind the paid horizon. CAS conflicts never revive revocation.
    /// Chronological recomputation retains late money without moving periods to processing time.
    /// A replay exposes historical success separately from current authority, even after revocation/ABA.
    /// No provider calls, email or billing occurs inside or outside this transaction.
    /// </summary>
    [HttpPost("personal-day-passes/payments")]
    public async Task<IActionResult> ApplyPersonalDayPassPayment([FromBody] PersonalDayPassRequest request,
        CancellationToken cancellationToken)
    {
        var (authorized, scopedProduct) = await GetAuthContextAsync();
        if (!authorized || (scopedProduct.HasValue && scopedProduct != request.ProductId)) return Unauthorized();
        if (!ValidPersonalDayPassRequest(request)) return BadRequest(new { error = "personal_pass_invalid_request" });
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "personal_pass_postgres_required" });

        var identity = PersonalDayPassPolicy.Identity(request.Provider, request.ProviderAccount, request.Environment, request.PaymentId);
        var digest = PersonalDayPassDigest(request);
        var evidenceDigest = PersonalDayPassDigest(new { Version = 1, request.ProductId, request.CommercialSubjectId,
            request.LicenseTypeId, request.Provider, request.ProviderAccount, request.Environment, request.PaymentId,
            request.PaidAtUtc, request.AmountMinor, request.Currency, request.MaxSeats, request.AllowedVersions,
            request.CustomerEmail, request.CustomerName, request.PrioritySupport, request.Offer, request.DurationSeconds });
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        await LockPersonalDayPassAsync($"personal-pass-operation-v1|{request.OperationId:D}", cancellationToken);
        // Payment then stable pass identity precede global/license/ownership locks. No network is permitted here.
        await LockPersonalDayPassAsync("personal-pass-payment-v1|" + identity, cancellationToken);
        await LockPersonalDayPassAsync($"personal-pass-v1|{request.ProductId:D}|{request.CommercialSubjectId:D}", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);

        var oldOperation = await _db.PersonalDayPassOperations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == request.OperationId, cancellationToken);
        if (oldOperation is not null && !string.Equals(oldOperation.RequestDigest, digest, StringComparison.Ordinal))
            return Conflict(new { error = "personal_pass_operation_conflict" });
        var payment = await _db.PersonalDayPassPayments.AsNoTracking().SingleOrDefaultAsync(p =>
            p.Provider == request.Provider && p.ProviderAccount == request.ProviderAccount
            && p.Environment == request.Environment && p.PaymentId == request.PaymentId, cancellationToken);
        if (payment is not null && !string.Equals(payment.EvidenceDigest, evidenceDigest, StringComparison.Ordinal))
            return Conflict(new { error = "personal_pass_payment_conflict" });
        var pass = await _db.PersonalDayPasses.SingleOrDefaultAsync(p =>
            p.ProductId == request.ProductId && p.CommercialSubjectId == request.CommercialSubjectId, cancellationToken);
        if (payment is not null && (pass is null || payment.PassId != pass.Id))
            return Conflict(new { error = "personal_pass_attribution_conflict" });

        License? license = null;
        List<RuntimeRecoveryCommercialOwnership> owners = [];
        if (pass is not null)
        {
            license = await _db.Licenses.FromSqlInterpolated($"""
                SELECT * FROM public."Licenses" WHERE "Id" = {pass.LicenseId} AND "ProductId" = {pass.ProductId} FOR UPDATE
                """).SingleAsync(cancellationToken);
            owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
                WHERE "ProductId" = {pass.ProductId} AND "LicenseId" = {pass.LicenseId} AND "State" = 'ACTIVE'
                ORDER BY "Id" FOR UPDATE
                """).AsNoTracking().ToListAsync(cancellationToken);
        }
        else
        {
            // A commercial subject keeps its existing paid key when it first adds a day pass.
            owners = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
                WHERE "ProductId" = {request.ProductId} AND "OwnerSubjectId" = {request.CommercialSubjectId} AND "State" = 'ACTIVE'
                ORDER BY "LicenseId", "Id" FOR UPDATE
                """).AsNoTracking().ToListAsync(cancellationToken);
            if (owners.Count > 1) return Conflict(new { error = "personal_pass_existing_authority_ambiguous" });
            if (owners.Count == 1)
            {
                license = await _db.Licenses.FromSqlInterpolated($"""
                    SELECT * FROM public."Licenses" WHERE "Id" = {owners[0].LicenseId} AND "ProductId" = {request.ProductId} FOR UPDATE
                    """).SingleAsync(cancellationToken);
            }
        }

        // Existing money is not a new grant. Preserve its historical result even if current guards changed.
        if (payment is not null)
        {
            var receipt = oldOperation ?? await _db.PersonalDayPassOperations.AsNoTracking()
                .Where(o => o.PaymentId == payment.Id).OrderBy(o => o.Id).FirstAsync(cancellationToken);
            if (oldOperation is null)
            {
                receipt = new PersonalDayPassOperation { Id = request.OperationId, PaymentId = payment.Id,
                    RequestDigest = digest, ResultAuthorityVersion = receipt.ResultAuthorityVersion,
                    PeriodStartsAtUtc = receipt.PeriodStartsAtUtc, PeriodExpiresAtUtc = receipt.PeriodExpiresAtUtc,
                    PeriodPrioritySupport = receipt.PeriodPrioritySupport, PaidThroughUtc = receipt.PaidThroughUtc };
                _db.Add(receipt);
                await _db.SaveChangesAsync(cancellationToken);
            }
            var replayPending = await PersonalDayPassActivationService.IsPendingAsync(_db, pass!, license!, cancellationToken);
            var replayResult = PersonalDayPassReadback(pass!, license!, owners, receipt, replayPending, true);
            await transaction.CommitAsync(cancellationToken);
            return Ok(replayResult);
        }
        if (oldOperation is not null) return Conflict(new { error = "personal_pass_receipt_inconsistent" });

        var type = await _db.LicenseTypes.Include(t => t.CustomParams).SingleOrDefaultAsync(t =>
            t.Id == request.LicenseTypeId && t.ProductId == request.ProductId, cancellationToken);
        if (type is null)
            return Conflict(new { error = "personal_pass_type_contract_mismatch" });
        // Policy belongs to SoftLicence, not the Website sale or the installed TIA Portal platform.
        // Lock the type before reading its default so an administrative change cannot race issuance.
        if (license is null)
        {
            await _db.Database.ExecuteSqlInterpolatedAsync($"""
                SELECT 1 FROM "LicenseTypes" WHERE "Id" = {type.Id} FOR UPDATE
                """, cancellationToken);
            await _db.Entry(type).ReloadAsync(cancellationToken);
        }
        // TKT-001217: a first paid purchase creates its own commercial authority. Requiring an existing
        // active licence refused every paying customer without one (revoked Freemium, closed trial...).
        // A free, anonymous or non-recurring type still never mints paid time for a brand-new licence.
        if (request.Offer == "day_pass" && !PersonalDayPassPolicy.IsValidPassType(type)
            || request.Offer != "day_pass" && license is null
                && (type.IsFree || type.AllowAnonymous || !type.IsRecurring))
            return Conflict(new { error = "personal_pass_type_contract_mismatch" });
        var allowedVersions = license is null ? type.DefaultAllowedVersions : license.AllowedVersions;
        if (request.AllowedVersions is not null
            && !string.Equals(request.AllowedVersions, allowedVersions, StringComparison.Ordinal))
            return Conflict(new { error = "personal_pass_version_authority_conflict" });
        var pendingFirstActivation = pass is not null && license is not null
            && await PersonalDayPassActivationService.IsPendingAsync(_db, pass, license, cancellationToken);
        if (pass is not null && license is not null && (license.Id != request.ExpectedLicenseId
            || license.LicenseTypeId != request.LicenseTypeId
            || license.AuthorityVersion != request.ExpectedAuthorityVersion || owners.Count != 1
            || owners[0].Id != request.ExpectedOwnershipId || owners[0].OwnerSubjectId != request.CommercialSubjectId
            || !license.IsActive || license.RevokedAt.HasValue || license.RevocationReason is not null
            || !string.Equals(license.CustomerEmail, request.CustomerEmail, StringComparison.Ordinal)
            || !string.Equals(license.CustomerName, request.CustomerName, StringComparison.Ordinal)
            || !pendingFirstActivation && license.ExpirationDate != pass!.PaidThroughUtc))
            return Conflict(new { error = "personal_pass_authority_conflict" });
        if (pass is null && license is not null && (request.ExpectedLicenseId.HasValue
            || request.ExpectedOwnershipId.HasValue || request.ExpectedAuthorityVersion.HasValue
            || owners.Count != 1 || owners[0].OwnerSubjectId != request.CommercialSubjectId
            || license.LicenseTypeId != request.LicenseTypeId
            || !license.IsActive || license.RevokedAt.HasValue || license.RevocationReason is not null
            || !string.Equals(license.CustomerEmail, request.CustomerEmail, StringComparison.Ordinal)
            || !string.Equals(license.CustomerName, request.CustomerName, StringComparison.Ordinal)))
            return Conflict(new { error = "personal_pass_existing_authority_conflict" });
        if (license is null && (request.ExpectedLicenseId.HasValue || request.ExpectedOwnershipId.HasValue
            || request.ExpectedAuthorityVersion.HasValue))
            return Conflict(new { error = "personal_pass_initial_snapshot_conflict" });

        var priorPayments = pass is null ? new List<PersonalDayPassPayment>() : await _db.PersonalDayPassPayments.AsNoTracking()
            .Where(p => p.PassId == pass.Id).ToListAsync(cancellationToken);
        // The stable tuple order is calculated in .NET ordinal semantics, not database locale ordering.
        var inputs = priorPayments.Select(p => new PersonalDayPassPolicy.Payment(
            PersonalDayPassPolicy.Identity(p.Provider, p.ProviderAccount, p.Environment, p.PaymentId), p.PaidAtUtc, p.MaxSeats, p.DurationSeconds, p.PrioritySupport)).ToList();
        var currentInput = new PersonalDayPassPolicy.Payment(identity, request.PaidAtUtc, request.MaxSeats, request.DurationSeconds, request.PrioritySupport);
        IReadOnlyList<PersonalDayPassPolicy.Period> periods;
        // Once the pass ledger exists, only its frozen predecessor horizon may seed the projection.
        // Falling back to the license's ever-growing expiry would count previously purchased pass days twice.
        var initialPaidThrough = pass is not null
            ? pass.InitialPaidThroughUtc
            : license?.ExpirationDate is DateTime expiry && expiry > request.PaidAtUtc ? expiry : null;
        try
        {
            var priorPeriods = PersonalDayPassPolicy.Allocate(inputs, initialPaidThrough);
            var projectedPriorHorizon = priorPeriods.LastOrDefault()?.ExpiresAtUtc ?? initialPaidThrough;
            // The legacy recurring endpoint may have appended paid time without changing seats. Preserve that
            // trailing horizon while keeping every earlier period boundary immutable for seat materialization.
            if (pass is not null && projectedPriorHorizon.HasValue && pass.PaidThroughUtc > projectedPriorHorizon.Value)
            {
                if (priorPayments.Count != 0 && request.PaidAtUtc < priorPayments.Max(payment => payment.PaidAtUtc))
                    return Conflict(new { error = "personal_pass_chronology_invalid" });
                var start = pass.PaidThroughUtc > request.PaidAtUtc ? pass.PaidThroughUtc : request.PaidAtUtc;
                if (start > DateTime.MaxValue.AddSeconds(-request.DurationSeconds))
                    return Conflict(new { error = "personal_pass_chronology_invalid" });
                periods = [.. priorPeriods, new PersonalDayPassPolicy.Period(identity, start, start.AddSeconds(request.DurationSeconds), request.MaxSeats, request.PrioritySupport)];
            }
            else
            {
                inputs.Add(currentInput);
                periods = PersonalDayPassPolicy.Allocate(inputs, initialPaidThrough);
            }
        }
        catch (ArgumentException) { return Conflict(new { error = "personal_pass_chronology_invalid" }); }
        var period = periods.Single(p => p.Identity == identity);
        var horizon = periods[^1].ExpiresAtUtc;
        var authorityNowUtc = DateTime.UtcNow;
        var currentPeriod = periods.LastOrDefault(candidate =>
            candidate.StartsAtUtc <= authorityNowUtc && authorityNowUtc < candidate.ExpiresAtUtc);

        if (license is null)
        {
            // Existing administrative suspension is preserved and prevents new key issuance.
            if (type.DisableNewActivations) return Conflict(new { error = "personal_pass_new_activations_disabled" });
            await _db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO "RuntimeRecoveryCommercialSubjects" ("ProductId", "Id", "CreatedAtUtc")
                VALUES ({request.ProductId}, {request.CommercialSubjectId}, {DateTime.UtcNow})
                ON CONFLICT ("ProductId", "Id") DO NOTHING
                """, cancellationToken);
            var provenance = new LicenseProvisioningRequest { ProductId = request.ProductId,
                CommercialSubjectId = request.CommercialSubjectId, AuthorityProvenance = LicenseProvisioningRequest.ProviderAdminApiProvenance,
                Reference = $"personal-pass-v1:{request.ProductId:D}:{request.CommercialSubjectId:D}", RequestHash = evidenceDigest };
            license = new License { ProductId = request.ProductId, LicenseTypeId = type.Id,
                LicenseKey = Guid.NewGuid().ToString("D").ToUpperInvariant(), ExpirationDate = null,
                ValidityDays = null, MaxSeats = request.MaxSeats, AllowedVersions = allowedVersions,
                CustomerEmail = request.CustomerEmail, CustomerName = request.CustomerName,
                ProvisioningRequest = provenance, ProvisioningSequence = 0, Reference = provenance.Reference };
            var owner = new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = request.ProductId,
                LicenseId = license.Id, OwnerSubjectId = request.CommercialSubjectId, State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow };
            owners.Add(owner);
            pass = new PersonalDayPass { ProductId = request.ProductId, CommercialSubjectId = request.CommercialSubjectId,
                LicenseId = license.Id, PaidThroughUtc = horizon, InitialPaidThroughUtc = null,
                CurrentPrioritySupport = false };
            _db.AddRange(provenance, license, owner);
            // Persist principal rows first inside the same transaction; FK ordering is explicit for untracked navigations.
            await _db.SaveChangesAsync(cancellationToken);
            _db.Add(pass);
        }
        else
        {
            // Paid time queues behind the existing horizon; seat rights change only if this period is already current.
            if (pendingFirstActivation)
            {
                // A deferred licence has no expiry row update to advance the authority trigger. Rotate the
                // CAS explicitly so two distinct verified payments cannot both accept one stale Website snapshot.
                await _db.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE public."Licenses" SET "AuthorityVersion" = "AuthorityVersion"
                    WHERE "Id" = {license.Id}
                    """, cancellationToken);
                await _db.Entry(license).ReloadAsync(cancellationToken);
            }
            else
                license.ExpirationDate = horizon;
            if (!pendingFirstActivation && currentPeriod is not null)
            {
                license.MaxSeats = currentPeriod.MaxSeats;
                if (pass is not null) pass.CurrentPrioritySupport = currentPeriod.PrioritySupport;
            }
            else if (!pendingFirstActivation && pass is not null) pass.CurrentPrioritySupport = false;
            if (pass is null)
            {
                pass = new PersonalDayPass { ProductId = request.ProductId, CommercialSubjectId = request.CommercialSubjectId,
                    LicenseId = license.Id, PaidThroughUtc = horizon, InitialPaidThroughUtc = initialPaidThrough,
                    CurrentPrioritySupport = currentPeriod?.PrioritySupport ?? false };
                _db.Add(pass);
            }
            else pass.PaidThroughUtc = horizon;
        }
        await _db.SaveChangesAsync(cancellationToken);
        payment = new PersonalDayPassPayment { PassId = pass!.Id, Provider = request.Provider,
            ProviderAccount = request.ProviderAccount, Environment = request.Environment, PaymentId = request.PaymentId,
            PaidAtUtc = request.PaidAtUtc, AmountMinor = request.AmountMinor, MaxSeats = request.MaxSeats,
            PrioritySupport = request.PrioritySupport, DurationSeconds = request.DurationSeconds, Offer = request.Offer,
            Currency = request.Currency, EvidenceDigest = evidenceDigest };
        _db.Add(payment);
        await _db.SaveChangesAsync(cancellationToken);
        var operation = new PersonalDayPassOperation { Id = request.OperationId, PaymentId = payment.Id, RequestDigest = digest,
            ResultAuthorityVersion = license.AuthorityVersion, PeriodStartsAtUtc = period.StartsAtUtc,
            PeriodExpiresAtUtc = period.ExpiresAtUtc, PeriodPrioritySupport = period.PrioritySupport, PaidThroughUtc = horizon };
        _db.Add(operation);
        _db.LicenseHistories.Add(new LicenseHistory { LicenseId = license.Id, Action = "PERSONAL_PASS_PAID_V1",
            Details = JsonSerializer.Serialize(new { OperationId = operation.Id, PaymentEvidenceId = payment.Id, PaidThroughUtc = horizon }), PerformedBy = "Admin (paid-pass API)" });
        await _db.SaveChangesAsync(cancellationToken);
        var currentPending = await PersonalDayPassActivationService.IsPendingAsync(_db, pass, license, cancellationToken);
        var result = PersonalDayPassReadback(pass, license, owners, operation, currentPending, false);
        await transaction.CommitAsync(cancellationToken);
        return Ok(result);
    }

    /// <summary>Rejects missing, changed-price, future or imprecise evidence before any transaction or grant.</summary>
    private static bool ValidPersonalDayPassRequest(PersonalDayPassRequest r) => r.OperationId != Guid.Empty
        && r.ProductId != Guid.Empty && r.CommercialSubjectId != Guid.Empty && r.LicenseTypeId != Guid.Empty
        && PersonalDayPassPolicy.IsOpaqueIdentity(r.Provider) && PersonalDayPassPolicy.IsOpaqueIdentity(r.ProviderAccount)
        && PersonalDayPassPolicy.IsOpaqueIdentity(r.Environment) && PersonalDayPassPolicy.IsOpaqueIdentity(r.PaymentId)
        && PersonalDayPassPolicy.IsPaidInstant(r.PaidAtUtc) && r.PaidAtUtc <= DateTime.UtcNow
        && r.MaxSeats is >= 1 and <= 10 && r.Currency == "eur"
        && ((r.Offer == "day_pass" && r.DurationSeconds == 86_400
                && r.AmountMinor == (r.PrioritySupport ? 1140 : 1000) * r.MaxSeats)
            || (r.Offer == "subscription" && !r.PrioritySupport
                && r.DurationSeconds is >= 86_400 and <= 31_622_400 && r.AmountMinor > 0))
        && (r.AllowedVersions is null || PersonalDayPassPolicy.IsOpaqueIdentity(r.AllowedVersions))
        && PersonalDayPassPolicy.IsOpaqueIdentity(r.CustomerName)
        && r.CustomerEmail is { Length: > 0 and <= 254 }
        && System.Net.Mail.MailAddress.TryCreate(r.CustomerEmail, out var address)
        && string.Equals(address.Address, r.CustomerEmail, StringComparison.Ordinal);

    /// <summary>Creates a deterministic lowercase JSON SHA-256; typed UUIDs/dates and exact strings define equality.</summary>
    private static string PersonalDayPassDigest<T>(T value) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));

    /// <summary>Acquires a transaction-scoped exact-identity advisory lock; callers preserve the documented lock order.</summary>
    private Task LockPersonalDayPassAsync(string identity, CancellationToken cancellationToken) =>
        _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({identity}, {LicenseAuthorityLockSalt}))", cancellationToken);

    /// <summary>Projects locked authority; pending is supplied only by the shared receipt, type, ownership and activation-history proof.</summary>
    private static PersonalDayPassResponse PersonalDayPassReadback(PersonalDayPass pass, License license,
        List<RuntimeRecoveryCommercialOwnership> owners, PersonalDayPassOperation receipt,
        bool pendingFirstActivation, bool idempotent)
    {
        return new(
            pass.Id, license.Id, license.LicenseKey, receipt.PaymentId, receipt.Id,
            receipt.PeriodStartsAtUtc, receipt.PeriodExpiresAtUtc, receipt.PaidThroughUtc, receipt.ResultAuthorityVersion,
            license.ExpirationDate, license.AuthorityVersion, owners.Count == 1 ? owners[0].Id : null,
            license.LicenseTypeId, license.MaxSeats, pass.CurrentPrioritySupport, receipt.PeriodPrioritySupport,
            pendingFirstActivation, pass.InitialPaidThroughUtc,
            !pendingFirstActivation && owners.Count == 1 && owners[0].OwnerSubjectId == pass.CommercialSubjectId
                && license.IsActive && !license.RevokedAt.HasValue && license.RevocationReason is null
                && license.ExpirationDate == pass.PaidThroughUtc && license.ExpirationDate > DateTime.UtcNow, idempotent);
    }
}
