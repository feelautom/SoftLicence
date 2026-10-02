using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>Exact self-service policy value; it cannot authorize an arbitrary administrative cause.</summary>
    private const string SelfRevocationCause = "User self-revoke from dashboard";

    /// <summary>
    /// Binds one operation to the observed license, product, commercial owner and authority snapshot.
    /// Nullable evidence must be explicitly present. Reasons are opaque ordinal strings; timestamps
    /// retain UTC precision and are never supplied as a replacement revocation date.
    /// </summary>
    public sealed record ConditionalLicenseRevocationRequest(
        Guid OperationId, Guid LicenseId, Guid ProductId, Guid CommercialSubjectId,
        Guid ExpectedOwnershipId, Guid ExpectedAuthorityVersion,
        [property: JsonRequired] bool ExpectedAuthorityIsActive,
        [property: JsonRequired] string? ExpectedRevocationReason,
        [property: JsonRequired] DateTime? ExpectedRevokedAt,
        [property: JsonRequired] string DesiredRevocationReason);

    /// <summary>Immutable receipt committed with the license mutation in the existing history table.</summary>
    private sealed record LicenseRevocationReceipt(string RequestDigest, Guid AuthorityVersion,
        string RevocationReason, DateTime RevokedAt);

    /// <summary>
    /// Revokes only the exact observed owner/version under the existing global, license and ownership
    /// locks. Replays require the resulting authority to remain current; prior revocations are verified
    /// without changing their cause, date, version or history. Legacy administrator routes are unchanged.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/revoke-conditional")]
    public async Task<IActionResult> RevokeLicenseConditionally(
        string licenseKey, [FromBody] JsonElement payload, CancellationToken cancellationToken)
    {
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        // Reject duplicate aliases before deserialization: last-property-wins is not authority evidence.
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "OperationId", "LicenseId", "ProductId", "CommercialSubjectId", "ExpectedOwnershipId",
            "ExpectedAuthorityVersion", "ExpectedAuthorityIsActive", "ExpectedRevocationReason",
            "ExpectedRevokedAt", "DesiredRevocationReason"
        };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (payload.ValueKind != JsonValueKind.Object
            || payload.EnumerateObject().Any(p => !allowed.Contains(p.Name) || !seen.Add(p.Name)))
            return BadRequest(new { error = "revocation_evidence_invalid" });
        ConditionalLicenseRevocationRequest? request;
        try { request = payload.Deserialize<ConditionalLicenseRevocationRequest>(new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); }
        catch (JsonException) { return BadRequest(new { error = "revocation_evidence_invalid" }); }
        if (request is null || request.OperationId == Guid.Empty || request.LicenseId == Guid.Empty
            || request.ProductId == Guid.Empty || request.CommercialSubjectId == Guid.Empty
            || request.ExpectedOwnershipId == Guid.Empty || request.ExpectedAuthorityVersion == Guid.Empty
            || request.DesiredRevocationReason != SelfRevocationCause
            || (request.ExpectedRevokedAt.HasValue && request.ExpectedRevokedAt.Value.Kind != DateTimeKind.Utc))
            return BadRequest(new { error = "revocation_evidence_invalid" });
        if (scopedProductId.HasValue && scopedProductId != request.ProductId) return Unauthorized();
        if (!_db.Database.IsNpgsql()) return StatusCode(503, new { error = "revocation_provider_unavailable" });

        var digest = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(
            new { Version = 1, Command = "REVOKED_CONDITIONAL_V1", LicenseKey = licenseKey, Request = request })));
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        // Share the existing operation namespace despite its historical name, preventing cross-command
        // operation-ID races without changing the already-qualified reactivation endpoint.
        var operationLock = $"license-reactivation-v1|{request.OperationId:D}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({operationLock}, {LicenseAuthorityLockSalt}))", cancellationToken);
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);
        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses"
            WHERE "Id" = {request.LicenseId} AND "ProductId" = {request.ProductId} AND "LicenseKey" = {licenseKey}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });
        var ownerships = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {request.ProductId} AND "LicenseId" = {request.LicenseId} AND "State" = 'ACTIVE'
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (ownerships.Count != 1 || ownerships[0].Id != request.ExpectedOwnershipId
            || ownerships[0].OwnerSubjectId != request.CommercialSubjectId)
            return Conflict(new { error = "revocation_ownership_conflict" });

        /// <summary>Describes the locked authority without inferring customer identity or expiry.</summary>
        object Acknowledgement(string outcome, bool idempotent) => new
        {
            request.OperationId, LicenseId = license.Id, license.ProductId, request.CommercialSubjectId,
            CommercialOwnershipId = ownerships[0].Id, license.LicenseKey, license.AuthorityVersion,
            AuthorityIsActive = license.IsActive, license.RevocationReason, license.RevokedAt,
            Outcome = outcome, Idempotent = idempotent
        };
        var history = await _db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == request.OperationId, cancellationToken);
        if (history is not null)
        {
            if (history.LicenseId != license.Id || history.Action != "REVOKED_CONDITIONAL_V1")
                return Conflict(new { error = "revocation_operation_conflict" });
            LicenseRevocationReceipt? receipt;
            try { receipt = JsonSerializer.Deserialize<LicenseRevocationReceipt>(history.Details ?? "null"); }
            catch (JsonException) { return Conflict(new { error = "revocation_receipt_invalid" }); }
            if (receipt is null || !string.Equals(receipt.RequestDigest, digest, StringComparison.Ordinal))
                return Conflict(new { error = "revocation_operation_conflict" });
            if (license.IsActive || license.AuthorityVersion != receipt.AuthorityVersion
                || license.RevocationReason != receipt.RevocationReason || license.RevokedAt != receipt.RevokedAt)
                return Conflict(new { error = "revocation_state_changed" });
            await transaction.CommitAsync(cancellationToken);
            return Ok(Acknowledgement("Revoked", true));
        }
        if (license.AuthorityVersion != request.ExpectedAuthorityVersion || license.IsActive != request.ExpectedAuthorityIsActive
            || !string.Equals(license.RevocationReason, request.ExpectedRevocationReason, StringComparison.Ordinal)
            || license.RevokedAt != request.ExpectedRevokedAt)
            return Conflict(new { error = "revocation_state_changed" });
        if (!license.IsActive)
        {
            if (string.IsNullOrEmpty(license.RevocationReason) || !license.RevokedAt.HasValue)
                return Conflict(new { error = "revocation_state_inconsistent" });
            await transaction.CommitAsync(cancellationToken);
            return Ok(Acknowledgement("AlreadyRevokedVerified", true));
        }
        if (license.RevocationReason is not null || license.RevokedAt.HasValue)
            return Conflict(new { error = "revocation_state_inconsistent" });
        license.IsActive = false;
        license.RevocationReason = SelfRevocationCause;
        license.RevokedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);
        // PostgreSQL timestamp precision is authoritative for both the receipt and response.
        await _db.Entry(license).ReloadAsync(cancellationToken);
        _db.LicenseHistories.Add(new LicenseHistory
        {
            Id = request.OperationId, LicenseId = license.Id, Action = "REVOKED_CONDITIONAL_V1",
            Details = JsonSerializer.Serialize(new LicenseRevocationReceipt(digest, license.AuthorityVersion,
                license.RevocationReason!, license.RevokedAt!.Value)), PerformedBy = "Self-service (conditional API)"
        });
        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        // Existing notification transport is not part of the atomic receipt guarantee. A replay
        // never emits again, including when the response or this best-effort transport was lost.
        _notifier.Notify(Services.NotificationService.Triggers.LicenseRevoked, "🚫 Licence Révoquée",
            $"Clé: {licenseKey}\nRaison: {SelfRevocationCause}");
        return Ok(Acknowledgement("Revoked", false));
    }
}
