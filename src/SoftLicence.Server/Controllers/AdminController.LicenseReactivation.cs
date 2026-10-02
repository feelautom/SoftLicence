using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>
    /// Identifies one exact observed revocation and commercial ownership version. UUIDs are typed
    /// identifiers; the nullable reason is opaque and compared ordinally without trimming or folding.
    /// OperationId must remain unchanged for retries of the same payload, including lost responses.
    /// </summary>
    public sealed record ConditionalLicenseReactivationRequest(
        Guid OperationId,
        Guid LicenseId,
        Guid ProductId,
        Guid CommercialSubjectId,
        Guid ExpectedOwnershipId,
        Guid ExpectedAuthorityVersion,
        [property: System.Text.Json.Serialization.JsonRequired] bool ExpectedAuthorityIsActive,
        [property: System.Text.Json.Serialization.JsonRequired] string? ExpectedRevocationReason);

    /// <summary>
    /// Persists the exact request digest and resulting database version in the existing immutable
    /// license history transaction. A later row or ownership change invalidates successful replay.
    /// </summary>
    private sealed record LicenseReactivationReceipt(string RequestDigest, Guid ResultingAuthorityVersion);

    /// <summary>
    /// Reactivates only the observed revoked state under PostgreSQL row locks. Product credentials
    /// remain scoped, ownership must match by stable IDs, and history commits atomically with the
    /// state change. An explicitly observed active state can be verified without mutation to
    /// reconcile lost responses. Retries never clear a newer revocation or alter expiration, keys, or rights.
    /// Legacy unconditional unrevoke remains a separate administrator operation.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/reactivate-conditional")]
    public async Task<IActionResult> ReactivateLicenseConditionally(
        string licenseKey, [FromBody] ConditionalLicenseReactivationRequest request,
        CancellationToken cancellationToken)
    {
        TagLog("REACTIVATE_CONDITIONAL", licenseKey);
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized || (scopedProductId.HasValue && scopedProductId != request.ProductId))
            return Unauthorized();
        if (request.OperationId == Guid.Empty || request.LicenseId == Guid.Empty
            || request.ProductId == Guid.Empty || request.CommercialSubjectId == Guid.Empty
            || request.ExpectedOwnershipId == Guid.Empty || request.ExpectedAuthorityVersion == Guid.Empty)
            return BadRequest(new { error = "reactivation_identity_required" });
        if (!_db.Database.IsNpgsql())
            return StatusCode(503, new { error = "reactivation_provider_unavailable" });

        // Serialize operation IDs before license rows, matching the ownership-command lock order.
        // The exact route key participates in the digest; no opaque string normalization is allowed.
        var digest = Convert.ToHexStringLower(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(new { Version = 1, LicenseKey = licenseKey, Request = request })));
        await using var transaction = await _db.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await _db.Database.ExecuteSqlRawAsync(
            "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';", cancellationToken);
        var operationLock = $"license-reactivation-v1|{request.OperationId:D}";
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({operationLock}, {LicenseAuthorityLockSalt}))",
            cancellationToken);
        // Runtime-enrollment BEFORE STATEMENT triggers acquire the global authority lock before
        // UPDATE row locks. Match that order before locking license/ownership rows so a concurrent
        // SQL writer cannot hold the global lock while this transaction holds the license row.
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)", cancellationToken);

        var license = await _db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses"
            WHERE "Id" = {request.LicenseId} AND "ProductId" = {request.ProductId}
              AND "LicenseKey" = {licenseKey}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (license is null) return NotFound(new { error = "license_not_found" });

        // Ownership commands lock the same license before its active ownership rows. Holding both
        // prevents a transfer between the identity check and the revocation state mutation.
        var ownerships = await _db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {request.ProductId} AND "LicenseId" = {request.LicenseId}
              AND "State" = 'ACTIVE'
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (ownerships.Count != 1 || ownerships[0].Id != request.ExpectedOwnershipId
            || ownerships[0].OwnerSubjectId != request.CommercialSubjectId)
            return Conflict(new { error = "reactivation_ownership_conflict" });

        var history = await _db.LicenseHistories.AsNoTracking()
            .SingleOrDefaultAsync(h => h.Id == request.OperationId, cancellationToken);
        if (history is not null)
        {
            if (history.LicenseId != license.Id || history.Action != "REACTIVATED_CONDITIONAL_V1")
                return Conflict(new { error = "reactivation_operation_conflict" });
            LicenseReactivationReceipt? receipt;
            try { receipt = JsonSerializer.Deserialize<LicenseReactivationReceipt>(history.Details ?? "null"); }
            catch (JsonException) { return Conflict(new { error = "reactivation_receipt_invalid" }); }
            if (receipt is null || !string.Equals(receipt.RequestDigest, digest, StringComparison.Ordinal))
                return Conflict(new { error = "reactivation_operation_conflict" });
            if (!license.IsActive || license.RevokedAt.HasValue || license.RevocationReason is not null
                || license.AuthorityVersion != receipt.ResultingAuthorityVersion)
                return Conflict(new { error = "reactivation_state_changed" });
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { license.LicenseKey, license.AuthorityVersion, AuthorityIsActive = true, Idempotent = true });
        }

        if (license.IsActive != request.ExpectedAuthorityIsActive || license.AuthorityVersion != request.ExpectedAuthorityVersion
            || !string.Equals(license.RevocationReason, request.ExpectedRevocationReason, StringComparison.Ordinal))
            return Conflict(new { error = "reactivation_state_changed" });

        // Verify ownership under the same locks even when no reactivation is needed. Do not
        // normalize inconsistent legacy states or create a new history event for a pure check.
        if (license.IsActive)
        {
            if (license.RevokedAt.HasValue || license.RevocationReason is not null)
                return Conflict(new { error = "reactivation_state_inconsistent" });
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { license.LicenseKey, license.AuthorityVersion, AuthorityIsActive = true, Idempotent = true });
        }

        license.IsActive = true;
        license.RevocationReason = null;
        license.RevokedAt = null;
        await _db.SaveChangesAsync(cancellationToken);
        _db.LicenseHistories.Add(new LicenseHistory
        {
            Id = request.OperationId,
            LicenseId = license.Id,
            Action = "REACTIVATED_CONDITIONAL_V1",
            Details = JsonSerializer.Serialize(new LicenseReactivationReceipt(digest, license.AuthorityVersion)),
            PerformedBy = "Admin (conditional API)"
        });
        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Ok(new { license.LicenseKey, license.AuthorityVersion, AuthorityIsActive = true, Idempotent = false });
    }
}
