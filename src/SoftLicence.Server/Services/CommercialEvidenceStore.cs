using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Shared purchase identity authority. Callers hold the global PostgreSQL authority lock and transaction.</summary>
internal static class CommercialEvidenceStore
{
    /// <summary>Hashes canonical typed terms without depending on raw HTTP JSON member order.</summary>
    internal static string Digest<T>(T value) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));

    /// <summary>Separates immutable order facts from the operation/CAS envelope that may legitimately change.</summary>
    internal static string AttributionDigest(CommercialEvidence evidence, string entitlementDigest) => Digest(new
    {
        evidence.Version, evidence.OrderId, evidence.CommercialSubjectId, evidence.Nature,
        evidence.PaidAmountMinor, evidence.Currency, EntitlementDigest = entitlementDigest
    });

    /// <summary>Returns an identity conflict before any rights change; a matching order is a historical attribution.</summary>
    internal static async Task<(bool Conflict, CommercialOrderEvidence? Order)> CheckAsync(LicenseDbContext db,
        CommercialEvidence evidence, Guid productId, Guid? licenseId, string producer, string receiptKey,
        string attributionDigest, string requestDigest, CancellationToken token = default)
    {
        var operation = await db.Set<CommercialEvidenceOperation>().AsNoTracking().SingleOrDefaultAsync(x => x.Id == evidence.OperationId, token);
        var order = await db.Set<CommercialOrderEvidence>().AsNoTracking()
            .SingleOrDefaultAsync(x => x.ProductId == productId && x.OrderId == evidence.OrderId, token);
        if (operation is not null && (order is null || operation.OrderEvidenceId != order.Id || operation.RequestDigest != requestDigest))
            return (true, order);
        if (order is not null && (order.Producer != producer || order.ReceiptKey != receiptKey
            || order.AttributionDigest != attributionDigest || (licenseId.HasValue && order.LicenseId != licenseId)))
            return (true, order);
        return (false, order);
    }

    /// <summary>Requires one current owner only for a new attribution; historical replay does not call this predicate.</summary>
    internal static async Task<bool> OwnsAsync(LicenseDbContext db, License license, Guid subject, CancellationToken token = default)
    {
        var owners = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .Where(x => x.ProductId == license.ProductId && x.LicenseId == license.Id && x.State == "ACTIVE")
            .Select(x => x.OwnerSubjectId).ToListAsync(token);
        return owners.Count == 1 && owners[0] == subject;
    }

    /// <summary>Stages proof with the producer receipt in the caller transaction. Existing orders only gain an operation alias.</summary>
    internal static async Task RecordAsync(LicenseDbContext db, License license, CommercialEvidence evidence,
        string producer, string receiptKey, string attributionDigest, string requestDigest, bool newlyCreated,
        CancellationToken token = default)
    {
        var order = await db.Set<CommercialOrderEvidence>().SingleOrDefaultAsync(x =>
            x.ProductId == license.ProductId && x.OrderId == evidence.OrderId, token);
        if (order is null)
        {
            order = new CommercialOrderEvidence { ProductId = license.ProductId, LicenseId = license.Id,
                OrderId = evidence.OrderId, CommercialSubjectId = evidence.CommercialSubjectId,
                Nature = evidence.Nature, PaidAmountMinor = evidence.PaidAmountMinor, Currency = evidence.Currency,
                Producer = producer, ReceiptKey = receiptKey, AttributionDigest = attributionDigest };
            db.Add(order);
            license.CommercialNature = EffectiveNature(license.CommercialNature, evidence.Nature, newlyCreated);
        }
        if (!await db.Set<CommercialEvidenceOperation>().AnyAsync(x => x.Id == evidence.OperationId, token))
            db.Add(new CommercialEvidenceOperation { Id = evidence.OperationId, OrderEvidenceId = order.Id, RequestDigest = requestDigest });
    }

    /// <summary>Preserves paid and historical authority; free gifts cannot erase a first-order origin or paid entitlement.</summary>
    internal static string EffectiveNature(string current, string incoming, bool newlyCreated) =>
        newlyCreated ? incoming : incoming == "PAID" ? "PAID" : current is "UNKNOWN" or "PAID" ? current
            : incoming == "PAID_TRIAL" ? "PAID_TRIAL" : current;

    /// <summary>Stages paid-equivalent UNKNOWN for newly acquired V1 rights, never for replay or non-acquiring commands.</summary>
    internal static void RecordUnqualifiedAcquisition(License license)
    {
        // Keep explicit paid authority; no commercial proof or amount is inferred from a legacy request.
        if (license.CommercialNature is "FIRST_ORDER_FREE" or "FREE" or "PAID_TRIAL")
            license.CommercialNature = "UNKNOWN";
    }
}
