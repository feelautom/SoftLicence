using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Reuses only versioned decisions within an authenticated machine authority tuple.</summary>
public static class RuntimeMachineEvidenceAuthority
{
    /// <summary>
    /// Resolves the key from current enrollment or one unambiguous authenticated preflight key. Finalize
    /// has no submitted key field; this binds provider evidence, not proof of possession by its caller.
    /// The caller holds Runtime authority barriers and license locks; this method takes the machine proof lock.
    /// Missing or ambiguous proof returns unknown. Database faults and cancellation propagate, never becoming a policy refusal.
    /// </summary>
    public static async Task<VirtualMachinePolicy.Assessment> ForFinalizeAsync(LicenseDbContext db,
        string clientId, Guid productId, Guid licenseId, string grantDigest, string installationId,
        string installationHash, string hardwareHash, CancellationToken cancellationToken)
    {
        await LockAsync(db, clientId, productId, licenseId, hardwareHash, cancellationToken);
        var enrollments = await db.RuntimeEnrollments.AsNoTracking().Where(row => row.ProductId == productId
            && row.InstallationId == installationId).Select(row => new { row.State, row.KeyThumbprint }).ToListAsync(cancellationToken);
        string? key;
        if (enrollments.Count > 0)
        {
            var active = enrollments.Where(row => row.State == "ACTIVE").ToArray();
            if (active.Length != 1) return new("unknown", "enrollment_key_ambiguous", null);
            key = active[0].KeyThumbprint;
        }
        else
        {
            var keys = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().Where(row =>
                row.ClientId == clientId && row.ProductId == productId && row.LicenseId == licenseId
                && row.GrantRefDigestSha256 == grantDigest && row.InstallationIdHash == installationHash
                && row.HardwareIdHash == hardwareHash && row.MachineEvidenceSourceDecisionId != null)
                .Select(row => row.KeyThumbprint).Distinct().Take(2).ToListAsync(cancellationToken);
            if (keys.Count != 1) return new("unknown", "authenticated_key_ambiguous", null);
            key = keys[0];
        }
        if (key is not { Length: 43 }) return new("unknown", "authenticated_key_missing", null);
        return await FindAsync(db, clientId, productId, licenseId, grantDigest, hardwareHash,
            installationHash, key, false, cancellationToken);
    }

    /// <summary>Copies a bounded assessment onto a new decision in its existing transaction. Only validated complete request evidence may set newSource; reuse preserves the original source ID.</summary>
    public static void Store(RuntimeDistributionHardwareDecision row, VirtualMachinePolicy.Assessment assessment, bool newSource)
    {
        row.MachineClassifierVersion = VirtualMachinePolicy.Version;
        row.MachineClassification = assessment.Kind;
        row.MachineClassificationReason = assessment.Reason;
        row.MachineEvidenceDigestSha256 = assessment.EvidenceDigest;
        row.MachineEvidenceSourceDecisionId = newSource ? row.Id : assessment.SourceDecisionId;
    }

    /// <summary>Historical or unsupported versions are not inferred to describe a physical machine.</summary>
    public static VirtualMachinePolicy.Assessment Read(RuntimeDistributionHardwareDecision row) =>
        row.MachineClassifierVersion == VirtualMachinePolicy.Version
            && row.MachineClassification is "physical" or "virtual" or "unknown"
            && row.MachineEvidenceDigestSha256 is { Length: 64 }
            ? new(row.MachineClassification, row.MachineClassificationReason ?? "stored_classification", row.MachineEvidenceDigestSha256, row.MachineEvidenceSourceDecisionId)
            : new("unknown", "authenticated_evidence_missing", null);

    /// <summary>
    /// Finds unambiguous classification in the exact client/product/licence/hardware scope. Full requests
    /// additionally bind installation/key; digest-only requests require the current grant. Only a caller
    /// that has validated the locked current enrollment may omit grant matching when refreshing its proof.
    /// Only full authenticated source requests can supersede previous evidence in the same key scope.
    /// Replays and digest revalidations never advance the source clock. Concurrent equal-time sources fail closed.
    /// Callers granting authority must hold the proof lock and current commercial/enrollment barriers. The query
    /// changes no rows; unavailable evidence returns unknown, whereas database faults and cancellation propagate.
    /// </summary>
    public static async Task<VirtualMachinePolicy.Assessment> FindAsync(
        LicenseDbContext db, string clientId, Guid productId, Guid licenseId, string grantDigest,
        string hardwareHash, string? installationHash, string? keyThumbprint,
        bool allowPreviousGrant, CancellationToken cancellationToken)
    {
        var receipts = db.RuntimeDistributionHardwareDecisions.AsNoTracking().Where(row =>
            row.ClientId == clientId && row.ProductId == productId && row.LicenseId == licenseId
            && row.HardwareIdHash == hardwareHash && row.MachineClassifierVersion == VirtualMachinePolicy.Version);
        if (!allowPreviousGrant) receipts = receipts.Where(row => row.GrantRefDigestSha256 == grantDigest);
        if (installationHash != null) receipts = receipts.Where(row => row.InstallationIdHash == installationHash && row.KeyThumbprint == keyThumbprint);
        // A linked receipt authorizes reuse across a grant only through its exact original immutable source.
        var query = (from receipt in receipts
            join source in db.RuntimeDistributionHardwareDecisions.AsNoTracking()
                on receipt.MachineEvidenceSourceDecisionId equals (Guid?)source.Id
            where source.MachineEvidenceSourceDecisionId == source.Id
                && source.MachineClassifierVersion == VirtualMachinePolicy.Version
                && source.ClientId == receipt.ClientId && source.ProductId == receipt.ProductId
                && source.LicenseId == receipt.LicenseId && source.HardwareIdHash == receipt.HardwareIdHash
                && source.InstallationIdHash == receipt.InstallationIdHash && source.KeyThumbprint == receipt.KeyThumbprint
                && source.InstallationIdHash != null && source.KeyThumbprint != null
                && (source.AuthorityMode == "server-derived" || source.AuthorityMode == "known-enrollment")
                && source.MachineClassification == receipt.MachineClassification
                && source.MachineEvidenceDigestSha256 == receipt.MachineEvidenceDigestSha256
            select source).Distinct();
        if (installationHash == null && await query.Select(row => new { row.InstallationIdHash, row.KeyThumbprint }).Distinct().CountAsync(cancellationToken) != 1)
            return new("unknown", "authenticated_scope_ambiguous", null);
        var newest = await query.MaxAsync(row => (DateTime?)row.CreatedAtUtc, cancellationToken);
        if (newest is null)
            return new("unknown", "authenticated_evidence_missing", null);
        var rows = await query.Where(row => row.CreatedAtUtc == newest).Take(2).ToListAsync(cancellationToken);
        if (rows.Count != 1) return new("unknown", "authenticated_source_time_ambiguous", null);
        var proofs = rows.Select(Read).ToArray();
        {
            // A grant-bound receipt establishes permission to reuse its source, never permission to ignore
            // newer evidence from the same machine authority. Cross-grant freshness may deny, not grant rights.
            var bound = rows[0];
            var current = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().Where(source =>
                source.ClientId == clientId && source.ProductId == productId && source.LicenseId == licenseId
                && source.HardwareIdHash == hardwareHash && source.InstallationIdHash == bound.InstallationIdHash
                && source.KeyThumbprint == bound.KeyThumbprint && source.MachineEvidenceSourceDecisionId == source.Id
                && (source.AuthorityMode == "server-derived" || source.AuthorityMode == "known-enrollment"))
                .OrderByDescending(source => source.CreatedAtUtc).Take(2).ToListAsync(cancellationToken);
            if (current.Count == 0 || current.Count > 1 && current[0].CreatedAtUtc == current[1].CreatedAtUtc)
                return new("unknown", "authenticated_source_time_ambiguous", null);
            if (current[0].Id != bound.Id)
            {
                var latest = Read(current[0]);
                return allowPreviousGrant || latest.Kind == "virtual" ? latest : new("unknown", "grant_source_stale", null);
            }
        }
        if (proofs[0].Kind == "unknown") return new("unknown", "authenticated_evidence_conflict", null);
        return proofs[0];
    }

    /// <summary>Serializes evidence and finalize across grants/installations for one authenticated license and machine, so cross-grant freshness cannot race.</summary>
    public static async Task LockAsync(LicenseDbContext db, string clientId, Guid productId, Guid licenseId,
        string hardwareHash, CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql()) return;
        var resource = $"vm-evidence:{clientId}:{productId:D}:{licenseId:D}:{hardwareHash}";
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({resource}, 1550))", cancellationToken);
    }
}
