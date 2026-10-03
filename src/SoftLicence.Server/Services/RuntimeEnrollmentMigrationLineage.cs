using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed partial class RuntimeEnrollmentService
{
    /// <summary>
    /// Proves only that an immutable binding digest and the current seat belong to one accepted
    /// signed migration. No client-supplied pair, alias alone, or historical right grants eligibility.
    /// The caller must separately check current licence, seat, quota, bans, binaries and version.
    /// Exact canonical digests and opaque authority identifiers are never normalized here.
    /// </summary>
    /// <param name="db">Caller-owned authority context; no writes are performed.</param>
    /// <param name="binding">Persisted source binding whose complete scope must match.</param>
    /// <param name="targetDigest">SHA-256 of the current commercial seat identity.</param>
    /// <param name="crypto">Server envelope authenticator; absence fails closed.</param>
    /// <param name="cancellationToken">Cancels reads without changing authority.</param>
    /// <returns>True only for a unique authenticated current alias, with at most the exact TKT-001500 historical companion.</returns>
    /// <exception cref="RuntimeEnrollmentException">Receipt authentication fails; never converted into eligibility.</exception>
    internal static async Task<bool> HasAcceptedBindingHardwareAsync(
        LicenseDbContext db, DistributionInstallationBinding binding, string targetDigest,
        IRuntimeEnrollmentCryptoService? crypto, CancellationToken cancellationToken)
    {
        if (crypto == null || !LowerSha256Pattern.IsMatch(targetDigest)
            || !LowerSha256Pattern.IsMatch(binding.HardwareIdHash))
            return false;
        var aliases = await db.HardwareAuthorityAliases.AsNoTracking()
            .Where(row => row.BindingId == binding.Id && row.IsActive)
            .Take(3).ToListAsync(cancellationToken);
        var enrollments = await db.RuntimeEnrollments.AsNoTracking()
            .Where(row => row.BindingId == binding.Id).Take(2).ToListAsync(cancellationToken);
        if (enrollments.Count != 1)
            return false;
        var alias = aliases.Count == 1 ? aliases[0]
            : await SelectAuthenticatedCurrentAliasCoreAsync(db, aliases, binding, enrollments,
                targetDigest, crypto, null, cancellationToken);
        if (alias == null || alias.DisabledAtUtc != null || alias.DisabledReason != null
            || alias.ProductId != binding.ProductId || alias.LicenseId != binding.LicenseId
            || alias.LicenseSeatId != binding.LicenseSeatId
            || alias.CanonicalHardwareIdSha256 != targetDigest)
            return false;
        var enrollment = enrollments[0];
        if (enrollment.Id != alias.RuntimeEnrollmentId || enrollment.ProductId != binding.ProductId
            || enrollment.LicenseId != binding.LicenseId || enrollment.LicenseSeatId != binding.LicenseSeatId
            || enrollment.InstallationId != binding.InstallationId
            || enrollment.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
            || enrollment.HandoffDigestSha256 != binding.HandoffDigestSha256
            || enrollment.ReleaseVersion != binding.Version
            || alias.SecurityEpoch < 1 || alias.SecurityEpoch > enrollment.SecurityEpoch
            || alias.AuthorityEpoch < 0 || alias.AuthorityEpoch > enrollment.AuthorityEpoch)
            return false;
        return await HasAcceptedMigrationLineageCoreAsync(db, alias, binding, enrollment,
            targetDigest, crypto, null, cancellationToken);
    }

    /// <summary>Separates durable acceptance envelopes from expiring migration response envelopes.</summary>
    private const string MigrationReceiptOwner = "hardware-migration-receipt";

    /// <summary>
    /// Records one signed, server-accepted migration edge inside the caller's authority transaction.
    /// Missing historical parent evidence leaves the alias unproved; this method never manufactures history.
    /// The caller has verified the signature, current assignment, quota, bans and source seat identity.
    /// </summary>
    /// <param name="db">Context owning the migration transaction and authority row locks.</param>
    /// <param name="alias">Tracked alias already retargeted in memory, not yet committed.</param>
    /// <param name="binding">Binding whose immutable digest supplies the installation provenance.</param>
    /// <param name="enrollment">Credential that signed this accepted migration.</param>
    /// <param name="request">Validated canonical request and proof.</param>
    /// <param name="bodyDigest">Digest of the exact signed request body.</param>
    /// <param name="now">Database acceptance time.</param>
    /// <param name="cancellationToken">Cancels before the surrounding transaction commits.</param>
    private async Task RecordMigrationLineageAsync(LicenseDbContext db, HardwareAuthorityAlias alias,
        DistributionInstallationBinding binding, RuntimeEnrollment enrollment,
        HardwareAuthorityMigrationValidated request, string bodyDigest, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var source = Sha256(request.LegacyHardwareId);
        var target = Sha256(request.HardwareIdV2);
        HardwareAuthorityMigrationReceipt? parent = null;
        if (alias.MigrationReceiptId is { } parentId)
        {
            var chain = await ReadMigrationLineageAsync(db, alias, parentId, source, cancellationToken);
            if (chain == null)
            {
                // The signed operation may still perform its existing migration, but cannot bless an unproved chain.
                alias.MigrationReceiptId = null;
                _historyLogger?.LogWarning("MIGRATION_LINEAGE_UNPROVED Alias {AliasId}, request {RequestId}: invalid parent receipt.",
                    alias.Id, request.RequestId);
                return;
            }
            parent = chain[0].Row;
        }
        else if (alias.LegacyHardwareIdSha256 != source)
        {
            _historyLogger?.LogWarning("MIGRATION_LINEAGE_UNPROVED Alias {AliasId}, request {RequestId}: historical parent receipt missing.",
                alias.Id, request.RequestId);
            return;
        }

        var id = Guid.NewGuid();
        var fact = new MigrationLineageFact(id, alias.Id, alias.ProductId, alias.LicenseId, alias.LicenseSeatId,
            binding.Id, enrollment.Id, enrollment.InstallationId, enrollment.Epoch,
            enrollment.PublicKeySpkiSha256, enrollment.ClientId, enrollment.SecurityEpoch, enrollment.AuthorityEpoch,
            request.RequestId, request.Proof.Jti, bodyDigest, request.Proof.ProofDigest,
            source, target, parent?.Id, parent == null ? null : Sha256(parent.Ciphertext), now.UtcDateTime);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(fact, JsonOptions);
        try
        {
            var envelope = await _crypto.SealAsync(db, MigrationReceiptOwner, id, enrollment.Epoch,
                bytes, MigrationReceiptReference(id, enrollment.Id), cancellationToken);
            db.HardwareAuthorityMigrationReceipts.Add(new HardwareAuthorityMigrationReceipt
            {
                Id = id, EnrollmentId = enrollment.Id, EnrollmentEpoch = enrollment.Epoch,
                RequestId = request.RequestId, Jti = request.Proof.Jti, ParentReceiptId = parent?.Id,
                KeyId = envelope.KeyId, Ciphertext = envelope.Ciphertext
            });
            alias.MigrationReceiptId = id;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Selects the sole authenticated S-to-U root beside one retained historical L-to-S alias.
    /// Every excluded row must be the exact same server-owned authority ending at the proven source S.
    /// No row is rewritten or treated as migration evidence; every other multi-alias graph stays ambiguous.
    /// </summary>
    /// <param name="db">Confirm transaction holding predecessor and alias locks.</param>
    /// <param name="aliases">All active aliases attached to that predecessor, including foreign destinations.</param>
    /// <param name="predecessor">Direct predecessor carrying the historical stable digest S.</param>
    /// <param name="enrollments">Locked predecessor credentials.</param>
    /// <param name="successor">Server-owned successor whose canonical digest is U.</param>
    /// <param name="cancellationToken">Cancels without repointing either alias.</param>
    /// <returns>The proved current alias, or null for any ambiguity or unmatched historical row.</returns>
    private async Task<HardwareAuthorityAlias?> SelectAuthenticatedCurrentAliasAsync(
        LicenseDbContext db, IReadOnlyList<HardwareAuthorityAlias> aliases,
        DistributionInstallationBinding predecessor, IReadOnlyList<RuntimeEnrollment> enrollments,
        DistributionInstallationBinding successor, CancellationToken cancellationToken)
    {
        if (successor.SupersededBindingId != predecessor.Id)
            return null;
        return await SelectAuthenticatedCurrentAliasCoreAsync(db, aliases, predecessor, enrollments,
            successor.HardwareIdHash, _crypto, _historyLogger, cancellationToken);
    }

    /// <summary>
    /// Shares TKT-001500's exact historical-companion selection with current-seat eligibility.
    /// The Confirm wrapper additionally proves direct successor ancestry before calling here.
    /// Every unrelated alias still refuses; no destination-only filtering grants acceptance.
    /// </summary>
    private static async Task<HardwareAuthorityAlias?> SelectAuthenticatedCurrentAliasCoreAsync(
        LicenseDbContext db, IReadOnlyList<HardwareAuthorityAlias> aliases,
        DistributionInstallationBinding predecessor, IReadOnlyList<RuntimeEnrollment> enrollments,
        string targetDigest, IRuntimeEnrollmentCryptoService crypto, ILogger? logger,
        CancellationToken cancellationToken)
    {
        // This exception covers only the approved historical pair, never a general destination filter.
        if (aliases.Count != 2 || predecessor.HardwareIdHash == targetDigest)
            return null;
        var candidates = aliases.Where(row => row.CanonicalHardwareIdSha256 == targetDigest).ToArray();
        if (candidates.Length != 1)
            return null;
        var current = candidates[0];
        var source = enrollments.SingleOrDefault(row => row.Id == current.RuntimeEnrollmentId);
        if (source == null || current.MigrationReceiptId is not { } receiptId
            || current.BindingId != predecessor.Id || source.BindingId != predecessor.Id
            || current.ProductId != predecessor.ProductId || current.LicenseId != predecessor.LicenseId
            || current.LicenseSeatId != predecessor.LicenseSeatId
            || !await HasAcceptedMigrationLineageCoreAsync(db, current, predecessor, source,
                targetDigest, crypto, logger, cancellationToken))
            return null;
        var chain = await ReadMigrationLineageCoreAsync(db, current, receiptId, targetDigest,
            crypto, logger, cancellationToken);
        if (chain is not { Count: 1 } || chain[0].Fact.ParentId != null
            || chain[0].Fact.SourceDigest != predecessor.HardwareIdHash
            || current.LegacyHardwareIdSha256 != predecessor.HardwareIdHash)
            return null;
        var historical = aliases.Single(row => row.Id != current.Id);
        var fact = chain[0].Fact;
        // The historical backfill legitimately stores a null request id; it is never acceptance evidence.
        if (historical.MigrationReceiptId != null || historical.MigrationRequestId == Guid.Empty || !historical.IsActive || historical.DisabledAtUtc != null
            || historical.DisabledReason != null
            || historical.ProductId != current.ProductId || historical.LicenseId != current.LicenseId
            || historical.LicenseSeatId != current.LicenseSeatId || historical.BindingId != predecessor.Id
            || historical.RuntimeEnrollmentId != source.Id
            || historical.CanonicalHardwareIdSha256 != fact.SourceDigest
            || !LowerSha256Pattern.IsMatch(historical.LegacyHardwareIdSha256)
            || historical.LegacyHardwareIdSha256 == fact.SourceDigest
            || historical.LegacyHardwareIdSha256 == fact.TargetDigest
            || historical.SecurityEpoch < 1 || historical.SecurityEpoch > fact.SecurityEpoch
            || historical.AuthorityEpoch < 0 || historical.AuthorityEpoch > fact.AuthorityEpoch
            || historical.CreatedAtUtc > fact.AcceptedAtUtc)
            return null;
        return current;
    }

    /// <summary>
    /// Requires an authenticated migration chain from the predecessor's immutable binding digest to the
    /// successor's canonical digest. It grants no authority outside the existing Confirm graph checks.
    /// Missing evidence returns false; unavailable or corrupt cryptography remains authority_unavailable.
    /// </summary>
    /// <param name="db">Confirm transaction context holding alias and credential locks.</param>
    /// <param name="alias">The unique active alias linked to the direct predecessor.</param>
    /// <param name="predecessor">The terminal direct-predecessor binding.</param>
    /// <param name="enrollment">Its terminal credential, whose key and generation must match the latest receipt.</param>
    /// <param name="target">Exact canonical successor hardware digest.</param>
    /// <param name="cancellationToken">Cancels before repoint or commit.</param>
    /// <returns>True only for a complete accepted chain within this alias's authority scope.</returns>
    private async Task<bool> HasAcceptedMigrationLineageAsync(LicenseDbContext db, HardwareAuthorityAlias alias,
        DistributionInstallationBinding predecessor, RuntimeEnrollment enrollment, string target,
        CancellationToken cancellationToken)
        => await HasAcceptedMigrationLineageCoreAsync(db, alias, predecessor, enrollment, target,
            _crypto, _historyLogger, cancellationToken);

    /// <summary>Shared authenticated chain predicate; commercial rights remain the caller's responsibility.</summary>
    private static async Task<bool> HasAcceptedMigrationLineageCoreAsync(LicenseDbContext db, HardwareAuthorityAlias alias,
        DistributionInstallationBinding predecessor, RuntimeEnrollment enrollment, string target,
        IRuntimeEnrollmentCryptoService crypto, ILogger? logger, CancellationToken cancellationToken)
    {
        if (alias.MigrationReceiptId is not { } receiptId)
            return false;
        var chain = await ReadMigrationLineageCoreAsync(db, alias, receiptId, target, crypto, logger, cancellationToken);
        if (chain == null)
            return false;
        var head = chain[0].Fact;
        return head.RequestId == alias.MigrationRequestId
            && head.BindingId == predecessor.Id && head.EnrollmentId == enrollment.Id
            && head.InstallationId == predecessor.InstallationId && head.EnrollmentEpoch == enrollment.Epoch
            && head.PublicKeyDigest == enrollment.PublicKeySpkiSha256 && head.ClientId == enrollment.ClientId
            && head.SecurityEpoch <= enrollment.SecurityEpoch && head.AuthorityEpoch <= enrollment.AuthorityEpoch
            && chain.Any(edge => edge.Fact.SourceDigest == predecessor.HardwareIdHash);
    }

    /// <summary>
    /// Opens a complete immutable chain backwards, checking every encrypted scope and parent link.
    /// No time-to-live applies. Cycles, missing parents, duplicate authority or ciphertext substitution fail closed.
    /// Database or crypto failures propagate distinctly; malformed authenticated facts never become acceptance.
    /// </summary>
    /// <param name="db">Caller-owned authority context.</param>
    /// <param name="alias">Expected immutable alias identity and commercial scope.</param>
    /// <param name="headId">Exact receipt reference, never a search by two hardware digests.</param>
    /// <param name="target">Expected final digest, or the next migration's source when extending a chain.</param>
    /// <param name="cancellationToken">Cancels bounded per-edge database reads.</param>
    /// <returns>Head-first authenticated edges, or null for missing or inconsistent evidence.</returns>
    private async Task<List<MigrationLineageEdge>?> ReadMigrationLineageAsync(LicenseDbContext db,
        HardwareAuthorityAlias alias, Guid headId, string target, CancellationToken cancellationToken)
        => await ReadMigrationLineageCoreAsync(db, alias, headId, target, _crypto, _historyLogger, cancellationToken);

    /// <summary>Authenticates every durable edge with the supplied server cryptographic authority.</summary>
    private static async Task<List<MigrationLineageEdge>?> ReadMigrationLineageCoreAsync(LicenseDbContext db,
        HardwareAuthorityAlias alias, Guid headId, string target, IRuntimeEnrollmentCryptoService crypto,
        ILogger? logger, CancellationToken cancellationToken)
    {
        var result = new List<MigrationLineageEdge>();
        var visited = new HashSet<Guid>();
        Guid? next = headId;
        string? expectedEnvelopeDigest = null;
        DateTime? childAcceptedAt = null;
        while (next is { } id)
        {
            if (!visited.Add(id)) return null;
            var row = await db.HardwareAuthorityMigrationReceipts.AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == id, cancellationToken);
            if (row == null || (expectedEnvelopeDigest != null && Sha256(row.Ciphertext) != expectedEnvelopeDigest))
                return null;
            var fact = OpenMigrationReceipt(row, crypto, logger);
            if (fact.Id != row.Id || fact.EnrollmentId != row.EnrollmentId || fact.EnrollmentEpoch != row.EnrollmentEpoch
                || fact.RequestId != row.RequestId || fact.Jti != row.Jti || fact.ParentId != row.ParentReceiptId
                || fact.AliasId != alias.Id || fact.ProductId != alias.ProductId || fact.LicenseId != alias.LicenseId
                || fact.SeatId != alias.LicenseSeatId || fact.TargetDigest != target
                || fact.SourceDigest == null || !LowerSha256Pattern.IsMatch(fact.SourceDigest)
                || !LowerSha256Pattern.IsMatch(fact.TargetDigest ?? string.Empty)
                || !LowerSha256Pattern.IsMatch(fact.BodyDigest ?? string.Empty)
                || !LowerSha256Pattern.IsMatch(fact.ProofDigest ?? string.Empty)
                || fact.SourceDigest == fact.TargetDigest || fact.SecurityEpoch < 1 || fact.AuthorityEpoch < 0
                || (childAcceptedAt.HasValue && fact.AcceptedAtUtc > childAcceptedAt.Value)
                || ((fact.ParentId == null) != (fact.ParentEnvelopeDigest == null)))
                return null;
            result.Add(new MigrationLineageEdge(row, fact));
            next = fact.ParentId;
            expectedEnvelopeDigest = fact.ParentEnvelopeDigest;
            childAcceptedAt = fact.AcceptedAtUtc;
            target = fact.SourceDigest;
        }
        return result.Count > 0 && target == alias.LegacyHardwareIdSha256 ? result : null;
    }

    /// <summary>Binds an envelope to its exact receipt and signing enrollment without normalization.</summary>
    /// <param name="id">Receipt identifier.</param>
    /// <param name="enrollmentId">Signing enrollment identifier.</param>
    /// <returns>Stable domain-specific authenticated context.</returns>
    private static string MigrationReceiptReference(Guid id, Guid enrollmentId) =>
        $"migration-receipt/{enrollmentId:D}/{id:D}";

    /// <summary>Authenticates a durable envelope and clears its temporary plaintext bytes even after parsing failure.</summary>
    /// <param name="row">Exact persisted envelope owner and key reference.</param>
    /// <param name="crypto">Server-owned cryptographic authority; never constructed from client input.</param>
    /// <param name="logger">Optional bounded receipt-identifier diagnostic sink.</param>
    /// <returns>The immutable parsed acceptance fact; cryptographic failures remain authority_unavailable.</returns>
    private static MigrationLineageFact OpenMigrationReceipt(HardwareAuthorityMigrationReceipt row,
        IRuntimeEnrollmentCryptoService crypto, ILogger? logger)
    {
        byte[]? bytes = null;
        try
        {
            bytes = crypto.Open(MigrationReceiptOwner, row.Id, row.EnrollmentEpoch,
                row.KeyId, row.Ciphertext, MigrationReceiptReference(row.Id, row.EnrollmentId));
            return JsonSerializer.Deserialize<MigrationLineageFact>(bytes, JsonOptions)
                ?? throw new JsonException("Migration receipt payload is empty.");
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            logger?.LogError(exception, "MIGRATION_RECEIPT_UNAVAILABLE Receipt {ReceiptId} could not be authenticated or decoded.", row.Id);
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "migration_receipt_unavailable");
        }
        finally
        {
            if (bytes != null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Pairs a persisted immutable envelope with its authenticated server acceptance fact.</summary>
    /// <param name="Row">Persisted envelope and indexed identifiers.</param>
    /// <param name="Fact">Decrypted fact; never supplied by a client or reconstructed from an alias.</param>
    private sealed record MigrationLineageEdge(HardwareAuthorityMigrationReceipt Row, MigrationLineageFact Fact);

    /// <summary>
    /// Internal encrypted acceptance payload. GUIDs, digests and client/installation identifiers retain exact
    /// ordinal semantics. PublicKeyDigest identifies the signing credential; no private key or raw HWID is retained.
    /// ParentEnvelopeDigest authenticates the prior accepted edge and prevents chain substitution.
    /// </summary>
    /// <param name="Id">Immutable envelope owner.</param>
    /// <param name="AliasId">Alias whose lineage this edge can authorize.</param>
    /// <param name="ProductId">Accepted product scope.</param>
    /// <param name="LicenseId">Accepted commercial license scope.</param>
    /// <param name="SeatId">Single accepted seat scope.</param>
    /// <param name="BindingId">Installation binding authenticated at acceptance.</param>
    /// <param name="EnrollmentId">Credential that signed the migration.</param>
    /// <param name="InstallationId">Exact opaque installation identifier.</param>
    /// <param name="EnrollmentEpoch">Positive signing-credential generation.</param>
    /// <param name="PublicKeyDigest">Lowercase SHA-256 of the enrolled signing public key.</param>
    /// <param name="ClientId">Authenticated S2S owner of the signing enrollment.</param>
    /// <param name="SecurityEpoch">Security generation accepted by the migration.</param>
    /// <param name="AuthorityEpoch">Authority generation accepted by the migration.</param>
    /// <param name="RequestId">Canonical signed operation identifier.</param>
    /// <param name="Jti">Canonical detached-proof nonce identifier.</param>
    /// <param name="BodyDigest">Lowercase SHA-256 of the exact signed request bytes.</param>
    /// <param name="ProofDigest">Lowercase SHA-256 of the verified detached proof.</param>
    /// <param name="SourceDigest">Digest of the seat identity before the accepted move.</param>
    /// <param name="TargetDigest">Digest of the UUID-derived seat identity after the move.</param>
    /// <param name="ParentId">Previous accepted edge, or null only for the authenticated root.</param>
    /// <param name="ParentEnvelopeDigest">Exact predecessor ciphertext digest, null only at the root.</param>
    /// <param name="AcceptedAtUtc">UTC database time of acceptance in the migration transaction.</param>
    private sealed record MigrationLineageFact(Guid Id, Guid AliasId, Guid ProductId, Guid LicenseId, Guid SeatId,
        Guid BindingId, Guid EnrollmentId, string InstallationId, int EnrollmentEpoch, string PublicKeyDigest,
        string ClientId, int SecurityEpoch, long AuthorityEpoch, Guid RequestId, Guid Jti, string BodyDigest,
        string ProofDigest, string SourceDigest, string TargetDigest, Guid? ParentId, string? ParentEnvelopeDigest,
        DateTime AcceptedAtUtc);
}
