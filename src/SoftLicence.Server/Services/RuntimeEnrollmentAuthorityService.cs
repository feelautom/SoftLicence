using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Identifies the closed outcome of persisting one validated authority generation.</summary>
internal enum RuntimeEnrollmentAuthorityPersistenceStatus
{
    /// <summary>The lineage/generation/request transaction committed successfully.</summary>
    Created,
    /// <summary>An authoritative read proved complete immutable equality with the stored result.</summary>
    ExactStoredResult,
    /// <summary>An authoritative read or lineage-head CAS proved a structural divergence.</summary>
    StructuralConflict
}

/// <summary>Names each ordered phase that the transactional persistence implementation advances.</summary>
internal enum RuntimeEnrollmentAuthorityPersistencePhase
{
    /// <summary>The database transaction was opened.</summary>
    Begin,
    /// <summary>Bounded PostgreSQL lock and statement timeouts were installed.</summary>
    Timeouts,
    /// <summary>The shared global authority advisory lock was acquired.</summary>
    Global,
    /// <summary>The current authority epoch was read under the global lock.</summary>
    Epoch,
    /// <summary>All binding advisory locks were acquired in ordinal UUID-text order.</summary>
    Bindings,
    /// <summary>The tuple or lineage identity advisory lock was acquired.</summary>
    Identity,
    /// <summary>Authoritative request and lineage identity state was reread.</summary>
    Reread,
    /// <summary>The successor lineage row was locked and validated.</summary>
    LineageRow,
    /// <summary>The immutable generation/request rows were inserted.</summary>
    Insert,
    /// <summary>The successor lineage head compare-and-swap was executed.</summary>
    Cas,
    /// <summary>The transaction commit was requested.</summary>
    Commit
}

/// <summary>
/// Enforces the exact phase sequence consumed by one persistence attempt. Genesis omits successor-only
/// lineage-row and CAS phases; an authoritative early result may terminate only after Reread or LineageRow.
/// </summary>
internal sealed class RuntimeEnrollmentAuthorityPersistenceFlow
{
    private static readonly RuntimeEnrollmentAuthorityPersistencePhase[] Genesis =
    [
        RuntimeEnrollmentAuthorityPersistencePhase.Begin,
        RuntimeEnrollmentAuthorityPersistencePhase.Timeouts,
        RuntimeEnrollmentAuthorityPersistencePhase.Global,
        RuntimeEnrollmentAuthorityPersistencePhase.Epoch,
        RuntimeEnrollmentAuthorityPersistencePhase.Bindings,
        RuntimeEnrollmentAuthorityPersistencePhase.Identity,
        RuntimeEnrollmentAuthorityPersistencePhase.Reread,
        RuntimeEnrollmentAuthorityPersistencePhase.Insert,
        RuntimeEnrollmentAuthorityPersistencePhase.Commit
    ];

    private static readonly RuntimeEnrollmentAuthorityPersistencePhase[] Successor =
    [
        RuntimeEnrollmentAuthorityPersistencePhase.Begin,
        RuntimeEnrollmentAuthorityPersistencePhase.Timeouts,
        RuntimeEnrollmentAuthorityPersistencePhase.Global,
        RuntimeEnrollmentAuthorityPersistencePhase.Epoch,
        RuntimeEnrollmentAuthorityPersistencePhase.Bindings,
        RuntimeEnrollmentAuthorityPersistencePhase.Identity,
        RuntimeEnrollmentAuthorityPersistencePhase.Reread,
        RuntimeEnrollmentAuthorityPersistencePhase.LineageRow,
        RuntimeEnrollmentAuthorityPersistencePhase.Insert,
        RuntimeEnrollmentAuthorityPersistencePhase.Cas,
        RuntimeEnrollmentAuthorityPersistencePhase.Commit
    ];

    private readonly IReadOnlyList<RuntimeEnrollmentAuthorityPersistencePhase> _expected;
    private int _next;

    /// <summary>Creates the closed genesis or successor phase path for one write attempt.</summary>
    /// <param name="genesis">True for sequence zero; false for a successor generation.</param>
    internal RuntimeEnrollmentAuthorityPersistenceFlow(bool genesis) =>
        _expected = genesis ? Genesis : Successor;

    /// <summary>
    /// Advances exactly one expected phase and rejects an omitted, duplicated, permuted, or post-terminal step.
    /// </summary>
    internal void Advance(RuntimeEnrollmentAuthorityPersistencePhase phase)
    {
        if (_next >= _expected.Count || _expected[_next] != phase)
            throw new InvalidOperationException($"Invalid Runtime Enrollment persistence phase: {phase}.");
        _next++;
    }

    /// <summary>
    /// Allows an authoritative replay/conflict branch to commit only after identity reread or successor-row
    /// validation, while rejecting all earlier or already completed termination attempts.
    /// </summary>
    internal void AdvanceAuthoritativeCommit()
    {
        var previous = _next == 0 ? (RuntimeEnrollmentAuthorityPersistencePhase?)null : _expected[_next - 1];
        if (previous is not RuntimeEnrollmentAuthorityPersistencePhase.Reread
            and not RuntimeEnrollmentAuthorityPersistencePhase.LineageRow)
            throw new InvalidOperationException("An authoritative result cannot commit from the current phase.");
        _next = _expected.Count - 1;
        Advance(RuntimeEnrollmentAuthorityPersistencePhase.Commit);
    }
}

/// <summary>
/// Carries opaque, already validated Runtime Enrollment v2 values into the persistence boundary.
/// Callers must supply exact contract strings and bytes without trimming, case folding, Unicode
/// normalization, canonicalization, hashing, signing, or verification in this component.
/// </summary>
internal sealed class RuntimeEnrollmentAuthorityPersistenceCandidate
{
    /// <summary>Gets the immutable lineage UUID.</summary>
    public required Guid AuthorityLineageId { get; init; }
    /// <summary>Gets the immutable generation UUID.</summary>
    public required Guid AuthorityGenerationId { get; init; }
    /// <summary>Gets the immutable request UUID.</summary>
    public required Guid RequestId { get; init; }
    /// <summary>Gets the exact 64-byte lowercase hexadecimal request digest.</summary>
    public required string RequestDigest { get; init; }
    /// <summary>Gets the exact provider identifier; no normalization is applied.</summary>
    public required string Provider { get; init; }
    /// <summary>Gets the product UUID that owns the lineage.</summary>
    public required Guid ProductId { get; init; }
    /// <summary>Gets the exact SoftLicence commercial seat that owns the lineage.</summary>
    public required Guid LicenseSeatId { get; init; }
    /// <summary>Gets the opaque provider grant reference exactly as received.</summary>
    public required string ProviderGrantRef { get; init; }
    /// <summary>Gets the validated Unicode scalar count of <see cref="ProviderGrantRef"/>.</summary>
    public required int ProviderGrantRefScalarCount { get; init; }
    /// <summary>Gets the immutable UTC creation time of the lineage.</summary>
    public required DateTime LineageCreatedAtUtc { get; init; }
    /// <summary>Gets the zero-based monotonic generation sequence.</summary>
    public required long Sequence { get; init; }
    /// <summary>Gets null for genesis, otherwise the exact preceding generation UUID.</summary>
    public required Guid? PreviousGenerationId { get; init; }
    /// <summary>Gets the opaque canonical payload bytes, bounded to 1..2895 bytes.</summary>
    public required byte[] CanonicalPayloadUtf8 { get; init; }
    /// <summary>Gets the opaque signed statement bytes, bounded to 1..3569 bytes.</summary>
    public required byte[] SignedStatementUtf8 { get; init; }
    /// <summary>Gets the exact 64-byte lowercase hexadecimal authority digest.</summary>
    public required string AuthorityDigest { get; init; }
    /// <summary>Gets the already validated signature algorithm identifier.</summary>
    public required string SignatureAlgorithm { get; init; }
    /// <summary>Gets the already validated opaque signature key identifier.</summary>
    public required string SignatureKeyId { get; init; }
    /// <summary>Gets the already validated Base64Url signature value without transformation.</summary>
    public required string SignatureValue { get; init; }
    /// <summary>Gets the immutable UTC contract occurrence time.</summary>
    public required DateTime OccurredAtUtc { get; init; }
    /// <summary>Gets the immutable UTC persistence creation time shared by generation and request.</summary>
    public required DateTime CreatedAtUtc { get; init; }
    /// <summary>Gets binding UUIDs whose advisory locks are acquired in ordinal UUID-text order.</summary>
    public IReadOnlyCollection<Guid> BindingIds { get; init; } = [];
}

/// <summary>Returns the closed status and immutable identifiers of a persistence decision.</summary>
/// <param name="Status">The closed created, exact, or conflict classification.</param>
/// <param name="AuthorityLineageId">The immutable lineage UUID.</param>
/// <param name="AuthorityGenerationId">The immutable generation UUID.</param>
internal sealed record RuntimeEnrollmentAuthorityPersistenceResult(
    RuntimeEnrollmentAuthorityPersistenceStatus Status,
    Guid AuthorityLineageId,
    Guid AuthorityGenerationId);

/// <summary>Describes the closed handling decision for one PostgreSQL persistence failure.</summary>
internal enum RuntimeEnrollmentAuthorityRetryDecision
{
    /// <summary>Retries the complete transaction while write-attempt budget remains.</summary>
    Retry,
    /// <summary>Performs one read-only authoritative classification after the final rollback.</summary>
    AuthoritativeRead,
    /// <summary>Propagates the original PostgreSQL failure without reclassification.</summary>
    Propagate
}

/// <summary>Closes the read-only outcome after the final named 23505 rollback.</summary>
internal enum RuntimeEnrollmentAuthorityFinalCollisionOutcome
{
    /// <summary>Complete immutable equality was established authoritatively.</summary>
    ExactStoredResult,
    /// <summary>A stored request exists and complete immutable equality proved divergence.</summary>
    StructuralConflict,
    /// <summary>No candidate request exists, so no exact/conflict classification is safe.</summary>
    Exhausted
}

/// <summary>Signals that bounded writes ended without enough stored state to classify a named collision.</summary>
internal sealed class RuntimeEnrollmentAuthorityPersistenceExhaustedException : InvalidOperationException
{
    /// <summary>Creates an explicit bounded failure for an unclassifiable final named collision.</summary>
    public RuntimeEnrollmentAuthorityPersistenceExhaustedException()
        : base("Runtime Enrollment authority persistence exhausted before an authoritative result existed.") { }
}

public sealed class RuntimeAuthorityLease : IAsyncDisposable
{
    private readonly IDbContextTransaction _transaction;
    public long AuthorityEpoch { get; }

    internal RuntimeAuthorityLease(IDbContextTransaction transaction, long authorityEpoch)
    {
        _transaction = transaction;
        AuthorityEpoch = authorityEpoch;
    }

    public Task CommitAsync(CancellationToken cancellationToken = default) =>
        _transaction.CommitAsync(cancellationToken);

    public ValueTask DisposeAsync() => _transaction.DisposeAsync();
}

public interface IRuntimeEnrollmentAuthorityService
{
    Task<RuntimeAuthorityLease> AcquireAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default);

    Task<RuntimeAuthorityLease> AcquireMutationAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default);

    Task ValidateInfrastructureAsync(CancellationToken cancellationToken = default);
}

public sealed class RuntimeEnrollmentAuthorityService : IRuntimeEnrollmentAuthorityService
{
    public const int GlobalLockNamespace = 999831;
    public const int GlobalLockKey = 1;
    public const long BindingLockSalt = 999831;
    /// <summary>Gets the closed maximum number of write transactions.</summary>
    internal const int MaximumPersistenceAttempts = 3;
    /// <summary>Gets the inclusive canonical payload byte limit from the v2 contract.</summary>
    internal const int MaximumCanonicalPayloadBytes = 2895;
    /// <summary>Gets the inclusive signed statement byte limit from the v2 contract.</summary>
    internal const int MaximumSignedStatementBytes = 3569;

    /// <summary>Gets every named unique surface eligible for authoritative 23505 reclassification.</summary>
    internal static readonly IReadOnlySet<string> PersistenceUniqueConstraintNames =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "PK_REAuthorityLineages",
            "UX_REAuthorityLineages_Provider_ProductId_GrantRef_SeatId",
            "PK_REAuthorityGenerations",
            "AK_REAuthorityGenerations_LineageId_GenerationId",
            "AK_REAuthorityGenerations_LineageId_GenerationId_Sequence",
            "AK_REAuthorityGenerations_GenerationId_RequestId",
            "AK_REAuthorityGenerations_LineageId_GenerationId_RequestId",
            "UX_REAuthorityGenerations_LineageId_Sequence",
            "UX_REAuthorityGenerations_LineageId_PredecessorId",
            "UX_REAuthorityRequests_RequestId_LineageId_GenerationId",
            "PK_REAuthorityRequests"
        };

    private const string AuthorityFunctionSource = """
        BEGIN
            PERFORM pg_catalog.pg_advisory_xact_lock(999831, 1);
            UPDATE public."RuntimeEnrollmentAuthorityStates"
            SET "Epoch" = "Epoch" + 1,
                "UpdatedAtUtc" = statement_timestamp()
            WHERE "Id" = 1;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'runtime enrollment authority singleton is missing';
            END IF;
            RETURN NULL;
        END;
        """;

    private static readonly IReadOnlyDictionary<string, string[]> ProtectedTables =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["ApprovedBinaries"] = ["ProductId", "Version", "Key", "Hash", "Source"],
            ["BannedComponents"] = ["ComponentType", "ComponentHash", "ProductId", "ExpiresAt", "IsActive"],
            ["BannedHardwareIds"] = ["HardwareId", "ProductId", "ExpiresAt", "IsActive"],
            ["DistributionBindingRequests"] = ["ClientId", "Operation", "BindingId"],
            ["DistributionGrantOwnerships"] = ["ProductId", "GrantRefDigestSha256", "ClientId", "Source"],
            ["DistributionInstallationBindings"] = ["ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "SubjectRefDigestSha256", "GrantRef", "GrantRefDigestSha256", "HandoffDigestSha256", "HandoffIssuedAtUtc", "HandoffExpiresAtUtc", "DownloadCompletedAtUtc", "InstallationId", "HardwareIdHash", "Version", "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256", "CoreSha256", "ApprovedBinariesSource", "State", "SupersededBindingId", "InitialSecurityEpoch", "InvalidatedAtUtc", "InvalidationReason"],
            ["LicenseSeats"] = ["LicenseId", "HardwareId", "IsActive"],
            ["Licenses"] = ["ProductId", "IsActive", "RevokedAt", "ExpirationDate", "MaxSeats", "AllowedVersions"],
            ["Products"] = ["MinimumAllowedVersion"]
        };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly RuntimeEnrollmentOptions _options;

    public RuntimeEnrollmentAuthorityService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IOptions<RuntimeEnrollmentOptions> options)
    {
        _dbFactory = dbFactory;
        _options = options.Value;
    }

    /// <summary>
    /// Atomically persists an already validated frozen generation while advancing
    /// <see cref="RuntimeEnrollmentAuthorityPersistenceFlow"/> after every effective transaction phase.
    /// The method never normalizes, canonicalizes, hashes, signs,
    /// verifies, routes, or applies transition policy. It returns Created only after commit,
    /// ExactStoredResult only after complete immutable equality, and StructuralConflict only after an
    /// authoritative read proves divergence. Serialization/deadlock failures retry at most three writes;
    /// the final named 23505 receives one read-only classification. Lock/statement timeout, cancellation,
    /// unknown constraints, and unclassifiable exhaustion propagate as bounded failures.
    /// </summary>
    /// <param name="db">Npgsql context whose connection is used for the complete transaction.</param>
    /// <param name="candidate">Opaque candidate already validated by the item 2/3 boundary.</param>
    /// <param name="cancellationToken">Cancels database waits, reads, writes, rollback, or commit.</param>
    /// <returns>The committed or authoritatively classified closed persistence result.</returns>
    internal async Task<RuntimeEnrollmentAuthorityPersistenceResult> PersistValidatedGenerationAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabledNpgsql(db);
        ValidatePersistenceCandidate(candidate);

        for (var attempt = 1; attempt <= MaximumPersistenceAttempts; attempt++)
        {
            var flow = new RuntimeEnrollmentAuthorityPersistenceFlow(candidate.Sequence == 0);
            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.ReadCommitted, cancellationToken);
            flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Begin);
            try
            {
                await ExecuteNonQueryAsync(db,
                    $"SET LOCAL lock_timeout = '{_options.LockTimeoutMilliseconds}ms'; " +
                    $"SET LOCAL statement_timeout = '{_options.StatementTimeoutMilliseconds}ms';",
                    cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Timeouts);
                await ExecuteNonQueryAsync(db,
                    "SELECT pg_catalog.pg_advisory_xact_lock_shared(999831, 1);", cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Global);
                _ = await ExecuteScalarAsync<long>(db,
                    "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;",
                    cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Epoch);

                foreach (var bindingId in candidate.BindingIds
                             .OrderBy(value => value.ToString("D"), StringComparer.Ordinal))
                {
                    await ExecuteNonQueryAsync(db,
                        "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(@value, 999831));",
                        cancellationToken, new NpgsqlParameter("value", bindingId.ToString("D")));
                }
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Bindings);

                if (candidate.Sequence == 0)
                    await AcquireTupleLockAsync(db, candidate, cancellationToken);
                else
                    await AcquireLineageLockAsync(db, candidate.AuthorityLineageId, cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Identity);

                var existingRequest = await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                    .SingleOrDefaultAsync(item => item.RequestId == candidate.RequestId, cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Reread);
                if (existingRequest != null)
                {
                    var replay = await ClassifyStoredResultAsync(db, candidate, existingRequest, cancellationToken);
                    flow.AdvanceAuthoritativeCommit();
                    await transaction.CommitAsync(cancellationToken);
                    return replay;
                }

                var tupleLineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                    .SingleOrDefaultAsync(item =>
                        item.Provider == candidate.Provider
                        && item.ProductId == candidate.ProductId
                        && item.ProviderGrantRef == candidate.ProviderGrantRef
                        && item.LicenseSeatId == candidate.LicenseSeatId, cancellationToken);
                var idLineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                    .SingleOrDefaultAsync(item =>
                        item.AuthorityLineageId == candidate.AuthorityLineageId, cancellationToken);

                if ((tupleLineage != null
                        && tupleLineage.AuthorityLineageId != candidate.AuthorityLineageId)
                    || (idLineage != null && !LineageEquals(idLineage, candidate)))
                {
                    flow.AdvanceAuthoritativeCommit();
                    await transaction.CommitAsync(cancellationToken);
                    return Conflict(candidate);
                }

                if (candidate.Sequence == 0)
                {
                    if (tupleLineage != null || idLineage != null)
                    {
                        await AcquireLineageLockAsync(db, candidate.AuthorityLineageId, cancellationToken);
                        flow.AdvanceAuthoritativeCommit();
                        await transaction.CommitAsync(cancellationToken);
                        return Conflict(candidate);
                    }

                    await InsertGenesisAsync(db, candidate, cancellationToken);
                    flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Insert);
                    flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Commit);
                    await transaction.CommitAsync(cancellationToken);
                    return Created(candidate);
                }

                var lineage = await db.RuntimeEnrollmentAuthorityLineages
                    .FromSqlInterpolated($"""
                        SELECT * FROM public."RuntimeEnrollmentAuthorityLineages"
                        WHERE "AuthorityLineageId" = {candidate.AuthorityLineageId}
                        FOR UPDATE
                        """)
                    .AsNoTracking()
                    .SingleOrDefaultAsync(cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.LineageRow);
                if (lineage == null || !LineageEquals(lineage, candidate)
                    || candidate.PreviousGenerationId != lineage.HeadGenerationId
                    || candidate.Sequence != lineage.HeadSequence + 1)
                {
                    flow.AdvanceAuthoritativeCommit();
                    await transaction.CommitAsync(cancellationToken);
                    return Conflict(candidate);
                }

                var existingGeneration = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                    .SingleOrDefaultAsync(item =>
                        item.AuthorityGenerationId == candidate.AuthorityGenerationId, cancellationToken);
                if (existingGeneration != null)
                {
                    flow.AdvanceAuthoritativeCommit();
                    await transaction.CommitAsync(cancellationToken);
                    return Conflict(candidate);
                }

                await InsertGenerationAndRequestAsync(db, candidate, cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Insert);
                var affected = await db.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE public."RuntimeEnrollmentAuthorityLineages"
                    SET "HeadGenerationId" = {candidate.AuthorityGenerationId},
                        "HeadSequence" = {candidate.Sequence}
                    WHERE "AuthorityLineageId" = {candidate.AuthorityLineageId}
                      AND "HeadGenerationId" = {candidate.PreviousGenerationId!.Value}
                      AND "HeadSequence" = {candidate.Sequence - 1}
                    """, cancellationToken);
                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Cas);
                if (ClassifyCasRowCount(affected) != RuntimeEnrollmentAuthorityPersistenceStatus.Created)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Conflict(candidate);
                }

                flow.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Commit);
                await transaction.CommitAsync(cancellationToken);
                return Created(candidate);
            }
            catch (PostgresException exception) when (
                DecideRetry(exception, attempt) == RuntimeEnrollmentAuthorityRetryDecision.Retry)
            {
                await transaction.RollbackAsync(cancellationToken);
                db.ChangeTracker.Clear();
            }
            catch (PostgresException exception) when (
                DecideRetry(exception, attempt) == RuntimeEnrollmentAuthorityRetryDecision.AuthoritativeRead)
            {
                await transaction.RollbackAsync(cancellationToken);
                db.ChangeTracker.Clear();
                return await ClassifyAfterFinalCollisionAsync(db, candidate, cancellationToken);
            }
        }

        throw new InvalidOperationException("The closed persistence attempt loop ended unexpectedly.");
    }

    /// <summary>
    /// Persists one validated candidate inside the caller-owned transaction. The caller owns retries,
    /// rollback, and the sole commit; this method never starts or completes a transaction.
    /// </summary>
    /// <param name="db">Context with an active caller-owned transaction and acquired authority lease.</param>
    /// <param name="candidate">Opaque, canonicalized and signed candidate.</param>
    /// <param name="cancellationToken">Cancels bounded database work.</param>
    /// <returns>Created, ExactStoredResult, or StructuralConflict after authoritative comparison.</returns>
    internal async Task<RuntimeEnrollmentAuthorityPersistenceResult> PersistValidatedGenerationInAmbientTransactionAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabledNpgsql(db);
        ValidatePersistenceCandidate(candidate);
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned authority transaction is required.");

        var request = await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
            .SingleOrDefaultAsync(item => item.RequestId == candidate.RequestId, cancellationToken);
        if (request is not null)
            return await ClassifyStoredResultAsync(db, candidate, request, cancellationToken);

        if (candidate.Sequence == 0)
        {
            await AcquireTupleLockAsync(db, candidate, cancellationToken);
            await InsertGenesisAsync(db, candidate, cancellationToken);
            return new(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                candidate.AuthorityLineageId, candidate.AuthorityGenerationId);
        }

        await AcquireLineageLockAsync(db, candidate.AuthorityLineageId, cancellationToken);
        var lineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AuthorityLineageId == candidate.AuthorityLineageId, cancellationToken);
        if (lineage is null
            || !string.Equals(lineage.Provider, candidate.Provider, StringComparison.Ordinal)
            || lineage.ProductId != candidate.ProductId
            || lineage.LicenseSeatId != candidate.LicenseSeatId
            || !string.Equals(lineage.ProviderGrantRef, candidate.ProviderGrantRef, StringComparison.Ordinal)
            || lineage.ProviderGrantRefScalarCount != candidate.ProviderGrantRefScalarCount
            || lineage.CreatedAtUtc != candidate.LineageCreatedAtUtc
            || lineage.HeadGenerationId != candidate.PreviousGenerationId
            || lineage.HeadSequence + 1 != candidate.Sequence)
            return new(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
                candidate.AuthorityLineageId, candidate.AuthorityGenerationId);
        await InsertGenerationAndRequestAsync(db, candidate, cancellationToken);
        var changed = await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE public."RuntimeEnrollmentAuthorityLineages"
            SET "HeadGenerationId" = {candidate.AuthorityGenerationId}, "HeadSequence" = {candidate.Sequence}
            WHERE "AuthorityLineageId" = {candidate.AuthorityLineageId}
              AND "HeadGenerationId" = {candidate.PreviousGenerationId}
              AND "HeadSequence" = {candidate.Sequence - 1}
            """, cancellationToken);
        return ClassifyCasRowCount(changed)
            == RuntimeEnrollmentAuthorityPersistenceStatus.Created
            ? new(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                candidate.AuthorityLineageId, candidate.AuthorityGenerationId)
            : new(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
                candidate.AuthorityLineageId, candidate.AuthorityGenerationId);
    }

    /// <summary>
    /// Persists one validated recovery genesis without using the globally keyed legacy request ledger.
    /// The caller-owned composite recovery ledger remains the sole idempotency authority, so two S2S
    /// clients may safely use the same request UUID without cross-client replay or disclosure.
    /// </summary>
    /// <param name="db">Context with the caller-owned transaction and global Runtime lock already held.</param>
    /// <param name="candidate">Validated and signed sequence-zero generation owned by the recovery transaction.</param>
    /// <param name="cancellationToken">Cancels bounded PostgreSQL work.</param>
    /// <returns>Created, exact stored generation, or structural conflict.</returns>
    internal async Task<RuntimeEnrollmentAuthorityPersistenceResult> PersistRecoveryGenesisInAmbientTransactionAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabledNpgsql(db);
        ValidatePersistenceCandidate(candidate);
        if (candidate.Sequence != 0 || db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned transaction and sequence-zero recovery candidate are required.");

        await AcquireTupleLockAsync(db, candidate, cancellationToken);
        var lineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking().SingleOrDefaultAsync(item =>
            item.Provider == candidate.Provider && item.ProductId == candidate.ProductId
            && item.LicenseSeatId == candidate.LicenseSeatId
            && item.ProviderGrantRef == candidate.ProviderGrantRef, cancellationToken);
        if (lineage is not null)
        {
            var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                .SingleOrDefaultAsync(item => item.AuthorityGenerationId == lineage.HeadGenerationId,
                    cancellationToken);
            return lineage.AuthorityLineageId == candidate.AuthorityLineageId
                && lineage.HeadSequence == 0 && generation is not null
                && GenerationEquals(generation, candidate)
                    ? new(RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult,
                        candidate.AuthorityLineageId, candidate.AuthorityGenerationId)
                    : new(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
                        candidate.AuthorityLineageId, candidate.AuthorityGenerationId);
        }

        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                ("AuthorityLineageId", "Provider", "ProductId", "LicenseSeatId", "ProviderGrantRef",
                 "ProviderGrantRefScalarCount", "CreatedAtUtc", "HeadGenerationId", "HeadSequence")
            VALUES ({candidate.AuthorityLineageId}, {candidate.Provider}, {candidate.ProductId},
                    {candidate.LicenseSeatId}, {candidate.ProviderGrantRef}, {candidate.ProviderGrantRefScalarCount},
                    {candidate.LineageCreatedAtUtc}, {candidate.AuthorityGenerationId}, 0)
            """, cancellationToken);
        await InsertGenerationOnlyAsync(db, candidate, cancellationToken);
        return new(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
            candidate.AuthorityLineageId, candidate.AuthorityGenerationId);
    }

    /// <summary>Persists one refused terminal request/attempt inside the caller-owned transaction.</summary>
    internal async Task PersistRefusedResultInAmbientTransactionAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityRequest? request,
        RuntimeEnrollmentAuthorityAttempt attempt, CancellationToken cancellationToken)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned authority transaction is required.");
        if (request is not null) db.RuntimeEnrollmentAuthorityRequests.Add(request);
        db.RuntimeEnrollmentAuthorityAttempts.Add(attempt);
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Persists an accepted/exact terminal attempt after its immutable request result exists.</summary>
    internal async Task PersistAttemptInAmbientTransactionAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityAttempt attempt,
        CancellationToken cancellationToken)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned authority transaction is required.");
        db.RuntimeEnrollmentAuthorityAttempts.Add(attempt);
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Returns whether PostgreSQL requires a complete transaction retry.</summary>
    internal static bool IsRetryableTransactionFailure(PostgresException exception) =>
        exception.SqlState is PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.DeadlockDetected;

    /// <summary>Returns whether a 23505 names one exact persistence identity surface.</summary>
    internal static bool IsNamedPersistenceUniqueViolation(PostgresException exception) =>
        exception.SqlState == PostgresErrorCodes.UniqueViolation
        && exception.ConstraintName != null
        && PersistenceUniqueConstraintNames.Contains(exception.ConstraintName);

    /// <summary>
    /// Classifies SQLSTATE, exact ordinal constraint name, and one-based attempt number without reading
    /// exception messages. Attempts one and two retry recognized transient or named-unique failures;
    /// attempt three reserves a read-only classification only for named 23505 and propagates everything else.
    /// </summary>
    internal static RuntimeEnrollmentAuthorityRetryDecision DecideRetry(
        PostgresException exception, int attempt)
        => DecideRetry(exception.SqlState, exception.ConstraintName, attempt);

    /// <summary>Classifies raw PostgreSQL failure identity using ordinal constraint-name matching.</summary>
    internal static RuntimeEnrollmentAuthorityRetryDecision DecideRetry(
        string sqlState, string? constraintName, int attempt)
    {
        if (attempt is < 1 or > MaximumPersistenceAttempts)
            throw new ArgumentOutOfRangeException(nameof(attempt));
        if (sqlState is PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.DeadlockDetected)
            return attempt < MaximumPersistenceAttempts
                ? RuntimeEnrollmentAuthorityRetryDecision.Retry
                : RuntimeEnrollmentAuthorityRetryDecision.Propagate;
        if (sqlState != PostgresErrorCodes.UniqueViolation
            || constraintName == null
            || !PersistenceUniqueConstraintNames.Contains(constraintName))
            return RuntimeEnrollmentAuthorityRetryDecision.Propagate;
        return attempt < MaximumPersistenceAttempts
            ? RuntimeEnrollmentAuthorityRetryDecision.Retry
            : RuntimeEnrollmentAuthorityRetryDecision.AuthoritativeRead;
    }

    /// <summary>
    /// Maps the final authoritative read to exact, conflict, or bounded exhaustion. This helper is the
    /// only decision consumed after a final named 23505; absence can never become StructuralConflict.
    /// </summary>
    internal static RuntimeEnrollmentAuthorityFinalCollisionOutcome ClassifyFinalCollision(
        bool storedRequestFound, bool exactStoredResult) =>
        !storedRequestFound
            ? RuntimeEnrollmentAuthorityFinalCollisionOutcome.Exhausted
            : exactStoredResult
                ? RuntimeEnrollmentAuthorityFinalCollisionOutcome.ExactStoredResult
                : RuntimeEnrollmentAuthorityFinalCollisionOutcome.StructuralConflict;

    /// <summary>
    /// Rejects payload/statement sizes outside 1..2895 and 1..3569, malformed digests, a sequence
    /// outside the JSON-safe lineage domain, or a genesis/predecessor mismatch. Exact strings and bytes
    /// are inspected without repair.
    /// </summary>
    internal static void ValidatePersistenceCandidate(
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate)
    {
        if (candidate.CanonicalPayloadUtf8.Length is < 1 or > MaximumCanonicalPayloadBytes
            || candidate.SignedStatementUtf8.Length is < 1 or > MaximumSignedStatementBytes
            || !IsLowerHexDigest(candidate.RequestDigest)
            || !IsLowerHexDigest(candidate.AuthorityDigest)
            || !RuntimeEnrollmentLineageSequence.TryCreate(candidate.Sequence, out _)
            || (candidate.Sequence == 0) != (candidate.PreviousGenerationId == null))
            throw new ArgumentException("The frozen Runtime Enrollment authority candidate is outside storage bounds.");
    }

    /// <summary>Returns true only for exactly 64 ordinal lowercase ASCII hexadecimal characters.</summary>
    internal static bool IsLowerHexDigest(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>
    /// Acquires the deterministic genesis tuple advisory lock using exact byte lengths and opaque values.
    /// Hash collisions are tolerated because subsequent relational rereads remain authoritative.
    /// </summary>
    private static async Task AcquireTupleLockAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken) =>
        await ExecuteNonQueryAsync(db, """
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
                'runtime-enrollment-v2:tuple:'
                || octet_length(@provider)::text || ':' || @provider || ':'
                || @productId || ':'
                || octet_length(@grantRef)::text || ':' || @grantRef || ':'
                || @seatId, 999831));
            """, cancellationToken,
            new NpgsqlParameter("provider", candidate.Provider),
            new NpgsqlParameter("productId", candidate.ProductId.ToString("D")),
            new NpgsqlParameter("grantRef", candidate.ProviderGrantRef),
            new NpgsqlParameter("seatId", candidate.LicenseSeatId.ToString("D")));

    /// <summary>Acquires the deterministic successor lineage advisory lock before any authoritative reread.</summary>
    private static async Task AcquireLineageLockAsync(
        LicenseDbContext db, Guid lineageId, CancellationToken cancellationToken) =>
        await ExecuteNonQueryAsync(db, """
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
                'runtime-enrollment-v2:lineage:' || @lineageId, 999831));
            """, cancellationToken, new NpgsqlParameter("lineageId", lineageId.ToString("D")));

    /// <summary>
    /// Inserts lineage, genesis generation, and request in the current transaction; the deferred head FK
    /// makes the cycle committable only when all three immutable rows are coherent.
    /// </summary>
    private static async Task InsertGenesisAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken)
    {
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                ("AuthorityLineageId", "Provider", "ProductId", "LicenseSeatId", "ProviderGrantRef",
                 "ProviderGrantRefScalarCount", "CreatedAtUtc", "HeadGenerationId", "HeadSequence")
            VALUES ({candidate.AuthorityLineageId}, {candidate.Provider}, {candidate.ProductId},
                    {candidate.LicenseSeatId}, {candidate.ProviderGrantRef}, {candidate.ProviderGrantRefScalarCount},
                    {candidate.LineageCreatedAtUtc}, {candidate.AuthorityGenerationId}, 0)
            """, cancellationToken);
        await InsertGenerationAndRequestAsync(db, candidate, cancellationToken);
    }

    /// <summary>Inserts opaque generation bytes and the corresponding immutable ACCEPTED request atomically.</summary>
    private static async Task InsertGenerationAndRequestAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken)
    {
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeEnrollmentAuthorityGenerations"
                ("AuthorityGenerationId", "AuthorityLineageId", "Sequence", "PreviousGenerationId",
                 "RequestId", "CanonicalPayloadUtf8", "SignedStatementUtf8", "AuthorityDigest",
                 "SignatureAlgorithm", "SignatureKeyId", "SignatureValue", "OccurredAtUtc", "CreatedAtUtc")
            VALUES ({candidate.AuthorityGenerationId}, {candidate.AuthorityLineageId}, {candidate.Sequence},
                    {candidate.PreviousGenerationId}, {candidate.RequestId}, {candidate.CanonicalPayloadUtf8},
                    {candidate.SignedStatementUtf8}, {candidate.AuthorityDigest},
                    {candidate.SignatureAlgorithm}, {candidate.SignatureKeyId}, {candidate.SignatureValue},
                    {candidate.OccurredAtUtc}, {candidate.CreatedAtUtc})
            """, cancellationToken);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeEnrollmentAuthorityRequests"
                ("RequestId", "RequestDigest", "AuthorityLineageId", "AuthorityGenerationId", "ResultCode",
                 "ErrorCode", "HttpStatusCode", "CreatedAtUtc", "CompletedAtUtc", "ExactResponseUtf8")
            VALUES ({candidate.RequestId}, {candidate.RequestDigest}, {candidate.AuthorityLineageId},
                     {candidate.AuthorityGenerationId}, 'ACCEPTED', NULL, 200, {candidate.CreatedAtUtc},
                    {candidate.CreatedAtUtc}, {candidate.SignedStatementUtf8})
            """, cancellationToken);
    }

    /// <summary>Inserts only immutable generation bytes for the dedicated composite recovery ledger.</summary>
    private static async Task InsertGenerationOnlyAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken) =>
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."RuntimeEnrollmentAuthorityGenerations"
                ("AuthorityGenerationId", "AuthorityLineageId", "Sequence", "PreviousGenerationId",
                 "RequestId", "CanonicalPayloadUtf8", "SignedStatementUtf8", "AuthorityDigest",
                 "SignatureAlgorithm", "SignatureKeyId", "SignatureValue", "OccurredAtUtc", "CreatedAtUtc")
            VALUES ({candidate.AuthorityGenerationId}, {candidate.AuthorityLineageId}, 0, NULL,
                    {candidate.RequestId}, {candidate.CanonicalPayloadUtf8}, {candidate.SignedStatementUtf8},
                    {candidate.AuthorityDigest}, {candidate.SignatureAlgorithm}, {candidate.SignatureKeyId},
                    {candidate.SignatureValue}, {candidate.OccurredAtUtc}, {candidate.CreatedAtUtc})
            """, cancellationToken);

    /// <summary>Loads immutable companions and classifies complete stored equality.</summary>
    private static async Task<RuntimeEnrollmentAuthorityPersistenceResult> ClassifyStoredResultAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        RuntimeEnrollmentAuthorityRequest request,
        CancellationToken cancellationToken)
    {
        var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleOrDefaultAsync(item =>
                item.AuthorityGenerationId == request.AuthorityGenerationId, cancellationToken);
        var lineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleOrDefaultAsync(item =>
                item.AuthorityLineageId == candidate.AuthorityLineageId, cancellationToken);
        var status = ClassifyStoredResult(request, lineage, generation, candidate);
        return status == RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult
            ? new(status,
                candidate.AuthorityLineageId, candidate.AuthorityGenerationId)
            : Conflict(candidate);
    }

    /// <summary>
    /// Performs the sole read-only authoritative classification after the final named 23505 rollback.
    /// Immutable request/generation rows make a found result safe to classify without another write lock;
    /// absence is an explicit bounded failure rather than an invented conflict.
    /// </summary>
    private static async Task<RuntimeEnrollmentAuthorityPersistenceResult> ClassifyAfterFinalCollisionAsync(
        LicenseDbContext db,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate,
        CancellationToken cancellationToken)
    {
        var request = await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
            .SingleOrDefaultAsync(item => item.RequestId == candidate.RequestId, cancellationToken);
        if (ClassifyFinalCollision(request != null, exactStoredResult: false)
            == RuntimeEnrollmentAuthorityFinalCollisionOutcome.Exhausted)
            throw new RuntimeEnrollmentAuthorityPersistenceExhaustedException();

        var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleOrDefaultAsync(item =>
                item.AuthorityGenerationId == request!.AuthorityGenerationId, cancellationToken);
        var lineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleOrDefaultAsync(item =>
                item.AuthorityLineageId == candidate.AuthorityLineageId, cancellationToken);
        return ClassifyFinalCollision(
                storedRequestFound: true,
                StoredResultEquals(request!, lineage, generation, candidate))
            == RuntimeEnrollmentAuthorityFinalCollisionOutcome.ExactStoredResult
                ? new(RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult,
                    candidate.AuthorityLineageId, candidate.AuthorityGenerationId)
                : Conflict(candidate);
    }

    /// <summary>Compares every immutable request, lineage, and generation field exactly and ordinally.</summary>
    internal static bool StoredResultEquals(
        RuntimeEnrollmentAuthorityRequest request,
        RuntimeEnrollmentAuthorityLineage? lineage,
        RuntimeEnrollmentAuthorityGeneration? generation,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        request.RequestId == candidate.RequestId
        && string.Equals(request.RequestDigest, candidate.RequestDigest, StringComparison.Ordinal)
        && request.AuthorityGenerationId == candidate.AuthorityGenerationId
        && request.AuthorityLineageId == candidate.AuthorityLineageId
        && string.Equals(request.ResultCode, "ACCEPTED", StringComparison.Ordinal)
        && request.ErrorCode is null
        && request.HttpStatusCode == StatusCodes.Status200OK
        && request.CreatedAtUtc == candidate.CreatedAtUtc
        && request.CompletedAtUtc == candidate.CreatedAtUtc
        && request.ExactResponseUtf8.AsSpan().SequenceEqual(candidate.SignedStatementUtf8)
        && lineage != null && LineageEquals(lineage, candidate)
        && generation != null && GenerationEquals(generation, candidate);

    /// <summary>Returns ExactStoredResult only for complete equality; every proven divergence is StructuralConflict.</summary>
    internal static RuntimeEnrollmentAuthorityPersistenceStatus ClassifyStoredResult(
        RuntimeEnrollmentAuthorityRequest request,
        RuntimeEnrollmentAuthorityLineage? lineage,
        RuntimeEnrollmentAuthorityGeneration? generation,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        StoredResultEquals(request, lineage, generation, candidate)
            ? RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult
            : RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict;

    /// <summary>Compares immutable lineage identity fields without normalizing opaque strings.</summary>
    internal static bool LineageEquals(
        RuntimeEnrollmentAuthorityLineage lineage,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        lineage.AuthorityLineageId == candidate.AuthorityLineageId
        && string.Equals(lineage.Provider, candidate.Provider, StringComparison.Ordinal)
        && lineage.ProductId == candidate.ProductId
        && lineage.LicenseSeatId == candidate.LicenseSeatId
        && string.Equals(lineage.ProviderGrantRef, candidate.ProviderGrantRef, StringComparison.Ordinal)
        && lineage.ProviderGrantRefScalarCount == candidate.ProviderGrantRefScalarCount
        && lineage.CreatedAtUtc == candidate.LineageCreatedAtUtc;

    /// <summary>Compares every immutable generation field, including both opaque byte arrays.</summary>
    internal static bool GenerationEquals(
        RuntimeEnrollmentAuthorityGeneration generation,
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        generation.AuthorityGenerationId == candidate.AuthorityGenerationId
        && generation.AuthorityLineageId == candidate.AuthorityLineageId
        && generation.Sequence == candidate.Sequence
        && generation.PreviousGenerationId == candidate.PreviousGenerationId
        && generation.RequestId == candidate.RequestId
        && generation.CanonicalPayloadUtf8.AsSpan().SequenceEqual(candidate.CanonicalPayloadUtf8)
        && generation.SignedStatementUtf8.AsSpan().SequenceEqual(candidate.SignedStatementUtf8)
        && string.Equals(generation.AuthorityDigest, candidate.AuthorityDigest, StringComparison.Ordinal)
        && string.Equals(generation.SignatureAlgorithm, candidate.SignatureAlgorithm, StringComparison.Ordinal)
        && string.Equals(generation.SignatureKeyId, candidate.SignatureKeyId, StringComparison.Ordinal)
        && string.Equals(generation.SignatureValue, candidate.SignatureValue, StringComparison.Ordinal)
        && generation.OccurredAtUtc == candidate.OccurredAtUtc
        && generation.CreatedAtUtc == candidate.CreatedAtUtc;

    /// <summary>Builds the Created result after the transaction has committed successfully.</summary>
    private static RuntimeEnrollmentAuthorityPersistenceResult Created(
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        new(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
            candidate.AuthorityLineageId, candidate.AuthorityGenerationId);

    /// <summary>Builds StructuralConflict only after an authoritative read or CAS proves divergence.</summary>
    private static RuntimeEnrollmentAuthorityPersistenceResult Conflict(
        RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        new(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
            candidate.AuthorityLineageId, candidate.AuthorityGenerationId);

    /// <summary>
    /// Converts a CAS row count into Created or StructuralConflict; counts above one violate the unique
    /// lineage target invariant and therefore fail explicitly.
    /// </summary>
    internal static RuntimeEnrollmentAuthorityPersistenceStatus ClassifyCasRowCount(int affected) => affected switch
    {
        0 => RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
        1 => RuntimeEnrollmentAuthorityPersistenceStatus.Created,
        _ => throw new InvalidOperationException("A lineage head CAS affected more than one row.")
    };

    public async Task<RuntimeAuthorityLease> AcquireAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default) =>
        await AcquireCoreAsync(db, bindingId, globalMutation: false, cancellationToken);

    public async Task<RuntimeAuthorityLease> AcquireMutationAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default) =>
        await AcquireCoreAsync(db, bindingId, globalMutation: true, cancellationToken);

    private async Task<RuntimeAuthorityLease> AcquireCoreAsync(
        LicenseDbContext db,
        Guid bindingId,
        bool globalMutation,
        CancellationToken cancellationToken)
    {
        EnsureEnabledNpgsql(db);
        var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        try
        {
            await ExecuteNonQueryAsync(db,
                $"SET LOCAL lock_timeout = '{_options.LockTimeoutMilliseconds}ms'; " +
                $"SET LOCAL statement_timeout = '{_options.StatementTimeoutMilliseconds}ms';",
                cancellationToken);
            await ExecuteNonQueryAsync(db, globalMutation
                ? "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);"
                : "SELECT pg_catalog.pg_advisory_xact_lock_shared(999831, 1);", cancellationToken);

            var authorityEpoch = await ExecuteScalarAsync<long>(db,
                "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;",
                cancellationToken);
            await ExecuteNonQueryAsync(db,
                "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(@bindingId, 999831));",
                cancellationToken,
                new NpgsqlParameter("bindingId", bindingId.ToString("D")));
            return new RuntimeAuthorityLease(transaction, authorityEpoch);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            throw;
        }
    }

    public async Task ValidateInfrastructureAsync(CancellationToken cancellationToken = default)
    {
        if (_options.Mode == "off")
            return;
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        EnsureEnabledNpgsql(db);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
            await connection.OpenAsync(cancellationToken);

        var singletonCount = await ScalarStandaloneAsync<long>(connection, """
            SELECT count(*)
            FROM public."RuntimeEnrollmentAuthorityStates"
            WHERE "Id" = 1 AND "Epoch" >= 0;
            """, cancellationToken);
        if (singletonCount != 1)
            throw InvalidInfrastructure();

        var triggerRows = await QueryStandaloneAsync(connection, """
            SELECT c.relname || '|' || t.tgname || '|' || t.tgtype::text || '|'
                || (t.tgfoid = 'public.runtime_enrollment_bump_authority_epoch()'::regprocedure)::text || '|'
                || pg_catalog.octet_length(t.tgargs)::text || '|'
                || COALESCE((
                    SELECT string_agg(a.attname, ',' ORDER BY attrs.ordinality)
                    FROM unnest(t.tgattr::smallint[]) WITH ORDINALITY attrs(attnum, ordinality)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid = t.tgrelid AND a.attnum = attrs.attnum
                ), '')
            FROM pg_catalog.pg_trigger t
            JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND NOT t.tgisinternal
              AND c.relname = ANY(@tables)
              AND pg_catalog.starts_with(t.tgname, 'trg_runtime_authority_')
              AND t.tgenabled = 'O'
            ORDER BY c.relname, t.tgname;
            """, cancellationToken, new NpgsqlParameter("tables", ProtectedTables.Keys.ToArray()));
        foreach (var (table, updateColumns) in ProtectedTables)
        {
            var stem = table.ToLowerInvariant();
            var expected = new HashSet<string>(StringComparer.Ordinal)
            {
                $"{table}|trg_runtime_authority_{stem}_insert|6|true|0|",
                $"{table}|trg_runtime_authority_{stem}_update|18|true|0|{string.Join(',', updateColumns)}",
                $"{table}|trg_runtime_authority_{stem}_delete|10|true|0|",
                $"{table}|trg_runtime_authority_{stem}_truncate|34|true|0|"
            };
            if (!expected.SetEquals(triggerRows.Where(row => row.StartsWith(table + '|', StringComparison.Ordinal))))
                throw InvalidInfrastructure();
        }

        var hardening = await ScalarStandaloneAsync<bool>(connection, """
            SELECT p.prosecdef
               AND NOT r.rolcanlogin
               AND p.proacl IS NOT NULL
               AND NOT pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE')
               AND NOT pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
               AND NOT current_role = r.rolname
               AND NOT pg_catalog.pg_has_role(current_user, r.rolname, 'MEMBER')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'INSERT')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'UPDATE')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'DELETE')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'TRUNCATE')
               AND pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'SELECT')
               AND (
                   SELECT owner_role.rolname
                   FROM pg_catalog.pg_class owner_table
                   JOIN pg_catalog.pg_namespace owner_ns ON owner_ns.oid = owner_table.relnamespace
                   JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = owner_table.relowner
                   WHERE owner_ns.nspname = 'public'
                     AND owner_table.relname = 'RuntimeEnrollmentAuthorityStates'
               ) = 'softlicence_runtime_authority_owner'
               AND NOT EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = 'public'
                     AND c.relname = ANY(@tables)
                     AND pg_catalog.pg_get_userbyid(c.relowner) = current_role)
               AND pg_catalog.pg_get_function_result(p.oid) = 'trigger'
               AND p.pronargs = 0
               AND p.proargtypes = ''::oidvector
               AND pg_catalog.regexp_replace(p.prosrc, '[[:space:]]', '', 'g')
                   = pg_catalog.regexp_replace(@source, '[[:space:]]', '', 'g')
               AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']::text[]
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
            WHERE n.nspname = 'public'
              AND p.oid = 'public.runtime_enrollment_bump_authority_epoch()'::regprocedure
              AND r.rolname = 'softlicence_runtime_authority_owner';
            """, cancellationToken,
            new NpgsqlParameter("tables", ProtectedTables.Keys.ToArray()),
            new NpgsqlParameter("source", AuthorityFunctionSource));
        if (!hardening)
            throw InvalidInfrastructure();

        if (_options.AuthorityGenerationV2.Mode == "enabled")
        {
            var v2SurfaceCount = await ScalarStandaloneAsync<long>(connection, """
                SELECT count(*)
                FROM (
                    SELECT 'table:attempts' WHERE to_regclass('public."RuntimeEnrollmentAuthorityAttempts"') IS NOT NULL
                    UNION ALL SELECT 'trigger:attempt-update-delete' WHERE EXISTS (
                        SELECT 1 FROM pg_catalog.pg_trigger
                        WHERE tgrelid = 'public."RuntimeEnrollmentAuthorityAttempts"'::regclass
                          AND tgname = 'trg_re_authority_attempts_immutable' AND tgenabled = 'O')
                    UNION ALL SELECT 'trigger:attempt-truncate' WHERE EXISTS (
                        SELECT 1 FROM pg_catalog.pg_trigger
                        WHERE tgrelid = 'public."RuntimeEnrollmentAuthorityAttempts"'::regclass
                          AND tgname = 'trg_re_authority_attempts_no_truncate' AND tgenabled = 'O')
                    UNION ALL SELECT 'trigger:request-update-delete' WHERE EXISTS (
                        SELECT 1 FROM pg_catalog.pg_trigger
                        WHERE tgrelid = 'public."RuntimeEnrollmentAuthorityRequests"'::regclass
                          AND tgname = 'trg_runtime_enrollment_authority_requests_immutable' AND tgenabled = 'O')
                    UNION ALL SELECT 'trigger:request-truncate' WHERE EXISTS (
                        SELECT 1 FROM pg_catalog.pg_trigger
                        WHERE tgrelid = 'public."RuntimeEnrollmentAuthorityRequests"'::regclass
                          AND tgname = 'trg_runtime_enrollment_authority_requests_no_truncate' AND tgenabled = 'O')
                    UNION ALL SELECT 'constraint:attempt-shape' WHERE EXISTS (
                        SELECT 1 FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'public."RuntimeEnrollmentAuthorityAttempts"'::regclass
                          AND conname = 'CK_REAuthorityAttempts_TerminalShape')
                    UNION ALL SELECT 'constraint:request-shape' WHERE EXISTS (
                        SELECT 1 FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'public."RuntimeEnrollmentAuthorityRequests"'::regclass
                          AND conname = 'CK_REAuthorityRequests_TerminalShape')
                ) AS required_surface;
                """, cancellationToken);
            if (v2SurfaceCount != 7)
                throw InvalidInfrastructure();
        }
    }

    private void EnsureEnabledNpgsql(LicenseDbContext db)
    {
        if (_options.Mode != "enabled" || !db.Database.IsNpgsql())
            throw InvalidInfrastructure();
    }

    private static async Task ExecuteNonQueryAsync(
        LicenseDbContext db,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<T> ExecuteScalarAsync<T>(
        LicenseDbContext db,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is T typed ? typed : (T)Convert.ChangeType(value!, typeof(T));
    }

    private static async Task<T> ScalarStandaloneAsync<T>(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        if (value == null || value is DBNull)
            throw InvalidInfrastructure();
        return value is T typed ? typed : (T)Convert.ChangeType(value, typeof(T));
    }

    private static async Task<IReadOnlyList<string>> QueryStandaloneAsync(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<string>();
        while (await reader.ReadAsync(cancellationToken))
            rows.Add(reader.GetString(0));
        return rows;
    }

    private static InvalidOperationException InvalidInfrastructure() =>
        new("Runtime enrollment enabled infrastructure validation failed.");
}

public sealed class RuntimeEnrollmentStartupValidator(
    IRuntimeEnrollmentAuthorityService authority,
    IOptions<RuntimeEnrollmentOptions> options) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        options.Value.Mode == "enabled" || options.Value.AuthorityGenerationV2.Mode == "enabled"
            ? authority.ValidateInfrastructureAsync(cancellationToken)
            : Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>Signals that a losing write invalidated the complete authority transaction.</summary>
internal sealed class RuntimeEnrollmentAuthorityTransactionInvalidatedException : InvalidOperationException
{
    /// <summary>Creates the rollback-only signal consumed by the outer retry envelope.</summary>
    internal RuntimeEnrollmentAuthorityTransactionInvalidatedException()
        : base("The Runtime Enrollment authority transaction requires rollback.") { }
}

/// <summary>Names the effective phases advanced by the production v2 coordinator.</summary>
internal enum RuntimeEnrollmentAuthorityIssuancePhase
{
    /// <summary>Exact request parsing completed without candidate allocation.</summary>
    Parsed,
    /// <summary>Request and attempt locks were acquired in that order.</summary>
    ReplayLocks,
    /// <summary>Authoritative replay was resolved.</summary>
    ReplayResolved,
    /// <summary>The tuple or lineage/head was locked and resolved.</summary>
    IdentityResolved,
    /// <summary>Authoritative business evidence was read.</summary>
    EvidenceResolved,
    /// <summary>Key lifecycle and recovery evidence were validated.</summary>
    LifecycleValidated,
    /// <summary>The final payload was signed.</summary>
    Signed,
    /// <summary>Immutable authority state was persisted.</summary>
    Persisted,
    /// <summary>The terminal attempt was persisted.</summary>
    AttemptStored
}

/// <summary>Rejects omitted, duplicated, permuted, or post-terminal issuance phases.</summary>
internal sealed class RuntimeEnrollmentAuthorityIssuanceFlow
{
    private static readonly RuntimeEnrollmentAuthorityIssuancePhase[] Expected =
    [
        RuntimeEnrollmentAuthorityIssuancePhase.Parsed,
        RuntimeEnrollmentAuthorityIssuancePhase.ReplayLocks,
        RuntimeEnrollmentAuthorityIssuancePhase.ReplayResolved,
        RuntimeEnrollmentAuthorityIssuancePhase.IdentityResolved,
        RuntimeEnrollmentAuthorityIssuancePhase.EvidenceResolved,
        RuntimeEnrollmentAuthorityIssuancePhase.LifecycleValidated,
        RuntimeEnrollmentAuthorityIssuancePhase.Signed,
        RuntimeEnrollmentAuthorityIssuancePhase.Persisted,
        RuntimeEnrollmentAuthorityIssuancePhase.AttemptStored
    ];
    private int next;

    /// <summary>Advances the same closed phase mechanism consumed by production.</summary>
    /// <param name="phase">The phase just completed.</param>
    /// <exception cref="InvalidOperationException">The phase is not the next exact phase.</exception>
    internal void Advance(RuntimeEnrollmentAuthorityIssuancePhase phase)
    {
        if (next >= Expected.Length || Expected[next] != phase)
            throw new InvalidOperationException($"Invalid Runtime Enrollment issuance phase: {phase}.");
        next++;
    }

    /// <summary>Allows terminal replay only immediately after replay resolution.</summary>
    internal void CompleteReplay()
    {
        if (next != 3) throw new InvalidOperationException("Replay is not resolved.");
        next = Expected.Length;
    }
}

[Flags]
internal enum RuntimeEnrollmentAuthorityLeaf
{
    /// <summary>No payload leaf changes.</summary>
    None = 0,
    /// <summary>The release version changed ordinally.</summary>
    ReleaseVersion = 1 << 0,
    /// <summary>The approved artifact-set digest changed ordinally.</summary>
    ReleaseArtifact = 1 << 1,
    /// <summary>The binding identifier changed ordinally.</summary>
    BindingId = 1 << 2,
    /// <summary>The hardware digest changed ordinally.</summary>
    Hardware = 1 << 3,
    /// <summary>The enrollment identifier changed ordinally.</summary>
    EnrollmentId = 1 << 4,
    /// <summary>The enrollment state changed ordinally.</summary>
    EnrollmentState = 1 << 5,
    /// <summary>The enrollment issue instant changed ordinally.</summary>
    IssuedAt = 1 << 6,
    /// <summary>The enrollment expiry instant changed ordinally.</summary>
    ExpiresAt = 1 << 7,
    /// <summary>The authority signing key identifier changed ordinally.</summary>
    AuthorityKeyId = 1 << 8,
    /// <summary>The security epoch changed.</summary>
    SecurityEpoch = 1 << 9,
    /// <summary>The installation identifier changed ordinally.</summary>
    InstallationId = 1 << 10,
    /// <summary>The seat identifier changed ordinally.</summary>
    SeatId = 1 << 11,
    /// <summary>Every contract leaf changed.</summary>
    All = (1 << 12) - 1
}

/// <summary>Defines one immutable row of the canonical 13-row transition registry.</summary>
internal sealed record RuntimeEnrollmentAuthorityTransitionRule(
    string ReasonCode, string Kind, RuntimeEnrollmentAuthorityLeaf Allowed,
    RuntimeEnrollmentAuthorityLeaf Required, IReadOnlySet<string> Edges,
    IReadOnlyList<string> Evidence, string EvidenceFailure);

/// <summary>Owns exact authoritative evidence labels read under the authority transaction.</summary>
internal sealed class RuntimeEnrollmentAuthorityEvidence
{
    private readonly HashSet<string> labels;

    /// <summary>Copies exact labels without text repair or normalization.</summary>
    internal RuntimeEnrollmentAuthorityEvidence(IEnumerable<string> labels) =>
        this.labels = new(labels, StringComparer.Ordinal);

    /// <summary>Tests one exact evidence label ordinally.</summary>
    internal bool Contains(string label) => labels.Contains(label);

    /// <summary>Copies the snapshot and adds one item-2-owned cryptographic proof label.</summary>
    internal RuntimeEnrollmentAuthorityEvidence With(string label) => new(labels.Append(label));
}

/// <summary>Identifies the complete authority scope to which one business decision belongs.</summary>
/// <param name="ClientId">Exact authenticated client identifier.</param>
/// <param name="ProductId">Exact product UUID.</param>
/// <param name="BindingId">Exact binding UUID.</param>
/// <param name="EnrollmentId">Exact enrollment UUID.</param>
/// <param name="LicenseId">Exact license UUID.</param>
/// <param name="LineageRootSeatId">Immutable seat UUID that scopes the lineage root.</param>
/// <param name="RequestedCurrentSeatId">Exact current seat UUID requested by this generation.</param>
/// <param name="LineageId">Exact authority-lineage UUID.</param>
/// <param name="HeadGenerationId">Exact locked head UUID, or empty only for genesis.</param>
internal sealed record RuntimeEnrollmentAuthorityEvidenceScope(
    string ClientId, Guid ProductId, Guid BindingId, Guid EnrollmentId, Guid LicenseId,
    Guid LineageRootSeatId, Guid RequestedCurrentSeatId,
    Guid LineageId, Guid HeadGenerationId);

/// <summary>Classifies whether a requested generation represents live authority or terminal history.</summary>
internal enum RuntimeEnrollmentAuthorityResultClass
{
    /// <summary>The generation can participate in a later grant and therefore requires current B.</summary>
    Live,
    /// <summary>The generation records exact terminal history and cannot require or create a current assignment.</summary>
    Terminal
}

/// <summary>Returns transaction-scoped evidence together with the post-barrier provider time.</summary>
/// <param name="Evidence">Exact transition evidence bound to both lineage and requested seat scopes.</param>
/// <param name="AuthoritativeNowUtc">Fresh PostgreSQL time sampled after decisive waits.</param>
/// <param name="ScopeAuthorized">Whether A/P and, for live results, B match the requested scope.</param>
internal sealed record RuntimeEnrollmentAuthorityEvidenceResolution(
    RuntimeEnrollmentAuthorityEvidence Evidence,
    DateTimeOffset AuthoritativeNowUtc,
    bool ScopeAuthorized);

/// <summary>Associates one exact evidence label with the complete scope read from its authoritative row.</summary>
/// <param name="Label">Exact closed evidence label.</param>
/// <param name="Scope">Complete scope read under the authority transaction.</param>
internal sealed record RuntimeEnrollmentAuthorityScopedDecision(
    string Label, RuntimeEnrollmentAuthorityEvidenceScope Scope);

/// <summary>Returns the first closed transition diagnostic, or null after complete acceptance.</summary>
internal sealed record RuntimeEnrollmentAuthorityTransitionDecision(string? ErrorCode)
{
    /// <summary>Gets whether all closed registry rules passed.</summary>
    internal bool Accepted => ErrorCode is null;
}

/// <summary>Owns the single canonical transition registry and its deterministic evaluator.</summary>
internal static class RuntimeEnrollmentAuthorityTransitionPolicy
{
    private static readonly IReadOnlyList<RuntimeEnrollmentAuthorityTransitionRule> Rules =
    [
        R("INITIAL_ENROLLMENT", "genesis", RuntimeEnrollmentAuthorityLeaf.All,
            RuntimeEnrollmentAuthorityLeaf.All, ["none->pending", "none->active"],
            ["INITIAL_ENTITLEMENT"], "INITIAL_ENROLLMENT_NOT_AUTHORIZED"),
        R("APPROVED_RELEASE_ADVANCE", "release",
            RuntimeEnrollmentAuthorityLeaf.ReleaseVersion | RuntimeEnrollmentAuthorityLeaf.ReleaseArtifact,
            RuntimeEnrollmentAuthorityLeaf.ReleaseVersion | RuntimeEnrollmentAuthorityLeaf.ReleaseArtifact,
            [], ["APPROVED_ARTIFACT_SET"], "RELEASE_NOT_AUTHORIZED"),
        R("BINDING_REPLACEMENT", "binding",
            RuntimeEnrollmentAuthorityLeaf.BindingId | RuntimeEnrollmentAuthorityLeaf.Hardware,
            RuntimeEnrollmentAuthorityLeaf.BindingId | RuntimeEnrollmentAuthorityLeaf.Hardware,
            [], ["BINDING_REPLACEMENT_AUTHORITY", "ELIGIBLE_HARDWARE"], "BINDING_CHANGE_NOT_AUTHORIZED"),
        R("ENROLLMENT_ACTIVATED", "enrollment", RuntimeEnrollmentAuthorityLeaf.EnrollmentState,
            RuntimeEnrollmentAuthorityLeaf.EnrollmentState, ["pending->active"],
            ["ACTIVATION_PROOF"], "ENROLLMENT_ACTIVATION_NOT_AUTHORIZED"),
        R("ENROLLMENT_EXPIRED", "enrollment", RuntimeEnrollmentAuthorityLeaf.EnrollmentState,
            RuntimeEnrollmentAuthorityLeaf.EnrollmentState, ["active->expired"],
            ["AUTHORITATIVE_EXPIRY"], "ENROLLMENT_EXPIRY_NOT_AUTHORIZED"),
        R("ENROLLMENT_REPLACED", "enrollment",
            RuntimeEnrollmentAuthorityLeaf.EnrollmentId | RuntimeEnrollmentAuthorityLeaf.EnrollmentState
                | RuntimeEnrollmentAuthorityLeaf.IssuedAt | RuntimeEnrollmentAuthorityLeaf.ExpiresAt,
            RuntimeEnrollmentAuthorityLeaf.EnrollmentId | RuntimeEnrollmentAuthorityLeaf.EnrollmentState
                | RuntimeEnrollmentAuthorityLeaf.IssuedAt,
            ["expired->pending", "expired->active", "revoked->pending", "revoked->active"],
            ["REPLACEMENT_ELIGIBILITY"], "ENROLLMENT_REPLACEMENT_NOT_AUTHORIZED"),
        R("AUTHORITY_REVOKED", "revocation", RuntimeEnrollmentAuthorityLeaf.EnrollmentState,
            RuntimeEnrollmentAuthorityLeaf.EnrollmentState, ["pending->revoked", "active->revoked"],
            ["SIGNED_REVOCATION_DECISION"], "REVOCATION_NOT_AUTHORIZED"),
        R("SIGNING_KEY_ROTATED", "key_rotation",
            RuntimeEnrollmentAuthorityLeaf.AuthorityKeyId | RuntimeEnrollmentAuthorityLeaf.SecurityEpoch,
            RuntimeEnrollmentAuthorityLeaf.AuthorityKeyId | RuntimeEnrollmentAuthorityLeaf.SecurityEpoch,
            [], ["PREDECESSOR_KEY_SIGNATURE", "KEY_ROTATION_AUTHORIZATION"], "KEY_ROTATION_NOT_AUTHORIZED"),
        R("SECURITY_EPOCH_ADVANCED", "security_epoch", RuntimeEnrollmentAuthorityLeaf.SecurityEpoch,
            RuntimeEnrollmentAuthorityLeaf.SecurityEpoch, [], ["SECURITY_DECISION"], "SECURITY_EPOCH_NOT_AUTHORIZED"),
        R("INSTALLATION_REINSTALLED", "reinstall", RuntimeEnrollmentAuthorityLeaf.InstallationId,
            RuntimeEnrollmentAuthorityLeaf.InstallationId, [], ["REINSTALL_PROOF", "CURRENT_HEAD_PROOF"],
            "INSTALLATION_CHANGE_NOT_AUTHORIZED"),
        R("RECOVERY_AUTHORIZED", "recovery",
            RuntimeEnrollmentAuthorityLeaf.AuthorityKeyId | RuntimeEnrollmentAuthorityLeaf.SecurityEpoch,
            RuntimeEnrollmentAuthorityLeaf.AuthorityKeyId | RuntimeEnrollmentAuthorityLeaf.SecurityEpoch,
            ["pending->pending", "active->active", "expired->expired", "revoked->revoked"],
            ["SIGNED_RECOVERY_AUTHORITY", "CURRENT_HEAD_PROOF"], "RECOVERY_NOT_AUTHORIZED"),
        R("REPAIR_AUTHORIZED", "repair", RuntimeEnrollmentAuthorityLeaf.None,
            RuntimeEnrollmentAuthorityLeaf.None, [], ["REPAIR_PROOF"], "REPAIR_NOT_AUTHORIZED"),
        R("SEAT_REASSIGNED", "seat", RuntimeEnrollmentAuthorityLeaf.SeatId,
            RuntimeEnrollmentAuthorityLeaf.SeatId, [], ["SEAT_RELEASE_PROOF", "SEAT_ACQUISITION_PROOF"],
            "SEAT_CHANGE_NOT_AUTHORIZED")
    ];
    private static readonly IReadOnlyDictionary<string, RuntimeEnrollmentAuthorityTransitionRule> ByReason =
        Rules.ToDictionary(rule => rule.ReasonCode, StringComparer.Ordinal);

    /// <summary>Gets the exact canonical rows for exhaustive contract tests.</summary>
    internal static IReadOnlyList<RuntimeEnrollmentAuthorityTransitionRule> Registry => Rules;

    /// <summary>Returns the closed authorization failure owned by one registered transition.</summary>
    /// <param name="reasonCode">Exact transition reason.</param>
    /// <returns>The registered evidence failure, or the unknown-reason diagnostic.</returns>
    internal static string EvidenceFailure(string reasonCode) =>
        ByReason.TryGetValue(reasonCode, out var rule)
            ? rule.EvidenceFailure
            : "TRANSITION_REASON_UNKNOWN";

    /// <summary>
    /// Filters reason-owned decisions by the complete expected scope. Unknown labels, labels belonging to
    /// another reason, and cross-scope decisions are rejected without text repair.
    /// </summary>
    /// <param name="reasonCode">Exact canonical reason selecting the sole allowed evidence set.</param>
    /// <param name="expectedScope">Complete locked request scope.</param>
    /// <param name="decisions">Authoritative row decisions with their independently read scopes.</param>
    /// <returns>A defensive evidence set containing only exact reason-and-scope matches.</returns>
    internal static RuntimeEnrollmentAuthorityEvidence ResolveScopedEvidence(
        string reasonCode, RuntimeEnrollmentAuthorityEvidenceScope expectedScope,
        IEnumerable<RuntimeEnrollmentAuthorityScopedDecision> decisions)
    {
        if (!ByReason.TryGetValue(reasonCode, out var rule))
            return new([]);
        return new(decisions
            .Where(decision => decision.Scope == expectedScope
                && rule.Evidence.Contains(decision.Label, StringComparer.Ordinal))
            .Select(decision => decision.Label));
    }

    /// <summary>Validates pair and predecessor-ID shape before any durable refusal is created.</summary>
    internal static bool IsAllowed(RuntimeEnrollmentAuthorityRequestV2 request)
    {
        var genesis = request.Transition.Kind == "genesis";
        var ids = genesis
            ? request.ExpectedAuthorityLineageId is null && request.ExpectedCurrentGenerationId is null
                && request.ExpectedPredecessorGenerationId is null
            : request.ExpectedAuthorityLineageId is not null && request.ExpectedCurrentGenerationId is not null
                && request.ExpectedPredecessorGenerationId is not null
                && string.Equals(request.ExpectedCurrentGenerationId,
                    request.ExpectedPredecessorGenerationId, StringComparison.Ordinal);
        return ids && ByReason.TryGetValue(request.Transition.ReasonCode, out var rule)
            && string.Equals(rule.Kind, request.Transition.Kind, StringComparison.Ordinal);
    }

    /// <summary>Evaluates leaves, edges, chronology, progression, and exact evidence in canonical order.</summary>
    internal static RuntimeEnrollmentAuthorityTransitionDecision Evaluate(
        RuntimeEnrollmentAuthorityGenerationPayloadV2? previous,
        RuntimeEnrollmentAuthorityGenerationPayloadV2 current,
        RuntimeEnrollmentAuthorityEvidence evidence, DateTimeOffset authoritativeNowUtc)
    {
        if (!ByReason.TryGetValue(current.Transition.ReasonCode, out var rule))
            return new("TRANSITION_REASON_UNKNOWN");
        if (!string.Equals(rule.Kind, current.Transition.Kind, StringComparison.Ordinal))
            return new("TRANSITION_KIND_REASON_MISMATCH");
        if (!RuntimeEnrollmentLineageSequence.TryCreate(current.Sequence, out var currentSequence)
            || previous is not null
                && !RuntimeEnrollmentLineageSequence.TryCreate(previous.Sequence, out _))
            return new("GENERATION_SEQUENCE_INVALID");
        RuntimeEnrollmentLineageSequence previousSequence = default;
        if (previous is not null)
            RuntimeEnrollmentLineageSequence.TryCreate(previous.Sequence, out previousSequence);
        if (previous is null
            ? !currentSequence.IsGenesis || current.PreviousGenerationId is not null
            : !currentSequence.IsDirectSuccessorOf(previousSequence)
                || !string.Equals(current.PreviousGenerationId,
                    previous.AuthorityGenerationId, StringComparison.Ordinal))
            return new("GENERATION_SEQUENCE_INVALID");
        if (!RuntimeEnrollmentSecurityEpoch.TryCreate(current.Key.SecurityEpoch, out var currentSecurityEpoch)
            || previous is not null
                && !RuntimeEnrollmentSecurityEpoch.TryCreate(previous.Key.SecurityEpoch, out _))
            return new("SECURITY_EPOCH_INVALID");
        RuntimeEnrollmentSecurityEpoch previousSecurityEpoch = default;
        if (previous is not null)
            RuntimeEnrollmentSecurityEpoch.TryCreate(previous.Key.SecurityEpoch, out previousSecurityEpoch);
        var changed = Changes(previous, current);
        if (previous is not null)
        {
            var key = changed.HasFlag(RuntimeEnrollmentAuthorityLeaf.AuthorityKeyId);
            var epoch = changed.HasFlag(RuntimeEnrollmentAuthorityLeaf.SecurityEpoch);
            if (key && rule.ReasonCode is not ("SIGNING_KEY_ROTATED" or "RECOVERY_AUTHORIZED"))
                return new("KEY_ROTATION_REQUIRED");
            if (rule.ReasonCode == "SIGNING_KEY_ROTATED" && key
                && (!epoch || !currentSecurityEpoch.IsDirectSuccessorOf(previousSecurityEpoch)))
                return new("KEY_EPOCH_MISMATCH");
            if (rule.ReasonCode == "SIGNING_KEY_ROTATED" && !key && epoch)
                return new("KEY_ROTATION_REQUIRED");
            if (rule.ReasonCode == "RECOVERY_AUTHORIZED"
                && (!key || !epoch || !currentSecurityEpoch.IsDirectSuccessorOf(previousSecurityEpoch)))
                return new("RECOVERY_KEY_EPOCH_MISMATCH");
            if (epoch && currentSecurityEpoch.Value > previousSecurityEpoch.Value
                && !currentSecurityEpoch.IsDirectSuccessorOf(previousSecurityEpoch))
                return new("SECURITY_EPOCH_STEP_INVALID");
            if (previous.Enrollment.EnrollmentId == current.Enrollment.EnrollmentId
                && previous.Enrollment.State is "expired" or "revoked"
                && current.Enrollment.State == "active") return new("ENROLLMENT_TERMINAL");
        }
        if ((changed & ~rule.Allowed) != RuntimeEnrollmentAuthorityLeaf.None)
            return new(rule.ReasonCode == "REPAIR_AUTHORIZED"
                ? "REPAIR_SCOPE_VIOLATION" : "TRANSITION_SCOPE_VIOLATION");
        if ((changed & rule.Required) != rule.Required)
            return new("TRANSITION_REQUIRED_CHANGE_MISSING");
        var edge = (previous?.Enrollment.State ?? "none") + "->" + current.Enrollment.State;
        if (rule.Edges.Count == 0
            ? previous is not null && previous.Enrollment.State != current.Enrollment.State
            : !rule.Edges.Contains(edge))
            return new("ENROLLMENT_TRANSITION_INVALID");
        var occurred = Utc(current.Transition.OccurredAtUtc);
        if (previous is not null && occurred <= Utc(previous.Transition.OccurredAtUtc))
            return new("TRANSITION_TIME_REGRESSION");
        if (occurred > authoritativeNowUtc.AddSeconds(120)) return new("TRANSITION_TIME_FUTURE");
        if (current.Enrollment.ExpiresAtUtc is not null
            && Utc(current.Enrollment.ExpiresAtUtc) <= Utc(current.Enrollment.IssuedAtUtc))
            return new("ENROLLMENT_TIME_INVALID");
        if (previous is not null && currentSecurityEpoch.IsRegressionFrom(previousSecurityEpoch))
            return new("SECURITY_EPOCH_REGRESSION");
        if (rule.ReasonCode == "APPROVED_RELEASE_ADVANCE"
            && CompareRelease(current.Release.Version, previous!.Release.Version) <= 0)
            return new("RELEASE_REGRESSION");
        foreach (var label in rule.Evidence)
            if (!evidence.Contains(label)) return new(rule.EvidenceFailure);
        return new(null);
    }

    /// <summary>Compatibility helper using complete synthetic evidence for legacy pure tests.</summary>
    internal static bool HasExactPrimaryDelta(
        RuntimeEnrollmentAuthorityGenerationPayloadV2? previous,
        RuntimeEnrollmentAuthorityGenerationPayloadV2 current) =>
        Evaluate(previous, current, new(Rules.SelectMany(rule => rule.Evidence)),
            Utc(current.Transition.OccurredAtUtc)).Accepted;

    private static RuntimeEnrollmentAuthorityTransitionRule R(
        string reason, string kind, RuntimeEnrollmentAuthorityLeaf allowed,
        RuntimeEnrollmentAuthorityLeaf required, string[] edges, string[] evidence, string failure) =>
        new(reason, kind, allowed, required, new HashSet<string>(edges, StringComparer.Ordinal), evidence, failure);

    private static RuntimeEnrollmentAuthorityLeaf Changes(
        RuntimeEnrollmentAuthorityGenerationPayloadV2? previous,
        RuntimeEnrollmentAuthorityGenerationPayloadV2 current)
    {
        if (previous is null) return RuntimeEnrollmentAuthorityLeaf.All;
        var value = RuntimeEnrollmentAuthorityLeaf.None;
        Add(previous.Release.Version, current.Release.Version, RuntimeEnrollmentAuthorityLeaf.ReleaseVersion);
        Add(previous.Release.ArtifactSetDigest, current.Release.ArtifactSetDigest, RuntimeEnrollmentAuthorityLeaf.ReleaseArtifact);
        Add(previous.Binding.BindingId, current.Binding.BindingId, RuntimeEnrollmentAuthorityLeaf.BindingId);
        Add(previous.Binding.HardwareIdDigest, current.Binding.HardwareIdDigest, RuntimeEnrollmentAuthorityLeaf.Hardware);
        Add(previous.Enrollment.EnrollmentId, current.Enrollment.EnrollmentId, RuntimeEnrollmentAuthorityLeaf.EnrollmentId);
        Add(previous.Enrollment.State, current.Enrollment.State, RuntimeEnrollmentAuthorityLeaf.EnrollmentState);
        Add(previous.Enrollment.IssuedAtUtc, current.Enrollment.IssuedAtUtc, RuntimeEnrollmentAuthorityLeaf.IssuedAt);
        Add(previous.Enrollment.ExpiresAtUtc, current.Enrollment.ExpiresAtUtc, RuntimeEnrollmentAuthorityLeaf.ExpiresAt);
        Add(previous.Key.AuthorityKeyId, current.Key.AuthorityKeyId, RuntimeEnrollmentAuthorityLeaf.AuthorityKeyId);
        if (previous.Key.SecurityEpoch != current.Key.SecurityEpoch) value |= RuntimeEnrollmentAuthorityLeaf.SecurityEpoch;
        Add(previous.Installation.InstallationId, current.Installation.InstallationId, RuntimeEnrollmentAuthorityLeaf.InstallationId);
        Add(previous.Installation.SeatId, current.Installation.SeatId, RuntimeEnrollmentAuthorityLeaf.SeatId);
        return value;
        void Add(string? left, string? right, RuntimeEnrollmentAuthorityLeaf leaf)
        { if (!string.Equals(left, right, StringComparison.Ordinal)) value |= leaf; }
    }

    private static DateTimeOffset Utc(string value) => DateTimeOffset.ParseExact(
        value, "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static int CompareRelease(string left, string right)
    {
        static (long[] Core, string[] Pre) Parse(string value)
        {
            var parts = value.Split('+', 2)[0].Split('-', 2);
            return (parts[0].Split('.').Select(long.Parse).ToArray(),
                parts.Length == 1 ? [] : parts[1].Split('.'));
        }
        var l = Parse(left); var r = Parse(right);
        for (var i = 0; i < Math.Max(l.Core.Length, r.Core.Length); i++)
        {
            var c = (i < l.Core.Length ? l.Core[i] : 0).CompareTo(i < r.Core.Length ? r.Core[i] : 0);
            if (c != 0) return c;
        }
        if (l.Pre.Length == 0 || r.Pre.Length == 0)
            return l.Pre.Length == r.Pre.Length ? 0 : l.Pre.Length == 0 ? 1 : -1;
        for (var i = 0; i < Math.Max(l.Pre.Length, r.Pre.Length); i++)
        {
            if (i == l.Pre.Length) return -1;
            if (i == r.Pre.Length) return 1;
            var ln = long.TryParse(l.Pre[i], out var lv); var rn = long.TryParse(r.Pre[i], out var rv);
            var c = ln && rn ? lv.CompareTo(rv) : ln ? -1 : rn ? 1
                : string.Compare(l.Pre[i], r.Pre[i], StringComparison.Ordinal);
            if (c != 0) return c;
        }
        return 0;
    }
}

/// <summary>Closed request/attempt replay classification evaluated under exact advisory locks.</summary>
internal enum RuntimeEnrollmentAuthorityReplayDecision
{
    /// <summary>No terminal state exists.</summary>
    New,
    /// <summary>The exact attempt terminal state exists.</summary>
    ExactAttempt,
    /// <summary>The attempt ID is bound to different immutable input.</summary>
    AttemptIdReuse,
    /// <summary>The exact request terminal state exists.</summary>
    ExactRequest,
    /// <summary>The request ID is bound to a different canonical digest.</summary>
    RequestReplayDivergence
}

/// <summary>Pure replay state machine consumed by production and local concurrency tests.</summary>
internal static class RuntimeEnrollmentAuthorityReplayRules
{
    /// <summary>Classifies exact immutable identity without text repair.</summary>
    internal static RuntimeEnrollmentAuthorityReplayDecision Classify(
        RuntimeEnrollmentAuthorityAttempt? attempt, RuntimeEnrollmentAuthorityRequest? request,
        Guid requestId, string requestDigest)
    {
        if (attempt is not null)
            return attempt.RequestId == requestId
                && string.Equals(attempt.RequestDigest, requestDigest, StringComparison.Ordinal)
                ? RuntimeEnrollmentAuthorityReplayDecision.ExactAttempt
                : RuntimeEnrollmentAuthorityReplayDecision.AttemptIdReuse;
        if (request is null) return RuntimeEnrollmentAuthorityReplayDecision.New;
        return string.Equals(request.RequestDigest, requestDigest, StringComparison.Ordinal)
            ? RuntimeEnrollmentAuthorityReplayDecision.ExactRequest
            : RuntimeEnrollmentAuthorityReplayDecision.RequestReplayDivergence;
    }
}

/// <summary>
/// Immutable parsed request identity. It deliberately contains no allocated lineage/generation,
/// final payload, registry snapshot proof, private-key handle, or signature.
/// </summary>
internal sealed class RuntimeEnrollmentAuthorityV2Prepared
{
    /// <summary>
    /// Copies retry-stable authenticated and canonical request identity, including the exact seat
    /// scope that is revalidated against relational authority before persistence. A recovery
    /// finalization also carries the provider-issued expiry for the decisive post-barrier check.
    /// </summary>
    internal RuntimeEnrollmentAuthorityV2Prepared(
        string clientId, string transportKeyId, Guid attemptId, Guid requestId,
        Guid? expectedLineageId, Guid? previousId, Guid productId, Guid bindingId,
        Guid licenseSeatId,
        string provider, string grantRef, string requestDigest, DateTime occurredAtUtc,
        string? recoveryKeyId, string? recoverySignature,
        RuntimeEnrollmentAuthorityRequestV2 request,
        RuntimeEnrollmentAuthorityCryptography crypto,
        Guid? reservedGenerationId = null, string? reservedPayloadDigest = null,
        DateTime? recoveryPreparationExpiresAtUtc = null)
    {
        ClientId = clientId; TransportKeyId = transportKeyId; AttemptId = attemptId;
        RequestId = requestId; ExpectedLineageId = expectedLineageId; PreviousId = previousId;
        ProductId = productId; BindingId = bindingId; LicenseSeatId = licenseSeatId;
        Provider = provider; GrantRef = grantRef;
        RequestDigest = requestDigest; OccurredAtUtc = occurredAtUtc;
        RecoveryKeyId = recoveryKeyId; RecoverySignature = recoverySignature;
        Request = request; Crypto = crypto;
        ReservedGenerationId = reservedGenerationId;
        ReservedPayloadDigest = reservedPayloadDigest;
        RecoveryPreparationExpiresAtUtc = recoveryPreparationExpiresAtUtc;
    }

    /// <summary>Gets the exact authenticated S2S client identifier.</summary>
    internal string ClientId { get; }
    /// <summary>Gets the exact authenticated S2S transport key identifier.</summary>
    internal string TransportKeyId { get; }
    /// <summary>Gets the canonical transport attempt UUID.</summary>
    internal Guid AttemptId { get; }
    /// <summary>Gets the canonical semantic request UUID.</summary>
    internal Guid RequestId { get; }
    /// <summary>Gets null for genesis or the exact expected lineage UUID.</summary>
    internal Guid? ExpectedLineageId { get; }
    /// <summary>Gets null for genesis or the exact expected current/predecessor UUID.</summary>
    internal Guid? PreviousId { get; }
    /// <summary>Gets the exact product UUID.</summary>
    internal Guid ProductId { get; }
    /// <summary>Gets the exact binding UUID used by the outer lease.</summary>
    internal Guid BindingId { get; }
    /// <summary>Gets the canonical seat UUID requested for the authority and later verified relationally.</summary>
    internal Guid LicenseSeatId { get; }
    /// <summary>Gets the exact provider text.</summary>
    internal string Provider { get; }
    /// <summary>Gets the opaque grant reference without normalization.</summary>
    internal string GrantRef { get; }
    /// <summary>Gets the lowercase domain-separated canonical request digest.</summary>
    internal string RequestDigest { get; }
    /// <summary>Gets the exact requested occurrence instant.</summary>
    internal DateTime OccurredAtUtc { get; }
    /// <summary>Gets the detached recovery key identifier only for recovery.</summary>
    internal string? RecoveryKeyId { get; }
    /// <summary>Gets the detached recovery signature only for recovery.</summary>
    internal string? RecoverySignature { get; }
    /// <summary>Gets the strictly parsed, operation-owned closed request.</summary>
    internal RuntimeEnrollmentAuthorityRequestV2 Request { get; }
    /// <summary>Gets the item-2 parser rooted in the independently pinned registry authority.</summary>
    internal RuntimeEnrollmentAuthorityCryptography Crypto { get; }
    /// <summary>Gets the server-allocated successor UUID bound by a verified preparation token.</summary>
    internal Guid? ReservedGenerationId { get; }
    /// <summary>Gets the exact lowercase digest of the prepared canonical payload.</summary>
    internal string? ReservedPayloadDigest { get; }
    /// <summary>Gets the provider-issued recovery preparation expiry for post-barrier validation.</summary>
    internal DateTime? RecoveryPreparationExpiresAtUtc { get; }
}

/// <summary>Returns server-owned canonical recovery bytes and their short signed preparation token.</summary>
internal sealed class RuntimeEnrollmentAuthorityRecoveryPreparation
{
    private readonly byte[] payload;
    /// <summary>Copies the exact canonical payload and immutable token result.</summary>
    internal RuntimeEnrollmentAuthorityRecoveryPreparation(byte[] payload, string token, DateTime expiresAtUtc)
    { this.payload = [.. payload]; Token = token; ExpiresAtUtc = expiresAtUtc; }
    /// <summary>Gets a defensive copy of the exact bytes the recovery authority must sign.</summary>
    internal byte[] CanonicalPayloadUtf8 => [.. payload];
    /// <summary>Gets the short signed token binding the complete preparation scope.</summary>
    internal string Token { get; }
    /// <summary>Gets the exclusive UTC expiry of the preparation.</summary>
    internal DateTime ExpiresAtUtc { get; }
}

/// <summary>Closed claims signed by SoftLicence for one recovery finalization.</summary>
internal sealed class RuntimeEnrollmentAuthorityRecoveryPreparationClaims
{
    [System.Text.Json.Serialization.JsonPropertyName("clientId")] public required string ClientId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("transportKeyId")] public required string TransportKeyId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("attemptId")] public required string AttemptId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("requestId")] public required string RequestId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("lineageId")] public required string LineageId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("predecessorGenerationId")] public required string PredecessorGenerationId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("generationId")] public required string GenerationId { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("requestDigest")] public required string RequestDigest { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("payloadDigest")] public required string PayloadDigest { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("expiresAtUtc")] public required string ExpiresAtUtc { get; init; }
}

/// <summary>Contains the locked lineage identity and predecessor resolved before UUID allocation.</summary>
/// <param name="LineageId">Immutable lineage identifier.</param>
/// <param name="GenerationId">Reserved candidate generation identifier.</param>
/// <param name="PreviousGenerationId">Locked predecessor identifier, or null for genesis.</param>
/// <param name="Sequence">Monotonic generation sequence.</param>
/// <param name="LineageCreatedAtUtc">Persisted lineage creation time.</param>
/// <param name="LineageRootSeatId">Immutable root seat retained across a seat reassignment.</param>
/// <param name="Predecessor">Exact predecessor payload, or null for genesis.</param>
internal sealed record RuntimeEnrollmentAuthorityResolvedIdentity(
    Guid LineageId, Guid GenerationId, Guid? PreviousGenerationId,
    RuntimeEnrollmentLineageSequence Sequence,
    DateTime LineageCreatedAtUtc, Guid LineageRootSeatId,
    RuntimeEnrollmentAuthorityGenerationPayloadV2? Predecessor);

/// <summary>Freezes the three lifecycle outcomes consumed by the recovery branch.</summary>
/// <param name="Predecessor">Classification of the locked predecessor operational key.</param>
/// <param name="Successor">Classification of the requested successor operational key.</param>
/// <param name="Recovery">Classification of the detached recovery key.</param>
internal sealed record RuntimeEnrollmentAuthorityRecoveryLifecycleDecision(
    RuntimeEnrollmentAuthorityCryptography.KeyLifecycleClassification Predecessor,
    RuntimeEnrollmentAuthorityCryptography.KeyLifecycleClassification Successor,
    RuntimeEnrollmentAuthorityCryptography.KeyLifecycleClassification Recovery)
{
    /// <summary>Gets whether a compromised or revoked predecessor is replaced by a distinct active key.</summary>
    /// <param name="predecessorKeyId">Exact locked predecessor key identifier.</param>
    /// <param name="successorKeyId">Exact requested successor key identifier.</param>
    /// <returns>True only for the closed recovery lifecycle combination.</returns>
    internal bool Accepted(string predecessorKeyId, string successorKeyId) =>
        !string.Equals(predecessorKeyId, successorKeyId, StringComparison.Ordinal)
        && Predecessor.Outcome is RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Compromised
            or RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Revoked
        && Successor.Outcome == RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid
        && Recovery.Outcome == RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid;
}

/// <summary>
/// Coordinates exact parsing, replay-first locking, authoritative evidence, lifecycle, signing, and
/// ambient persistence. Transport nonce, transaction, commit, retry, and logging remain caller-owned.
/// </summary>
public sealed class RuntimeEnrollmentAuthorityV2Coordinator
{
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";
    private const int RecoveryPreparationLifetimeSeconds = 60;
    private readonly RuntimeEnrollmentAuthorityService authority;
    private readonly RuntimeEnrollmentOptions options;
    private readonly TimeProvider clock;

    /// <summary>Creates the internal coordinator from item 1, item 2, and trusted time.</summary>
    public RuntimeEnrollmentAuthorityV2Coordinator(
        RuntimeEnrollmentAuthorityService authority, IOptions<RuntimeEnrollmentOptions> options,
        TimeProvider? clock = null)
    { this.authority = authority; this.options = options.Value; this.clock = clock ?? TimeProvider.System; }

    /// <summary>
    /// Classifies the exact predecessor, requested successor, and recovery key from one authenticated
    /// snapshot. Callers cannot substitute free lifecycle flags or normalize key identifiers.
    /// </summary>
    /// <param name="registry">Sealed authenticated item-2 snapshot proof.</param>
    /// <param name="predecessorKeyId">Exact key identifier from the locked head.</param>
    /// <param name="successorKeyId">Exact requested new operational key identifier.</param>
    /// <param name="recoveryKeyId">Exact detached recovery key identifier.</param>
    /// <param name="occurredAtUtc">Exact contract transition instant.</param>
    /// <param name="authoritativeNowUtc">Trusted SoftLicence clock instant.</param>
    /// <returns>Immutable classifications consumed directly by the recovery branch.</returns>
    internal static RuntimeEnrollmentAuthorityRecoveryLifecycleDecision ClassifyRecoveryLifecycle(
        RuntimeEnrollmentAuthorityCryptography.TrustedKeyRegistrySnapshotProof registry,
        string predecessorKeyId, string successorKeyId, string recoveryKeyId,
        DateTimeOffset occurredAtUtc, DateTimeOffset authoritativeNowUtc) => new(
            registry.ClassifyCurrentSigner(predecessorKeyId, occurredAtUtc, authoritativeNowUtc),
            registry.ClassifyCurrentSigner(successorKeyId, occurredAtUtc, authoritativeNowUtc),
            registry.ClassifyRecovery(recoveryKeyId, occurredAtUtc, authoritativeNowUtc));

    /// <summary>
    /// Parses authenticated untrusted UTF-8 and freezes only request identity. It performs no registry
    /// authentication, private-key import, authority UUID allocation, payload creation, or signing.
    /// </summary>
    /// <param name="clientId">Exact authenticated S2S client identifier.</param>
    /// <param name="transportKeyId">Exact authenticated S2S transport key identifier.</param>
    /// <param name="attemptId">Canonical transport attempt UUID.</param>
    /// <param name="exactBody">Exact S2S-authenticated request bytes.</param>
    /// <param name="recoveryKeyId">Detached recovery key ID only for recovery.</param>
    /// <param name="recoverySignature">Detached recovery signature only for recovery.</param>
    /// <returns>A replay-stable identity with no generated authority state.</returns>
    /// <exception cref="RuntimeEnrollmentException">Encoding, schema, IDs, transition, or pin configuration fails closed.</exception>
    internal RuntimeEnrollmentAuthorityV2Prepared Prepare(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlySpan<byte> exactBody,
        string? recoveryKeyId, string? recoverySignature,
        bool unsignedRecoveryPreparation = false)
    {
        if (clientId.Length == 0 || transportKeyId.Length == 0 || attemptId == Guid.Empty)
            throw Invalid("INVALID_AUTHORITY_REQUEST");
        byte[] pin;
        try { pin = Convert.FromBase64String(options.AuthorityGenerationV2.RegistryAuthoritySpkiBase64); }
        catch (FormatException) { throw Invalid("KEY_CONFIGURATION_INVALID"); }
        RuntimeEnrollmentAuthorityCryptography crypto;
        try { crypto = new RuntimeEnrollmentAuthorityCryptography(clock, pin); }
        catch (ArgumentException) { throw Invalid("KEY_CONFIGURATION_INVALID"); }
        finally { CryptographicOperations.ZeroMemory(pin); }
        var canonical = crypto.CanonicalizeRequest(exactBody);
        if (canonical.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid(canonical.Error is RuntimeEnrollmentAuthorityCryptography.Failure.SchemaInvalid
                or RuntimeEnrollmentAuthorityCryptography.Failure.ContractVersionUnsupported
                ? "UNSUPPORTED_AUTHORITY_CONTRACT" : "INVALID_AUTHORITY_REQUEST");
        RuntimeEnrollmentAuthorityRequestV2 request;
        try
        {
            request = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityRequestV2>(
                canonical.Value!.CanonicalUtf8, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions())!;
        }
        catch (JsonException) { throw Invalid("INVALID_AUTHORITY_REQUEST"); }
        if (!RuntimeEnrollmentAuthorityTransitionPolicy.IsAllowed(request)
            || !Guid.TryParseExact(request.RequestId, "D", out var requestId)
            || !Guid.TryParseExact(request.ProductId, "D", out var productId)
            || !Guid.TryParseExact(request.RequestedAuthority.Binding.BindingId, "D", out var bindingId)
            || !Guid.TryParseExact(request.RequestedAuthority.Installation.SeatId, "D", out var licenseSeatId)
            || !DateTime.TryParseExact(request.Transition.RequestedAtUtc, UtcFormat,
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var occurredAtUtc))
            throw Invalid("INVALID_AUTHORITY_REQUEST");
        var recovery = request.Transition.Kind == "recovery";
        if (unsignedRecoveryPreparation
            ? !recovery || recoveryKeyId is not null || recoverySignature is not null
            : recovery != (recoveryKeyId is not null && recoverySignature is not null)
                || (!recovery && (recoveryKeyId is not null || recoverySignature is not null)))
            throw Invalid("RECOVERY_PROOF_INVALID");
        return new(clientId, transportKeyId, attemptId, requestId,
            request.ExpectedAuthorityLineageId is null ? null
                : Guid.ParseExact(request.ExpectedAuthorityLineageId, "D"),
            request.ExpectedCurrentGenerationId is null ? null
                : Guid.ParseExact(request.ExpectedCurrentGenerationId, "D"),
            productId, bindingId, licenseSeatId, request.Provider, request.ProviderGrantRef,
            canonical.Value.Digest, occurredAtUtc, recoveryKeyId, recoverySignature, request, crypto);
    }

    /// <summary>Parses an unsigned recovery request for server-owned identity preparation.</summary>
    internal RuntimeEnrollmentAuthorityV2Prepared PrepareRecovery(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlySpan<byte> exactBody) =>
        Prepare(clientId, transportKeyId, attemptId, exactBody, null, null, true);

    /// <summary>
    /// Locks and revalidates the current head, allocates the successor UUID, builds exact canonical bytes,
    /// rechecks A/P and current B after the commercial barrier, and signs a short scope-bound token whose
    /// expiry is derived from provider time inside the caller-owned transaction.
    /// </summary>
    internal async Task<RuntimeEnrollmentAuthorityRecoveryPreparation> PrepareRecoveryAmbientAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned authority transaction is required.");
        var identity = await ResolveIdentityAsync(db, prepared, cancellationToken)
            ?? throw Invalid("AUTHORITY_STATE_CONFLICT");
        if (identity.Predecessor is null || prepared.Request.Transition.Kind != "recovery")
            throw Invalid("RECOVERY_PROOF_INVALID");
        var payload = BuildPayload(prepared, identity);
        var serialized = JsonSerializer.SerializeToUtf8Bytes(
            payload, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());
        var canonical = prepared.Crypto.CanonicalizeGenerationPayload(serialized);
        if (canonical.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid("INVALID_AUTHORITY_REQUEST");
        var authority = await ResolveAuthoritativeEvidenceAsync(
            db, prepared, identity, payload, cancellationToken);
        if (!authority.ScopeAuthorized)
            throw Invalid("RECOVERY_NOT_AUTHORIZED");
        var expires = authority.AuthoritativeNowUtc.AddSeconds(
            RecoveryPreparationLifetimeSeconds).UtcDateTime;
        var claims = new RuntimeEnrollmentAuthorityRecoveryPreparationClaims
        {
            ClientId = prepared.ClientId,
            TransportKeyId = prepared.TransportKeyId,
            AttemptId = prepared.AttemptId.ToString("D"),
            RequestId = prepared.RequestId.ToString("D"),
            LineageId = identity.LineageId.ToString("D"),
            PredecessorGenerationId = identity.PreviousGenerationId!.Value.ToString("D"),
            GenerationId = identity.GenerationId.ToString("D"),
            RequestDigest = prepared.RequestDigest,
            PayloadDigest = canonical.Value!.Digest,
            ExpiresAtUtc = expires.ToString(UtcFormat, CultureInfo.InvariantCulture)
        };
        var claimsBytes = JsonSerializer.SerializeToUtf8Bytes(
            claims, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());
        var session = prepared.Crypto.CreateSigningSession(options.AuthorityGenerationSigning);
        if (session.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid("KEY_CONFIGURATION_INVALID");
        using var signer = session.Value!;
        var signature = signer.SignRecoveryPreparation(claimsBytes);
        if (signature.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid("KEY_CONFIGURATION_INVALID");
        var token = EncodeTokenPart(claimsBytes) + "." + signer.KeyId + "." + signature.Value;
        return new(canonical.Value.CanonicalUtf8, token, expires);
    }

    /// <summary>
    /// Verifies one signed preparation token and freezes its server-allocated successor identity. This
    /// parser does not consult the application clock; execution performs the authoritative expiry and
    /// maximum-lifetime checks against fresh PostgreSQL time after decisive waits.
    /// </summary>
    internal RuntimeEnrollmentAuthorityV2Prepared PrepareRecoveryFinalization(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlySpan<byte> exactBody,
        string preparationToken, string recoveryKeyId, string recoverySignature,
        bool authorizeCurrentToken = true)
    {
        var prepared = Prepare(clientId, transportKeyId, attemptId, exactBody,
            recoveryKeyId, recoverySignature);
        var parts = preparationToken.Split('.');
        if (parts.Length != 3 || !TryDecodeTokenPart(parts[0], out var claimsBytes)
            || !TryDecodeTokenPart(parts[2], out var tokenSignature)
            || tokenSignature.Length != 256)
            throw Invalid("RECOVERY_PREPARATION_MALFORMED");
        RuntimeEnrollmentAuthorityRecoveryPreparationClaims? claims;
        try
        {
            claims = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityRecoveryPreparationClaims>(
                claimsBytes, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());
        }
        catch (JsonException) { throw Invalid("RECOVERY_PREPARATION_MALFORMED"); }
        if (claims is null
            || !Guid.TryParseExact(claims.AttemptId, "D", out _)
            || !Guid.TryParseExact(claims.RequestId, "D", out _)
            || !Guid.TryParseExact(claims.LineageId, "D", out _)
            || !Guid.TryParseExact(claims.PredecessorGenerationId, "D", out _)
            || !Guid.TryParseExact(claims.GenerationId, "D", out var generationId)
            || !DateTime.TryParseExact(claims.ExpiresAtUtc, UtcFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var expires))
            throw Invalid("RECOVERY_PREPARATION_MALFORMED");
        if (!string.Equals(claims.ClientId, clientId, StringComparison.Ordinal)
            || !string.Equals(claims.TransportKeyId, transportKeyId, StringComparison.Ordinal)
            || !string.Equals(claims.AttemptId, attemptId.ToString("D"), StringComparison.Ordinal)
            || !string.Equals(claims.RequestId, prepared.RequestId.ToString("D"), StringComparison.Ordinal)
            || !string.Equals(claims.LineageId, prepared.ExpectedLineageId?.ToString("D"), StringComparison.Ordinal)
            || !string.Equals(claims.PredecessorGenerationId, prepared.PreviousId?.ToString("D"), StringComparison.Ordinal)
            || !string.Equals(claims.RequestDigest, prepared.RequestDigest, StringComparison.Ordinal))
            throw Invalid("RECOVERY_PREPARATION_SCOPE_MISMATCH");
        if (authorizeCurrentToken)
        {
            var registry = AuthenticateRegistry(prepared.Crypto);
            if (prepared.Crypto.VerifyRecoveryPreparationSignature(
                    claimsBytes, parts[1], parts[2], registry)
                != RuntimeEnrollmentAuthorityCryptography.Failure.None)
                throw Invalid("RECOVERY_PREPARATION_NOT_AUTHORIZED");
        }
        return new(prepared.ClientId, prepared.TransportKeyId, prepared.AttemptId, prepared.RequestId,
            prepared.ExpectedLineageId, prepared.PreviousId, prepared.ProductId, prepared.BindingId,
            prepared.LicenseSeatId, prepared.Provider, prepared.GrantRef, prepared.RequestDigest,
            prepared.OccurredAtUtc,
            prepared.RecoveryKeyId, prepared.RecoverySignature, prepared.Request, prepared.Crypto,
            generationId, claims.PayloadDigest, expires);
    }

    /// <summary>
    /// Resolves only an exact durable attempt under replay locks. It intentionally does not authenticate
    /// the current preparation signer or TTL because a committed terminal result is already authoritative.
    /// </summary>
    internal async Task<RuntimeEnrollmentAuthorityV2OperationResult?> ResolveExactAttemptAmbientAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned authority transaction is required.");
        await AcquireReplayLocksAsync(db, prepared, cancellationToken);
        var attempt = await db.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AttemptId == prepared.AttemptId, cancellationToken);
        if (attempt is null) return null;
        if (attempt.RequestId != prepared.RequestId
            || !string.Equals(attempt.RequestDigest, prepared.RequestDigest, StringComparison.Ordinal))
            throw new RuntimeEnrollmentException(
                "RUNTIME_ENROLLMENT_CONFLICT", StatusCodes.Status409Conflict, "ATTEMPT_ID_REUSE");
        return new(ReplayStatus(attempt.Status, attempt.HttpStatusCode),
            attempt.ExactResponseUtf8, true);
    }

    /// <summary>
    /// Executes frozen exact replay before current authority reads; new issuance then rechecks A/P and,
    /// for live results, B after decisive locks and fresh provider time. Any post-insert structural
    /// conflict throws a rollback-only signal; this method never commits or retries.
    /// </summary>
    internal async Task<RuntimeEnrollmentAuthorityV2OperationResult> ExecuteAmbientAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A caller-owned authority transaction is required.");
        var flow = new RuntimeEnrollmentAuthorityIssuanceFlow();
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.Parsed);
        await AcquireReplayLocksAsync(db, prepared, cancellationToken);
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.ReplayLocks);
        var replay = await ResolveReplayAsync(db, prepared, cancellationToken);
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.ReplayResolved);
        if (replay is not null)
        {
            flow.CompleteReplay();
            return replay;
        }

        var identity = await ResolveIdentityAsync(db, prepared, cancellationToken);
        if (identity is null)
            return await StoreAttemptAsync(db, prepared, "REFUSED", "AUTHORITY_STATE_CONFLICT",
                ErrorBody("AUTHORITY_STATE_CONFLICT"), StatusCodes.Status409Conflict, cancellationToken);
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.IdentityResolved);
        var payload = BuildPayload(prepared, identity);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(
            payload, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());
        var canonical = prepared.Crypto.CanonicalizeGenerationPayload(payloadBytes);
        if (canonical.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid("INVALID_AUTHORITY_REQUEST");
        if (prepared.ReservedPayloadDigest is not null
            && !string.Equals(prepared.ReservedPayloadDigest, canonical.Value!.Digest, StringComparison.Ordinal))
            return await StoreAttemptAsync(db, prepared, "REFUSED", "RECOVERY_PREPARATION_PAYLOAD_MISMATCH",
                ErrorBody("RECOVERY_PREPARATION_PAYLOAD_MISMATCH"), StatusCodes.Status403Forbidden,
                cancellationToken);
        var authorityResolution = await ResolveAuthoritativeEvidenceAsync(
            db, prepared, identity, payload, cancellationToken);
        if (prepared.RecoveryPreparationExpiresAtUtc is { } preparationExpiresAtUtc
            && (authorityResolution.AuthoritativeNowUtc.UtcDateTime >= preparationExpiresAtUtc
                || preparationExpiresAtUtc > authorityResolution.AuthoritativeNowUtc
                    .AddSeconds(RecoveryPreparationLifetimeSeconds).UtcDateTime))
            throw Invalid("RECOVERY_PREPARATION_EXPIRED");
        if (!authorityResolution.ScopeAuthorized)
        {
            var failure = RuntimeEnrollmentAuthorityTransitionPolicy.EvidenceFailure(
                payload.Transition.ReasonCode);
            return await StoreAttemptAsync(db, prepared, "REFUSED", failure,
                ErrorBody(failure), StatusFor(failure), cancellationToken);
        }
        var evidence = authorityResolution.Evidence;
        if (identity.Predecessor is not null
            && payload.Transition.ReasonCode is "INSTALLATION_REINSTALLED" or "RECOVERY_AUTHORIZED")
            evidence = evidence.With("CURRENT_HEAD_PROOF");
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.EvidenceResolved);

        var registry = AuthenticateRegistry(prepared.Crypto);
        var occurred = new DateTimeOffset(prepared.OccurredAtUtc, TimeSpan.Zero);
        var now = authorityResolution.AuthoritativeNowUtc;
        var requestedKeyId = payload.Key.AuthorityKeyId;
        var signerKeyId = identity.Predecessor?.Key.AuthorityKeyId ?? requestedKeyId;
        RuntimeEnrollmentAuthorityCryptography.KeyLifecycleClassification lifecycle;
        if (payload.Transition.Kind == "recovery")
        {
            if (identity.Predecessor is null)
                return await StoreAttemptAsync(db, prepared, "REFUSED", "RECOVERY_PROOF_INVALID",
                    ErrorBody("RECOVERY_PROOF_INVALID"), StatusCodes.Status403Forbidden, cancellationToken);
            var recoveryLifecycle = ClassifyRecoveryLifecycle(
                registry, identity.Predecessor.Key.AuthorityKeyId, requestedKeyId,
                prepared.RecoveryKeyId!, occurred, now);
            lifecycle = recoveryLifecycle.Successor;
            var recoveryProof = prepared.Crypto.VerifyRecoverySignature(
                canonical.Value!.CanonicalUtf8, prepared.RecoveryKeyId!,
                prepared.RecoverySignature!, registry);
            if (!recoveryLifecycle.Accepted(identity.Predecessor.Key.AuthorityKeyId, requestedKeyId)
                || recoveryProof.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None
                || prepared.Crypto.ConsumeRecoveryProof(recoveryProof.Value!,
                    canonical.Value.CanonicalUtf8, prepared.RecoveryKeyId!, registry)
                    != RuntimeEnrollmentAuthorityCryptography.Failure.None)
                return await StoreAttemptAsync(db, prepared, "REFUSED", "RECOVERY_PROOF_INVALID",
                    ErrorBody("RECOVERY_PROOF_INVALID"), StatusCodes.Status403Forbidden, cancellationToken);
            evidence = evidence.With("SIGNED_RECOVERY_AUTHORITY");
            signerKeyId = requestedKeyId;
        }
        else if (payload.Transition.Kind == "key_rotation")
        {
            if (identity.Predecessor is null)
                return await StoreAttemptAsync(db, prepared, "REFUSED", "KEY_ROTATION_INVALID",
                    ErrorBody("KEY_ROTATION_INVALID"), StatusCodes.Status403Forbidden, cancellationToken);
            lifecycle = registry.ClassifyRotation(
                identity.Predecessor.Key.AuthorityKeyId, requestedKeyId, occurred, now);
            if (lifecycle.Outcome == RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid)
                evidence = evidence.With("KEY_ROTATION_AUTHORIZATION");
        }
        else
        {
            if (identity.Predecessor is not null
                && !string.Equals(identity.Predecessor.Key.AuthorityKeyId,
                    requestedKeyId, StringComparison.Ordinal))
                return await StoreAttemptAsync(db, prepared, "REFUSED", "KEY_ROTATION_REQUIRED",
                    ErrorBody("KEY_ROTATION_REQUIRED"), StatusCodes.Status403Forbidden, cancellationToken);
            lifecycle = registry.ClassifyCurrentSigner(signerKeyId, occurred, now);
        }
        if (lifecycle.Outcome != RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid)
            return await StoreAttemptAsync(db, prepared, "REFUSED", "KEY_NOT_AUTHORIZED",
                ErrorBody("KEY_NOT_AUTHORIZED"), StatusCodes.Status403Forbidden, cancellationToken);
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.LifecycleValidated);

        var session = prepared.Crypto.CreateSigningSession(options.AuthorityGenerationSigning);
        if (session.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid("KEY_CONFIGURATION_INVALID");
        using var signingSession = session.Value!;
        var signed = signingSession.Sign(canonical.Value!.CanonicalUtf8, signerKeyId);
        if (signed.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None
            || !string.Equals(signed.Value!.KeyId, signerKeyId, StringComparison.Ordinal))
            return await StoreAttemptAsync(db, prepared, "REFUSED", "KEY_ROTATION_SIGNER_INVALID",
                ErrorBody("KEY_ROTATION_SIGNER_INVALID"), StatusCodes.Status403Forbidden, cancellationToken);
        if (payload.Transition.Kind == "key_rotation")
            evidence = evidence.With("PREDECESSOR_KEY_SIGNATURE");
        var decision = RuntimeEnrollmentAuthorityTransitionPolicy.Evaluate(
            identity.Predecessor, payload, evidence, now);
        if (!decision.Accepted)
            return await StoreAttemptAsync(db, prepared, "REFUSED", decision.ErrorCode!,
                ErrorBody(decision.ErrorCode!), StatusFor(decision.ErrorCode!), cancellationToken);
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.Signed);

        var createdAt = clock.GetUtcNow().UtcDateTime;
        var candidate = new RuntimeEnrollmentAuthorityPersistenceCandidate
        {
            AuthorityLineageId = identity.LineageId,
            AuthorityGenerationId = identity.GenerationId,
            RequestId = prepared.RequestId,
            RequestDigest = prepared.RequestDigest,
            Provider = prepared.Provider,
            ProductId = prepared.ProductId,
            LicenseSeatId = identity.LineageRootSeatId,
            ProviderGrantRef = prepared.GrantRef,
            ProviderGrantRefScalarCount = prepared.GrantRef.EnumerateRunes().Count(),
            LineageCreatedAtUtc = identity.LineageCreatedAtUtc,
            Sequence = identity.Sequence.Value,
            PreviousGenerationId = identity.PreviousGenerationId,
            CanonicalPayloadUtf8 = canonical.Value.CanonicalUtf8,
            SignedStatementUtf8 = signed.Value.StatementUtf8,
            AuthorityDigest = signed.Value.AuthorityDigest,
            SignatureAlgorithm = "PS256",
            SignatureKeyId = signed.Value.KeyId,
            SignatureValue = signed.Value.Signature,
            OccurredAtUtc = prepared.OccurredAtUtc,
            CreatedAtUtc = createdAt,
            BindingIds = [prepared.BindingId]
        };
        var outcome = await authority.PersistValidatedGenerationInAmbientTransactionAsync(
            db, candidate, cancellationToken);
        if (outcome.Status == RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict)
            throw new RuntimeEnrollmentAuthorityTransactionInvalidatedException();
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.Persisted);
        var response = signed.Value.StatementUtf8;
        if (outcome.Status == RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult)
            response = (await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .SingleAsync(item => item.RequestId == prepared.RequestId, cancellationToken))
                .ExactResponseUtf8;
        var result = await StoreAttemptAsync(db, prepared, "ACCEPTED", null, response,
            outcome.Status == RuntimeEnrollmentAuthorityPersistenceStatus.Created
                ? StatusCodes.Status201Created : StatusCodes.Status200OK,
            cancellationToken,
            outcome.Status == RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult,
            outcome.AuthorityLineageId, outcome.AuthorityGenerationId);
        flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.AttemptStored);
        return result;
    }

    /// <summary>
    /// Performs request-first classification in the fresh transaction opened after the final rollback.
    /// It never allocates or signs; absence freezes only a bounded structural-conflict result.
    /// </summary>
    internal async Task<RuntimeEnrollmentAuthorityV2OperationResult> ResolveAfterRollbackAmbientAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("A fresh caller-owned authority transaction is required.");
        await AcquireReplayLocksAsync(db, prepared, cancellationToken);
        var replay = await ResolveReplayAsync(db, prepared, cancellationToken);
        return replay ?? await StoreAttemptAsync(db, prepared, "REFUSED", "AUTHORITY_STATE_CONFLICT",
            ErrorBody("AUTHORITY_STATE_CONFLICT"), StatusCodes.Status409Conflict, cancellationToken);
    }

    /// <summary>Acquires deterministic request then attempt locks before every replay read.</summary>
    private static async Task AcquireReplayLocksAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended({prepared.RequestId.ToString("D")}, 62901))
            """, cancellationToken);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended({prepared.AttemptId.ToString("D")}, 62902))
            """, cancellationToken);
    }

    /// <summary>Returns frozen replay before any current registry/private-key use.</summary>
    private async Task<RuntimeEnrollmentAuthorityV2OperationResult?> ResolveReplayAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        var attempt = await db.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AttemptId == prepared.AttemptId, cancellationToken);
        var request = await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
            .SingleOrDefaultAsync(item => item.RequestId == prepared.RequestId, cancellationToken);
        var classification = RuntimeEnrollmentAuthorityReplayRules.Classify(
            attempt, request, prepared.RequestId, prepared.RequestDigest);
        if (classification == RuntimeEnrollmentAuthorityReplayDecision.ExactRequest
            && request!.ResultCode == "ACCEPTED" && prepared.ReservedGenerationId is not null)
        {
            var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                .SingleOrDefaultAsync(item => item.AuthorityGenerationId == request.AuthorityGenerationId,
                    cancellationToken);
            var digest = generation is null ? null
                : Convert.ToHexStringLower(SHA256.HashData(generation.CanonicalPayloadUtf8));
            if (request.AuthorityGenerationId != prepared.ReservedGenerationId
                || !string.Equals(digest, prepared.ReservedPayloadDigest, StringComparison.Ordinal))
                return await StoreAttemptAsync(db, prepared, "REFUSED", "AUTHORITY_STATE_CONFLICT",
                    ErrorBody("AUTHORITY_STATE_CONFLICT"), StatusCodes.Status409Conflict,
                    cancellationToken);
        }
        return classification switch
        {
            RuntimeEnrollmentAuthorityReplayDecision.ExactAttempt =>
                new(ReplayStatus(attempt!.Status, attempt.HttpStatusCode),
                    attempt.ExactResponseUtf8, true),
            RuntimeEnrollmentAuthorityReplayDecision.AttemptIdReuse =>
                throw new RuntimeEnrollmentException(
                    "RUNTIME_ENROLLMENT_CONFLICT", StatusCodes.Status409Conflict, "ATTEMPT_ID_REUSE"),
            RuntimeEnrollmentAuthorityReplayDecision.RequestReplayDivergence =>
                await StoreAttemptAsync(db, prepared, "REFUSED", "REQUEST_REPLAY_DIVERGENCE",
                    ErrorBody("REQUEST_REPLAY_DIVERGENCE"), StatusCodes.Status409Conflict, cancellationToken),
            RuntimeEnrollmentAuthorityReplayDecision.ExactRequest =>
                await StoreAttemptAsync(db, prepared, request!.ResultCode, request.ErrorCode,
                    request.ExactResponseUtf8, ReplayStatus(request.ResultCode, request.HttpStatusCode),
                    cancellationToken, true, request.AuthorityLineageId, request.AuthorityGenerationId),
            RuntimeEnrollmentAuthorityReplayDecision.New => null,
            _ => throw new InvalidOperationException("Unknown authority replay classification.")
        };
    }

    /// <summary>
    /// Locks and rereads both tuple directions for genesis or the complete lineage/head for a successor,
    /// then allocates candidate UUIDs. Opaque tuple values are compared ordinally without repair.
    /// </summary>
    private async Task<RuntimeEnrollmentAuthorityResolvedIdentity?> ResolveIdentityAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        CancellationToken cancellationToken)
    {
        if (prepared.PreviousId is null)
        {
            var tuple = $"{Encoding.UTF8.GetByteCount(prepared.Provider)}:{prepared.Provider}:"
                + $"{prepared.ProductId:D}:{Encoding.UTF8.GetByteCount(prepared.GrantRef)}:{prepared.GrantRef}:"
                + prepared.LicenseSeatId.ToString("D");
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                SELECT pg_catalog.pg_advisory_xact_lock(
                    pg_catalog.hashtextextended({"runtime-enrollment-v2:tuple:" + tuple}, 999831))
                """, cancellationToken);
            var byTuple = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                .SingleOrDefaultAsync(item => item.Provider == prepared.Provider
                    && item.ProductId == prepared.ProductId
                    && item.ProviderGrantRef == prepared.GrantRef
                    && item.LicenseSeatId == prepared.LicenseSeatId, cancellationToken);
            if (byTuple is not null) return null;
            return new(Guid.NewGuid(), Guid.NewGuid(), null, RuntimeEnrollmentLineageSequence.Genesis,
                clock.GetUtcNow().UtcDateTime, prepared.LicenseSeatId, null);
        }

        var lineageId = prepared.ExpectedLineageId!.Value;
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended(
                    {"runtime-enrollment-v2:lineage:" + lineageId.ToString("D")}, 999831))
            """, cancellationToken);
        var lineage = await db.RuntimeEnrollmentAuthorityLineages.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollmentAuthorityLineages"
            WHERE "AuthorityLineageId" = {lineageId} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (lineage is null || lineage.Provider != prepared.Provider
            || lineage.ProductId != prepared.ProductId
            || lineage.ProviderGrantRef != prepared.GrantRef
            || lineage.HeadGenerationId != prepared.PreviousId)
            return null;
        var bytes = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .Where(item => item.AuthorityGenerationId == prepared.PreviousId
                && item.AuthorityLineageId == lineageId && item.Sequence == lineage.HeadSequence)
            .Select(item => item.CanonicalPayloadUtf8).SingleOrDefaultAsync(cancellationToken);
        if (bytes is null) return null;
        RuntimeEnrollmentAuthorityGenerationPayloadV2 predecessor;
        try
        {
            predecessor = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                bytes, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions())!;
        }
        catch (JsonException) { return null; }
        if (predecessor.AuthorityLineageId != lineageId.ToString("D")
            || predecessor.AuthorityGenerationId != prepared.PreviousId.Value.ToString("D")
            || predecessor.Provider != prepared.Provider
            || predecessor.ProductId != prepared.ProductId.ToString("D")
            || predecessor.ProviderGrantRef != prepared.GrantRef)
            return null;
        if (!RuntimeEnrollmentLineageSequence.TryCreate(lineage.HeadSequence, out var headSequence)
            || !headSequence.TryNext(out var nextSequence))
            return null;
        return new(lineageId, prepared.ReservedGenerationId ?? Guid.NewGuid(), prepared.PreviousId,
            nextSequence, lineage.CreatedAtUtc, lineage.LicenseSeatId, predecessor);
    }

    /// <summary>Encodes exact token bytes as canonical unpadded Base64Url.</summary>
    private static string EncodeTokenPart(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Decodes only canonical unpadded Base64Url token bytes.</summary>
    private static bool TryDecodeTokenPart(string value, out byte[] bytes)
    {
        bytes = [];
        if (value.Length == 0 || value.Contains('=') || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            return false;
        try
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            base64 += new string('=', (4 - base64.Length % 4) % 4);
            bytes = Convert.FromBase64String(base64);
            return string.Equals(value, EncodeTokenPart(bytes), StringComparison.Ordinal);
        }
        catch (FormatException) { return false; }
    }

    /// <summary>Builds the final generation from SoftLicence-owned identity and unmodified requested leaves.</summary>
    private static RuntimeEnrollmentAuthorityGenerationPayloadV2 BuildPayload(
        RuntimeEnrollmentAuthorityV2Prepared prepared,
        RuntimeEnrollmentAuthorityResolvedIdentity identity) => new()
    {
        Schema = "runtime-enrollment-authority-generation-v2",
        ContractVersion = 2,
        AuthorityLineageId = identity.LineageId.ToString("D"),
        AuthorityGenerationId = identity.GenerationId.ToString("D"),
        PreviousGenerationId = identity.PreviousGenerationId?.ToString("D"),
        Sequence = identity.Sequence.Value,
        Provider = prepared.Request.Provider,
        ProductId = prepared.Request.ProductId,
        ProviderGrantRef = prepared.Request.ProviderGrantRef,
        Release = prepared.Request.RequestedAuthority.Release,
        Binding = prepared.Request.RequestedAuthority.Binding,
        Enrollment = prepared.Request.RequestedAuthority.Enrollment,
        Key = prepared.Request.RequestedAuthority.Key,
        Installation = prepared.Request.RequestedAuthority.Installation,
        Transition = new RuntimeEnrollmentAuthorityGenerationTransitionV2
        {
            Kind = prepared.Request.Transition.Kind,
            ReasonCode = prepared.Request.Transition.ReasonCode,
            RequestId = prepared.Request.RequestId,
            OccurredAtUtc = prepared.Request.Transition.RequestedAtUtc
        }
    };

    /// <summary>
    /// Reads A/P and, only for a live result, current B after the enrollment row and item-2 barrier.
    /// Signed hardware, licence dates, and seat fields remain immutable provenance and never grant B;
    /// current authorization comes from the Runtime key lineage and locked active assignment.
    /// </summary>
    /// <param name="db">Ambient transaction context that owns the enrollment lock and item-2 barrier.</param>
    /// <param name="prepared">Strict normalized authority request and server-derived relational identifiers.</param>
    /// <param name="identity">Resolved immutable authority lineage and predecessor generation.</param>
    /// <param name="current">Exact signed generation payload being classified.</param>
    /// <param name="cancellationToken">Cancels database reads before the ambient transaction completes.</param>
    /// <returns>The allowlisted evidence decisions and exact server-derived authority scope.</returns>
    private async Task<RuntimeEnrollmentAuthorityEvidenceResolution> ResolveAuthoritativeEvidenceAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared,
        RuntimeEnrollmentAuthorityResolvedIdentity identity,
        RuntimeEnrollmentAuthorityGenerationPayloadV2 current,
        CancellationToken cancellationToken)
    {
        var predecessor = identity.Predecessor;
        var decisions = new List<RuntimeEnrollmentAuthorityScopedDecision>();
        var enrollmentId = Guid.ParseExact(current.Enrollment.EnrollmentId, "D");
        _ = await db.RuntimeEnrollments.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollments"
            WHERE "Id" = {enrollmentId}
            FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
        var now = await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken);
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == enrollmentId, cancellationToken);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == prepared.BindingId, cancellationToken);
        var owned = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(item =>
            item.BindingId == prepared.BindingId && item.ClientId == prepared.ClientId
                && item.Operation == "finalize_binding",
            cancellationToken);

        var resultClass = ClassifyResult(current);
        RuntimeCommercialEligibilityValidator.EligibleAssignment? currentAssignment = null;
        IReadOnlyDictionary<string, string>? approvedBinaries = null;
        if (resultClass == RuntimeEnrollmentAuthorityResultClass.Live && enrollment is not null)
        {
            try
            {
                approvedBinaries = (await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                    db, enrollment, cancellationToken)).Binaries;
            }
            catch (RuntimeEnrollmentException exception)
                when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                approvedBinaries = null;
            }
            if (approvedBinaries is not null)
            {
                var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
                    db, enrollment, approvedBinaries, now, null, cancellationToken);
                currentAssignment = assessment.Assignment;
            }
        }

        var historicalAssignment = currentAssignment is null
            ? await db.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(item => item.EnrollmentId == enrollmentId
                    && item.LicenseSeatId == prepared.LicenseSeatId
                    && (binding == null || item.LicenseId == binding.LicenseId))
                .OrderByDescending(item => item.Revision)
                .FirstOrDefaultAsync(cancellationToken)
            : null;
        var provenanceLicenseId = currentAssignment?.LicenseId
            ?? historicalAssignment?.LicenseId
            ?? binding?.LicenseId
            ?? Guid.Empty;
        var license = provenanceLicenseId == Guid.Empty ? null : await db.Licenses.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == provenanceLicenseId, cancellationToken);

        var bindingProvenanceMatches = binding is not null && owned
            && binding.ProductId == prepared.ProductId
            && binding.GrantRef == prepared.GrantRef
            && binding.Version == current.Release.Version
            && binding.InstallationId == current.Installation.InstallationId
            && binding.LicenseSeatId == prepared.LicenseSeatId
            && binding.LicenseSeatId.ToString("D") == current.Installation.SeatId;
        var enrollmentSecurityEpochMatches = current.Transition.ReasonCode
                is "SECURITY_EPOCH_ADVANCED" or "RECOVERY_AUTHORIZED"
            ? predecessor is not null && enrollment?.SecurityEpoch == predecessor.Key.SecurityEpoch
            : enrollment?.SecurityEpoch == current.Key.SecurityEpoch;
        var enrollmentProvenanceMatches = enrollment is not null
            && license is not null
            && enrollment.ClientId == prepared.ClientId
            && enrollment.ProductId == prepared.ProductId
            && enrollment.BindingId == prepared.BindingId
            && enrollment.InstallationId == current.Installation.InstallationId
            && enrollment.ReleaseVersion == current.Release.Version
            && enrollmentSecurityEpochMatches
            && ContractTimeEquals(license.ActivationDate ?? license.CreationDate,
                current.Enrollment.IssuedAtUtc)
            && ContractTimeEquals(license.ExpirationDate, current.Enrollment.ExpiresAtUtc);
        var liveScopeMatches = resultClass == RuntimeEnrollmentAuthorityResultClass.Live
            && bindingProvenanceMatches && binding!.State == "active"
            && enrollmentProvenanceMatches
            && ContractState(enrollment!.State) == current.Enrollment.State
            && currentAssignment is not null
            && currentAssignment.LicenseId == binding.LicenseId
            && currentAssignment.SeatId == prepared.LicenseSeatId;
        var terminalScopeMatches = resultClass == RuntimeEnrollmentAuthorityResultClass.Terminal
            && bindingProvenanceMatches && enrollmentProvenanceMatches
            && TerminalStateMatches(current.Enrollment.State, enrollment!, license!, now);
        var expectedScope = new RuntimeEnrollmentAuthorityEvidenceScope(
            prepared.ClientId, prepared.ProductId, prepared.BindingId, enrollmentId,
            license?.Id ?? Guid.Empty, identity.LineageRootSeatId, prepared.LicenseSeatId,
            identity.LineageId, identity.PreviousGenerationId ?? Guid.Empty);
        void Add(string label, bool authorized)
        {
            if (authorized)
                decisions.Add(new(label, expectedScope));
        }
        var approvedRelease = await db.ApprovedBinaryRegistrations.AsNoTracking().AnyAsync(item =>
                item.ProductId == prepared.ProductId
                && item.Version == current.Release.Version
                && item.BaselineDigestSha256 == current.Release.ArtifactSetDigest
                && item.Source == "release", cancellationToken);
        switch (current.Transition.ReasonCode)
        {
            case "INITIAL_ENROLLMENT":
                Add("INITIAL_ENTITLEMENT", liveScopeMatches);
                break;
            case "APPROVED_RELEASE_ADVANCE":
                Add("APPROVED_ARTIFACT_SET", liveScopeMatches && approvedRelease);
                break;
            case "BINDING_REPLACEMENT":
                Add("BINDING_REPLACEMENT_AUTHORITY", liveScopeMatches && predecessor is not null
                    && Guid.TryParseExact(predecessor.Binding.BindingId, "D", out var replacedBindingId)
                    && binding!.SupersededBindingId == replacedBindingId);
                Add("ELIGIBLE_HARDWARE", liveScopeMatches);
                break;
            case "ENROLLMENT_ACTIVATED":
                Add("ACTIVATION_PROOF", liveScopeMatches && enrollment!.ActivatedAtUtc is not null
                    && ContractState(enrollment.State) == "active");
                break;
            case "ENROLLMENT_EXPIRED":
                Add("AUTHORITATIVE_EXPIRY", terminalScopeMatches && current.Enrollment.State == "expired"
                    && license!.ExpirationDate is not null
                    && license.ExpirationDate.Value <= now.UtcDateTime);
                break;
            case "ENROLLMENT_REPLACED":
                var oldEnrollmentId = predecessor is null ? Guid.Empty
                    : Guid.ParseExact(predecessor.Enrollment.EnrollmentId, "D");
                Add("REPLACEMENT_ELIGIBILITY", liveScopeMatches && oldEnrollmentId != enrollmentId
                    && await db.RuntimeEnrollments.AsNoTracking().AnyAsync(item =>
                        item.Id == oldEnrollmentId && item.ClientId == prepared.ClientId
                        && item.ProductId == prepared.ProductId
                        && item.State == "INVALIDATED" && item.InvalidatedAtUtc != null,
                        cancellationToken));
                break;
            case "AUTHORITY_REVOKED":
                Add("SIGNED_REVOCATION_DECISION", terminalScopeMatches && enrollment!.State == "INVALIDATED"
                    && enrollment.InvalidatedAtUtc is not null && enrollment.InvalidationReason is not null
                    && await db.DistributionBindingInvalidations.AsNoTracking().AnyAsync(item =>
                        item.BindingId == prepared.BindingId && item.ProductId == prepared.ProductId
                        && item.ClientId == prepared.ClientId && item.Reason == enrollment.InvalidationReason,
                        cancellationToken));
                break;
            case "SECURITY_EPOCH_ADVANCED":
            case "RECOVERY_AUTHORIZED":
                Add("SECURITY_DECISION", (resultClass == RuntimeEnrollmentAuthorityResultClass.Live
                        ? liveScopeMatches : terminalScopeMatches) && predecessor is not null
                    && await db.RuntimeCriticalRecoveries.AsNoTracking().AnyAsync(item =>
                        item.EnrollmentId == enrollmentId && item.BindingId == prepared.BindingId
                        && item.ProductId == prepared.ProductId && item.InstallationId == current.Installation.InstallationId
                        && item.OldSecurityEpoch == predecessor.Key.SecurityEpoch
                        && item.NewSecurityEpoch == current.Key.SecurityEpoch
                        && item.RecoveredByClientId == prepared.ClientId,
                        cancellationToken));
                break;
            case "INSTALLATION_REINSTALLED":
                Add("REINSTALL_PROOF", liveScopeMatches && predecessor is not null
                    && predecessor.Installation.InstallationId != current.Installation.InstallationId
                    && binding!.InstallationId == current.Installation.InstallationId);
                break;
            case "REPAIR_AUTHORIZED":
                Add("REPAIR_PROOF", liveScopeMatches && approvedRelease);
                break;
            case "SEAT_REASSIGNED":
                Add("SEAT_ACQUISITION_PROOF", liveScopeMatches
                    && await db.LicenseSeats.AsNoTracking().AnyAsync(item =>
                        item.Id == prepared.LicenseSeatId && item.LicenseId == license!.Id && item.IsActive,
                        cancellationToken));
                Add("SEAT_RELEASE_PROOF", liveScopeMatches && predecessor is not null
                    && Guid.TryParseExact(predecessor.Installation.SeatId, "D", out var oldSeatId)
                    && oldSeatId != prepared.LicenseSeatId
                    && await db.LicenseSeats.AsNoTracking().AnyAsync(item =>
                        item.Id == oldSeatId && !item.IsActive,
                        cancellationToken));
                break;
        }
        _ = prepared.TransportKeyId;
        var evidence = RuntimeEnrollmentAuthorityTransitionPolicy.ResolveScopedEvidence(
            current.Transition.ReasonCode, expectedScope, decisions);
        var scopeAuthorized = resultClass == RuntimeEnrollmentAuthorityResultClass.Live
            ? liveScopeMatches : terminalScopeMatches;
        if (current.Transition.ReasonCode is "SECURITY_EPOCH_ADVANCED" or "RECOVERY_AUTHORIZED")
            scopeAuthorized = scopeAuthorized && decisions.Any(item =>
                item.Label == "SECURITY_DECISION" && item.Scope == expectedScope);
        return new(evidence, now, scopeAuthorized);
    }

    /// <summary>Classifies recovery by resulting state and every other terminal transition explicitly.</summary>
    internal static RuntimeEnrollmentAuthorityResultClass ClassifyResult(
        RuntimeEnrollmentAuthorityGenerationPayloadV2 current) =>
        current.Enrollment.State is "expired" or "revoked"
            ? RuntimeEnrollmentAuthorityResultClass.Terminal
            : RuntimeEnrollmentAuthorityResultClass.Live;

    /// <summary>Matches exact terminal state without consulting or reviving current commercial B.</summary>
    private static bool TerminalStateMatches(
        string requestedState,
        RuntimeEnrollment enrollment,
        License license,
        DateTimeOffset now) => requestedState switch
        {
            "expired" => enrollment.State is "PENDING" or "ACTIVE"
                && license.ExpirationDate is not null
                && license.ExpirationDate.Value <= now.UtcDateTime,
            "revoked" => enrollment.State == "INVALIDATED"
                && enrollment.InvalidatedAtUtc is not null,
            _ => false
        };

    /// <summary>Authenticates the current registry only after replay, locks, and business evidence.</summary>
    private RuntimeEnrollmentAuthorityCryptography.TrustedKeyRegistrySnapshotProof AuthenticateRegistry(
        RuntimeEnrollmentAuthorityCryptography crypto)
    {
        if (!DateTimeOffset.TryParseExact(options.AuthorityGenerationV2.RegistryObservedAtUtc, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var observed)
            || observed.Offset != TimeSpan.Zero)
            throw Invalid("KEY_REGISTRY_TIME_INVALID");
        var evidence = crypto.AuthenticateRegistrySnapshot(
            options.AuthorityGenerationSigning, observed,
            options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url);
        if (evidence.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
            throw Invalid(evidence.Error == RuntimeEnrollmentAuthorityCryptography.Failure.KeyRegistryStale
                ? "KEY_REGISTRY_STALE" : "KEY_REGISTRY_AUTHENTICATION_INVALID");
        return crypto.CreateTrustedSnapshotProof(evidence.Value!);
    }

    /// <summary>Freezes one terminal attempt and optional refused request in the active transaction.</summary>
    private async Task<RuntimeEnrollmentAuthorityV2OperationResult> StoreAttemptAsync(
        LicenseDbContext db, RuntimeEnrollmentAuthorityV2Prepared prepared, string status,
        string? error, byte[] response, int statusCode, CancellationToken cancellationToken,
        bool idempotent = false, Guid? storedLineageId = null, Guid? storedGenerationId = null)
    {
        var existing = await db.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AttemptId == prepared.AttemptId, cancellationToken);
        if (existing is not null)
        {
            if (existing.RequestId != prepared.RequestId
                || existing.RequestDigest != prepared.RequestDigest)
                throw new RuntimeEnrollmentException(
                    "RUNTIME_ENROLLMENT_CONFLICT", StatusCodes.Status409Conflict, "ATTEMPT_ID_REUSE");
            return new(ReplayStatus(existing.Status, existing.HttpStatusCode),
                existing.ExactResponseUtf8, true);
        }
        var now = clock.GetUtcNow().UtcDateTime;
        RuntimeEnrollmentAuthorityRequest? refused = null;
        if (status == "REFUSED" && !await db.RuntimeEnrollmentAuthorityRequests.AnyAsync(
                item => item.RequestId == prepared.RequestId, cancellationToken))
        {
            refused = new()
            {
                RequestId = prepared.RequestId,
                RequestDigest = prepared.RequestDigest,
                ResultCode = "REFUSED",
                ErrorCode = error,
                HttpStatusCode = statusCode,
                CreatedAtUtc = now,
                CompletedAtUtc = now,
                ExactResponseUtf8 = [.. response]
            };
        }
        var attempt = new RuntimeEnrollmentAuthorityAttempt
        {
            AttemptId = prepared.AttemptId,
            RequestId = prepared.RequestId,
            RequestDigest = prepared.RequestDigest,
            AuthorityLineageId = status == "ACCEPTED" ? storedLineageId : null,
            AuthorityGenerationId = status == "ACCEPTED" ? storedGenerationId : null,
            Status = status,
            ErrorCode = error,
            HttpStatusCode = status == "ACCEPTED" ? StatusCodes.Status200OK : statusCode,
            CreatedAtUtc = now,
            CompletedAtUtc = now,
            ExactResponseUtf8 = [.. response]
        };
        if (status == "REFUSED")
            await authority.PersistRefusedResultInAmbientTransactionAsync(
                db, refused, attempt, cancellationToken);
        else
            await authority.PersistAttemptInAmbientTransactionAsync(db, attempt, cancellationToken);
        return new(statusCode, response, idempotent);
    }

    /// <summary>Returns 200 for accepted replay and the frozen original category status for refusal.</summary>
    internal static int ReplayStatus(string status, int storedStatus) =>
        status == "ACCEPTED" ? StatusCodes.Status200OK : storedStatus;

    /// <summary>Compares a trusted UTC instant with one exact six-fraction contract timestamp.</summary>
    private static bool ContractTimeEquals(DateTime? trustedUtc, string? contractUtc) =>
        trustedUtc is null ? contractUtc is null
            : DateTime.TryParseExact(contractUtc, UtcFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
                && parsed == DateTime.SpecifyKind(trustedUtc.Value, DateTimeKind.Utc);

    /// <summary>Maps exact database states to contract states without case folding.</summary>
    private static string ContractState(string state) => state switch
    {
        "PENDING" => "pending",
        "ACTIVE" => "active",
        "INVALIDATED" => "revoked",
        _ => string.Empty
    };

    /// <summary>Builds an ASCII public error envelope from a closed internal code.</summary>
    private static byte[] ErrorBody(string code) =>
        Encoding.UTF8.GetBytes($"{{\"error\":\"{PublicCategory(code)}\"}}");

    /// <summary>Maps exactly five public categories to stable HTTP status codes.</summary>
    private static int StatusFor(string code) => PublicCategory(code) switch
    {
        "RUNTIME_ENROLLMENT_UNSUPPORTED" => StatusCodes.Status400BadRequest,
        "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE" => StatusCodes.Status400BadRequest,
        "RUNTIME_ENROLLMENT_CONFLICT" => StatusCodes.Status409Conflict,
        "RUNTIME_ENROLLMENT_DENIED" => StatusCodes.Status403Forbidden,
        _ => StatusCodes.Status503ServiceUnavailable
    };

    /// <summary>Creates a closed public exception while retaining only an allowlisted internal diagnostic.</summary>
    private static RuntimeEnrollmentException Invalid(string code) =>
        new(PublicCategory(code), StatusFor(code), code);

    /// <summary>Maps internal diagnostics to exactly five normative public categories.</summary>
    private static string PublicCategory(string code) => code switch
    {
        "UNSUPPORTED_AUTHORITY_CONTRACT" or "AUTHORITY_V2_UNAVAILABLE" =>
            "RUNTIME_ENROLLMENT_UNSUPPORTED",
        "INVALID_AUTHORITY_REQUEST" or "KEY_REGISTRY_AUTHENTICATION_INVALID"
            or "RECOVERY_PREPARATION_MALFORMED" =>
            "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE",
        "REQUEST_REPLAY_DIVERGENCE" or "ATTEMPT_ID_REUSE" or "AUTHORITY_STATE_CONFLICT"
            or "PREDECESSOR_INVALID" or "LINEAGE_IDENTITY_MISMATCH"
            or "TRANSITION_TIME_REGRESSION" or "RELEASE_REGRESSION" =>
            "RUNTIME_ENROLLMENT_CONFLICT",
        "TRANSITION_REASON_UNKNOWN" or "TRANSITION_KIND_REASON_MISMATCH"
            or "KEY_ROTATION_REQUIRED" or "KEY_EPOCH_MISMATCH" or "ENROLLMENT_TERMINAL"
            or "REPAIR_SCOPE_VIOLATION" or "TRANSITION_SCOPE_VIOLATION"
            or "TRANSITION_REQUIRED_CHANGE_MISSING" or "ENROLLMENT_TRANSITION_INVALID"
            or "TRANSITION_TIME_FUTURE" or "ENROLLMENT_TIME_INVALID"
            or "SECURITY_EPOCH_REGRESSION" or "INITIAL_ENROLLMENT_NOT_AUTHORIZED"
            or "RELEASE_NOT_AUTHORIZED" or "BINDING_CHANGE_NOT_AUTHORIZED"
            or "ENROLLMENT_ACTIVATION_NOT_AUTHORIZED" or "ENROLLMENT_EXPIRY_NOT_AUTHORIZED"
            or "ENROLLMENT_REPLACEMENT_NOT_AUTHORIZED" or "REVOCATION_NOT_AUTHORIZED"
            or "KEY_ROTATION_NOT_AUTHORIZED" or "SECURITY_EPOCH_NOT_AUTHORIZED"
            or "INSTALLATION_CHANGE_NOT_AUTHORIZED" or "RECOVERY_NOT_AUTHORIZED"
            or "REPAIR_NOT_AUTHORIZED" or "SEAT_CHANGE_NOT_AUTHORIZED"
            or "KEY_NOT_AUTHORIZED" or "KEY_ROTATION_INVALID"
            or "KEY_ROTATION_SIGNER_INVALID" or "RECOVERY_PROOF_INVALID"
            or "RECOVERY_PREPARATION_SCOPE_MISMATCH" or "RECOVERY_PREPARATION_EXPIRED"
            or "RECOVERY_PREPARATION_NOT_AUTHORIZED" or "RECOVERY_PREPARATION_PAYLOAD_MISMATCH" =>
            "RUNTIME_ENROLLMENT_DENIED",
        _ => "RUNTIME_ENROLLMENT_TEMPORARILY_UNAVAILABLE"
    };
}
