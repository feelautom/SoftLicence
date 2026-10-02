using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Tests.Server;

/// <summary>Executes one predefined scenario through the real Runtime Enrollment v2 authority flow.</summary>
internal interface ITkt000672AuthorityScenarioExecutor
{
    /// <summary>Executes exactly one closed scenario without direct provider-table DML.</summary>
    /// <param name="scenario">Closed scenario descriptor in canonical order.</param>
    /// <param name="request">Validated producer request.</param>
    /// <param name="cancellationToken">Caller cancellation propagated to the real flow.</param>
    /// <returns>Only owned persisted request identifiers; classification is derived later from database evidence.</returns>
    Task<Tkt000672ScenarioExecution> ExecuteAsync(
        Tkt000672Scenario scenario,
        Tkt000672SourceCRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Creates isolated ephemeral signing and trust authorities for one producer invocation.</summary>
internal interface ITkt000672ManifestSignerFactory
{
    /// <summary>Creates a disposable signer containing two distinct in-memory RSA key owners.</summary>
    /// <returns>A new PS256 signer whose private material is never serialized.</returns>
    Tkt000672ManifestSigner Create();
}

/// <summary>Reads a bounded snapshot of already persisted v2 evidence for owned request IDs.</summary>
internal interface ITkt000672PersistedEvidenceReader
{
    /// <summary>Reads requests, attempts, and canonical generation payloads with a hard 501-row sentinel.</summary>
    /// <param name="ownedRequestIds">Distinct request IDs returned by authenticated scenario execution.</param>
    /// <param name="cancellationToken">Cancellation propagated to storage.</param>
    /// <returns>A detached bounded evidence snapshot.</returns>
    Task<Tkt000672PersistedEvidenceSnapshot> ReadAsync(
        IReadOnlyCollection<Guid> ownedRequestIds, CancellationToken cancellationToken);
}

/// <summary>Production-shaped evidence reader using only no-tracking bounded EF projections.</summary>
/// <param name="dbFactory">Application-role factory for the isolated PostgreSQL evidence store.</param>
internal sealed class Tkt000672PostgreSqlEvidenceReader(
    IDbContextFactory<LicenseDbContext> dbFactory) : ITkt000672PersistedEvidenceReader
{
    /// <inheritdoc />
    public async Task<Tkt000672PersistedEvidenceSnapshot> ReadAsync(
        IReadOnlyCollection<Guid> ownedRequestIds, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var requests = await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
            .Where(item => ownedRequestIds.Contains(item.RequestId))
            .Select(item => new Tkt000672PersistedRequest(item.RequestId, item.RequestDigest,
                item.ResultCode, item.ErrorCode))
            .Take(Tkt000672SourceCAuthorityContract.CollectionLimit + 1).ToListAsync(cancellationToken);
        var attempts = await db.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
            .Where(item => ownedRequestIds.Contains(item.RequestId))
            .Select(item => new Tkt000672PersistedAttempt(item.RequestId, item.Status, item.ErrorCode))
            .Take(Tkt000672SourceCAuthorityContract.CollectionLimit + 1).ToListAsync(cancellationToken);
        var generations = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .Where(item => ownedRequestIds.Contains(item.RequestId))
            .Join(db.RuntimeEnrollmentAuthorityRequests.AsNoTracking(), generation => generation.RequestId,
                request => request.RequestId, (generation, request) => new Tkt000672PersistedGeneration(
                    generation.RequestId, request.RequestDigest, generation.AuthorityGenerationId,
                    generation.AuthorityDigest, generation.CanonicalPayloadUtf8))
            .Take(Tkt000672SourceCAuthorityContract.CollectionLimit + 1).ToListAsync(cancellationToken);
        return new(requests, attempts, generations);
    }
}

/// <summary>Detached persisted request outcome used only for bounded evidence classification.</summary>
/// <param name="RequestId">Owned production-controller request identity.</param>
/// <param name="RequestDigest">Persisted lowercase request digest.</param>
/// <param name="ResultCode">Persisted terminal request result.</param>
/// <param name="ErrorCode">Optional persisted closed error code.</param>
internal sealed record Tkt000672PersistedRequest(
    Guid RequestId, string RequestDigest, string ResultCode, string? ErrorCode);

/// <summary>Detached persisted attempt outcome used only for bounded evidence validation.</summary>
/// <param name="RequestId">Owned production-controller request identity.</param>
/// <param name="Status">Persisted terminal attempt status.</param>
/// <param name="ErrorCode">Optional persisted closed error code.</param>
internal sealed record Tkt000672PersistedAttempt(Guid RequestId, string Status, string? ErrorCode);

/// <summary>Detached persisted generation and canonical tuple payload used by Contract C classification.</summary>
/// <param name="RequestId">Owned production-controller request identity.</param>
/// <param name="RequestDigest">Persisted lowercase request digest.</param>
/// <param name="AuthorityGenerationId">Persisted authority-generation identity.</param>
/// <param name="AuthorityDigest">Persisted lowercase canonical generation digest.</param>
/// <param name="CanonicalPayloadUtf8">Exact persisted canonical generation bytes.</param>
internal sealed record Tkt000672PersistedGeneration(
    Guid RequestId, string RequestDigest, Guid AuthorityGenerationId, string AuthorityDigest,
    byte[] CanonicalPayloadUtf8);

/// <summary>Bounded detached storage snapshot; each collection may contain at most the 501-row refusal sentinel.</summary>
/// <param name="Requests">Owned persisted request projections.</param>
/// <param name="Attempts">Owned persisted attempt projections.</param>
/// <param name="Generations">Owned persisted generation projections.</param>
internal sealed record Tkt000672PersistedEvidenceSnapshot(
    IReadOnlyList<Tkt000672PersistedRequest> Requests,
    IReadOnlyList<Tkt000672PersistedAttempt> Attempts,
    IReadOnlyList<Tkt000672PersistedGeneration> Generations);

/// <summary>Default signer factory; stable run-local private material exists only in disposable memory.</summary>
internal sealed class Tkt000672ManifestSignerFactory : ITkt000672ManifestSignerFactory, IDisposable
{
    private readonly byte[] manifestKey = CreatePrivateKey();
    private readonly byte[] trustKey = CreatePrivateKey();
    private bool disposed;

    /// <inheritdoc />
    public Tkt000672ManifestSigner Create()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var manifest = RSA.Create();
        manifest.ImportPkcs8PrivateKey(manifestKey, out _);
        var trust = RSA.Create();
        trust.ImportPkcs8PrivateKey(trustKey, out _);
        return new(manifest, trust, "tkt672-manifest-key-01");
    }

    /// <summary>Zeros the run-local private-key encodings when the test host releases its singleton.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(manifestKey);
        CryptographicOperations.ZeroMemory(trustKey);
    }

    /// <summary>Creates one independent 3072-bit PKCS#8 key encoding without durable storage.</summary>
    private static byte[] CreatePrivateKey()
    {
        using var key = RSA.Create(3072);
        return key.ExportPkcs8PrivateKey();
    }
}

/// <summary>Closed fail-closed capability settings registered only by the test assembly.</summary>
/// <param name="Enabled">Whether the test host explicitly enables the otherwise absent capability.</param>
/// <param name="AuthorizedClientId">Exact authenticated S2S client ID; no normalization is allowed.</param>
/// <param name="RequiredPermission">Exact permission required before any body read.</param>
internal sealed record Tkt000672SourceCAuthorityGate(
    bool Enabled,
    string AuthorizedClientId,
    string RequiredPermission)
{
    /// <summary>Returns the default-off gate used whenever tests do not explicitly enable the capability.</summary>
    internal static Tkt000672SourceCAuthorityGate Disabled { get; } =
        new(false, string.Empty, "runtime-enrollment.source-c.generate");
}

/// <summary>Stable metadata-only harness result with no raw provider, tuple, or request values.</summary>
internal sealed record Tkt000672HarnessResult(
    bool Ok,
    Tkt000672SourceCResponse? Response,
    string? Reason,
    string? Field)
{
    /// <summary>Creates one stable metadata-only refusal without echoing rejected provider or request data.</summary>
    /// <param name="reason">Closed refusal reason.</param>
    /// <param name="field">Stable public field category, never a rejected value.</param>
    /// <returns>A failed result with no response payload.</returns>
    internal static Tkt000672HarnessResult Refuse(string reason, string field) => new(false, null, reason, field);
}

/// <summary>
/// Composes the four real v2 flows, bounded database projection, opaque identity derivation, and PS256 manifest.
/// It performs no direct DML and trusts no provider identity declared by generated rows.
/// </summary>
internal sealed class Tkt000672SourceCAuthorityHarness
{
    private readonly ITkt000672PersistedEvidenceReader evidenceReader;
    private readonly ITkt000672AuthorityScenarioExecutor scenarios;
    private readonly ITkt000672ManifestSignerFactory signers;

    /// <summary>Creates the test-only composition over the real database model and an explicit flow executor.</summary>
    /// <param name="evidenceReader">Bounded reader for real persisted evidence or transport-only detached fixtures.</param>
    /// <param name="scenarios">Executor that traverses real controller/service v2 flows.</param>
    /// <param name="signers">Factory for distinct ephemeral PS256 and trust authorities.</param>
    public Tkt000672SourceCAuthorityHarness(
        ITkt000672PersistedEvidenceReader evidenceReader,
        ITkt000672AuthorityScenarioExecutor scenarios,
        ITkt000672ManifestSignerFactory signers)
    {
        this.evidenceReader = evidenceReader;
        this.scenarios = scenarios;
        this.signers = signers;
    }

    /// <summary>
    /// Dispatches every scenario exactly once after controller authorization, reads at most 501 owned rows,
    /// and returns a signed metadata-only response. Cancellation may interrupt before a manifest is returned.
    /// </summary>
    /// <param name="request">Validated closed request.</param>
    /// <param name="cancellationToken">Cancellation propagated to flows and EF queries.</param>
    /// <returns>A successful signed response or one stable refusal without sensitive echoes.</returns>
    internal async Task<Tkt000672HarnessResult> RunAsync(
        Tkt000672SourceCRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Environment != Tkt000672SourceCAuthorityContract.Environment)
            return Tkt000672HarnessResult.Refuse("NON_PRODUCTION_GATE_REQUIRED", "environment");

        var executions = new List<Tkt000672ScenarioExecution>(Tkt000672SourceCAuthorityContract.Scenarios.Length);
        foreach (var scenario in Tkt000672SourceCAuthorityContract.Scenarios)
        {
            var execution = await scenarios.ExecuteAsync(scenario, request, cancellationToken);
            if (execution.ScenarioId != scenario.ScenarioId || execution.RequestIds.Count is < 1 or > 2)
                return Tkt000672HarnessResult.Refuse("SCENARIO_DISPATCH_INVALID", "scenarios");
            executions.Add(execution);
        }
        if (executions.Select(item => item.ScenarioId).Distinct(StringComparer.Ordinal).Count() != executions.Count
            || executions.SelectMany(item => item.RequestIds).Distinct().Count()
                != executions.Sum(item => item.RequestIds.Count))
            return Tkt000672HarnessResult.Refuse("SCENARIO_DISPATCH_INVALID", "scenarios");

        var ownedRequests = executions.SelectMany(item => item.RequestIds).ToArray();
        var snapshot = await evidenceReader.ReadAsync(ownedRequests, cancellationToken);
        var persistedRequests = snapshot.Requests;
        var attempts = snapshot.Attempts;
        var rows = snapshot.Generations;
        if (rows.Count > Tkt000672SourceCAuthorityContract.CollectionLimit
            || persistedRequests.Count > Tkt000672SourceCAuthorityContract.CollectionLimit
            || attempts.Count > Tkt000672SourceCAuthorityContract.CollectionLimit)
            return Tkt000672HarnessResult.Refuse("COLLECTION_LIMIT_EXCEEDED", "authorityGenerations");
        var evidence = new List<Tkt000672ScenarioEvidence>(executions.Count);
        foreach (var execution in executions)
        {
            var ids = execution.RequestIds.ToHashSet();
            var requestSet = persistedRequests.Where(item => ids.Contains(item.RequestId)).ToArray();
            var generationSet = rows.Where(item => ids.Contains(item.RequestId)).ToArray();
            var attemptSet = attempts.Where(item => ids.Contains(item.RequestId)).ToArray();
            var expected = Tkt000672SourceCAuthorityContract.Scenarios.Single(item =>
                item.ScenarioId == execution.ScenarioId);
            var tuples = generationSet.OrderBy(item => item.AuthorityGenerationId)
                .Select(item => ParseAttestedTuple(item.CanonicalPayloadUtf8, item.AuthorityDigest)).ToArray();
            if (tuples.Length is < 1 or > 2 || requestSet.Any(item => item.ResultCode != "ACCEPTED")
                || attemptSet.Any(item => item.Status != "ACCEPTED"))
                return Tkt000672HarnessResult.Refuse("PERSISTED_EVIDENCE_INVALID", execution.ScenarioId);
            var first = tuples[0];
            var scope = new Tkt000672LegacyScope("SOFTLICENCE_ATTESTED_SCOPE", first.Provider,
                first.ProductId, first.ProviderGrantRef);
            var legacy = LegacyEvidence(execution.ScenarioId, first);
            var derived = Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(legacy, scope, tuples);
            if (derived.Classification != expected.Classification || derived.Reason != expected.Reason)
                return Tkt000672HarnessResult.Refuse("PERSISTED_EVIDENCE_INVALID", execution.ScenarioId);
            evidence.Add(new(execution.ScenarioId, derived.Classification, derived.Reason,
                requestSet.Length, generationSet.Length, attemptSet.Length));
        }

        var classifications = evidence.SelectMany(item => executions.Single(execution =>
                execution.ScenarioId == item.ScenarioId).RequestIds.Select(id => (id, item)))
            .ToDictionary(pair => pair.id, pair => pair.item);
        var observations = rows.Select(row => new Tkt000672GenerationObservation(
            classifications[row.RequestId].ScenarioId,
            classifications[row.RequestId].Classification,
            Tkt000672SourceCAuthorityContract.PublicId("tuple", row.RequestId.ToString("D")),
            Tkt000672SourceCAuthorityContract.PublicDigest("tuple-digest", row.RequestDigest),
            Tkt000672SourceCAuthorityContract.PublicId("generation", row.AuthorityGenerationId.ToString("D")),
            row.AuthorityDigest)).ToArray();
        if (observations.Any(item => !Tkt000672SourceCAuthorityContract.IsHash(item.RequestDigest)
            || !Tkt000672SourceCAuthorityContract.IsHash(item.GenerationDigest)))
            return Tkt000672HarnessResult.Refuse("DIGEST_INVALID", "authorityGenerations");

        using var signer = signers.Create();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, observations, signer);
        if (!signer.Verify(built.SignedBytes, built.Manifest["signature"]!.GetValue<string>()))
            return Tkt000672HarnessResult.Refuse("SIGNATURE_INVALID", "signature");
        return new(true, new Tkt000672SourceCResponse
        {
            RunId = request.RunId,
            ScenarioCount = Tkt000672SourceCAuthorityContract.Scenarios.Length,
            Classifications = evidence.Select(item => item.Classification).ToArray(),
            ClassificationEvidence = evidence,
            Manifest = built.Manifest,
            TrustStoreSnapshot = built.TrustStoreSnapshot
        }, null, null);
    }

    /// <summary>Projects one persisted closed generation payload into the exact Contract C tuple fields.</summary>
    /// <param name="payloadUtf8">Persisted canonical generation payload bytes.</param>
    /// <param name="authorityDigest">Persisted authenticated generation digest.</param>
    /// <returns>An exact tuple without normalization or provider-value disclosure.</returns>
    private static Tkt000672AttestedTuple ParseAttestedTuple(byte[] payloadUtf8, string authorityDigest)
    {
        var payload = JsonSerializer.Deserialize<SoftLicence.Server.Models.RuntimeEnrollmentAuthorityGenerationPayloadV2>(
            payloadUtf8, SoftLicence.Server.Models.RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions())
            ?? throw new InvalidDataException("persisted_generation_payload_invalid");
        return new(payload.AuthorityLineageId, payload.AuthorityGenerationId, payload.Provider,
            payload.ProductId, payload.ProviderGrantRef, authorityDigest, payload.Key.SecurityEpoch,
            payload.Binding.BindingId, payload.Enrollment.EnrollmentId, payload.Key.AuthorityKeyId,
            payload.Release.Version);
    }

    /// <summary>Builds one closed synthetic legacy observation from persisted tuple values.</summary>
    /// <param name="scenarioId">Closed scenario identity selecting only the declared evidence absence/conflict.</param>
    /// <param name="tuple">First persisted authenticated tuple.</param>
    /// <returns>Exact legacy evidence used by the normative pure classifier.</returns>
    private static Tkt000672LegacyEvidence LegacyEvidence(string scenarioId, Tkt000672AttestedTuple tuple) =>
        scenarioId switch
        {
            "scenario_proven" => Complete(tuple),
            "scenario_partial" => Complete(tuple) with { EnrollmentId = null },
            "scenario_ambiguous" => Complete(tuple) with
                { AuthorityDigest = null, SecurityEpoch = null, KeyThumbprint = null },
            "scenario_inconsistent" => Complete(tuple) with { ReleaseVersion = tuple.ReleaseVersion + " " },
            _ => throw new InvalidDataException("scenario_dispatch_invalid")
        };

    /// <summary>Copies all seven comparable values from one persisted authenticated tuple.</summary>
    private static Tkt000672LegacyEvidence Complete(Tkt000672AttestedTuple tuple) => new(
        "legacy-source-tkt672", tuple.ProviderGrantRef, tuple.AuthorityDigest, tuple.SecurityEpoch,
        tuple.BindingId, tuple.EnrollmentId, tuple.KeyThumbprint, tuple.ReleaseVersion);
}
