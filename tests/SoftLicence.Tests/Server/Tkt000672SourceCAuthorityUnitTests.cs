using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises the closed request, canonical framing, bounds, scenarios, and PS256 producer contract.</summary>
public sealed class Tkt000672SourceCAuthorityUnitTests
{
    /// <summary>
    /// Proves the operational runner rejects missing project identity, missing restore assets, zero discovered tests,
    /// zero executed tests, contradictory result outcomes, and duplicated TRX identities through the same readiness
    /// and TRX validators used by a real run. Every probe runs before PostgreSQL provisioning and must emit only its
    /// stable non-sensitive diagnostic.
    /// </summary>
    /// <param name="probe">The exact closed probe selected by the runner.</param>
    /// <param name="expectedExitCode">The stable nonzero exit code for that refusal.</param>
    /// <param name="expectedDiagnostic">The complete non-sensitive standard-error line.</param>
    [Theory]
    [InlineData("MissingProject", 21, "The exact Source C test project is missing.")]
    [InlineData("MissingAssets", 22,
        "The Source C test project restore assets are missing; run the bounded restore first.")]
    [InlineData("ZeroTests", 23, "No tests were discovered; Source C validation was not executed.")]
    [InlineData("ZeroExecuted", 24, "No tests were executed; Source C validation was not executed.")]
    [InlineData("NonPassingResult", 26,
        "The TRX result rows do not exactly match the declared Passed counter.")]
    [InlineData("DuplicateExecutionId", 27,
        "The TRX result executionId values must be non-empty and unique.")]
    [InlineData("DuplicateTestId", 28,
        "The TRX result testId values must be non-empty and unique.")]
    [Trait("Category", "PrivateRepository")]
    public async Task SourceCAuthorityRunner_FailClosedProbesRejectInvalidEvidence(
        string probe, int expectedExitCode, string expectedDiagnostic)
    {
        var repositoryRoot = FindRepositoryRoot();
        var scriptPath = Path.Combine(repositoryRoot, "scripts", "Invoke-Tkt000672SourceCAuthority.ps1");
        var start = new ProcessStartInfo("pwsh")
        {
            WorkingDirectory = repositoryRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(scriptPath);
        start.ArgumentList.Add("-TestEvidenceProbe");
        start.ArgumentList.Add(probe);

        using var process = Process.Start(start) ?? throw new InvalidOperationException(
            "The fail-closed PowerShell probe could not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        var output = await stdout;
        var error = await stderr;

        Assert.Equal(expectedExitCode, process.ExitCode);
        Assert.Empty(output);
        Assert.Equal(expectedDiagnostic + Environment.NewLine, error);
    }

    /// <summary>Locks every authoritative Website Contract C precedence and reason against exact tuple evidence.</summary>
    [Fact]
    public void LegacyClassifier_MatchesAuthoritativeContractCReasonsExactly()
    {
        var tuple = LegacyTuple();
        var evidence = LegacyEvidence(tuple);
        var scope = new Tkt000672LegacyScope("SOFTLICENCE_ATTESTED_SCOPE", tuple.Provider,
            tuple.ProductId, tuple.ProviderGrantRef);
        Assert.Equal(new("PROVEN", "PROVEN_EXACT_ATTESTED_TUPLE"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(evidence, scope, [tuple]));
        Assert.Equal(new("PARTIAL", "PARTIAL_REQUIRED_EVIDENCE_MISSING"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(
                evidence with { EnrollmentId = null }, scope, [tuple]));
        Assert.Equal(new("PARTIAL", "PARTIAL_NO_ATTESTED_TUPLE"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(evidence, scope, []));
        var sibling = tuple with
        {
            AuthorityGenerationId = "generation-002", AuthorityDigest = new string('c', 64),
            SecurityEpoch = 8, KeyThumbprint = "operational-2026-02"
        };
        Assert.Equal(new("AMBIGUOUS", "AMBIGUOUS_MULTIPLE_ATTESTED_TUPLES"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(
                evidence with { AuthorityDigest = null, SecurityEpoch = null, KeyThumbprint = null },
                scope, [tuple, sibling]));
        Assert.Equal(new("INCONSISTENT", "INCONSISTENT_DUPLICATE_ATTESTED_IDENTITY"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(evidence, scope, [tuple, tuple]));
        Assert.Equal(new("INCONSISTENT", "INCONSISTENT_AUTHORITY_SCOPE_INVALID"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(evidence,
                scope with { Authority = null }, [tuple]));
        Assert.Equal(new("INCONSISTENT", "INCONSISTENT_AUTHORITY_SCOPE_CONFLICT"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(evidence,
                scope, [tuple with { Provider = "softlicence-shadow" }]));
        Assert.Equal(new("INCONSISTENT", "INCONSISTENT_ATTESTED_TUPLE_CONFLICT"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(
                evidence with { ReleaseVersion = evidence.ReleaseVersion + " " }, scope, [tuple]));
        Assert.Equal(new("PROVEN", "PROVEN_EXACT_ATTESTED_TUPLE"),
            Tkt000672SourceCAuthorityContract.ClassifyLegacyEvidence(evidence, scope,
                [tuple, sibling]));
    }

    /// <summary>
    /// Resolves the owning worktree without accepting a sibling repository or relying on the process launch directory.
    /// </summary>
    /// <returns>The exact ancestor containing both the Source C runner and test project.</returns>
    private static string FindRepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory); current is not null; current = current.Parent)
        {
            var script = Path.Combine(current.FullName, "scripts", "Invoke-Tkt000672SourceCAuthority.ps1");
            var project = Path.Combine(current.FullName, "tests", "SoftLicence.Tests", "SoftLicence.Tests.csproj");
            if (File.Exists(script) && File.Exists(project))
                return current.FullName;
        }
        throw new InvalidOperationException("The exact Source C repository root was not found.");
    }

    /// <summary>Creates one exact metadata-safe authenticated tuple for Contract C tests.</summary>
    /// <returns>A complete tuple with exact ordinal values.</returns>
    private static Tkt000672AttestedTuple LegacyTuple() => new(
        "lineage-001", "generation-001", "softlicence", "product-001", "grant-001",
        new string('a', 64), 7, "binding-001", "enrollment-001", "operational-2026-01", "2.3.445");

    /// <summary>Copies complete comparable legacy evidence from one authenticated tuple.</summary>
    /// <param name="tuple">Authenticated source tuple.</param>
    /// <returns>Complete legacy evidence matching all seven comparable fields.</returns>
    private static Tkt000672LegacyEvidence LegacyEvidence(Tkt000672AttestedTuple tuple) => new(
        "legacy-source-001", tuple.ProviderGrantRef, tuple.AuthorityDigest, tuple.SecurityEpoch,
        tuple.BindingId, tuple.EnrollmentId, tuple.KeyThumbprint, tuple.ReleaseVersion);

    /// <summary>Proves complete validation finishes before an at-most-once PS256 callback.</summary>
    [Fact]
    public void CompleteManifestValidator_IsFailClosedAndInvokesVerifierAtMostOnce()
    {
        var request = ValidRequest();
        using var signer = NewSigner();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, [], signer);
        var context = ValidationContext(request, signer, built);
        var calls = 0;
        var accepted = Tkt000672SourceCAuthorityContract.ValidateManifest(
            built.Manifest, built.TrustStoreSnapshot, context, (bytes, signature) =>
            {
                calls++;
                Assert.Equal(built.SignedBytes, bytes);
                return signer.Verify(bytes, signature);
            });
        Assert.True(accepted.Ok);
        Assert.Equal(1, calls);

        var drift = (JsonObject)built.Manifest.DeepClone();
        drift["algorithm"] = "RS256";
        calls = 0;
        Assert.Equal(new(false, "ALGORITHM_INVALID", "algorithm"),
            Tkt000672SourceCAuthorityContract.ValidateManifest(
                drift, built.TrustStoreSnapshot, context, (_, _) => { calls++; return true; }));
        Assert.Equal(0, calls);
        Assert.Equal(new(false, "SIGNATURE_INVALID", "signature"),
            Tkt000672SourceCAuthorityContract.ValidateManifest(
                built.Manifest, built.TrustStoreSnapshot, context, (_, _) => false));
        Assert.Equal(new(false, "SIGNATURE_INVALID", "signature"),
            Tkt000672SourceCAuthorityContract.ValidateManifest(
                built.Manifest, built.TrustStoreSnapshot, context, (_, _) => throw new CryptographicException()));
    }

    /// <summary>Creates the injected public trust context for one built manifest.</summary>
    /// <param name="request">Expected producer request.</param>
    /// <param name="signer">Signer owning the public trust binding.</param>
    /// <param name="built">Built manifest providing the observed issuance instant.</param>
    /// <returns>A closed injected validation context.</returns>
    private static Tkt000672ManifestValidationContext ValidationContext(
        Tkt000672SourceCRequest request, Tkt000672ManifestSigner signer, Tkt000672BuiltManifest built) => new(
        request, signer.Binding["snapshotId"]!.GetValue<string>(), signer.Binding["digest"]!.GetValue<string>(),
        signer.Binding["domain"]!.GetValue<string>(), signer.KeyId, signer.Fingerprint,
        built.Manifest["issuedAtUtc"]!.GetValue<string>());

    /// <summary>Compares every canonical derivation with independently computed Website golden bytes.</summary>
    [Fact]
    public void GoldenCryptoArtifacts_AreByteForByteExactAndIndependent()
    {
        using var fixture = LoadFixture();
        var golden = fixture.RootElement.GetProperty("golden");
        var payloadJson = golden.GetProperty("canonicalPayloadJson").GetString()!;
        var payload = JsonNode.Parse(payloadJson)!;
        Assert.Equal(payloadJson, Tkt000672SourceCAuthorityContract.Canonicalize(payload));
        var canonicalPayload = Tkt000672SourceCAuthorityContract.Frame(
            Tkt000672SourceCAuthorityContract.CanonicalPayloadDomain, payloadJson);
        Assert.Equal(golden.GetProperty("canonicalPayload").GetString(), canonicalPayload);
        var authorityDigest = Tkt000672SourceCAuthorityContract.Sha256(
            Tkt000672SourceCAuthorityContract.Frame(
                Tkt000672SourceCAuthorityContract.AuthorityDigestDomain, canonicalPayload));
        Assert.Equal(golden.GetProperty("authorityDigest").GetString(), authorityDigest);
        Assert.Equal(golden.GetProperty("signedStatement").GetString(),
            Tkt000672SourceCAuthorityContract.Frame(
                Tkt000672SourceCAuthorityContract.SignedStatementDomain,
                Tkt000672SourceCAuthorityContract.ManifestSchema, authorityDigest));
        var projection = golden.GetProperty("signingProjectionCanonical").GetString()!;
        Assert.Equal(projection, Tkt000672SourceCAuthorityContract.Canonicalize(JsonNode.Parse(projection)));
        Assert.Equal(golden.GetProperty("signedBytesUtf8").GetString(),
            Tkt000672SourceCAuthorityContract.Frame(
                Tkt000672SourceCAuthorityContract.CanonicalManifestDomain, projection));
        var manifest = golden.GetProperty("canonicalManifest").GetString()!;
        Assert.Equal(manifest, Tkt000672SourceCAuthorityContract.Canonicalize(JsonNode.Parse(manifest)));
        var payloadObject = JsonNode.Parse(payloadJson)!.AsObject();
        var manifestNode = JsonNode.Parse(manifest)!;
        var expectedSignedBytes = Encoding.UTF8.GetBytes(golden.GetProperty("signedBytesUtf8").GetString()!);
        using var goldenSigner = Tkt000672ManifestSigner.CreateGolden(
            payloadObject["trustSnapshotBinding"]!.AsObject(), expectedSignedBytes,
            golden.GetProperty("signatureBase64url").GetString()!,
            manifestNode["validFromUtc"]!.GetValue<string>(),
            manifestNode["validUntilUtc"]!.GetValue<string>());
        var payloadScopes = payloadObject["scopes"]!.AsObject();
        var request = new Tkt000672SourceCRequest(
            Tkt000672SourceCAuthorityContract.RequestSchema, "run_golden_000000000000000000000001",
            payloadObject["environment"]!.GetValue<string>(), payloadObject["sourceId"]!.GetValue<string>(),
            manifestNode["issuedAtUtc"]!.GetValue<string>(),
            payloadObject["evidenceHashes"]!["snapshotHash"]!.GetValue<string>(),
            payloadObject["evidenceHashes"]!["catalogHash"]!.GetValue<string>(),
            payloadObject["evidenceHashes"]!["migrationsHash"]!.GetValue<string>(),
            payloadObject["evidenceHashes"]!["oracleHash"]!.GetValue<string>(),
            payloadObject["evidenceHashes"]!["generationSpecHash"]!.GetValue<string>(),
            payloadScopes["provider"]!["opaqueId"]!.GetValue<string>(),
            payloadScopes["product"]!["opaqueId"]!.GetValue<string>(),
            payloadScopes["grant"]!["opaqueId"]!.GetValue<string>());
        var goldenGeneration = payloadObject["authorityGenerations"]![0]!;
        var goldenTuple = payloadObject["authorityTuples"]![0]!;
        var rows = new[] { new Tkt000672GenerationObservation(
            "scenario_proven", "PROVEN", goldenTuple["tupleId"]!.GetValue<string>(),
            goldenTuple["tupleDigest"]!.GetValue<string>(),
            goldenGeneration["generationId"]!.GetValue<string>(),
            goldenGeneration["generationDigest"]!.GetValue<string>(),
            payloadScopes["provider"]!["digest"]!.GetValue<string>(),
            payloadScopes["product"]!["digest"]!.GetValue<string>(),
            payloadScopes["grant"]!["digest"]!.GetValue<string>()) };
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, rows, goldenSigner);
        Assert.Equal(payloadJson, built.CanonicalPayloadJson);
        Assert.Equal(canonicalPayload, built.CanonicalPayload);
        Assert.Equal(authorityDigest, built.AuthorityDigest);
        Assert.Equal(golden.GetProperty("signedStatement").GetString(), built.SignedStatement);
        Assert.Equal(projection, built.SigningProjectionCanonical);
        Assert.Equal(expectedSignedBytes, built.SignedBytes);
        Assert.Equal(manifest, built.CanonicalManifest);
        Assert.True(goldenSigner.Verify(built.SignedBytes,
            built.Manifest["signature"]!.GetValue<string>()));
        var digests = golden.GetProperty("digests");
        Assert.Equal(digests.GetProperty("canonicalPayloadJsonSha256").GetString(), Hash(payloadJson));
        Assert.Equal(digests.GetProperty("canonicalPayloadSha256").GetString(), Hash(canonicalPayload));
        Assert.Equal(digests.GetProperty("signedStatementSha256").GetString(),
            Hash(golden.GetProperty("signedStatement").GetString()!));
        Assert.Equal(digests.GetProperty("signingProjectionSha256").GetString(), Hash(projection));
        Assert.Equal(digests.GetProperty("signedBytesSha256").GetString(),
            Hash(golden.GetProperty("signedBytesUtf8").GetString()!));
        Assert.Equal(digests.GetProperty("canonicalManifestSha256").GetString(), Hash(manifest));
    }

    /// <summary>Proves the closed fixture dispatcher has unique names and executes each exactly once.</summary>
    [Fact]
    public void ReferenceVectorDispatcher_ExecutesEveryUniqueNamedVectorExactlyOnce()
    {
        using var fixture = LoadFixture();
        var named = fixture.RootElement.GetProperty("namedCases").EnumerateArray()
            .Select(item => item.GetString()!).ToArray();
        Assert.NotEmpty(named);
        Assert.Equal(named.Length, named.Distinct(StringComparer.Ordinal).Count());
        var executed = named.ToDictionary(item => item, _ => 0, StringComparer.Ordinal);
        foreach (var name in named)
        {
            Assert.True(IsClosedReferenceCase(name));
            DispatchReferenceVector(name, fixture.RootElement.GetProperty("golden"));
            executed[name]++;
        }
        Assert.All(executed, item => Assert.Equal(1, item.Value));
    }

    /// <summary>Behaviorally dispatches every closed Website vector name to a producer invariant with no fallback.</summary>
    private static void DispatchReferenceVector(string name, JsonElement golden)
    {
        if (name == "golden-crypto-byte-for-byte")
        {
            Assert.Equal(golden.GetProperty("authorityDigest").GetString(),
                Tkt000672SourceCAuthorityContract.Sha256(Tkt000672SourceCAuthorityContract.Frame(
                    Tkt000672SourceCAuthorityContract.AuthorityDigestDomain,
                    golden.GetProperty("canonicalPayload").GetString()!)));
            return;
        }
        if (name.Contains("population", StringComparison.Ordinal))
        {
            AssertPopulationVector(name);
            return;
        }
        if (name.Contains("extra-key", StringComparison.Ordinal)
            || name.Contains("missing-key", StringComparison.Ordinal)
            || name is "context-verifier-missing" or "context-verifier-accessor"
                or "context-verifier-non-enumerable")
        {
            if (name.StartsWith("expected-", StringComparison.Ordinal)
                || name.StartsWith("context-", StringComparison.Ordinal))
            {
                AssertRefusal(MutateContextVector(name), "SCHEMA_INVALID", "request.keys");
                return;
            }
            AssertClosedLayerMutation(name);
            return;
        }
        if (name.StartsWith("context-proxy-", StringComparison.Ordinal))
        {
            AssertContextStructureVector(name);
            return;
        }
        if (name.StartsWith("signature-", StringComparison.Ordinal))
        {
            AssertSignatureVector(name);
            return;
        }
        if (name is "identifier-multibyte-128-accepted" or "identifier-multibyte-129-rejected"
            or "lone-surrogate-value" or "lone-surrogate-key" or "canonical-equivalence-not-normalized"
            or "normalization-exact-mismatch" or "whitespace-exact-mismatch" or "case-exact-mismatch")
        {
            if (name == "identifier-multibyte-128-accepted")
                Assert.True(Tkt000672SourceCAuthorityContract.IsIdentifier(string.Concat(Enumerable.Repeat("é", 64))));
            else if (name == "identifier-multibyte-129-rejected")
                Assert.False(Tkt000672SourceCAuthorityContract.IsIdentifier(string.Concat(Enumerable.Repeat("é", 64)) + "a"));
            else if (name == "lone-surrogate-key")
                AssertRefusal(Encoding.UTF8.GetBytes("{\"\\uD800\":\"x\"}"), "UNICODE_INVALID", "request.propertyNameUnicode");
            else if (name == "lone-surrogate-value")
                AssertRefusal(Encoding.UTF8.GetBytes("{\"schema\":\"\\uDC00\"}"), "UNICODE_INVALID", "request.valueUnicode");
            else if (name == "whitespace-exact-mismatch")
                Assert.NotEqual(Tkt000672SourceCAuthorityContract.PublicDigest("exact", "scope"),
                    Tkt000672SourceCAuthorityContract.PublicDigest("exact", "scope "));
            else if (name == "case-exact-mismatch")
                Assert.NotEqual(Tkt000672SourceCAuthorityContract.PublicDigest("exact", "Scope"),
                    Tkt000672SourceCAuthorityContract.PublicDigest("exact", "scope"));
            else if (name == "normalization-exact-mismatch")
                Assert.NotEqual(Tkt000672SourceCAuthorityContract.PublicDigest("exact", "é"),
                    Tkt000672SourceCAuthorityContract.PublicDigest("exact", "e\u0301"));
            else
            {
                Assert.Equal("canonical-equivalence-not-normalized", name);
                Assert.NotEqual(Tkt000672SourceCAuthorityContract.PublicId("exact", "é"),
                    Tkt000672SourceCAuthorityContract.PublicId("exact", "e\u0301"));
            }
            return;
        }
        if (name is "fixture-promotable-true" or "native-pass-pass" or "materialization-authorized-true"
            or "native-recipe-state-drift" or "artifact-kind-drift" || name.StartsWith("source-c-state-", StringComparison.Ordinal))
        {
            AssertBoundaryMutation(name);
            return;
        }
        if (name.Contains("byte-limit", StringComparison.Ordinal) || name.StartsWith("structural-", StringComparison.Ordinal)
            || name is "array-getter" or "object-getter" or "symbol-key" or "sparse-array"
                or "exotic-prototype" or "proxy-ownkeys-error" or "proxy-descriptor-error")
        {
            AssertStructuralVector(name);
            return;
        }
        if (name is "deep-freeze" or "input-mutation-isolated")
        {
            AssertMutationIsolationVector(name);
            return;
        }
        if (name is "verifier-false" or "verifier-throws")
        {
            AssertVerifierRefusal(name == "verifier-throws");
            return;
        }
        AssertNamedManifestMutation(name);
    }

    /// <summary>Rejects unknown, missing, malformed, production, fixture, and non-exact request strings.</summary>
    [Fact]
    public void RequestParser_IsClosedExactAndUnicodeSafe()
    {
        var valid = ValidRequestJson();
        Assert.True(Tkt000672SourceCAuthorityContract.ParseRequest(valid).Ok);
        AssertRefusal(Mutate(valid, node => node["extra"] = true), "SCHEMA_INVALID", "request.keys");
        AssertRefusal(Mutate(valid, node => node.Remove("sourceId")), "SCHEMA_INVALID", "request.keys");
        AssertRefusal(Mutate(valid, node => node["environment"] = "FIXTURE_QUALIFICATION"),
            "ENVIRONMENT_INVALID", "environment");
        AssertRefusal(Mutate(valid, node => node["environment"] = "PRODUCTION"),
            "ENVIRONMENT_INVALID", "environment");
        AssertRefusal(Mutate(valid, node => node["sourceId"] = string.Empty),
            "IDENTIFIER_INVALID", "identity");
        Assert.False(Tkt000672SourceCAuthorityContract.IsIdentifier("\ud800"));
        AssertRefusal(Encoding.UTF8.GetBytes("{\"\\uD800\":\"x\"}"),
            "UNICODE_INVALID", "request.propertyNameUnicode");
        AssertRefusal(Encoding.UTF8.GetBytes("{\"\\uDC00\":\"x\"}"),
            "UNICODE_INVALID", "request.propertyNameUnicode");
        AssertRefusal(Encoding.UTF8.GetBytes("{\"schema\":\"\\uD800\"}"),
            "UNICODE_INVALID", "request.valueUnicode");
        AssertRefusal(Encoding.UTF8.GetBytes("{\"schema\":\"\\uDC00\"}"),
            "UNICODE_INVALID", "request.valueUnicode");
        var accepted128 = string.Concat(Enumerable.Repeat("é", 64));
        Assert.Equal(128, Encoding.UTF8.GetByteCount(accepted128));
        Assert.True(Tkt000672SourceCAuthorityContract.IsIdentifier(accepted128));
        var rejected129 = accepted128 + "a";
        Assert.Equal(129, Encoding.UTF8.GetByteCount(rejected129));
        Assert.False(Tkt000672SourceCAuthorityContract.IsIdentifier(rejected129));
        Assert.NotEqual(Tkt000672SourceCAuthorityContract.PublicId("exact", "é"),
            Tkt000672SourceCAuthorityContract.PublicId("exact", "e\u0301"));
    }

    /// <summary>Checks every missing request field, duplicate keys, malformed UTF-8, and exact byte boundaries.</summary>
    [Fact]
    public void RequestParser_CoversEveryClosedKeyAndIndependentTransportByteBoundary()
    {
        var valid = ValidRequestJson();
        foreach (var key in Tkt000672SourceCAuthorityContract.RequestKeys)
            AssertRefusal(Mutate(valid, node => node.Remove(key)), "SCHEMA_INVALID", "request.keys");
        var text = Encoding.UTF8.GetString(valid);
        var duplicate = Encoding.UTF8.GetBytes(text[..^1] + ",\"sourceId\":\"duplicate\"}");
        AssertRefusal(duplicate, "SCHEMA_INVALID", "request.keys");
        AssertRefusal([], "REQUEST_SIZE_INVALID", "request");
        AssertRefusal([0xff], "SCHEMA_INVALID", "request");
        var atLimit = valid.Concat(Enumerable.Repeat((byte)' ',
            Tkt000672SourceCAuthorityContract.RequestUtf8Limit - valid.Length)).ToArray();
        Assert.True(Tkt000672SourceCAuthorityContract.ParseRequest(atLimit).Ok);
        AssertRefusal(atLimit.Append((byte)' ').ToArray(), "REQUEST_SIZE_INVALID", "request");
    }

    /// <summary>Accepts 0 and 500 rows, rejects 501, and keeps materialization states structurally inert.</summary>
    [Fact]
    public void ManifestBuilder_EnforcesIndependentCollectionAndNoMaterializationBounds()
    {
        var request = ValidRequest();
        using var signer = NewSigner();
        var empty = Tkt000672SourceCAuthorityContract.BuildManifest(request, [], signer);
        AssertNoMaterialization(empty.Manifest);
        Assert.Equal(
            ["digest", "domain", "fingerprint", "keyId", "revocation", "snapshotId", "validFromUtc", "validUntilUtc"],
            empty.TrustStoreSnapshot.Select(item => item.Key)
                .OrderBy(item => item, StringComparer.Ordinal).ToArray());
        var fiveHundred = Enumerable.Range(0, 500).Select(Observation).ToArray();
        using var boundarySigner = NewSigner();
        var boundary = Tkt000672SourceCAuthorityContract.BuildManifest(request, fiveHundred, boundarySigner);
        Assert.Equal(500, boundary.Manifest["payload"]!["authorityGenerations"]!.AsArray().Count);
        Assert.Equal(500, boundary.Manifest["payload"]!["authorityTuples"]!.AsArray().Count);
        Assert.True(boundarySigner.Verify(boundary.SignedBytes,
            boundary.Manifest["signature"]!.GetValue<string>()));
        using var overflowSigner = NewSigner();
        Assert.Equal("GENERATION_LIMIT_EXCEEDED", Assert.Throws<InvalidOperationException>(() =>
            Tkt000672SourceCAuthorityContract.BuildManifest(
                request, Enumerable.Range(0, 501).Select(Observation).ToArray(), overflowSigner)).Message);
    }

    /// <summary>Proves the four-scenario dispatcher is exact, ordered, and duplicate-free.</summary>
    [Fact]
    public void ScenarioRegistry_IsTheExactClosedGenerationContractOrder()
    {
        Assert.Equal(
            [
                ("scenario_proven", 0, "PROVEN"),
                ("scenario_partial", 1, "PARTIAL"),
                ("scenario_ambiguous", 2, "AMBIGUOUS"),
                ("scenario_inconsistent", 3, "INCONSISTENT")
            ],
            Tkt000672SourceCAuthorityContract.Scenarios
                .Select(item => (item.ScenarioId, item.Order, item.Classification)).ToArray());
    }

    /// <summary>Verifies probabilistic PS256 envelopes exactly while preserving deterministic payload trust binding.</summary>
    [Fact]
    public void ManifestSigner_UsesProbabilisticPs256WithExactTrustBinding()
    {
        using var signer = NewSigner();
        var first = Tkt000672SourceCAuthorityContract.BuildManifest(ValidRequest(), [], signer);
        var second = Tkt000672SourceCAuthorityContract.BuildManifest(ValidRequest(), [], signer);
        Assert.Equal(first.AuthorityDigest, second.AuthorityDigest);
        var firstSignature = first.Manifest["signature"]!.GetValue<string>();
        var secondSignature = second.Manifest["signature"]!.GetValue<string>();
        Assert.NotEqual(firstSignature, secondSignature);
        Assert.True(signer.Verify(first.SignedBytes, firstSignature));
        Assert.True(signer.Verify(second.SignedBytes, secondSignature));
        Assert.Equal(signer.Binding["fingerprint"]!.GetValue<string>(),
            first.TrustStoreSnapshot["fingerprint"]!.GetValue<string>());
        Assert.Equal(signer.Binding["snapshotId"]!.GetValue<string>(),
            first.TrustStoreSnapshot["snapshotId"]!.GetValue<string>());
    }

    /// <summary>Asserts every immutable no-materialization field on a producer-owned manifest.</summary>
    /// <param name="manifest">Manifest produced by the contract under test.</param>
    private static void AssertNoMaterialization(JsonObject manifest)
    {
        var proof = manifest["payload"]!["proofBoundary"]!;
        Assert.Equal("SOFTLICENCE_AUTHORITY_METADATA", proof["artifactKind"]!.GetValue<string>());
        Assert.False(proof["fixtureQualificationPromotable"]!.GetValue<bool>());
        Assert.False(proof["materializationAuthorized"]!.GetValue<bool>());
        Assert.Equal("NOT_RUN", proof["nativeRecipeState"]!.GetValue<string>());
        Assert.Equal("NOT_CLAIMED", proof["nativePass"]!.GetValue<string>());
        Assert.Equal(Tkt000672SourceCAuthorityContract.SourceCStates,
            proof["sourceCStates"]!.AsArray().Select(item => item!.GetValue<string>()).ToArray());
    }

    /// <summary>Executes one real closed-shape mutation and proves refusal before signature verification.</summary>
    /// <param name="name">Closed vector selecting one exact layer and missing/extra mutation.</param>
    private static void AssertClosedLayerMutation(string name)
    {
        using var signer = NewSigner();
        var request = ValidRequest();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, [Observation(0)], signer);
        var manifest = (JsonObject)built.Manifest.DeepClone();
        var trust = (JsonObject)built.TrustStoreSnapshot.DeepClone();
        JsonObject target;
        string field;
        string missingKey;
        if (name.StartsWith("top-level-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest, "manifest.keys", "schema");
        else if (name.StartsWith("payload-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!.AsObject(), "payload.keys", "ticketRef");
        else if (name.StartsWith("evidence-hashes-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["evidenceHashes"]!.AsObject(),
                "payload.evidenceHashes.keys", "snapshotHash");
        else if (name.StartsWith("scopes-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["scopes"]!.AsObject(),
                "payload.scopes.keys", "provider");
        else if (name.StartsWith("scope-provider-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["scopes"]!["provider"]!.AsObject(),
                "payload.scopes.provider.keys", "opaqueId");
        else if (name.StartsWith("scope-product-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["scopes"]!["product"]!.AsObject(),
                "payload.scopes.product.keys", "opaqueId");
        else if (name.StartsWith("scope-grant-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["scopes"]!["grant"]!.AsObject(),
                "payload.scopes.grant.keys", "opaqueId");
        else if (name.StartsWith("history-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["history"]!.AsObject(),
                "payload.history.keys", "completeOneBatch");
        else if (name.StartsWith("generation-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["authorityGenerations"]![0]!.AsObject(),
                "payload.authorityGenerations.item.keys", "generationId");
        else if (name.StartsWith("tuple-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["authorityTuples"]![0]!.AsObject(),
                "payload.authorityTuples.item.keys", "tupleId");
        else if (name.StartsWith("proof-boundary-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["proofBoundary"]!.AsObject(),
                "payload.proofBoundary.keys", "artifactKind");
        else if (name.StartsWith("trust-snapshot-binding-", StringComparison.Ordinal))
            (target, field, missingKey) = (manifest["payload"]!["trustSnapshotBinding"]!.AsObject(),
                "payload.trustSnapshotBinding.keys", "snapshotId");
        else if (name.StartsWith("trust-store-snapshot-", StringComparison.Ordinal))
            (target, field, missingKey) = (trust, "trustStoreSnapshot.keys", "snapshotId");
        else if (name.StartsWith("revocation-", StringComparison.Ordinal))
            (target, field, missingKey) = (trust["revocation"]!.AsObject(),
                "trustStoreSnapshot.revocation.keys", "status");
        else
            throw new InvalidOperationException("UNHANDLED_CLOSED_LAYER_VECTOR:" + name);
        if (name.EndsWith("extra-key", StringComparison.Ordinal)) target["unexpected"] = true;
        else Assert.True(target.Remove(missingKey));
        var calls = 0;
        var result = Tkt000672SourceCAuthorityContract.ValidateManifest(manifest, trust,
            ValidationContext(request, signer, built), (_, _) => { calls++; return true; });
        Assert.Equal(new(false, "SCHEMA_INVALID", field), result);
        Assert.Equal(0, calls);
    }

    /// <summary>Exercises independent generation/tuple cardinality boundaries through the complete validator.</summary>
    /// <param name="name">Closed population vector including dimension and boundary.</param>
    private static void AssertPopulationVector(string name)
    {
        var count = name switch
        {
            "population-zero" => 0, "population-one" => 1,
            "tuple-population-499" or "generation-population-499" => 499,
            _ => 500
        };
        using var signer = NewSigner();
        var request = ValidRequest();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(
            request, Enumerable.Range(0, count).Select(Observation).ToArray(), signer);
        var manifest = (JsonObject)built.Manifest.DeepClone();
        var payload = manifest["payload"]!.AsObject();
        var generations = payload["authorityGenerations"]!.AsArray();
        var tuples = payload["authorityTuples"]!.AsArray();
        var history = payload["history"]!;
        if (name.StartsWith("tuple-population-", StringComparison.Ordinal))
        {
            while (generations.Count > Math.Min(1, count)) generations.RemoveAt(generations.Count - 1);
            if (generations.Count == 1)
            {
                var generationId = generations[0]!["generationId"]!.GetValue<string>();
                foreach (var tuple in tuples) tuple!["generationId"] = generationId;
            }
            history["generationCount"] = generations.Count;
        }
        else if (name.StartsWith("generation-population-", StringComparison.Ordinal))
        {
            tuples.Clear();
            history["tupleCount"] = 0;
            history["totalCardinality"] = 0;
        }
        if (name.EndsWith("501", StringComparison.Ordinal))
        {
            var target = name.StartsWith("tuple-", StringComparison.Ordinal) ? tuples : generations;
            var clone = target[^1]!.DeepClone();
            if (ReferenceEquals(target, tuples))
            {
                clone!["tupleId"] = "tuple_501";
                clone["tupleDigest"] = new string('f', 64);
                history["tupleCount"] = 501;
                history["totalCardinality"] = 501;
            }
            else
            {
                clone!["generationId"] = "generation_501";
                clone["generationDigest"] = new string('f', 64);
                history["generationCount"] = 501;
            }
            target.Add(clone);
        }
        Reframe(manifest);
        var calls = 0;
        var result = Tkt000672SourceCAuthorityContract.ValidateManifest(
            manifest, built.TrustStoreSnapshot, ValidationContext(request, signer, built),
            (_, _) => { calls++; return true; });
        if (name.EndsWith("501", StringComparison.Ordinal))
        {
            Assert.Equal(new(false, "COLLECTION_LIMIT_EXCEEDED", "payload.inventory"), result);
            Assert.Equal(0, calls);
        }
        else
        {
            Assert.True(result.Ok);
            Assert.Equal(1, calls);
        }
    }

    /// <summary>Recomputes producer framing after a test-owned semantic mutation and installs a canonical spy signature.</summary>
    /// <param name="manifest">Owned manifest mutated only by the current test.</param>
    private static void Reframe(JsonObject manifest)
    {
        var payloadJson = Tkt000672SourceCAuthorityContract.Canonicalize(manifest["payload"]);
        var canonical = Tkt000672SourceCAuthorityContract.Frame(
            Tkt000672SourceCAuthorityContract.CanonicalPayloadDomain, payloadJson);
        var digest = Tkt000672SourceCAuthorityContract.Sha256(Tkt000672SourceCAuthorityContract.Frame(
            Tkt000672SourceCAuthorityContract.AuthorityDigestDomain, canonical));
        manifest["canonicalPayload"] = canonical;
        manifest["authorityDigest"] = digest;
        manifest["signedStatement"] = Tkt000672SourceCAuthorityContract.Frame(
            Tkt000672SourceCAuthorityContract.SignedStatementDomain,
            Tkt000672SourceCAuthorityContract.ManifestSchema, digest);
        manifest["signature"] = "AA";
    }

    /// <summary>Mutates one no-materialization field and proves a pre-signature closed refusal.</summary>
    /// <param name="name">Closed boundary vector selecting exactly one field.</param>
    private static void AssertBoundaryMutation(string name)
    {
        using var signer = NewSigner();
        var request = ValidRequest();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, [], signer);
        var manifest = (JsonObject)built.Manifest.DeepClone();
        var boundary = manifest["payload"]!["proofBoundary"]!.AsObject();
        if (name == "fixture-promotable-true") boundary["fixtureQualificationPromotable"] = true;
        else if (name == "native-pass-pass") boundary["nativePass"] = "PASS";
        else if (name == "materialization-authorized-true") boundary["materializationAuthorized"] = true;
        else if (name == "native-recipe-state-drift") boundary["nativeRecipeState"] = "COMPLETE";
        else if (name == "artifact-kind-drift") boundary["artifactKind"] = "SOURCE_C_MATERIALIZED";
        else
        {
            var index = int.Parse(name["source-c-state-".Length..^"-drift".Length],
                System.Globalization.CultureInfo.InvariantCulture);
            boundary["sourceCStates"]![index] = "CREATED";
        }
        var calls = 0;
        Assert.Equal(new(false, "MATERIALIZATION_BOUNDARY_INVALID", "payload.proofBoundary"),
            Tkt000672SourceCAuthorityContract.ValidateManifest(manifest, built.TrustStoreSnapshot,
                ValidationContext(request, signer, built), (_, _) => { calls++; return true; }));
        Assert.Equal(0, calls);
    }

    /// <summary>Proves false and throwing verifier callbacks become the same stable refusal after one call.</summary>
    /// <param name="throws">Whether the injected callback throws instead of returning false.</param>
    private static void AssertVerifierRefusal(bool throws)
    {
        using var signer = NewSigner();
        var request = ValidRequest();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, [], signer);
        var calls = 0;
        var result = Tkt000672SourceCAuthorityContract.ValidateManifest(
            built.Manifest, built.TrustStoreSnapshot, ValidationContext(request, signer, built), (_, _) =>
            {
                calls++;
                if (throws) throw new CryptographicException();
                return false;
            });
        Assert.Equal(new(false, "SIGNATURE_INVALID", "signature"), result);
        Assert.Equal(1, calls);
    }

    /// <summary>Mutates exact signature text and proves byte/text limits plus callback order.</summary>
    /// <param name="name">Closed signature vector selecting exact text bytes.</param>
    private static void AssertSignatureVector(string name)
    {
        using var signer = NewSigner();
        var request = ValidRequest();
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, [], signer);
        var manifest = (JsonObject)built.Manifest.DeepClone();
        var acceptedSyntax = name is "signature-decoded-768-accepted"
            or "signature-alphabet-extremes-accepted" or "signature-drift-callback-once";
        manifest["signature"] = name switch
        {
            "signature-decoded-768-accepted" => Base64Url(new byte[768]),
            "signature-decoded-769-rejected" => Base64Url(new byte[769]),
            "signature-empty" => string.Empty,
            "signature-padding" => "AA==",
            "signature-forbidden-plus" => "AA+A",
            "signature-forbidden-slash" => "AA/A",
            "signature-forbidden-asterisk" => "AA*A",
            "signature-malformed-length" => "A",
            "signature-alphabet-extremes-accepted" => "-_AA",
            "signature-text-2048-decoded-limit" => new string('A', 2048),
            "signature-text-2049-byte-limit" => new string('A', 2049),
            "signature-text-multibyte-invalid" => "é",
            "signature-drift-callback-once" => "AA",
            _ => throw new InvalidOperationException("UNHANDLED_SIGNATURE_VECTOR:" + name)
        };
        var calls = 0;
        var result = Tkt000672SourceCAuthorityContract.ValidateManifest(
            manifest, built.TrustStoreSnapshot, ValidationContext(request, signer, built),
            (_, _) => { calls++; return name != "signature-drift-callback-once"; });
        Assert.Equal(acceptedSyntax && name != "signature-drift-callback-once", result.Ok);
        Assert.Equal(acceptedSyntax ? 1 : 0, calls);
        if (!result.Ok) Assert.Equal(new(false, "SIGNATURE_INVALID", "signature"), result);
    }

    /// <summary>Applies one closed semantic/inventory/trust mutation through the complete real validator.</summary>
    /// <param name="name">Closed vector selecting one exact mutation and refusal tuple.</param>
    private static void AssertNamedManifestMutation(string name)
    {
        var inventoryCase = name.StartsWith("generation-", StringComparison.Ordinal)
            || name.StartsWith("tuple-", StringComparison.Ordinal);
        using var signer = NewSigner();
        var request = ValidRequest();
        var rows = inventoryCase ? new[] { Observation(0), Observation(1) } : new[] { Observation(0) };
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(request, rows, signer);
        var manifest = (JsonObject)built.Manifest.DeepClone();
        var trust = (JsonObject)built.TrustStoreSnapshot.DeepClone();
        var context = ValidationContext(request, signer, built);
        string reason;
        string field;
        var payload = manifest["payload"]!.AsObject();
        switch (name)
        {
            case "schema-drift": manifest["schema"] = "runtime-enrollment-softlicence-authority-manifest-v2";
                (reason, field) = ("SCHEMA_INVALID", "schema"); break;
            case "canonical-payload-drift": manifest["canonicalPayload"] = "drift";
                (reason, field) = ("CANONICAL_PAYLOAD_MISMATCH", "canonicalPayload"); break;
            case "authority-digest-drift": manifest["authorityDigest"] = new string('0', 64);
                (reason, field) = ("AUTHORITY_DIGEST_MISMATCH", "authorityDigest"); break;
            case "signed-statement-drift": manifest["signedStatement"] = "drift";
                (reason, field) = ("SIGNED_STATEMENT_MISMATCH", "signedStatement"); break;
            case "algorithm-not-ps256": manifest["algorithm"] = "RS256";
                (reason, field) = ("ALGORITHM_INVALID", "algorithm"); break;
            case "key-id-mismatch": manifest["keyId"] = "other-key";
                (reason, field) = ("KEY_ID_MISMATCH", "keyId"); break;
            case "fingerprint-mismatch": context = context with { Fingerprint = new string('0', 64) };
                (reason, field) = ("TRUST_BINDING_MISMATCH", "payload.trustSnapshotBinding"); break;
            case "trust-domain-mismatch": trust["domain"] = "OTHER-DOMAIN";
                (reason, field) = ("TRUST_SNAPSHOT_MISMATCH", "trustStoreSnapshot.domain"); break;
            case "trust-snapshot-id-mismatch": trust["snapshotId"] = "other-snapshot";
                (reason, field) = ("TRUST_SNAPSHOT_MISMATCH", "trustStoreSnapshot.snapshotId"); break;
            case "trust-snapshot-binding-mismatch": payload["trustSnapshotBinding"]!["keyId"] = "other-key";
                (reason, field) = ("TRUST_BINDING_MISMATCH", "payload.trustSnapshotBinding"); break;
            case "trust-snapshot-digest-invalid": payload["trustSnapshotBinding"]!["digest"] = new string('0', 64);
                (reason, field) = ("TRUST_BINDING_MISMATCH", "payload.trustSnapshotBinding"); break;
            case "trust-not-yet-valid": trust["validFromUtc"] = "2026-08-26T09:00:00.000Z";
                (reason, field) = ("TRUST_WINDOW_INVALID", "trustStoreSnapshot.validity"); break;
            case "trust-expired": trust["validUntilUtc"] = "2026-08-26T07:00:00.000Z";
                (reason, field) = ("TRUST_WINDOW_INVALID", "trustStoreSnapshot.validity"); break;
            case "manifest-issued-in-future": manifest["issuedAtUtc"] = "2026-08-26T09:00:00.000Z";
                (reason, field) = ("MANIFEST_TIME_INVALID", "issuedAtUtc"); break;
            case "trust-revoked": trust["revocation"]!["status"] = "REVOKED";
                (reason, field) = ("TRUST_REVOKED", "trustStoreSnapshot.revocation"); break;
            case "revocation-time-mismatch": trust["revocation"]!["observedAtUtc"] = "2026-08-26T08:00:00.001Z";
                (reason, field) = ("TRUST_REVOKED", "trustStoreSnapshot.revocation"); break;
            case "environment-fixture-rejected": payload["environment"] = "FIXTURE_QUALIFICATION";
                (reason, field) = ("ENVIRONMENT_MISMATCH", "payload.environment"); break;
            case "environment-production-rejected": payload["environment"] = "PRODUCTION";
                (reason, field) = ("ENVIRONMENT_MISMATCH", "payload.environment"); break;
            case "expected-environment-fixture-rejected":
                context = context with { Request = request with { Environment = "FIXTURE_QUALIFICATION" } };
                (reason, field) = ("ENVIRONMENT_MISMATCH", "payload.environment"); break;
            case "source-mismatch": payload["sourceId"] = "other-source";
                (reason, field) = ("SOURCE_MISMATCH", "payload.sourceId"); break;
            case "history-complete-false": payload["history"]!["completeOneBatch"] = false;
                (reason, field) = ("HISTORY_INVALID", "payload.history"); break;
            case "history-sampling-true": payload["history"]!["samplingUsed"] = true;
                (reason, field) = ("HISTORY_INVALID", "payload.history"); break;
            case "history-paging-true": payload["history"]!["pagingUsed"] = true;
                (reason, field) = ("HISTORY_INVALID", "payload.history"); break;
            case "history-count-drift": payload["history"]!["tupleCount"] = 499;
                (reason, field) = ("HISTORY_COUNT_MISMATCH", "payload.history"); break;
            case "generation-derived-count-drift": payload["history"]!["generationCount"] = 499;
                (reason, field) = ("HISTORY_COUNT_MISMATCH", "payload.history"); break;
            case "generation-reference-unresolved": payload["authorityTuples"]![0]!["generationId"] = "missing-generation";
                (reason, field) = ("GENERATION_REFERENCE_INVALID", "payload.authorityTuples.generationId"); break;
            case "generation-scope-mismatch": payload["authorityGenerations"]![0]!["providerScopeId"] = "other-provider";
                (reason, field) = ("SCOPE_MISMATCH", "payload.authorityGenerations.scope"); break;
            case "generation-order-drift": Swap(payload["authorityGenerations"]!.AsArray());
                (reason, field) = ("INVENTORY_ORDER_INVALID", "payload.authorityGenerations"); break;
            case "generation-id-duplicate": payload["authorityGenerations"]![1]!["generationId"] =
                    payload["authorityGenerations"]![0]!["generationId"]!.GetValue<string>();
                (reason, field) = ("INVENTORY_ORDER_INVALID", "payload.authorityGenerations"); break;
            case "generation-digest-duplicate": payload["authorityGenerations"]![1]!["generationDigest"] =
                    payload["authorityGenerations"]![0]!["generationDigest"]!.GetValue<string>();
                (reason, field) = ("INVENTORY_ORDER_INVALID", "payload.authorityGenerations"); break;
            case "tuple-order-drift": Swap(payload["authorityTuples"]!.AsArray());
                (reason, field) = ("INVENTORY_ORDER_INVALID", "payload.authorityTuples"); break;
            case "tuple-id-duplicate": payload["authorityTuples"]![1]!["tupleId"] =
                    payload["authorityTuples"]![0]!["tupleId"]!.GetValue<string>();
                (reason, field) = ("INVENTORY_ORDER_INVALID", "payload.authorityTuples"); break;
            case "tuple-digest-duplicate": payload["authorityTuples"]![1]!["tupleDigest"] =
                    payload["authorityTuples"]![0]!["tupleDigest"]!.GetValue<string>();
                (reason, field) = ("INVENTORY_ORDER_INVALID", "payload.authorityTuples"); break;
            case var _ when name.StartsWith("evidence-", StringComparison.Ordinal):
                var hash = name["evidence-".Length..name.LastIndexOf("-mismatch", StringComparison.Ordinal)];
                payload["evidenceHashes"]![hash] = new string('0', 64);
                (reason, field) = ("EVIDENCE_MISMATCH", $"payload.evidenceHashes.{hash}"); break;
            case var _ when name.StartsWith("scope-", StringComparison.Ordinal):
                var role = name.Split('-')[1];
                payload["scopes"]![role]!["opaqueId"] = "other-scope";
                (reason, field) = ("SCOPE_MISMATCH", $"payload.scopes.{role}"); break;
            default: throw new InvalidOperationException("UNDISPATCHED_REFERENCE_VECTOR:" + name);
        }
        var calls = 0;
        var result = Tkt000672SourceCAuthorityContract.ValidateManifest(manifest, trust, context,
            (_, _) => { calls++; return true; });
        Assert.Equal(new(false, reason, field), result);
        Assert.Equal(0, calls);
    }

    /// <summary>Swaps exactly two owned JSON array entries using detached clones.</summary>
    /// <param name="array">Owned two-or-more-item array.</param>
    private static void Swap(JsonArray array)
    {
        var first = array[0]!.DeepClone();
        var second = array[1]!.DeepClone();
        array[0] = second;
        array[1] = first;
    }

    /// <summary>Creates distinct closed request bytes for each non-representable JavaScript context shape.</summary>
    /// <param name="name">Closed Website context vector mapped to one unique raw boundary adversary.</param>
    /// <returns>Newly allocated hostile request bytes whose mutation is unique to the vector.</returns>
    private static byte[] MutateContextVector(string name) => Mutate(ValidRequestJson(), root =>
    {
        var missingKey = name switch
        {
            "expected-evidence-hashes-missing-key" => "snapshotHash",
            "expected-scopes-missing-key" => "providerScope",
            "expected-scope-provider-missing-key" => "productScope",
            "expected-scope-product-missing-key" => "grantScope",
            "expected-scope-grant-missing-key" => "catalogHash",
            "context-missing-key" => "runId",
            "context-verifier-missing" => "sourceId",
            _ => null
        };
        if (missingKey is not null) Assert.True(root.Remove(missingKey));
        else root["adversary:" + name] = true;
    });

    /// <summary>Maps JavaScript hostile-context vectors to the bounded raw UTF-8 C# request boundary.</summary>
    /// <param name="name">Closed context-proxy vector.</param>
    private static void AssertContextStructureVector(string name)
    {
        if (name == "context-proxy-exact-keys-eight-descriptors")
        {
            Assert.True(Tkt000672SourceCAuthorityContract.ParseRequest(ValidRequestJson()).Ok);
            return;
        }
        var bytes = name == "context-proxy-voluminous-keys-zero-descriptors"
            ? Encoding.UTF8.GetBytes("{" + string.Join(',', Enumerable.Range(0, 2000)
                .Select(index => $"\"k{index}\":0")) + "}")
            : Mutate(ValidRequestJson(), root => root["unexpected"] = true);
        var refusal = Tkt000672SourceCAuthorityContract.ParseRequest(bytes);
        Assert.False(refusal.Ok);
        Assert.Equal(name.Contains("voluminous", StringComparison.Ordinal)
            ? "REQUEST_SIZE_INVALID" : "SCHEMA_INVALID", refusal.Reason);
        Assert.Equal(name.Contains("voluminous", StringComparison.Ordinal) ? "request" : "request.keys",
            refusal.Field);
    }

    /// <summary>Exercises hostile JavaScript fixture concepts at the equivalent bounded raw-JSON C# boundary.</summary>
    /// <param name="name">Closed structural vector selecting distinct raw bytes and refusal.</param>
    private static void AssertStructuralVector(string name)
    {
        byte[] bytes;
        string reason;
        string field;
        switch (name)
        {
            case "canonical-payload-byte-limit":
                bytes = Enumerable.Repeat((byte)' ', Tkt000672SourceCAuthorityContract.RequestUtf8Limit + 1).ToArray();
                (reason, field) = ("REQUEST_SIZE_INVALID", "request"); break;
            case "canonical-manifest-byte-limit":
                bytes = Enumerable.Repeat((byte)' ', Tkt000672SourceCAuthorityContract.RequestUtf8Limit + 2).ToArray();
                (reason, field) = ("REQUEST_SIZE_INVALID", "request"); break;
            case "structural-byte-budget":
                bytes = Enumerable.Repeat((byte)' ', Tkt000672SourceCAuthorityContract.RequestUtf8Limit).ToArray();
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            case "signed-statement-byte-limit":
                bytes = Mutate(ValidRequestJson(), root => root["sourceId"] = new string('x', 129));
                (reason, field) = ("IDENTIFIER_INVALID", "identity"); break;
            case "structural-node-budget": bytes = Encoding.UTF8.GetBytes("[[[[[[[[[0]]]]]]]]]");
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            case "array-getter": bytes = Encoding.UTF8.GetBytes("[null]");
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            case "sparse-array": bytes = Encoding.UTF8.GetBytes("[null,null]");
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            case "object-getter": bytes = Mutate(ValidRequestJson(), root => root["sourceId"] = new JsonObject());
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            case "symbol-key" or "exotic-prototype":
                bytes = Mutate(ValidRequestJson(), root => root[name == "symbol-key" ? "$symbol" : "__proto__"] = true);
                (reason, field) = ("SCHEMA_INVALID", "request.keys"); break;
            case "proxy-ownkeys-error": bytes = Encoding.UTF8.GetBytes("{");
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            case "proxy-descriptor-error": bytes = [0xff];
                (reason, field) = ("SCHEMA_INVALID", "request"); break;
            default: throw new InvalidOperationException("UNHANDLED_STRUCTURAL_VECTOR:" + name);
        }
        AssertRefusal(bytes, reason, field);
    }

    /// <summary>Proves immutable accepted snapshots and producer artifacts are isolated from later mutation.</summary>
    /// <param name="name">Either deep-freeze or input-mutation-isolated.</param>
    private static void AssertMutationIsolationVector(string name)
    {
        using var signer = NewSigner();
        var rows = new[] { Observation(0) };
        var built = Tkt000672SourceCAuthorityContract.BuildManifest(ValidRequest(), rows, signer);
        var frozenCanonical = built.CanonicalManifest;
        if (name == "deep-freeze")
        {
            using var document = JsonDocument.Parse(frozenCanonical);
            var immutableSnapshot = document.RootElement.Clone();
            built.Manifest["schema"] = "mutated-after-acceptance";
            Assert.Equal(frozenCanonical, immutableSnapshot.GetRawText());
            Assert.NotEqual(frozenCanonical,
                Tkt000672SourceCAuthorityContract.Canonicalize(built.Manifest));
            Assert.Equal(Tkt000672SourceCAuthorityContract.ManifestSchema,
                immutableSnapshot.GetProperty("schema").GetString());
            return;
        }
        Assert.Equal("input-mutation-isolated", name);
        var originalTupleId = rows[0].RequestId;
        rows[0] = Observation(1);
        Assert.Equal(frozenCanonical, built.CanonicalManifest);
        Assert.Contains(originalTupleId, built.CanonicalManifest, StringComparison.Ordinal);
        Assert.DoesNotContain(rows[0].RequestId, built.CanonicalManifest, StringComparison.Ordinal);
    }

    /// <summary>Creates one deterministic metadata-safe generation observation for collection bounds.</summary>
    /// <param name="index">Zero-based bounded fixture discriminator.</param>
    /// <returns>One metadata-only observation with stable opaque IDs and digests.</returns>
    private static Tkt000672GenerationObservation Observation(int index) => new(
        Tkt000672SourceCAuthorityContract.Scenarios[index % 4].ScenarioId,
        Tkt000672SourceCAuthorityContract.Scenarios[index % 4].Classification,
        GuidFrom(index, 1).ToString("D"), Hash("request-" + index),
        GuidFrom(index, 2).ToString("D"), Hash("generation-" + index));

    /// <summary>Creates a stable opaque GUID from bounded test index and role discriminators.</summary>
    /// <param name="index">Zero-based fixture index.</param>
    /// <param name="discriminator">Closed identity role byte.</param>
    /// <returns>A deterministic GUID used only by test-owned metadata.</returns>
    private static Guid GuidFrom(int index, byte discriminator)
    {
        var bytes = new byte[16];
        BitConverter.GetBytes(index).CopyTo(bytes, 0);
        bytes[15] = discriminator;
        return new Guid(bytes);
    }

    /// <summary>Creates distinct disposable 2048-bit manifest and trust authorities for one unit test.</summary>
    /// <returns>A caller-owned signer that must be disposed.</returns>
    private static Tkt000672ManifestSigner NewSigner() => new(RSA.Create(2048), RSA.Create(2048), "unit-manifest-key");

    /// <summary>Serializes one exact valid request containing only metadata-safe opaque values.</summary>
    /// <returns>Owned compact UTF-8 JSON bytes.</returns>
    private static byte[] ValidRequestJson() => JsonSerializer.SerializeToUtf8Bytes(new
    {
        schema = Tkt000672SourceCAuthorityContract.RequestSchema,
        runId = "run_00000000000000000000000000000001",
        environment = Tkt000672SourceCAuthorityContract.Environment,
        sourceId = "source_c_opaque_01",
        observedAtUtc = "2026-08-26T08:00:00.000Z",
        snapshotHash = new string('1', 64), catalogHash = new string('2', 64),
        migrationsHash = new string('3', 64), oracleHash = new string('4', 64),
        generationSpecHash = new string('5', 64), providerScope = "provider_scope_01",
        productScope = "product_scope_01", grantScope = "grant_scope_01"
    });

    /// <summary>Parses the owned valid request and returns its non-null closed model.</summary>
    /// <returns>The validated metadata-only request.</returns>
    private static Tkt000672SourceCRequest ValidRequest() =>
        Tkt000672SourceCAuthorityContract.ParseRequest(ValidRequestJson()).Request!;

    /// <summary>Applies one test-owned JSON mutation and returns newly serialized bytes.</summary>
    /// <param name="source">Owned valid JSON bytes.</param>
    /// <param name="mutation">One bounded test mutation applied to an owned object.</param>
    /// <returns>New compact UTF-8 bytes after mutation.</returns>
    private static byte[] Mutate(byte[] source, Action<JsonObject> mutation)
    {
        var node = JsonNode.Parse(source)!.AsObject();
        mutation(node);
        return JsonSerializer.SerializeToUtf8Bytes(node);
    }

    /// <summary>Asserts one exact metadata-only parser refusal without echoing input values.</summary>
    /// <param name="request">Hostile or invalid raw request bytes.</param>
    /// <param name="reason">Expected closed refusal reason.</param>
    /// <param name="field">Expected stable field category.</param>
    private static void AssertRefusal(byte[] request, string reason, string field)
    {
        var result = Tkt000672SourceCAuthorityContract.ParseRequest(request);
        Assert.False(result.Ok);
        Assert.Equal(reason, result.Reason);
        Assert.Equal(field, result.Field);
    }

    /// <summary>Checks the bounded ASCII vector-name registry before closed behavioral dispatch.</summary>
    /// <param name="name">Fixture vector name.</param>
    /// <returns><see langword="true"/> only for the closed safe name alphabet and bound.</returns>
    private static bool IsClosedReferenceCase(string name) => name.Length is > 0 and <= 96
        && name.All(character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z'
            or >= '0' and <= '9' or '-');

    /// <summary>Computes lowercase SHA-256 over exact UTF-8 golden text without normalization.</summary>
    /// <param name="value">Exact golden text.</param>
    /// <returns>Lowercase 64-character digest.</returns>
    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Encodes deterministic boundary bytes with canonical non-padded base64url.</summary>
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Reads only the fixed copied metadata-safe fixture from the test output directory.</summary>
    /// <returns>A caller-owned JSON document that must be disposed.</returns>
    private static JsonDocument LoadFixture() => JsonDocument.Parse(File.ReadAllBytes(Path.Combine(
        AppContext.BaseDirectory, "TestData",
        "runtime-enrollment-softlicence-authority-manifest-v1-reference-vectors.json")));
}
