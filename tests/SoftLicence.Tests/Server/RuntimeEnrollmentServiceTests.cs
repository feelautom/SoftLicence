using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Reflection;
using System.Globalization;
using System.Linq;
using Microsoft.AspNetCore.Http;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentServiceTests
{
    /// <summary>
    /// Proves the global availability gate keeps its stable 503 precedence even when the
    /// caller supplies an unknown additive release-transition schema.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReleaseTransition_WhenDisabledAndSchemaUnknown_Returns503BeforeSchemaValidation(
        bool rollback)
    {
        var service = new RuntimeEnrollmentService(
            null!, null!, null!, null!, Options.Create(new RuntimeEnrollmentOptions { Mode = "off" }));
        var request = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = "runtime-enrollment-release-unknown-v99"
        };

        var exception = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => rollback
            ? service.RollbackAsync("website-step1", "test-key", "invalid", request)
            : service.UpgradeAsync("website-step1", "test-key", "invalid", request));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, exception.StatusCode);
        Assert.Equal("runtime_enrollment_unavailable", exception.ErrorCode);
    }

    /// <summary>Proves current Prepare responses never expose the provider-owned assignment.</summary>
    /// <param name="schema">Exact temporarily supported response boundary being serialized.</param>
    [Theory]
    [InlineData(RuntimeEnrollmentService.PrepareResponseSchema)]
    [InlineData(RuntimeEnrollmentService.PrepareV2ResponseSchema)]
    public void PrepareResponse_DoesNotSerializeAssignment(string schema)
    {
        var response = new RuntimeEnrollmentPrepareResponse(
            schema, RuntimeEnrollmentService.ProtocolVersion, "pending",
            "11111111-1111-4111-8111-111111111111", 1, "challenge",
            "2026-09-25T07:00:00.0000000Z", "https://runtime.example.test")
        {
            SecurityEpoch = schema == RuntimeEnrollmentService.PrepareResponseSchema ? null : 1
        };

        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.DoesNotContain("\"assignmentId\"", json, StringComparison.Ordinal);
    }

    /// <summary>
    /// Proves v2 evidence binds the immutable lineage-root seat independently from the requested current seat.
    /// </summary>
    [Fact]
    public void AuthorityEvidenceScope_BindsRootAndRequestedSeatsIndependently()
    {
        var scope = new RuntimeEnrollmentAuthorityEvidenceScope(
            "website-step1", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var exact = RuntimeEnrollmentAuthorityTransitionPolicy.ResolveScopedEvidence(
            "SEAT_REASSIGNED", scope,
            [new RuntimeEnrollmentAuthorityScopedDecision("SEAT_ACQUISITION_PROOF", scope)]);

        Assert.True(exact.Contains("SEAT_ACQUISITION_PROOF"));
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.ResolveScopedEvidence(
            "SEAT_REASSIGNED", scope,
            [new RuntimeEnrollmentAuthorityScopedDecision("SEAT_ACQUISITION_PROOF",
                scope with { LineageRootSeatId = Guid.NewGuid() })])
            .Contains("SEAT_ACQUISITION_PROOF"));
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.ResolveScopedEvidence(
            "SEAT_REASSIGNED", scope,
            [new RuntimeEnrollmentAuthorityScopedDecision("SEAT_ACQUISITION_PROOF",
                scope with { RequestedCurrentSeatId = Guid.NewGuid() })])
            .Contains("SEAT_ACQUISITION_PROOF"));
    }

    /// <summary>
    /// Proves the v1 producer cannot emit signed-generation v2 authority material and that the two
    /// serialized roots retain disjoint exact schemas and semantic fields.
    /// </summary>
    [Fact]
    public void ReinstallAuthorityV1Producer_EmitsNoSignedGenerationV2Guarantees()
    {
        var v1 = RuntimeReinstallAuthorityV1Producer.Produce(new RuntimeReinstallAuthorityV1Scope(
            "2", RuntimeReinstallAuthorityV1Decision.IdentityConfirmed,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
            "55555555-5555-4555-8555-555555555555",
            "installation:v1:opaque", "2.3.445", "key-thumbprint:v1", 14,
            "Grant:Opaque:E\u0301", new string('a', 64),
            "66666666-6666-4666-8666-666666666666",
            "77777777-7777-4777-8777-777777777777"));
        var v1Json = JsonSerializer.SerializeToElement(
            v1, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal(RuntimeEnrollmentService.ReinstallAuthorityResponseSchema,
            v1Json.GetProperty("schema").GetString());
        Assert.Equal("identity_confirmed", v1Json.GetProperty("decision").GetString());
        Assert.Equal("Grant:Opaque:E\u0301", v1Json.GetProperty("grantRef").GetString());
        Assert.Equal(new[]
        {
            "bindingId", "correlationId", "decision", "enrollmentId", "grantRef",
            "installationId", "keyThumbprint", "productId", "protocolVersion", "releaseVersion",
            "requestId", "schema", "securityEpoch", "softLicenceLicenseId", "softLicenceSeatId",
            "subjectRefDigestSha256"
        }, v1Json.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.DoesNotContain("authorityDigest", v1Json.EnumerateObject().Select(property => property.Name));
        Assert.DoesNotContain("authorityLineageId", v1Json.EnumerateObject().Select(property => property.Name));
        Assert.DoesNotContain("authorityGenerationId", v1Json.EnumerateObject().Select(property => property.Name));
        Assert.DoesNotContain("signature", v1Json.EnumerateObject().Select(property => property.Name));

        var v2 = new RuntimeEnrollmentSignedGenerationStatementV2
        {
            Schema = "runtime-enrollment-signed-generation-v2",
            Payload = GenerationPayload("Grant:Opaque:E\u0301"),
            AuthorityDigest = new string('b', 64),
            Signature = new RuntimeEnrollmentAuthoritySignatureV2
            {
                Algorithm = "PS256",
                KeyId = "operational-2026-01",
                Value = new string('A', 342)
            }
        };
        var v2Json = JsonSerializer.SerializeToElement(
            v2, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal("runtime-enrollment-signed-generation-v2",
            v2Json.GetProperty("schema").GetString());
        Assert.Equal(new[] { "authorityDigest", "payload", "schema", "signature" },
            v2Json.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.False(v2Json.TryGetProperty("decision", out _));
        Assert.False(v2Json.TryGetProperty("securityEpoch", out _));
    }

    /// <summary>Proves source eligibility cannot elevate the identity-only v1 decision.</summary>
    [Fact]
    public void ReinstallAuthorityV1DecisionPolicy_UsesClosedCapabilities()
    {
        var eligibleIdentity = RuntimeReinstallAuthorityV1DecisionPolicy.Classify(
            sourceLicenseEligible: true);
        var ineligibleIdentity = RuntimeReinstallAuthorityV1DecisionPolicy.Classify(
            sourceLicenseEligible: false);

        Assert.Equal(RuntimeReinstallAuthorityV1Decision.IdentityConfirmed, eligibleIdentity);
        Assert.True(RuntimeReinstallAuthorityV1DecisionPolicy.Permits(
            eligibleIdentity, RuntimeReinstallAuthorityV1Capability.ConfirmBoundRuntimeIdentity));
        Assert.Equal(RuntimeReinstallAuthorityV1Decision.IdentityConfirmed, ineligibleIdentity);
        Assert.True(RuntimeReinstallAuthorityV1DecisionPolicy.Permits(
            ineligibleIdentity, RuntimeReinstallAuthorityV1Capability.ConfirmBoundRuntimeIdentity));
    }

    /// <summary>Proves the v1 producer rejects decisions outside the closed enum vocabulary.</summary>
    [Fact]
    public void ReinstallAuthorityV1Producer_RejectsUnknownDecision()
    {
        var input = new RuntimeReinstallAuthorityV1Scope(
            "2", (RuntimeReinstallAuthorityV1Decision)int.MaxValue,
            "request", "correlation", "product", "enrollment", "binding",
            "installation", "release", "key", 1, "grant", "subject", "license", "seat");

        Assert.Throws<InvalidOperationException>(() => RuntimeReinstallAuthorityV1Producer.Produce(input));
    }

    /// <summary>Proves undeclared capabilities fail closed instead of inheriting authority.</summary>
    [Fact]
    public void ReinstallAuthorityV1DecisionPolicy_RejectsUnknownCapability()
    {
        Assert.Throws<InvalidOperationException>(() => RuntimeReinstallAuthorityV1DecisionPolicy.Permits(
            RuntimeReinstallAuthorityV1Decision.IdentityConfirmed,
            (RuntimeReinstallAuthorityV1Capability)int.MaxValue));
    }

    /// <summary>Proves genesis requires all three expected identifiers to be null.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_GenesisRequiresNullExpectedIdentity()
    {
        var request = AuthorityRequest("grant:exact");
        request.Transition.Kind = "genesis";
        request.Transition.ReasonCode = "INITIAL_ENROLLMENT";
        request.ExpectedAuthorityLineageId = null;
        request.ExpectedCurrentGenerationId = null;
        request.ExpectedPredecessorGenerationId = null;
        Assert.True(RuntimeEnrollmentAuthorityTransitionPolicy.IsAllowed(request));
        request.ExpectedCurrentGenerationId = "11111111-1111-4111-8111-111111111111";
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.IsAllowed(request));
    }

    /// <summary>Proves a successor requires complete ordinally equal current and predecessor identifiers.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_SuccessorRejectsMissingOrDivergentPredecessor()
    {
        var request = AuthorityRequest("grant:exact");
        request.Transition.Kind = "release";
        request.Transition.ReasonCode = "APPROVED_RELEASE_ADVANCE";
        request.ExpectedAuthorityLineageId = "11111111-1111-4111-8111-111111111111";
        request.ExpectedCurrentGenerationId = "22222222-2222-4222-8222-222222222222";
        request.ExpectedPredecessorGenerationId = request.ExpectedCurrentGenerationId;
        Assert.True(RuntimeEnrollmentAuthorityTransitionPolicy.IsAllowed(request));
        request.ExpectedPredecessorGenerationId = "33333333-3333-4333-8333-333333333333";
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.IsAllowed(request));
        request.ExpectedPredecessorGenerationId = null;
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.IsAllowed(request));
    }

    /// <summary>
    /// Proves equal primitive values remain separate domains and each domain advances only through its
    /// own constructor and successor relation.
    /// </summary>
    [Fact]
    public void AuthorityNumericDomains_AdvanceIndependentlyAndFailClosedAtTheirOwnBounds()
    {
        Assert.True(RuntimeEnrollmentSecurityEpoch.TryCreate(7, out var epoch));
        Assert.True(RuntimeEnrollmentLineageSequence.TryCreate(7, out var sequence));
        Assert.Equal(7, epoch.Value);
        Assert.Equal(7, sequence.Value);

        Assert.True(RuntimeEnrollmentSecurityEpoch.TryCreate(8, out var nextEpoch));
        Assert.True(RuntimeEnrollmentLineageSequence.TryCreate(8, out var nextSequence));
        Assert.True(nextEpoch.IsDirectSuccessorOf(epoch));
        Assert.True(nextSequence.IsDirectSuccessorOf(sequence));
        Assert.False(nextEpoch.IsRegressionFrom(epoch));

        Assert.False(RuntimeEnrollmentSecurityEpoch.TryCreate(-1, out _));
        Assert.False(RuntimeEnrollmentLineageSequence.TryCreate(-1, out _));
        Assert.False(RuntimeEnrollmentLineageSequence.TryCreate(
            RuntimeEnrollmentLineageSequence.MaximumWireValue + 1, out _));
        Assert.True(RuntimeEnrollmentLineageSequence.TryCreate(
            RuntimeEnrollmentLineageSequence.MaximumWireValue, out var maximum));
        Assert.False(maximum.TryNext(out _));
    }

    /// <summary>
    /// Proves a lineage sequence advance does not require or imply a security-epoch advance.
    /// </summary>
    [Fact]
    public void AuthorityTransitionPolicy_LineageSequenceAdvanceDoesNotAdvanceSecurityEpoch()
    {
        var previous = GenerationPayload("grant:exact");
        var current = CopyPayload(previous);
        previous.Transition.OccurredAtUtc = "2026-08-22T16:00:01.000000Z";
        current.PreviousGenerationId = previous.AuthorityGenerationId;
        current.Sequence = previous.Sequence + 1;
        current.Release.Version = "2.3.446";
        current.Release.ArtifactSetDigest = new string('3', 64);
        current.Transition.Kind = "release";
        current.Transition.ReasonCode = "APPROVED_RELEASE_ADVANCE";
        current.Transition.OccurredAtUtc = "2026-08-22T16:00:02.000000Z";

        var decision = RuntimeEnrollmentAuthorityTransitionPolicy.Evaluate(
            previous, current, new(["APPROVED_ARTIFACT_SET"]),
            DateTimeOffset.Parse("2026-08-22T16:00:02Z", CultureInfo.InvariantCulture));

        Assert.True(decision.Accepted, decision.ErrorCode);
        Assert.Equal(previous.Key.SecurityEpoch, current.Key.SecurityEpoch);
    }

    /// <summary>Proves request and attempt replay are classified from exact immutable identity only.</summary>
    [Fact]
    public void AuthorityReplayRules_CloseExactAndDivergentOutcomes()
    {
        var requestId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var digest = new string('a', 64);
        var request = new RuntimeEnrollmentAuthorityRequest
            { RequestId = requestId, RequestDigest = digest };
        var attempt = new RuntimeEnrollmentAuthorityAttempt
            { RequestId = requestId, RequestDigest = digest };

        Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.ExactAttempt,
            RuntimeEnrollmentAuthorityReplayRules.Classify(attempt, request, requestId, digest));
        attempt.RequestDigest = new string('b', 64);
        Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.AttemptIdReuse,
            RuntimeEnrollmentAuthorityReplayRules.Classify(attempt, request, requestId, digest));
        Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.ExactRequest,
            RuntimeEnrollmentAuthorityReplayRules.Classify(null, request, requestId, digest));
        Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.RequestReplayDivergence,
            RuntimeEnrollmentAuthorityReplayRules.Classify(
                null, request, requestId, new string('b', 64)));
        Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.New,
            RuntimeEnrollmentAuthorityReplayRules.Classify(null, null, requestId, digest));
    }

    /// <summary>Proves two absent-read candidates converge on one stored UUID/PS256 response through the production replay classifier.</summary>
    [Fact]
    public async Task AuthorityReplayRules_ConcurrentCandidatesReturnWinnerBytes()
    {
        var requestId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var digest = new string('a', 64);
        using var rsa = RSA.Create(2048);
        var input = "authority-race"u8.ToArray();
        var signatures = new[]
        {
            rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
        };
        Assert.False(signatures[0].SequenceEqual(signatures[1]));
        var generationIds = new[] { Guid.NewGuid(), Guid.NewGuid() };
        RuntimeEnrollmentAuthorityRequest? stored = null;
        var persistCount = 0;
        var sync = new object();
        using var barrier = new Barrier(2);
        async Task<byte[]> CompeteAsync(int index)
        {
            Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.New,
                RuntimeEnrollmentAuthorityReplayRules.Classify(null, stored, requestId, digest));
            barrier.SignalAndWait();
            await Task.Yield();
            lock (sync)
            {
                var flow = new RuntimeEnrollmentAuthorityIssuanceFlow();
                flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.Parsed);
                flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.ReplayLocks);
                var decision = RuntimeEnrollmentAuthorityReplayRules.Classify(
                    null, stored, requestId, digest);
                flow.Advance(RuntimeEnrollmentAuthorityIssuancePhase.ReplayResolved);
                if (decision == RuntimeEnrollmentAuthorityReplayDecision.New)
                {
                    var response = Encoding.UTF8.GetBytes(
                        generationIds[index].ToString("D") + ":" + Convert.ToBase64String(signatures[index]));
                    stored = new RuntimeEnrollmentAuthorityRequest
                    {
                        RequestId = requestId, RequestDigest = digest, ResultCode = "ACCEPTED",
                        AuthorityLineageId = Guid.NewGuid(), AuthorityGenerationId = generationIds[index],
                        ExactResponseUtf8 = response, HttpStatusCode = StatusCodes.Status200OK
                    };
                    foreach (var phase in new[]
                    {
                        RuntimeEnrollmentAuthorityIssuancePhase.IdentityResolved,
                        RuntimeEnrollmentAuthorityIssuancePhase.EvidenceResolved,
                        RuntimeEnrollmentAuthorityIssuancePhase.LifecycleValidated,
                        RuntimeEnrollmentAuthorityIssuancePhase.Signed,
                        RuntimeEnrollmentAuthorityIssuancePhase.Persisted,
                        RuntimeEnrollmentAuthorityIssuancePhase.AttemptStored
                    }) flow.Advance(phase);
                    persistCount++;
                    return response;
                }
                Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.ExactRequest, decision);
                flow.CompleteReplay();
                return [.. stored!.ExactResponseUtf8];
            }
        }

        var responses = await Task.WhenAll(
            Task.Run(() => CompeteAsync(0)), Task.Run(() => CompeteAsync(1)));

        Assert.Equal(1, persistCount);
        Assert.Equal(responses[0], responses[1]);
        Assert.Equal(StatusCodes.Status200OK,
            RuntimeEnrollmentAuthorityV2Coordinator.ReplayStatus("ACCEPTED", StatusCodes.Status201Created));
    }

    /// <summary>Proves immutable attempt storage projects exact IDs/digest and closed lowercase contract status.</summary>
    [Fact]
    public void AuthorityAttempt_ToContract_UsesClosedV2Projection()
    {
        var attempt = new RuntimeEnrollmentAuthorityAttempt
        {
            AttemptId = Guid.Parse("11111111-1111-4111-8111-111111111111"),
            RequestId = Guid.Parse("22222222-2222-4222-8222-222222222222"),
            RequestDigest = new string('a', 64),
            AuthorityLineageId = Guid.Parse("33333333-3333-4333-8333-333333333333"),
            AuthorityGenerationId = Guid.Parse("44444444-4444-4444-8444-444444444444"),
            Status = "ACCEPTED", CreatedAtUtc = new DateTime(2026, 8, 24, 10, 0, 0, DateTimeKind.Utc),
            CompletedAtUtc = new DateTime(2026, 8, 24, 10, 0, 1, DateTimeKind.Utc)
        };

        var contract = attempt.ToContract();

        Assert.Equal("runtime-enrollment-authority-discovery-attempt-v2", contract.Schema);
        Assert.Equal("accepted", contract.Status);
        Assert.Equal(attempt.RequestDigest, contract.RequestDigest);
        Assert.Equal(attempt.AuthorityGenerationId!.Value.ToString("D"), contract.AuthorityGenerationId);
    }

    /// <summary>Proves release advancement requires the exact version-and-artifact pair and no extra leaf.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_RequiresExactlyOnePrimaryDelta()
    {
        var previous = GenerationPayload("grant:exact");
        var current = GenerationPayload("grant:exact");
        previous.Transition.OccurredAtUtc = "2026-08-22T16:00:01.000000Z";
        current.PreviousGenerationId = previous.AuthorityGenerationId;
        current.Sequence = 1;
        current.Transition.Kind = "release";
        current.Transition.ReasonCode = "APPROVED_RELEASE_ADVANCE";
        current.Release.Version = "2.3.446";
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.HasExactPrimaryDelta(previous, current));
        current.Release.ArtifactSetDigest = new string('3', 64);
        Assert.True(RuntimeEnrollmentAuthorityTransitionPolicy.HasExactPrimaryDelta(previous, current));
        current.Key.SecurityEpoch++;
        Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.HasExactPrimaryDelta(previous, current));
    }

    /// <summary>Proves the production registry contains exactly the canonical 13 kind/reason pairs.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_RegistryIsClosedAndCanonical()
    {
        var pairs = RuntimeEnrollmentAuthorityTransitionPolicy.Registry
            .Select(rule => $"{rule.Kind}:{rule.ReasonCode}").ToArray();

        Assert.Equal(new[]
        {
            "genesis:INITIAL_ENROLLMENT",
            "release:APPROVED_RELEASE_ADVANCE",
            "binding:BINDING_REPLACEMENT",
            "enrollment:ENROLLMENT_ACTIVATED",
            "enrollment:ENROLLMENT_EXPIRED",
            "enrollment:ENROLLMENT_REPLACED",
            "revocation:AUTHORITY_REVOKED",
            "key_rotation:SIGNING_KEY_ROTATED",
            "security_epoch:SECURITY_EPOCH_ADVANCED",
            "reinstall:INSTALLATION_REINSTALLED",
            "recovery:RECOVERY_AUTHORIZED",
            "repair:REPAIR_AUTHORIZED",
            "seat:SEAT_REASSIGNED"
        }, pairs);
        Assert.Equal(pairs.Length, pairs.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>Proves every canonical registry row accepts its exact leaf, edge, evidence, and chronology.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_AllCanonicalRowsAreExecutable()
    {
        foreach (var rule in RuntimeEnrollmentAuthorityTransitionPolicy.Registry)
        {
            var transition = ValidTransition(rule.ReasonCode);
            var evidence = new RuntimeEnrollmentAuthorityEvidence(rule.Evidence);

            var decision = RuntimeEnrollmentAuthorityTransitionPolicy.Evaluate(
                transition.Previous, transition.Current, evidence,
                DateTimeOffset.ParseExact(transition.Current.Transition.OccurredAtUtc,
                    "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal));

            Assert.True(decision.Accepted, $"{rule.Kind}:{rule.ReasonCode}:{decision.ErrorCode}");
        }
    }

    /// <summary>
    /// Proves every business evidence label is accepted only for its owning reason and the exact complete
    /// client/product/binding/enrollment/license/seat/lineage/head scope.
    /// </summary>
    [Fact]
    public void AuthorityEvidenceResolver_RejectsEveryCrossScopeDecisionPerLabel()
    {
        var scope = new RuntimeEnrollmentAuthorityEvidenceScope(
            "website-step1", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        foreach (var rule in RuntimeEnrollmentAuthorityTransitionPolicy.Registry)
        foreach (var label in rule.Evidence)
        {
            var exact = RuntimeEnrollmentAuthorityTransitionPolicy.ResolveScopedEvidence(
                rule.ReasonCode, scope, [new RuntimeEnrollmentAuthorityScopedDecision(label, scope)]);
            Assert.True(exact.Contains(label), $"{rule.ReasonCode}:{label}:exact");

            var crossScopes = new[]
            {
                scope with { ClientId = "website-step2" }, scope with { ProductId = Guid.NewGuid() },
                scope with { BindingId = Guid.NewGuid() }, scope with { EnrollmentId = Guid.NewGuid() },
                scope with { LicenseId = Guid.NewGuid() },
                scope with { LineageRootSeatId = Guid.NewGuid() },
                scope with { RequestedCurrentSeatId = Guid.NewGuid() },
                scope with { LineageId = Guid.NewGuid() }, scope with { HeadGenerationId = Guid.NewGuid() }
            };
            foreach (var crossScope in crossScopes)
                Assert.False(RuntimeEnrollmentAuthorityTransitionPolicy.ResolveScopedEvidence(
                    rule.ReasonCode, scope,
                    [new RuntimeEnrollmentAuthorityScopedDecision(label, crossScope)]).Contains(label),
                    $"{rule.ReasonCode}:{label}:cross-scope");
        }
    }

    /// <summary>Proves recovery changes only the compromised predecessor key and advances its epoch once.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_RecoveryRequiresNewKeyEpochAndClosedScope()
    {
        var valid = ValidTransition("RECOVERY_AUTHORIZED");
        Assert.True(Evaluate(valid).Accepted);

        var sameKey = ValidTransition("RECOVERY_AUTHORIZED");
        sameKey.Current.Key.AuthorityKeyId = sameKey.Previous!.Key.AuthorityKeyId;
        Assert.Equal("RECOVERY_KEY_EPOCH_MISMATCH", Evaluate(sameKey).ErrorCode);

        var staleEpoch = ValidTransition("RECOVERY_AUTHORIZED");
        staleEpoch.Current.Key.SecurityEpoch = staleEpoch.Previous!.Key.SecurityEpoch;
        Assert.Equal("RECOVERY_KEY_EPOCH_MISMATCH", Evaluate(staleEpoch).ErrorCode);

        var releaseChanged = ValidTransition("RECOVERY_AUTHORIZED");
        releaseChanged.Current.Release.Version = "2.3.446";
        Assert.Equal("TRANSITION_SCOPE_VIOLATION", Evaluate(releaseChanged).ErrorCode);
    }

    /// <summary>Proves recovery authority is commercial only for live resulting enrollment states.</summary>
    [Theory]
    [InlineData("pending", 0)]
    [InlineData("active", 0)]
    [InlineData("expired", 1)]
    [InlineData("revoked", 1)]
    public void AuthorityRecovery_ResultClassFollowsResultingState(
        string resultingState,
        int expected)
    {
        var (_, payload) = ValidTransition("RECOVERY_AUTHORIZED");
        payload.Enrollment.State = resultingState;

        Assert.Equal(expected, (int)RuntimeEnrollmentAuthorityV2Coordinator.ClassifyResult(payload));
    }

    /// <summary>Proves every epoch-changing transition rejects a silent numeric jump.</summary>
    [Theory]
    [InlineData("SIGNING_KEY_ROTATED", "KEY_EPOCH_MISMATCH")]
    [InlineData("SECURITY_EPOCH_ADVANCED", "SECURITY_EPOCH_STEP_INVALID")]
    [InlineData("RECOVERY_AUTHORIZED", "RECOVERY_KEY_EPOCH_MISMATCH")]
    public void AuthorityTransitionPolicy_EpochChangesRequireDirectSuccessor(
        string reasonCode, string expectedError)
    {
        var transition = ValidTransition(reasonCode);
        transition.Current.Key.SecurityEpoch = transition.Previous!.Key.SecurityEpoch + 2;

        Assert.Equal(expectedError, Evaluate(transition).ErrorCode);
    }

    /// <summary>
    /// Proves each closed recovery-preparation diagnostic maps to its normative public body and status
    /// without copying preparation tokens or detached signatures into the response.
    /// </summary>
    /// <param name="diagnostic">Closed internal diagnostic produced by the recovery preparation boundary.</param>
    /// <param name="category">Expected normative public error category.</param>
    /// <param name="statusCode">Expected stable HTTP status.</param>
    [Theory]
    [InlineData("RECOVERY_PREPARATION_MALFORMED", "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE", 400)]
    [InlineData("RECOVERY_PREPARATION_SCOPE_MISMATCH", "RUNTIME_ENROLLMENT_DENIED", 403)]
    [InlineData("RECOVERY_PREPARATION_EXPIRED", "RUNTIME_ENROLLMENT_DENIED", 403)]
    [InlineData("RECOVERY_PREPARATION_NOT_AUTHORIZED", "RUNTIME_ENROLLMENT_DENIED", 403)]
    [InlineData("RECOVERY_PREPARATION_PAYLOAD_MISMATCH", "RUNTIME_ENROLLMENT_DENIED", 403)]
    [InlineData("AUTHORITY_STATE_CONFLICT", "RUNTIME_ENROLLMENT_CONFLICT", 409)]
    [InlineData("KEY_REGISTRY_STALE", "RUNTIME_ENROLLMENT_TEMPORARILY_UNAVAILABLE", 503)]
    public void AuthorityRecoveryPreparationDiagnostics_MapToClosedPublicFailures(
        string diagnostic, string category, int statusCode)
    {
        var coordinator = typeof(RuntimeEnrollmentAuthorityV2Coordinator);
        var publicCategory = coordinator.GetMethod(
            "PublicCategory", BindingFlags.NonPublic | BindingFlags.Static)!;
        var statusFor = coordinator.GetMethod(
            "StatusFor", BindingFlags.NonPublic | BindingFlags.Static)!;
        var errorBody = coordinator.GetMethod(
            "ErrorBody", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(category, publicCategory.Invoke(null, [diagnostic]));
        Assert.Equal(statusCode, statusFor.Invoke(null, [diagnostic]));
        var body = Assert.IsType<byte[]>(errorBody.Invoke(null, [diagnostic]));
        Assert.Equal($"{{\"error\":\"{category}\"}}", Encoding.UTF8.GetString(body));
        Assert.DoesNotContain("token", Encoding.UTF8.GetString(body), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("signature", Encoding.UTF8.GetString(body), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Proves required leaves, forbidden leaves, edge, kind, and chronology fail closed.</summary>
    [Fact]
    public void AuthorityTransitionPolicy_InvalidMatricesUseDeterministicDiagnostics()
    {
        var release = ValidTransition("APPROVED_RELEASE_ADVANCE");
        release.Current.Release.ArtifactSetDigest = release.Previous!.Release.ArtifactSetDigest;
        Assert.Equal("TRANSITION_REQUIRED_CHANGE_MISSING", Evaluate(release).ErrorCode);

        var repair = ValidTransition("REPAIR_AUTHORIZED");
        repair.Current.Binding.HardwareIdDigest = new string('9', 64);
        Assert.Equal("REPAIR_SCOPE_VIOLATION", Evaluate(repair).ErrorCode);

        var activation = ValidTransition("ENROLLMENT_ACTIVATED");
        activation.Previous!.Enrollment.State = "active";
        activation.Current.Enrollment.State = "pending";
        Assert.Equal("ENROLLMENT_TRANSITION_INVALID", Evaluate(activation).ErrorCode);

        var terminal = ValidTransition("ENROLLMENT_ACTIVATED");
        terminal.Previous!.Enrollment.State = "expired";
        Assert.Equal("ENROLLMENT_TERMINAL", Evaluate(terminal).ErrorCode);

        var wrongKind = ValidTransition("SEAT_REASSIGNED");
        wrongKind.Current.Transition.Kind = "release";
        Assert.Equal("TRANSITION_KIND_REASON_MISMATCH", Evaluate(wrongKind).ErrorCode);

        var wrongSequence = ValidTransition("REPAIR_AUTHORIZED");
        wrongSequence.Current.Sequence = wrongSequence.Previous!.Sequence;
        Assert.Equal("GENERATION_SEQUENCE_INVALID", Evaluate(wrongSequence).ErrorCode);

        var chronology = ValidTransition("REPAIR_AUTHORIZED");
        chronology.Current.Transition.OccurredAtUtc = chronology.Previous!.Transition.OccurredAtUtc;
        Assert.Equal("TRANSITION_TIME_REGRESSION", Evaluate(chronology).ErrorCode);

        var missingEvidence = ValidTransition("BINDING_REPLACEMENT");
        Assert.Equal("BINDING_CHANGE_NOT_AUTHORIZED",
            RuntimeEnrollmentAuthorityTransitionPolicy.Evaluate(
                missingEvidence.Previous, missingEvidence.Current,
                new RuntimeEnrollmentAuthorityEvidence([]), ContractNow).ErrorCode);
    }

    /// <summary>Proves sealed snapshot classifiers distinguish current, retired, recovery, purpose, and rotation outcomes.</summary>
    [Fact]
    public void AuthorityLifecycleProof_ClassifiesClosedTransitionOutcomes()
    {
        var now = new DateTimeOffset(2026, 8, 24, 10, 0, 0, TimeSpan.Zero);
        using var active = RSA.Create(2048);
        using var next = RSA.Create(2048);
        using var retired = RSA.Create(2048);
        using var compromised = RSA.Create(2048);
        using var revoked = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        using var revokedRecovery = RSA.Create(2048);
        using var registry = RSA.Create(2048);
        var options = new RuntimeAuthorityGenerationSigningOptions
        {
            ActiveSigningKeyId = "operational-active",
            RegistrySnapshotId = "snapshot-1",
            RegistrySnapshotVersion = 1,
            Keys =
            [
                new() { KeyId = "operational-active", Purpose = "operational", Domain = "generation",
                    ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddDays(-2),
                    PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                    PrivateKeyPem = active.ExportPkcs8PrivateKeyPem() },
                new() { KeyId = "operational-compromised", Purpose = "operational", Domain = "generation",
                    ContractVersion = 2, Status = "revoked", ActivatedAtUtc = now.AddDays(-3),
                    CompromiseFromUtc = now.AddHours(-2), RevokedAtUtc = now.AddHours(-1),
                    RevocationReason = "COMPROMISED", PublicKeyPem = compromised.ExportSubjectPublicKeyInfoPem() },
                new() { KeyId = "operational-next", Purpose = "operational", Domain = "generation",
                    ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddDays(-1),
                    PublicKeyPem = next.ExportSubjectPublicKeyInfoPem() },
                new() { KeyId = "operational-retired", Purpose = "operational", Domain = "generation",
                    ContractVersion = 2, Status = "retired", ActivatedAtUtc = now.AddDays(-3),
                    RetiredAtUtc = now.AddDays(-1), PublicKeyPem = retired.ExportSubjectPublicKeyInfoPem() },
                new() { KeyId = "operational-revoked", Purpose = "operational", Domain = "generation",
                    ContractVersion = 2, Status = "revoked", ActivatedAtUtc = now.AddDays(-3),
                    RevokedAtUtc = now.AddHours(-1), RevocationReason = "REVOKED",
                    PublicKeyPem = revoked.ExportSubjectPublicKeyInfoPem() },
                new() { KeyId = "recovery-active", Purpose = "recovery", Domain = "recovery",
                    ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddDays(-2),
                    PublicKeyPem = recovery.ExportSubjectPublicKeyInfoPem() },
                new() { KeyId = "recovery-revoked", Purpose = "recovery", Domain = "recovery",
                    ContractVersion = 2, Status = "revoked", ActivatedAtUtc = now.AddDays(-3),
                    RevokedAtUtc = now.AddHours(-1), RevocationReason = "REVOKED",
                    PublicKeyPem = revokedRecovery.ExportSubjectPublicKeyInfoPem() }
            ]
        };
        var crypto = new RuntimeEnrollmentAuthorityCryptography(
            new AuthorityFixedTimeProvider(now), registry.ExportSubjectPublicKeyInfo());
        var input = crypto.GetRegistrySnapshotAuthenticationInput(options, now).Value!;
        var evidence = crypto.AuthenticateRegistrySnapshot(options, now,
            registry.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).Value!;
        var proof = crypto.CreateTrustedSnapshotProof(evidence);

        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid,
            proof.ClassifyCurrentSigner("operational-active", now, now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Retired,
            proof.ClassifyCurrentSigner("operational-retired", now, now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid,
            proof.ClassifyCurrentSigner("operational-retired", now.AddDays(-2), now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Compromised,
            proof.ClassifyCurrentSigner("operational-compromised", now.AddMinutes(-90), now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Revoked,
            proof.ClassifyCurrentSigner("operational-compromised", now.AddHours(-1), now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid,
            proof.ClassifyCurrentSigner("operational-compromised", now.AddHours(-3), now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Revoked,
            proof.ClassifyCurrentSigner("operational-revoked", now, now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid,
            proof.ClassifyRecovery("recovery-active", now, now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.WrongPurpose,
            proof.ClassifyRecovery("operational-active", now, now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid,
            proof.ClassifyRotation("operational-active", "operational-next", now, now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.PredecessorMismatch,
            proof.ClassifyRotation("operational-active", "operational-active", now, now).Outcome);
        var recoveryDecision = RuntimeEnrollmentAuthorityV2Coordinator.ClassifyRecoveryLifecycle(
            proof, "operational-compromised", "operational-active", "recovery-active", now, now);
        Assert.True(recoveryDecision.Accepted("operational-compromised", "operational-active"));
        Assert.False(recoveryDecision.Accepted("operational-active", "operational-active"));
        Assert.False(RuntimeEnrollmentAuthorityV2Coordinator.ClassifyRecoveryLifecycle(
            proof, "operational-compromised", "operational-active", "recovery-revoked", now, now)
            .Accepted("operational-compromised", "operational-active"));
    }
    /// <summary>Verifies the hardware migration path is frozen into the signed proof contract.</summary>
    [Fact]
    public void HardwareAuthorityMigration_ProofPathIsExact()
    {
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");

        Assert.Equal(
            "/api/v1/runtime-enrollments/11111111-1111-4111-8111-111111111111/hardware-authority-migrations",
            RuntimeEnrollmentService.BuildProofPath(enrollmentId, "hardware-authority-migration"));
    }

    /// <summary>Verifies the strict migration schema accepts only canonical V1 authority values.</summary>
    [Fact]
    public void HardwareAuthorityMigration_ValidationAcceptsCanonicalContract()
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateHardwareAuthorityMigration", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var validated = validate.Invoke(null,
        [
            enrollmentId, ValidHardwareMigrationRequest(enrollmentId), ValidMigrationProofHeaders(), new string('d', 64)
        ]);

        Assert.NotNull(validated);
    }

    /// <summary>Verifies case, length, algorithm, version, and extension near misses fail closed.</summary>
    [Theory]
    [InlineData("legacy-lowercase")]
    [InlineData("stable-short")]
    [InlineData("legacy-algorithm")]
    [InlineData("stable-algorithm")]
    [InlineData("sdk-old")]
    [InlineData("pre-uuid-legacy-algorithm")]
    [InlineData("pre-uuid-stable-algorithm")]
    [InlineData("schema-case")]
    [InlineData("extension")]
    public void HardwareAuthorityMigration_ValidationRejectsNearMisses(string mutation)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateHardwareAuthorityMigration", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = ValidHardwareMigrationRequest(enrollmentId);
        switch (mutation)
        {
            case "legacy-lowercase": request.LegacyHardwareId = "a6d3eed115bc84ad"; break;
            case "stable-short": request.HardwareIdV2 = "A6D3EED115BC84A"; break;
            case "legacy-algorithm": request.LegacyAlgorithm = "legacy-wmi-any-disk"; break;
            case "stable-algorithm": request.HardwareIdV2Algorithm = "v2-wmi-first-disk"; break;
            case "sdk-old": request.SdkVersion = "1.1.14"; break;
            case "pre-uuid-legacy-algorithm": request.LegacyAlgorithm = "legacy-wmi-first-disk"; break;
            case "pre-uuid-stable-algorithm": request.HardwareIdV2Algorithm = "v2-wmi-disk-index-0"; break;
            case "schema-case": request.Schema = request.Schema!.ToUpperInvariant(); break;
            case "extension": request.ExtensionData = new() { ["unexpected"] = default }; break;
        }

        var thrown = Assert.Throws<TargetInvocationException>(() => validate.Invoke(null,
        [
            enrollmentId, request, ValidMigrationProofHeaders(), new string('d', 64)
        ]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    /// <summary>
    /// TKT-001277 lot 5: the target identifier must be the one the SDK 2.0 rule derives from an accepted UUID.
    /// Absent, generic, malformed or oversized UUIDs and non-derived targets are refused as device_refused.
    /// </summary>
    [Theory]
    [InlineData(null, "6B775195D2F86F36")]
    [InlineData("", "6B775195D2F86F36")]
    [InlineData("03000200-0400-0500-0006-000700080009", "6B775195D2F86F36")]
    [InlineData("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "6B775195D2F86F36")]
    [InlineData("not-a-uuid", "6B775195D2F86F36")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E33", "6B775195D2F86F36")]
    [InlineData("4C4C4544-0051-3610-8052-B7C04F4A4E32", "6B775195D2F86F37")]
    public void HardwareAuthorityMigration_ValidationRefusesTargetsNotDerivedFromAnAcceptedUuid(
        string? systemUuid, string hardwareIdV2)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateHardwareAuthorityMigration", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = ValidHardwareMigrationRequest(enrollmentId);
        request.SystemUuid = systemUuid;
        request.HardwareIdV2 = hardwareIdV2;

        var thrown = Assert.Throws<TargetInvocationException>(() => validate.Invoke(null,
        [
            enrollmentId, request, ValidMigrationProofHeaders(), new string('d', 64)
        ]));

        var refused = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        Assert.Equal("device_refused", refused.ErrorCode);
    }

    /// <summary>The UUID is canonicalized by the SDK rule: braces and lowercase hex derive the same target.</summary>
    [Theory]
    [InlineData("{4c4c4544-0051-3610-8052-b7c04f4a4e32}")]
    [InlineData(" 4C4C4544-0051-3610-8052-B7C04F4A4E32 ")]
    public void HardwareAuthorityMigration_ValidationAcceptsCanonicallyEquivalentUuid(string systemUuid)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateHardwareAuthorityMigration", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = ValidHardwareMigrationRequest(enrollmentId);
        request.SystemUuid = systemUuid;

        Assert.NotNull(validate.Invoke(null,
        [
            enrollmentId, request, ValidMigrationProofHeaders(), new string('d', 64)
        ]));
    }

    /// <summary>Builds the canonical request shared by strict contract tests.</summary>
    private static RuntimeHardwareAuthorityMigrationRequest ValidHardwareMigrationRequest(Guid enrollmentId) => new()
    {
        Schema = RuntimeEnrollmentService.HardwareAuthorityMigrationSchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        RequestId = "22222222-2222-4222-8222-222222222222",
        EnrollmentId = enrollmentId.ToString("D"),
        Epoch = 1,
        SecurityEpoch = 3,
        LegacyHardwareId = "A00272B768FFD6AF",
        HardwareIdV2 = "6B775195D2F86F36",
        LegacyAlgorithm = RuntimeEnrollmentService.HardwareMigrationSourceAlgorithm,
        HardwareIdV2Algorithm = RuntimeEnrollmentService.HardwareMigrationTargetAlgorithm,
        SdkVersion = "2.0.0",
        SystemUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32"
    };

    /// <summary>Builds syntactically canonical detached proof headers for validator tests.</summary>
    private static RuntimeProofHeaders ValidMigrationProofHeaders() => new(
        "2026-08-16T13:00:00.0000000Z",
        "33333333-3333-4333-8333-333333333333",
        new string('A', 512));

    [Fact]
    public void PrepareResponseV1_SerializationRemainsExactWithoutSecurityEpoch()
    {
        var response = new RuntimeEnrollmentPrepareResponse(
            RuntimeEnrollmentService.PrepareResponseSchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "pending",
            "55555555-5555-4555-8555-555555555555",
            1,
            "challenge",
            "2026-08-04T08:00:00.0000000Z",
            "https://runtime.example.test");

        Assert.Equal(
            "{\"schema\":\"runtime-enrollment-prepare-response-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"status\":\"pending\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"epoch\":1,\"challenge\":\"challenge\",\"expiresAtUtc\":\"2026-08-04T08:00:00.0000000Z\",\"confirmAudience\":\"https://runtime.example.test\"}",
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }

    [Fact]
    public void PrepareResponseV2_SerializationCarriesAuthoritativeSecurityEpoch()
    {
        var response = new RuntimeEnrollmentPrepareResponse(
            RuntimeEnrollmentService.PrepareV2ResponseSchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "pending",
            "55555555-5555-4555-8555-555555555555",
            1,
            "challenge",
            "2026-08-04T08:00:00.0000000Z",
            "https://runtime.example.test")
        {
            SecurityEpoch = 5
        };

        Assert.Equal(
            "{\"schema\":\"runtime-enrollment-prepare-response-v2\",\"protocolVersion\":\"runtime-enrollment-v1\",\"status\":\"pending\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"epoch\":1,\"challenge\":\"challenge\",\"expiresAtUtc\":\"2026-08-04T08:00:00.0000000Z\",\"confirmAudience\":\"https://runtime.example.test\",\"securityEpoch\":5}",
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }

    [Theory]
    [InlineData("runtime-enrollment-refresh-v1", null, "runtime-enrollment-refresh-response-v1", null)]
    [InlineData("runtime-enrollment-refresh-v2", 5, "runtime-enrollment-refresh-response-v2", 5)]
    public void RefreshResponse_SerializationPreservesVersionedExactShape(
        string requestSchema,
        int? expectedSecurityEpoch,
        string responseSchema,
        int? securityEpoch)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateRefresh", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidRefreshRequest(requestSchema, expectedSecurityEpoch);

        var validated = validate.Invoke(null, [request, new string('d', 64)]);
        var response = new RuntimeEnrollmentPrepareResponse(
            responseSchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "pending",
            request.EnrollmentId!,
            1,
            "challenge",
            "2026-08-04T08:00:00.0000000Z",
            "https://runtime.example.test")
        {
            SecurityEpoch = securityEpoch
        };

        Assert.NotNull(validated);
        var expectedSuffix = securityEpoch.HasValue ? ",\"securityEpoch\":5}" : "}";
        Assert.EndsWith(expectedSuffix,
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Proves that the production v2 JSON policy emits the exact lineage wire shape and preserves
    /// the opaque Unicode provider grant reference without normalization.
    /// </summary>
    [Fact]
    public void AuthorityLineageV2_SerializationPreservesContractVersionAndLineageIdentity()
    {
        var payload = new RuntimeEnrollmentAuthorityLineageV2
        {
            Schema = "runtime-enrollment-authority-lineage-v2",
            ContractVersion = 2,
            AuthorityLineageId = "018f6fd4-8f31-7cc2-8d19-9e79c8b87a01",
            Provider = "softlicence",
            ProductId = "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11",
            ProviderGrantRef = "grant:tenant-a:café:🚀",
            CreatedAtUtc = "2026-08-22T16:00:00.000000Z"
        };

        var serialized = JsonSerializer.Serialize(payload, AuthorityContractJsonOptions);
        using var document = JsonDocument.Parse(serialized);
        var root = document.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        var propertyNames = root.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal(
            ["schema", "contractVersion", "authorityLineageId", "provider", "productId", "providerGrantRef", "createdAtUtc"],
            propertyNames);
        Assert.Equal("runtime-enrollment-authority-lineage-v2", root.GetProperty("schema").GetString());
        Assert.Equal(2, root.GetProperty("contractVersion").GetInt32());
        Assert.Equal("018f6fd4-8f31-7cc2-8d19-9e79c8b87a01", root.GetProperty("authorityLineageId").GetString());
        Assert.Equal("grant:tenant-a:café:🚀", root.GetProperty("providerGrantRef").GetString());
        Assert.Equal("2026-08-22T16:00:00.000000Z", root.GetProperty("createdAtUtc").GetString());
        Assert.Equal("softlicence", root.GetProperty("provider").GetString());
    }

    /// <summary>
    /// Proves that the production v2 JSON policy emits the exact signed-statement wire shape,
    /// required null predecessor, signed sequence, and exact shared PS256 signature vector.
    /// </summary>
    [Fact]
    public void SignedGenerationStatementV2_SerializationPreservesPayloadAndSignatureMetadata()
    {
        var payload = new RuntimeEnrollmentSignedGenerationStatementV2
        {
            Schema = "runtime-enrollment-signed-generation-v2",
            Payload = new RuntimeEnrollmentAuthorityGenerationPayloadV2
            {
                Schema = "runtime-enrollment-authority-generation-v2",
                ContractVersion = 2,
                AuthorityLineageId = "018f6fd4-8f31-7cc2-8d19-9e79c8b87a01",
                AuthorityGenerationId = "018f6fd4-aad1-7a27-91fe-fec30a9ff201",
                PreviousGenerationId = null,
                Sequence = 0,
                Provider = "softlicence",
                ProductId = "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11",
                ProviderGrantRef = "grant:tenant-a:café:🚀",
                Release = new RuntimeEnrollmentAuthorityReleaseV2
                {
                    Version = "2.3.445",
                    ArtifactSetDigest = "1111111111111111111111111111111111111111111111111111111111111111"
                },
                Binding = new RuntimeEnrollmentAuthorityBindingV2
                {
                    BindingId = "018f6fd4-bbc2-7467-a238-0bf114bb3101",
                    HardwareIdDigest = "2222222222222222222222222222222222222222222222222222222222222222"
                },
                Enrollment = new RuntimeEnrollmentAuthorityEnrollmentV2
                {
                    EnrollmentId = "018f6fd4-cbd3-7d7d-b8db-a905a7786201",
                    State = "active",
                    IssuedAtUtc = "2026-08-22T16:00:01.000000Z",
                    ExpiresAtUtc = null
                },
                Key = new RuntimeEnrollmentAuthorityKeyV2
                {
                    AuthorityKeyId = "runtime-enrollment-ps256-2026-01",
                    SecurityEpoch = 7
                },
                Installation = new RuntimeEnrollmentAuthorityInstallationV2
                {
                    InstallationId = "018f6fd4-dce4-7b2a-8202-5846e80d1301",
                    SeatId = "018f6fd4-edf5-7524-9c37-1ae1a3764401"
                },
            Transition = new RuntimeEnrollmentAuthorityGenerationTransitionV2
                {
                    Kind = "genesis",
                    ReasonCode = "INITIAL_ENROLLMENT",
                    RequestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5501",
                    OccurredAtUtc = "2026-08-22T16:00:02.000000Z"
                }
            },
            AuthorityDigest = "01c18f45c35263bef28814300bc38e8d903e9a5fd22ada4c8c094c21d0110402",
            Signature = new RuntimeEnrollmentAuthoritySignatureV2
            {
                Algorithm = "PS256",
                KeyId = "runtime-enrollment-ps256-2026-01",
                Value = SharedPs256Signature
            }
        };

        var json = JsonSerializer.Serialize(payload, AuthorityContractJsonOptions);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.Equal(
            ["schema", "payload", "authorityDigest", "signature"],
            root.EnumerateObject().Select(property => property.Name).ToArray());
        Assert.Equal("runtime-enrollment-signed-generation-v2", root.GetProperty("schema").GetString());
        Assert.Equal("01c18f45c35263bef28814300bc38e8d903e9a5fd22ada4c8c094c21d0110402",
            root.GetProperty("authorityDigest").GetString());

        var statementPayload = root.GetProperty("payload");
        Assert.Equal(JsonValueKind.Object, statementPayload.ValueKind);
        Assert.Equal(
            ["schema", "contractVersion", "authorityLineageId", "authorityGenerationId", "previousGenerationId", "sequence", "provider",
                "productId", "providerGrantRef", "release", "binding", "enrollment", "key", "installation", "transition"],
            statementPayload.EnumerateObject().Select(property => property.Name).ToArray());
        Assert.Equal("018f6fd4-aad1-7a27-91fe-fec30a9ff201", statementPayload.GetProperty("authorityGenerationId").GetString());
        Assert.Equal("grant:tenant-a:café:🚀", statementPayload.GetProperty("providerGrantRef").GetString());
        Assert.True(statementPayload.GetProperty("previousGenerationId").ValueKind == JsonValueKind.Null);
        Assert.Equal(0, statementPayload.GetProperty("sequence").GetInt64());
        Assert.Equal("018f6fd4-8f31-7cc2-8d19-9e79c8b87a01", statementPayload.GetProperty("authorityLineageId").GetString());

        var statementSignature = root.GetProperty("signature");
        Assert.Equal(
            ["algorithm", "keyId", "value"],
            statementSignature.EnumerateObject().Select(property => property.Name).ToArray());
        Assert.Equal("PS256", statementSignature.GetProperty("algorithm").GetString());
        Assert.Equal("runtime-enrollment-ps256-2026-01", statementSignature.GetProperty("keyId").GetString());
        Assert.Equal(SharedPs256Signature, statementSignature.GetProperty("value").GetString());
        Assert.Equal("runtime-enrollment-ps256-2026-01", statementPayload.GetProperty("key").GetProperty("authorityKeyId").GetString());
        Assert.Equal("genesis", statementPayload.GetProperty("transition").GetProperty("kind").GetString());
    }

    [Theory]
    [InlineData("Runtime-enrollment-refresh-v2", 5)]
    [InlineData("runtime-enrollment-refresh-v3", 5)]
    [InlineData("runtime-enrollment-refresh-v2", null)]
    [InlineData("runtime-enrollment-refresh-v2", 0)]
    [InlineData("runtime-enrollment-refresh-v1", 1)]
    public void RefreshValidation_RejectsNearMissAndHybridVersionContracts(
        string schema,
        int? expectedSecurityEpoch)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateRefresh", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidRefreshRequest(schema, expectedSecurityEpoch);

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            validate.Invoke(null, [request, new string('d', 64)]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    private static RuntimeEnrollmentRefreshRequest ValidRefreshRequest(
        string schema,
        int? expectedSecurityEpoch) => new()
    {
        Schema = schema,
        RequestId = "11111111-1111-4111-8111-111111111111",
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        ProductId = "22222222-2222-4222-8222-222222222222",
        BindingId = "33333333-3333-4333-8333-333333333333",
        EnrollmentId = "44444444-4444-4444-8444-444444444444",
        ExpectedChallengeDigestSha256 = new string('a', 64),
        ExpectedSecurityEpoch = expectedSecurityEpoch
    };

    [Fact]
    public void ReinstallAuthorityLegacyV2_ValidationPreservesExactSignedReferences()
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateReinstallAuthority", BindingFlags.NonPublic | BindingFlags.Static)!;
        var build = typeof(RuntimeEnrollmentService).GetMethod(
            "BuildReinstallProofPayload", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidLegacyV2ReinstallRequest();

        var validated = validate.Invoke(null, [request]);
        var payload = Assert.IsType<string>(build.Invoke(null, [validated]));

        Assert.Equal(string.Join('\n',
            "distribution-reinstall-proof-v2",
            request.BootstrapId,
            request.RequestId,
            request.InstallationId,
            request.EnrollmentId,
            request.ReleaseVersion,
            request.KeyThumbprint,
            "3",
            request.GrantRef,
            request.SubjectRef,
            request.Challenge), payload);
    }

    [Theory]
    [InlineData("subject-length")]
    [InlineData("subject-character")]
    [InlineData("grant-uppercase")]
    [InlineData("v1-extra-fields")]
    public void ReinstallAuthorityValidation_RejectsNonCanonicalOrCrossSchemaReferences(string mutation)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateReinstallAuthority", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidLegacyV2ReinstallRequest();
        switch (mutation)
        {
            case "subject-length": request.SubjectRef += "A"; break;
            case "subject-character": request.SubjectRef = new string('A', 42) + "+"; break;
            case "grant-uppercase": request.GrantRef = request.GrantRef!.ToUpperInvariant(); break;
            case "v1-extra-fields": request.Schema = RuntimeEnrollmentService.ReinstallAuthoritySchema; break;
        }

        var thrown = Assert.Throws<TargetInvocationException>(() => validate.Invoke(null, [request]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    [Fact]
    public void BuildProofPayload_UsesFrozenLineOrderWithoutTrailingNewline()
    {
        var id = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var payload = RuntimeEnrollmentService.BuildProofPayload(
            "capability", id, 1,
            "/api/v1/runtime-enrollments/11111111-1111-4111-8111-111111111111/capabilities",
            "https://broker.example.test", "2026-07-19T00:00:00.0000000Z",
            "22222222-2222-4222-8222-222222222222", "-", new string('a', 64));

        Assert.Equal(12, payload.Split('\n').Length);
        Assert.StartsWith("runtime-enrollment-proof-v1\nPS256\ncapability\n", payload, StringComparison.Ordinal);
        Assert.EndsWith(new string('a', 64), payload, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", payload, StringComparison.Ordinal);
    }

    [Fact]
    public void SignCapability_ProducesVerifiablePs256TokenWithBoundCnf()
    {
        using var rsa = RSA.Create(3072);
        using var service = new RuntimeEnrollmentCryptoService(Options.Create(OptionsFor(rsa)));
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var issued = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        var token = service.SignCapability(enrollmentId, 1, 7,
            "44444444-4444-4444-8444-444444444444", "2.2.844",
            "77777777-7777-4777-8777-777777777777",
            CapabilityBinaries(), "https://broker.example.test",
            ["runtime.execute"], new string('a', 64), issued,
            "22222222-2222-4222-8222-222222222222");

        var segments = token.Split('.');
        Assert.Equal(3, segments.Length);
        using var header = JsonDocument.Parse(Decode(segments[0]));
        using var payload = JsonDocument.Parse(Decode(segments[1]));
        Assert.Equal("PS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("runtime-2026-01", header.RootElement.GetProperty("kid").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(enrollmentId.ToString("D"), payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal(7, payload.RootElement.GetProperty("security_epoch").GetInt32());
        Assert.Equal("2.2.844", payload.RootElement.GetProperty("release_version").GetString());
        Assert.Equal(new string('c', 64), payload.RootElement.GetProperty("binaries").GetProperty("FP_CORE").GetString());
        Assert.Equal(issued.ToUnixTimeSeconds() + 120, payload.RootElement.GetProperty("exp").GetInt64());
        Assert.Equal(new string('a', 64), payload.RootElement.GetProperty("cnf").GetProperty("spki_sha256").GetString());
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), Decode(segments[2]),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        var rejected = Assert.Throws<RuntimeEnrollmentException>(() => service.SignCapability(
            enrollmentId, 1, 7, null!, "2.2.844",
            "77777777-7777-4777-8777-777777777777", CapabilityBinaries(),
            "https://broker.example.test", ["runtime.execute"], new string('a', 64), issued,
            "33333333-3333-4333-8333-333333333333"));
        Assert.Equal("authority_unavailable", rejected.ErrorCode);
    }

    [Fact]
    public void SignLegacyCapability_ProducesExactHistoricalClaimSet()
    {
        using var rsa = RSA.Create(3072);
        using var service = new RuntimeEnrollmentCryptoService(Options.Create(OptionsFor(rsa)));
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var token = service.SignLegacyCapability(
            enrollmentId, 1, 3, "https://broker.example.test", ["runtime.execute"],
            new string('a', 64), DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            "22222222-2222-4222-8222-222222222222");

        var segments = token.Split('.');
        using var payload = JsonDocument.Parse(Decode(segments[1]));
        Assert.Equal(
            ["iss", "aud", "sub", "jti", "iat", "nbf", "exp", "epoch", "security_epoch", "scope", "cnf"],
            payload.RootElement.EnumerateObject().Select(property => property.Name).ToArray());
        Assert.False(payload.RootElement.TryGetProperty("installation_id", out _));
        Assert.False(payload.RootElement.TryGetProperty("release_version", out _));
        Assert.False(payload.RootElement.TryGetProperty("session_id", out _));
        Assert.False(payload.RootElement.TryGetProperty("binaries", out _));
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), Decode(segments[2]),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Fact]
    public void CapabilityValidation_AcceptsHistoricalShapeButRejectsMixedShape()
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateCapability", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = LegacyCapabilityRequest(enrollmentId);

        Assert.NotNull(method.Invoke(null, [enrollmentId, request, ValidProofHeaders(), new string('b', 64)]));

        request.SessionId = "22222222-2222-4222-8222-222222222222";
        var thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [enrollmentId, request, ValidProofHeaders(), new string('b', 64)]));
        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);

        request = LegacyCapabilityRequest(enrollmentId);
        request.InstallationId = null;
        thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [enrollmentId, request, ValidProofHeaders(), new string('b', 64)]));
        invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    /// <summary>
    /// Proves the exact historical capability shape is admitted only for an ACTIVE enrollment on the
    /// one allowlisted release; no distribution-binding version participates in Runtime authority.
    /// </summary>
    /// <param name="enrollmentVersion">The authoritative release stored on the Runtime enrollment.</param>
    /// <param name="enrollmentState">The authoritative Runtime enrollment lifecycle state.</param>
    /// <param name="expectedStatusCode">Zero for admission, otherwise the expected stable rejection status.</param>
    /// <param name="expectedErrorCode">The stable rejection code, or <see langword="null"/> for admission.</param>
    [Theory]
    [InlineData("2.2.916", "ACTIVE", 0, null)]
    [InlineData("2.2.915", "ACTIVE", StatusCodes.Status409Conflict, "capability_binding_mismatch")]
    [InlineData("2.2.916", "PENDING", StatusCodes.Status422UnprocessableEntity, "enrollment_inactive")]
    public async Task HistoricalCapability_IsRestrictedToExactActiveEnrollmentRelease(
        string enrollmentVersion, string enrollmentState, int expectedStatusCode, string? expectedErrorCode)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateCapability", BindingFlags.NonPublic | BindingFlags.Static)!;
        var validateIdentity = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateCapabilityIdentityAsync", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var bindingId = Guid.Parse("33333333-3333-4333-8333-333333333333");
        const string installationId = "44444444-4444-4444-8444-444444444444";
        var capability = validate.Invoke(null,
            [enrollmentId, LegacyCapabilityRequest(enrollmentId), ValidProofHeaders(), new string('b', 64)]);
        var factory = new InMemoryFactory();
        await using var db = await factory.CreateDbContextAsync();
        foreach (var (key, hash) in new[]
        {
            ("FP_CORE", new string('c', 64)),
            ("FP_DLL", new string('d', 64)),
            ("FP_EXE", new string('e', 64))
        })
        {
            db.ApprovedBinaries.Add(new ApprovedBinary
            {
                ProductId = enrollmentId,
                Version = enrollmentVersion,
                Key = key,
                Hash = hash,
                Source = ApprovedBinaryService.ReleaseSource
            });
        }
        await db.SaveChangesAsync();
        var enrollment = new RuntimeEnrollment
        {
            Id = enrollmentId,
            ProductId = enrollmentId,
            BindingId = bindingId,
            InstallationId = installationId,
            ReleaseVersion = enrollmentVersion,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            Algorithm = "PS256",
            Epoch = 1,
            SecurityEpoch = 1,
            PublicKeySpkiCiphertext = "sealed",
            PublicKeySpkiKeyId = "test-key",
            PublicKeySpkiSha256 = new string('a', 64),
            KeyThumbprint = new string('A', 43),
            State = enrollmentState
        };

        RuntimeEnrollmentException? rejection = null;
        try
        {
            var validation = Assert.IsAssignableFrom<Task>(validateIdentity.Invoke(
                null, [db, enrollment, capability, CancellationToken.None]));
            await validation;
        }
        catch (TargetInvocationException exception)
        {
            rejection = Assert.IsType<RuntimeEnrollmentException>(exception.InnerException);
        }
        catch (RuntimeEnrollmentException exception)
        {
            rejection = exception;
        }

        if (expectedStatusCode == 0)
        {
            Assert.Null(rejection);
            return;
        }

        var rejected = Assert.IsType<RuntimeEnrollmentException>(rejection);
        Assert.Equal(expectedStatusCode, rejected.StatusCode);
        Assert.Equal(expectedErrorCode, rejected.ErrorCode);
    }

    private static List<RuntimeEnrollmentBinaryEvidenceRequest> CapabilityBinaries() =>
    [
        new() { Key = "FP_CORE", Sha256 = new string('c', 64) },
        new() { Key = "FP_DLL", Sha256 = new string('d', 64) },
        new() { Key = "FP_EXE", Sha256 = new string('e', 64) }
    ];

    private static RuntimeEnrollmentCapabilityRequest LegacyCapabilityRequest(Guid enrollmentId) => new()
    {
        Schema = RuntimeEnrollmentService.CapabilitySchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        EnrollmentId = enrollmentId.ToString("D"),
        Epoch = 1,
        SecurityEpoch = 1,
        Audience = "https://broker.example.test",
        Scope = ["runtime.execute"]
    };

    private static RuntimeReinstallAuthorityRequest ValidLegacyV2ReinstallRequest() => new()
    {
        Schema = RuntimeEnrollmentService.ReinstallAuthorityLegacyV2Schema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        RequestId = "11111111-1111-4111-8111-111111111111",
        ProductId = "22222222-2222-4222-8222-222222222222",
        BootstrapId = "33333333-3333-4333-8333-333333333333",
        InstallationId = "44444444-4444-4444-8444-444444444444",
        EnrollmentId = "55555555-5555-4555-8555-555555555555",
        ReleaseVersion = "2.3.7",
        KeyThumbprint = new string('A', 43),
        SecurityEpoch = 3,
        GrantRef = "abcdefab-cdef-4abc-8def-abcdefabcdef",
        SubjectRef = new string('A', 43),
        Challenge = new string('B', 86),
        Signature = new string('C', 512)
    };

    [Fact]
    public void EncryptionOwnerType_AllowsCriticalRecoveryClientRefetchResponse()
    {
        var allowlist = typeof(RuntimeEnrollmentCryptoService).GetMethod(
            "IsOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var mapping = typeof(RuntimeEnrollmentService).GetMethod(
            "ProofResponseOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ownerType = Assert.IsType<string>(mapping.Invoke(null, ["critical-recovery-refetch"]));

        Assert.Equal("recovery-refetch-response", ownerType);
        Assert.True(ownerType.Length <= 32);
        Assert.True((bool)allowlist.Invoke(null, [ownerType])!);
        Assert.False((bool)allowlist.Invoke(null, ["critical-recovery-refetch-response"])!);
    }

    [Fact]
    public void EncryptionOwnerType_AllowsMilestoneResponse()
    {
        var allowlist = typeof(RuntimeEnrollmentCryptoService).GetMethod(
            "IsOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var mapping = typeof(RuntimeEnrollmentService).GetMethod(
            "ProofResponseOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ownerType = Assert.IsType<string>(mapping.Invoke(null, ["milestone"]));

        Assert.Equal("milestone-response", ownerType);
        Assert.True((bool)allowlist.Invoke(null, [ownerType])!);
    }

    [Theory]
    [InlineData("bootstrap_entered")]
    [InlineData("integrity_denied")]
    [InlineData("mcp_invocation_requested")]
    [InlineData("tia_operation_failed")]
    public void MilestoneValidation_AcceptsExactAllowlistedCodes(string code)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateMilestone", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = MilestoneRequest(enrollmentId, code);

        var result = method.Invoke(null,
            [enrollmentId, request, ValidProofHeaders(), new string('a', 64)]);

        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("Bootstrap_entered")]
    [InlineData("bootstrap-entered")]
    [InlineData("server_verified")]
    [InlineData("")]
    public void MilestoneValidation_RejectsNonAllowlistedCodes(string code)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateMilestone", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null,
            [enrollmentId, MilestoneRequest(enrollmentId, code), ValidProofHeaders(), new string('a', 64)]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal("invalid_request", invalid.ErrorCode);
        Assert.Equal(400, invalid.StatusCode);
    }

    [Fact]
    public void MilestoneAuthorization_AllowsConfiguredScopeAtDifferentCapabilityAudience()
    {
        var productId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var options = new RuntimeEnrollmentOptions
        {
            ConfirmAudience = "https://runtime.example.test",
            Products =
            [
                new()
                {
                    ProductId = productId.ToString("D"),
                    Capabilities =
                    [
                        new()
                        {
                            Audience = "https://broker.example.test",
                            Scopes = ["milestone:write", "runtime.execute"]
                        }
                    ]
                }
            ]
        };
        var service = new RuntimeEnrollmentService(
            null!, null!, null!, null!, Options.Create(options));
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateMilestoneAuthorization", BindingFlags.NonPublic | BindingFlags.Instance)!;

        method.Invoke(service, [productId]);

        options.Products[0].Capabilities[0].Scopes = ["runtime.execute"];
        var denied = Assert.Throws<TargetInvocationException>(() => method.Invoke(service, [productId]));
        Assert.Equal("capability_not_allowed",
            Assert.IsType<RuntimeEnrollmentException>(denied.InnerException).ErrorCode);
    }

    [Fact]
    public void MilestoneSession_AtAbsoluteExpiry_IsRejected()
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "EnsureMilestoneSessionActive", BindingFlags.NonPublic | BindingFlags.Static)!;
        var now = DateTimeOffset.Parse("2026-07-20T10:00:00Z", CultureInfo.InvariantCulture);
        var session = new RuntimeMilestoneSession
        {
            ExpiresAtUtc = now.UtcDateTime
        };

        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, [session, now]));

        var expired = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal("session_expired", expired.ErrorCode);
        Assert.Equal(409, expired.StatusCode);
    }

    [Fact]
    public async Task EnabledAuthority_WithNonPostgreSqlProvider_FailsClosed()
    {
        var factory = new InMemoryFactory();
        var authority = new RuntimeEnrollmentAuthorityService(
            factory, Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => authority.ValidateInfrastructureAsync());

        Assert.Equal("Runtime enrollment enabled infrastructure validation failed.", exception.Message);
    }

    /// <summary>Proves explicit v2 activation cannot bypass the global Runtime Enrollment switch.</summary>
    [Fact]
    public void AuthorityGenerationV2_EnabledWithGlobalModeOff_FailsStartupValidation()
    {
        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, new RuntimeEnrollmentOptions
        {
            Mode = "off",
            AuthorityGenerationV2 = new RuntimeAuthorityGenerationV2Options { Mode = "enabled" }
        });

        Assert.True(result.Failed);
        Assert.Contains("Enabled runtime authority-generation v2 requires runtime enrollment mode 'enabled'.",
            result.Failures);
    }

    [Theory]
    [InlineData("2.10.0", "2.9.0", false)]
    [InlineData("2.9.0", "2.10.0", true)]
    [InlineData("2.2.0-alpha.9", "2.2.0-alpha.10", true)]
    [InlineData("2.2.0-rc.1", "2.2.0", true)]
    [InlineData("2.2.0+build.7", "2.2.0+build.8", false)]
    [InlineData("2.2.0-01", "2.2.0", true)]
    public void MinimumVersion_UsesSemVerPrecedence(string current, string minimum, bool expectedBelow)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "IsVersionBelow", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(expectedBelow, (bool)method.Invoke(null, [current, minimum])!);
    }

    /// <summary>Exercises the production Runtime validator, including masks that the looser Distribution prefix matcher must not imply are supported.</summary>
    [Theory]
    [InlineData("2.4.50", "*", true)]
    [InlineData("2.4.50", "2.*", true)]
    [InlineData("2.4.50", "2.4.*", true)]
    [InlineData("2.4.50", "2.4.50", true)]
    [InlineData("2.4.50", "2.4.51", false)]
    [InlineData("2.4.50", "02.*", false)]
    [InlineData("2.4.50", "2.4.50.*", false)]
    [InlineData("2.4.50", "17,18,19,20,21", false)]
    [InlineData("2.4.50", "V17-V21", false)]
    [InlineData("2.4.50", ">=2.0.0", false)]
    [InlineData("2.10.0", "2.*", true)]
    [InlineData("2.10.0-rc.1+build.7", "2.10.*", true)]
    [InlineData("2.10.0+build.7", "2.10.0+build.7", true)]
    [InlineData("2.10.0+build.8", "2.10.0+build.7", false)]
    [InlineData("2.10.0-01", "2.*", false)]
    public void AllowedVersion_RequiresValidSemVerAndCanonicalMask(
        string version, string mask, bool expectedAllowed)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "IsVersionAllowed", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(expectedAllowed, (bool)method.Invoke(null, [version, mask])!);
    }

    /// <summary>Proves Prepare rejects a non-canonical semantic version before consulting open version policies.</summary>
    [Fact]
    public void PrepareValidation_RejectsNonCanonicalSemVerBeforeOpenVersionPolicies()
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidatePrepare", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = new RuntimeEnrollmentPrepareRequest
        {
            Schema = RuntimeEnrollmentService.PrepareSchema,
            RequestId = "11111111-1111-4111-8111-111111111111",
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = "22222222-2222-4222-8222-222222222222",
            BindingId = "33333333-3333-4333-8333-333333333333",
            HandoffDigestSha256 = new string('a', 64),
            InstallationId = "44444444-4444-4444-8444-444444444444",
            ReleaseVersion = "2.2.0-01",
            Epoch = 1,
            Key = new RuntimeEnrollmentKeyRequest()
        };

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [request, new string('b', 64)]));
        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(400, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    [Theory]
    [InlineData("runtime-enrollment-prepare-v1", true)]
    [InlineData("runtime-enrollment-prepare-v2", true)]
    [InlineData("Runtime-enrollment-prepare-v2", false)]
    [InlineData("runtime-enrollment-prepare-v4", false)]
    /// <summary>Proves the boundary adapter accepts only the two temporarily supported exact wire schemas.</summary>
    /// <param name="schema">Case-sensitive external schema identifier presented to Prepare.</param>
    /// <param name="accepted">Whether the identifier is an explicitly supported compatibility boundary.</param>
    public void PrepareValidation_AcceptsOnlySupportedBoundarySchemas(string schema, bool accepted)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidatePrepare", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = new RuntimeEnrollmentPrepareRequest
        {
            Schema = schema,
            RequestId = "11111111-1111-4111-8111-111111111111",
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = "22222222-2222-4222-8222-222222222222",
            BindingId = "33333333-3333-4333-8333-333333333333",
            HandoffDigestSha256 = new string('a', 64),
            InstallationId = "44444444-4444-4444-8444-444444444444",
            ReleaseVersion = "2.2.844",
            Epoch = 1,
            Key = new RuntimeEnrollmentKeyRequest()
        };

        if (accepted)
        {
            Assert.NotNull(method.Invoke(null, [request, new string('b', 64)]));
            return;
        }

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [request, new string('b', 64)]));
        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    /// <summary>
    /// Proves that all six v1/v2 authority roots and every nested object reject unknown members,
    /// omitted required members, wire-name aliases, and incorrect wire-name casing.
    /// </summary>
    [Fact]
    public void AuthorityContracts_AllRootsAndChildrenAreClosedAndRequireExactWireNames()
    {
        foreach (var (type, value) in AuthorityContractRoots(" Grant:café:🚀 "))
        {
            var json = JsonSerializer.Serialize(value, type, AuthorityContractJsonOptions);
            Assert.NotNull(JsonSerializer.Deserialize(json, type, AuthorityContractJsonOptions));

            var root = JsonNode.Parse(json)!.AsObject();
            foreach (var path in ObjectPaths(root))
            {
                var unknown = root.DeepClone().AsObject();
                ObjectAt(unknown, path)["unknownMember"] = true;
                Assert.Throws<JsonException>(() =>
                    JsonSerializer.Deserialize(unknown.ToJsonString(), type, AuthorityContractJsonOptions));
            }

            foreach (var path in PropertyPaths(root))
            {
                var omitted = root.DeepClone().AsObject();
                var owner = ObjectAt(omitted, path.OwnerPath);
                var valueNode = owner[path.PropertyName];
                owner.Remove(path.PropertyName);
                Assert.Throws<JsonException>(() =>
                    JsonSerializer.Deserialize(omitted.ToJsonString(), type, AuthorityContractJsonOptions));

                var wrongCase = root.DeepClone().AsObject();
                owner = ObjectAt(wrongCase, path.OwnerPath);
                owner[UppercaseFirst(path.PropertyName)] = owner[path.PropertyName]?.DeepClone();
                owner.Remove(path.PropertyName);
                Assert.Throws<JsonException>(() =>
                    JsonSerializer.Deserialize(wrongCase.ToJsonString(), type, AuthorityContractJsonOptions));

                var alias = root.DeepClone().AsObject();
                owner = ObjectAt(alias, path.OwnerPath);
                owner[path.PropertyName + "Alias"] = valueNode?.DeepClone();
                Assert.Throws<JsonException>(() =>
                    JsonSerializer.Deserialize(alias.ToJsonString(), type, AuthorityContractJsonOptions));
            }
        }
    }

    /// <summary>
    /// Proves that required nullable members remain present as JSON null while non-nullable members
    /// reject null under nullable-annotation enforcement.
    /// </summary>
    [Fact]
    public void AuthorityContracts_DistinguishRequiredNullFromOmission()
    {
        var generation = JsonSerializer.SerializeToNode(
            GenerationPayload("grant:exact"), AuthorityContractJsonOptions)!.AsObject();
        Assert.Null(generation["previousGenerationId"]);
        Assert.Null(generation["enrollment"]!["expiresAtUtc"]);
        Assert.Null(generation["installation"]!["seatId"]);
        Assert.NotNull(JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
            generation.ToJsonString(), AuthorityContractJsonOptions));

        var lineageNull = JsonSerializer.SerializeToNode(
            AuthorityContractRoots("grant:exact").First().Value,
            AuthorityContractJsonOptions)!.AsObject();
        lineageNull["providerGrantRef"] = null;
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityLineageV2>(
                lineageNull.ToJsonString(), AuthorityContractJsonOptions));

        var request = JsonSerializer.SerializeToNode(
            AuthorityRequest("grant:exact"), AuthorityContractJsonOptions)!.AsObject();
        Assert.Null(request["expectedAuthorityLineageId"]);
        Assert.Null(request["expectedCurrentGenerationId"]);
        Assert.Null(request["expectedPredecessorGenerationId"]);
    }

    /// <summary>
    /// Proves that request and generation transitions expose disjoint, closed timestamp shapes.
    /// </summary>
    [Fact]
    public void AuthorityContracts_RequestAndGenerationTransitionsRemainDistinct()
    {
        var requestTransition = JsonSerializer.SerializeToNode(
            AuthorityRequest("grant:exact").Transition, AuthorityContractJsonOptions)!.AsObject();
        Assert.Equal(["kind", "reasonCode", "requestedAtUtc"],
            requestTransition.Select(property => property.Key).ToArray());
        Assert.False(requestTransition.ContainsKey("requestId"));
        Assert.False(requestTransition.ContainsKey("occurredAtUtc"));

        var generationTransition = JsonSerializer.SerializeToNode(
            GenerationPayload("grant:exact").Transition, AuthorityContractJsonOptions)!.AsObject();
        Assert.Equal(["kind", "reasonCode", "requestId", "occurredAtUtc"],
            generationTransition.Select(property => property.Key).ToArray());
        Assert.False(generationTransition.ContainsKey("requestedAtUtc"));
    }

    /// <summary>
    /// Proves ordinal preservation of opaque composed, decomposed, spaced, cased, and astral strings.
    /// </summary>
    [Fact]
    public void AuthorityContracts_OpaqueStringsArePreservedWithoutRepair()
    {
        string[] values = ["grant:café", "grant:cafe\u0301", " Grant:É ", "grant:🚀"];
        var roundTrips = values.Select(value =>
        {
            var json = JsonSerializer.Serialize(GenerationPayload(value), AuthorityContractJsonOptions);
            using var document = JsonDocument.Parse(json);
            return document.RootElement.GetProperty("providerGrantRef").GetString();
        }).ToArray();

        Assert.Equal(values, roundTrips);
        Assert.NotEqual(roundTrips[0], roundTrips[1]);
        Assert.Equal(" Grant:É ", roundTrips[2]);
    }

    /// <summary>
    /// Proves exact v1 compatibility markers and the shared 256-byte PS256 signature vector.
    /// </summary>
    [Fact]
    public void AuthorityContracts_PreserveLegacyMarkersAndExactPs256Vector()
    {
        var roots = AuthorityContractRoots("grant:exact").ToArray();
        var legacy = JsonSerializer.SerializeToNode(roots.Single(root =>
            root.Type == typeof(RuntimeEnrollmentAuthorityLegacyProjectionV2)).Value,
            AuthorityContractJsonOptions)!.AsObject();
        Assert.Equal(1, legacy["contractVersion"]!.GetValue<int>());
        Assert.Equal("legacy_projection", legacy["source"]!.GetValue<string>());

        var statement = Assert.IsType<RuntimeEnrollmentSignedGenerationStatementV2>(roots.Single(root =>
            root.Type == typeof(RuntimeEnrollmentSignedGenerationStatementV2)).Value);
        Assert.Equal(342, SharedPs256Signature.Length);
        Assert.DoesNotContain('=', SharedPs256Signature);
        Assert.Equal(SharedPs256Signature, statement.Signature.Value);
        Assert.Matches("^[A-Za-z0-9_-]{342}$", statement.Signature.Value);
    }

    /// <summary>Creates the six canonical root DTOs used by the closed-contract matrix.</summary>
    private static IEnumerable<(Type Type, object Value)> AuthorityContractRoots(string providerGrantRef)
    {
        yield return (typeof(RuntimeEnrollmentAuthorityLineageV2), new RuntimeEnrollmentAuthorityLineageV2
        {
            Schema = "runtime-enrollment-authority-lineage-v2", ContractVersion = 2,
            AuthorityLineageId = LineageId, Provider = "softlicence", ProductId = ProductId,
            ProviderGrantRef = providerGrantRef, CreatedAtUtc = Timestamp
        });
        yield return (typeof(RuntimeEnrollmentAuthorityRequestV2), AuthorityRequest(providerGrantRef));
        yield return (typeof(RuntimeEnrollmentAuthorityGenerationPayloadV2), GenerationPayload(providerGrantRef));
        yield return (typeof(RuntimeEnrollmentSignedGenerationStatementV2), new RuntimeEnrollmentSignedGenerationStatementV2
        {
            Schema = "runtime-enrollment-signed-generation-v2", Payload = GenerationPayload(providerGrantRef),
            AuthorityDigest = new string('f', 64), Signature = new RuntimeEnrollmentAuthoritySignatureV2
            { Algorithm = "PS256", KeyId = "runtime-enrollment-ps256-2026-01", Value = SharedPs256Signature }
        });
        yield return (typeof(RuntimeEnrollmentAuthorityDiscoveryAttemptV2), new RuntimeEnrollmentAuthorityDiscoveryAttemptV2
        {
            Schema = "runtime-enrollment-discovery-attempt-v2", ContractVersion = 2, AttemptId = AttemptId,
            RequestId = RequestId, RequestDigest = new string('e', 64), AuthorityLineageId = LineageId,
            Status = "accepted", AuthorityGenerationId = GenerationId, ErrorCode = null,
            CreatedAtUtc = Timestamp, CompletedAtUtc = Timestamp
        });
        yield return (typeof(RuntimeEnrollmentAuthorityLegacyProjectionV2), new RuntimeEnrollmentAuthorityLegacyProjectionV2
        {
            Schema = "runtime-enrollment-authority-v1-compat", ContractVersion = 1,
            Provider = "softlicence", ProductId = ProductId, ProviderGrantRef = providerGrantRef,
            AuthorityDigest = new string('d', 64), Source = "legacy_projection"
        });
    }

    /// <summary>Creates the canonical authority request with the request-only transition shape.</summary>
    private static RuntimeEnrollmentAuthorityRequestV2 AuthorityRequest(string providerGrantRef) => new()
    {
        Schema = "runtime-enrollment-authority-request-v2", ContractVersion = 2, RequestId = RequestId,
        Provider = "softlicence", ProductId = ProductId, ProviderGrantRef = providerGrantRef,
        ExpectedAuthorityLineageId = null, ExpectedCurrentGenerationId = null,
        ExpectedPredecessorGenerationId = null, RequestedAuthority = RequestedAuthority(),
        Transition = new RuntimeEnrollmentAuthorityRequestTransitionV2
        { Kind = "genesis", ReasonCode = "INITIAL_ENROLLMENT", RequestedAtUtc = Timestamp }
    };

    /// <summary>Creates the canonical generation payload with every closed authority child.</summary>
    private static RuntimeEnrollmentAuthorityGenerationPayloadV2 GenerationPayload(string providerGrantRef) => new()
    {
        Schema = "runtime-enrollment-authority-generation-v2", ContractVersion = 2,
        AuthorityLineageId = LineageId, AuthorityGenerationId = GenerationId, PreviousGenerationId = null,
        Sequence = 0,
        Provider = "softlicence", ProductId = ProductId, ProviderGrantRef = providerGrantRef,
        Release = ReleaseAuthority(), Binding = BindingAuthority(), Enrollment = EnrollmentAuthority(),
        Key = KeyAuthority(), Installation = InstallationAuthority(),
        Transition = new RuntimeEnrollmentAuthorityGenerationTransitionV2
        { Kind = "genesis", ReasonCode = "INITIAL_ENROLLMENT", RequestId = RequestId, OccurredAtUtc = Timestamp }
    };

    /// <summary>Creates one independently owned payload copy through the production closed JSON contract.</summary>
    private static RuntimeEnrollmentAuthorityGenerationPayloadV2 CopyPayload(
        RuntimeEnrollmentAuthorityGenerationPayloadV2 value) =>
        JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
            JsonSerializer.SerializeToUtf8Bytes(value, AuthorityContractJsonOptions),
            AuthorityContractJsonOptions)!;

    /// <summary>Builds the exact valid predecessor/current pair for one canonical reason code.</summary>
    private static (RuntimeEnrollmentAuthorityGenerationPayloadV2? Previous,
        RuntimeEnrollmentAuthorityGenerationPayloadV2 Current) ValidTransition(string reasonCode)
    {
        var previous = GenerationPayload("grant:exact");
        previous.Transition.OccurredAtUtc = "2026-08-22T16:00:01.000000Z";
        var current = CopyPayload(previous);
        current.AuthorityGenerationId = "018f6fd4-aad1-7a27-91fe-fec30a9ff299";
        current.PreviousGenerationId = previous.AuthorityGenerationId;
        current.Sequence = checked(previous.Sequence + 1);
        current.Transition.RequestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5599";
        current.Transition.OccurredAtUtc = Timestamp;
        var rule = RuntimeEnrollmentAuthorityTransitionPolicy.Registry.Single(
            item => item.ReasonCode == reasonCode);
        current.Transition.Kind = rule.Kind;
        current.Transition.ReasonCode = rule.ReasonCode;
        switch (reasonCode)
        {
            case "INITIAL_ENROLLMENT":
                current.PreviousGenerationId = null;
                current.Sequence = 0;
                return (null, current);
            case "APPROVED_RELEASE_ADVANCE":
                current.Release.Version = "2.3.446";
                current.Release.ArtifactSetDigest = new string('3', 64);
                break;
            case "BINDING_REPLACEMENT":
                current.Binding.BindingId = "018f6fd4-bbc2-7467-a238-0bf114bb3199";
                current.Binding.HardwareIdDigest = new string('3', 64);
                break;
            case "ENROLLMENT_ACTIVATED":
                previous.Enrollment.State = "pending";
                break;
            case "ENROLLMENT_EXPIRED":
                current.Enrollment.State = "expired";
                break;
            case "ENROLLMENT_REPLACED":
                previous.Enrollment.State = "expired";
                current.Enrollment.State = "pending";
                current.Enrollment.EnrollmentId = "018f6fd4-cbd3-7d7d-b8db-a905a7786299";
                current.Enrollment.IssuedAtUtc = "2026-08-22T16:00:01.500000Z";
                break;
            case "AUTHORITY_REVOKED":
                current.Enrollment.State = "revoked";
                break;
            case "SIGNING_KEY_ROTATED":
                current.Key.AuthorityKeyId = "runtime-enrollment-ps256-2026-02";
                current.Key.SecurityEpoch++;
                break;
            case "SECURITY_EPOCH_ADVANCED":
                current.Key.SecurityEpoch++;
                break;
            case "INSTALLATION_REINSTALLED":
                current.Installation.InstallationId = "018f6fd4-dce4-7b2a-8202-5846e80d1399";
                break;
            case "RECOVERY_AUTHORIZED":
                current.Key.AuthorityKeyId = "runtime-enrollment-ps256-2026-02";
                current.Key.SecurityEpoch++;
                break;
            case "REPAIR_AUTHORIZED":
                break;
            case "SEAT_REASSIGNED":
                current.Installation.SeatId = "018f6fd4-dce4-7b2a-8202-5846e80d1398";
                break;
            default:
                throw new InvalidOperationException($"Unknown canonical reason: {reasonCode}.");
        }
        return (previous, current);
    }

    /// <summary>Evaluates one test pair with the exact evidence labels owned by its canonical rule.</summary>
    private static RuntimeEnrollmentAuthorityTransitionDecision Evaluate(
        (RuntimeEnrollmentAuthorityGenerationPayloadV2? Previous,
            RuntimeEnrollmentAuthorityGenerationPayloadV2 Current) transition)
    {
        var rule = RuntimeEnrollmentAuthorityTransitionPolicy.Registry.Single(
            item => item.ReasonCode == transition.Current.Transition.ReasonCode);
        return RuntimeEnrollmentAuthorityTransitionPolicy.Evaluate(
            transition.Previous, transition.Current,
            new RuntimeEnrollmentAuthorityEvidence(rule.Evidence), ContractNow);
    }

    /// <summary>Creates the requested-authority child shared by request test vectors.</summary>
    private static RuntimeEnrollmentAuthorityRequestedRequestV2 RequestedAuthority() => new()
    {
        Release = ReleaseAuthority(), Binding = BindingAuthority(), Enrollment = EnrollmentAuthority(),
        Key = KeyAuthority(), Installation = InstallationAuthority()
    };

    /// <summary>Creates a closed release-authority child.</summary>
    private static RuntimeEnrollmentAuthorityReleaseV2 ReleaseAuthority() => new()
    { Version = "2.3.445", ArtifactSetDigest = new string('1', 64) };

    /// <summary>Creates a closed binding-authority child.</summary>
    private static RuntimeEnrollmentAuthorityBindingV2 BindingAuthority() => new()
    { BindingId = BindingId, HardwareIdDigest = new string('2', 64) };

    /// <summary>Creates a closed enrollment-authority child with an explicit null expiry.</summary>
    private static RuntimeEnrollmentAuthorityEnrollmentV2 EnrollmentAuthority() => new()
    { EnrollmentId = EnrollmentId, State = "active", IssuedAtUtc = Timestamp, ExpiresAtUtc = null };

    /// <summary>Creates a closed key-authority child.</summary>
    private static RuntimeEnrollmentAuthorityKeyV2 KeyAuthority() => new()
    { AuthorityKeyId = "runtime-enrollment-ps256-2026-01", SecurityEpoch = 7 };

    /// <summary>Creates a closed installation-authority child with a required null seat identifier.</summary>
    private static RuntimeEnrollmentAuthorityInstallationV2 InstallationAuthority() => new()
    { InstallationId = InstallationId, SeatId = null };

    /// <summary>Enumerates every object location so closure is tested recursively.</summary>
    private static IEnumerable<string[]> ObjectPaths(JsonObject root)
    {
        yield return [];
        foreach (var property in root)
        {
            if (property.Value is not JsonObject child) continue;
            foreach (var suffix in ObjectPaths(child)) yield return [property.Key, .. suffix];
        }
    }

    /// <summary>Enumerates every property and owning object path so required presence is tested recursively.</summary>
    private static IEnumerable<(string[] OwnerPath, string PropertyName)> PropertyPaths(JsonObject root)
    {
        foreach (var property in root)
        {
            yield return ([], property.Key);
            if (property.Value is not JsonObject child) continue;
            foreach (var nested in PropertyPaths(child))
                yield return ([property.Key, .. nested.OwnerPath], nested.PropertyName);
        }
    }

    /// <summary>Resolves an object at an exact property path without case folding or aliases.</summary>
    private static JsonObject ObjectAt(JsonObject root, IReadOnlyList<string> path)
    {
        var current = root;
        foreach (var segment in path) current = current[segment]!.AsObject();
        return current;
    }

    /// <summary>Produces an intentionally invalid first-character case mutation.</summary>
    private static string UppercaseFirst(string value) => char.ToUpperInvariant(value[0]) + value[1..];

    private static readonly JsonSerializerOptions AuthorityContractJsonOptions =
        RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions();

    /// <summary>Supplies one trusted immutable UTC instant to lifecycle proof tests.</summary>
    private sealed class AuthorityFixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        /// <summary>Returns the fixed trusted UTC instant.</summary>
        public override DateTimeOffset GetUtcNow() => value;
    }

    private const string LineageId = "018f6fd4-8f31-7cc2-8d19-9e79c8b87a01";
    private const string GenerationId = "018f6fd4-aad1-7a27-91fe-fec30a9ff201";
    private const string ProductId = "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11";
    private const string RequestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5501";
    private const string AttemptId = "018f6fd4-aad1-7a27-91fe-fec30a9ff202";
    private const string BindingId = "018f6fd4-bbc2-7467-a238-0bf114bb3101";
    private const string EnrollmentId = "018f6fd4-cbd3-7d7d-b8db-a905a7786201";
    private const string InstallationId = "018f6fd4-dce4-7b2a-8202-5846e80d1301";
    private const string Timestamp = "2026-08-22T16:00:02.000000Z";
    private static readonly DateTimeOffset ContractNow = new(
        2026, 8, 22, 16, 0, 2, TimeSpan.Zero);
    private const string SharedPs256Signature = "yoqBwXPL0pmS2_XK8op3hdX_qnDzCGYNYjywLpu01YRq6NCYjiQ-n3-PaO6jD9nKtWeouNbkfOu_mWiVOsdmucwW3N8-q7YZqUYeWRCe0vdONsN4bEPu5aLoBWQDJAevpKwJh9Y0iC6_fZWVo5rMZNOJ06-kYNMwVl-pNa0DffUeYpHFqVw2yXA7u_mY-pnmTaZ1bLsJ6-JXh7rcqT1f2pmdFIK9xdYTWviN5jGn3RQ2NBRa2ryxBbRZ6ax0M8UAVQ9StLrPubFOkse39GA8sLmNm4QD9tAO2Zp9x2YowYs-BLU3NM6ukoutNPvlzYLzOcfGKzC8EnUlaORykL960A";

    /// <summary>Proves exact lowercase digest validation without padding, recasing, or repair.</summary>
    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
    [InlineData(" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ", false)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false)]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", false)]
    [InlineData("_______________________________________________________________=", false)]
    public void AuthorityPersistence_DigestGuardUsesExactLowercaseHex(string value, bool expected)
    {
        var method = typeof(RuntimeEnrollmentAuthorityService).GetMethod(
            "IsLowerHexDigest", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(expected, (bool)method.Invoke(null, [value])!);
    }

    /// <summary>Proves the closed persistence bounds and retry constraint-name inventory.</summary>
    [Fact]
    public void AuthorityPersistence_UsesClosedBoundsAndCanonicalConstraintNames()
    {
        var type = typeof(RuntimeEnrollmentAuthorityService);
        Assert.Equal(2895, (int)type.GetField(
            "MaximumCanonicalPayloadBytes", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!);
        Assert.Equal(3569, (int)type.GetField(
            "MaximumSignedStatementBytes", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!);
        Assert.Equal(3, (int)type.GetField(
            "MaximumPersistenceAttempts", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!);

        var names = Assert.IsAssignableFrom<IReadOnlySet<string>>(type.GetField(
            "PersistenceUniqueConstraintNames", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null));
        Assert.Equal(PersistenceConstraintNames, names.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
        Assert.All(names, name => Assert.True(Encoding.UTF8.GetByteCount(name) <= 63, name));
    }

    /// <summary>Proves exact byte boundaries and the closed genesis/predecessor sequence invariant.</summary>
    [Theory]
    [InlineData(0, 1, 0, false, false)]
    [InlineData(1, 1, 0, false, true)]
    [InlineData(2895, 3569, 0, false, true)]
    [InlineData(2896, 1, 0, false, false)]
    [InlineData(1, 0, 0, false, false)]
    [InlineData(1, 3570, 0, false, false)]
    [InlineData(1, 1, 1, false, false)]
    [InlineData(1, 1, 0, true, false)]
    [InlineData(1, 1, 1, true, true)]
    [InlineData(1, 1, -1, false, false)]
    [InlineData(1, 1, 9007199254740991L, true, true)]
    [InlineData(1, 1, 9007199254740992L, true, false)]
    public void AuthorityPersistence_ValidationIsClosed(
        int payloadBytes, int statementBytes, long sequence, bool hasPredecessor, bool valid)
    {
        var candidate = PersistenceCandidate(payloadBytes, statementBytes, sequence,
            hasPredecessor ? Guid.Parse(GenerationId) : null);

        var exception = Record.Exception(() =>
            RuntimeEnrollmentAuthorityService.ValidatePersistenceCandidate(candidate));

        Assert.Equal(valid, exception == null);
    }

    /// <summary>Proves each immutable request, lineage, generation, and opaque byte field is required for exact replay.</summary>
    [Fact]
    public void AuthorityPersistence_StoredEqualityRejectsEveryIsolatedDivergence()
    {
        var candidate = PersistenceCandidate();
        var baseline = StoredPersistence(candidate);
        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult,
            RuntimeEnrollmentAuthorityService.ClassifyStoredResult(
                baseline.Request, baseline.Lineage, baseline.Generation, candidate));

        var mutations = new Action<RuntimeEnrollmentAuthorityRequest, RuntimeEnrollmentAuthorityLineage,
            RuntimeEnrollmentAuthorityGeneration>[]
        {
            (request, _, _) => request.RequestId = Guid.NewGuid(),
            (request, _, _) => request.RequestDigest = new string('b', 64),
            (request, _, _) => request.AuthorityGenerationId = Guid.NewGuid(),
            (request, _, _) => request.AuthorityLineageId = Guid.NewGuid(),
            (request, _, _) => request.ResultCode = "REJECTED",
            (request, _, _) => request.ErrorCode = "ERROR",
            (request, _, _) => request.HttpStatusCode = 201,
            (request, _, _) => request.CreatedAtUtc = request.CreatedAtUtc.AddTicks(1),
            (request, _, _) => request.CompletedAtUtc = request.CompletedAtUtc.AddTicks(1),
            (request, _, _) => request.ExactResponseUtf8 = [9],
            (_, lineage, _) => lineage.AuthorityLineageId = Guid.NewGuid(),
            (_, lineage, _) => lineage.Provider = "Provider",
            (_, lineage, _) => lineage.ProductId = Guid.NewGuid(),
            (_, lineage, _) => lineage.LicenseSeatId = Guid.NewGuid(),
            (_, lineage, _) => lineage.ProviderGrantRef += " ",
            (_, lineage, _) => lineage.ProviderGrantRefScalarCount++,
            (_, lineage, _) => lineage.CreatedAtUtc = lineage.CreatedAtUtc.AddTicks(1),
            (_, _, generation) => generation.AuthorityGenerationId = Guid.NewGuid(),
            (_, _, generation) => generation.AuthorityLineageId = Guid.NewGuid(),
            (_, _, generation) => generation.Sequence++,
            (_, _, generation) => generation.PreviousGenerationId = Guid.NewGuid(),
            (_, _, generation) => generation.RequestId = Guid.NewGuid(),
            (_, _, generation) => generation.CanonicalPayloadUtf8 = [9],
            (_, _, generation) => generation.SignedStatementUtf8 = [9],
            (_, _, generation) => generation.AuthorityDigest = new string('b', 64),
            (_, _, generation) => generation.SignatureAlgorithm = "ps256",
            (_, _, generation) => generation.SignatureKeyId += " ",
            (_, _, generation) => generation.SignatureValue += "A",
            (_, _, generation) => generation.OccurredAtUtc = generation.OccurredAtUtc.AddTicks(1),
            (_, _, generation) => generation.CreatedAtUtc = generation.CreatedAtUtc.AddTicks(1)
        };

        foreach (var mutate in mutations)
        {
            var stored = StoredPersistence(candidate);
            mutate(stored.Request, stored.Lineage, stored.Generation);
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
                RuntimeEnrollmentAuthorityService.ClassifyStoredResult(
                    stored.Request, stored.Lineage, stored.Generation, candidate));
        }

        Assert.False(RuntimeEnrollmentAuthorityService.StoredResultEquals(
            baseline.Request, null, baseline.Generation, candidate));
        Assert.False(RuntimeEnrollmentAuthorityService.StoredResultEquals(
            baseline.Request, baseline.Lineage, null, candidate));
    }

    /// <summary>Proves retry, final authoritative-read, propagation, and CAS decisions are closed.</summary>
    [Fact]
    public void AuthorityPersistence_RetryAndCasDecisionsAreClosed()
    {
        var named = PersistenceConstraintNames[0];
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Retry,
            RuntimeEnrollmentAuthorityService.DecideRetry("23505", named, 1));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Retry,
            RuntimeEnrollmentAuthorityService.DecideRetry("23505", named, 2));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.AuthoritativeRead,
            RuntimeEnrollmentAuthorityService.DecideRetry("23505", named, 3));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Propagate,
            RuntimeEnrollmentAuthorityService.DecideRetry("23505", "unknown", 1));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Propagate,
            RuntimeEnrollmentAuthorityService.DecideRetry("23505", null, 1));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Retry,
            RuntimeEnrollmentAuthorityService.DecideRetry("40001", null, 1));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Retry,
            RuntimeEnrollmentAuthorityService.DecideRetry("40P01", null, 2));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Propagate,
            RuntimeEnrollmentAuthorityService.DecideRetry("40001", null, 3));
        Assert.Equal(RuntimeEnrollmentAuthorityRetryDecision.Propagate,
            RuntimeEnrollmentAuthorityService.DecideRetry("55P03", null, 1));
        Assert.Equal(RuntimeEnrollmentAuthorityFinalCollisionOutcome.ExactStoredResult,
            RuntimeEnrollmentAuthorityService.ClassifyFinalCollision(
                storedRequestFound: true, exactStoredResult: true));
        Assert.Equal(RuntimeEnrollmentAuthorityFinalCollisionOutcome.StructuralConflict,
            RuntimeEnrollmentAuthorityService.ClassifyFinalCollision(
                storedRequestFound: true, exactStoredResult: false));
        Assert.Equal(RuntimeEnrollmentAuthorityFinalCollisionOutcome.Exhausted,
            RuntimeEnrollmentAuthorityService.ClassifyFinalCollision(
                storedRequestFound: false, exactStoredResult: false));

        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
            RuntimeEnrollmentAuthorityService.ClassifyCasRowCount(0));
        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
            RuntimeEnrollmentAuthorityService.ClassifyCasRowCount(1));
        Assert.Throws<InvalidOperationException>(() =>
            RuntimeEnrollmentAuthorityService.ClassifyCasRowCount(2));
    }

    /// <summary>Proves the same phase machine consumed by persistence accepts nominal successor order.</summary>
    [Fact]
    public void AuthorityPersistence_StepOrderIsClosed()
    {
        var flow = new RuntimeEnrollmentAuthorityPersistenceFlow(genesis: false);
        foreach (var phase in new[]
        {
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
        })
            flow.Advance(phase);
    }

    /// <summary>Proves the production phase machine rejects omitted, duplicated, and permuted steps.</summary>
    [Fact]
    public void AuthorityPersistence_StepOrderRejectsInvalidTransitions()
    {
        var omitted = new RuntimeEnrollmentAuthorityPersistenceFlow(genesis: false);
        omitted.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Begin);
        Assert.Throws<InvalidOperationException>(() =>
            omitted.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Global));

        var duplicated = new RuntimeEnrollmentAuthorityPersistenceFlow(genesis: false);
        duplicated.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Begin);
        Assert.Throws<InvalidOperationException>(() =>
            duplicated.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Begin));

        var permuted = new RuntimeEnrollmentAuthorityPersistenceFlow(genesis: false);
        permuted.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Begin);
        permuted.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Timeouts);
        Assert.Throws<InvalidOperationException>(() =>
            permuted.Advance(RuntimeEnrollmentAuthorityPersistencePhase.Epoch));
    }

    /// <summary>Creates a valid opaque persistence candidate without normalization or cryptographic work.</summary>
    private static RuntimeEnrollmentAuthorityPersistenceCandidate PersistenceCandidate(
        int payloadBytes = 1, int statementBytes = 1, long sequence = 0, Guid? predecessor = null) => new()
    {
        AuthorityLineageId = Guid.Parse(LineageId),
        AuthorityGenerationId = Guid.Parse(GenerationId),
        RequestId = Guid.Parse(RequestId),
        RequestDigest = new string('a', 64),
        Provider = "provider",
        ProductId = Guid.Parse(ProductId),
        LicenseSeatId = Guid.Parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        ProviderGrantRef = "café-𐐀",
        ProviderGrantRefScalarCount = 6,
        LineageCreatedAtUtc = DateTime.Parse(Timestamp, null, DateTimeStyles.RoundtripKind),
        Sequence = sequence,
        PreviousGenerationId = predecessor,
        CanonicalPayloadUtf8 = new byte[payloadBytes],
        SignedStatementUtf8 = new byte[statementBytes],
        AuthorityDigest = new string('a', 64),
        SignatureAlgorithm = "PS256",
        SignatureKeyId = "key-1",
        SignatureValue = SharedPs256Signature,
        OccurredAtUtc = DateTime.Parse(Timestamp, null, DateTimeStyles.RoundtripKind),
        CreatedAtUtc = DateTime.Parse(Timestamp, null, DateTimeStyles.RoundtripKind),
        BindingIds = []
    };

    /// <summary>Creates exact immutable stored rows corresponding to one candidate.</summary>
    private static (RuntimeEnrollmentAuthorityRequest Request, RuntimeEnrollmentAuthorityLineage Lineage,
        RuntimeEnrollmentAuthorityGeneration Generation) StoredPersistence(
            RuntimeEnrollmentAuthorityPersistenceCandidate candidate) =>
        (new()
        {
            RequestId = candidate.RequestId,
            RequestDigest = candidate.RequestDigest,
            AuthorityLineageId = candidate.AuthorityLineageId,
            AuthorityGenerationId = candidate.AuthorityGenerationId,
            ResultCode = "ACCEPTED",
            HttpStatusCode = StatusCodes.Status200OK,
            CreatedAtUtc = candidate.CreatedAtUtc,
            CompletedAtUtc = candidate.CreatedAtUtc,
            ExactResponseUtf8 = [.. candidate.SignedStatementUtf8]
        },
        new()
        {
            AuthorityLineageId = candidate.AuthorityLineageId,
            Provider = candidate.Provider,
            ProductId = candidate.ProductId,
            LicenseSeatId = candidate.LicenseSeatId,
            ProviderGrantRef = candidate.ProviderGrantRef,
            ProviderGrantRefScalarCount = candidate.ProviderGrantRefScalarCount,
            CreatedAtUtc = candidate.LineageCreatedAtUtc,
            HeadGenerationId = candidate.AuthorityGenerationId,
            HeadSequence = candidate.Sequence
        },
        new()
        {
            AuthorityGenerationId = candidate.AuthorityGenerationId,
            AuthorityLineageId = candidate.AuthorityLineageId,
            Sequence = candidate.Sequence,
            PreviousGenerationId = candidate.PreviousGenerationId,
            RequestId = candidate.RequestId,
            CanonicalPayloadUtf8 = [.. candidate.CanonicalPayloadUtf8],
            SignedStatementUtf8 = [.. candidate.SignedStatementUtf8],
            AuthorityDigest = candidate.AuthorityDigest,
            SignatureAlgorithm = candidate.SignatureAlgorithm,
            SignatureKeyId = candidate.SignatureKeyId,
            SignatureValue = candidate.SignatureValue,
            OccurredAtUtc = candidate.OccurredAtUtc,
            CreatedAtUtc = candidate.CreatedAtUtc
        });

    /// <summary>Lists the canonical named unique surfaces in ordinal order.</summary>
    private static readonly string[] PersistenceConstraintNames =
    [
        "AK_REAuthorityGenerations_GenerationId_RequestId",
        "AK_REAuthorityGenerations_LineageId_GenerationId",
        "AK_REAuthorityGenerations_LineageId_GenerationId_RequestId",
        "AK_REAuthorityGenerations_LineageId_GenerationId_Sequence",
        "PK_REAuthorityGenerations",
        "PK_REAuthorityLineages",
        "PK_REAuthorityRequests",
        "UX_REAuthorityGenerations_LineageId_PredecessorId",
        "UX_REAuthorityGenerations_LineageId_Sequence",
        "UX_REAuthorityLineages_Provider_ProductId_GrantRef_SeatId",
        "UX_REAuthorityRequests_RequestId_LineageId_GenerationId"
    ];

    private static RuntimeEnrollmentOptions OptionsFor(RSA rsa) => new()
    {
        Mode = "enabled",
        Issuer = "https://runtime.example.test",
        CapabilityTtlSeconds = 120,
        CapabilitySigning = new RuntimeCapabilitySigningOptions
        {
            ActiveKeyId = "runtime-2026-01",
            Keys =
            [
                new RuntimeCapabilitySigningKeyOptions
                {
                    KeyId = "runtime-2026-01",
                    Role = "active",
                    PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
                    PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem()
                }
            ]
        },
        Encryption = new RuntimeEncryptionOptions { Keys = [] }
    };

    private static RuntimeMilestoneRequest MilestoneRequest(Guid enrollmentId, string code) => new()
    {
        Schema = RuntimeEnrollmentService.MilestoneSchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        EnrollmentId = enrollmentId.ToString("D"),
        Epoch = 1,
        SecurityEpoch = 1,
        SessionId = "22222222-2222-4222-8222-222222222222",
        Sequence = 1,
        EventId = "33333333-3333-4333-8333-333333333333",
        Code = code,
        OccurredAtUtc = "2026-07-20T10:00:00.0000000Z"
    };

    private static RuntimeProofHeaders ValidProofHeaders() => new(
        "2026-07-20T10:00:00.0000000Z",
        "44444444-4444-4444-8444-444444444444",
        new string('A', 512));

    private static byte[] Decode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        return Convert.FromBase64String(base64);
    }

    private sealed class InMemoryFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>()
                .UseInMemoryDatabase("runtime-provider-gate-" + Guid.NewGuid().ToString("N"))
                .Options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}
