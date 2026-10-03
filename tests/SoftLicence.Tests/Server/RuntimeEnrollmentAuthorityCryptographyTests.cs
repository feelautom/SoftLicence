using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Discriminates strict Runtime Enrollment v2 bytes, PS256, registry trust, and immutable results.</summary>
public sealed class RuntimeEnrollmentAuthorityCryptographyTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 24, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Proves the byte-identical shared request/payload/PS256 oracle and RSA exponent 65537.</summary>
    [Fact]
    public void SharedVector_RemainsByteExactAndVerifiesPs256Profile()
    {
        var bytes = File.ReadAllBytes(VectorPath());
        Assert.Equal(59771, bytes.Length);
        Assert.Equal("a2d1df332a432c838d64e51338275215e9413cbb2cc158b95441daf365771cd6",
            Convert.ToHexStringLower(SHA256.HashData(bytes)));
        using var vector = JsonDocument.Parse(bytes);
        var crypto = Crypto();
        var request = vector.RootElement.GetProperty("requestCanonicalization");
        var requestResult = crypto.CanonicalizeRequest(Encoding.UTF8.GetBytes(request.GetProperty("request").GetRawText()));
        Assert.Equal(request.GetProperty("canonicalJson").GetString(), Encoding.UTF8.GetString(requestResult.Value!.CanonicalUtf8));
        Assert.Equal(request.GetProperty("requestDigest").GetString(), requestResult.Value.Digest);
        var generation = vector.RootElement.GetProperty("canonicalization");
        var generationResult = crypto.CanonicalizeGenerationPayload(Encoding.UTF8.GetBytes(generation.GetProperty("payload").GetRawText()));
        Assert.Equal(generation.GetProperty("canonicalJson").GetString(), Encoding.UTF8.GetString(generationResult.Value!.CanonicalUtf8));
        Assert.Equal(generation.GetProperty("authorityDigest").GetString(), generationResult.Value.Digest);
        var ps = vector.RootElement.GetProperty("ps256");
        var spki = Convert.FromBase64String(ps.GetProperty("publicKeySpkiBase64").GetString()!);
        using var rsa = RSA.Create(); rsa.ImportSubjectPublicKeyInfo(spki, out _);
        Assert.Equal([0x01, 0x00, 0x01], rsa.ExportParameters(false).Exponent);
        Assert.Equal(ps.GetProperty("publicKeyModulusBase64Url").GetString(),
            EncodeBase64Url(rsa.ExportParameters(false).Modulus!));
        var input = Convert.FromHexString(ps.GetProperty("domainHex").GetString()! + "0a" + generation.GetProperty("canonicalUtf8Hex").GetString());
        Assert.Equal(ps.GetProperty("signingInputSha256").GetString(),
            Convert.ToHexStringLower(SHA256.HashData(input)));
        Assert.True(RuntimeEnrollmentAuthorityCryptography.VerifyDetachedPs256(spki, input, DecodeBase64Url(ps.GetProperty("signatureBase64Url").GetString()!)));
    }

    /// <summary>Proves the canonical wire schema, four-member root, complete sign/reparse/verify, and old-schema refusal.</summary>
    [Fact]
    public void SignedGeneration_IsAtomicCanonicalAndRejectsFormerSchema()
    {
        using var keys = new TestKeys();
        var options = keys.CreateOptions();
        var crypto = Crypto(keys.Registry);
        var proof = Authenticate(crypto, options, keys.Registry);
        var signed = crypto.SignGeneration(options, ValidPayloadBytes());
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, signed.Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.ParseAndVerifyStatement(signed.Value!.StatementUtf8, proof));
        using var statement = JsonDocument.Parse(signed.Value.StatementUtf8);
        Assert.Equal(["schema", "payload", "authorityDigest", "signature"], statement.RootElement.EnumerateObject().Select(property => property.Name));
        Assert.Equal("runtime-enrollment-signed-generation-v2", statement.RootElement.GetProperty("schema").GetString());
        Assert.Equal(0, statement.RootElement.GetProperty("payload").GetProperty("sequence").GetInt64());
        Assert.False(statement.RootElement.TryGetProperty("contractVersion", out _));
        var oldSchema = MutateJson(signed.Value.StatementUtf8, root => root["schema"] = "runtime-enrollment-authority-generation-statement-v2");
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.SchemaInvalid, crypto.ParseAndVerifyStatement(oldSchema, proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.DigestInvalid, crypto.ParseAndVerifyStatement(MutateJson(signed.Value.StatementUtf8, root => root["payload"]!["providerGrantRef"] = "substituted"), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.DigestInvalid, crypto.ParseAndVerifyStatement(MutateJson(signed.Value.StatementUtf8, root => root["payload"]!["sequence"] = 1), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyNotAuthorized, crypto.ParseAndVerifyStatement(MutateJson(signed.Value.StatementUtf8, root => root["signature"]!["keyId"] = "recovery-2026-01"), proof));
        var payloadCopy = signed.Value.CanonicalPayloadUtf8; payloadCopy[0] ^= 1;
        var statementCopy = signed.Value.StatementUtf8; statementCopy[0] ^= 1;
        Assert.Equal((byte)'{', signed.Value.CanonicalPayloadUtf8[0]);
        Assert.Equal((byte)'{', signed.Value.StatementUtf8[0]);
    }

    /// <summary>
    /// Proves persisted generic generations are reverified with their exact configured operational key and
    /// that payload, key, and signature substitution fail closed without relying on a fresh registry snapshot.
    /// </summary>
    [Fact]
    public void PersistedGeneration_RequiresExactConfiguredOperationalSignature()
    {
        using var keys = new TestKeys();
        var options = keys.CreateOptions();
        var crypto = Crypto(keys.Registry);
        var payload = ValidPayloadBytes();
        var signed = crypto.SignGeneration(options, payload).Value!;

        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None,
            crypto.VerifyGenerationSignature(options, signed.CanonicalPayloadUtf8, signed.KeyId, signed.Signature));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.SignatureInvalid,
            crypto.VerifyGenerationSignature(options, signed.CanonicalPayloadUtf8, signed.KeyId,
                (signed.Signature[0] == 'A' ? "B" : "A") + signed.Signature[1..]));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyNotAuthorized,
            crypto.VerifyGenerationSignature(options, signed.CanonicalPayloadUtf8,
                "recovery-2026-01", signed.Signature));
        Assert.NotEqual(RuntimeEnrollmentAuthorityCryptography.Failure.None,
            crypto.VerifyGenerationSignature(options,
                MutatedPayload(root => root["providerGrantRef"] = "substituted"),
                signed.KeyId, signed.Signature));

        var rotated = keys.CreateOptions(includeSecondOperational: true);
        var historical = crypto.SignGeneration(rotated, payload).Value!;
        rotated.Keys.Single(key => key.KeyId == "operational-2026-01").PrivateKeyPem = null;
        rotated.Keys.Single(key => key.KeyId == "operational-next").PrivateKeyPem =
            keys.Other.ExportPkcs8PrivateKeyPem();
        rotated.ActiveSigningKeyId = "operational-next";
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(rotated));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None,
            crypto.VerifyGenerationSignature(rotated, historical.CanonicalPayloadUtf8,
                historical.KeyId, historical.Signature));
    }

    /// <summary>Proves request-only transition shape, requestedAtUtc, and genesis expected-ID relations are closed.</summary>
    [Fact]
    public void RequestParser_RejectsCrossedTransitionAndGenesisRelations()
    {
        var crypto = Crypto();
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidContract, crypto.CanonicalizeRequest(MutateJson(ValidRequestBytes(), root => root["transition"]!["requestId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeRequest(MutateJson(ValidRequestBytes(), root => root["transition"]!["requestedAtUtc"] = null)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeRequest(MutateJson(ValidRequestBytes(), root => root["expectedAuthorityLineageId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).Error);
        var nonGenesis = ValidNonGenesisRequestBytes();
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.CanonicalizeRequest(nonGenesis).Error);
        foreach (var name in new[] { "expectedAuthorityLineageId", "expectedCurrentGenerationId", "expectedPredecessorGenerationId" })
            Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeRequest(MutateJson(nonGenesis, root => root[name] = null)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeRequest(MutateJson(nonGenesis, root => root["expectedPredecessorGenerationId"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc")).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeRequest(MutateJson(nonGenesis, root => { root["expectedCurrentGenerationId"] = null; root["expectedPredecessorGenerationId"] = null; })).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeRequest(MutateJson(nonGenesis, root => { root["expectedAuthorityLineageId"] = null; root["expectedCurrentGenerationId"] = null; root["expectedPredecessorGenerationId"] = null; })).Error);
    }

    /// <summary>Proves only sequence-zero recovery may open a lineage without predecessor.</summary>
    [Fact]
    public void RecoveryGenesis_RequiresSequenceZeroAndNullPredecessor()
    {
        var crypto = Crypto();
        var recoveryGenesis = MutatedPayload(root =>
        {
            root["transition"]!["kind"] = "recovery";
            root["transition"]!["reasonCode"] = "RECOVERY_AUTHORIZED";
        });
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None,
            crypto.CanonicalizeGenerationPayload(recoveryGenesis).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid,
            crypto.CanonicalizeGenerationPayload(MutateJson(recoveryGenesis,
                root => root["sequence"] = 1)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid,
            crypto.CanonicalizeGenerationPayload(MutateJson(recoveryGenesis,
                root => root["previousGenerationId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).Error);
    }

    /// <summary>Proves every leaf family rejects wrong type, nullability, grammar, enum, relation, float, and coercion.</summary>
    [Fact]
    public void PayloadParser_RejectsClosedScalarMatrix()
    {
        var crypto = Crypto();
        var mutations = new Action<JsonObject>[]
        {
            root => root["contractVersion"] = "2",
            root => root["authorityLineageId"] = null,
            root => root["authorityGenerationId"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            root => root["sequence"] = -1,
            root => root["sequence"] = JsonNode.Parse("1.0"),
            root => root["sequence"] = "0",
            root => root["provider"] = "Provider",
            root => root["providerGrantRef"] = "",
            root => root["providerGrantRef"] = new string('x', 257),
            root => root["providerGrantRef"] = "bad\u0001ref",
            root => root["productId"] = true,
            root => root["release"]!["version"] = "01.2.3",
            root => root["release"]!["version"] = "2147483648.0.0",
            root => root["release"]!["artifactSetDigest"] = new string('A', 64),
            root => root["binding"]!["bindingId"] = 1,
            root => root["enrollment"]!["state"] = "ACTIVE",
            root => root["enrollment"]!["issuedAtUtc"] = "2026-08-24T12:00:00Z",
            root => root["enrollment"]!["expiresAtUtc"] = root["enrollment"]!["issuedAtUtc"]!.DeepClone(),
            root => root["key"]!["authorityKeyId"] = "UPPER",
            root => root["key"]!["securityEpoch"] = -1,
            root => root["key"]!["securityEpoch"] = JsonNode.Parse("1.0"),
            root => root["installation"]!["installationId"] = null,
            root => root["transition"]!["kind"] = "unknown",
            root => root["transition"]!["reasonCode"] = "APPROVED_RELEASE_ADVANCE",
            root => root["transition"]!["occurredAtUtc"] = false,
        };
        foreach (var mutation in mutations)
            Assert.NotEqual(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.CanonicalizeGenerationPayload(MutatedPayload(mutation)).Error);

        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidContract, crypto.CanonicalizeGenerationPayload(MutatedPayload(root => root.Remove("binding"))).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidContract, crypto.CanonicalizeGenerationPayload(MutatedPayload(root => root.Remove("sequence"))).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.CanonicalizeGenerationPayload(MutatedPayload(root => root["sequence"] = 9_007_199_254_740_991L)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.ScalarInvalid, crypto.CanonicalizeGenerationPayload(MutatedPayload(root => root["sequence"] = 9_007_199_254_740_992L)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidContract, crypto.CanonicalizeGenerationPayload(MutatedPayload(root => root["unknown"] = 1)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidContract, crypto.CanonicalizeGenerationPayload(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(ValidPayloadBytes()).Replace("{\"schema\":", "{\"Schema\":"))).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidContract, crypto.CanonicalizeGenerationPayload(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(ValidPayloadBytes())[..^1] + ",\"schema\":\"runtime-enrollment-authority-generation-v2\"}")).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InvalidUtf8, crypto.CanonicalizeGenerationPayload([0xff]).Error);
        Assert.NotEqual(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.CanonicalizeGenerationPayload([.. ValidPayloadBytes(), (byte)'x']).Error);
    }

    /// <summary>Proves composed, decomposed, astral, whitespace, and case variants remain ordinally distinct and unrepaired.</summary>
    [Fact]
    public void OpaqueProviderGrantRef_IsNeverNormalizedOrCaseFolded()
    {
        var crypto = Crypto();
        var values = new[] { "grant:café", "grant:cafe\u0301", "grant:🚀", " Grant:Case " };
        var canonical = values.Select(value => Encoding.UTF8.GetString(crypto.CanonicalizeGenerationPayload(MutatedPayload(root => root["providerGrantRef"] = value)).Value!.CanonicalUtf8)).ToArray();
        Assert.Equal(values.Length, canonical.Distinct(StringComparer.Ordinal).Count());
        for (var index = 0; index < values.Length; index++)
        { using var document = JsonDocument.Parse(canonical[index]); Assert.Equal(values[index], document.RootElement.GetProperty("providerGrantRef").GetString()); }
    }

    /// <summary>Proves lowercase digest bytes and canonical Base64Url reject malformed, mismatched, padded, aliased, and bad-alphabet inputs.</summary>
    [Fact]
    public void StatementParser_RejectsDigestAndBase64UrlAliases()
    {
        using var keys = new TestKeys(); var options = keys.CreateOptions(); var crypto = Crypto(keys.Registry); var proof = Authenticate(crypto, options, keys.Registry);
        var signed = crypto.SignGeneration(options, ValidPayloadBytes()).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.DigestInvalid, crypto.ParseAndVerifyStatement(MutateJson(signed.StatementUtf8, root => root["authorityDigest"] = new string('A', 64)), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.DigestInvalid, crypto.ParseAndVerifyStatement(MutateJson(signed.StatementUtf8, root => root["authorityDigest"] = new string('0', 63)), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.DigestInvalid, crypto.ParseAndVerifyStatement(MutateJson(signed.StatementUtf8, root => root["authorityDigest"] = new string('0', 64)), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.Base64UrlInvalid, crypto.ParseAndVerifyStatement(MutateSignature(signed, value => value + "="), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.Base64UrlInvalid, crypto.ParseAndVerifyStatement(MutateSignature(signed, value => value[..^1] + "+"), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.Base64UrlInvalid, crypto.ParseAndVerifyStatement(MutateSignature(signed, NonZeroUnusedPadBits), proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.SignatureInvalid, crypto.ParseAndVerifyStatement(MutateSignature(signed, value => (value[0] == 'A' ? "B" : "A") + value[1..]), proof));
    }

    /// <summary>Proves one shared validator closes startup, proof authentication, and direct signing configuration.</summary>
    [Fact]
    public void ConfigurationValidator_RejectsEachDivergenceAndAllowsCoexistingActivePublicKeys()
    {
        using var keys = new TestKeys(); var validator = new RuntimeEnrollmentOptionsValidator();
        Assert.Equal(ValidateOptionsResult.Success, validator.Validate(null, new RuntimeEnrollmentOptions { Mode = "off" }));
        var valid = keys.CreateOptions();
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(valid));
        var crypto = Crypto();
        Assert.Equal(ValidateOptionsResult.Success, validator.Validate(null, new RuntimeEnrollmentOptions { Mode = "off", AuthorityGenerationSigning = valid }));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.SignGeneration(null, ValidPayloadBytes()).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.GetRegistrySnapshotAuthenticationInput(null, Now).Error);
        var invalids = new Action<RuntimeAuthorityGenerationSigningOptions>[]
        {
            options => options.Keys.Clear(),
            options => options.RegistrySnapshotVersion = 0,
            options => options.Keys[0].KeyId = new string('a', 129),
            options => options.Keys[1].KeyId = options.Keys[0].KeyId,
            options => options.Keys[0].Status = "preauthorized",
            options => options.Keys[0].Purpose = "recovery",
            options => options.Keys[0].Domain = "recovery",
            options => options.Keys[0].ContractVersion = 1,
            options => options.Keys.Reverse(),
            options => options.Keys[1].PublicKeyPem = options.Keys[0].PublicKeyPem,
            options => options.Keys[0].ActivatedAtUtc = new DateTimeOffset(Now.DateTime, TimeSpan.FromHours(1)),
            options => options.Keys[0].RetiredAtUtc = Now,
            options => options.Keys[0].CompromiseFromUtc = Now.AddDays(-2),
            options => { options.Keys[1].Status = "revoked"; options.Keys[1].RevokedAtUtc = Now; },
            options => options.Keys[1].PrivateKeyPem = keys.Recovery.ExportPkcs8PrivateKeyPem(),
            options => options.Keys[0].PrivateKeyPem = keys.Other.ExportPkcs8PrivateKeyPem(),
        };
        foreach (var mutation in invalids)
        {
            var options = keys.CreateOptions(); mutation(options);
            Assert.NotEmpty(RuntimeAuthorityGenerationConfigurationValidator.Validate(options));
            Assert.True(validator.Validate(null, new RuntimeEnrollmentOptions { Mode = "off", AuthorityGenerationSigning = options }).Failed);
            Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.SignGeneration(options, ValidPayloadBytes()).Error);
            Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.GetRegistrySnapshotAuthenticationInput(options, Now).Error);
        }
        var coexist = keys.CreateOptions(includeSecondOperational: true);
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(coexist));
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(keys.CreateOptions(activeKeyId: "a")));
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(keys.CreateOptions(activeKeyId: new string('a', 128))));
        var nineKeys = keys.CreateOptions();
        var additionalKeys = Enumerable.Range(0, 7).Select(_ => RSA.Create(2048)).ToArray();
        try
        {
            for (var index = 0; index < additionalKeys.Length; index++)
                nineKeys.Keys.Add(new() { KeyId = $"x{index}", Purpose = "operational", Domain = "generation", ContractVersion = 2, Status = "active", ActivatedAtUtc = Now.AddDays(-1), PublicKeyPem = additionalKeys[index].ExportSubjectPublicKeyInfoPem() });
            nineKeys.Keys.Sort((left, right) => string.CompareOrdinal(left.KeyId, right.KeyId));
            Assert.Equal(9, nineKeys.Keys.Count);
            Assert.Equal(9, nineKeys.Keys.Select(key => key.PublicKeyPem).Distinct(StringComparer.Ordinal).Count());
            Assert.Equal(
                ["Runtime authority-generation registry requires identifiers, a positive snapshot version, and one to eight keys."],
                RuntimeAuthorityGenerationConfigurationValidator.Validate(nineKeys));
        }
        finally
        {
            foreach (var additionalKey in additionalKeys) additionalKey.Dispose();
        }
        var retired = keys.CreateOptions();
        retired.Keys[1].Status = "retired"; retired.Keys[1].RetiredAtUtc = Now;
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(retired));
        var revoked = keys.CreateOptions();
        revoked.Keys[1].Status = "revoked"; revoked.Keys[1].RevokedAtUtc = Now; revoked.Keys[1].RevocationReason = "compromised"; revoked.Keys[1].CompromiseFromUtc = Now.AddHours(-1);
        Assert.Empty(RuntimeAuthorityGenerationConfigurationValidator.Validate(revoked));
    }

    /// <summary>Proves the immutable registry authority pin cannot equal an operational or recovery key at any item 2 entry point.</summary>
    [Fact]
    public void RegistryAuthorityPin_MustRemainSeparateFromOperationalAndRecoveryKeys()
    {
        using var keys = new TestKeys();
        AssertRegistryPinCollisionRejected(keys, keys.Operational);
        AssertRegistryPinCollisionRejected(keys, keys.Recovery);
    }

    /// <summary>Proves authenticated recovery evidence permits exact retry while rejecting every binding substitution.</summary>
    [Fact]
    public void SnapshotAndRecoveryProofs_AreAuthenticatedBoundAndOneUse()
    {
        using var keys = new TestKeys(); var options = keys.CreateOptions(); var crypto = Crypto(keys.Registry);
        var input = crypto.GetRegistrySnapshotAuthenticationInput(options, Now).Value!;
        var selfDeclared = keys.CreateOptions(); selfDeclared.Keys[1].PublicKeyPem = keys.Other.ExportSubjectPublicKeyInfoPem();
        var selfInput = crypto.GetRegistrySnapshotAuthenticationInput(selfDeclared, Now).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.SnapshotAuthenticationInvalid, crypto.AuthenticateRegistrySnapshot(selfDeclared, Now, keys.Other.SignData(selfInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyRegistryTimeInvalid, AuthenticateAt(crypto, options, keys.Registry, Now.AddTicks(1)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, AuthenticateAt(crypto, options, keys.Registry, Now.AddSeconds(-300)).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyRegistryStale, AuthenticateAt(crypto, options, keys.Registry, Now.AddSeconds(-300).AddTicks(-1)).Error);
        var payload = ValidPayloadBytes();
        var signedBeforeMutation = crypto.SignGeneration(options, payload).Value!;
        var evidence = AuthenticateAt(crypto, options, keys.Registry, Now).Value!;
        options.Keys.Clear();
        var proof = crypto.CreateTrustedSnapshotProof(evidence);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.ParseAndVerifyStatement(signedBeforeMutation.StatementUtf8, proof));
        var canonical = crypto.CanonicalizeGenerationPayload(payload).Value!.CanonicalUtf8;
        var recoveryInput = Encoding.UTF8.GetBytes("T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n" + Encoding.UTF8.GetString(canonical));
        var signature = EncodeBase64Url(keys.Recovery.SignData(recoveryInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var recoveryProof = crypto.VerifyRecoverySignature(payload, "recovery-2026-01", signature, proof).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.RecoveryProofInvalid, crypto.ConsumeRecoveryProof(recoveryProof, MutatedPayload(root => root["providerGrantRef"] = "different"), "recovery-2026-01", proof));
        var wrongKeyProof = crypto.VerifyRecoverySignature(payload, "recovery-2026-01", signature, proof).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.RecoveryProofInvalid, crypto.ConsumeRecoveryProof(wrongKeyProof, payload, "other-key", proof));
        var otherIdentityOptions = keys.CreateOptions(); otherIdentityOptions.RegistrySnapshotId = "registry-other"; otherIdentityOptions.RegistrySnapshotVersion = 2;
        var otherIdentityProof = Authenticate(crypto, otherIdentityOptions, keys.Registry);
        var wrongSnapshotProof = crypto.VerifyRecoverySignature(payload, "recovery-2026-01", signature, proof).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.RecoveryProofInvalid, crypto.ConsumeRecoveryProof(wrongSnapshotProof, payload, "recovery-2026-01", otherIdentityProof));
        var changedKeysetOptions = keys.CreateOptions(); changedKeysetOptions.Keys[1].PublicKeyPem = keys.Other.ExportSubjectPublicKeyInfoPem();
        var changedKeysetProof = Authenticate(crypto, changedKeysetOptions, keys.Registry);
        var fingerprintProof = crypto.VerifyRecoverySignature(payload, "recovery-2026-01", signature, proof).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.RecoveryProofInvalid, crypto.ConsumeRecoveryProof(fingerprintProof, payload, "recovery-2026-01", changedKeysetProof));
        var freshProof = crypto.VerifyRecoverySignature(payload, "recovery-2026-01", signature, proof).Value!;
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.ConsumeRecoveryProof(freshProof, payload, "recovery-2026-01", proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.ConsumeRecoveryProof(freshProof, payload, "recovery-2026-01", proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.RecoveryProofInvalid,
            crypto.ConsumeRecoveryProof(freshProof, MutatedPayload(root => root["providerGrantRef"] = "retry-substitution"), "recovery-2026-01", proof));
    }

    /// <summary>Proves valid payload and signed-statement fixtures at exact item 1 bounds and max-plus-one refusal.</summary>
    [Fact]
    public void ValidFixtures_ReachExactPayloadAndStatementBounds()
    {
        using var keys = new TestKeys(); var crypto = Crypto(keys.Registry);
        var requestAtBound = PadValidJson(ValidRequestBytes(), 4096);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.CanonicalizeRequest(requestAtBound).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InputTooLarge, crypto.CanonicalizeRequest([.. requestAtBound, (byte)' ']).Error);
        var payload = PadValidJson(ValidPayloadBytes(), 2895);
        Assert.Equal(2895, payload.Length);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.CanonicalizeGenerationPayload(payload).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InputTooLarge, crypto.CanonicalizeGenerationPayload([.. payload, (byte)' ']).Error);
        var options = keys.CreateOptions();
        var proof = Authenticate(crypto, options, keys.Registry);
        var signed = crypto.SignGeneration(options, payload).Value!;
        var statementAtBound = PadValidJson(signed.StatementUtf8, 3569);
        Assert.Equal(3569, statementAtBound.Length);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, crypto.ParseAndVerifyStatement(statementAtBound, proof));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.InputTooLarge, crypto.ParseAndVerifyStatement([.. statementAtBound, (byte)' '], proof));
    }

    /// <summary>Creates the item 2 component with immutable trusted test time.</summary>
    private static RuntimeEnrollmentAuthorityCryptography Crypto(RSA? registryAuthority = null)
    {
        if (registryAuthority is not null) return new(new FixedTimeProvider(Now), registryAuthority.ExportSubjectPublicKeyInfo());
        using var vector = JsonDocument.Parse(File.ReadAllBytes(VectorPath()));
        return new(new FixedTimeProvider(Now), Convert.FromBase64String(vector.RootElement.GetProperty("ps256").GetProperty("publicKeySpkiBase64").GetString()!));
    }
    /// <summary>Returns the copied shared-vector path.</summary>
    private static string VectorPath() => Path.Combine(AppContext.BaseDirectory, "TestData", "runtime-enrollment-v2-reference-vectors.json");
    /// <summary>Reads the independent shared canonical request bytes.</summary>
    private static byte[] ValidRequestBytes() { using var vector = JsonDocument.Parse(File.ReadAllBytes(VectorPath())); return Encoding.UTF8.GetBytes(vector.RootElement.GetProperty("requestCanonicalization").GetProperty("canonicalJson").GetString()!); }
    /// <summary>Builds a valid non-genesis request with three non-null expected IDs and exact predecessor equality.</summary>
    private static byte[] ValidNonGenesisRequestBytes() => MutateJson(ValidRequestBytes(), root =>
    {
        root["expectedAuthorityLineageId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        root["expectedCurrentGenerationId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        root["expectedPredecessorGenerationId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        root["transition"]!["kind"] = "release";
        root["transition"]!["reasonCode"] = "APPROVED_RELEASE_ADVANCE";
    });
    /// <summary>Reads the independent shared canonical payload bytes.</summary>
    private static byte[] ValidPayloadBytes() { using var vector = JsonDocument.Parse(File.ReadAllBytes(VectorPath())); return Encoding.UTF8.GetBytes(vector.RootElement.GetProperty("canonicalization").GetProperty("canonicalJson").GetString()!); }
    /// <summary>Mutates a fresh valid payload without using production writers.</summary>
    private static byte[] MutatedPayload(Action<JsonObject> mutation) => MutateJson(ValidPayloadBytes(), mutation);
    /// <summary>Mutates test JSON through the general JSON DOM, independently of production canonicalization.</summary>
    private static byte[] MutateJson(byte[] source, Action<JsonObject> mutation) { var root = JsonNode.Parse(source)!.AsObject(); mutation(root); return Encoding.UTF8.GetBytes(root.ToJsonString()); }
    /// <summary>Mutates only statement signature text.</summary>
    private static byte[] MutateSignature(RuntimeEnrollmentAuthorityCryptography.SignedGenerationResult signed, Func<string, string> mutation) => MutateJson(signed.StatementUtf8, root => root["signature"]!["value"] = mutation(root["signature"]!["value"]!.GetValue<string>()));
    /// <summary>Creates a same-prefix Base64Url alias with non-zero unused pad bits.</summary>
    private static string NonZeroUnusedPadBits(string value) { const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; var index = alphabet.IndexOf(value[^1]); return value[..^1] + alphabet[(index & 0x30) | 1]; }
    /// <summary>Decodes known-good shared unpadded Base64Url.</summary>
    private static byte[] DecodeBase64Url(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "==");
    /// <summary>Encodes test-generated signatures as unpadded Base64Url.</summary>
    private static string EncodeBase64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Authenticates options and creates a proof through item 2-owned APIs.</summary>
    private static RuntimeEnrollmentAuthorityCryptography.TrustedKeyRegistrySnapshotProof Authenticate(RuntimeEnrollmentAuthorityCryptography crypto, RuntimeAuthorityGenerationSigningOptions options, RSA registry)
        => crypto.CreateTrustedSnapshotProof(AuthenticateAt(crypto, options, registry, Now).Value!);
    /// <summary>Signs exact snapshot-authentication bytes with the independent test registry authority.</summary>
    private static RuntimeEnrollmentAuthorityCryptography.Result<RuntimeEnrollmentAuthorityCryptography.AuthenticatedRegistrySnapshotEvidence> AuthenticateAt(RuntimeEnrollmentAuthorityCryptography crypto, RuntimeAuthorityGenerationSigningOptions options, RSA registry, DateTimeOffset observed)
    { var input = crypto.GetRegistrySnapshotAuthenticationInput(options, observed).Value!; return crypto.AuthenticateRegistrySnapshot(options, observed, registry.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)); }

    /// <summary>Proves one otherwise-valid configuration is rejected solely because an external authority pin equals a keyset SPKI.</summary>
    /// <param name="keys">Owner of the otherwise-valid operational, recovery, and independent registry keys.</param>
    /// <param name="collidingAuthority">Operational or recovery key deliberately reused as the immutable external registry pin.</param>
    private static void AssertRegistryPinCollisionRejected(TestKeys keys, RSA collidingAuthority)
    {
        var options = keys.CreateOptions();
        var inputBuilder = Crypto(keys.Registry);
        var authenticationInput = inputBuilder.GetRegistrySnapshotAuthenticationInput(options, Now).Value!;
        var authoritySignature = collidingAuthority.SignData(authenticationInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var crypto = Crypto(collidingAuthority);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.GetRegistrySnapshotAuthenticationInput(options, Now).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.AuthenticateRegistrySnapshot(options, Now, authoritySignature).Error);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.KeyConfigurationInvalid, crypto.SignGeneration(options, ValidPayloadBytes()).Error);
    }

    /// <summary>Pads a complete JSON value with insignificant spaces to an exact valid input-byte boundary.</summary>
    private static byte[] PadValidJson(byte[] json, int length) => json.Length <= length
        ? [.. json, .. Enumerable.Repeat((byte)' ', length - json.Length)]
        : throw new ArgumentOutOfRangeException(nameof(length));

    /// <summary>Owns ephemeral RSA-2048 test keys and disposes all private material.</summary>
    private sealed class TestKeys : IDisposable
    {
        /// <summary>Gets the selected operational signer.</summary>
        internal RSA Operational { get; } = RSA.Create(2048);
        /// <summary>Gets the separately purposed recovery signer.</summary>
        internal RSA Recovery { get; } = RSA.Create(2048);
        /// <summary>Gets the separately pinned registry authority.</summary>
        internal RSA Registry { get; } = RSA.Create(2048);
        /// <summary>Gets unrelated RSA material for mismatch tests.</summary>
        internal RSA Other { get; } = RSA.Create(2048);
        /// <summary>Creates exact sorted valid options, optionally with a second active public operational key.</summary>
        internal RuntimeAuthorityGenerationSigningOptions CreateOptions(string activeKeyId = "operational-2026-01", bool includeSecondOperational = false)
        {
            var keys = new List<RuntimeAuthorityGenerationKeyOptions>
            {
                new() { KeyId = activeKeyId, Purpose = "operational", Domain = "generation", ContractVersion = 2, Status = "active", ActivatedAtUtc = Now.AddDays(-1), PublicKeyPem = Operational.ExportSubjectPublicKeyInfoPem(), PrivateKeyPem = Operational.ExportPkcs8PrivateKeyPem() },
                new() { KeyId = "recovery-2026-01", Purpose = "recovery", Domain = "recovery", ContractVersion = 2, Status = "active", ActivatedAtUtc = Now.AddDays(-1), PublicKeyPem = Recovery.ExportSubjectPublicKeyInfoPem() },
            };
            if (includeSecondOperational) keys.Add(new() { KeyId = "operational-next", Purpose = "operational", Domain = "generation", ContractVersion = 2, Status = "active", ActivatedAtUtc = Now.AddDays(-1), PublicKeyPem = Other.ExportSubjectPublicKeyInfoPem() });
            keys.Sort((left, right) => string.CompareOrdinal(left.KeyId, right.KeyId));
            return new() { ActiveSigningKeyId = activeKeyId, RegistrySnapshotId = "registry-2026-01", RegistrySnapshotVersion = 1, Keys = keys };
        }
        /// <summary>Disposes every ephemeral private key.</summary>
        public void Dispose() { Operational.Dispose(); Recovery.Dispose(); Registry.Dispose(); Other.Dispose(); }
    }

    /// <summary>Supplies one trusted immutable UTC instant.</summary>
    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        /// <summary>Returns the trusted fixed UTC instant.</summary>
        public override DateTimeOffset GetUtcNow() => value;
    }
}
