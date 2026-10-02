using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SoftLicence.Server.Services;

/// <summary>Owns strict Runtime Enrollment v2 bytes, current registry trust, PS256 signing, and verification.</summary>
internal sealed class RuntimeEnrollmentAuthorityCryptography
{
    /// <summary>Maximum authority-request input length before parsing.</summary>
    internal const int MaximumRequestBytes = 4096;
    /// <summary>Maximum generation-payload input length before parsing.</summary>
    internal const int MaximumGenerationPayloadBytes = 2895;
    /// <summary>Maximum signed-statement input length before parsing.</summary>
    internal const int MaximumSignedStatementBytes = 3569;
    /// <summary>Inclusive authenticated registry freshness limit.</summary>
    internal static readonly TimeSpan MaximumRegistryAge = TimeSpan.FromSeconds(300);
    /// <summary>Exact 42-byte request digest domain.</summary>
    private static readonly byte[] RequestDomain = "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0REQUEST\0V2"u8.ToArray();
    /// <summary>Exact 55-byte generation signing domain.</summary>
    private static readonly byte[] GenerationDomain = "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2"u8.ToArray();
    /// <summary>Internal domain for authentication of current registry metadata.</summary>
    private static readonly byte[] RegistryDomain = "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0KEY-REGISTRY-SNAPSHOT\0V2"u8.ToArray();
    /// <summary>BOM-free decoder that throws on malformed UTF-8.</summary>
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    /// <summary>Process-private capability required by every proof constructor and consumer.</summary>
    private static readonly object ProofSeal = new();
    /// <summary>Trusted SoftLicence time source.</summary>
    private readonly TimeProvider clock;
    /// <summary>Immutable item-2-owned copy of the independently provisioned registry authority SPKI.</summary>
    private readonly byte[] registryAuthoritySpki;

    /// <summary>Initializes the item 2 owner with trusted time and an independent immutable registry-authority pin.</summary>
    /// <param name="clock">Authoritative time source, never request or payload time.</param>
    /// <param name="registryAuthoritySpki">RSA-2048/e65537 public SPKI supplied by future trusted composition, never by snapshot options.</param>
    /// <exception cref="ArgumentException">The pin is not a complete RSA-2048/e65537 SPKI.</exception>
    internal RuntimeEnrollmentAuthorityCryptography(TimeProvider clock, ReadOnlySpan<byte> registryAuthoritySpki)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(registryAuthoritySpki, out var read);
            if (read != registryAuthoritySpki.Length || rsa.KeySize != 2048 || rsa.ExportParameters(false).Exponent is not [0x01, 0x00, 0x01])
                throw new ArgumentException("Registry authority pin must be exact RSA-2048/e65537 SPKI.", nameof(registryAuthoritySpki));
            this.registryAuthoritySpki = rsa.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException("Registry authority pin must be exact RSA-2048/e65537 SPKI.", nameof(registryAuthoritySpki), exception);
        }
        this.clock = clock;
    }

    /// <summary>Closed internal failures returned instead of parsing, conversion, or cryptographic exceptions.</summary>
    internal enum Failure
    {
        /// <summary>Operation succeeded and its value owns all returned buffers.</summary>
        None,
        /// <summary>Input exceeded the applicable pre-allocation byte bound.</summary>
        InputTooLarge,
        /// <summary>Input was malformed UTF-8 or carried a BOM.</summary>
        InvalidUtf8,
        /// <summary>Object shape, member presence, case, uniqueness, or trailing-token validation failed.</summary>
        InvalidContract,
        /// <summary>The exact wire schema marker was unsupported.</summary>
        SchemaInvalid,
        /// <summary>The exact integer contract version was not 2.</summary>
        ContractVersionUnsupported,
        /// <summary>A leaf type, nullability, grammar, enum, bound, or cross-field relation failed.</summary>
        ScalarInvalid,
        /// <summary>A digest was malformed or differed from canonical payload bytes.</summary>
        DigestInvalid,
        /// <summary>A signature was not canonical unpadded Base64Url for 256 bytes.</summary>
        Base64UrlInvalid,
        /// <summary>The optional key registry configuration failed the shared validator.</summary>
        KeyConfigurationInvalid,
        /// <summary>The authenticated observation was not UTC or was future-dated.</summary>
        KeyRegistryTimeInvalid,
        /// <summary>The authenticated observation exceeded the inclusive 300-second age.</summary>
        KeyRegistryStale,
        /// <summary>The separately pinned registry authority did not authenticate the snapshot.</summary>
        SnapshotAuthenticationInvalid,
        /// <summary>The exact key purpose, domain, lifecycle, version, or activation was unauthorized.</summary>
        KeyNotAuthorized,
        /// <summary>PS256 verification failed after canonical decoding.</summary>
        SignatureInvalid,
        /// <summary>Recovery evidence was substituted, stale, snapshot-mismatched, or already consumed.</summary>
        RecoveryProofInvalid,
    }

    /// <summary>Closed result carrying either one owned value or one failure.</summary>
    internal sealed record Result<T>(T? Value, Failure Error) where T : class;

    /// <summary>Non-forgeable authorization proving the current operational signer passed lifecycle checks.</summary>
    internal sealed class TransitionSigningAuthorization
    {
        /// <summary>Creates evidence only for this item 2 cryptographic component.</summary>
        internal TransitionSigningAuthorization(object seal, string keyId)
        { EnsureSeal(seal); KeyId = keyId; }
        /// <summary>Gets the exact authorized predecessor/current signing key identifier.</summary>
        internal string KeyId { get; }
    }

    /// <summary>Owns canonical bytes and lowercase SHA-256 text; byte access returns defensive copies.</summary>
    internal sealed class CanonicalDocument
    {
        /// <summary>Privately owned canonical bytes.</summary>
        private readonly byte[] canonicalUtf8;
        /// <summary>Copies canonical bytes and retains exact digest text.</summary>
        internal CanonicalDocument(byte[] bytes, string digest) { canonicalUtf8 = [.. bytes]; Digest = digest; }
        /// <summary>Gets a defensive copy of canonical UTF-8.</summary>
        internal byte[] CanonicalUtf8 => [.. canonicalUtf8];
        /// <summary>Gets exact lowercase SHA-256 text.</summary>
        internal string Digest { get; }
    }

    /// <summary>Owns one atomically assembled signed result; all byte properties return defensive copies.</summary>
    internal sealed class SignedGenerationResult
    {
        /// <summary>Privately owned canonical payload.</summary>
        private readonly byte[] payload;
        /// <summary>Privately owned signed statement.</summary>
        private readonly byte[] statement;
        /// <summary>Copies the coherent payload and statement assembled by the private writer.</summary>
        internal SignedGenerationResult(byte[] payload, string digest, string keyId, string signature, byte[] statement)
        { this.payload = [.. payload]; AuthorityDigest = digest; KeyId = keyId; Signature = signature; this.statement = [.. statement]; }
        /// <summary>Gets a defensive copy of the signed canonical payload.</summary>
        internal byte[] CanonicalPayloadUtf8 => [.. payload];
        /// <summary>Gets the digest computed from that payload.</summary>
        internal string AuthorityDigest { get; }
        /// <summary>Gets the selected exact key identifier.</summary>
        internal string KeyId { get; }
        /// <summary>Gets canonical unpadded PS256 text.</summary>
        internal string Signature { get; }
        /// <summary>Gets a defensive copy of the four-member statement.</summary>
        internal byte[] StatementUtf8 => [.. statement];
    }

    /// <summary>Owns one validated active private RSA handle and disposes it after the complete retry envelope.</summary>
    internal sealed class SigningSession : IDisposable
    {
        private readonly RuntimeEnrollmentAuthorityCryptography owner;
        private readonly RSA rsa;
        private int disposed;
        internal SigningSession(object seal, RuntimeEnrollmentAuthorityCryptography owner, RSA rsa, string keyId)
        { EnsureSeal(seal); this.owner = owner; this.rsa = rsa; KeyId = keyId; }
        /// <summary>Gets the exact classifier-visible signer identifier.</summary>
        internal string KeyId { get; }
        /// <summary>Signs canonical payload bytes only when the required predecessor/current key matches ordinally.</summary>
        internal Result<SignedGenerationResult> Sign(ReadOnlySpan<byte> payloadUtf8, string requiredKeyId)
        {
            if (Volatile.Read(ref disposed) != 0
                || !string.Equals(KeyId, requiredKeyId, StringComparison.Ordinal))
                return Fail<SignedGenerationResult>(Failure.KeyNotAuthorized);
            var canonical = owner.CanonicalizeGenerationPayload(payloadUtf8);
            if (canonical.Error != Failure.None) return Fail<SignedGenerationResult>(canonical.Error);
            var payload = canonical.Value!.CanonicalUtf8;
            var signature = EncodeBase64Url(rsa.SignData(
                SigningInput(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            var statement = BuildStatement(payload, canonical.Value.Digest, KeyId, signature);
            return statement.Length <= MaximumSignedStatementBytes
                ? Ok(new SignedGenerationResult(payload, canonical.Value.Digest, KeyId, signature, statement))
                : Fail<SignedGenerationResult>(Failure.InputTooLarge);
        }
        /// <summary>Signs exact recovery-preparation claims with the active operational key.</summary>
        /// <param name="claimsUtf8">Caller-owned canonical claims bytes; no normalization is performed.</param>
        /// <returns>A canonical unpadded PS256 signature or a closed key failure.</returns>
        internal Result<string> SignRecoveryPreparation(ReadOnlySpan<byte> claimsUtf8)
        {
            if (Volatile.Read(ref disposed) != 0)
                return Fail<string>(Failure.KeyNotAuthorized);
            return Ok(EncodeBase64Url(rsa.SignData(
                RecoveryPreparationInput(claimsUtf8), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
        }
        /// <summary>Destroys the imported private RSA handle exactly once.</summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0) rsa.Dispose();
        }
    }

    /// <summary>Authenticated, sealed, deep-copied registry evidence that callers cannot fabricate.</summary>
    internal sealed class AuthenticatedRegistrySnapshotEvidence
    {
        /// <summary>Deep-copied validated public key metadata.</summary>
        private readonly RegistryKey[] keys;
        /// <summary>Exact SHA-256 fingerprint of the bytes verified by the independent trust root.</summary>
        private readonly byte[] fingerprint;
        /// <summary>Constructs evidence only with the process-private seal after authority verification.</summary>
        /// <param name="seal">Process-private capability; any other object is rejected.</param>
        /// <param name="id">Authenticated exact snapshot identity.</param>
        /// <param name="version">Authenticated positive snapshot version.</param>
        /// <param name="observed">Authenticated UTC observation instant.</param>
        /// <param name="keys">Validated public metadata deep-copied by the constructor.</param>
        /// <param name="fingerprint">SHA-256 of the exact authenticated bytes, deep-copied by the constructor.</param>
        internal AuthenticatedRegistrySnapshotEvidence(object seal, string id, long version, DateTimeOffset observed, RegistryKey[] keys, byte[] fingerprint)
        { EnsureSeal(seal); SnapshotId = id; SnapshotVersion = version; RegistryObservedAtUtc = observed; this.keys = keys.Select(key => key.Copy()).ToArray(); this.fingerprint = [.. fingerprint]; }
        /// <summary>Gets the authenticated exact snapshot identity.</summary>
        internal string SnapshotId { get; }
        /// <summary>Gets the authenticated positive snapshot version.</summary>
        internal long SnapshotVersion { get; }
        /// <summary>Gets the authenticated UTC observation instant.</summary>
        internal DateTimeOffset RegistryObservedAtUtc { get; }
        /// <summary>Returns a new deep copy only to a process-sealed item 2 constructor.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <returns>New key metadata and SPKI copies owned by the caller.</returns>
        internal RegistryKey[] CopyKeys(object seal) { EnsureSeal(seal); return keys.Select(key => key.Copy()).ToArray(); }
        /// <summary>Returns a fingerprint copy only to a process-sealed item 2 constructor.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <returns>A new 32-byte fingerprint copy owned by the caller.</returns>
        internal byte[] CopyFingerprint(object seal) { EnsureSeal(seal); return [.. fingerprint]; }
    }

    /// <summary>Sealed registry proof that resolves keys without exposing mutable SPKI arrays.</summary>
    internal sealed class TrustedKeyRegistrySnapshotProof
    {
        /// <summary>Private deep copies used for in-proof key resolution.</summary>
        private readonly RegistryKey[] keys;
        /// <summary>Exact authenticated snapshot fingerprint retained privately for proof binding.</summary>
        private readonly byte[] fingerprint;
        /// <summary>Constructs a proof only from authenticated sealed evidence.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <param name="evidence">Authenticated evidence whose keys and fingerprint are deep-copied.</param>
        internal TrustedKeyRegistrySnapshotProof(object seal, AuthenticatedRegistrySnapshotEvidence evidence)
        { EnsureSeal(seal); SnapshotId = evidence.SnapshotId; SnapshotVersion = evidence.SnapshotVersion; RegistryObservedAtUtc = evidence.RegistryObservedAtUtc; keys = evidence.CopyKeys(seal); fingerprint = evidence.CopyFingerprint(seal); }
        /// <summary>Gets the bound exact snapshot identity.</summary>
        internal string SnapshotId { get; }
        /// <summary>Gets the bound snapshot version.</summary>
        internal long SnapshotVersion { get; }
        /// <summary>Gets the bound authenticated observation instant.</summary>
        internal DateTimeOffset RegistryObservedAtUtc { get; }
        /// <summary>Returns an owned copy of the authenticated snapshot fingerprint to sealed item 2 consumers.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <returns>A new 32-byte fingerprint copy.</returns>
        internal byte[] CopyFingerprint(object seal) { EnsureSeal(seal); return [.. fingerprint]; }
        /// <summary>Resolves and verifies a current key entirely inside the sealed proof.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <param name="input">Exact domain-separated bytes to verify.</param>
        /// <param name="keyId">Exact ordinal key identifier.</param>
        /// <param name="signature">Canonical unpadded Base64Url signature.</param>
        /// <param name="purpose">Closed operational or recovery purpose selected by item 2.</param>
        /// <param name="now">Trusted clock value used for freshness and activation.</param>
        /// <returns>None or a closed freshness, authorization, Base64Url, or PS256 failure.</returns>
        internal Failure Verify(object seal, ReadOnlySpan<byte> input, string keyId, string signature, string purpose, DateTimeOffset now)
        {
            EnsureSeal(seal);
            var freshness = Freshness(RegistryObservedAtUtc, now);
            if (freshness != Failure.None) return freshness;
            var key = keys.SingleOrDefault(candidate => string.Equals(candidate.Id, keyId, StringComparison.Ordinal));
            if (key is null || key.Purpose != purpose || key.Domain != (purpose == "recovery" ? "recovery" : "generation")
                || key.ContractVersion != 2 || key.Status != "active" || now < key.ActivatedAtUtc) return Failure.KeyNotAuthorized;
            if (!TryDecodeSignature(signature, out var signatureBytes)) return Failure.Base64UrlInvalid;
            return VerifyDetachedPs256(key.CopySpki(), input, signatureBytes) ? Failure.None : Failure.SignatureInvalid;
        }

        /// <summary>Classifies one exact current operational signer from authenticated lifecycle metadata.</summary>
        internal KeyLifecycleClassification ClassifyCurrentSigner(
            string keyId, DateTimeOffset occurredAtUtc, DateTimeOffset authoritativeNowUtc)
        {
            var freshness = Freshness(RegistryObservedAtUtc, authoritativeNowUtc);
            if (freshness != Failure.None)
                return new(ProofSeal, freshness == Failure.KeyRegistryTimeInvalid
                    ? KeyLifecycleOutcome.RegistryTimeInvalid : KeyLifecycleOutcome.RegistryStale, keyId);
            return ClassifyKey(keyId, "operational", "generation", occurredAtUtc, authoritativeNowUtc);
        }

        /// <summary>Classifies predecessor-signed rotation to a distinct authenticated successor.</summary>
        internal KeyLifecycleClassification ClassifyRotation(
            string predecessorKeyId, string successorKeyId, DateTimeOffset occurredAtUtc,
            DateTimeOffset authoritativeNowUtc)
        {
            var predecessor = ClassifyCurrentSigner(predecessorKeyId, occurredAtUtc, authoritativeNowUtc);
            if (predecessor.Outcome != KeyLifecycleOutcome.Valid) return predecessor;
            if (string.Equals(predecessorKeyId, successorKeyId, StringComparison.Ordinal))
                return new(ProofSeal, KeyLifecycleOutcome.PredecessorMismatch, predecessorKeyId);
            var successor = ClassifyKey(successorKeyId, "operational", "generation", occurredAtUtc, authoritativeNowUtc);
            return successor.Outcome == KeyLifecycleOutcome.Valid
                ? new(ProofSeal, KeyLifecycleOutcome.Valid, predecessorKeyId) : successor;
        }

        /// <summary>Classifies one separately purposed recovery key from authenticated lifecycle metadata.</summary>
        internal KeyLifecycleClassification ClassifyRecovery(
            string recoveryKeyId, DateTimeOffset occurredAtUtc, DateTimeOffset authoritativeNowUtc)
        {
            var freshness = Freshness(RegistryObservedAtUtc, authoritativeNowUtc);
            if (freshness != Failure.None)
                return new(ProofSeal, freshness == Failure.KeyRegistryTimeInvalid
                    ? KeyLifecycleOutcome.RegistryTimeInvalid : KeyLifecycleOutcome.RegistryStale, recoveryKeyId);
            return ClassifyKey(recoveryKeyId, "recovery", "recovery", occurredAtUtc, authoritativeNowUtc);
        }

        private KeyLifecycleClassification ClassifyKey(
            string keyId, string purpose, string domain, DateTimeOffset occurredAtUtc,
            DateTimeOffset authoritativeNowUtc)
        {
            var key = keys.SingleOrDefault(candidate => string.Equals(candidate.Id, keyId, StringComparison.Ordinal));
            if (key is null) return new(ProofSeal, KeyLifecycleOutcome.UnknownKey, keyId);
            if (key.Purpose != purpose) return new(ProofSeal, KeyLifecycleOutcome.WrongPurpose, keyId);
            if (key.Domain != domain) return new(ProofSeal, KeyLifecycleOutcome.WrongDomain, keyId);
            if (key.ContractVersion != 2) return new(ProofSeal, KeyLifecycleOutcome.WrongVersion, keyId);
            if (occurredAtUtc < key.ActivatedAtUtc || authoritativeNowUtc < key.ActivatedAtUtc)
                return new(ProofSeal, KeyLifecycleOutcome.NotActive, keyId);
            if (key.RevokedAtUtc is not null && occurredAtUtc >= key.RevokedAtUtc)
                return new(ProofSeal, KeyLifecycleOutcome.Revoked, keyId);
            if (key.CompromiseFromUtc is not null && occurredAtUtc >= key.CompromiseFromUtc
                && (key.RevokedAtUtc is null || occurredAtUtc < key.RevokedAtUtc))
                return new(ProofSeal, KeyLifecycleOutcome.Compromised, keyId);
            if (key.RetiredAtUtc is not null && occurredAtUtc >= key.RetiredAtUtc)
                return new(ProofSeal, KeyLifecycleOutcome.Retired, keyId);
            return new(ProofSeal, KeyLifecycleOutcome.Valid, keyId);
        }
    }

    /// <summary>Closed lifecycle outcomes produced only from authenticated proof-owned key metadata.</summary>
    internal enum KeyLifecycleOutcome
    {
        /// <summary>The exact key and lifecycle are authorized.</summary>
        Valid,
        /// <summary>No authenticated key has the exact identifier.</summary>
        UnknownKey,
        /// <summary>The occurrence precedes inclusive activation.</summary>
        NotActive,
        /// <summary>The occurrence is at or beyond retirement.</summary>
        Retired,
        /// <summary>The occurrence is at or beyond revocation.</summary>
        Revoked,
        /// <summary>The occurrence is in the authenticated compromise interval.</summary>
        Compromised,
        /// <summary>The authenticated purpose differs.</summary>
        WrongPurpose,
        /// <summary>The authenticated signing domain differs.</summary>
        WrongDomain,
        /// <summary>The authenticated contract version is not 2.</summary>
        WrongVersion,
        /// <summary>Rotation did not retain a distinct predecessor signer.</summary>
        PredecessorMismatch,
        /// <summary>The authenticated registry timestamp is invalid or future-dated.</summary>
        RegistryTimeInvalid,
        /// <summary>The authenticated registry snapshot is older than the inclusive freshness bound.</summary>
        RegistryStale
    }

    /// <summary>Non-forgeable lifecycle classification consumed by item 3 transition policy.</summary>
    internal sealed class KeyLifecycleClassification
    {
        internal KeyLifecycleClassification(object seal, KeyLifecycleOutcome outcome, string keyId)
        { EnsureSeal(seal); Outcome = outcome; KeyId = keyId; }
        /// <summary>Gets the closed lifecycle outcome.</summary>
        internal KeyLifecycleOutcome Outcome { get; }
        /// <summary>Gets the exact classified key identifier.</summary>
        internal string KeyId { get; }
    }

    /// <summary>One-use recovery evidence bound to exact input hash, key, snapshot, and freshness.</summary>
    internal sealed class RecoveryVerificationProof
    {
        /// <summary>Exact SHA-256 of generation domain, LF, and canonical payload.</summary>
        private readonly byte[] inputHash;
        /// <summary>Exact verified recovery key identifier.</summary>
        private readonly string keyId;
        /// <summary>Bound registry snapshot identity.</summary>
        private readonly string snapshotId;
        /// <summary>Bound registry snapshot version.</summary>
        private readonly long snapshotVersion;
        /// <summary>Bound authenticated registry observation.</summary>
        private readonly DateTimeOffset observed;
        /// <summary>Exact authenticated snapshot fingerprint bound at recovery verification.</summary>
        private readonly byte[] snapshotFingerprint;
        /// <summary>Atomic marker proving that this exact binding has already been accepted.</summary>
        private int consumed;
        /// <summary>Constructs recovery evidence only after sealed PS256 verification.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <param name="hash">Exact signing-input SHA-256, deep-copied.</param>
        /// <param name="keyId">Verified recovery key identifier.</param>
        /// <param name="snapshot">Authenticated snapshot whose identity, time, and fingerprint are bound.</param>
        internal RecoveryVerificationProof(object seal, byte[] hash, string keyId, TrustedKeyRegistrySnapshotProof snapshot)
        { EnsureSeal(seal); inputHash = [.. hash]; this.keyId = keyId; snapshotId = snapshot.SnapshotId; snapshotVersion = snapshot.SnapshotVersion; observed = snapshot.RegistryObservedAtUtc; snapshotFingerprint = snapshot.CopyFingerprint(seal); }
        /// <summary>Accepts the same exact proof binding idempotently while rejecting every substituted binding.</summary>
        /// <param name="seal">Process-private capability.</param>
        /// <param name="hash">Candidate signing-input hash compared in fixed time.</param>
        /// <param name="candidateKeyId">Candidate key identifier compared ordinally.</param>
        /// <param name="snapshot">Candidate authenticated snapshot including fingerprint.</param>
        /// <param name="now">Trusted clock value for inclusive freshness.</param>
        /// <returns>True for the exact binding on first use and transaction retry; false for stale or substituted input.</returns>
        internal bool TryConsume(object seal, ReadOnlySpan<byte> hash, string candidateKeyId, TrustedKeyRegistrySnapshotProof snapshot, DateTimeOffset now)
        {
            EnsureSeal(seal);
            var matches = Freshness(observed, now) == Failure.None
                && string.Equals(keyId, candidateKeyId, StringComparison.Ordinal)
                && string.Equals(snapshotId, snapshot.SnapshotId, StringComparison.Ordinal)
                && snapshotVersion == snapshot.SnapshotVersion && observed == snapshot.RegistryObservedAtUtc
                && CryptographicOperations.FixedTimeEquals(snapshotFingerprint, snapshot.CopyFingerprint(seal))
                && CryptographicOperations.FixedTimeEquals(inputHash, hash);
            if (!matches) return false;
            Interlocked.Exchange(ref consumed, 1);
            return true;
        }
    }

    /// <summary>Deep-copied public registry key metadata used only inside sealed evidence and proofs.</summary>
    internal sealed class RegistryKey
    {
        /// <summary>Privately owned SPKI bytes.</summary>
        private readonly byte[] spki;
        /// <summary>Copies one already validated options entry and its SPKI.</summary>
        /// <param name="source">Validated public metadata; no private key field is retained.</param>
        /// <param name="spki">Public SPKI copied into private storage.</param>
        internal RegistryKey(RuntimeAuthorityGenerationKeyOptions source, byte[] spki)
        { Id = source.KeyId; Purpose = source.Purpose; Domain = source.Domain; ContractVersion = source.ContractVersion; Status = source.Status; ActivatedAtUtc = source.ActivatedAtUtc; RetiredAtUtc = source.RetiredAtUtc; RevokedAtUtc = source.RevokedAtUtc; RevocationReason = source.RevocationReason; CompromiseFromUtc = source.CompromiseFromUtc; this.spki = [.. spki]; }
        /// <summary>Gets the exact key identifier.</summary>
        internal string Id { get; }
        /// <summary>Gets operational or recovery purpose.</summary>
        internal string Purpose { get; }
        /// <summary>Gets generation or recovery domain.</summary>
        internal string Domain { get; }
        /// <summary>Gets exact contract version 2.</summary>
        internal int ContractVersion { get; }
        /// <summary>Gets the exact lifecycle status.</summary>
        internal string Status { get; }
        /// <summary>Gets inclusive UTC activation.</summary>
        internal DateTimeOffset ActivatedAtUtc { get; }
        /// <summary>Gets the exclusive authenticated retirement boundary.</summary>
        internal DateTimeOffset? RetiredAtUtc { get; }
        /// <summary>Gets the authenticated revocation boundary.</summary>
        internal DateTimeOffset? RevokedAtUtc { get; }
        /// <summary>Gets the exact authenticated revocation reason.</summary>
        internal string? RevocationReason { get; }
        /// <summary>Gets the inclusive authenticated compromise boundary.</summary>
        internal DateTimeOffset? CompromiseFromUtc { get; }
        /// <summary>Gets a defensive SPKI copy.</summary>
        /// <returns>Caller-owned public bytes; no secret zeroing is required.</returns>
        internal byte[] CopySpki() => [.. spki];
        /// <summary>Creates a deep metadata and SPKI copy.</summary>
        /// <returns>A new independently owned registry key.</returns>
        internal RegistryKey Copy() => new(new RuntimeAuthorityGenerationKeyOptions { KeyId = Id, Purpose = Purpose, Domain = Domain, ContractVersion = ContractVersion, Status = Status, ActivatedAtUtc = ActivatedAtUtc, RetiredAtUtc = RetiredAtUtc, RevokedAtUtc = RevokedAtUtc, RevocationReason = RevocationReason, CompromiseFromUtc = CompromiseFromUtc }, spki);
    }

    /// <summary>Validates one leaf and returns a closed failure.</summary>
    private delegate Failure LeafValidator(JsonElement value);
    /// <summary>Defines one exact property, child object, or leaf rule.</summary>
    private sealed record Field(string Name, Shape? Child, LeafValidator? Validate);
    /// <summary>Defines one complete closed object shape.</summary>
    private sealed record Shape(Field[] Fields);
    /// <summary>Closed release shape.</summary>
    private static readonly Shape Release = S(L("version", ReleaseVersion), L("artifactSetDigest", Digest));
    /// <summary>Closed binding shape.</summary>
    private static readonly Shape Binding = S(L("bindingId", Uuid), L("hardwareIdDigest", Digest));
    /// <summary>Closed enrollment shape.</summary>
    private static readonly Shape Enrollment = S(L("enrollmentId", Uuid), L("state", EnrollmentState), L("issuedAtUtc", Utc), L("expiresAtUtc", NullableUtc));
    /// <summary>Closed authority-key shape.</summary>
    private static readonly Shape KeyShape = S(L("authorityKeyId", KeyId), L("securityEpoch", SecurityEpoch));
    /// <summary>Closed installation shape.</summary>
    private static readonly Shape Installation = S(L("installationId", Uuid), L("seatId", NullableUuid));
    /// <summary>Closed requested-authority shape.</summary>
    private static readonly Shape RequestedAuthority = S(O("release", Release), O("binding", Binding), O("enrollment", Enrollment), O("key", KeyShape), O("installation", Installation));
    /// <summary>Closed request transition with requestedAtUtc only.</summary>
    private static readonly Shape RequestTransition = S(L("kind", TransitionKind), L("reasonCode", TransitionReason), L("requestedAtUtc", Utc));
    /// <summary>Closed generation transition with requestId and occurredAtUtc only.</summary>
    private static readonly Shape GenerationTransition = S(L("kind", TransitionKind), L("reasonCode", TransitionReason), L("requestId", Uuid), L("occurredAtUtc", Utc));
    /// <summary>Closed authority-request root.</summary>
    private static readonly Shape RequestShape = S(L("schema", Const("runtime-enrollment-authority-request-v2", Failure.SchemaInvalid)), L("contractVersion", Version), L("requestId", Uuid), L("provider", Provider), L("productId", Uuid), L("providerGrantRef", ProviderGrantRef), L("expectedAuthorityLineageId", NullableUuid), L("expectedCurrentGenerationId", NullableUuid), L("expectedPredecessorGenerationId", NullableUuid), O("requestedAuthority", RequestedAuthority), O("transition", RequestTransition));
    /// <summary>Closed authority-generation payload root.</summary>
    private static readonly Shape PayloadShape = S(L("schema", Const("runtime-enrollment-authority-generation-v2", Failure.SchemaInvalid)), L("contractVersion", Version), L("authorityLineageId", Uuid), L("authorityGenerationId", Uuid), L("previousGenerationId", NullableUuid), L("sequence", Sequence), L("provider", Provider), L("productId", Uuid), L("providerGrantRef", ProviderGrantRef), O("release", Release), O("binding", Binding), O("enrollment", Enrollment), O("key", KeyShape), O("installation", Installation), O("transition", GenerationTransition));
    /// <summary>Closed PS256 metadata shape.</summary>
    private static readonly Shape SignatureShape = S(L("algorithm", Const("PS256", Failure.ScalarInvalid)), L("keyId", KeyId), L("value", Signature));
    /// <summary>Closed four-member signed-generation statement.</summary>
    private static readonly Shape StatementShape = S(L("schema", Const("runtime-enrollment-signed-generation-v2", Failure.SchemaInvalid)), O("payload", PayloadShape), L("authorityDigest", Digest), O("signature", SignatureShape));

    /// <summary>Strictly canonicalizes an untrusted request without normalizing any string and computes its domain-separated digest.</summary>
    /// <param name="utf8">Untrusted BOM-free UTF-8 JSON, bounded to 4096 bytes before parsing.</param>
    /// <returns>An owned result whose CanonicalUtf8 accessor returns copies, or a closed size, UTF-8, shape, schema, version, scalar, or <see cref="Failure.DigestInvalid"/> failure.</returns>
    internal Result<CanonicalDocument> CanonicalizeRequest(ReadOnlySpan<byte> utf8) => Canonicalize(utf8, MaximumRequestBytes, RequestShape, true);
    /// <summary>Strictly canonicalizes an untrusted generation payload without normalization and computes SHA-256 over canonical bytes.</summary>
    /// <param name="utf8">Untrusted BOM-free UTF-8 JSON, bounded to 2895 bytes before parsing.</param>
    /// <returns>An owned result whose CanonicalUtf8 accessor returns copies, or a closed size, UTF-8, shape, schema, version, scalar, or <see cref="Failure.DigestInvalid"/> failure.</returns>
    internal Result<CanonicalDocument> CanonicalizeGenerationPayload(ReadOnlySpan<byte> utf8) => Canonicalize(utf8, MaximumGenerationPayloadBytes, PayloadShape, false);

    /// <summary>Returns owned bytes that the separately pinned registry authority must sign.</summary>
    /// <param name="options">Untrusted optional configuration validated without repair.</param>
    /// <param name="observed">Exact UTC observation bound into the authenticated bytes.</param>
    /// <returns>Owned authentication bytes or KeyConfigurationInvalid.</returns>
    internal Result<byte[]> GetRegistrySnapshotAuthenticationInput(RuntimeAuthorityGenerationSigningOptions? options, DateTimeOffset observed)
        => ValidateOwnedConfiguration(options) == Failure.None && observed.Offset == TimeSpan.Zero
            ? Ok(BuildRegistryAuthenticationInput(options!, observed)) : Fail<byte[]>(Failure.KeyConfigurationInvalid);

    /// <summary>Authenticates registry metadata before returning sealed, deep-copied evidence.</summary>
    /// <param name="options">Untrusted configuration consumed by the shared validator.</param>
    /// <param name="observed">UTC trusted-source observation checked against the trusted clock.</param>
    /// <param name="authoritySignature">Exactly 256 PS256 bytes from the separately pinned registry authority.</param>
    /// <returns>Sealed evidence, or configuration, time, staleness, or authentication failure.</returns>
    internal Result<AuthenticatedRegistrySnapshotEvidence> AuthenticateRegistrySnapshot(RuntimeAuthorityGenerationSigningOptions? options, DateTimeOffset observed, ReadOnlySpan<byte> authoritySignature)
    {
        if (ValidateOwnedConfiguration(options) != Failure.None) return Fail<AuthenticatedRegistrySnapshotEvidence>(Failure.KeyConfigurationInvalid);
        if (observed.Offset != TimeSpan.Zero) return Fail<AuthenticatedRegistrySnapshotEvidence>(Failure.KeyRegistryTimeInvalid);
        if (authoritySignature.Length != 256) return Fail<AuthenticatedRegistrySnapshotEvidence>(Failure.SnapshotAuthenticationInvalid);
        var freshness = Freshness(observed, clock.GetUtcNow());
        if (freshness != Failure.None) return Fail<AuthenticatedRegistrySnapshotEvidence>(freshness);
        try
        {
            var validatedOptions = options!;
            using var authority = RSA.Create(); authority.ImportSubjectPublicKeyInfo(registryAuthoritySpki, out _);
            var authenticatedBytes = BuildRegistryAuthenticationInput(validatedOptions, observed);
            if (!authority.VerifyData(authenticatedBytes, authoritySignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                return Fail<AuthenticatedRegistrySnapshotEvidence>(Failure.SnapshotAuthenticationInvalid);
            return Ok(new AuthenticatedRegistrySnapshotEvidence(ProofSeal, validatedOptions.RegistrySnapshotId, validatedOptions.RegistrySnapshotVersion, observed, CopyRegistryKeys(validatedOptions.Keys), SHA256.HashData(authenticatedBytes)));
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException) { return Fail<AuthenticatedRegistrySnapshotEvidence>(Failure.SnapshotAuthenticationInvalid); }
    }

    /// <summary>Authenticates a canonical Base64Url registry signature without exposing decoded buffers.</summary>
    internal Result<AuthenticatedRegistrySnapshotEvidence> AuthenticateRegistrySnapshot(
        RuntimeAuthorityGenerationSigningOptions? options, DateTimeOffset observed, string authoritySignature)
    {
        if (!TryDecodeSignature(authoritySignature, out var decoded))
            return Fail<AuthenticatedRegistrySnapshotEvidence>(Failure.Base64UrlInvalid);
        try { return AuthenticateRegistrySnapshot(options, observed, decoded); }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }

    /// <summary>Creates a registry proof only from sealed authenticated evidence.</summary>
    /// <param name="evidence">Evidence created only by successful item 2 authority verification.</param>
    /// <returns>A proof with deep-copied public metadata and snapshot/time binding.</returns>
    internal TrustedKeyRegistrySnapshotProof CreateTrustedSnapshotProof(AuthenticatedRegistrySnapshotEvidence evidence) => new(ProofSeal, evidence);

    /// <summary>Returns one immutable payload/digest/key/signature/statement result or one closed failure.</summary>
    /// <param name="options">Present configuration consumed by the shared fail-closed validator.</param>
    /// <param name="payloadUtf8">Untrusted payload bytes; canonical bytes are copied before signing.</param>
    /// <returns>One coherent owned result; no partial result is returned on any failure.</returns>
    internal Result<SignedGenerationResult> SignGeneration(RuntimeAuthorityGenerationSigningOptions? options, ReadOnlySpan<byte> payloadUtf8)
        => SignGeneration(options, payloadUtf8, options?.ActiveSigningKeyId);

    /// <summary>Signs with one exact classifier-approved operational key, including predecessor rotation signing.</summary>
    internal Result<SignedGenerationResult> SignGeneration(
        RuntimeAuthorityGenerationSigningOptions? options, ReadOnlySpan<byte> payloadUtf8,
        string? requiredKeyId)
    {
        if (ValidateOwnedConfiguration(options) != Failure.None) return Fail<SignedGenerationResult>(Failure.KeyConfigurationInvalid);
        if (requiredKeyId is null) return Fail<SignedGenerationResult>(Failure.KeyNotAuthorized);
        var canonical = CanonicalizeGenerationPayload(payloadUtf8);
        if (canonical.Error != Failure.None) return Fail<SignedGenerationResult>(canonical.Error);
        var selected = options!.Keys.SingleOrDefault(key => string.Equals(key.KeyId, requiredKeyId, StringComparison.Ordinal));
        if (selected is null || selected.Purpose != "operational" || selected.Domain != "generation"
            || selected.PrivateKeyPem is null) return Fail<SignedGenerationResult>(Failure.KeyNotAuthorized);
        try
        {
            using var rsa = RSA.Create(); rsa.ImportFromPem(selected.PrivateKeyPem);
            var payload = canonical.Value!.CanonicalUtf8;
            var signature = EncodeBase64Url(rsa.SignData(SigningInput(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            var statement = BuildStatement(payload, canonical.Value.Digest, selected.KeyId, signature);
            return statement.Length <= MaximumSignedStatementBytes
                ? Ok(new SignedGenerationResult(payload, canonical.Value.Digest, selected.KeyId, signature, statement))
                : Fail<SignedGenerationResult>(Failure.InputTooLarge);
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException) { return Fail<SignedGenerationResult>(Failure.KeyConfigurationInvalid); }
    }

    /// <summary>Classifies the configured current signer against exact lifecycle metadata before a transition is issued.</summary>
    /// <param name="options">Untrusted key configuration validated by the shared item 2 validator.</param>
    /// <param name="transitionKind">Closed transition kind; inspected ordinally without normalization.</param>
    /// <returns>Sealed signer authorization or a closed configuration/key authorization failure.</returns>
    internal Result<TransitionSigningAuthorization> AuthorizeTransitionSigner(
        RuntimeAuthorityGenerationSigningOptions? options, string transitionKind)
    {
        if (ValidateOwnedConfiguration(options) != Failure.None)
            return Fail<TransitionSigningAuthorization>(Failure.KeyConfigurationInvalid);
        if (transitionKind is not ("genesis" or "release" or "binding" or "enrollment"
            or "key_rotation" or "security_epoch" or "seat" or "repair" or "reinstall"
            or "recovery" or "revocation"))
            return Fail<TransitionSigningAuthorization>(Failure.KeyNotAuthorized);
        var key = options!.Keys.Single(candidate => string.Equals(
            candidate.KeyId, options.ActiveSigningKeyId, StringComparison.Ordinal));
        var now = clock.GetUtcNow();
        if (key.Status != "active" || key.Purpose != "operational" || key.Domain != "generation"
            || key.ContractVersion != 2 || now < key.ActivatedAtUtc
            || (key.RetiredAtUtc is not null && now >= key.RetiredAtUtc)
            || key.RevokedAtUtc is not null)
            return Fail<TransitionSigningAuthorization>(Failure.KeyNotAuthorized);
        return Ok(new TransitionSigningAuthorization(ProofSeal, key.KeyId));
    }

    /// <summary>Imports the sole active private key into an operation-owned disposable signing session.</summary>
    internal Result<SigningSession> CreateSigningSession(
        RuntimeAuthorityGenerationSigningOptions? options)
    {
        if (ValidateOwnedConfiguration(options) != Failure.None)
            return Fail<SigningSession>(Failure.KeyConfigurationInvalid);
        try
        {
            var selected = options!.Keys.Single(key => string.Equals(
                key.KeyId, options.ActiveSigningKeyId, StringComparison.Ordinal));
            var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(selected.PrivateKeyPem);
                return Ok(new SigningSession(ProofSeal, this, rsa, selected.KeyId));
            }
            catch { rsa.Dispose(); throw; }
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        { return Fail<SigningSession>(Failure.KeyConfigurationInvalid); }
    }

    /// <summary>Parses a complete statement, fixed-time compares digest bytes, and verifies current operational PS256.</summary>
    /// <param name="statement">Untrusted statement bytes bounded before parsing.</param>
    /// <param name="proof">Authenticated current snapshot proof used internally for key resolution.</param>
    /// <returns>None or one closed parse, digest, registry, key, Base64Url, or signature failure.</returns>
    internal Failure ParseAndVerifyStatement(ReadOnlySpan<byte> statement, TrustedKeyRegistrySnapshotProof proof)
    {
        var parsed = Parse(statement, MaximumSignedStatementBytes, StatementShape);
        if (parsed.Error != Failure.None) return parsed.Error;
        using var document = parsed.Value!;
        var root = document.RootElement;
        var payload = CanonicalBytes(root.GetProperty("payload"), PayloadShape);
        if (payload.Length > MaximumGenerationPayloadBytes) return Failure.InputTooLarge;
        if (!TryDecodeDigest(root.GetProperty("authorityDigest").GetString()!, out var supplied)
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), supplied)) return Failure.DigestInvalid;
        var signature = root.GetProperty("signature");
        return proof.Verify(ProofSeal, SigningInput(payload), signature.GetProperty("keyId").GetString()!, signature.GetProperty("value").GetString()!, "operational", clock.GetUtcNow());
    }

    /// <summary>Verifies recovery over the unchanged generation input and returns input-bound one-use evidence.</summary>
    /// <param name="payloadUtf8">Untrusted generation payload, strictly canonicalized before verification.</param>
    /// <param name="keyId">Exact recovery key identifier.</param>
    /// <param name="signature">Canonical 342-character unpadded Base64Url PS256 signature.</param>
    /// <param name="proof">Authenticated current registry proof.</param>
    /// <returns>One-use evidence or one closed validation/verification failure.</returns>
    internal Result<RecoveryVerificationProof> VerifyRecoverySignature(ReadOnlySpan<byte> payloadUtf8, string keyId, string signature, TrustedKeyRegistrySnapshotProof proof)
    {
        var canonical = CanonicalizeGenerationPayload(payloadUtf8);
        if (canonical.Error != Failure.None) return Fail<RecoveryVerificationProof>(canonical.Error);
        var input = SigningInput(canonical.Value!.CanonicalUtf8);
        var failure = proof.Verify(ProofSeal, input, keyId, signature, "recovery", clock.GetUtcNow());
        return failure == Failure.None ? Ok(new RecoveryVerificationProof(ProofSeal, SHA256.HashData(input), keyId, proof)) : Fail<RecoveryVerificationProof>(failure);
    }

    /// <summary>Verifies a short recovery-preparation token with an authenticated operational key.</summary>
    /// <param name="claimsUtf8">Exact claims bytes extracted from the token.</param>
    /// <param name="keyId">Exact ordinal operational key identifier embedded in the token.</param>
    /// <param name="signature">Canonical unpadded PS256 signature.</param>
    /// <param name="proof">Authenticated current registry snapshot.</param>
    /// <returns>None only when the exact domain-separated claims signature is valid.</returns>
    internal Failure VerifyRecoveryPreparationSignature(
        ReadOnlySpan<byte> claimsUtf8, string keyId, string signature,
        TrustedKeyRegistrySnapshotProof proof) => proof.Verify(
            ProofSeal, RecoveryPreparationInput(claimsUtf8), keyId, signature,
            "operational", clock.GetUtcNow());

    /// <summary>Consumes recovery evidence idempotently for one exact operation across database retries.</summary>
    /// <param name="proof">Previously verified one-use recovery evidence.</param>
    /// <param name="payloadUtf8">Candidate payload that must reproduce the bound signing-input hash.</param>
    /// <param name="keyId">Candidate key identifier that must match ordinally.</param>
    /// <param name="snapshot">Candidate authenticated snapshot that must match all bound metadata.</param>
    /// <returns>None for the same complete binding on first use or retry; otherwise RecoveryProofInvalid or payload failure.</returns>
    internal Failure ConsumeRecoveryProof(RecoveryVerificationProof proof, ReadOnlySpan<byte> payloadUtf8, string keyId, TrustedKeyRegistrySnapshotProof snapshot)
    {
        var canonical = CanonicalizeGenerationPayload(payloadUtf8);
        if (canonical.Error != Failure.None) return canonical.Error;
        var hash = SHA256.HashData(SigningInput(canonical.Value!.CanonicalUtf8));
        return proof.TryConsume(ProofSeal, hash, keyId, snapshot, clock.GetUtcNow()) ? Failure.None : Failure.RecoveryProofInvalid;
    }

    /// <summary>Verifies exact RSA-2048, exponent 65537, and PS256 detached data.</summary>
    /// <param name="spki">Untrusted SubjectPublicKeyInfo bytes.</param>
    /// <param name="input">Exact data covered by PS256.</param>
    /// <param name="signature">Exactly decoded signature bytes.</param>
    /// <returns>True only for the required RSA profile and valid signature.</returns>
    internal static bool VerifyDetachedPs256(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
    {
        try { using var rsa = RSA.Create(); rsa.ImportSubjectPublicKeyInfo(spki, out var read); return read == spki.Length && rsa.KeySize == 2048 && rsa.ExportParameters(false).Exponent is [1, 0, 1] && rsa.VerifyData(input, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss); }
        catch (CryptographicException) { return false; }
    }

    /// <summary>Runs bounded parsing, canonical writing, and the selected digest construction.</summary>
    private Result<CanonicalDocument> Canonicalize(ReadOnlySpan<byte> utf8, int maximum, Shape shape, bool requestDigest)
    {
        var parsed = Parse(utf8, maximum, shape); if (parsed.Error != Failure.None) return Fail<CanonicalDocument>(parsed.Error);
        using var document = parsed.Value!; var canonical = CanonicalBytes(document.RootElement, shape);
        if (canonical.Length > maximum) return Fail<CanonicalDocument>(Failure.InputTooLarge);
        var input = requestDigest ? WithDomain(RequestDomain, canonical) : canonical;
        return Ok(new CanonicalDocument(canonical, Convert.ToHexStringLower(SHA256.HashData(input))));
    }

    /// <summary>Converts every hostile byte, JSON, and scalar conversion failure into a closed result.</summary>
    private static Result<JsonDocument> Parse(ReadOnlySpan<byte> utf8, int maximum, Shape shape)
    {
        if (utf8.Length > maximum) return Fail<JsonDocument>(Failure.InputTooLarge);
        if (utf8.Length >= 3 && utf8[0] == 0xef && utf8[1] == 0xbb && utf8[2] == 0xbf) return Fail<JsonDocument>(Failure.InvalidUtf8);
        try { _ = StrictUtf8.GetCharCount(utf8); } catch (DecoderFallbackException) { return Fail<JsonDocument>(Failure.InvalidUtf8); }
        try
        {
            var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            if (!reader.Read() || !ValidateStructure(ref reader, shape) || reader.Read()) return Fail<JsonDocument>(Failure.InvalidContract);
            var document = JsonDocument.Parse(utf8.ToArray());
            var failure = ValidateValues(document.RootElement, shape); if (failure == Failure.None) failure = ValidateRelations(document.RootElement, shape);
            if (failure == Failure.None) return Ok(document); document.Dispose(); return Fail<JsonDocument>(failure);
        }
        catch (Exception exception) when (exception is JsonException or FormatException or OverflowException or InvalidOperationException or ArgumentException) { return Fail<JsonDocument>(Failure.ScalarInvalid); }
    }

    /// <summary>Consumes exact case-sensitive object names and refuses missing, duplicate, unknown, and crossed children.</summary>
    private static bool ValidateStructure(ref Utf8JsonReader reader, Shape shape)
    {
        if (reader.TokenType != JsonTokenType.StartObject) return false; var seen = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName) return false; var name = reader.GetString()!;
            var field = shape.Fields.SingleOrDefault(candidate => string.Equals(candidate.Name, name, StringComparison.Ordinal));
            if (field is null || !seen.Add(name) || !reader.Read()) return false;
            if (field.Child is not null) { if (!ValidateStructure(ref reader, field.Child)) return false; }
            else if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray) return false;
        }
        return reader.TokenType == JsonTokenType.EndObject && seen.Count == shape.Fields.Length;
    }

    /// <summary>Applies the declared type, nullability, grammar, enum, and numeric rule to every leaf.</summary>
    private static Failure ValidateValues(JsonElement element, Shape shape)
    { foreach (var field in shape.Fields) { var value = element.GetProperty(field.Name); var failure = field.Child is null ? field.Validate!(value) : ValidateValues(value, field.Child); if (failure != Failure.None) return failure; } return Failure.None; }

    /// <summary>Applies enrollment-time, transition reason, genesis, and predecessor relations.</summary>
    private static Failure ValidateRelations(JsonElement root, Shape shape)
    {
        var enrollment = ReferenceEquals(shape, RequestShape) ? root.GetProperty("requestedAuthority").GetProperty("enrollment") : root.TryGetProperty("enrollment", out var direct) ? direct : default;
        if (enrollment.ValueKind == JsonValueKind.Object && enrollment.GetProperty("expiresAtUtc").ValueKind != JsonValueKind.Null && ParseUtc(enrollment.GetProperty("issuedAtUtc").GetString()!) >= ParseUtc(enrollment.GetProperty("expiresAtUtc").GetString()!)) return Failure.ScalarInvalid;
        if (ReferenceEquals(shape, StatementShape)) return ValidateRelations(root.GetProperty("payload"), PayloadShape);
        if (ReferenceEquals(shape, RequestShape) || ReferenceEquals(shape, PayloadShape))
        {
            var transition = root.GetProperty("transition"); if (!ReasonMatches(transition)) return Failure.ScalarInvalid;
            var genesis = transition.GetProperty("kind").GetString() == "genesis";
            if (ReferenceEquals(shape, PayloadShape))
            {
                var recoveryGenesis = transition.GetProperty("kind").GetString() == "recovery"
                    && root.GetProperty("sequence").GetInt64() == 0;
                if ((genesis || recoveryGenesis)
                    != (root.GetProperty("previousGenerationId").ValueKind == JsonValueKind.Null))
                    return Failure.ScalarInvalid;
            }
            if (ReferenceEquals(shape, RequestShape))
            {
                var lineageNull = root.GetProperty("expectedAuthorityLineageId").ValueKind == JsonValueKind.Null;
                var currentNull = root.GetProperty("expectedCurrentGenerationId").ValueKind == JsonValueKind.Null;
                var predecessorNull = root.GetProperty("expectedPredecessorGenerationId").ValueKind == JsonValueKind.Null;
                if (genesis)
                {
                    if (!lineageNull || !currentNull || !predecessorNull) return Failure.ScalarInvalid;
                }
                else if (lineageNull || currentNull || predecessorNull
                    || !string.Equals(root.GetProperty("expectedCurrentGenerationId").GetString(), root.GetProperty("expectedPredecessorGenerationId").GetString(), StringComparison.Ordinal))
                {
                    return Failure.ScalarInvalid;
                }
            }
        }
        return Failure.None;
    }

    /// <summary>Checks the closed transition kind-to-reason registry.</summary>
    private static bool ReasonMatches(JsonElement transition) => transition.GetProperty("kind").GetString() switch
    { "genesis" => transition.GetProperty("reasonCode").GetString() == "INITIAL_ENROLLMENT", "release" => transition.GetProperty("reasonCode").GetString() == "APPROVED_RELEASE_ADVANCE", "binding" => transition.GetProperty("reasonCode").GetString() == "BINDING_REPLACEMENT", "enrollment" => transition.GetProperty("reasonCode").GetString() is "ENROLLMENT_ACTIVATED" or "ENROLLMENT_EXPIRED" or "ENROLLMENT_REPLACED", "revocation" => transition.GetProperty("reasonCode").GetString() == "AUTHORITY_REVOKED", "key_rotation" => transition.GetProperty("reasonCode").GetString() == "SIGNING_KEY_ROTATED", "security_epoch" => transition.GetProperty("reasonCode").GetString() == "SECURITY_EPOCH_ADVANCED", "reinstall" => transition.GetProperty("reasonCode").GetString() == "INSTALLATION_REINSTALLED", "recovery" => transition.GetProperty("reasonCode").GetString() == "RECOVERY_AUTHORIZED", "repair" => transition.GetProperty("reasonCode").GetString() == "REPAIR_AUTHORIZED", "seat" => transition.GetProperty("reasonCode").GetString() == "SEAT_REASSIGNED", _ => false };

    /// <summary>Returns owned canonical UTF-8 for one validated object.</summary>
    private static byte[] CanonicalBytes(JsonElement element, Shape shape) { var output = new ArrayBufferWriter<byte>(); WriteObject(output, element, shape); return output.WrittenSpan.ToArray(); }
    /// <summary>Writes exact property order without serializer policy.</summary>
    private static void WriteObject(ArrayBufferWriter<byte> output, JsonElement element, Shape shape)
    { Raw(output, "{"u8); for (var i = 0; i < shape.Fields.Length; i++) { if (i != 0) Raw(output, ","u8); var field = shape.Fields[i]; String(output, field.Name); Raw(output, ":"u8); var value = element.GetProperty(field.Name); if (field.Child is null) WriteScalar(output, value); else WriteObject(output, value, field.Child); } Raw(output, "}"u8); }
    /// <summary>Writes only validated strings, canonical integers, and explicit nulls.</summary>
    private static void WriteScalar(ArrayBufferWriter<byte> output, JsonElement value)
    { if (value.ValueKind == JsonValueKind.String) String(output, value.GetString()!); else if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var integer)) Raw(output, Encoding.ASCII.GetBytes(integer.ToString(CultureInfo.InvariantCulture))); else if (value.ValueKind == JsonValueKind.Null) Raw(output, "null"u8); else throw new JsonException("Unsupported scalar."); }
    /// <summary>Writes contract escapes while preserving every Unicode scalar without normalization.</summary>
    private static void String(ArrayBufferWriter<byte> output, string value)
    {
        Raw(output, "\""u8); Span<byte> encoded = stackalloc byte[4];
        foreach (var rune in value.EnumerateRunes())
        {
            ReadOnlySpan<byte> escape = rune.Value switch { 0x22 => "\\\""u8, 0x5c => "\\\\"u8, 0x08 => "\\b"u8, 0x09 => "\\t"u8, 0x0a => "\\n"u8, 0x0c => "\\f"u8, 0x0d => "\\r"u8, _ => [] };
            if (!escape.IsEmpty) { Raw(output, escape); continue; }
            if (rune.Value < 0x20 || rune.Value is 0x85 or 0x2028 or 0x2029) { Raw(output, Encoding.ASCII.GetBytes($"\\u{rune.Value:x4}")); continue; }
            var written = rune.EncodeToUtf8(encoded); output.Write(encoded[..written]);
        }
        Raw(output, "\""u8);
    }

    /// <summary>Privately assembles exactly schema, payload, authorityDigest, and signature.</summary>
    private static byte[] BuildStatement(ReadOnlySpan<byte> payload, string digest, string keyId, string signature)
    { var output = new ArrayBufferWriter<byte>(); Raw(output, "{\"schema\":\"runtime-enrollment-signed-generation-v2\",\"payload\":"u8); output.Write(payload); Raw(output, ",\"authorityDigest\":"u8); String(output, digest); Raw(output, ",\"signature\":{\"algorithm\":\"PS256\",\"keyId\":"u8); String(output, keyId); Raw(output, ",\"value\":"u8); String(output, signature); Raw(output, "}}"u8); return output.WrittenSpan.ToArray(); }
    /// <summary>Builds the exact bytes authenticated by the external registry-authority pin without normalizing validated metadata.</summary>
    /// <param name="options">Configuration already accepted by static and owner pin/keyset validation.</param>
    /// <param name="observed">Already validated UTC registry observation bound into the snapshot.</param>
    /// <returns>A newly allocated caller-owned buffer containing registry domain, LF, and SHA-256 of the complete deterministic metadata encoding.</returns>
    /// <exception cref="CryptographicException">Validated public PEM unexpectedly cannot be re-imported.</exception>
    /// <exception cref="ArgumentException">A PEM or SPKI unexpectedly became invalid when re-imported after validation.</exception>
    private static byte[] BuildRegistryAuthenticationInput(RuntimeAuthorityGenerationSigningOptions options, DateTimeOffset observed)
    {
        var output = new ArrayBufferWriter<byte>(); Raw(output, RegistryDomain); Raw(output, "\n"u8); String(output, options.RegistrySnapshotId); Raw(output, "\n"u8); Raw(output, Encoding.ASCII.GetBytes(options.RegistrySnapshotVersion.ToString(CultureInfo.InvariantCulture))); Raw(output, "\n"u8); Raw(output, Encoding.ASCII.GetBytes(observed.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))); Raw(output, "\n"u8);
        foreach (var key in options.Keys)
        {
            String(output, key.KeyId); Raw(output, "|"u8); String(output, key.Purpose); Raw(output, "|"u8); String(output, key.Domain); Raw(output, "|"u8);
            Raw(output, Encoding.ASCII.GetBytes(key.ContractVersion.ToString(CultureInfo.InvariantCulture))); Raw(output, "|"u8); String(output, key.Status); Raw(output, "|"u8);
            String(output, key.ActivatedAtUtc.ToString("O", CultureInfo.InvariantCulture)); Raw(output, "|"u8);
            WriteNullableMetadata(output, key.RetiredAtUtc?.ToString("O", CultureInfo.InvariantCulture)); Raw(output, "|"u8);
            WriteNullableMetadata(output, key.RevokedAtUtc?.ToString("O", CultureInfo.InvariantCulture)); Raw(output, "|"u8);
            WriteNullableMetadata(output, key.RevocationReason); Raw(output, "|"u8);
            WriteNullableMetadata(output, key.CompromiseFromUtc?.ToString("O", CultureInfo.InvariantCulture)); Raw(output, "|"u8);
            using var rsa = RSA.Create(); rsa.ImportFromPem(key.PublicKeyPem); String(output, Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())); Raw(output, "\n"u8);
        }
        return WithDomain(RegistryDomain, SHA256.HashData(output.WrittenSpan));
    }

    /// <summary>Writes nullable trusted metadata without conflating null and an empty string.</summary>
    private static void WriteNullableMetadata(ArrayBufferWriter<byte> output, string? value)
    { if (value is null) Raw(output, "null"u8); else String(output, value); }

    /// <summary>Imports validated public keys without normalization and deep-copies each canonical SPKI into proof-owned metadata.</summary>
    /// <param name="keys">Configuration entries already accepted by static and owner pin/keyset validation.</param>
    /// <returns>A newly allocated array of independently owned RegistryKey objects; each object owns its own public SPKI copy.</returns>
    /// <exception cref="CryptographicException">Validated public PEM unexpectedly cannot be re-imported.</exception>
    /// <exception cref="ArgumentException">A PEM or SPKI unexpectedly became invalid when re-imported after validation.</exception>
    private static RegistryKey[] CopyRegistryKeys(IEnumerable<RuntimeAuthorityGenerationKeyOptions> keys) => keys.Select(key => { using var rsa = RSA.Create(); rsa.ImportFromPem(key.PublicKeyPem); return new RegistryKey(key, rsa.ExportSubjectPublicKeyInfo()); }).ToArray();

    /// <summary>Combines shared configuration validation with item-2-owned separation of the external pin from every registry key.</summary>
    /// <param name="options">Untrusted optional keyset configuration.</param>
    /// <returns>None only when configuration is valid and no canonical key SPKI equals the immutable authority pin; otherwise KeyConfigurationInvalid.</returns>
    private Failure ValidateOwnedConfiguration(RuntimeAuthorityGenerationSigningOptions? options)
    {
        if (RuntimeAuthorityGenerationConfigurationValidator.Validate(options).Count != 0) return Failure.KeyConfigurationInvalid;
        try
        {
            foreach (var key in options!.Keys)
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(key.PublicKeyPem);
                var keySpki = rsa.ExportSubjectPublicKeyInfo();
                try
                {
                    if (keySpki.Length == registryAuthoritySpki.Length
                        && CryptographicOperations.FixedTimeEquals(keySpki, registryAuthoritySpki))
                        return Failure.KeyConfigurationInvalid;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(keySpki);
                }
            }
            return Failure.None;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return Failure.KeyConfigurationInvalid;
        }
    }
    /// <summary>Builds the sole generation/recovery input: 55-byte domain, LF, canonical payload.</summary>
    private static byte[] SigningInput(ReadOnlySpan<byte> payload) => WithDomain(GenerationDomain, payload);

    /// <summary>Builds the distinct item-3 recovery-preparation token signing input.</summary>
    private static byte[] RecoveryPreparationInput(ReadOnlySpan<byte> claims) =>
        WithDomain("T-IA-CONNECT\0RUNTIME-ENROLLMENT\0RECOVERY-PREPARATION\0V2"u8, claims);
    /// <summary>Concatenates exact domain bytes, one LF, and owned payload bytes.</summary>
    private static byte[] WithDomain(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> payload) => [.. domain, (byte)'\n', .. payload];
    /// <summary>Returns future, stale, or current status against trusted time.</summary>
    private static Failure Freshness(DateTimeOffset observed, DateTimeOffset now) => observed > now ? Failure.KeyRegistryTimeInvalid : now - observed > MaximumRegistryAge ? Failure.KeyRegistryStale : Failure.None;
    /// <summary>Creates an exact string-constant leaf validator.</summary>
    private static LeafValidator Const(string expected, Failure failure) => value => value.ValueKind == JsonValueKind.String && string.Equals(value.GetString(), expected, StringComparison.Ordinal) ? Failure.None : failure;
    /// <summary>Accepts only the integer token 2.</summary>
    private static Failure Version(JsonElement value) => value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) && number == 2 && value.GetRawText() == "2" ? Failure.None : Failure.ContractVersionUnsupported;
    /// <summary>Accepts only a mandatory canonical lowercase UUID.</summary>
    private static Failure Uuid(JsonElement value) => value.ValueKind == JsonValueKind.String && IsUuid(value.GetString()) ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Accepts explicit null or a canonical lowercase UUID.</summary>
    private static Failure NullableUuid(JsonElement value) => value.ValueKind == JsonValueKind.Null || Uuid(value) == Failure.None ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Checks canonical UUID text, RFC version, and RFC variant.</summary>
    private static bool IsUuid(string? value) => value is not null && Guid.TryParseExact(value, "D", out var parsed) && value == parsed.ToString("D") && value[14] is >= '1' and <= '8' && value[19] is '8' or '9' or 'a' or 'b';
    /// <summary>Checks the provider ASCII grammar and 1..64 bound.</summary>
    private static Failure Provider(JsonElement value) => Pattern(value, 1, 64, text => text[0] is >= 'a' and <= 'z' or >= '0' and <= '9' && text.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-'));
    /// <summary>Checks the key-id ASCII grammar and 1..128 bound.</summary>
    private static Failure KeyId(JsonElement value) => Pattern(value, 1, 128, text => text[0] is >= 'a' and <= 'z' or >= '0' and <= '9' && text.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-'));
    /// <summary>Checks opaque provider reference runes and controls without transforming text.</summary>
    private static Failure ProviderGrantRef(JsonElement value) => value.ValueKind == JsonValueKind.String && value.GetString()! is var text && text.EnumerateRunes().Count() is >= 1 and <= 256 && text.All(character => character >= 0x20 && character != 0x7f) ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Checks three canonical decimal release components bounded to Int32.MaxValue.</summary>
    private static Failure ReleaseVersion(JsonElement value)
    { if (value.ValueKind != JsonValueKind.String) return Failure.ScalarInvalid; var parts = value.GetString()!.Split('.'); return parts.Length == 3 && parts.All(part => part.Length is >= 1 and <= 10 && !(part.Length > 1 && part[0] == '0') && part.All(char.IsAsciiDigit) && !(part.Length == 10 && string.CompareOrdinal(part, "2147483647") > 0)) ? Failure.None : Failure.ScalarInvalid; }
    /// <summary>Checks exact lowercase 64-hex SHA-256 text.</summary>
    private static Failure Digest(JsonElement value) => value.ValueKind == JsonValueKind.String && TryDecodeDigest(value.GetString()!, out _) ? Failure.None : Failure.DigestInvalid;
    /// <summary>Checks exact six-fractional-digit UTC text.</summary>
    private static Failure Utc(JsonElement value) => value.ValueKind == JsonValueKind.String && TryUtc(value.GetString(), out _) ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Accepts explicit null or exact canonical UTC text.</summary>
    private static Failure NullableUtc(JsonElement value) => value.ValueKind == JsonValueKind.Null || Utc(value) == Failure.None ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Checks the closed enrollment-state registry.</summary>
    private static Failure EnrollmentState(JsonElement value) => value.ValueKind == JsonValueKind.String && value.GetString() is "pending" or "active" or "revoked" or "expired" ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Checks the closed transition-kind registry.</summary>
    private static Failure TransitionKind(JsonElement value) => value.ValueKind == JsonValueKind.String && value.GetString() is "genesis" or "release" or "binding" or "enrollment" or "key_rotation" or "security_epoch" or "seat" or "repair" or "reinstall" or "recovery" or "revocation" ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Checks the closed transition-reason registry.</summary>
    private static Failure TransitionReason(JsonElement value) => value.ValueKind == JsonValueKind.String && value.GetString() is "INITIAL_ENROLLMENT" or "APPROVED_RELEASE_ADVANCE" or "BINDING_REPLACEMENT" or "ENROLLMENT_ACTIVATED" or "ENROLLMENT_EXPIRED" or "ENROLLMENT_REPLACED" or "AUTHORITY_REVOKED" or "SIGNING_KEY_ROTATED" or "SECURITY_EPOCH_ADVANCED" or "INSTALLATION_REINSTALLED" or "RECOVERY_AUTHORIZED" or "REPAIR_AUTHORIZED" or "SEAT_REASSIGNED" ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Accepts only canonical non-negative Int32 integer tokens.</summary>
    private static Failure SecurityEpoch(JsonElement value) => value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) && number >= 0 && value.GetRawText() == number.ToString(CultureInfo.InvariantCulture) ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Accepts canonical non-negative sequence tokens that remain exact in C# and JavaScript.</summary>
    /// <remarks>The upper bound is the IEEE-754 maximum safe integer consumed by Website.</remarks>
    private static Failure Sequence(JsonElement value) => value.ValueKind == JsonValueKind.Number
        && value.TryGetInt64(out var number) && number is >= 0 and <= 9_007_199_254_740_991
        && value.GetRawText() == number.ToString(CultureInfo.InvariantCulture)
            ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Checks canonical 342-character Base64Url for exactly 256 bytes.</summary>
    private static Failure Signature(JsonElement value) => value.ValueKind == JsonValueKind.String && TryDecodeSignature(value.GetString()!, out _) ? Failure.None : Failure.Base64UrlInvalid;
    /// <summary>Applies an exact string length and character predicate.</summary>
    private static Failure Pattern(JsonElement value, int min, int max, Func<string, bool> predicate) => value.ValueKind == JsonValueKind.String && value.GetString()! is var text && text.Length >= min && text.Length <= max && predicate(text) ? Failure.None : Failure.ScalarInvalid;
    /// <summary>Parses only yyyy-MM-ddTHH:mm:ss.ffffffZ as UTC.</summary>
    private static bool TryUtc(string? value, out DateTimeOffset parsed) => DateTimeOffset.TryParseExact(value, "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed) && parsed.Offset == TimeSpan.Zero;
    /// <summary>Returns a timestamp already proven valid by the leaf validator.</summary>
    private static DateTimeOffset ParseUtc(string value) { _ = TryUtc(value, out var parsed); return parsed; }
    /// <summary>Decodes exact lowercase digest text into exactly 32 bytes.</summary>
    private static bool TryDecodeDigest(string value, out byte[] bytes) { bytes = []; if (value.Length != 64 || value.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))) return false; try { bytes = Convert.FromHexString(value); return bytes.Length == 32; } catch (FormatException) { return false; } }
    /// <summary>Decodes, re-encodes, and ordinally compares canonical unpadded Base64Url.</summary>
    private static bool TryDecodeSignature(string value, out byte[] bytes) { bytes = []; if (value.Length != 342 || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))) return false; try { bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "=="); return bytes.Length == 256 && value == EncodeBase64Url(bytes); } catch (FormatException) { return false; } }
    /// <summary>Encodes bytes as canonical unpadded Base64Url.</summary>
    private static string EncodeBase64Url(ReadOnlySpan<byte> value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    /// <summary>Creates one leaf field.</summary>
    private static Field L(string name, LeafValidator validator) => new(name, null, validator);
    /// <summary>Creates one child-object field.</summary>
    private static Field O(string name, Shape shape) => new(name, shape, null);
    /// <summary>Creates one closed object shape.</summary>
    private static Shape S(params Field[] fields) => new(fields);
    /// <summary>Creates an owned successful result.</summary>
    private static Result<T> Ok<T>(T value) where T : class => new(value, Failure.None);
    /// <summary>Creates a failed result without a partial value.</summary>
    private static Result<T> Fail<T>(Failure failure) where T : class => new(null, failure);
    /// <summary>Appends exact bytes to the current writer.</summary>
    private static void Raw(ArrayBufferWriter<byte> output, ReadOnlySpan<byte> value) => output.Write(value);
    /// <summary>Rejects any proof construction or consumption attempt lacking the process-private capability.</summary>
    private static void EnsureSeal(object seal) { if (!ReferenceEquals(seal, ProofSeal)) throw new InvalidOperationException("Item 2 proof ownership violation."); }
}
