using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SoftLicence.Tests.Server;

/// <summary>Defines the closed, metadata-only TKT-000672 Source C producer protocol.</summary>
internal static class Tkt000672SourceCAuthorityContract
{
    internal const string RequestSchema = "runtime-enrollment-source-c-authority-request-v1";
    internal const string ResponseSchema = "runtime-enrollment-source-c-authority-response-v1";
    internal const string ManifestSchema = "runtime-enrollment-softlicence-authority-manifest-v1";
    internal const string Ticket = "TKT-000672";
    internal const string ParentTicket = "TKT-000631";
    internal const string RecipeId = "8f322459-01f8-4d03-8266-00a3b5caac15";
    internal const int RecipeRevision = 1;
    internal const string ContractDBaseline = "3738e8f5e98284f9793818fa960e5dbb885fb82d";
    internal const string Environment = "NON_PRODUCTION_REAL";
    internal const string Algorithm = "PS256";
    internal const string TrustDomain = "SOFTLICENCE-AUTHORITY-MANIFEST-V1";
    internal const int CollectionLimit = 500;
    internal const int IdentifierUtf8Limit = 128;
    internal const int RequestUtf8Limit = 16_384;
    internal const int CanonicalPayloadUtf8Limit = 512_000;
    internal const int SignedStatementUtf8Limit = 512;
    internal const int SignatureUtf8Limit = 2_048;
    internal const int SignatureBytesLimit = 768;
    internal const int CanonicalManifestUtf8Limit = 640_000;
    internal const string CanonicalPayloadDomain = "TKT-000672/SOFTLICENCE-AUTHORITY-MANIFEST/V1/CANONICAL-PAYLOAD";
    internal const string AuthorityDigestDomain = "TKT-000672/SOFTLICENCE-AUTHORITY-MANIFEST/V1/AUTHORITY-DIGEST";
    internal const string SignedStatementDomain = "TKT-000672/SOFTLICENCE-AUTHORITY-MANIFEST/V1/SIGNED-STATEMENT";
    internal const string CanonicalManifestDomain = "TKT-000672/SOFTLICENCE-AUTHORITY-MANIFEST/V1/CANONICAL-MANIFEST";
    internal const string PublicIdentityDomain = "TKT-000672/SOURCE-C/PUBLIC-IDENTITY/V1";

    internal static readonly string[] RequestKeys =
    [
        "schema", "runId", "environment", "sourceId", "observedAtUtc", "snapshotHash",
        "catalogHash", "migrationsHash", "oracleHash", "generationSpecHash",
        "providerScope", "productScope", "grantScope"
    ];

    internal static readonly Tkt000672Scenario[] Scenarios =
    [
        new("scenario_proven", 0, "PROVEN", "PROVEN_EXACT_ATTESTED_TUPLE"),
        new("scenario_partial", 1, "PARTIAL", "PARTIAL_REQUIRED_EVIDENCE_MISSING"),
        new("scenario_ambiguous", 2, "AMBIGUOUS", "AMBIGUOUS_MULTIPLE_ATTESTED_TUPLES"),
        new("scenario_inconsistent", 3, "INCONSISTENT", "INCONSISTENT_ATTESTED_TUPLE_CONFLICT")
    ];

    internal static readonly string[] SourceCStates =
        ["PROPOSED", "NOT_CREATED", "NOT_ATTESTED", "NOT_AUTHORIZED_FOR_MATERIALIZATION"];

    /// <summary>Parses an exact closed request without trimming, folding, normalization, or repair.</summary>
    /// <param name="utf8">Caller-owned UTF-8 request bytes, bounded to 16,384 bytes.</param>
    /// <returns>A validated request or a stable metadata-only refusal.</returns>
    internal static Tkt000672RequestValidation ParseRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.IsEmpty || utf8.Length > RequestUtf8Limit)
            return Tkt000672RequestValidation.Refuse("REQUEST_SIZE_INVALID", "request");
        if (FindEscapedLoneSurrogate(utf8, out var unicodeField))
            return Tkt000672RequestValidation.Refuse("UNICODE_INVALID", unicodeField);
        try
        {
            using var document = JsonDocument.Parse(utf8.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Tkt000672RequestValidation.Refuse("SCHEMA_INVALID", "request");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!seen.Add(property.Name) || !RequestKeys.Contains(property.Name, StringComparer.Ordinal))
                    return Tkt000672RequestValidation.Refuse("SCHEMA_INVALID", "request.keys");
            }
            if (seen.Count != RequestKeys.Length)
                return Tkt000672RequestValidation.Refuse("SCHEMA_INVALID", "request.keys");
            string S(string name) => root.GetProperty(name).ValueKind == JsonValueKind.String
                ? root.GetProperty(name).GetString()!
                : throw new JsonException();
            var request = new Tkt000672SourceCRequest(
                S("schema"), S("runId"), S("environment"), S("sourceId"), S("observedAtUtc"),
                S("snapshotHash"), S("catalogHash"), S("migrationsHash"), S("oracleHash"),
                S("generationSpecHash"), S("providerScope"), S("productScope"), S("grantScope"));
            if (request.Schema != RequestSchema)
                return Tkt000672RequestValidation.Refuse("SCHEMA_INVALID", "schema");
            if (!IsIdentifier(request.RunId) || !IsIdentifier(request.SourceId))
                return Tkt000672RequestValidation.Refuse("IDENTIFIER_INVALID", "identity");
            if (request.Environment != Environment)
                return Tkt000672RequestValidation.Refuse("ENVIRONMENT_INVALID", "environment");
            if (!IsUtc(request.ObservedAtUtc))
                return Tkt000672RequestValidation.Refuse("TIMESTAMP_INVALID", "observedAtUtc");
            if (!new[] { request.SnapshotHash, request.CatalogHash, request.MigrationsHash,
                    request.OracleHash, request.GenerationSpecHash }.All(IsHash))
                return Tkt000672RequestValidation.Refuse("DIGEST_INVALID", "evidenceHashes");
            if (!new[] { request.ProviderScope, request.ProductScope, request.GrantScope }.All(IsIdentifier))
                return Tkt000672RequestValidation.Refuse("SCOPE_INVALID", "scopes");
            return new(true, request, null, null);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException)
        {
            return Tkt000672RequestValidation.Refuse("SCHEMA_INVALID", "request");
        }
    }

    /// <summary>
    /// Screens JSON string tokens for escaped unpaired UTF-16 surrogates before JSON decoding can repair them.
    /// Work is linear in the already bounded 16,384-byte request and allocates no caller-sized object graph.
    /// </summary>
    /// <param name="utf8">Bounded raw JSON bytes.</param>
    /// <param name="field">Stable property-name or value category, never rejected text.</param>
    /// <returns><see langword="true"/> when one string token contains an escaped lone surrogate.</returns>
    private static bool FindEscapedLoneSurrogate(ReadOnlySpan<byte> utf8, out string field)
    {
        field = "request.valueUnicode";
        for (var index = 0; index < utf8.Length; index++)
        {
            if (utf8[index] != (byte)'\"') continue;
            var invalid = false;
            for (index++; index < utf8.Length && utf8[index] != (byte)'\"'; index++)
            {
                if (utf8[index] != (byte)'\\') continue;
                if (++index >= utf8.Length) break;
                if (utf8[index] != (byte)'u') continue;
                if (!TryHex16(utf8, index + 1, out var codeUnit)) continue;
                index += 4;
                if (codeUnit is >= 0xdc00 and <= 0xdfff)
                {
                    invalid = true;
                    continue;
                }
                if (codeUnit is not (>= 0xd800 and <= 0xdbff)) continue;
                if (index + 6 >= utf8.Length || utf8[index + 1] != (byte)'\\'
                    || utf8[index + 2] != (byte)'u'
                    || !TryHex16(utf8, index + 3, out var low)
                    || low is not (>= 0xdc00 and <= 0xdfff))
                {
                    invalid = true;
                    continue;
                }
                index += 6;
            }
            if (!invalid) continue;
            var probe = index + 1;
            while (probe < utf8.Length && utf8[probe] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') probe++;
            field = probe < utf8.Length && utf8[probe] == (byte)':'
                ? "request.propertyNameUnicode"
                : "request.valueUnicode";
            return true;
        }
        return false;
    }

    /// <summary>Parses exactly four ASCII hexadecimal digits without creating a string.</summary>
    /// <param name="utf8">Raw bounded JSON bytes.</param>
    /// <param name="start">First hexadecimal digit.</param>
    /// <param name="value">Parsed UTF-16 code unit when successful.</param>
    /// <returns><see langword="true"/> only for four present hexadecimal digits.</returns>
    private static bool TryHex16(ReadOnlySpan<byte> utf8, int start, out int value)
    {
        value = 0;
        if (start < 0 || start + 4 > utf8.Length) return false;
        for (var offset = 0; offset < 4; offset++)
        {
            var digit = utf8[start + offset] switch
            {
                >= (byte)'0' and <= (byte)'9' => utf8[start + offset] - (byte)'0',
                >= (byte)'a' and <= (byte)'f' => utf8[start + offset] - (byte)'a' + 10,
                >= (byte)'A' and <= (byte)'F' => utf8[start + offset] - (byte)'A' + 10,
                _ => -1
            };
            if (digit < 0) return false;
            value = value * 16 + digit;
        }
        return true;
    }

    /// <summary>Builds and signs the exact manifest from bounded, already opaque generation metadata.</summary>
    /// <param name="request">Validated external authority request.</param>
    /// <param name="rows">At most 500 owned generation observations.</param>
    /// <param name="signer">Ephemeral PS256 manifest authority.</param>
    /// <returns>The signed response plus exact canonical artifacts used by the harness.</returns>
    /// <exception cref="InvalidOperationException">A bound, order, duplicate, or framing invariant fails.</exception>
    internal static Tkt000672BuiltManifest BuildManifest(
        Tkt000672SourceCRequest request,
        IReadOnlyList<Tkt000672GenerationObservation> rows,
        Tkt000672ManifestSigner signer)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(signer);
        if (rows.Count > CollectionLimit) throw new InvalidOperationException("GENERATION_LIMIT_EXCEEDED");
        if (rows.Any(row => !Scenarios.Any(scenario => scenario.Classification == row.Classification)))
            throw new InvalidOperationException("CLASSIFICATION_INVALID");

        var provider = Scope(request.ProviderScope, "provider", rows.FirstOrDefault()?.ProviderScopeDigest);
        var product = Scope(request.ProductScope, "product", rows.FirstOrDefault()?.ProductScopeDigest);
        var grant = Scope(request.GrantScope, "grant", rows.FirstOrDefault()?.GrantScopeDigest);
        if (rows.Any(row => row.ProviderScopeDigest is not null
                && row.ProviderScopeDigest != provider["digest"]!.GetValue<string>()
            || row.ProductScopeDigest is not null
                && row.ProductScopeDigest != product["digest"]!.GetValue<string>()
            || row.GrantScopeDigest is not null
                && row.GrantScopeDigest != grant["digest"]!.GetValue<string>()))
            throw new InvalidOperationException("SCOPE_DIGEST_MISMATCH");
        var generations = rows.Select(row => new JsonObject
        {
            ["generationId"] = row.GenerationId,
            ["generationDigest"] = row.GenerationDigest,
            ["providerScopeId"] = provider["opaqueId"]!.GetValue<string>(),
            ["productScopeId"] = product["opaqueId"]!.GetValue<string>(),
            ["grantScopeId"] = grant["opaqueId"]!.GetValue<string>(),
            ["tupleCount"] = 1
        }).OrderBy(item => item["generationId"]!.GetValue<string>(), Utf8OrdinalComparer.Instance).ToArray();
        var tuples = rows.Select(row => new JsonObject
        {
            ["tupleId"] = row.RequestId,
            ["tupleDigest"] = row.RequestDigest,
            ["generationId"] = row.GenerationId,
            ["providerScopeId"] = provider["opaqueId"]!.GetValue<string>(),
            ["productScopeId"] = product["opaqueId"]!.GetValue<string>(),
            ["grantScopeId"] = grant["opaqueId"]!.GetValue<string>()
        }).OrderBy(item => item["tupleId"]!.GetValue<string>(), Utf8OrdinalComparer.Instance).ToArray();
        EnsureUniqueOrdered(generations, "generationId", "generationDigest");
        EnsureUniqueOrdered(tuples, "tupleId", "tupleDigest");

        var payload = new JsonObject
        {
            ["ticketRef"] = Ticket,
            ["parentTicketRef"] = ParentTicket,
            ["recipeId"] = RecipeId,
            ["recipeRevision"] = RecipeRevision,
            ["contractDBaselineCommit"] = ContractDBaseline,
            ["environment"] = request.Environment,
            ["sourceId"] = request.SourceId,
            ["evidenceHashes"] = new JsonObject
            {
                ["snapshotHash"] = request.SnapshotHash, ["catalogHash"] = request.CatalogHash,
                ["migrationsHash"] = request.MigrationsHash, ["oracleHash"] = request.OracleHash,
                ["generationSpecHash"] = request.GenerationSpecHash
            },
            ["scopes"] = new JsonObject { ["provider"] = provider, ["product"] = product, ["grant"] = grant },
            ["trustSnapshotBinding"] = signer.Binding.DeepClone(),
            ["history"] = new JsonObject
            {
                ["completeOneBatch"] = true, ["samplingUsed"] = false, ["pagingUsed"] = false,
                ["totalCardinality"] = tuples.Length, ["generationCount"] = generations.Length,
                ["tupleCount"] = tuples.Length
            },
            ["authorityGenerations"] = new JsonArray(generations.Select(item => (JsonNode)item).ToArray()),
            ["authorityTuples"] = new JsonArray(tuples.Select(item => (JsonNode)item).ToArray()),
            ["proofBoundary"] = new JsonObject
            {
                ["artifactKind"] = "SOFTLICENCE_AUTHORITY_METADATA",
                ["fixtureQualificationPromotable"] = false,
                ["sourceCStates"] = new JsonArray(SourceCStates
                    .Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
                ["materializationAuthorized"] = false,
                ["nativeRecipeState"] = "NOT_RUN",
                ["nativePass"] = "NOT_CLAIMED"
            }
        };
        return BuildManifestCore(payload, request.ObservedAtUtc, signer.PinnedValidFromUtc,
            signer.PinnedValidUntilUtc, signer);
    }

    /// <summary>Applies the single canonical framing/signing pipeline shared by real and golden payloads.</summary>
    private static Tkt000672BuiltManifest BuildManifestCore(
        JsonObject payload, string issuedAtUtc, string? pinnedValidFromUtc,
        string? pinnedValidUntilUtc, Tkt000672ManifestSigner signer)
    {
        var canonicalPayloadJson = Canonicalize(payload);
        var canonicalPayload = Frame(CanonicalPayloadDomain, canonicalPayloadJson);
        BoundUtf8(canonicalPayload, CanonicalPayloadUtf8Limit, "canonicalPayload");
        var authorityDigest = Sha256(Frame(AuthorityDigestDomain, canonicalPayload));
        var signedStatement = Frame(SignedStatementDomain, ManifestSchema, authorityDigest);
        BoundUtf8(signedStatement, SignedStatementUtf8Limit, "signedStatement");
        var issued = issuedAtUtc;
        var observed = DateTimeOffset.ParseExact(issued, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        var validFrom = pinnedValidFromUtc ?? observed.AddMinutes(-5)
            .ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        var validUntil = pinnedValidUntilUtc ?? observed.AddMinutes(5)
            .ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        signer.SetWindow(validFrom, validUntil, issued);
        var projection = new JsonObject
        {
            ["schema"] = ManifestSchema, ["payload"] = payload.DeepClone(),
            ["canonicalPayload"] = canonicalPayload, ["signedStatement"] = signedStatement,
            ["authorityDigest"] = authorityDigest, ["algorithm"] = Algorithm,
            ["keyId"] = signer.KeyId, ["issuedAtUtc"] = issued,
            ["validFromUtc"] = validFrom, ["validUntilUtc"] = validUntil
        };
        var signingProjectionCanonical = Canonicalize(projection);
        var signedBytes = Encoding.UTF8.GetBytes(Frame(CanonicalManifestDomain, signingProjectionCanonical));
        var signature = signer.Sign(signedBytes);
        BoundUtf8(signature, SignatureUtf8Limit, "signature");
        var manifest = (JsonObject)projection.DeepClone();
        manifest["signature"] = signature;
        var canonicalManifest = Canonicalize(manifest);
        BoundUtf8(canonicalManifest, CanonicalManifestUtf8Limit, "manifest");
        return new(manifest, signer.TrustSnapshot.DeepClone().AsObject(), canonicalPayloadJson,
            canonicalPayload, authorityDigest, signedStatement, signingProjectionCanonical,
            signedBytes, canonicalManifest);
    }

    /// <summary>Canonicalizes JSON with exact UTF-8 ordinal object-key ordering and no string normalization.</summary>
    /// <param name="node">A data-only JSON node.</param>
    /// <returns>Compact canonical UTF-8-equivalent JSON text.</returns>
    internal static string Canonicalize(JsonNode? node)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(writerBuffer, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false,
            SkipValidation = false
        }))
        {
            WriteNode(writer, node);
        }
        return Encoding.UTF8.GetString(writerBuffer.WrittenSpan);
    }

    /// <summary>Frames exact strings as LF-separated UTF-8 byte-length-prefixed protocol values.</summary>
    /// <param name="domain">Closed ASCII domain.</param>
    /// <param name="values">Exact values whose byte lengths are independently encoded.</param>
    /// <returns>The unambiguous domain-separated text frame.</returns>
    internal static string Frame(string domain, params string[] values) => domain + "\n" +
        string.Join("\n", values.Select(value => $"{Encoding.UTF8.GetByteCount(value)}:{value}"));

    /// <summary>Computes lowercase SHA-256 over exact UTF-8 text.</summary>
    /// <param name="value">Exact text without normalization.</param>
    /// <returns>A 64-character lowercase digest.</returns>
    internal static string Sha256(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Derives a non-reversible public identifier from one internal opaque identity.</summary>
    /// <param name="kind">Closed identity role.</param>
    /// <param name="value">Exact internal identity.</param>
    /// <returns>A bounded lowercase digest identifier.</returns>
    internal static string PublicId(string kind, string value) =>
        Sha256(Frame($"{PublicIdentityDomain}/{kind}", value))[..32];

    /// <summary>Derives a non-reversible public digest from an already opaque internal digest.</summary>
    /// <param name="kind">Closed digest role.</param>
    /// <param name="value">Exact internal digest.</param>
    /// <returns>A lowercase SHA-256 digest.</returns>
    internal static string PublicDigest(string kind, string value) => Sha256(Frame($"{PublicIdentityDomain}/{kind}", value));

    /// <summary>
    /// Classifies exact legacy evidence against authenticated v2 tuples using the authoritative Website
    /// Contract C precedence. Inputs are compared ordinally without trimming, folding, normalization,
    /// synthesis, deduplication, or inference.
    /// </summary>
    /// <param name="evidence">Closed nullable legacy evidence read from the synthetic scenario.</param>
    /// <param name="scope">Injected authoritative provider/product/grant scope.</param>
    /// <param name="tuples">Bounded authenticated tuples in persisted generation order.</param>
    /// <returns>One closed classification and normative Contract C reason.</returns>
    internal static Tkt000672LegacyClassification ClassifyLegacyEvidence(
        Tkt000672LegacyEvidence evidence,
        Tkt000672LegacyScope scope,
        IReadOnlyList<Tkt000672AttestedTuple> tuples)
    {
        if (tuples.Select(tuple => tuple.AuthorityGenerationId)
            .Distinct(StringComparer.Ordinal).Count() != tuples.Count)
            return new("INCONSISTENT", "INCONSISTENT_DUPLICATE_ATTESTED_IDENTITY");
        if (scope.Authority != "SOFTLICENCE_ATTESTED_SCOPE" || string.IsNullOrEmpty(scope.Provider)
            || string.IsNullOrEmpty(scope.ProductId) || string.IsNullOrEmpty(scope.ProviderGrantRef))
            return new("INCONSISTENT", "INCONSISTENT_AUTHORITY_SCOPE_INVALID");
        if (tuples.Any(tuple => tuple.Provider != scope.Provider || tuple.ProductId != scope.ProductId
                || tuple.ProviderGrantRef != scope.ProviderGrantRef)
            || evidence.ProviderGrantRef is not null && evidence.ProviderGrantRef != scope.ProviderGrantRef)
            return new("INCONSISTENT", "INCONSISTENT_AUTHORITY_SCOPE_CONFLICT");

        var matching = tuples.Where(tuple => EvidenceMatches(evidence, tuple)).ToArray();
        if (matching.Length > 1)
            return new("AMBIGUOUS", "AMBIGUOUS_MULTIPLE_ATTESTED_TUPLES");
        var complete = evidence.ProviderGrantRef is not null && evidence.AuthorityDigest is not null
            && evidence.SecurityEpoch is not null && evidence.BindingId is not null
            && evidence.EnrollmentId is not null && evidence.KeyThumbprint is not null
            && evidence.ReleaseVersion is not null;
        if (matching.Length == 1)
            return complete
                ? new("PROVEN", "PROVEN_EXACT_ATTESTED_TUPLE")
                : new("PARTIAL", "PARTIAL_REQUIRED_EVIDENCE_MISSING");
        if (tuples.Any(tuple => EvidenceContradicts(evidence, tuple)))
            return new("INCONSISTENT", "INCONSISTENT_ATTESTED_TUPLE_CONFLICT");
        return complete
            ? new("PARTIAL", "PARTIAL_NO_ATTESTED_TUPLE")
            : new("PARTIAL", "PARTIAL_REQUIRED_EVIDENCE_MISSING");
    }

    /// <summary>
    /// Validates one complete produced manifest against injected request and trust authority before invoking
    /// the PS256 verifier at most once. All schema, canonical, bound, trust, and no-materialization checks
    /// finish before the callback; callback false or exception becomes `SIGNATURE_INVALID`.
    /// </summary>
    /// <param name="manifest">Caller-owned complete manifest JSON.</param>
    /// <param name="trustSnapshot">Injected trust-store snapshot, never taken from the payload.</param>
    /// <param name="context">Closed expected request and public trust identities.</param>
    /// <param name="verifier">Caller-owned real PS256 verifier for exact signed bytes and signature.</param>
    /// <returns>A stable data-only acceptance/refusal without rejected-value echo.</returns>
    internal static Tkt000672ManifestValidation ValidateManifest(
        JsonObject manifest, JsonObject trustSnapshot, Tkt000672ManifestValidationContext context,
        Func<byte[], string, bool> verifier)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(trustSnapshot);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(verifier);
        try
        {
            if (!Closed(manifest, ["schema", "payload", "canonicalPayload", "signedStatement",
                    "authorityDigest", "algorithm", "keyId", "signature", "issuedAtUtc",
                    "validFromUtc", "validUntilUtc"]))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "manifest.keys");
            if (manifest["schema"]?.GetValue<string>() != ManifestSchema)
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "schema");
            if (manifest["payload"] is not JsonObject payload || !Closed(payload,
                    ["ticketRef", "parentTicketRef", "recipeId", "recipeRevision",
                    "contractDBaselineCommit", "environment", "sourceId", "evidenceHashes", "scopes",
                    "trustSnapshotBinding", "history", "authorityGenerations", "authorityTuples", "proofBoundary"]))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.keys");
            if (!ClosedObject(payload, "evidenceHashes",
                    ["snapshotHash", "catalogHash", "migrationsHash", "oracleHash", "generationSpecHash"],
                    out var evidenceHashes))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.evidenceHashes.keys");
            if (!ClosedObject(payload, "scopes", ["provider", "product", "grant"], out var scopes))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.scopes.keys");
            foreach (var role in new[] { "provider", "product", "grant" })
                if (!ClosedObject(scopes, role, ["opaqueId", "digest"], out _))
                    return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", $"payload.scopes.{role}.keys");
            if (!ClosedObject(payload, "history", ["completeOneBatch", "samplingUsed", "pagingUsed",
                    "totalCardinality", "generationCount", "tupleCount"], out var history))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.history.keys");
            if (!ClosedObject(payload, "proofBoundary", ["artifactKind", "fixtureQualificationPromotable",
                    "sourceCStates", "materializationAuthorized", "nativeRecipeState", "nativePass"], out var proof))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.proofBoundary.keys");
            if (!ClosedObject(payload, "trustSnapshotBinding",
                    ["snapshotId", "digest", "domain", "keyId", "fingerprint"], out var binding))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.trustSnapshotBinding.keys");
            if (!Closed(trustSnapshot, ["snapshotId", "digest", "domain", "keyId", "fingerprint",
                    "validFromUtc", "validUntilUtc", "revocation"]))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "trustStoreSnapshot.keys");
            if (!ClosedObject(trustSnapshot, "revocation", ["status", "observedAtUtc"], out var revocation))
                return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "trustStoreSnapshot.revocation.keys");

            var request = context.Request;
            if (payload["ticketRef"]?.GetValue<string>() != Ticket
                || payload["parentTicketRef"]?.GetValue<string>() != ParentTicket
                || payload["recipeId"]?.GetValue<string>() != RecipeId
                || payload["recipeRevision"]?.GetValue<int>() != RecipeRevision
                || payload["contractDBaselineCommit"]?.GetValue<string>() != ContractDBaseline)
                return Tkt000672ManifestValidation.Refuse("IDENTITY_MISMATCH", "payload.identity");
            if (payload["environment"]?.GetValue<string>() != request.Environment
                || request.Environment != Environment)
                return Tkt000672ManifestValidation.Refuse("ENVIRONMENT_MISMATCH", "payload.environment");
            if (payload["sourceId"]?.GetValue<string>() != request.SourceId)
                return Tkt000672ManifestValidation.Refuse("SOURCE_MISMATCH", "payload.sourceId");
            var expectedHashes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["snapshotHash"] = request.SnapshotHash, ["catalogHash"] = request.CatalogHash,
                ["migrationsHash"] = request.MigrationsHash, ["oracleHash"] = request.OracleHash,
                ["generationSpecHash"] = request.GenerationSpecHash
            };
            foreach (var expected in expectedHashes)
                if (evidenceHashes[expected.Key]?.GetValue<string>() != expected.Value)
                    return Tkt000672ManifestValidation.Refuse("EVIDENCE_MISMATCH", $"payload.evidenceHashes.{expected.Key}");
            foreach (var expected in new[] { ("provider", request.ProviderScope),
                         ("product", request.ProductScope), ("grant", request.GrantScope) })
                if (scopes[expected.Item1]!["opaqueId"]!.GetValue<string>() != expected.Item2)
                    return Tkt000672ManifestValidation.Refuse("SCOPE_MISMATCH", $"payload.scopes.{expected.Item1}");

            if (proof["artifactKind"]?.GetValue<string>() != "SOFTLICENCE_AUTHORITY_METADATA"
                || proof["fixtureQualificationPromotable"]?.GetValue<bool>() != false
                || proof["materializationAuthorized"]?.GetValue<bool>() != false
                || proof["nativeRecipeState"]?.GetValue<string>() != "NOT_RUN"
                || proof["nativePass"]?.GetValue<string>() != "NOT_CLAIMED"
                || proof["sourceCStates"] is not JsonArray states || states.Count != SourceCStates.Length
                || states.Select(node => node!.GetValue<string>()).Where((value, index) => value != SourceCStates[index]).Any())
                return Tkt000672ManifestValidation.Refuse("MATERIALIZATION_BOUNDARY_INVALID", "payload.proofBoundary");
            if (history["completeOneBatch"]?.GetValue<bool>() != true
                || history["samplingUsed"]?.GetValue<bool>() != false
                || history["pagingUsed"]?.GetValue<bool>() != false)
                return Tkt000672ManifestValidation.Refuse("HISTORY_INVALID", "payload.history");
            if (payload["authorityGenerations"] is not JsonArray generations
                || payload["authorityTuples"] is not JsonArray tuples
                || generations.Count > CollectionLimit || tuples.Count > CollectionLimit)
                return Tkt000672ManifestValidation.Refuse("COLLECTION_LIMIT_EXCEEDED", "payload.inventory");
            if (history["generationCount"]?.GetValue<int>() != generations.Count
                || history["tupleCount"]?.GetValue<int>() != tuples.Count
                || history["totalCardinality"]?.GetValue<int>() != tuples.Count)
                return Tkt000672ManifestValidation.Refuse("HISTORY_COUNT_MISMATCH", "payload.history");
            var generationIds = new HashSet<string>(StringComparer.Ordinal);
            var generationDigests = new HashSet<string>(StringComparer.Ordinal);
            string? previousGeneration = null;
            foreach (var node in generations)
            {
                if (node is not JsonObject generation || !Closed(generation,
                        ["generationId", "generationDigest", "providerScopeId", "productScopeId", "grantScopeId", "tupleCount"]))
                    return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.authorityGenerations.item.keys");
                var id = generation["generationId"]!.GetValue<string>();
                var digest = generation["generationDigest"]!.GetValue<string>();
                if (!generationIds.Add(id) || !generationDigests.Add(digest) || previousGeneration is not null
                    && Utf8OrdinalComparer.Instance.Compare(previousGeneration, id) >= 0)
                    return Tkt000672ManifestValidation.Refuse("INVENTORY_ORDER_INVALID", "payload.authorityGenerations");
                if (generation["providerScopeId"]!.GetValue<string>() != request.ProviderScope
                    || generation["productScopeId"]!.GetValue<string>() != request.ProductScope
                    || generation["grantScopeId"]!.GetValue<string>() != request.GrantScope)
                    return Tkt000672ManifestValidation.Refuse("SCOPE_MISMATCH", "payload.authorityGenerations.scope");
                previousGeneration = id;
            }
            var tupleIds = new HashSet<string>(StringComparer.Ordinal);
            var tupleDigests = new HashSet<string>(StringComparer.Ordinal);
            string? previousTuple = null;
            foreach (var node in tuples)
            {
                if (node is not JsonObject tuple || !Closed(tuple,
                        ["tupleId", "tupleDigest", "generationId", "providerScopeId", "productScopeId", "grantScopeId"]))
                    return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "payload.authorityTuples.item.keys");
                var id = tuple["tupleId"]!.GetValue<string>();
                var digest = tuple["tupleDigest"]!.GetValue<string>();
                if (!tupleIds.Add(id) || !tupleDigests.Add(digest) || previousTuple is not null
                    && Utf8OrdinalComparer.Instance.Compare(previousTuple, id) >= 0)
                    return Tkt000672ManifestValidation.Refuse("INVENTORY_ORDER_INVALID", "payload.authorityTuples");
                if (!generationIds.Contains(tuple["generationId"]!.GetValue<string>()))
                    return Tkt000672ManifestValidation.Refuse("GENERATION_REFERENCE_INVALID", "payload.authorityTuples.generationId");
                if (tuple["providerScopeId"]!.GetValue<string>() != request.ProviderScope
                    || tuple["productScopeId"]!.GetValue<string>() != request.ProductScope
                    || tuple["grantScopeId"]!.GetValue<string>() != request.GrantScope)
                    return Tkt000672ManifestValidation.Refuse("SCOPE_MISMATCH", "payload.authorityTuples.scope");
                previousTuple = id;
            }

            if (binding["snapshotId"]?.GetValue<string>() != context.SnapshotId
                || binding["digest"]?.GetValue<string>() != context.SnapshotDigest
                || binding["domain"]?.GetValue<string>() != context.Domain
                || binding["keyId"]?.GetValue<string>() != context.KeyId
                || binding["fingerprint"]?.GetValue<string>() != context.Fingerprint)
                return Tkt000672ManifestValidation.Refuse("TRUST_BINDING_MISMATCH", "payload.trustSnapshotBinding");
            foreach (var key in new[] { "snapshotId", "digest", "domain", "keyId", "fingerprint" })
                if (trustSnapshot[key]?.GetValue<string>() != binding[key]?.GetValue<string>())
                    return Tkt000672ManifestValidation.Refuse("TRUST_SNAPSHOT_MISMATCH", $"trustStoreSnapshot.{key}");
            if (revocation["status"]?.GetValue<string>() != "NOT_REVOKED"
                || revocation["observedAtUtc"]?.GetValue<string>() != context.ObservedAtUtc)
                return Tkt000672ManifestValidation.Refuse("TRUST_REVOKED", "trustStoreSnapshot.revocation");
            var observed = DateTimeOffset.ParseExact(context.ObservedAtUtc, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
            if (manifest["issuedAtUtc"]?.GetValue<string>() != context.ObservedAtUtc)
                return Tkt000672ManifestValidation.Refuse("MANIFEST_TIME_INVALID", "issuedAtUtc");
            var trustFrom = DateTimeOffset.ParseExact(trustSnapshot["validFromUtc"]!.GetValue<string>(),
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
            var trustUntil = DateTimeOffset.ParseExact(trustSnapshot["validUntilUtc"]!.GetValue<string>(),
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
            if (observed < trustFrom || observed > trustUntil)
                return Tkt000672ManifestValidation.Refuse("TRUST_WINDOW_INVALID", "trustStoreSnapshot.validity");

            var canonicalPayloadJson = Canonicalize(payload);
            var canonicalPayload = Frame(CanonicalPayloadDomain, canonicalPayloadJson);
            if (manifest["canonicalPayload"]?.GetValue<string>() != canonicalPayload)
                return Tkt000672ManifestValidation.Refuse("CANONICAL_PAYLOAD_MISMATCH", "canonicalPayload");
            var authorityDigest = Sha256(Frame(AuthorityDigestDomain, canonicalPayload));
            if (manifest["authorityDigest"]?.GetValue<string>() != authorityDigest)
                return Tkt000672ManifestValidation.Refuse("AUTHORITY_DIGEST_MISMATCH", "authorityDigest");
            var statement = Frame(SignedStatementDomain, ManifestSchema, authorityDigest);
            if (manifest["signedStatement"]?.GetValue<string>() != statement)
                return Tkt000672ManifestValidation.Refuse("SIGNED_STATEMENT_MISMATCH", "signedStatement");
            if (manifest["algorithm"]?.GetValue<string>() != Algorithm)
                return Tkt000672ManifestValidation.Refuse("ALGORITHM_INVALID", "algorithm");
            if (manifest["keyId"]?.GetValue<string>() != context.KeyId)
                return Tkt000672ManifestValidation.Refuse("KEY_ID_MISMATCH", "keyId");
            var signature = manifest["signature"]?.GetValue<string>() ?? string.Empty;
            if (!IsCanonicalSignature(signature))
                return Tkt000672ManifestValidation.Refuse("SIGNATURE_INVALID", "signature");
            var projection = (JsonObject)manifest.DeepClone();
            projection.Remove("signature");
            var signedBytes = Encoding.UTF8.GetBytes(Frame(CanonicalManifestDomain, Canonicalize(projection)));
            try
            {
                if (!verifier(signedBytes, signature))
                    return Tkt000672ManifestValidation.Refuse("SIGNATURE_INVALID", "signature");
            }
            catch (Exception)
            {
                return Tkt000672ManifestValidation.Refuse("SIGNATURE_INVALID", "signature");
            }
            return new(true, null, null);
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
            return Tkt000672ManifestValidation.Refuse("SCHEMA_INVALID", "manifest");
        }
    }

    /// <summary>Tests one JSON object against an exact closed enumerable key set.</summary>
    /// <param name="value">Object inspected without normalization.</param>
    /// <param name="keys">Exact required ordinal key inventory.</param>
    /// <returns>True only when no key is missing or additional.</returns>
    private static bool Closed(JsonObject value, IReadOnlyCollection<string> keys) =>
        value.Count == keys.Count && value.Select(item => item.Key).ToHashSet(StringComparer.Ordinal)
            .SetEquals(keys);

    /// <summary>Reads and validates one required closed child object.</summary>
    /// <param name="parent">Validated owning object.</param>
    /// <param name="name">Exact child property name.</param>
    /// <param name="keys">Exact required child keys.</param>
    /// <param name="value">Closed child when successful; otherwise an empty detached object.</param>
    /// <returns>True only for a present object with the exact key set.</returns>
    private static bool ClosedObject(JsonObject parent, string name, IReadOnlyCollection<string> keys,
        out JsonObject value)
    {
        value = parent[name] as JsonObject ?? [];
        return parent[name] is JsonObject && Closed(value, keys);
    }

    /// <summary>Tests every present legacy field for an exact ordinal tuple match.</summary>
    /// <param name="evidence">Nullable legacy evidence.</param>
    /// <param name="tuple">Authenticated tuple.</param>
    /// <returns>True when every present evidence value matches ordinally.</returns>
    private static bool EvidenceMatches(Tkt000672LegacyEvidence evidence, Tkt000672AttestedTuple tuple) =>
        (evidence.ProviderGrantRef is null || evidence.ProviderGrantRef == tuple.ProviderGrantRef)
        && (evidence.AuthorityDigest is null || evidence.AuthorityDigest == tuple.AuthorityDigest)
        && (evidence.SecurityEpoch is null || evidence.SecurityEpoch == tuple.SecurityEpoch)
        && (evidence.BindingId is null || evidence.BindingId == tuple.BindingId)
        && (evidence.EnrollmentId is null || evidence.EnrollmentId == tuple.EnrollmentId)
        && (evidence.KeyThumbprint is null || evidence.KeyThumbprint == tuple.KeyThumbprint)
        && (evidence.ReleaseVersion is null || evidence.ReleaseVersion == tuple.ReleaseVersion);

    /// <summary>Tests whether any present legacy field ordinally contradicts one in-scope tuple.</summary>
    /// <param name="evidence">Nullable legacy evidence.</param>
    /// <param name="tuple">Authenticated in-scope tuple.</param>
    /// <returns>True when at least one present evidence value differs ordinally.</returns>
    private static bool EvidenceContradicts(Tkt000672LegacyEvidence evidence, Tkt000672AttestedTuple tuple) =>
        evidence.ProviderGrantRef is not null && evidence.ProviderGrantRef != tuple.ProviderGrantRef
        || evidence.AuthorityDigest is not null && evidence.AuthorityDigest != tuple.AuthorityDigest
        || evidence.SecurityEpoch is not null && evidence.SecurityEpoch != tuple.SecurityEpoch
        || evidence.BindingId is not null && evidence.BindingId != tuple.BindingId
        || evidence.EnrollmentId is not null && evidence.EnrollmentId != tuple.EnrollmentId
        || evidence.KeyThumbprint is not null && evidence.KeyThumbprint != tuple.KeyThumbprint
        || evidence.ReleaseVersion is not null && evidence.ReleaseVersion != tuple.ReleaseVersion;

    /// <summary>Tests one exact bounded opaque identifier using UTF-8 bytes, not UTF-16 units.</summary>
    internal static bool IsIdentifier(string value) => IsWellFormed(value) && value.Length > 0
        && Encoding.UTF8.GetByteCount(value) <= IdentifierUtf8Limit
        && !value.Any(character => character is <= '\u001f' or '\u007f');

    /// <summary>Tests the exact lowercase SHA-256 textual representation.</summary>
    internal static bool IsHash(string value) => value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>Validates canonical non-padded base64url signature text against independent text and byte limits.</summary>
    /// <param name="value">Exact signature text; no trimming or alphabet repair is performed.</param>
    /// <returns><see langword="true"/> only for non-empty canonical text decoding to at most 768 bytes.</returns>
    internal static bool IsCanonicalSignature(string value)
    {
        if (!IsWellFormed(value) || value.Length is 0 or > SignatureUtf8Limit
            || value.Any(character => character is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z'
                or >= '0' and <= '9' or '-' or '_'))
            || value.Length % 4 == 1)
            return false;
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            var decoded = Convert.FromBase64String(padded);
            return decoded.Length is > 0 and <= SignatureBytesLimit
                && string.Equals(Base64Url(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Encodes bytes using the canonical non-padded base64url alphabet.</summary>
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Tests exact millisecond UTC text with round-trip calendar validation.</summary>
    internal static bool IsUtc(string value) => DateTimeOffset.TryParseExact(value,
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
        && parsed.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) == value;

    /// <summary>Builds one exact scope value and its independently domain-separated digest.</summary>
    private static JsonObject Scope(string exact, string kind, string? authenticatedDigest = null) => new()
    {
        ["opaqueId"] = exact,
        ["digest"] = authenticatedDigest ?? PublicDigest($"{kind}-scope", exact)
    };

    /// <summary>Rejects duplicate identifiers, duplicate digests, and non-increasing UTF-8 order.</summary>
    private static void EnsureUniqueOrdered(JsonObject[] items, string idKey, string digestKey)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var digests = new HashSet<string>(StringComparer.Ordinal);
        string? previous = null;
        foreach (var item in items)
        {
            var id = item[idKey]!.GetValue<string>();
            var digest = item[digestKey]!.GetValue<string>();
            if (!ids.Add(id) || !digests.Add(digest) || previous is not null
                && Utf8OrdinalComparer.Instance.Compare(previous, id) >= 0)
                throw new InvalidOperationException("INVENTORY_INVALID");
            previous = id;
        }
    }

    /// <summary>Rejects ill-formed text or a field exceeding its independent UTF-8 byte budget.</summary>
    private static void BoundUtf8(string value, int limit, string field)
    {
        if (!IsWellFormed(value) || Encoding.UTF8.GetByteCount(value) > limit)
            throw new InvalidOperationException("BYTE_LIMIT_EXCEEDED:" + field);
    }

    /// <summary>Rejects unpaired UTF-16 surrogates without repairing the input.</summary>
    private static bool IsWellFormed(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (!char.IsSurrogate(value[index])) continue;
            if (!char.IsHighSurrogate(value[index]) || index + 1 >= value.Length
                || !char.IsLowSurrogate(value[++index])) return false;
        }
        return true;
    }

    /// <summary>Writes one owned data-only JSON tree with UTF-8 ordinal object-key order.</summary>
    private static void WriteNode(Utf8JsonWriter writer, JsonNode? node)
    {
        switch (node)
        {
            case null: writer.WriteNullValue(); return;
            case JsonObject record:
                writer.WriteStartObject();
                foreach (var property in record.OrderBy(item => item.Key, Utf8OrdinalComparer.Instance))
                {
                    writer.WritePropertyName(property.Key);
                    WriteNode(writer, property.Value);
                }
                writer.WriteEndObject(); return;
            case JsonArray array:
                writer.WriteStartArray();
                foreach (var item in array) WriteNode(writer, item);
                writer.WriteEndArray(); return;
            default:
                node.WriteTo(writer); return;
        }
    }
}

/// <summary>Compares exact strings by unsigned UTF-8 bytes without locale or normalization.</summary>
internal sealed class Utf8OrdinalComparer : IComparer<string>
{
    /// <summary>Gets the stateless exact UTF-8 ordinal comparer shared by canonical ordering checks.</summary>
    internal static Utf8OrdinalComparer Instance { get; } = new();

    /// <inheritdoc />
    public int Compare(string? left, string? right)
    {
        if (ReferenceEquals(left, right)) return 0;
        if (left is null) return -1;
        if (right is null) return 1;
        return Encoding.UTF8.GetBytes(left).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(right));
    }
}

/// <summary>Owns distinct ephemeral RSA authorities for manifest signing and trust-snapshot attestation.</summary>
internal sealed class Tkt000672ManifestSigner : IDisposable
{
    private readonly RSA? manifestKey;
    private readonly RSA? trustAuthorityKey;
    private readonly byte[]? expectedSignedBytes;
    private readonly string? fixedSignature;
    private bool disposed;

    /// <summary>Captures distinct manifest and trust key owners and derives public trust metadata.</summary>
    internal Tkt000672ManifestSigner(RSA manifestKey, RSA trustAuthorityKey, string keyId)
    {
        this.manifestKey = manifestKey ?? throw new ArgumentNullException(nameof(manifestKey));
        this.trustAuthorityKey = trustAuthorityKey ?? throw new ArgumentNullException(nameof(trustAuthorityKey));
        if (ReferenceEquals(manifestKey, trustAuthorityKey)) throw new ArgumentException("Distinct key owners are required.");
        if (!Tkt000672SourceCAuthorityContract.IsIdentifier(keyId)) throw new ArgumentException("Invalid key identifier.");
        KeyId = keyId;
        Fingerprint = Convert.ToHexStringLower(SHA256.HashData(manifestKey.ExportSubjectPublicKeyInfo()));
        var snapshotDigest = Convert.ToHexStringLower(SHA256.HashData(trustAuthorityKey.ExportSubjectPublicKeyInfo()));
        Binding = new JsonObject
        {
            ["snapshotId"] = "trust_" + snapshotDigest[..32], ["digest"] = snapshotDigest,
            ["domain"] = Tkt000672SourceCAuthorityContract.TrustDomain,
            ["keyId"] = KeyId, ["fingerprint"] = Fingerprint
        };
        TrustSnapshot = new JsonObject();
    }

    /// <summary>Creates a deterministic metadata-only golden signer that never owns private key material.</summary>
    /// <param name="binding">Independent fixture trust binding copied into the payload.</param>
    /// <param name="expectedSignedBytes">Exact independently pinned domain-separated bytes.</param>
    /// <param name="signature">Exact canonical fixture signature text.</param>
    /// <param name="validFromUtc">Independently pinned strict UTC validity start.</param>
    /// <param name="validUntilUtc">Independently pinned strict UTC validity end.</param>
    /// <returns>A signer spy that rejects any byte drift and verifies the exact fixture signature.</returns>
    internal static Tkt000672ManifestSigner CreateGolden(
        JsonObject binding, byte[] expectedSignedBytes, string signature,
        string validFromUtc, string validUntilUtc) =>
        new(binding, expectedSignedBytes, signature, validFromUtc, validUntilUtc);

    /// <summary>Captures only public golden artifacts for deterministic producer comparison.</summary>
    private Tkt000672ManifestSigner(JsonObject binding, byte[] expectedSignedBytes, string signature,
        string validFromUtc, string validUntilUtc)
    {
        Binding = (JsonObject)binding.DeepClone();
        KeyId = Binding["keyId"]!.GetValue<string>();
        Fingerprint = Binding["fingerprint"]!.GetValue<string>();
        this.expectedSignedBytes = expectedSignedBytes.ToArray();
        fixedSignature = signature;
        PinnedValidFromUtc = validFromUtc;
        PinnedValidUntilUtc = validUntilUtc;
        TrustSnapshot = new JsonObject();
    }

    /// <summary>Gets the exact bounded manifest signing key identifier.</summary>
    internal string KeyId { get; }
    /// <summary>Gets the lowercase SHA-256 fingerprint of the manifest signing SPKI.</summary>
    internal string Fingerprint { get; }
    /// <summary>Gets the closed five-field trust binding copied into the authenticated payload.</summary>
    internal JsonObject Binding { get; }
    /// <summary>Gets the closed injected-context trust snapshot with validity and revocation evidence.</summary>
    internal JsonObject TrustSnapshot { get; private set; }
    /// <summary>Gets the independently pinned golden validity start, or null for real production-path derivation.</summary>
    internal string? PinnedValidFromUtc { get; }
    /// <summary>Gets the independently pinned golden validity end, or null for real production-path derivation.</summary>
    internal string? PinnedValidUntilUtc { get; }

    /// <summary>Completes the exact trust validity and non-revocation evidence for one observed instant.</summary>
    internal void SetWindow(string validFromUtc, string validUntilUtc, string observedAtUtc)
    {
        var body = (JsonObject)Binding.DeepClone();
        body["validFromUtc"] = validFromUtc;
        body["validUntilUtc"] = validUntilUtc;
        body["revocation"] = new JsonObject { ["status"] = "NOT_REVOKED", ["observedAtUtc"] = observedAtUtc };
        TrustSnapshot = body;
    }

    /// <summary>Signs exact domain-framed bytes once with RSASSA-PSS SHA-256 and returns canonical base64url.</summary>
    internal string Sign(ReadOnlySpan<byte> signedBytes)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (fixedSignature is not null)
        {
            if (!signedBytes.SequenceEqual(expectedSignedBytes))
                throw new InvalidOperationException("GOLDEN_SIGNED_BYTES_MISMATCH");
            return fixedSignature;
        }
        var signature = manifestKey!.SignData(signedBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (signature.Length is 0 or > Tkt000672SourceCAuthorityContract.SignatureBytesLimit)
            throw new InvalidOperationException("SIGNATURE_LIMIT_EXCEEDED");
        return Base64Url(signature);
    }

    /// <summary>Verifies a canonical signature against the same ephemeral PS256 key for harness assurance.</summary>
    internal bool Verify(ReadOnlySpan<byte> signedBytes, string signature) => fixedSignature is not null
        ? signedBytes.SequenceEqual(expectedSignedBytes) && string.Equals(signature, fixedSignature, StringComparison.Ordinal)
        : manifestKey!.VerifyData(signedBytes, DecodeBase64Url(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    /// <summary>Disposes both private key owners exactly once.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        manifestKey?.Dispose();
        trustAuthorityKey?.Dispose();
        if (expectedSignedBytes is not null) CryptographicOperations.ZeroMemory(expectedSignedBytes);
    }

    /// <summary>Encodes bytes with the non-padded canonical base64url alphabet.</summary>
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Decodes a producer-owned canonical base64url value for local verification only.</summary>
    private static byte[] DecodeBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}

/// <summary>Names one exact predefined scenario and its independently expected persisted classification.</summary>
/// <param name="ScenarioId">Closed scenario dispatcher identity.</param>
/// <param name="Order">Zero-based canonical execution order.</param>
/// <param name="Classification">Expected authoritative Contract C classification.</param>
/// <param name="Reason">Expected authoritative Contract C reason.</param>
internal sealed record Tkt000672Scenario(string ScenarioId, int Order, string Classification, string Reason);

/// <summary>Exact nullable v1 evidence compared against authenticated v2 tuples.</summary>
internal sealed record Tkt000672LegacyEvidence(
    string LegacySourceId, string? ProviderGrantRef, string? AuthorityDigest, int? SecurityEpoch,
    string? BindingId, string? EnrollmentId, string? KeyThumbprint, string? ReleaseVersion);

/// <summary>Injected authenticated scope because legacy evidence does not own provider/product authority.</summary>
internal sealed record Tkt000672LegacyScope(
    string? Authority, string? Provider, string? ProductId, string? ProviderGrantRef);

/// <summary>Authenticated persisted v2 tuple projected without changing exact strings.</summary>
internal sealed record Tkt000672AttestedTuple(
    string AuthorityLineageId, string AuthorityGenerationId, string Provider, string ProductId,
    string ProviderGrantRef, string AuthorityDigest, int SecurityEpoch, string BindingId,
    string EnrollmentId, string KeyThumbprint, string ReleaseVersion);

/// <summary>Closed Contract C classification and reason.</summary>
internal sealed record Tkt000672LegacyClassification(string Classification, string Reason);

/// <summary>Injected request and public trust authority used by the complete manifest validator.</summary>
internal sealed record Tkt000672ManifestValidationContext(
    Tkt000672SourceCRequest Request, string SnapshotId, string SnapshotDigest, string Domain,
    string KeyId, string Fingerprint, string ObservedAtUtc);

/// <summary>Stable complete-manifest validation result without rejected-value echo.</summary>
internal sealed record Tkt000672ManifestValidation(bool Ok, string? Reason, string? Field)
{
    /// <summary>Creates one stable closed refusal.</summary>
    internal static Tkt000672ManifestValidation Refuse(string reason, string field) =>
        new(false, reason, field);
}

/// <summary>Closed exact request accepted only by the test-only controller.</summary>
internal sealed record Tkt000672SourceCRequest(
    string Schema, string RunId, string Environment, string SourceId, string ObservedAtUtc,
    string SnapshotHash, string CatalogHash, string MigrationsHash, string OracleHash,
    string GenerationSpecHash, string ProviderScope, string ProductScope, string GrantScope);

/// <summary>Stable request-validation result that never echoes rejected data.</summary>
internal sealed record Tkt000672RequestValidation(
    bool Ok, Tkt000672SourceCRequest? Request, string? Reason, string? Field)
{
    /// <summary>Creates one stable parser refusal without retaining or echoing hostile input.</summary>
    /// <param name="reason">Closed parser refusal reason.</param>
    /// <param name="field">Stable public field category.</param>
    /// <returns>A failed validation containing no parsed request.</returns>
    internal static Tkt000672RequestValidation Refuse(string reason, string field) => new(false, null, reason, field);
}

/// <summary>Opaque owned request identities returned after one real v2 scenario execution.</summary>
/// <param name="ScenarioId">Exact closed scenario identity.</param>
/// <param name="RequestIds">One or two owned request IDs; no classification is accepted from the executor.</param>
internal sealed record Tkt000672ScenarioExecution(string ScenarioId, IReadOnlyList<Guid> RequestIds);

/// <summary>Closed classification derived only from bounded persisted request, generation, and attempt evidence.</summary>
internal sealed record Tkt000672ScenarioEvidence(
    [property: JsonPropertyName("scenarioId")] string ScenarioId,
    [property: JsonPropertyName("classification")] string Classification,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("requestCount")] int RequestCount,
    [property: JsonPropertyName("generationCount")] int GenerationCount,
    [property: JsonPropertyName("attemptCount")] int AttemptCount);

/// <summary>Bounded, already public opaque metadata derived from one real v2 authority generation.</summary>
internal sealed record Tkt000672GenerationObservation(
    string ScenarioId, string Classification, string RequestId, string RequestDigest,
    string GenerationId, string GenerationDigest, string? ProviderScopeDigest = null,
    string? ProductScopeDigest = null, string? GrantScopeDigest = null);

/// <summary>Signed manifest and its exact canonical derivation artifacts.</summary>
internal sealed record Tkt000672BuiltManifest(
    JsonObject Manifest, JsonObject TrustStoreSnapshot, string CanonicalPayloadJson,
    string CanonicalPayload, string AuthorityDigest, string SignedStatement,
    string SigningProjectionCanonical, byte[] SignedBytes, string CanonicalManifest);

/// <summary>Closed successful response returned by the test-only endpoint.</summary>
internal sealed class Tkt000672SourceCResponse
{
    /// <summary>Gets the closed producer response schema.</summary>
    [JsonPropertyName("schema")] public string Schema { get; init; } = Tkt000672SourceCAuthorityContract.ResponseSchema;
    /// <summary>Gets the exact opaque caller run ID.</summary>
    [JsonPropertyName("runId")] public required string RunId { get; init; }
    /// <summary>Gets the derived number of dispatched scenarios.</summary>
    [JsonPropertyName("scenarioCount")] public required int ScenarioCount { get; init; }
    /// <summary>Gets the four classifications in canonical scenario order.</summary>
    [JsonPropertyName("classifications")] public required IReadOnlyList<string> Classifications { get; init; }
    /// <summary>Gets exact non-sensitive reasons and persisted cardinalities behind every derived classification.</summary>
    [JsonPropertyName("classificationEvidence")]
    public required IReadOnlyList<Tkt000672ScenarioEvidence> ClassificationEvidence { get; init; }
    /// <summary>Gets the signed metadata-only authority manifest.</summary>
    [JsonPropertyName("manifest")] public required JsonObject Manifest { get; init; }
    /// <summary>Gets the closed public trust-store snapshot required by the injected Website context.</summary>
    [JsonPropertyName("trustStoreSnapshot")] public required JsonObject TrustStoreSnapshot { get; init; }
}
