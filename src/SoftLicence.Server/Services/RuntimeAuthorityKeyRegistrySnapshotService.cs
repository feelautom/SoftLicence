using System.Buffers;
using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Names the bounded service that publishes the authenticated public Runtime authority key registry.</summary>
public interface IRuntimeAuthorityKeyRegistrySnapshotService
{
    /// <summary>
    /// Returns a caller-owned copy of the exact current public snapshot after serializable PostgreSQL
    /// locking, provider-source authentication, durable semantic replay, and fixed-time body validation.
    /// </summary>
    /// <param name="clientId">Exact authenticated S2S client namespace; it is compared ordinally.</param>
    /// <param name="exactRequestBody">Exact canonical request bytes used as the semantic replay digest source.</param>
    /// <param name="cancellationToken">Caller cancellation, which always takes priority over provider failures.</param>
    /// <returns>A new byte array containing the frozen public response body.</returns>
    /// <exception cref="RuntimeAuthorityKeyRegistryContractException">The request diverges or the provider state is unavailable.</exception>
    /// <exception cref="OperationCanceledException">The caller cancels before the locked readback completes.</exception>
    Task<byte[]> ReadCurrentAsync(string clientId, ReadOnlyMemory<byte> exactRequestBody, CancellationToken cancellationToken);
}

/// <summary>Represents one closed public key-registry failure without exposing internal configuration details.</summary>
/// <param name="errorCode">Closed public protocol error.</param>
/// <param name="statusCode">Matching HTTP status.</param>
internal sealed class RuntimeAuthorityKeyRegistryContractException(string errorCode, int statusCode) : Exception(errorCode)
{
    /// <summary>Gets the closed public error code.</summary>
    internal string ErrorCode { get; } = errorCode;
    /// <summary>Gets the closed HTTP status.</summary>
    internal int StatusCode { get; } = statusCode;
}

/// <summary>Owns exact request parsing and public-only snapshot serialization without string normalization.</summary>
internal static class RuntimeAuthorityKeyRegistryContract
{
    /// <summary>Exact provider-owned namespace for the generation-v2 public key registry.</summary>
    internal const string RegistryId = "runtime-enrollment-authority-generation-v2";
    /// <summary>Maximum frozen response length allowed by the public contract.</summary>
    internal const int MaximumResponseBytes = 16384;
    /// <summary>BOM-free decoder that rejects malformed UTF-8.</summary>
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Contains one validated canonical readback request and its exact-body digest.</summary>
    /// <param name="RequestId">Semantic request identity inside the authenticated client namespace.</param>
    /// <param name="ProductId">Exact S2S product scope.</param>
    /// <param name="RequestDigestSha256">Lowercase SHA-256 of the exact canonical request bytes.</param>
    internal sealed record Request(Guid RequestId, Guid ProductId, string RequestDigestSha256);

    /// <summary>Contains one authenticated immutable public snapshot ready for relational persistence.</summary>
    /// <param name="SnapshotId">Provider-owned unique snapshot identity.</param>
    /// <param name="SnapshotVersion">Positive globally monotone snapshot version.</param>
    /// <param name="ObservedAtUtc">Authenticated UTC observation.</param>
    /// <param name="MetadataDigestSha256">Digest of the exact metadata encoding.</param>
    /// <param name="RegistryAuthenticationInputDigestSha256">Digest of the registry authentication input.</param>
    /// <param name="SignatureBase64Url">Canonical registry-authority PS256 signature.</param>
    /// <param name="ExactResponseBody">Frozen public response bytes.</param>
    /// <param name="ExactResponseBodySha256">Digest of the frozen response bytes.</param>
    internal sealed record Snapshot(
        string SnapshotId,
        long SnapshotVersion,
        string ObservedAtUtc,
        string MetadataDigestSha256,
        string RegistryAuthenticationInputDigestSha256,
        string SignatureBase64Url,
        byte[] ExactResponseBody,
        string ExactResponseBodySha256);

    /// <summary>Parses only the exact four-member canonical request and never repairs an alias.</summary>
    internal static Request ParseRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8 is { Length: < 1 or > 4096 } || utf8.StartsWith(Encoding.UTF8.Preamble))
            throw Integrity();
        try
        {
            _ = StrictUtf8.GetString(utf8);
            using var document = JsonDocument.Parse(utf8.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw Integrity();
            var properties = root.EnumerateObject().ToArray();
            if (properties.Length != 4
                || properties[0].Name != "schema" || properties[0].Value.ValueKind != JsonValueKind.String
                || properties[0].Value.GetString() != "runtime-enrollment-authority-key-registry-readback-v1"
                || properties[1].Name != "contractVersion" || properties[1].Value.ValueKind != JsonValueKind.Number
                || !properties[1].Value.TryGetInt32(out var version) || version != 1 || properties[1].Value.GetRawText() != "1"
                || properties[2].Name != "requestId" || properties[2].Value.ValueKind != JsonValueKind.String
                || properties[3].Name != "productId" || properties[3].Value.ValueKind != JsonValueKind.String
                || !TryCanonicalUuid(properties[2].Value.GetString(), out var requestId)
                || !TryCanonicalUuid(properties[3].Value.GetString(), out var productId))
                throw Integrity();
            var canonical = Encoding.UTF8.GetBytes(
                $"{{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"{requestId:D}\",\"productId\":\"{productId:D}\"}}");
            if (!utf8.SequenceEqual(canonical))
                throw Integrity();
            return new(requestId, productId, Digest(utf8));
        }
        catch (RuntimeAuthorityKeyRegistryContractException) { throw; }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or FormatException)
        { throw Integrity(); }
    }

    /// <summary>Authenticates provider-owned configuration at PostgreSQL time and writes only public material.</summary>
    internal static Snapshot BuildSnapshot(RuntimeEnrollmentOptions options, DateTimeOffset decisionNowUtc)
    {
        try
        {
            if (options.AuthorityGenerationSigning is null
                || !DateTimeOffset.TryParseExact(options.AuthorityGenerationV2.RegistryObservedAtUtc, "O",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var observed)
                || observed.Offset != TimeSpan.Zero)
                throw Unavailable();
            var authoritySpki = Convert.FromBase64String(options.AuthorityGenerationV2.RegistryAuthoritySpkiBase64);
            var cryptography = new RuntimeEnrollmentAuthorityCryptography(
                new FixedTimeProvider(decisionNowUtc), authoritySpki);
            var evidence = cryptography.AuthenticateRegistrySnapshot(
                options.AuthorityGenerationSigning, observed,
                options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url);
            if (evidence.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None)
                throw Unavailable();
            var authenticationInput = cryptography.GetRegistrySnapshotAuthenticationInput(
                options.AuthorityGenerationSigning, observed);
            if (authenticationInput.Error != RuntimeEnrollmentAuthorityCryptography.Failure.None
                || authenticationInput.Value is not { Length: >= 32 } exactInput)
                throw Unavailable();

            var metadataDigest = Convert.ToHexStringLower(exactInput.AsSpan(exactInput.Length - 32));
            var authenticationDigest = Digest(exactInput);
            var response = WriteResponse(
                options.AuthorityGenerationSigning, observed, metadataDigest, authenticationDigest,
                options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url);
            if (response.Length is < 1 or > MaximumResponseBytes)
                throw Unavailable();
            var observedText = observed.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
            if (!string.Equals(options.AuthorityGenerationV2.RegistryObservedAtUtc, observedText, StringComparison.Ordinal))
                throw Unavailable();
            return new(
                options.AuthorityGenerationSigning.RegistrySnapshotId,
                options.AuthorityGenerationSigning.RegistrySnapshotVersion,
                observedText,
                metadataDigest,
                authenticationDigest,
                options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url,
                response,
                Digest(response));
        }
        catch (RuntimeAuthorityKeyRegistryContractException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException or FormatException)
        { throw Unavailable(); }
    }

    /// <summary>Recomputes and fixed-time compares the stored response digest before any success bytes are returned.</summary>
    internal static bool HasExactBodyDigest(ReadOnlySpan<byte> body, string firstDigest, string secondDigest)
    {
        if (body is { Length: < 1 or > MaximumResponseBytes }
            || !TryDigest(firstDigest, out var first) || !TryDigest(secondDigest, out var second))
            return false;
        var actual = SHA256.HashData(body);
        return CryptographicOperations.FixedTimeEquals(actual, first)
            && CryptographicOperations.FixedTimeEquals(actual, second);
    }

    /// <summary>Requires the lossless stored observation text to equal the exact public body member.</summary>
    internal static bool HasExactObservedAtUtc(ReadOnlySpan<byte> body, string observedAtUtc)
    {
        if (!DateTimeOffset.TryParseExact(observedAtUtc, "O", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var observed)
            || observed.Offset != TimeSpan.Zero
            || !string.Equals(observedAtUtc, observed.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
            return false;
        try
        {
            using var document = JsonDocument.Parse(body.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return false;
            var matches = document.RootElement.EnumerateObject()
                .Where(property => property.NameEquals("observedAtUtc"))
                .ToArray();
            return matches.Length == 1
                && matches[0].Value.ValueKind == JsonValueKind.String
                && string.Equals(matches[0].Value.GetString(), observedAtUtc, StringComparison.Ordinal);
        }
        catch (JsonException) { return false; }
    }

    /// <summary>Writes the closed public JSON member order from authenticated provider metadata.</summary>
    private static byte[] WriteResponse(
        RuntimeAuthorityGenerationSigningOptions options,
        DateTimeOffset observed,
        string metadataDigest,
        string authenticationDigest,
        string signature)
    {
        var output = new ArrayBufferWriter<byte>();
        Raw(output, "{\"schema\":\"runtime-enrollment-authority-key-registry-snapshot-v1\",\"contractVersion\":1,\"registrySnapshotId\":"u8);
        String(output, options.RegistrySnapshotId);
        Raw(output, ",\"registrySnapshotVersion\":"u8);
        Raw(output, Encoding.ASCII.GetBytes(options.RegistrySnapshotVersion.ToString(CultureInfo.InvariantCulture)));
        Raw(output, ",\"observedAtUtc\":"u8); String(output, observed.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Raw(output, ",\"metadataDigestSha256\":"u8); String(output, metadataDigest);
        Raw(output, ",\"registryAuthenticationInputDigestSha256\":"u8); String(output, authenticationDigest);
        Raw(output, ",\"keys\":["u8);
        for (var index = 0; index < options.Keys.Count; index++)
        {
            if (index != 0) Raw(output, ","u8);
            var key = options.Keys[index];
            var revocationCode = key.Status switch
            {
                "active" or "retired" when key.RevocationReason is null => null,
                "revoked" when key.RevocationReason is "compromised" or "operator_revoked" or "policy_revoked" or "material_invalid" => key.RevocationReason,
                _ => throw Unavailable()
            };
            using var rsa = RSA.Create(); rsa.ImportFromPem(key.PublicKeyPem);
            var spki = rsa.ExportSubjectPublicKeyInfo();
            Raw(output, "{\"keyId\":"u8); String(output, key.KeyId);
            Raw(output, ",\"spkiDerBase64\":"u8); String(output, Convert.ToBase64String(spki));
            Raw(output, ",\"spkiSha256\":"u8); String(output, Digest(spki));
            Raw(output, ",\"purpose\":"u8); String(output, key.Purpose);
            Raw(output, ",\"domain\":"u8); String(output, key.Domain);
            Raw(output, ",\"contractVersion\":"u8); Raw(output, Encoding.ASCII.GetBytes(key.ContractVersion.ToString(CultureInfo.InvariantCulture)));
            Raw(output, ",\"status\":"u8); String(output, key.Status);
            Raw(output, ",\"validFromUtc\":"u8); String(output, key.ActivatedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            Raw(output, ",\"retiredAtUtc\":"u8); NullableString(output, key.RetiredAtUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            Raw(output, ",\"revokedAtUtc\":"u8); NullableString(output, key.RevokedAtUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            Raw(output, ",\"revocationCode\":"u8); NullableString(output, revocationCode);
            Raw(output, ",\"compromiseFromUtc\":"u8); NullableString(output, key.CompromiseFromUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            Raw(output, "}"u8);
        }
        Raw(output, "],\"signature\":{\"algorithm\":\"PS256\",\"value\":"u8);
        String(output, signature); Raw(output, "}}"u8);
        return output.WrittenSpan.ToArray();
    }

    /// <summary>Writes one string with the exact contract escape table and no Unicode normalization.</summary>
    private static void String(ArrayBufferWriter<byte> output, string value)
    {
        Raw(output, "\""u8); Span<byte> encoded = stackalloc byte[4];
        foreach (var rune in value.EnumerateRunes())
        {
            ReadOnlySpan<byte> escape = rune.Value switch
            {
                0x22 => "\\\""u8, 0x5c => "\\\\"u8, 0x08 => "\\b"u8, 0x09 => "\\t"u8,
                0x0a => "\\n"u8, 0x0c => "\\f"u8, 0x0d => "\\r"u8, _ => []
            };
            if (!escape.IsEmpty) { Raw(output, escape); continue; }
            if (rune.Value < 0x20 || rune.Value is 0x85 or 0x2028 or 0x2029)
            { Raw(output, Encoding.ASCII.GetBytes($"\\u{rune.Value:x4}")); continue; }
            output.Write(encoded[..rune.EncodeToUtf8(encoded)]);
        }
        Raw(output, "\""u8);
    }

    /// <summary>Writes either an explicit JSON null or one exact canonical string.</summary>
    private static void NullableString(ArrayBufferWriter<byte> output, string? value)
    { if (value is null) Raw(output, "null"u8); else String(output, value); }
    /// <summary>Appends exact bytes to the current canonical output.</summary>
    private static void Raw(ArrayBufferWriter<byte> output, ReadOnlySpan<byte> bytes) => output.Write(bytes);
    /// <summary>Returns lowercase SHA-256 text for exact bytes.</summary>
    private static string Digest(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    /// <summary>Decodes only canonical lowercase 64-hex SHA-256 text.</summary>
    private static bool TryDigest(string value, out byte[] bytes)
    {
        bytes = [];
        if (value.Length != 64 || value.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            return false;
        try { bytes = Convert.FromHexString(value); return bytes.Length == 32; }
        catch (FormatException) { return false; }
    }
    /// <summary>Accepts only lowercase canonical UUID-D text without repair.</summary>
    private static bool TryCanonicalUuid(string? value, out Guid parsed) =>
        Guid.TryParseExact(value, "D", out parsed) && value == parsed.ToString("D");
    /// <summary>Creates the sole malformed-contract public failure.</summary>
    private static RuntimeAuthorityKeyRegistryContractException Integrity() =>
        new("RUNTIME_ENROLLMENT_INTEGRITY_FAILURE", StatusCodes.Status400BadRequest);
    /// <summary>Creates the uniform provider-unavailable public failure.</summary>
    private static RuntimeAuthorityKeyRegistryContractException Unavailable() =>
        new("RUNTIME_ENROLLMENT_TEMPORARILY_UNAVAILABLE", StatusCodes.Status503ServiceUnavailable);

    /// <summary>Supplies the PostgreSQL decision instant to existing registry cryptography.</summary>
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow() => now;
    }
}

/// <summary>Publishes and replays the dedicated current public snapshot under PostgreSQL locks.</summary>
/// <param name="contextFactory">Factory for one isolated transaction context per attempt.</param>
/// <param name="options">Validated provider-owned Runtime Enrollment configuration.</param>
internal sealed class RuntimeAuthorityKeyRegistrySnapshotService(
    IDbContextFactory<LicenseDbContext> contextFactory,
    IOptions<RuntimeEnrollmentOptions> options) : IRuntimeAuthorityKeyRegistrySnapshotService
{
    /// <summary>Startup-validated provider configuration retained without normalization.</summary>
    private readonly RuntimeEnrollmentOptions configured = options.Value;

    /// <inheritdoc />
    public async Task<byte[]> ReadCurrentAsync(
        string clientId, ReadOnlyMemory<byte> exactRequestBody, CancellationToken cancellationToken)
    {
        var request = RuntimeAuthorityKeyRegistryContract.ParseRequest(exactRequestBody.Span);
        if (clientId is not { Length: >= 1 and <= 64 })
            throw Unavailable();
        var attempts = Math.Clamp(configured.MaximumTransactionAttempts, 1, 3);
        for (var attempt = 1; ; attempt++)
        {
            try { return await ReadOnceAsync(clientId, request, cancellationToken); }
            catch (Exception exception)
            {
                var classification = ClassifyDatabaseFailure(exception, cancellationToken);
                if (classification == DatabaseFailureClassification.CallerCancellation)
                    throw new OperationCanceledException(cancellationToken);
                if (classification is DatabaseFailureClassification.RetryTransaction
                    or DatabaseFailureClassification.RereadExpectedReadbackRace
                    && attempt < attempts)
                    continue;
                if (classification is not DatabaseFailureClassification.NotDatabaseFailure)
                    throw Unavailable();
                throw;
            }
        }
    }

    /// <summary>Runs one serializable locked publication/readback attempt.</summary>
    private async Task<byte[]> ReadOnceAsync(
        string clientId, RuntimeAuthorityKeyRegistryContract.Request request,
        CancellationToken cancellationToken)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            "SELECT set_config('lock_timeout', {0}, true), set_config('statement_timeout', {1}, true)",
            [
                $"{Math.Clamp(configured.LockTimeoutMilliseconds, 1, 60_000).ToString(CultureInfo.InvariantCulture)}ms",
                $"{Math.Clamp(configured.StatementTimeoutMilliseconds, 1, 60_000).ToString(CultureInfo.InvariantCulture)}ms"
            ], cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            "SELECT pg_advisory_xact_lock(hashtextextended({0}, 0))",
            [RuntimeAuthorityKeyRegistryContract.RegistryId], cancellationToken);

        var head = await db.RuntimeAuthorityKeyRegistryHeads
            .FromSqlInterpolated($"SELECT * FROM \"RuntimeAuthorityKeyRegistryHeads\" WHERE \"RegistryId\" = {RuntimeAuthorityKeyRegistryContract.RegistryId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var decisionNow = await DatabaseNowAsync(db, cancellationToken);
        var source = RuntimeAuthorityKeyRegistryContract.BuildSnapshot(configured, new DateTimeOffset(decisionNow));

        RuntimeAuthorityKeyRegistrySnapshot snapshot;
        if (head is null)
        {
            if (await db.RuntimeAuthorityKeyRegistrySnapshots.AnyAsync(
                    item => item.RegistryId == RuntimeAuthorityKeyRegistryContract.RegistryId, cancellationToken))
                throw Unavailable();
            snapshot = new()
            {
                SnapshotId = source.SnapshotId,
                RegistryId = RuntimeAuthorityKeyRegistryContract.RegistryId,
                SnapshotVersion = source.SnapshotVersion,
                MetadataDigestSha256 = source.MetadataDigestSha256,
                RegistryAuthenticationInputDigestSha256 = source.RegistryAuthenticationInputDigestSha256,
                ObservedAtUtc = source.ObservedAtUtc,
                PublicationState = "current",
                ExactResponseBody = [.. source.ExactResponseBody],
                ExactResponseBodySha256 = source.ExactResponseBodySha256,
                RegistrySignatureBase64Url = source.SignatureBase64Url,
                CreatedAtUtc = decisionNow
            };
            head = new()
            {
                RegistryId = RuntimeAuthorityKeyRegistryContract.RegistryId,
                CurrentSnapshotId = source.SnapshotId,
                CurrentSnapshotVersion = source.SnapshotVersion,
                CurrentMetadataDigestSha256 = source.MetadataDigestSha256,
                CurrentRegistryAuthenticationInputDigestSha256 = source.RegistryAuthenticationInputDigestSha256,
                CurrentPublicationState = "current",
                UpdatedAtUtc = decisionNow
            };
            db.RuntimeAuthorityKeyRegistrySnapshots.Add(snapshot);
            db.RuntimeAuthorityKeyRegistryHeads.Add(head);
        }
        else
        {
            snapshot = await db.RuntimeAuthorityKeyRegistrySnapshots.SingleOrDefaultAsync(item =>
                item.RegistryId == head.RegistryId
                && item.SnapshotId == head.CurrentSnapshotId
                && item.SnapshotVersion == head.CurrentSnapshotVersion
                && item.MetadataDigestSha256 == head.CurrentMetadataDigestSha256
                && item.RegistryAuthenticationInputDigestSha256 == head.CurrentRegistryAuthenticationInputDigestSha256
                && item.PublicationState == head.CurrentPublicationState, cancellationToken) ?? throw Unavailable();
            if (!IsInternallyConsistentCurrent(head, snapshot))
                throw Unavailable();
            if (!Matches(source, head, snapshot))
                snapshot = await PromoteAsync(
                    db, head, snapshot, source, decisionNow, cancellationToken);
        }

        var readback = await db.RuntimeAuthorityKeyRegistryReadbacks
            .FromSqlInterpolated($"SELECT * FROM \"RuntimeAuthorityKeyRegistryReadbacks\" WHERE \"ClientId\" = {clientId} AND \"RequestId\" = {request.RequestId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (readback is not null)
        {
            if (!string.Equals(readback.RequestDigestSha256, request.RequestDigestSha256, StringComparison.Ordinal))
                throw Conflict();
            if (!string.Equals(readback.SnapshotId, snapshot.SnapshotId, StringComparison.Ordinal)
                || !string.Equals(readback.ExactResponseBodySha256, snapshot.ExactResponseBodySha256, StringComparison.Ordinal))
                throw Unavailable();
        }
        else
        {
            db.RuntimeAuthorityKeyRegistryReadbacks.Add(new()
            {
                ClientId = clientId,
                RequestId = request.RequestId,
                RequestDigestSha256 = request.RequestDigestSha256,
                SnapshotId = snapshot.SnapshotId,
                ExactResponseBodySha256 = snapshot.ExactResponseBodySha256,
                CreatedAtUtc = decisionNow
            });
        }

        if (!RuntimeAuthorityKeyRegistryContract.HasExactObservedAtUtc(
                snapshot.ExactResponseBody, snapshot.ObservedAtUtc)
            || !RuntimeAuthorityKeyRegistryContract.HasExactBodyDigest(
                snapshot.ExactResponseBody, snapshot.ExactResponseBodySha256,
                readback?.ExactResponseBodySha256 ?? snapshot.ExactResponseBodySha256))
            throw Unavailable();
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return [.. snapshot.ExactResponseBody];
    }

    /// <summary>
    /// Promotes one provider-authenticated higher version with the contract's exact six-column
    /// head CAS. Any collision or unexpected row count aborts the surrounding transaction.
    /// </summary>
    private static async Task<RuntimeAuthorityKeyRegistrySnapshot> PromoteAsync(
        LicenseDbContext db,
        RuntimeAuthorityKeyRegistryHead head,
        RuntimeAuthorityKeyRegistrySnapshot current,
        RuntimeAuthorityKeyRegistryContract.Snapshot source,
        DateTime decisionNow,
        CancellationToken cancellationToken)
    {
        var highestPublishedVersion = await db.RuntimeAuthorityKeyRegistrySnapshots
            .Where(item => item.RegistryId == RuntimeAuthorityKeyRegistryContract.RegistryId)
            .MaxAsync(item => (long?)item.SnapshotVersion, cancellationToken);
        if (highestPublishedVersion != head.CurrentSnapshotVersion
            || source.SnapshotVersion <= highestPublishedVersion
            || string.Equals(source.SnapshotId, head.CurrentSnapshotId, StringComparison.Ordinal)
            || await db.RuntimeAuthorityKeyRegistrySnapshots.AnyAsync(item =>
                item.SnapshotId == source.SnapshotId
                || item.RegistryId == RuntimeAuthorityKeyRegistryContract.RegistryId
                    && (item.SnapshotVersion == source.SnapshotVersion
                        || item.MetadataDigestSha256 == source.MetadataDigestSha256), cancellationToken))
            throw Unavailable();

        var superseded = await db.RuntimeAuthorityKeyRegistrySnapshots
            .Where(item => item.SnapshotId == current.SnapshotId
                && item.RegistryId == head.RegistryId
                && item.SnapshotVersion == head.CurrentSnapshotVersion
                && item.MetadataDigestSha256 == head.CurrentMetadataDigestSha256
                && item.RegistryAuthenticationInputDigestSha256 == head.CurrentRegistryAuthenticationInputDigestSha256
                && item.PublicationState == "current"
                && item.RevokedAtUtc == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(item => item.PublicationState, "superseded"), cancellationToken);
        if (superseded != 1)
            throw Unavailable();

        var promoted = new RuntimeAuthorityKeyRegistrySnapshot
        {
            SnapshotId = source.SnapshotId,
            RegistryId = RuntimeAuthorityKeyRegistryContract.RegistryId,
            SnapshotVersion = source.SnapshotVersion,
            MetadataDigestSha256 = source.MetadataDigestSha256,
            RegistryAuthenticationInputDigestSha256 = source.RegistryAuthenticationInputDigestSha256,
            ObservedAtUtc = source.ObservedAtUtc,
            PublicationState = "current",
            ExactResponseBody = [.. source.ExactResponseBody],
            ExactResponseBodySha256 = source.ExactResponseBodySha256,
            RegistrySignatureBase64Url = source.SignatureBase64Url,
            CreatedAtUtc = decisionNow
        };
        db.Entry(current).State = EntityState.Detached;
        db.RuntimeAuthorityKeyRegistrySnapshots.Add(promoted);

        var headUpdated = await db.RuntimeAuthorityKeyRegistryHeads
            .Where(item => item.RegistryId == head.RegistryId
                && item.CurrentSnapshotId == head.CurrentSnapshotId
                && item.CurrentSnapshotVersion == head.CurrentSnapshotVersion
                && item.CurrentMetadataDigestSha256 == head.CurrentMetadataDigestSha256
                && item.CurrentRegistryAuthenticationInputDigestSha256 == head.CurrentRegistryAuthenticationInputDigestSha256
                && item.CurrentPublicationState == "current")
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(item => item.CurrentSnapshotId, source.SnapshotId)
                .SetProperty(item => item.CurrentSnapshotVersion, source.SnapshotVersion)
                .SetProperty(item => item.CurrentMetadataDigestSha256, source.MetadataDigestSha256)
                .SetProperty(item => item.CurrentRegistryAuthenticationInputDigestSha256,
                    source.RegistryAuthenticationInputDigestSha256)
                .SetProperty(item => item.CurrentPublicationState, "current")
                .SetProperty(item => item.UpdatedAtUtc, decisionNow), cancellationToken);
        if (headUpdated != 1)
            throw Unavailable();
        db.Entry(head).State = EntityState.Detached;
        return promoted;
    }

    /// <summary>Rejects a corrupt or revoked durable current snapshot before any promotion effect.</summary>
    private static bool IsInternallyConsistentCurrent(
        RuntimeAuthorityKeyRegistryHead head,
        RuntimeAuthorityKeyRegistrySnapshot snapshot) =>
        head.CurrentPublicationState == "current"
        && snapshot.PublicationState == "current"
        && snapshot.RevokedAtUtc is null
        && RuntimeAuthorityKeyRegistryContract.HasExactObservedAtUtc(
            snapshot.ExactResponseBody, snapshot.ObservedAtUtc)
        && RuntimeAuthorityKeyRegistryContract.HasExactBodyDigest(
            snapshot.ExactResponseBody, snapshot.ExactResponseBodySha256,
            snapshot.ExactResponseBodySha256);

    /// <summary>Requires source configuration, durable head, and stored snapshot to be byte-identical.</summary>
    private static bool Matches(
        RuntimeAuthorityKeyRegistryContract.Snapshot source,
        RuntimeAuthorityKeyRegistryHead head,
        RuntimeAuthorityKeyRegistrySnapshot snapshot) =>
        head.CurrentPublicationState == "current"
        && snapshot.PublicationState == "current" && snapshot.RevokedAtUtc is null
        && string.Equals(source.ObservedAtUtc, snapshot.ObservedAtUtc, StringComparison.Ordinal)
        && string.Equals(source.SnapshotId, head.CurrentSnapshotId, StringComparison.Ordinal)
        && source.SnapshotVersion == head.CurrentSnapshotVersion
        && string.Equals(source.MetadataDigestSha256, head.CurrentMetadataDigestSha256, StringComparison.Ordinal)
        && string.Equals(source.RegistryAuthenticationInputDigestSha256, head.CurrentRegistryAuthenticationInputDigestSha256, StringComparison.Ordinal)
        && string.Equals(source.SignatureBase64Url, snapshot.RegistrySignatureBase64Url, StringComparison.Ordinal)
        && string.Equals(source.ExactResponseBodySha256, snapshot.ExactResponseBodySha256, StringComparison.Ordinal)
        && source.ExactResponseBody.AsSpan().SequenceEqual(snapshot.ExactResponseBody);

    /// <summary>Closed outcomes for direct or arbitrarily wrapped database/provider failures.</summary>
    private enum DatabaseFailureClassification
    {
        NotDatabaseFailure,
        CallerCancellation,
        RetryTransaction,
        RereadExpectedReadbackRace,
        Unavailable
    }

    /// <summary>
    /// Classifies database failures without inspecting provider message text. Caller cancellation wins;
    /// only 40001/40P01 retry, while the named readback-PK race receives one bounded locked reread.
    /// </summary>
    private static DatabaseFailureClassification ClassifyDatabaseFailure(
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
            return DatabaseFailureClassification.CallerCancellation;
        var providerFailure = false;
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is PostgresException postgres)
            {
                if (postgres.SqlState is PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.DeadlockDetected)
                    return DatabaseFailureClassification.RetryTransaction;
                if (postgres.SqlState == PostgresErrorCodes.UniqueViolation
                    && string.Equals(postgres.ConstraintName,
                        "PK_RuntimeAuthorityKeyRegistryReadbacks", StringComparison.Ordinal))
                    return DatabaseFailureClassification.RereadExpectedReadbackRace;
                return DatabaseFailureClassification.Unavailable;
            }
            if (current is NpgsqlException or DbUpdateException or TimeoutException or OperationCanceledException)
                providerFailure = true;
        }
        return providerFailure
            ? DatabaseFailureClassification.Unavailable
            : DatabaseFailureClassification.NotDatabaseFailure;
    }

    /// <summary>Identifies only provider failures that the HTTP boundary may safely collapse to closed 503.</summary>
    internal static bool IsClosedProviderFailure(Exception exception) =>
        ClassifyDatabaseFailure(exception, CancellationToken.None)
            is not DatabaseFailureClassification.NotDatabaseFailure;

    /// <summary>Reads a fresh PostgreSQL clock value after the decisive registry lock.</summary>
    private static async Task<DateTime> DatabaseNowAsync(LicenseDbContext db, CancellationToken cancellationToken) =>
        await db.Database.SqlQueryRaw<DateTime>("SELECT clock_timestamp() AS \"Value\"")
            .SingleAsync(cancellationToken);

    /// <summary>Creates the sole semantic request divergence failure.</summary>
    private static RuntimeAuthorityKeyRegistryContractException Conflict() =>
        new("RUNTIME_ENROLLMENT_CONFLICT", StatusCodes.Status409Conflict);
    /// <summary>Creates the uniform fail-closed provider-unavailable failure.</summary>
    private static RuntimeAuthorityKeyRegistryContractException Unavailable() =>
        new("RUNTIME_ENROLLMENT_TEMPORARILY_UNAVAILABLE", StatusCodes.Status503ServiceUnavailable);
}
