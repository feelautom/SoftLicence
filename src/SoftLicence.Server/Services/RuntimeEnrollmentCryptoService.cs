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

public sealed record RuntimeEncryptedValue(string Ciphertext, string KeyId);

public interface IRuntimeEnrollmentCryptoService
{
    string ActiveSigningKeyId { get; }

    Task<RuntimeEncryptedValue> SealAsync(
        LicenseDbContext db,
        string ownerType,
        Guid ownerId,
        int enrollmentEpoch,
        ReadOnlyMemory<byte> plaintext,
        string ownerReference,
        CancellationToken cancellationToken = default);

    byte[] Open(
        string ownerType, Guid ownerId, int enrollmentEpoch, string keyId, string ciphertext, string ownerReference);

    string SignCapability(
        Guid enrollmentId,
        int enrollmentEpoch,
        int securityEpoch,
        string installationId,
        string releaseVersion,
        string sessionId,
        IReadOnlyList<RuntimeEnrollmentBinaryEvidenceRequest> binaries,
        string audience,
        IReadOnlyList<string> scopes,
        string publicKeySpkiSha256,
        DateTimeOffset issuedAtUtc,
        string tokenJti);

    string SignLegacyCapability(
        Guid enrollmentId,
        int enrollmentEpoch,
        int securityEpoch,
        string audience,
        IReadOnlyList<string> scopes,
        string publicKeySpkiSha256,
        DateTimeOffset issuedAtUtc,
        string tokenJti);

    string SignRecovery(RuntimeCriticalRecoveryResponse response);

    string SignUpgrade(RuntimeEnrollmentUpgradeResponse response);
    string SignWebSetupUpgrade(RuntimeWebSetupUpgradeResponse response);
}

public sealed class RuntimeEnrollmentCryptoService : IRuntimeEnrollmentCryptoService, IDisposable
{
    private const byte EnvelopeVersion = 1;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int MaximumNonceAttempts = 4;
    private readonly RuntimeEnrollmentOptions _options;
    private readonly IReadOnlyDictionary<string, byte[]> _encryptionKeys;
    private readonly RSA _activeSigningKey;
    private readonly object _signingLock = new();

    public RuntimeEnrollmentCryptoService(IOptions<RuntimeEnrollmentOptions> options)
    {
        _options = options.Value;
        _encryptionKeys = (_options.Encryption.Keys ?? [])
            .ToDictionary(key => key.KeyId, key => Convert.FromBase64String(key.KeyBase64), StringComparer.Ordinal);
        _activeSigningKey = RSA.Create();
        var active = (_options.CapabilitySigning.Keys ?? [])
            .SingleOrDefault(key => key.KeyId == _options.CapabilitySigning.ActiveKeyId);
        if (_options.Mode == "enabled")
            _activeSigningKey.ImportFromPem(active?.PrivateKeyPem);
    }

    public string ActiveSigningKeyId => _options.CapabilitySigning.ActiveKeyId;

    public async Task<RuntimeEncryptedValue> SealAsync(
        LicenseDbContext db,
        string ownerType,
        Guid ownerId,
        int enrollmentEpoch,
        ReadOnlyMemory<byte> plaintext,
        string ownerReference,
        CancellationToken cancellationToken = default)
    {
        if (_options.Mode != "enabled" || !IsOwnerType(ownerType) || enrollmentEpoch < 1
            || string.IsNullOrEmpty(ownerReference) || db.Database.CurrentTransaction == null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        if (!_encryptionKeys.TryGetValue(_options.Encryption.ActiveKeyId, out var key))
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);

        for (var attempt = 0; attempt < MaximumNonceAttempts; attempt++)
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            if (!await TryReserveNonceAsync(db, _options.Encryption.ActiveKeyId, nonce, ownerType, ownerId, cancellationToken))
                continue;

            var aad = BuildAad(ownerType, ownerId, enrollmentEpoch, _options.Encryption.ActiveKeyId, ownerReference);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagBytes];
            try
            {
                using var aes = new AesGcm(key, TagBytes);
                aes.Encrypt(nonce, plaintext.Span, ciphertext, tag, aad);
                var envelope = new byte[1 + NonceBytes + TagBytes + ciphertext.Length];
                envelope[0] = EnvelopeVersion;
                nonce.CopyTo(envelope.AsSpan(1, NonceBytes));
                tag.CopyTo(envelope.AsSpan(1 + NonceBytes, TagBytes));
                ciphertext.CopyTo(envelope.AsSpan(1 + NonceBytes + TagBytes));
                return new RuntimeEncryptedValue(EncodeBase64Url(envelope), _options.Encryption.ActiveKeyId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(tag);
            }
        }
        throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
    }

    public byte[] Open(
        string ownerType, Guid ownerId, int enrollmentEpoch, string keyId, string ciphertext, string ownerReference)
    {
        if (!IsOwnerType(ownerType) || enrollmentEpoch < 1 || string.IsNullOrEmpty(ownerReference)
            || !_encryptionKeys.TryGetValue(keyId, out var key))
            throw new CryptographicException("Runtime enrollment envelope unavailable.");
        var envelope = DecodeCanonicalBase64Url(ciphertext);
        try
        {
            if (envelope.Length < 1 + NonceBytes + TagBytes || envelope[0] != EnvelopeVersion)
                throw new CryptographicException("Runtime enrollment envelope invalid.");
            var plaintext = new byte[envelope.Length - 1 - NonceBytes - TagBytes];
            try
            {
                using var aes = new AesGcm(key, TagBytes);
                aes.Decrypt(
                    envelope.AsSpan(1, NonceBytes),
                    envelope.AsSpan(1 + NonceBytes + TagBytes),
                    envelope.AsSpan(1 + NonceBytes, TagBytes),
                    plaintext,
                    BuildAad(ownerType, ownerId, enrollmentEpoch, keyId, ownerReference));
                return plaintext;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    public string SignCapability(
        Guid enrollmentId,
        int enrollmentEpoch,
        int securityEpoch,
        string installationId,
        string releaseVersion,
        string sessionId,
        IReadOnlyList<RuntimeEnrollmentBinaryEvidenceRequest> binaries,
        string audience,
        IReadOnlyList<string> scopes,
        string publicKeySpkiSha256,
        DateTimeOffset issuedAtUtc,
        string tokenJti)
        => SignCapabilityCore(
            false, enrollmentId, enrollmentEpoch, securityEpoch,
            installationId, releaseVersion, sessionId, binaries,
            audience, scopes, publicKeySpkiSha256, issuedAtUtc, tokenJti);

    public string SignLegacyCapability(
        Guid enrollmentId,
        int enrollmentEpoch,
        int securityEpoch,
        string audience,
        IReadOnlyList<string> scopes,
        string publicKeySpkiSha256,
        DateTimeOffset issuedAtUtc,
        string tokenJti)
        => SignCapabilityCore(
            true, enrollmentId, enrollmentEpoch, securityEpoch,
            null, null, null, null,
            audience, scopes, publicKeySpkiSha256, issuedAtUtc, tokenJti);

    private string SignCapabilityCore(
        bool legacy,
        Guid enrollmentId,
        int enrollmentEpoch,
        int securityEpoch,
        string? installationId,
        string? releaseVersion,
        string? sessionId,
        IReadOnlyList<RuntimeEnrollmentBinaryEvidenceRequest>? binaries,
        string audience,
        IReadOnlyList<string> scopes,
        string publicKeySpkiSha256,
        DateTimeOffset issuedAtUtc,
        string tokenJti)
    {
        if (_options.Mode != "enabled")
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        if (securityEpoch < 1
            || (legacy && (installationId != null || releaseVersion != null || sessionId != null || binaries != null))
            || (!legacy && (installationId == null || releaseVersion == null || sessionId == null || binaries == null)))
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        var header = SerializeJson(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("alg", "PS256");
            writer.WriteString("kid", _options.CapabilitySigning.ActiveKeyId);
            writer.WriteString("typ", "JWT");
            writer.WriteEndObject();
        });
        var issuedAt = issuedAtUtc.ToUnixTimeSeconds();
        var payload = SerializeJson(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("iss", _options.Issuer);
            writer.WriteString("aud", audience);
            writer.WriteString("sub", enrollmentId.ToString("D"));
            writer.WriteString("jti", tokenJti);
            writer.WriteNumber("iat", issuedAt);
            writer.WriteNumber("nbf", issuedAt);
            writer.WriteNumber("exp", issuedAt + 120);
            writer.WriteNumber("epoch", enrollmentEpoch);
            writer.WriteNumber("security_epoch", securityEpoch);
            if (!legacy)
            {
                writer.WriteString("installation_id", installationId);
                writer.WriteString("release_version", releaseVersion);
                writer.WriteString("session_id", sessionId);
                writer.WritePropertyName("binaries");
                writer.WriteStartObject();
                foreach (var binary in binaries!)
                    writer.WriteString(binary.Key!, binary.Sha256);
                writer.WriteEndObject();
            }
            writer.WritePropertyName("scope");
            writer.WriteStartArray();
            foreach (var scope in scopes)
                writer.WriteStringValue(scope);
            writer.WriteEndArray();
            writer.WritePropertyName("cnf");
            writer.WriteStartObject();
            writer.WriteString("spki_sha256", publicKeySpkiSha256);
            writer.WriteEndObject();
            writer.WriteEndObject();
        });
        var signingInput = $"{EncodeBase64Url(header)}.{EncodeBase64Url(payload)}";
        byte[] signature;
        lock (_signingLock)
        {
            signature = _activeSigningKey.SignData(
                Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        try
        {
            return $"{signingInput}.{EncodeBase64Url(signature)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    public string SignRecovery(RuntimeCriticalRecoveryResponse response)
    {
        if (_options.Mode != "enabled"
            || response.Schema != "runtime-critical-recovery-receipt-v1"
            || response.ProtocolVersion != RuntimeEnrollmentService.ProtocolVersion
            || response.Alg != "PS256"
            || response.KeyId != ActiveSigningKeyId
            || response.Audience != RuntimeEnrollmentService.CriticalRecoveryAudience
            || response.Use != RuntimeEnrollmentService.CriticalRecoveryUse
            || response.Signature.Length != 0)
        {
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }

        byte[] signature;
        lock (_signingLock)
        {
            signature = _activeSigningKey.SignData(
                Encoding.UTF8.GetBytes(BuildRecoverySignaturePayload(response)),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }
        try
        {
            return EncodeBase64Url(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    public string SignUpgrade(RuntimeEnrollmentUpgradeResponse response)
    {
        if (_options.Mode != "enabled")
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        byte[] signature;
        lock (_signingLock)
        {
            signature = _activeSigningKey.SignData(
                Encoding.UTF8.GetBytes(BuildUpgradeSignaturePayload(response)),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }
        try { return EncodeBase64Url(signature); }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    public string SignWebSetupUpgrade(RuntimeWebSetupUpgradeResponse response)
    {
        if (_options.Mode != "enabled"
            || response.Schema != RuntimeEnrollmentService.WebSetupUpgradeResponseSchema
            || response.ProtocolVersion != RuntimeEnrollmentService.ProtocolVersion
            || response.Alg != "PS256"
            || response.KeyId != ActiveSigningKeyId
            || response.Audience != RuntimeEnrollmentService.WebSetupUpgradeAudience
            || response.Use != RuntimeEnrollmentService.WebSetupUpgradeUse
            || response.Signature.Length != 0)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        byte[] signature;
        lock (_signingLock)
        {
            signature = _activeSigningKey.SignData(
                Encoding.UTF8.GetBytes(BuildWebSetupUpgradeSignaturePayload(response)),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }
        try { return EncodeBase64Url(signature); }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    public static string BuildRecoverySignaturePayload(RuntimeCriticalRecoveryResponse response) => string.Join('\n',
        response.Schema,
        response.ProtocolVersion,
        response.Alg,
        response.KeyId,
        response.Audience,
        response.Use,
        response.RecoveryId,
        response.RequestId,
        response.ProductId,
        response.EnrollmentId,
        response.BindingId,
        response.InstallationId,
        response.EventId,
        response.OldSecurityEpoch.ToString(CultureInfo.InvariantCulture),
        response.NewSecurityEpoch.ToString(CultureInfo.InvariantCulture),
        response.Decision,
        response.IssuedAtUtc,
        response.ExpiresAtUtc);

    public static string BuildUpgradeSignaturePayload(RuntimeEnrollmentUpgradeResponse response) => string.Join('\n',
        response.Schema,
        response.ProtocolVersion,
        response.Alg,
        response.KeyId,
        response.Audience,
        response.Use,
        response.RequestId,
        response.ProductId,
        response.EnrollmentId,
        response.BindingId,
        response.InstallationId,
        response.SourceVersion,
        response.TargetVersion,
        response.OldSecurityEpoch.ToString(CultureInfo.InvariantCulture),
        response.NewSecurityEpoch.ToString(CultureInfo.InvariantCulture),
        response.RecoveryReceiptId,
        response.RecoveryReceiptDigestSha256,
        response.Decision,
        response.IssuedAtUtc,
        response.ExpiresAtUtc);

    public static string BuildWebSetupUpgradeSignaturePayload(RuntimeWebSetupUpgradeResponse response) => string.Join('\n',
        response.Schema,
        response.ProtocolVersion,
        response.Alg,
        response.KeyId,
        response.Audience,
        response.Use,
        response.RequestId,
        response.ProductId,
        response.EnrollmentId,
        response.BindingId,
        response.InstallationId,
        response.SourceVersion,
        response.TargetVersion,
        response.OldSecurityEpoch.ToString(CultureInfo.InvariantCulture),
        response.NewSecurityEpoch.ToString(CultureInfo.InvariantCulture),
        response.TransitionId,
        response.TransitionDigestSha256,
        response.Decision,
        response.IssuedAtUtc,
        response.ExpiresAtUtc);

    private static async Task<bool> TryReserveNonceAsync(
        LicenseDbContext db,
        string keyId,
        byte[] nonce,
        string ownerType,
        Guid ownerId,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
            await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = (NpgsqlTransaction?)db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = """
            INSERT INTO public."RuntimeEnrollmentEncryptionNonces"
                ("KeyId", "Nonce", "OwnerType", "OwnerId", "CreatedAtUtc")
            VALUES (@keyId, @nonce, @ownerType, @ownerId, clock_timestamp())
            ON CONFLICT ("KeyId", "Nonce") DO NOTHING
            RETURNING 1;
            """;
        command.Parameters.AddWithValue("keyId", keyId);
        command.Parameters.AddWithValue("nonce", nonce);
        command.Parameters.AddWithValue("ownerType", ownerType);
        command.Parameters.AddWithValue("ownerId", ownerId);
        return await command.ExecuteScalarAsync(cancellationToken) != null;
    }

    private static byte[] BuildAad(
        string ownerType, Guid ownerId, int enrollmentEpoch, string keyId, string ownerReference) =>
        Encoding.UTF8.GetBytes(string.Join('\n',
            "runtime-enrollment-envelope-v2", ownerType, ownerId.ToString("D"), ownerReference,
            enrollmentEpoch.ToString(CultureInfo.InvariantCulture), keyId));

    private static bool IsOwnerType(string value) => value is
        "enrollment-spki" or "enrollment-challenge" or "prepare-response" or "confirm-response"
            or "capability-response" or "canary-response" or "critical-recovery-response"
            or "recovery-refetch-response" or "milestone-response" or "upgrade-response"
            or "rollback-response" or "bootstrap-issue-response"
            or "bootstrap-redeem-response" or "websetup-transition-response"
            or "websetup-upgrade-response";

    private static byte[] SerializeJson(Action<Utf8JsonWriter> write)
    {
        using var memory = new MemoryStream();
        using (var writer = new Utf8JsonWriter(memory))
            write(writer);
        return memory.ToArray();
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeCanonicalBase64Url(string value)
    {
        if (value.Length == 0 || value.Contains('=') || value.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw new CryptographicException("Runtime enrollment envelope invalid.");
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        var decoded = Convert.FromBase64String(base64);
        if (EncodeBase64Url(decoded) != value)
            throw new CryptographicException("Runtime enrollment envelope invalid.");
        return decoded;
    }

    public void Dispose()
    {
        _activeSigningKey.Dispose();
        foreach (var key in _encryptionKeys.Values)
            CryptographicOperations.ZeroMemory(key);
    }
}
