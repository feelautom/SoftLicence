using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Fills one caller-owned 96-bit GCM nonce buffer from a cryptographic source.</summary>
/// <param name="destination">Exactly twelve bytes that must be completely overwritten.</param>
public delegate void RuntimeSeatRecoveryNonceGenerator(Span<byte> destination);

/// <summary>Signals that W8 seat-claim encryption cannot return a safe token.</summary>
public sealed class RuntimeSeatRecoveryCryptographyException : CryptographicException
{
    /// <summary>Creates the closed failure without exposing key material or collision candidates.</summary>
    public RuntimeSeatRecoveryCryptographyException() : base("Runtime seat-recovery cryptography failed closed.") { }
}

/// <summary>Reserves durable per-key nonces before producing exact SRSC AES-256-GCM seat claims.</summary>
public sealed class RuntimeSeatRecoverySeatClaimCryptography
{
    private const int MaximumNonceAttempts = 8;
    private static readonly byte[] FrameMagic = "SRSC"u8.ToArray();
    private static readonly byte[] AadDomain = "SOFTLICENCE\0RUNTIME-RECOVERY-SEAT-CLAIM\0V1"u8.ToArray();
    private readonly Func<string, byte[], Guid, CancellationToken, Task<bool>> reserveNonce;
    private readonly RuntimeSeatRecoveryNonceGenerator fillNonce;
    private readonly RuntimeEnrollmentOptions? options;

    /// <summary>Creates the production component whose nonce transaction commits independently before encryption.</summary>
    public RuntimeSeatRecoverySeatClaimCryptography(
        IServiceScopeFactory scopeFactory,
        IOptions<RuntimeEnrollmentOptions> options)
    {
        this.options = options.Value;
        reserveNonce = async (keyId, nonce, ownerId, cancellationToken) =>
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            db.RuntimeEnrollmentEncryptionNonces.Add(new RuntimeEnrollmentEncryptionNonce
            {
                Purpose = "encryption",
                KeyId = keyId,
                Nonce = [.. nonce],
                OwnerType = "seat-recovery-claim",
                OwnerId = ownerId,
                CreatedAtUtc = DateTime.UtcNow
            });
            try
            {
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return true;
            }
            catch (DbUpdateException exception) when (exception.InnerException is PostgresException
                { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                await transaction.RollbackAsync(cancellationToken);
                return false;
            }
        };
        fillNonce = RandomNumberGenerator.Fill;
    }

    /// <summary>Creates a deterministic test boundary for collision and burn-order proofs.</summary>
    internal RuntimeSeatRecoverySeatClaimCryptography(
        Func<string, byte[], Guid, CancellationToken, Task<bool>> reserveNonce,
        RuntimeSeatRecoveryNonceGenerator fillNonce)
    {
        this.reserveNonce = reserveNonce;
        this.fillNonce = fillNonce;
    }

    /// <summary>Creates a deterministic full crypto boundary for frame and authenticated-open tests.</summary>
    internal RuntimeSeatRecoverySeatClaimCryptography(
        RuntimeEnrollmentOptions options,
        Func<string, byte[], Guid, CancellationToken, Task<bool>> reserveNonce,
        RuntimeSeatRecoveryNonceGenerator fillNonce)
        : this(reserveNonce, fillNonce) => this.options = options;

    /// <summary>Reserves one nonce in a separately committed transaction and retries only unique collisions.</summary>
    public async Task<byte[]> ReserveNonceAsync(string keyId, Guid ownerId, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaximumNonceAttempts; attempt++)
        {
            var candidate = new byte[12];
            fillNonce(candidate);
            if (await reserveNonce(keyId, candidate, ownerId, cancellationToken)) return candidate;
            CryptographicOperations.ZeroMemory(candidate);
        }
        throw new RuntimeSeatRecoveryCryptographyException();
    }

    /// <summary>Encrypts one canonical plaintext only after its GCM nonce has become durable.</summary>
    public async Task<string> SealAsync(
        RuntimeSeatRecoverySeatClaimPlaintext claim,
        Guid ownerId,
        CancellationToken cancellationToken)
    {
        var configured = options ?? throw new RuntimeSeatRecoveryCryptographyException();
        var key = configured.Encryption.Keys.SingleOrDefault(candidate =>
            string.Equals(candidate.KeyId, configured.Encryption.ActiveKeyId, StringComparison.Ordinal));
        if (key is null || !key.KeyId.All(char.IsAscii) || key.KeyId.Length is < 1 or > 255)
            throw new RuntimeSeatRecoveryCryptographyException();
        byte[]? keyBytes = null;
        byte[]? plaintext = null;
        byte[]? nonce = null;
        try
        {
            keyBytes = Convert.FromBase64String(key.KeyBase64);
            if (keyBytes.Length != 32) throw new RuntimeSeatRecoveryCryptographyException();
            plaintext = RuntimeSeatRecoveryContractCodec.SerializeSeatClaimPlaintext(claim);
            nonce = await ReserveNonceAsync(key.KeyId, ownerId, cancellationToken);
            var keyIdBytes = Encoding.ASCII.GetBytes(key.KeyId);
            var aad = new byte[AadDomain.Length + 1 + keyIdBytes.Length];
            AadDomain.CopyTo(aad, 0);
            aad[AadDomain.Length] = 0x0a;
            keyIdBytes.CopyTo(aad, AadDomain.Length + 1);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(keyBytes, tag.Length))
                aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            if (ciphertext.Length > ushort.MaxValue) throw new RuntimeSeatRecoveryCryptographyException();
            var frame = new byte[4 + 1 + 1 + keyIdBytes.Length + 12 + 2 + ciphertext.Length + 16];
            var offset = 0;
            FrameMagic.CopyTo(frame, offset); offset += 4;
            frame[offset++] = 1;
            frame[offset++] = checked((byte)keyIdBytes.Length);
            keyIdBytes.CopyTo(frame, offset); offset += keyIdBytes.Length;
            nonce.CopyTo(frame, offset); offset += nonce.Length;
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(offset, 2), checked((ushort)ciphertext.Length)); offset += 2;
            ciphertext.CopyTo(frame, offset); offset += ciphertext.Length;
            tag.CopyTo(frame, offset);
            return Convert.ToBase64String(frame).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException or OverflowException)
        {
            throw new RuntimeSeatRecoveryCryptographyException();
        }
        finally
        {
            if (keyBytes is not null) CryptographicOperations.ZeroMemory(keyBytes);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (nonce is not null) CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>Authenticates and opens one exact SRSC frame without probing unknown keys.</summary>
    public RuntimeSeatRecoverySeatClaimPlaintext? Open(string token)
    {
        var configured = options ?? throw new RuntimeSeatRecoveryCryptographyException();
        byte[] frame;
        try
        {
            if (string.IsNullOrEmpty(token) || token.Length > 8192 || token.Contains('=')) return null;
            var padded = token.Replace('-', '+').Replace('_', '/');
            padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty };
            frame = Convert.FromBase64String(padded);
            if (!string.Equals(Convert.ToBase64String(frame).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
                    token, StringComparison.Ordinal)) return null;
        }
        catch (FormatException) { return null; }

        byte[]? keyBytes = null;
        byte[]? plaintext = null;
        try
        {
            if (frame.Length < 4 + 1 + 1 + 1 + 12 + 2 + 16 || !frame.AsSpan(0, 4).SequenceEqual(FrameMagic)
                || frame[4] != 1) return null;
            var keyIdLength = frame[5];
            var ciphertextLengthOffset = 6 + keyIdLength + 12;
            if (keyIdLength == 0 || ciphertextLengthOffset + 2 + 16 > frame.Length) return null;
            var keyIdBytes = frame.AsSpan(6, keyIdLength);
            for (var index = 0; index < keyIdBytes.Length; index++)
                if (keyIdBytes[index] > 0x7f) return null;
            var keyId = Encoding.ASCII.GetString(keyIdBytes);
            var ciphertextLength = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(ciphertextLengthOffset, 2));
            var ciphertextOffset = ciphertextLengthOffset + 2;
            if (ciphertextOffset + ciphertextLength + 16 != frame.Length) return null;
            var configuredKey = configured.Encryption.Keys.SingleOrDefault(candidate =>
                string.Equals(candidate.KeyId, keyId, StringComparison.Ordinal));
            if (configuredKey is null) return null;
            keyBytes = Convert.FromBase64String(configuredKey.KeyBase64);
            if (keyBytes.Length != 32) return null;
            var aad = new byte[AadDomain.Length + 1 + keyIdLength];
            AadDomain.CopyTo(aad, 0);
            aad[AadDomain.Length] = 0x0a;
            keyIdBytes.CopyTo(aad.AsSpan(AadDomain.Length + 1));
            plaintext = new byte[ciphertextLength];
            using (var aes = new AesGcm(keyBytes, 16))
                aes.Decrypt(frame.AsSpan(6 + keyIdLength, 12),
                    frame.AsSpan(ciphertextOffset, ciphertextLength),
                    frame.AsSpan(ciphertextOffset + ciphertextLength, 16), plaintext, aad);
            return RuntimeSeatRecoveryContractCodec.ParseSeatClaimPlaintext(plaintext);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException or ArgumentException)
        {
            return null;
        }
        finally
        {
            if (keyBytes is not null) CryptographicOperations.ZeroMemory(keyBytes);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(frame);
        }
    }
}
