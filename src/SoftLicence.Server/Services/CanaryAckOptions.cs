using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SoftLicence.Server.Services;

public sealed class CanaryAckOptions
{
    public const string InitialKeyId = "canary-rs256-2026-01";

    public int RegistryVersion { get; set; } = 1;
    public string ActiveKeyId { get; set; } = InitialKeyId;
    public string PrivateKeyPem { get; set; } = string.Empty;
    public List<CanaryAckPublicKeyOptions> Keys { get; set; } = [];
}

public sealed class CanaryAckPublicKeyOptions
{
    public string KeyId { get; set; } = string.Empty;
    public string PublicKeyPem { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTimeOffset? RetainUntilUtc { get; set; }
}

public sealed class CanaryAckOptionsValidator : IValidateOptions<CanaryAckOptions>
{
    public ValidateOptionsResult Validate(string? name, CanaryAckOptions options)
    {
        try
        {
            _ = CanaryAckKeyringConfiguration.Build(options);
            return ValidateOptionsResult.Success;
        }
        catch (CanaryAckConfigurationException exception)
        {
            return ValidateOptionsResult.Fail(exception.Message);
        }
    }
}

public sealed record CanaryAckConfiguredKey(
    string KeyId,
    string Role,
    string PublicSpkiBase64,
    string MaterialDigestSha256,
    DateTimeOffset? RetainUntilUtc);

public sealed class CanaryAckKeyringConfiguration
{
    private CanaryAckKeyringConfiguration(
        int registryVersion,
        string activeKeyId,
        string contentDigestSha256,
        IReadOnlyList<CanaryAckConfiguredKey> keys)
    {
        RegistryVersion = registryVersion;
        ActiveKeyId = activeKeyId;
        ContentDigestSha256 = contentDigestSha256;
        Keys = keys;
    }

    public int RegistryVersion { get; }
    public string ActiveKeyId { get; }
    public string ContentDigestSha256 { get; }
    public IReadOnlyList<CanaryAckConfiguredKey> Keys { get; }

    public CanaryAckConfiguredKey ActiveKey =>
        Keys.Single(key => string.Equals(key.KeyId, ActiveKeyId, StringComparison.Ordinal));

    public static CanaryAckKeyringConfiguration Build(CanaryAckOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.RegistryVersion < 1)
            throw Invalid("Canary ACK RegistryVersion must be positive.");
        if (!IsCanonicalKeyId(options.ActiveKeyId))
            throw Invalid("Canary ACK ActiveKeyId must be an exact canonical ASCII identifier.");

        var activePrivateSpki = ReadPrivateSpki(options.PrivateKeyPem);
        try
        {
            var configured = options.Keys is { Count: > 0 }
                ? BuildExplicit(options, activePrivateSpki)
                : BuildLegacy(options, activePrivateSpki);
            var contentDigest = ComputeContentDigest(options.RegistryVersion, configured);
            return new CanaryAckKeyringConfiguration(
                options.RegistryVersion,
                options.ActiveKeyId,
                contentDigest,
                configured);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(activePrivateSpki);
        }
    }

    public static RSA LoadActivePrivateKey(CanaryAckOptions options)
    {
        _ = Build(options);
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(options.PrivateKeyPem);
            return rsa;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            throw Invalid("Canary ACK active private key is invalid.", exception);
        }
    }

    public static bool IsCanonicalKeyId(string? value)
    {
        if (value is not { Length: >= 1 and <= 64 })
            return false;
        foreach (var character in value)
        {
            if ((character is >= 'a' and <= 'z')
                || (character is >= 'A' and <= 'Z')
                || (character is >= '0' and <= '9')
                || character is '-' or '_' or '.')
                continue;
            return false;
        }
        return true;
    }

    private static IReadOnlyList<CanaryAckConfiguredKey> BuildLegacy(
        CanaryAckOptions options,
        byte[] activePrivateSpki)
    {
        if (!string.Equals(options.ActiveKeyId, CanaryAckOptions.InitialKeyId, StringComparison.Ordinal))
            throw Invalid("Legacy Canary ACK configuration requires the initial active KeyId.");
        return [CreateConfiguredKey(options.ActiveKeyId, "active", activePrivateSpki, null)];
    }

    private static IReadOnlyList<CanaryAckConfiguredKey> BuildExplicit(
        CanaryAckOptions options,
        byte[] activePrivateSpki)
    {
        if (options.Keys.Count > 8)
            throw Invalid("Canary ACK keyring cannot contain more than eight live keys.");

        var result = new List<CanaryAckConfiguredKey>(options.Keys.Count);
        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        var materialDigests = new HashSet<string>(StringComparer.Ordinal);
        string? previousKeyId = null;
        foreach (var key in options.Keys)
        {
            if (!IsCanonicalKeyId(key.KeyId)
                || (previousKeyId != null && string.CompareOrdinal(previousKeyId, key.KeyId) >= 0))
                throw Invalid("Canary ACK KeyIds must be canonical, unique, and ordinally sorted.");
            previousKeyId = key.KeyId;
            if (!keyIds.Add(key.KeyId))
                throw Invalid("Canary ACK KeyIds must be unique.");
            if (key.Role is not ("active" or "next" or "previous"))
                throw Invalid("Canary ACK key roles must be active, next, or previous.");
            if (key.Role == "previous" && !key.RetainUntilUtc.HasValue)
                throw Invalid("Canary ACK previous keys require RetainUntilUtc.");
            if (key.Role != "previous" && key.RetainUntilUtc.HasValue)
                throw Invalid("Canary ACK retention is valid only for previous keys.");

            var publicSpki = ReadPublicSpki(key.PublicKeyPem);
            try
            {
                if (key.Role == "active"
                    && !CryptographicOperations.FixedTimeEquals(publicSpki, activePrivateSpki))
                    throw Invalid("Canary ACK active private and public keys do not match.");
                var configured = CreateConfiguredKey(
                    key.KeyId,
                    key.Role,
                    publicSpki,
                    key.RetainUntilUtc?.ToUniversalTime());
                if (!materialDigests.Add(configured.MaterialDigestSha256))
                    throw Invalid("Canary ACK keys must not alias the same public material.");
                result.Add(configured);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicSpki);
            }
        }

        if (result.Count(key => key.Role == "active") != 1
            || result.Count(key => key.Role == "next") > 1
            || !result.Any(key => key.Role == "active"
                && string.Equals(key.KeyId, options.ActiveKeyId, StringComparison.Ordinal)))
            throw Invalid("Canary ACK keyring requires exactly the configured active key and at most one next key.");
        return result;
    }

    private static CanaryAckConfiguredKey CreateConfiguredKey(
        string keyId,
        string role,
        byte[] publicSpki,
        DateTimeOffset? retainUntilUtc)
    {
        var digest = Convert.ToHexStringLower(SHA256.HashData(publicSpki));
        return new CanaryAckConfiguredKey(
            keyId,
            role,
            Convert.ToBase64String(publicSpki),
            digest,
            retainUntilUtc);
    }

    private static byte[] ReadPrivateSpki(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
            throw Invalid("Canary ACK active private key is not configured.");
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            ValidateRsa(rsa, "private");
            var proof = rsa.SignHash(
                new byte[SHA256.HashSizeInBytes],
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            CryptographicOperations.ZeroMemory(proof);
            return rsa.ExportSubjectPublicKeyInfo();
        }
        catch (CanaryAckConfigurationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            throw Invalid("Canary ACK active private key is invalid.", exception);
        }
    }

    private static byte[] ReadPublicSpki(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
            throw Invalid("Canary ACK public key is not configured.");
        try
        {
            var fields = PemEncoding.Find(pem);
            if (!pem.AsSpan(fields.Label).SequenceEqual("PUBLIC KEY"))
                throw Invalid("Canary ACK public key must contain public SPKI material only.");

            using var rsa = RSA.Create();
            var publicKey = Convert.FromBase64String(pem.AsSpan(fields.Base64Data).ToString());
            try
            {
                rsa.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
                if (bytesRead != publicKey.Length)
                    throw Invalid("Canary ACK public key is invalid.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
            ValidateRsa(rsa, "public");
            return rsa.ExportSubjectPublicKeyInfo();
        }
        catch (CanaryAckConfigurationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            throw Invalid("Canary ACK public key is invalid.", exception);
        }
    }

    private static void ValidateRsa(RSA rsa, string materialType)
    {
        var parameters = rsa.ExportParameters(false);
        if (rsa.KeySize != 2048 || parameters.Exponent is not [0x01, 0x00, 0x01])
            throw Invalid($"Canary ACK {materialType} key must be RSA-2048 with exponent 65537.");
    }

    private static string ComputeContentDigest(
        int registryVersion,
        IReadOnlyList<CanaryAckConfiguredKey> keys)
    {
        var canonical = new StringBuilder()
            .Append(registryVersion.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var key in keys)
        {
            canonical.Append(key.KeyId).Append('\n')
                .Append(key.Role).Append('\n')
                .Append(key.MaterialDigestSha256).Append('\n')
                .Append(key.RetainUntilUtc?.UtcTicks.ToString(CultureInfo.InvariantCulture) ?? "-")
                .Append('\n');
        }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(canonical.ToString())));
    }

    private static CanaryAckConfigurationException Invalid(string message, Exception? inner = null) =>
        inner == null
            ? new CanaryAckConfigurationException(message)
            : new CanaryAckConfigurationException(message, inner);
}
