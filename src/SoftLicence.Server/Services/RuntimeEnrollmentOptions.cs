using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace SoftLicence.Server.Services;

public sealed class RuntimeEnrollmentOptions
{
    public string Mode { get; set; } = "off";
    public string Issuer { get; set; } = string.Empty;
    public string ConfirmAudience { get; set; } = string.Empty;
    public string CanaryAudience { get; set; } = string.Empty;
    public List<string> CanaryTriggers { get; set; } = [];
    public int ChallengeTtlSeconds { get; set; } = 300;
    public int CapabilityTtlSeconds { get; set; } = 120;
    public int LicenseBootstrapCapabilityTtlSeconds { get; set; } = 120;
    public int ProofClockSkewSeconds { get; set; } = 60;
    public int ProofNonceRetentionHours { get; set; } = 24;
    public int PendingEnrollmentLimitPerBinding { get; set; } = 1;
    public int LockTimeoutMilliseconds { get; set; } = 2000;
    public int StatementTimeoutMilliseconds { get; set; } = 5000;
    public int MaximumTransactionAttempts { get; set; } = 3;
    public int KeyRegistryVersion { get; set; } = 1;
    public string IpPseudonymKeyBase64 { get; set; } = string.Empty;
    public RuntimeCapabilitySigningOptions CapabilitySigning { get; set; } = new();
    public RuntimeEncryptionOptions Encryption { get; set; } = new();
    public List<RuntimeProductCapabilityOptions> Products { get; set; } = [];
}

public sealed class RuntimeCapabilitySigningOptions
{
    public string ActiveKeyId { get; set; } = string.Empty;
    public List<RuntimeCapabilitySigningKeyOptions> Keys { get; set; } = [];
}

public sealed class RuntimeCapabilitySigningKeyOptions
{
    public string KeyId { get; set; } = string.Empty;
    public string PublicKeyPem { get; set; } = string.Empty;
    public string? PrivateKeyPem { get; set; }
    public string Role { get; set; } = string.Empty;
    public DateTimeOffset? RetainUntilUtc { get; set; }
}

public static class RuntimeEnrollmentOptionsConfiguration
{
    /// <summary>
    /// Removes only fully empty signing-key entries created by fixed Compose array slots.
    /// Non-empty or whitespace-bearing values remain untouched so validation still fails closed.
    /// </summary>
    public static void RemoveEmptySigningKeyPlaceholders(RuntimeEnrollmentOptions options)
    {
        options.CapabilitySigning.Keys.RemoveAll(key =>
            key.KeyId.Length == 0
            && key.Role.Length == 0
            && key.PublicKeyPem.Length == 0
            && string.IsNullOrEmpty(key.PrivateKeyPem)
            && key.RetainUntilUtc is null);
    }
}

public sealed class RuntimeEncryptionOptions
{
    public string ActiveKeyId { get; set; } = string.Empty;
    public List<RuntimeEncryptionKeyOptions> Keys { get; set; } = [];
}

public sealed class RuntimeEncryptionKeyOptions
{
    public string KeyId { get; set; } = string.Empty;
    public string KeyBase64 { get; set; } = string.Empty;
}

public sealed class RuntimeProductCapabilityOptions
{
    public string ProductId { get; set; } = string.Empty;
    public List<RuntimeCapabilityGrantOptions> Capabilities { get; set; } = [];
}

public sealed class RuntimeCapabilityGrantOptions
{
    public string Audience { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = [];
}

public sealed class RuntimeEnrollmentOptionsValidator : IValidateOptions<RuntimeEnrollmentOptions>
{
    public ValidateOptionsResult Validate(string? name, RuntimeEnrollmentOptions options)
    {
        if (options.Mode == "off")
            return ValidateOptionsResult.Success;
        if (options.Mode != "enabled")
            return ValidateOptionsResult.Fail("Runtime enrollment mode must be exactly 'off' or 'enabled'.");

        var failures = new List<string>();
        if (!IsHttpsOrigin(options.Issuer))
            failures.Add("Runtime enrollment issuer must be a canonical HTTPS origin.");
        if (!IsHttpsOrigin(options.ConfirmAudience))
            failures.Add("Runtime enrollment confirm audience must be a canonical HTTPS origin.");
        else if (!string.Equals(options.ConfirmAudience, options.Issuer, StringComparison.Ordinal))
            failures.Add("Runtime enrollment issuer and confirm audience must be the same canonical HTTPS origin.");
        if (!IsCanonicalHttpsEndpoint(options.CanaryAudience, "/api/health/ping"))
            failures.Add("Runtime enrollment canary audience must be the canonical HTTPS /api/health/ping endpoint.");
        if (options.CanaryTriggers is not { Count: > 0 and <= 64 }
            || !IsStrictlySorted(options.CanaryTriggers)
            || options.CanaryTriggers.Any(trigger => !IsCanaryTrigger(trigger)))
            failures.Add("Runtime enrollment canary triggers must be a non-empty, sorted, unique exact allowlist.");
        if (!IsCanonical32ByteBase64(options.IpPseudonymKeyBase64))
            failures.Add("Runtime enrollment IP pseudonym key must be canonical base64 for exactly 32 bytes.");
        if (options.ChallengeTtlSeconds is < 30 or > 300)
            failures.Add("Runtime enrollment challenge TTL must be between 30 and 300 seconds.");
        if (options.CapabilityTtlSeconds != 120)
            failures.Add("Runtime enrollment capability TTL must be exactly 120 seconds.");
        if (options.LicenseBootstrapCapabilityTtlSeconds is < 1 or > 300)
            failures.Add("License bootstrap capability TTL must be between 1 and 300 seconds.");
        if (options.ProofClockSkewSeconds is < 1 or > 60)
            failures.Add("Runtime enrollment proof clock skew must be between 1 and 60 seconds.");
        if (options.ProofNonceRetentionHours is < 1 or > 168)
            failures.Add("Runtime enrollment proof nonce retention must be between 1 and 168 hours.");
        if (options.PendingEnrollmentLimitPerBinding != 1)
            failures.Add("Runtime enrollment pending limit per binding must be exactly 1.");
        if (options.LockTimeoutMilliseconds is < 100 or > 5000)
            failures.Add("Runtime enrollment lock timeout must be between 100 and 5000 milliseconds.");
        if (options.StatementTimeoutMilliseconds is < 500 or > 15000)
            failures.Add("Runtime enrollment statement timeout must be between 500 and 15000 milliseconds.");
        if (options.MaximumTransactionAttempts is < 1 or > 3)
            failures.Add("Runtime enrollment transaction attempts must be between 1 and 3.");
        if (options.KeyRegistryVersion < 1)
            failures.Add("Runtime enrollment key registry version must be at least 1.");

        ValidateSigning(options, failures);
        ValidateEncryption(options, failures);
        var allKeyIds = options.CapabilitySigning.Keys.Select(key => key.KeyId)
            .Concat(options.Encryption.Keys.Select(key => key.KeyId));
        if (allKeyIds.Distinct(StringComparer.Ordinal).Count() != allKeyIds.Count())
            failures.Add("Runtime key ids must be globally unique across signing and encryption purposes.");
        if (allKeyIds.Contains("global", StringComparer.Ordinal))
            failures.Add("Runtime key id 'global' is reserved for the registry version sentinel.");
        ValidateProducts(options.Products, failures);
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateSigning(RuntimeEnrollmentOptions options, List<string> failures)
    {
        var signing = options.CapabilitySigning;
        if (!IsIdentifier(signing.ActiveKeyId) || signing.Keys is not { Count: >= 2 and <= 8 })
        {
            failures.Add("Runtime capability signing keyring must contain an active key and at least one pinned validation key.");
            return;
        }
        if (!IsStrictlySorted(signing.Keys.Select(key => key.KeyId))
            || signing.Keys.Any(key => !IsIdentifier(key.KeyId)))
            failures.Add("Runtime capability signing key ids must be canonical, unique, and ordinally sorted.");

        var activeCount = 0;
        var materialDigests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in signing.Keys)
        {
            var isActive = key.KeyId == signing.ActiveKeyId;
            if (isActive)
                activeCount++;
            if (key.Role is not ("active" or "previous" or "next"))
                failures.Add("Runtime capability signing key roles must be active, previous, or next.");
            if (isActive != (key.Role == "active"))
                failures.Add("Runtime capability signing active key id and role must identify exactly one key.");
            if (!TryReadRsa3072PublicKey(key.PublicKeyPem, out var publicSpki))
            {
                failures.Add("Runtime capability public keys must be canonical RSA-3072 public keys.");
                continue;
            }
            try
            {
                if (!materialDigests.Add(Convert.ToHexStringLower(SHA256.HashData(publicSpki))))
                    failures.Add("Runtime capability signing keys must not alias the same RSA material.");
                if (isActive)
                {
                    if (!TryReadRsa3072PrivateKey(key.PrivateKeyPem, out var privateSpki))
                    {
                        failures.Add("Runtime capability active private key must be RSA-3072 and match its public key.");
                    }
                    else
                    {
                        try
                        {
                            if (!CryptographicOperations.FixedTimeEquals(publicSpki, privateSpki))
                                failures.Add("Runtime capability active private key must be RSA-3072 and match its public key.");
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(privateSpki);
                        }
                    }
                }
                else if (!string.IsNullOrEmpty(key.PrivateKeyPem))
                {
                    failures.Add("Runtime capability non-active keys must be validation-only.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicSpki);
            }
            if (key.Role == "previous"
                && (!key.RetainUntilUtc.HasValue
                    || key.RetainUntilUtc <= DateTimeOffset.UtcNow.AddSeconds(
                        options.CapabilityTtlSeconds + options.ProofClockSkewSeconds)))
                failures.Add("Runtime capability previous keys must remain valid beyond capability TTL plus clock skew.");
        }
        if (activeCount != 1 || signing.Keys.Count(key => key.Role == "next") != 1)
            failures.Add("Runtime capability signing keyring requires exactly one active and one next key.");
    }

    private static void ValidateEncryption(RuntimeEnrollmentOptions options, List<string> failures)
    {
        var encryption = options.Encryption;
        if (!IsIdentifier(encryption.ActiveKeyId) || encryption.Keys is not { Count: >= 1 and <= 16 })
        {
            failures.Add("Runtime encryption keyring is incomplete.");
            return;
        }
        if (!IsStrictlySorted(encryption.Keys.Select(key => key.KeyId))
            || encryption.Keys.Any(key => !IsIdentifier(key.KeyId) || !IsCanonical32ByteBase64(key.KeyBase64))
            || encryption.Keys.Count(key => key.KeyId == encryption.ActiveKeyId) != 1)
        {
            failures.Add("Runtime encryption keys must be canonical, unique, ordinally sorted, and contain one active key.");
        }
        var materialDigests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in encryption.Keys)
        {
            if (!IsCanonical32ByteBase64(key.KeyBase64))
                continue;
            var material = Convert.FromBase64String(key.KeyBase64);
            try
            {
                if (!materialDigests.Add(Convert.ToHexStringLower(SHA256.HashData(material))))
                    failures.Add("Runtime encryption keys must not alias the same AES material.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
            }
        }
        if (options.IpPseudonymKeyBase64.Length > 0
            && encryption.Keys.Any(key => key.KeyBase64 == options.IpPseudonymKeyBase64))
            failures.Add("Runtime encryption and IP pseudonym keys must be distinct.");
    }

    private static void ValidateProducts(IReadOnlyList<RuntimeProductCapabilityOptions>? products, List<string> failures)
    {
        if (products is not { Count: > 0 } || !IsStrictlySorted(products.Select(product => product.ProductId)))
        {
            failures.Add("Runtime capability products must be non-empty, unique, and ordinally sorted.");
            return;
        }
        foreach (var product in products)
        {
            if (!IsCanonicalUuid(product.ProductId)
                || product.Capabilities is not { Count: > 0 }
                || !IsStrictlySorted(product.Capabilities.Select(capability => capability.Audience)))
            {
                failures.Add("Runtime product capability entries must use canonical products and sorted unique audiences.");
                continue;
            }
            foreach (var capability in product.Capabilities)
            {
                if (!IsHttpsOrigin(capability.Audience)
                    || capability.Scopes is not { Count: > 0 and <= 32 }
                    || !IsStrictlySorted(capability.Scopes)
                    || capability.Scopes.Any(scope => !IsScope(scope)))
                    failures.Add("Runtime capability audiences and scopes must be canonical, unique, and ordinally sorted.");
            }
        }
    }

    private static bool IsStrictlySorted(IEnumerable<string> values)
    {
        string? previous = null;
        foreach (var value in values)
        {
            if (previous != null && string.CompareOrdinal(previous, value) >= 0)
                return false;
            previous = value;
        }
        return true;
    }

    private static bool IsHttpsOrigin(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && string.IsNullOrEmpty(uri.UserInfo)
        && uri.AbsolutePath == "/"
        && string.IsNullOrEmpty(uri.Query)
        && string.IsNullOrEmpty(uri.Fragment)
        && value == uri.GetLeftPart(UriPartial.Authority);

    private static bool IsCanonicalHttpsEndpoint(string? value, string expectedPath) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && string.IsNullOrEmpty(uri.UserInfo)
        && uri.AbsolutePath == expectedPath
        && string.IsNullOrEmpty(uri.Query)
        && string.IsNullOrEmpty(uri.Fragment)
        && value == uri.GetLeftPart(UriPartial.Authority) + expectedPath;

    private static bool IsIdentifier(string? value) =>
        value is { Length: >= 3 and <= 64 }
        && value[0] is >= 'a' and <= 'z' or >= '0' and <= '9'
        && value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-');

    private static bool IsScope(string? value) =>
        value is { Length: >= 3 and <= 64 }
        && value[0] is >= 'a' and <= 'z'
        && value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or ':' or '_' or '-');

    private static bool IsCanaryTrigger(string? value) =>
        value is { Length: >= 3 and <= 128 }
        && value.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z'
            or >= '0' and <= '9' or '_' or '.' or '-');

    private static bool IsCanonicalUuid(string? value) =>
        value != null && Guid.TryParseExact(value, "D", out var parsed) && value == parsed.ToString("D");

    private static bool TryReadRsa3072PublicKey(string? pem, out byte[] spki)
    {
        spki = [];
        if (string.IsNullOrWhiteSpace(pem) || pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            spki = rsa.ExportSubjectPublicKeyInfo();
            var exponent = rsa.ExportParameters(false).Exponent;
            return rsa.KeySize == 3072 && exponent is [0x01, 0x00, 0x01];
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    private static bool TryReadRsa3072PrivateKey(string? pem, out byte[] spki)
    {
        spki = [];
        if (string.IsNullOrWhiteSpace(pem) || !pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            spki = rsa.ExportSubjectPublicKeyInfo();
            var exponent = rsa.ExportParameters(false).Exponent;
            return rsa.KeySize == 3072 && exponent is [0x01, 0x00, 0x01];
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    private static bool IsCanonical32ByteBase64(string? value)
    {
        if (value == null)
            return false;
        try
        {
            var bytes = Convert.FromBase64String(value);
            try
            {
                return bytes.Length == 32 && value == Convert.ToBase64String(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
