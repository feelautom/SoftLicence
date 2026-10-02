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
    /// <summary>Gets or sets the optional runtime authority-generation signing configuration.</summary>
    public RuntimeAuthorityGenerationSigningOptions? AuthorityGenerationSigning { get; set; }
    /// <summary>Gets or sets the optional, independently selected v2 issuance mode and registry authentication data.</summary>
    public RuntimeAuthorityGenerationV2Options AuthorityGenerationV2 { get; set; } = new();
    public RuntimeEncryptionOptions Encryption { get; set; } = new();
    public List<RuntimeProductCapabilityOptions> Products { get; set; } = [];
}

/// <summary>Activates the authenticated v2 authority-generation ingress without changing v1 availability.</summary>
public sealed class RuntimeAuthorityGenerationV2Options
{
    /// <summary>Gets or sets the exact selector, either off or enabled.</summary>
    public string Mode { get; set; } = "off";
    /// <summary>Gets or sets the separately provisioned Base64 DER registry-authority SPKI pin.</summary>
    public string RegistryAuthoritySpkiBase64 { get; set; } = string.Empty;
    /// <summary>Gets or sets the canonical unpadded Base64Url signature over the configured registry snapshot.</summary>
    public string RegistrySnapshotSignatureBase64Url { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact authenticated UTC snapshot observation timestamp.</summary>
    public string RegistryObservedAtUtc { get; set; } = string.Empty;
}

/// <summary>Configures the isolated PS256 key registry used by runtime authority generations.</summary>
public sealed class RuntimeAuthorityGenerationSigningOptions
{
    /// <summary>Gets or sets the sole operational key allowed to sign new generations.</summary>
    public string ActiveSigningKeyId { get; set; } = string.Empty;

    /// <summary>Gets or sets the trusted registry snapshot identity.</summary>
    public string RegistrySnapshotId { get; set; } = string.Empty;

    /// <summary>Gets or sets the positive trusted registry snapshot version.</summary>
    public long RegistrySnapshotVersion { get; set; }

    /// <summary>Gets or sets the ordinally sorted operational and recovery key metadata.</summary>
    public List<RuntimeAuthorityGenerationKeyOptions> Keys { get; set; } = [];
}

/// <summary>Describes one RSA-2048 authority-generation key without normalizing opaque values.</summary>
public sealed class RuntimeAuthorityGenerationKeyOptions
{
    /// <summary>Gets or sets the exact key identifier.</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>Gets or sets the closed purpose, either operational or recovery.</summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>Gets or sets the closed signing domain, either generation or recovery.</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Gets or sets the only supported authority contract version, exactly 2.</summary>
    public int ContractVersion { get; set; } = 2;

    /// <summary>Gets or sets the closed lifecycle state: active, retired, or revoked.</summary>
    public string Status { get; set; } = string.Empty;

    /// <summary>Gets or sets the pinned RSA public key in PEM form.</summary>
    public string PublicKeyPem { get; set; } = string.Empty;

    /// <summary>Gets or sets private PEM only for the active operational signer.</summary>
    public string? PrivateKeyPem { get; set; }

    /// <summary>Gets or sets the inclusive UTC activation instant.</summary>
    public DateTimeOffset ActivatedAtUtc { get; set; }

    /// <summary>Gets or sets the exclusive UTC retirement instant when applicable.</summary>
    public DateTimeOffset? RetiredAtUtc { get; set; }

    /// <summary>Gets or sets the UTC revocation observation instant when applicable.</summary>
    public DateTimeOffset? RevokedAtUtc { get; set; }

    /// <summary>Gets or sets the exact revocation reason when applicable.</summary>
    public string? RevocationReason { get; set; }

    /// <summary>Gets or sets the inclusive compromise instant when known.</summary>
    public DateTimeOffset? CompromiseFromUtc { get; set; }
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
    /// Removes only wholly absent signing configuration created by fixed Compose placeholders.
    /// Non-empty or whitespace-bearing values remain untouched so validation still fails closed.
    /// </summary>
    /// <param name="options">
    /// Caller-owned bound options mutated in place. Fully empty fixed slots are removed, a wholly
    /// absent authority signing object becomes null, and an exact empty nullable
    /// <c>RevocationReason</c> placeholder becomes null. Whitespace and non-empty values are preserved.
    /// </param>
    /// <remarks>
    /// The server host and database migrator both invoke this exact post-configuration step before
    /// validating Runtime options.
    /// </remarks>
    public static void RemoveEmptySigningKeyPlaceholders(RuntimeEnrollmentOptions options)
    {
        options.CapabilitySigning.Keys.RemoveAll(key =>
            key.KeyId.Length == 0
            && key.Role.Length == 0
            && key.PublicKeyPem.Length == 0
            && string.IsNullOrEmpty(key.PrivateKeyPem)
            && key.RetainUntilUtc is null);

        if (options.AuthorityGenerationSigning is not { } authoritySigning)
            return;

        authoritySigning.Keys.RemoveAll(key =>
            key.KeyId.Length == 0
            && key.Purpose.Length == 0
            && key.Domain.Length == 0
            && key.ContractVersion == 2
            && key.Status.Length == 0
            && key.PublicKeyPem.Length == 0
            && string.IsNullOrEmpty(key.PrivateKeyPem)
            && key.ActivatedAtUtc == default
            && key.RetiredAtUtc is null
            && key.RevokedAtUtc is null
            && string.IsNullOrEmpty(key.RevocationReason)
            && key.CompromiseFromUtc is null);

        foreach (var key in authoritySigning.Keys)
        {
            if (key.RevocationReason is { Length: 0 })
                key.RevocationReason = null;
        }

        if (authoritySigning.ActiveSigningKeyId.Length == 0
            && authoritySigning.RegistrySnapshotId.Length == 0
            && authoritySigning.RegistrySnapshotVersion == 0
            && authoritySigning.Keys.Count == 0)
        {
            options.AuthorityGenerationSigning = null;
        }
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
        var authorityFailures = new List<string>();
        if (options.AuthorityGenerationSigning is not null)
            ValidateAuthorityGenerationSigning(options.AuthorityGenerationSigning, authorityFailures);
        if (options.AuthorityGenerationV2.Mode is not "off" and not "enabled")
            authorityFailures.Add("Runtime authority-generation v2 mode must be exactly 'off' or 'enabled'.");
        if (options.AuthorityGenerationV2.Mode == "enabled")
        {
            if (options.Mode != "enabled")
                authorityFailures.Add("Enabled runtime authority-generation v2 requires runtime enrollment mode 'enabled'.");
            ValidateAuthorityGenerationV2(options, authorityFailures);
        }
        if (authorityFailures.Count != 0)
            return ValidateOptionsResult.Fail(authorityFailures);
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

    /// <summary>Validates an explicitly supplied authority registry without repairing identifiers or key material.</summary>
    private static void ValidateAuthorityGenerationSigning(
        RuntimeAuthorityGenerationSigningOptions signing,
        List<string> failures)
    {
        failures.AddRange(RuntimeAuthorityGenerationConfigurationValidator.Validate(signing));
    }

    /// <summary>Validates the independent registry pin, exact snapshot time/signature, and pin/key separation.</summary>
    private static void ValidateAuthorityGenerationV2(
        RuntimeEnrollmentOptions options, List<string> failures)
    {
        if (options.AuthorityGenerationSigning is null
            || !DateTimeOffset.TryParseExact(options.AuthorityGenerationV2.RegistryObservedAtUtc, "O",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var observed)
            || observed.Offset != TimeSpan.Zero
            || !TryCanonicalPs256(options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url))
        {
            failures.Add("Enabled runtime authority-generation v2 requires canonical registry authentication metadata.");
            return;
        }
        byte[] pin;
        try
        {
            pin = Convert.FromBase64String(options.AuthorityGenerationV2.RegistryAuthoritySpkiBase64);
            using var authority = RSA.Create();
            authority.ImportSubjectPublicKeyInfo(pin, out var read);
            if (read != pin.Length || authority.KeySize != 2048) throw new CryptographicException();
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            failures.Add("Runtime authority-generation registry pin must be canonical RSA-2048 SPKI Base64.");
            return;
        }
        try
        {
            foreach (var key in options.AuthorityGenerationSigning.Keys)
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(key.PublicKeyPem);
                if (CryptographicOperations.FixedTimeEquals(pin, rsa.ExportSubjectPublicKeyInfo()))
                {
                    failures.Add("Runtime registry authority pin must be separate from operational and recovery keys.");
                    break;
                }
            }
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            failures.Add("Runtime authority-generation public key material is invalid.");
        }
        finally { CryptographicOperations.ZeroMemory(pin); }
    }

    /// <summary>Checks canonical unpadded Base64Url text for one RSA-2048 PS256 signature.</summary>
    private static bool TryCanonicalPs256(string value)
    {
        if (value.Length != 342 || value.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'
                    or '-' or '_'))) return false;
        try
        {
            var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "==");
            return bytes.Length == 256 && string.Equals(
                Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
                value, StringComparison.Ordinal);
        }
        catch (FormatException) { return false; }
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

/// <summary>Owns the single fail-closed validation used by startup and all item 2 cryptographic entry points.</summary>
internal static class RuntimeAuthorityGenerationConfigurationValidator
{
    /// <summary>Validates exact registry identity, key profile, lifecycle, ownership, ordering, and RSA material.</summary>
    /// <param name="signing">Untrusted configuration. Values are inspected ordinally and never repaired.</param>
    /// <returns>English validation failures; an empty list is the sole success result.</returns>
    internal static IReadOnlyList<string> Validate(RuntimeAuthorityGenerationSigningOptions? signing)
    {
        var failures = new List<string>();
        if (signing is null)
        {
            failures.Add("Runtime authority-generation signing configuration is absent.");
            return failures;
        }
        if (!IsIdentifier(signing.ActiveSigningKeyId)
            || !IsIdentifier(signing.RegistrySnapshotId)
            || signing.RegistrySnapshotVersion < 1
            || signing.Keys is not { Count: >= 1 and <= 8 })
        {
            failures.Add("Runtime authority-generation registry requires identifiers, a positive snapshot version, and one to eight keys.");
            return failures;
        }
        var material = new HashSet<string>(StringComparer.Ordinal);
        var activeSignerCount = 0;
        var recoveryCount = 0;
        string? previous = null;
        foreach (var key in signing.Keys)
        {
            if (previous is not null && string.CompareOrdinal(previous, key.KeyId) >= 0)
                failures.Add("Runtime authority-generation key identifiers must be ordinally sorted and unique.");
            previous = key.KeyId;
            if (!IsIdentifier(key.KeyId)
                || key.Purpose is not ("operational" or "recovery")
                || key.Domain is not ("generation" or "recovery")
                || (key.Purpose == "operational") != (key.Domain == "generation")
                || key.ContractVersion != 2
                || key.Status is not ("active" or "retired" or "revoked"))
            {
                failures.Add("Runtime authority-generation key metadata must use exact id, purpose, domain, version 2, and closed status values.");
                continue;
            }
            if (!TryReadPublic(key.PublicKeyPem, out var publicSpki))
            {
                failures.Add("Runtime authority-generation public keys must be RSA-2048 with exponent 65537.");
                continue;
            }
            try
            {
                if (!material.Add(Convert.ToHexStringLower(SHA256.HashData(publicSpki))))
                    failures.Add("Runtime authority-generation public key material must be unique.");
                var selected = string.Equals(key.KeyId, signing.ActiveSigningKeyId, StringComparison.Ordinal);
                if (selected)
                    activeSignerCount++;
                if (key.Purpose == "recovery")
                    recoveryCount++;
                if (selected && (key.Purpose != "operational" || key.Domain != "generation" || key.Status != "active"))
                    failures.Add("ActiveSigningKeyId must select an active operational generation key.");
                if (selected)
                {
                    if (!TryReadPrivate(key.PrivateKeyPem, out var privateSpki)
                        || !CryptographicOperations.FixedTimeEquals(publicSpki, privateSpki))
                        failures.Add("The selected private signing key must match its configured RSA-2048 public key.");
                    CryptographicOperations.ZeroMemory(privateSpki);
                }
                else if (!string.IsNullOrEmpty(key.PrivateKeyPem))
                {
                    failures.Add("Only ActiveSigningKeyId may own private key material.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicSpki);
            }
            ValidateLifecycle(key, failures);
        }
        if (activeSignerCount != 1 || recoveryCount == 0)
            failures.Add("Runtime authority-generation registry requires one selected signer and at least one recovery key.");
        return failures;
    }

    /// <summary>Validates UTC and complete active, retired, or revoked lifecycle relations.</summary>
    /// <param name="key">Untrusted lifecycle metadata inspected without repair.</param>
    /// <param name="failures">Caller-owned collection receiving exact validation failures.</param>
    /// <remarks>No clock policy is applied here; this validates only metadata shape and ordering.</remarks>
    private static void ValidateLifecycle(RuntimeAuthorityGenerationKeyOptions key, List<string> failures)
    {
        var allUtc = key.ActivatedAtUtc.Offset == TimeSpan.Zero
            && (!key.RetiredAtUtc.HasValue || key.RetiredAtUtc.Value.Offset == TimeSpan.Zero)
            && (!key.RevokedAtUtc.HasValue || key.RevokedAtUtc.Value.Offset == TimeSpan.Zero)
            && (!key.CompromiseFromUtc.HasValue || key.CompromiseFromUtc.Value.Offset == TimeSpan.Zero);
        if (!allUtc || key.ActivatedAtUtc == default)
        {
            failures.Add("Runtime authority-generation lifecycle instants must be explicit UTC values.");
            return;
        }
        var valid = key.Status switch
        {
            "active" => key.RetiredAtUtc is null && key.RevokedAtUtc is null
                && key.CompromiseFromUtc is null && key.RevocationReason is null,
            "retired" => key.RetiredAtUtc > key.ActivatedAtUtc && key.RevokedAtUtc is null
                && key.CompromiseFromUtc is null && key.RevocationReason is null,
            "revoked" => key.RevokedAtUtc >= key.ActivatedAtUtc
                && (!key.RetiredAtUtc.HasValue || key.RetiredAtUtc >= key.ActivatedAtUtc && key.RetiredAtUtc <= key.RevokedAtUtc)
                && key.RevocationReason is { Length: >= 1 and <= 256 }
                && (!key.CompromiseFromUtc.HasValue || key.CompromiseFromUtc >= key.ActivatedAtUtc && key.CompromiseFromUtc <= key.RevokedAtUtc),
            _ => false,
        };
        if (!valid)
            failures.Add("Runtime authority-generation lifecycle fields are inconsistent with the exact status.");
    }

    /// <summary>Checks the exact 1..128 ASCII key/snapshot identifier grammar.</summary>
    private static bool IsIdentifier(string? value) => value is { Length: >= 1 and <= 128 }
        && value[0] is >= 'a' and <= 'z' or >= '0' and <= '9'
        && value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-');

    /// <summary>Imports one public RSA-2048 key with exponent 65537 and returns copied SPKI bytes.</summary>
    /// <param name="pem">Untrusted public PEM; private labels are refused ordinally.</param>
    /// <param name="spki">Caller-owned public bytes on success, empty on failure; the validator zeroes successful temporary copies.</param>
    /// <returns>True only for RSA-2048/e65537 public material.</returns>
    private static bool TryReadPublic(string? pem, out byte[] spki)
    {
        spki = [];
        if (string.IsNullOrWhiteSpace(pem) || pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            spki = rsa.ExportSubjectPublicKeyInfo();
            return rsa.KeySize == 2048 && rsa.ExportParameters(false).Exponent is [0x01, 0x00, 0x01];
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Imports one private RSA-2048 key with exponent 65537 and returns copied public SPKI bytes.</summary>
    /// <param name="pem">Untrusted private PEM used only for public-key matching.</param>
    /// <param name="spki">Caller-owned public projection on success, empty on failure; the caller zeroes it after comparison.</param>
    /// <returns>True only for RSA-2048/e65537 private material.</returns>
    /// <remarks>The RSA instance disposes imported private material; no private PEM or private parameters are returned.</remarks>
    private static bool TryReadPrivate(string? pem, out byte[] spki)
    {
        spki = [];
        if (string.IsNullOrWhiteSpace(pem) || !pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            spki = rsa.ExportSubjectPublicKeyInfo();
            return rsa.KeySize == 2048 && rsa.ExportParameters(false).Exponent is [0x01, 0x00, 0x01];
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}
