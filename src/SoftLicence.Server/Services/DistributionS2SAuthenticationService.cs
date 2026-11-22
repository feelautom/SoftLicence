using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed class DistributionS2SOptions
{
    public bool RequireHttps { get; set; } = true;
    public int ClockSkewSeconds { get; set; } = 60;
    public int NonceRetentionHours { get; set; } = 24;
    public List<DistributionS2SClientOptions> Clients { get; set; } = [];
}

public sealed class DistributionS2SClientOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public string PublicKeyPem { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public bool AllowRuntimeRecovery { get; set; }
    public bool AllowRuntimeUpgrade { get; set; }
    public bool AllowLicenseBootstrap { get; set; }
    /// <summary>Allows the dedicated client to invoke provider-owned portal deactivation.</summary>
    public bool AllowPortalDeactivation { get; set; }
    /// <summary>Allows the dedicated client to invoke provider-owned key-activation settings.</summary>
    public bool AllowLicenseKeyActivationSettings { get; set; }
    /// <summary>Allows the dedicated client to manage licence hardware exclusions.</summary>
    public bool AllowLicenseHardwareExclusions { get; set; }
    /// <summary>
    /// TKT-002919: allows the dedicated client to relink a Runtime installation after the account signed in inside
    /// the application. Strictly dedicated: the identity carries no other capability on any key rotation.
    /// </summary>
    public bool AllowRuntimeAccountRelink { get; set; }
    /// <summary>
    /// TKT-002919: distribution clients whose enrollments the dedicated relink identity may act on. Required
    /// (non-empty, canonical identifiers, without the identity itself, identical on every key rotation) exactly
    /// when <see cref="AllowRuntimeAccountRelink"/> is set, and forbidden otherwise.
    /// </summary>
    public List<string> AccountRelinkForClientIds { get; set; } = [];
    public DateTimeOffset? NotBeforeUtc { get; set; }
    public DateTimeOffset? NotAfterUtc { get; set; }
    public DateTimeOffset? RevokedAtUtc { get; set; }
    public List<string> ProductIds { get; set; } = [];
    public List<string> AllowedCidrs { get; set; } = [];
}

public sealed class DistributionS2SOptionsValidator : IValidateOptions<DistributionS2SOptions>
{
    public ValidateOptionsResult Validate(string? name, DistributionS2SOptions options)
    {
        var failures = new List<string>();
        if (!options.RequireHttps)
            failures.Add("Distribution S2S HTTPS cannot be disabled.");
        if (options.ClockSkewSeconds is < 1 or > 60)
            failures.Add("Distribution S2S clock skew must be between 1 and 60 seconds.");
        if (options.NonceRetentionHours is < 1 or > 168)
            failures.Add("Distribution S2S nonce retention must be between 1 and 168 hours.");

        var clientKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var client in options.Clients ?? [])
        {
            if (!IsIdentifier(client.ClientId) || !IsIdentifier(client.KeyId))
                failures.Add("Distribution S2S clientId and keyId must be canonical identifiers.");
            if (!clientKeys.Add($"{client.ClientId}\n{client.KeyId}"))
                failures.Add("Distribution S2S clientId/keyId pairs must be unique.");
            if (client.NotBeforeUtc.HasValue
                && client.NotAfterUtc.HasValue
                && client.NotBeforeUtc.Value >= client.NotAfterUtc.Value)
            {
                failures.Add("Distribution S2S key validity dates are incoherent.");
            }
            var productIds = client.ProductIds ?? [];
            if (productIds.Count == 0
                || productIds.Distinct(StringComparer.Ordinal).Count() != productIds.Count
                || productIds.Any(productId => !IsCanonicalLowerUuid(productId)))
            {
                failures.Add("Distribution S2S product scopes must be non-empty, unique canonical UUIDs.");
            }
            var allowedCidrs = client.AllowedCidrs ?? [];
            if (allowedCidrs.Count == 0
                || allowedCidrs.Distinct(StringComparer.Ordinal).Count() != allowedCidrs.Count
                || allowedCidrs.Any(cidr => !IsValidCidr(cidr)))
            {
                failures.Add("Distribution S2S network scopes must be non-empty, unique valid CIDRs.");
            }
            if (!IsValidPublicRsaKey(client.PublicKeyPem))
                failures.Add("Distribution S2S public keys must be RSA public keys of at least 2048 bits.");
        }

        // TKT-002919 review: a relink identity may only name distribution clients that exist in this configuration,
        // so a typo at deployment fails startup instead of answering 404 to every relink.
        var configuredClientIds = new HashSet<string>(
            (options.Clients ?? []).Select(client => client.ClientId), StringComparer.Ordinal);
        foreach (var identity in (options.Clients ?? []).GroupBy(client => client.ClientId, StringComparer.Ordinal))
        {
            // Historical rule kept as is: portal deactivation may share its identity with hardware exclusions.
            if (identity.Any(client => client.AllowPortalDeactivation)
                && identity.Any(client =>
                    !client.AllowPortalDeactivation
                    || client.AllowRuntimeRecovery
                    || client.AllowRuntimeUpgrade
                    || client.AllowLicenseBootstrap))
            {
                failures.Add("Portal deactivation requires one dedicated client identity across all key rotations.");
            }
            // TKT-002475: the new capability alone is strict, its identity carries no other capability.
            if (RequiresDedicatedIdentity(identity, client => client.AllowLicenseKeyActivationSettings))
            {
                failures.Add("License key activation settings require one dedicated client identity across all key rotations.");
            }
            // TKT-002919: decision of 31/10/2026, the account relink has its own identity and key pair, linked
            // explicitly to the distribution clients that created the enrollments it may relink.
            if (RequiresDedicatedIdentity(identity, client => client.AllowRuntimeAccountRelink))
            {
                failures.Add("Runtime account relink requires one dedicated client identity across all key rotations.");
            }
            failures.AddRange(ValidateAccountRelinkLinks(identity.Key, identity.ToList(), configuredClientIds));
            if (identity.Any(client => client.AllowLicenseHardwareExclusions)
                && identity.Any(client =>
                    !client.AllowLicenseHardwareExclusions
                    || client.AllowRuntimeRecovery
                    || client.AllowRuntimeUpgrade
                    || client.AllowLicenseBootstrap))
            {
                failures.Add("Licence hardware exclusions require one dedicated client identity across all key rotations.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// Returns whether an identity holding <paramref name="capability"/> violates the strict dedicated rule:
    /// every key rotation of that identity must carry exactly this one capability.
    /// </summary>
    private static bool RequiresDedicatedIdentity(
        IEnumerable<DistributionS2SClientOptions> identity,
        Func<DistributionS2SClientOptions, bool> capability)
    {
        if (!identity.Any(capability))
            return false;
        return identity.Any(client => CapabilityCount(client) != 1 || !capability(client));
    }

    /// <summary>
    /// Validates the TKT-002919 link between a relink identity and the distribution clients it acts for: the list is
    /// required exactly when the relink capability is set, holds unique canonical identifiers other than the identity
    /// itself, each naming a S2S client present in the configuration, and is identical (same order) on every key
    /// rotation, so a rotation cannot widen the scope silently.
    /// </summary>
    /// <param name="clientId">Identity whose key rotations are checked.</param>
    /// <param name="identity">Every configured key entry of that identity.</param>
    /// <param name="configuredClientIds">Every configured S2S client identifier, compared ordinally.</param>
    /// <returns>Configuration failures; empty when the identity is coherent.</returns>
    private static IEnumerable<string> ValidateAccountRelinkLinks(
        string clientId,
        IReadOnlyList<DistributionS2SClientOptions> identity,
        IReadOnlySet<string> configuredClientIds)
    {
        foreach (var client in identity)
        {
            var links = client.AccountRelinkForClientIds ?? [];
            if (client.AllowRuntimeAccountRelink && links.Count == 0)
                yield return "Runtime account relink requires a non-empty AccountRelinkForClientIds list.";
            if (!client.AllowRuntimeAccountRelink && links.Count > 0)
                yield return "AccountRelinkForClientIds is allowed only with AllowRuntimeAccountRelink.";
            if (links.Any(link => !IsIdentifier(link))
                || links.Distinct(StringComparer.Ordinal).Count() != links.Count
                || links.Contains(clientId, StringComparer.Ordinal))
                yield return "AccountRelinkForClientIds must hold unique canonical client identifiers other than the relink identity.";
            if (links.Any(link => !configuredClientIds.Contains(link)))
                yield return "AccountRelinkForClientIds must name configured Distribution S2S clients.";
        }
        var first = identity[0].AccountRelinkForClientIds ?? [];
        if (identity.Any(client => !(client.AccountRelinkForClientIds ?? []).SequenceEqual(first, StringComparer.Ordinal)))
            yield return "AccountRelinkForClientIds must be identical on every key rotation of the relink identity.";
    }

    /// <summary>Counts the S2S capabilities enabled on one client key entry.</summary>
    private static int CapabilityCount(DistributionS2SClientOptions client) =>
        (client.AllowRuntimeRecovery ? 1 : 0)
        + (client.AllowRuntimeUpgrade ? 1 : 0)
        + (client.AllowLicenseBootstrap ? 1 : 0)
        + (client.AllowPortalDeactivation ? 1 : 0)
        + (client.AllowLicenseKeyActivationSettings ? 1 : 0)
        + (client.AllowLicenseHardwareExclusions ? 1 : 0)
        + (client.AllowRuntimeAccountRelink ? 1 : 0);

    private static bool IsIdentifier(string? value) =>
        value is { Length: >= 3 and <= 64 }
        && value[0] is >= 'a' and <= 'z' or >= '0' and <= '9'
        && value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-');

    private static bool IsCanonicalLowerUuid(string? value) =>
        value != null
        && Guid.TryParseExact(value, "D", out var parsed)
        && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal)
        && value[14] is >= '1' and <= '5'
        && value[19] is '8' or '9' or 'a' or 'b';

    private static bool IsValidCidr(string? value)
    {
        if (value == null)
            return false;
        var parts = value.Split('/', StringSplitOptions.None);
        if (parts.Length is < 1 or > 2 || !IPAddress.TryParse(parts[0], out var address))
            return false;
        var maximumPrefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return parts.Length == 1
            || (int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
                && prefix >= 0
                && prefix <= maximumPrefix);
    }

    private static bool IsValidPublicRsaKey(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem)
            || pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa.KeySize >= 2048;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}

/// <summary>
/// Authenticated S2S caller returned by <see cref="IDistributionS2SAuthenticationService"/>: the exact configured
/// client and key, with the capabilities of that key entry. Every <c>Allow*</c> flag defaults to false, so a route
/// must check the flag it needs; since TKT-003162 no S2S route is reachable on authentication alone.
/// </summary>
/// <param name="ClientId">Configured client identifier; services scope their data by it, never by the body.</param>
/// <param name="KeyId">Configured key identifier that verified the request signature.</param>
/// <param name="AllowRuntimeRecovery">Runtime recovery routes (critical recovery, rollbacks, seat recovery).</param>
/// <param name="AllowRuntimeUpgrade">Runtime upgrade, WebSetup and authority v2 routes.</param>
/// <param name="AllowLicenseBootstrap">Licence bootstrap and refresh routes, and the installation flow
/// (<see cref="MayDriveInstallation"/>).</param>
/// <param name="AllowPortalDeactivation">Dedicated portal deactivation route.</param>
/// <param name="AllowLicenseHardwareExclusions">Dedicated licence hardware exclusion routes.</param>
/// <param name="AllowLicenseKeyActivationSettings">Dedicated key-activation setting routes.</param>
/// <param name="AllowRuntimeAccountRelink">Dedicated account relink route.</param>
/// <param name="AccountRelinkForClientIds">Distribution clients whose enrollments the relink identity may touch;
/// null or empty for every other identity.</param>
public sealed record DistributionS2SPrincipal(
    string ClientId,
    string KeyId,
    bool AllowRuntimeRecovery = false,
    bool AllowRuntimeUpgrade = false,
    bool AllowLicenseBootstrap = false,
    bool AllowPortalDeactivation = false,
    bool AllowLicenseHardwareExclusions = false,
    bool AllowLicenseKeyActivationSettings = false,
    bool AllowRuntimeAccountRelink = false,
    IReadOnlyList<string>? AccountRelinkForClientIds = null)
{
    /// <summary>
    /// TKT-003162: stable 403 error code returned by every installation route (binding, entitlement, hardware
    /// authority, source authority, enrollment prepare and reinstall) to an authenticated principal that is not a
    /// distribution client. The nonce is already consumed when it is returned; no business write has happened.
    /// </summary>
    public const string InstallationNotAuthorizedErrorCode = "installation_not_authorized";

    /// <summary>
    /// TKT-003162: whether this principal may drive the installation flow (hardware authority, entitlement issue,
    /// installation binding finalize, invalidate and source resolution, enrollment prepare and reinstall).
    /// </summary>
    /// <remarks>
    /// The flow ends with a licence bootstrap, so it reuses <see cref="AllowLicenseBootstrap"/> instead of a new
    /// capability: client 0 (the main distribution client) already holds it in production and cannot be changed by
    /// <c>deploy.ps1 -ConfigurationChange</c>, which only edits clients 1 and above. Every dedicated identity
    /// (portal deactivation, hardware exclusions, key-activation settings, account relink) is refused this right
    /// by <see cref="DistributionS2SOptionsValidator"/>, so none of them can reach these routes. Do not widen this to
    /// recovery or upgrade without re-checking that rule.
    /// </remarks>
    public bool MayDriveInstallation => AllowLicenseBootstrap;
}

public interface IDistributionS2SAuthenticationService
{
    Task<DistributionS2SPrincipal> AuthenticateAndReserveNonceAsync(
        HttpContext context,
        ReadOnlyMemory<byte> exactBody,
        string productId,
        CancellationToken cancellationToken = default);
}

public sealed class DistributionS2SAuthenticationException(string errorCode, int statusCode)
    : Exception(errorCode)
{
    public string ErrorCode { get; } = errorCode;
    public int StatusCode { get; } = statusCode;
}

public sealed class DistributionS2SAuthenticationService : IDistributionS2SAuthenticationService
{
    public const string ClientHeader = "X-Distribution-Client";
    public const string KeyIdHeader = "X-Distribution-KeyId";
    public const string TimestampHeader = "X-Distribution-Timestamp";
    public const string NonceHeader = "X-Distribution-Nonce";
    public const string SignatureHeader = "X-Distribution-Signature";
    public const string Algorithm = "PS256";

    private const string SignatureSchema = "distribution-s2s-v1";
    private static readonly Regex IdentifierPattern = new(
        "^[a-z0-9][a-z0-9._-]{2,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex LowerUuidPattern = new(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Base64UrlPattern = new(
        "^[A-Za-z0-9_-]{342,1024}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly DistributionS2SOptions _options;
    private readonly TimeProvider _timeProvider;

    public DistributionS2SAuthenticationService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IOptions<DistributionS2SOptions> options,
        TimeProvider timeProvider)
    {
        _dbFactory = dbFactory;
        _options = options.Value;
        _timeProvider = timeProvider;
    }

    public async Task<DistributionS2SPrincipal> AuthenticateAndReserveNonceAsync(
        HttpContext context,
        ReadOnlyMemory<byte> exactBody,
        string productId,
        CancellationToken cancellationToken = default)
    {
        if (!context.Request.IsHttps)
            throw Denied();

        var clientId = ReadSingleHeader(context.Request.Headers, ClientHeader);
        var keyId = ReadSingleHeader(context.Request.Headers, KeyIdHeader);
        var timestampText = ReadSingleHeader(context.Request.Headers, TimestampHeader);
        var nonce = ReadSingleHeader(context.Request.Headers, NonceHeader);
        var signatureText = ReadSingleHeader(context.Request.Headers, SignatureHeader);

        if (!IdentifierPattern.IsMatch(clientId)
            || !IdentifierPattern.IsMatch(keyId)
            || !IsCanonicalLowerUuid(productId)
            || !IsCanonicalLowerUuid(nonce)
            || !TryParseCanonicalUtc(timestampText, out var sentAtUtc)
            || !Base64UrlPattern.IsMatch(signatureText))
        {
            throw Denied();
        }

        var now = _timeProvider.GetUtcNow();
        var skew = TimeSpan.FromSeconds(Math.Clamp(_options.ClockSkewSeconds, 1, 60));
        if (sentAtUtc < now - skew || sentAtUtc > now + skew)
            throw Denied();

        var matchingClients = (_options.Clients ?? []).Where(candidate =>
            string.Equals(candidate.ClientId, clientId, StringComparison.Ordinal)
            && string.Equals(candidate.KeyId, keyId, StringComparison.Ordinal)).ToList();
        if (matchingClients.Count != 1)
            throw Denied();
        var client = matchingClients[0];
        if (!client.Enabled
            || string.IsNullOrWhiteSpace(client.PublicKeyPem)
            || client.RevokedAtUtc.HasValue
            || (client.NotBeforeUtc.HasValue && client.NotBeforeUtc.Value > now)
            || (client.NotAfterUtc.HasValue && client.NotAfterUtc.Value <= now)
            || !(client.ProductIds ?? []).Contains(productId, StringComparer.Ordinal)
            || !IsAddressAllowed(context.Connection.RemoteIpAddress, client.AllowedCidrs ?? []))
        {
            throw Denied();
        }

        byte[] signature = [];
        try
        {
            signature = DecodeBase64Url(signatureText);
            if (!string.Equals(signatureText, EncodeBase64Url(signature), StringComparison.Ordinal))
                throw Denied();
            using var rsa = RSA.Create();
            rsa.ImportFromPem(client.PublicKeyPem);
            if (rsa.KeySize < 2048 || !rsa.VerifyData(
                    Encoding.UTF8.GetBytes(BuildSignaturePayload(
                        clientId,
                        keyId,
                        context.Request.Method,
                        context.Request.Path.Value ?? string.Empty,
                        timestampText,
                        nonce,
                        exactBody.Span)),
                    signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss))
            {
                throw Denied();
            }
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException or ArgumentException)
        {
            throw Denied();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature ?? []);
        }

        await ReserveNonceAsync(clientId, nonce, sentAtUtc, now, cancellationToken);
        return new DistributionS2SPrincipal(
            clientId,
            keyId,
            client.AllowRuntimeRecovery,
            client.AllowRuntimeUpgrade,
            client.AllowLicenseBootstrap,
            client.AllowPortalDeactivation,
            client.AllowLicenseHardwareExclusions,
            client.AllowLicenseKeyActivationSettings,
            client.AllowRuntimeAccountRelink,
            client.AllowRuntimeAccountRelink ? (client.AccountRelinkForClientIds ?? []).ToArray() : []);
    }

    public static string BuildSignaturePayload(
        string clientId,
        string keyId,
        string method,
        string path,
        string timestamp,
        string nonce,
        ReadOnlySpan<byte> exactBody)
    {
        var bodyDigest = Convert.ToHexStringLower(SHA256.HashData(exactBody));
        return string.Join('\n',
            SignatureSchema,
            Algorithm,
            clientId,
            keyId,
            method,
            path,
            timestamp,
            nonce,
            bodyDigest);
    }

    private async Task ReserveNonceAsync(
        string clientId,
        string nonce,
        DateTimeOffset sentAtUtc,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var retention = TimeSpan.FromHours(Math.Clamp(_options.NonceRetentionHours, 1, 168));
        if (db.Database.IsRelational())
        {
            await db.DistributionS2SNonces
                .Where(candidate => candidate.ExpiresAtUtc <= now.UtcDateTime)
                .ExecuteDeleteAsync(cancellationToken);
        }
        else
        {
            var expired = await db.DistributionS2SNonces
                .Where(candidate => candidate.ExpiresAtUtc <= now.UtcDateTime)
                .ToListAsync(cancellationToken);
            db.DistributionS2SNonces.RemoveRange(expired);
        }
        db.DistributionS2SNonces.Add(new DistributionS2SNonce
        {
            ClientId = clientId,
            Nonce = nonce,
            SentAtUtc = sentAtUtc.UtcDateTime,
            ReservedAtUtc = now.UtcDateTime,
            ExpiresAtUtc = now.Add(retention).UtcDateTime
        });
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            throw new DistributionS2SAuthenticationException("replay_rejected", StatusCodes.Status409Conflict);
        }
    }

    private static string ReadSingleHeader(IHeaderDictionary headers, string name)
    {
        if (!headers.TryGetValue(name, out StringValues values) || values.Count != 1)
            throw Denied();
        return values[0] ?? string.Empty;
    }

    private static bool TryParseCanonicalUtc(string value, out DateTimeOffset parsed)
    {
        if (!DateTimeOffset.TryParseExact(
                value,
                UtcFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out parsed))
        {
            return false;
        }
        return string.Equals(value, parsed.UtcDateTime.ToString(UtcFormat, CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    private static bool IsCanonicalLowerUuid(string value) =>
        LowerUuidPattern.IsMatch(value)
        && Guid.TryParseExact(value, "D", out var parsed)
        && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool IsAddressAllowed(IPAddress? address, IReadOnlyCollection<string> allowedCidrs)
    {
        if (address == null || allowedCidrs.Count == 0)
            return false;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        foreach (var value in allowedCidrs)
        {
            if (TryContainsAddress(value, address))
                return true;
        }
        return false;
    }

    private static bool TryContainsAddress(string value, IPAddress address)
    {
        var parts = value.Split('/', StringSplitOptions.None);
        if (parts.Length is < 1 or > 2 || !IPAddress.TryParse(parts[0], out var network))
            return false;
        if (network.IsIPv4MappedToIPv6)
            network = network.MapToIPv4();
        if (network.AddressFamily != address.AddressFamily)
            return false;

        var networkBytes = network.GetAddressBytes();
        var addressBytes = address.GetAddressBytes();
        var totalBits = networkBytes.Length * 8;
        var prefix = totalBits;
        if (parts.Length == 2 && (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix)
                                  || prefix < 0 || prefix > totalBits))
            return false;

        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;
        for (var index = 0; index < fullBytes; index++)
        {
            if (networkBytes[index] != addressBytes[index])
                return false;
        }
        if (remainingBits == 0)
            return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[fullBytes] & mask) == (addressBytes[fullBytes] & mask);
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        return Convert.FromBase64String(base64);
    }

    private static string EncodeBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static DistributionS2SAuthenticationException Denied() =>
        new("authentication_failed", StatusCodes.Status401Unauthorized);
}
