using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed class AnalyticsApiKeyAuthService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public AnalyticsApiKeyAuthService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    /// <summary>
    /// Authenticates an analytics key for one scope.
    /// </summary>
    /// <returns>The key context, or null when the key is missing, unknown, inactive, expired or lacks the scope.</returns>
    public async Task<AnalyticsApiKeyAuthResult?> ValidateAsync(
        string apiKey,
        string requiredScope,
        string? clientIp,
        CancellationToken cancellationToken = default)
    {
        return (await ValidateDetailedAsync(apiKey, requiredScope, clientIp, cancellationToken)).Auth;
    }

    /// <summary>
    /// Authenticates an analytics key for one scope and reports why it failed, so callers can answer
    /// 401 for an unusable key and 403 for a valid key that lacks the endpoint scope.
    /// Usage audit (last use date and IP) is recorded only on success.
    /// </summary>
    /// <param name="apiKey">Raw key from the X-Analytics-Key header; surrounding whitespace is ignored.</param>
    /// <param name="requiredScope">Scope required by the endpoint, compared case-insensitively.</param>
    /// <param name="clientIp">Caller IP stored on success.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    public async Task<AnalyticsApiKeyValidation> ValidateDetailedAsync(
        string apiKey,
        string requiredScope,
        string? clientIp,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return new AnalyticsApiKeyValidation(null, AnalyticsApiKeyFailure.Missing, requiredScope);

        var trimmedKey = apiKey.Trim();
        var keyHash = ComputeKeyHash(trimmedKey);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var now = DateTime.UtcNow;

        var key = await db.AnalyticsApiKeys
            .Where(k => k.KeyHash == keyHash
                && k.IsActive
                && (k.ExpiresAtUtc == null || k.ExpiresAtUtc > now))
            .FirstOrDefaultAsync(cancellationToken);

        if (key == null)
            return new AnalyticsApiKeyValidation(null, AnalyticsApiKeyFailure.Invalid, requiredScope);
        if (!HasScope(key.Scopes, requiredScope))
            return new AnalyticsApiKeyValidation(null, AnalyticsApiKeyFailure.MissingScope, requiredScope);

        key.LastUsedAtUtc = now;
        key.LastUsedIp = clientIp;
        await db.SaveChangesAsync(cancellationToken);

        return new AnalyticsApiKeyValidation(
            new AnalyticsApiKeyAuthResult(key.Id, key.ProductId, key.Scopes, key.ScopeKind),
            AnalyticsApiKeyFailure.None,
            requiredScope);
    }

    public static string ComputeKeyHash(string apiKey)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey.Trim()));
        return Convert.ToHexString(bytes);
    }

    public static string BuildPrefix(string apiKey)
    {
        var trimmed = apiKey.Trim();
        return trimmed.Length <= 12 ? trimmed : trimmed[..12];
    }

    public static bool HasScope(string scopes, string requiredScope)
    {
        return scopes
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(scope => string.Equals(scope, requiredScope, StringComparison.OrdinalIgnoreCase));
    }
}

public sealed record AnalyticsApiKeyAuthResult(Guid KeyId, Guid? ProductId, string Scopes, string ScopeKind)
{
    public bool IsGlobal => string.Equals(ScopeKind, AnalyticsApiKeyScopeKinds.Global, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Why an analytics key was refused.</summary>
public enum AnalyticsApiKeyFailure
{
    /// <summary>The key was accepted.</summary>
    None,
    /// <summary>No key was sent.</summary>
    Missing,
    /// <summary>Unknown, inactive or expired key.</summary>
    Invalid,
    /// <summary>Usable key that lacks the scope required by the endpoint.</summary>
    MissingScope,
}

/// <summary>Detailed analytics key validation outcome.</summary>
/// <param name="Auth">Key context on success, otherwise null.</param>
/// <param name="Failure">Refusal reason, <see cref="AnalyticsApiKeyFailure.None"/> on success.</param>
/// <param name="RequiredScope">Scope that was required.</param>
public sealed record AnalyticsApiKeyValidation(
    AnalyticsApiKeyAuthResult? Auth,
    AnalyticsApiKeyFailure Failure,
    string RequiredScope);
