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

    public async Task<AnalyticsApiKeyAuthResult?> ValidateAsync(
        string apiKey,
        string requiredScope,
        string? clientIp,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        var trimmedKey = apiKey.Trim();
        var keyHash = ComputeKeyHash(trimmedKey);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var now = DateTime.UtcNow;

        var key = await db.AnalyticsApiKeys
            .Where(k => k.KeyHash == keyHash
                && k.IsActive
                && (k.ExpiresAtUtc == null || k.ExpiresAtUtc > now))
            .FirstOrDefaultAsync(cancellationToken);

        if (key == null || !HasScope(key.Scopes, requiredScope))
            return null;

        key.LastUsedAtUtc = now;
        key.LastUsedIp = clientIp;
        await db.SaveChangesAsync(cancellationToken);

        return new AnalyticsApiKeyAuthResult(key.Id, key.ProductId, key.Scopes, key.ScopeKind);
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
