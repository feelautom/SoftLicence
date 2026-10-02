using System.Security.Cryptography;
using System.Text;

namespace SoftLicence.Server.Services;

/// <summary>Matches only exact preflight digests against product/license-scoped stored identities.</summary>
public static class PreflightDiagnosticIdentity
{
    /// <summary>Uses the same uppercase UTF-8 SHA-256 identity as the preflight authority, without trimming.</summary>
    public static string? Resolve(string digest, IEnumerable<string?> candidates)
    {
        var matches = candidates.Where(value => !string.IsNullOrEmpty(value))
            .Select(value => value!.ToUpperInvariant()).Distinct(StringComparer.Ordinal)
            .Where(value => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
                .ToLowerInvariant() == digest).Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }
}
