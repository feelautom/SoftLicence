using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class SecurityCaseContextService
{
    private const int RecentWindowDays = 30;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public SecurityCaseContextService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public static string BuildSecurityCaseId(Guid? productId, string? hardwareId, string trigger)
    {
        var normalizedTrigger = NormalizeToken(trigger);
        var normalizedHardwareId = string.IsNullOrWhiteSpace(hardwareId)
            ? "unknown"
            : hardwareId.Trim().ToUpperInvariant();
        var material = $"{productId?.ToString("N") ?? "global"}|{normalizedHardwareId}|{normalizedTrigger}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
        return $"sec_{normalizedTrigger}_{hash[..16]}";
    }

    public async Task<SecurityCaseContext> BuildForHardwareIdAsync(
        Guid productId,
        string hardwareId,
        string trigger,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var now = DateTime.UtcNow;
        var recentSince = now.AddDays(-RecentWindowDays);

        var licenses = await db.Licenses.AsNoTracking()
            .Include(l => l.Seats)
            .Where(l => l.ProductId == productId
                && (l.Seats.Any(s => s.HardwareId == hardwareId)
                    || (l.Seats.Count == 0 && l.HardwareId == hardwareId)))
            .ToListAsync(cancellationToken);

        var failures = await db.AccessLogs.AsNoTracking()
            .CountAsync(l => l.HardwareId == hardwareId
                && l.Timestamp >= recentSince
                && !l.IsSuccess
                && (l.Endpoint == "ACTIVATE" || l.Path.Contains("/api/activation")),
                cancellationToken);

        var activations = licenses
            .SelectMany(l => l.Seats.Where(s => s.HardwareId == hardwareId).Select(s => (DateTime?)s.FirstActivatedAt))
            .Concat(licenses.Where(l => l.Seats.Count == 0 && l.HardwareId == hardwareId).Select(l => l.ActivationDate))
            .Count(date => date.HasValue && date.Value >= recentSince);

        return new SecurityCaseContext
        {
            SecurityCaseId = BuildSecurityCaseId(productId, hardwareId, trigger),
            Trigger = trigger,
            ProductId = productId,
            HardwareId = hardwareId,
            GeneratedAtUtc = now,
            LicenseCount = licenses.Count,
            DistinctEmailCount = licenses
                .Select(l => NormalizeEmail(l.CustomerEmail))
                .Where(email => email != null)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            ActiveLicenseCount = licenses.Count(l => IsActive(l, now)),
            ExpiredLicenseCount = licenses.Count(l => l.ExpirationDate.HasValue && l.ExpirationDate.Value <= now),
            RevokedLicenseCount = licenses.Count(l => !l.IsActive || l.RevokedAt != null),
            RecentActivationCount = activations,
            RecentActivationFailureCount = failures,
            EmailsRedacted = licenses
                .Select(l => RedactEmail(l.CustomerEmail))
                .Where(email => email != null)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(email => email, StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .Select(email => email!)
                .ToList(),
            LicenseKeysRedacted = licenses
                .Select(l => RedactLicenseKey(l.LicenseKey))
                .Where(key => key != null)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(key => key, StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .Select(key => key!)
                .ToList()
        };
    }

    private static bool IsActive(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt != null)
            return false;
        return !license.ExpirationDate.HasValue || license.ExpirationDate.Value > now;
    }

    private static string NormalizeToken(string value)
    {
        var token = new string(value
            .Trim()
            .ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) ? c : '_')
            .ToArray());
        while (token.Contains("__", StringComparison.Ordinal))
            token = token.Replace("__", "_", StringComparison.Ordinal);
        return string.IsNullOrWhiteSpace(token) ? "security" : token.Trim('_');
    }

    private static string? NormalizeEmail(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();

    private static string? RedactEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            return null;

        var parts = email.Trim().Split('@', 2);
        var local = parts[0];
        var prefix = local.Length <= 2 ? local : local[..2];
        return $"{prefix}***@{parts[1]}";
    }

    private static string? RedactLicenseKey(string? licenseKey)
    {
        if (string.IsNullOrWhiteSpace(licenseKey))
            return null;

        var compact = licenseKey.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
        return compact.Length <= 8 ? $"{compact[..Math.Min(4, compact.Length)]}***" : $"{compact[..4]}****{compact[^4..]}";
    }
}
