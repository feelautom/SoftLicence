using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed class HwidReuseAlertService
{
    private const int RecentWindowDays = 30;
    private const int MaxRowsInNotification = 8;
    private static readonly TimeSpan DedupTtl = TimeSpan.FromHours(6);
    private static readonly ConcurrentDictionary<string, DateTime> LastNotifications = new();

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly NotificationService _notifier;
    private readonly SecurityCaseContextService _securityCaseContext;
    private readonly ILogger<HwidReuseAlertService> _logger;

    public HwidReuseAlertService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        NotificationService notifier,
        SecurityCaseContextService securityCaseContext,
        ILogger<HwidReuseAlertService> logger)
    {
        _dbFactory = dbFactory;
        _notifier = notifier;
        _securityCaseContext = securityCaseContext;
        _logger = logger;
    }

    public async Task CheckAndNotifyAsync(
        Guid productId,
        string hardwareId,
        Guid currentLicenseId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
            return;

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var rows = await db.Licenses.AsNoTracking()
            .Include(l => l.Seats)
            .Where(l => l.ProductId == productId
                && (l.HardwareId == hardwareId || l.Seats.Any(s => s.HardwareId == hardwareId)))
            .Select(l => new HwidLicenseRow(
                l.Id,
                l.LicenseKey,
                l.CustomerName,
                l.CustomerEmail,
                l.IsActive,
                l.ActivationDate,
                l.CreationDate,
                l.ExpirationDate,
                l.RevokedAt,
                l.Seats
                    .Where(s => s.HardwareId == hardwareId)
                    .Select(s => (DateTime?)s.FirstActivatedAt)
                    .Min()))
            .ToListAsync(cancellationToken);

        if (rows.Count <= 1)
            return;

        var distinctEmails = rows
            .Select(r => NormalizeEmail(r.CustomerEmail))
            .Where(e => e != null)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var now = DateTime.UtcNow;
        var windowStart = now.AddDays(-RecentWindowDays);
        var recentRows = rows
            .Where(r => (r.FirstSeenUtc ?? r.CreationDate) >= windowStart)
            .ToList();

        var currentRow = rows.FirstOrDefault(r => r.LicenseId == currentLicenseId);
        var currentSeenUtc = currentRow?.FirstSeenUtc ?? currentRow?.CreationDate ?? now;
        var hasRevokedBeforeCurrent = rows.Any(r =>
            r.LicenseId != currentLicenseId
            && r.RevokedAtUtc != null
            && r.RevokedAtUtc <= currentSeenUtc);
        var hasBanBeforeCurrent = await db.BannedHardwareIds.AsNoTracking()
            .AnyAsync(b => b.HardwareId == hardwareId
                && (b.ProductId == null || b.ProductId == productId)
                && b.BannedAt <= currentSeenUtc,
                cancellationToken);

        var hasDistinctEmails = distinctEmails.Count >= 2;
        var hasRecentMultipleLicenses = recentRows.Count >= 2;
        if (!hasDistinctEmails && !hasRecentMultipleLicenses)
            return;

        var isCritical = (hasRevokedBeforeCurrent || hasBanBeforeCurrent) && currentRow is { IsActive: true };
        var severity = isCritical ? "CRITICAL" : "HIGH";
        var signature = string.Join('|',
            productId,
            hardwareId.ToUpperInvariant(),
            severity,
            string.Join(',', distinctEmails.OrderBy(e => e, StringComparer.OrdinalIgnoreCase)),
            rows.Count);

        if (IsDeduped(signature, now))
            return;

        var title = isCritical
            ? "HWID REUSE CRITICAL"
            : "HWID REUSE MULTI-ACCOUNT";

        var lines = new List<string>
        {
            $"Sévérité: {severity}",
            $"HWID: {hardwareId}",
            $"Comptes distincts: {distinctEmails.Count}",
            $"Licences associées: {rows.Count}",
            $"Licences récentes ({RecentWindowDays}j): {recentRows.Count}",
            "",
            "Licences:"
        };

        foreach (var row in rows
            .OrderByDescending(r => r.FirstSeenUtc ?? r.CreationDate)
            .Take(MaxRowsInNotification))
        {
            lines.Add(
                $"- {RedactEmail(row.CustomerEmail)} / {TrimOrPlaceholder(row.CustomerName)} / {RedactLicenseKey(row.LicenseKey)} / {GetStatus(row)} / activation {FormatDate(row.FirstSeenUtc ?? row.ActivationDateUtc ?? row.CreationDate)}");
        }

        _logger.LogWarning(
            "HWID reuse alert {Severity}: {HardwareId} has {EmailCount} accounts and {LicenseCount} licenses",
            severity,
            hardwareId,
            distinctEmails.Count,
            rows.Count);

        var securityCase = await _securityCaseContext.BuildForHardwareIdAsync(
            productId,
            hardwareId,
            NotificationService.Triggers.SecurityHwidReuseDetected,
            cancellationToken);

        lines.Insert(1, $"SecurityCaseId: {securityCase.SecurityCaseId}");

        _notifier.Notify(
            NotificationService.Triggers.SecurityHwidReuseDetected,
            title,
            string.Join('\n', lines),
            new
            {
                securityCaseId = securityCase.SecurityCaseId,
                category = "hwid-reuse",
                severity,
                productId,
                hardwareId,
                distinctEmailCount = distinctEmails.Count,
                licenseCount = rows.Count,
                recentLicenseCount = recentRows.Count,
                securityCase
            });
    }

    private static bool IsDeduped(string signature, DateTime now)
    {
        if (LastNotifications.TryGetValue(signature, out var last) && now - last < DedupTtl)
            return true;

        LastNotifications[signature] = now;

        foreach (var item in LastNotifications.Where(i => now - i.Value >= DedupTtl).ToList())
            LastNotifications.TryRemove(item.Key, out _);

        return false;
    }

    private static string? NormalizeEmail(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();

    private static string TrimOrPlaceholder(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "(sans nom)" : value.Trim();

    private static string FormatDate(DateTime date) =>
        date.ToString("yyyy-MM-dd HH:mm 'UTC'");

    private static string GetStatus(HwidLicenseRow row)
    {
        if (row.RevokedAtUtc != null)
            return "revoked";
        if (!row.IsActive)
            return "inactive";
        if (row.ExpirationDateUtc.HasValue && row.ExpirationDateUtc.Value <= DateTime.UtcNow)
            return "expired";
        return "active";
    }

    private static string RedactEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            return "(email absent)";

        var parts = email.Split('@', 2);
        var local = parts[0];
        var prefix = local.Length <= 2 ? local : local[..2];
        return $"{prefix}***@{parts[1]}";
    }

    private static string RedactLicenseKey(string? licenseKey)
    {
        if (string.IsNullOrWhiteSpace(licenseKey))
            return "(clé absente)";

        var compact = licenseKey.Replace("-", "").Replace(" ", "");
        if (compact.Length <= 8)
            return "****";

        return $"{compact[..4]}****{compact[^4..]}";
    }

    private sealed record HwidLicenseRow(
        Guid LicenseId,
        string LicenseKey,
        string CustomerName,
        string CustomerEmail,
        bool IsActive,
        DateTime? ActivationDateUtc,
        DateTime CreationDate,
        DateTime? ExpirationDateUtc,
        DateTime? RevokedAtUtc,
        DateTime? FirstSeatActivationUtc)
    {
        public DateTime? FirstSeenUtc => FirstSeatActivationUtc ?? ActivationDateUtc;
    }
}
