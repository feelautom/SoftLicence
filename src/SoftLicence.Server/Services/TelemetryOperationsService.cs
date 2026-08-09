using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class TelemetryRejectionService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly NotificationService _notifications;

    public TelemetryRejectionService(IDbContextFactory<LicenseDbContext> dbFactory, NotificationService notifications)
    {
        _dbFactory = dbFactory;
        _notifications = notifications;
    }

    public async Task RecordAsync(TelemetryRejectionCandidate candidate, CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var rejection = new TelemetryIngestionRejection
        {
            TimestampUtc = DateTime.UtcNow,
            Route = Limit(candidate.Route, 160) ?? string.Empty,
            ValidationCode = Limit(candidate.ValidationCode, 64) ?? "ModelValidationFailed",
            InvalidFields = Limit(string.Join(',', candidate.InvalidFields.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal)), 500) ?? string.Empty,
            AppName = Limit(candidate.AppName, 120),
            Version = Limit(candidate.Version, 80),
            EventName = Limit(candidate.EventName, 160),
            HardwareIdHash = HashIdentifier(candidate.HardwareId),
            HardwareIdMasked = MaskIdentifier(candidate.HardwareId),
            ClientIpMasked = MaskIp(candidate.ClientIp),
            ClientName = Limit(candidate.ClientName, 160),
            CorrelationId = Limit(candidate.CorrelationId, 80) ?? string.Empty
        };

        db.TelemetryIngestionRejections.Add(rejection);
        await db.SaveChangesAsync(cancellationToken);

        var since = DateTime.UtcNow.AddMinutes(-10);
        var repeats = await db.TelemetryIngestionRejections.CountAsync(
            x => x.TimestampUtc >= since && x.ValidationCode == rejection.ValidationCode && x.Version == rejection.Version,
            cancellationToken);
        if (repeats == 1 || repeats == 3)
        {
            rejection.Alerted = true;
            await db.SaveChangesAsync(cancellationToken);
            _notifications.Notify(NotificationService.Triggers.TelemetryRejected,
                "Telemetry payload rejected",
                $"{rejection.ValidationCode} on {rejection.Route}; version={rejection.Version ?? "unknown"}; repeats={repeats}; correlation={rejection.CorrelationId}");
        }
    }

    public static string? HashIdentifier(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var canonical = value.Trim().ToUpperInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public static string? MaskIdentifier(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var canonical = value.Trim().ToUpperInvariant();
        if (canonical.Length <= 8) return "***";
        return canonical[..4] + "…" + canonical[^4..];
    }

    public static string? MaskIp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!System.Net.IPAddress.TryParse(value.Trim(), out var ip)) return "unknown";
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4) return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";
        return string.Join(':', bytes.Take(6).Chunk(2).Select(x => Convert.ToHexString(x))) + "::/48";
    }

    private static string? Limit(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var sanitized = new string(value.Trim().Where(c => !char.IsControl(c)).ToArray());
        return sanitized[..Math.Min(sanitized.Length, max)];
    }
}

public sealed record TelemetryRejectionCandidate(
    string Route,
    string ValidationCode,
    IReadOnlyCollection<string> InvalidFields,
    string? AppName,
    string? Version,
    string? EventName,
    string? HardwareId,
    string? ClientIp,
    string? ClientName,
    string CorrelationId);

public sealed class ActivationIncidentService
{
    private static readonly TimeSpan IncidentWindow = TimeSpan.FromMinutes(15);
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly NotificationService _notifications;

    public ActivationIncidentService(IDbContextFactory<LicenseDbContext> dbFactory, NotificationService notifications)
    {
        _dbFactory = dbFactory;
        _notifications = notifications;
    }

    public async Task ProcessAsync(Guid? productId, TelemetryEventRequest request, string? ip, GeoInfo? geo, CancellationToken cancellationToken = default)
    {
        if (string.Equals(request.EventName, "LicenseActivation_Success", StringComparison.Ordinal))
        {
            await RecoverAsync(productId, request, cancellationToken);
            return;
        }
        if (!string.Equals(request.EventName, "LicenseActivation_NetworkError", StringComparison.Ordinal)) return;

        var now = DateTime.UtcNow;
        var hash = TelemetryRejectionService.HashIdentifier(request.HardwareId)!;
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var cutoff = now - IncidentWindow;
        var incident = await db.ActivationIncidents
            .Where(x => x.ProductId == productId && x.HardwareIdHash == hash && x.Status == "OPEN" && x.LastSeenUtc >= cutoff)
            .OrderByDescending(x => x.LastSeenUtc)
            .FirstOrDefaultAsync(cancellationToken);

        if (incident == null)
        {
            incident = new ActivationIncident
            {
                ProductId = productId,
                HardwareIdHash = hash,
                HardwareIdMasked = TelemetryRejectionService.MaskIdentifier(request.HardwareId) ?? "***",
                FirstSeenUtc = now,
                LastSeenUtc = now,
                RepeatCount = 1
            };
            db.ActivationIncidents.Add(incident);
        }
        else
        {
            incident.LastSeenUtc = now;
            incident.RepeatCount++;
        }

        incident.Version = Sanitize(request.Version, 80);
        incident.CountryCode = Sanitize(geo?.CountryCode, 8)?.ToUpperInvariant();
        incident.Isp = Sanitize(geo?.Isp, 160);
        incident.ClientIpMasked = TelemetryRejectionService.MaskIp(ip);
        await db.SaveChangesAsync(cancellationToken);
        var distinctDevices = await db.ActivationIncidents
            .Where(x => x.ProductId == productId && x.Status == "OPEN" && x.LastSeenUtc >= cutoff)
            .Select(x => x.HardwareIdHash).Distinct().CountAsync(cancellationToken);
        var distinctCountries = await db.ActivationIncidents
            .Where(x => x.ProductId == productId && x.Status == "OPEN" && x.LastSeenUtc >= cutoff
                && x.CountryCode != null && x.CountryCode != "??")
            .Select(x => x.CountryCode).Distinct().CountAsync(cancellationToken);
        var severity = distinctDevices >= 3 && distinctCountries >= 2
            ? "CRITICAL"
            : incident.RepeatCount >= 5 || distinctDevices >= 3
                ? "HIGH"
                : incident.RepeatCount >= 3 ? "WARNING" : "INFO";
        incident.Severity = severity;
        await db.SaveChangesAsync(cancellationToken);

        if (severity != "INFO" && !string.Equals(incident.LastNotifiedSeverity, severity, StringComparison.Ordinal))
        {
            incident.LastNotifiedSeverity = severity;
            await db.SaveChangesAsync(cancellationToken);
            _notifications.Notify(NotificationService.Triggers.ActivationIncident,
                $"{severity}: repeated activation network failures",
                $"device={incident.HardwareIdMasked}; count={incident.RepeatCount}; devices={distinctDevices}; countries={distinctCountries}; version={incident.Version ?? "unknown"}; country={incident.CountryCode ?? "??"}");
        }
    }

    private async Task RecoverAsync(Guid? productId, TelemetryEventRequest request, CancellationToken cancellationToken)
    {
        var hash = TelemetryRejectionService.HashIdentifier(request.HardwareId)!;
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var incident = await db.ActivationIncidents
            .Where(x => x.ProductId == productId && x.HardwareIdHash == hash && x.Status == "OPEN")
            .OrderByDescending(x => x.LastSeenUtc).FirstOrDefaultAsync(cancellationToken);
        if (incident == null) return;
        incident.Status = "RECOVERED";
        incident.RecoveredAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        if (incident.LastNotifiedSeverity != null)
            _notifications.Notify(NotificationService.Triggers.ActivationRecovered,
                "Activation incident recovered",
                $"device={incident.HardwareIdMasked}; failures={incident.RepeatCount}; version={Sanitize(request.Version, 80) ?? incident.Version ?? "unknown"}");
    }

    private static string? Sanitize(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var sanitized = new string(value.Trim().Where(c => !char.IsControl(c)).ToArray());
        return sanitized[..Math.Min(sanitized.Length, maxLength)];
    }
}
