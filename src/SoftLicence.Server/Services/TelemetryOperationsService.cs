using System.Security.Cryptography;
using System.Text;
using System.Data;
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
    /// <summary>
    /// <see cref="SecurityIncident.Family"/> of the per-machine record of an activation through a local licence server
    /// (TKT-003668): one row per product, canonical hardware identifier and <see cref="LicenseServerSpoofWindow"/>.
    /// </summary>
    public const string LicenseServerSpoofFamily = "LicenseServerSpoofed";

    /// <summary>
    /// Alert window of <see cref="LicenseServerSpoofFamily"/>: one alert per machine per UTC window, and the sliding
    /// period of the product budget <see cref="MaxLicenseServerSpoofAlertsPerProductPerWindow"/>.
    /// </summary>
    public static readonly TimeSpan LicenseServerSpoofWindow = TimeSpan.FromHours(24);

    /// <summary>
    /// Maximum spoofed-server alerts per product within <see cref="LicenseServerSpoofWindow"/>, same bound as the
    /// modified-binary alert of TKT-003674. Telemetry is unauthenticated: without it a sender changing hardware
    /// identifiers could flood the phone at maximum priority. Evidence is still recorded past the budget.
    /// </summary>
    public const int MaxLicenseServerSpoofAlertsPerProductPerWindow = 10;

    private static readonly TimeSpan IncidentWindow = TimeSpan.FromMinutes(15);
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly NotificationService _notifications;
    private readonly ILogger<ActivationIncidentService> _logger;

    /// <summary>Creates the service; the logger is optional so that tests may omit it.</summary>
    /// <param name="dbFactory">Factory of the licence database contexts.</param>
    /// <param name="notifications">Webhook notification dispatcher.</param>
    /// <param name="logger">Logger, or <see langword="null"/> for a no-op logger.</param>
    public ActivationIncidentService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        NotificationService notifications,
        ILogger<ActivationIncidentService>? logger = null)
    {
        _dbFactory = dbFactory;
        _notifications = notifications;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<ActivationIncidentService>.Instance;
    }

    /// <summary>
    /// Tracks activation health from client telemetry: repeated <c>LicenseActivation_NetworkError</c> events open or
    /// escalate an incident (notified once per severity), and a <c>LicenseActivation_Success</c> closes the open one.
    /// A successful activation whose reported activation host (<c>FailureHost</c> property) is local is recorded per
    /// machine and raises the critical alert <see cref="NotificationService.Triggers.SecurityLicenseServerSpoofed"/>,
    /// once per machine and window and within a product budget (TKT-003668): a genuine client only ever activates
    /// against the public SoftLicence server.
    /// </summary>
    /// <param name="productId">Product resolved from the telemetry, if any.</param>
    /// <param name="request">Telemetry event as received (untrusted client data).</param>
    /// <param name="ip">Client address observed by the server.</param>
    /// <param name="geo">Geolocation of <paramref name="ip"/>, if resolved.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    public async Task ProcessAsync(Guid? productId, TelemetryEventRequest request, string? ip, GeoInfo? geo, CancellationToken cancellationToken = default)
    {
        if (string.Equals(request.EventName, "LicenseActivation_Success", StringComparison.Ordinal))
        {
            await NotifyIfLocalLicenseServerAsync(productId, request, ip, geo, cancellationToken);
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

    /// <summary>
    /// Records a successful activation that reports a local activation host (see <see cref="IsLocalActivationHost"/>)
    /// as a <see cref="LicenseServerSpoofFamily"/> incident of its machine, and raises
    /// <see cref="NotificationService.Triggers.SecurityLicenseServerSpoofed"/> at most once per machine and
    /// <see cref="LicenseServerSpoofWindow"/>, within the product budget
    /// <see cref="MaxLicenseServerSpoofAlertsPerProductPerWindow"/> (TKT-003668, aligned on TKT-003674). The message
    /// carries the masked hardware identity, version, host, masked IP, country and ISP. No sanction is applied.
    /// </summary>
    /// <remarks>
    /// <para>The telemetry route is unauthenticated, so the alert is bounded: a repeat from the same machine in the
    /// same window only updates the incident, and past the product budget a new machine is recorded without alert
    /// (warning log). Different machines lock different keys, so concurrent first alerts may overshoot the budget by
    /// the number of racing machines; that bound is accepted, as in TKT-003674.</para>
    /// <para>Not recorded and not alerted: an event without a resolved product or with a hardware identifier that
    /// <see cref="SecurityIncidentService.CanonicalizeTelemetryHardwareId"/> rejects (warning log). A database failure
    /// is logged with its exception and sends nothing, so it can neither bypass the budget nor block the recovery of
    /// an activation incident; cancellation of the request is propagated.</para>
    /// </remarks>
    /// <param name="productId">Product resolved from the telemetry, if any.</param>
    /// <param name="request">Successful activation event (untrusted client data).</param>
    /// <param name="ip">Client address observed by the server.</param>
    /// <param name="geo">Geolocation of <paramref name="ip"/>, if resolved.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    private async Task NotifyIfLocalLicenseServerAsync(
        Guid? productId, TelemetryEventRequest request, string? ip, GeoInfo? geo, CancellationToken cancellationToken)
    {
        string? host = null;
        if (request.Properties?.TryGetValue("FailureHost", out host) != true || !IsLocalActivationHost(host)) return;
        var hardwareId = SecurityIncidentService.CanonicalizeTelemetryHardwareId(request.HardwareId);
        if (productId is not Guid product || hardwareId is null)
        {
            _logger.LogWarning(
                "LICENSE_SERVER_SPOOF_UNRECORDED: activation through local host {Host} without a resolved product or a usable hardware id; no alert.",
                Sanitize(host, 120));
            return;
        }

        bool alert;
        try
        {
            alert = await RecordLicenseServerSpoofAsync(product, hardwareId, Sanitize(request.Version, 80),
                Sanitize(ip, 50), DateTime.UtcNow, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogError(exception,
                "LICENSE_SERVER_SPOOF_RECORD_FAILED for product {ProductId}, hardware {HardwareId}; no alert sent.",
                product, TelemetryRejectionService.MaskIdentifier(hardwareId));
            return;
        }
        if (!alert) return;

        _notifications.Notify(NotificationService.Triggers.SecurityLicenseServerSpoofed,
            "ACTIVATION PAR UN SERVEUR DE LICENCES LOCAL",
            $"HWID: {TelemetryRejectionService.MaskIdentifier(hardwareId) ?? "?"}\n"
            + $"Version: {Sanitize(request.Version, 80) ?? "?"}\n"
            + $"Serveur d'activation: {Sanitize(host, 120)}\n"
            + $"IP: {TelemetryRejectionService.MaskIp(ip) ?? "?"} ({Sanitize(geo?.CountryCode, 8) ?? "??"}, {Sanitize(geo?.Isp, 160) ?? "?"})\n"
            + "Activation réussie hors du serveur SoftLicence : clé à vérifier, aucune sanction automatique.");
    }

    /// <summary>
    /// Finds or creates the <see cref="LicenseServerSpoofFamily"/> incident of one machine for the UTC window that
    /// contains <paramref name="observedAtUtc"/> and decides, in the same transaction, whether it alerts.
    /// </summary>
    /// <remarks>
    /// On PostgreSQL a transaction-scoped advisory lock on the exact ordinal key (product, family, canonical hardware,
    /// window) serializes the replicas handling the same machine, so the unique index
    /// (<c>ProductId</c>, <c>HardwareId</c>, <c>Family</c>, <c>WindowStartUtc</c>) is never hit by a duplicate. A new
    /// incident reserves the alert in <see cref="SecurityIncident.InitialNotificationSentAtUtc"/> only when the product
    /// has sent fewer than <see cref="MaxLicenseServerSpoofAlertsPerProductPerWindow"/> such alerts during the last
    /// <see cref="LicenseServerSpoofWindow"/>. Relational errors propagate to the caller.
    /// </remarks>
    /// <param name="productId">Resolved product.</param>
    /// <param name="hardwareId">Canonical hardware identifier.</param>
    /// <param name="version">Sanitized announced version, or null.</param>
    /// <param name="clientIp">Sanitized client IP (50 characters at most), or null.</param>
    /// <param name="observedAtUtc">Server reception time.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns><see langword="true"/> when this observation must send the alert.</returns>
    internal async Task<bool> RecordLicenseServerSpoofAsync(
        Guid productId, string hardwareId, string? version, string? clientIp, DateTime observedAtUtc,
        CancellationToken cancellationToken)
    {
        var windowTicks = LicenseServerSpoofWindow.Ticks;
        var windowStart = new DateTime(observedAtUtc.Ticks / windowTicks * windowTicks, DateTimeKind.Utc);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            : null;
        if (db.Database.IsNpgsql())
        {
            var lockKey = string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"{productId:D}:{LicenseServerSpoofFamily}:{hardwareId}:{windowStart:O}");
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({lockKey}, 0))", cancellationToken);
        }

        var incident = await db.SecurityIncidents.SingleOrDefaultAsync(row => row.ProductId == productId
            && row.HardwareId == hardwareId && row.Family == LicenseServerSpoofFamily
            && row.WindowStartUtc == windowStart, cancellationToken);
        var alert = false;
        if (incident != null)
        {
            incident.LastSeenUtc = observedAtUtc > incident.LastSeenUtc ? observedAtUtc : incident.LastSeenUtc;
            incident.OccurrenceCount++;
            incident.Version = version ?? incident.Version;
            incident.ClientIp = clientIp ?? incident.ClientIp;
        }
        else
        {
            var budgetFrom = observedAtUtc - LicenseServerSpoofWindow;
            var alertsInWindow = await db.SecurityIncidents.CountAsync(row => row.ProductId == productId
                && row.Family == LicenseServerSpoofFamily
                && row.InitialNotificationSentAtUtc > budgetFrom, cancellationToken);
            alert = alertsInWindow < MaxLicenseServerSpoofAlertsPerProductPerWindow;
            if (!alert)
            {
                _logger.LogWarning(
                    "Spoofed licence server alert budget reached for product {ProductId}: hardware {HardwareId} recorded without alert ({Alerts} alerts in 24 h).",
                    productId, TelemetryRejectionService.MaskIdentifier(hardwareId), alertsInWindow);
            }
            db.SecurityIncidents.Add(new SecurityIncident
            {
                ProductId = productId,
                HardwareId = hardwareId,
                Family = LicenseServerSpoofFamily,
                Severity = 5,
                WindowStartUtc = windowStart,
                WindowEndUtc = windowStart + LicenseServerSpoofWindow,
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc,
                OccurrenceCount = 1,
                Version = version,
                ClientIp = clientIp,
                IsHardwareBanned = false,
                InitialNotificationSentAtUtc = alert ? observedAtUtc : null
            });
        }

        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null) await transaction.CommitAsync(cancellationToken);
        return alert;
    }

    /// <summary>
    /// Whether an activation host reported by a client designates a local machine or network rather than the public
    /// licence server: <c>localhost</c> (or a <c>.localhost</c> name), or an IP literal that is loopback, unspecified,
    /// IPv4 private (10/8, 172.16/12, 192.168/16), IPv4 link-local, IPv6 link-local or unique-local. IPv4-mapped IPv6
    /// is evaluated as IPv4 and IPv6 brackets are accepted. Host names are compared ordinally ignoring ASCII case
    /// (DNS semantics) after trimming; any other name, including the official one redirected by a hosts file, is
    /// not considered local.
    /// </summary>
    /// <param name="host">Host as reported by the client (<c>Uri.Host</c>), or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> for a local host; <see langword="false"/> for null, empty or public hosts.</returns>
    internal static bool IsLocalActivationHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        var value = host.Trim();
        if (value.Length > 2 && value[0] == '[' && value[^1] == ']') value = value[1..^1];
        if (string.Equals(value, "localhost", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (!System.Net.IPAddress.TryParse(value, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (System.Net.IPAddress.IsLoopback(address)
            || address.Equals(System.Net.IPAddress.Any) || address.Equals(System.Net.IPAddress.IPv6Any)) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254);
        }
        return address.IsIPv6LinkLocal || address.IsIPv6UniqueLocal;
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
