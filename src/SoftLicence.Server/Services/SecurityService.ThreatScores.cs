using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Kind of event that added threat points, used to keep robot noise out of client alerts.</summary>
public enum ThreatScoreCategory
{
    /// <summary>Caller did not classify the event.</summary>
    Unspecified,
    /// <summary>Proactive scan pattern such as <c>.env</c> or <c>wp-admin</c>.</summary>
    Scan,
    /// <summary>Unknown route (404).</summary>
    NotFound,
    /// <summary>Authentication or authorization refusal (401/403).</summary>
    AuthFailure,
    /// <summary>Request from an IP with five or more prior bans.</summary>
    RepeatOffender,
    /// <summary>Failed admin login.</summary>
    AdminLoginFailure
}

/// <summary>
/// Request facts attached to one threat event. They only enrich the threshold alert and never change
/// the number of points. Values are copied from the audited request; the licence key is masked before
/// it leaves the server.
/// </summary>
/// <param name="Category">Event kind.</param>
/// <param name="Method">HTTP method.</param>
/// <param name="Path">Request path as audited.</param>
/// <param name="HardwareId">Hardware identifier carried by the request, when known.</param>
/// <param name="LicenseKey">Licence key carried by the request, when known.</param>
/// <param name="AppName">Audited application name, when known.</param>
/// <param name="CountryCode">GeoIP country code, when known.</param>
/// <param name="Isp">GeoIP provider, when known.</param>
public sealed record ThreatScoreContext(
    ThreatScoreCategory Category,
    string? Method = null,
    string? Path = null,
    string? HardwareId = null,
    string? LicenseKey = null,
    string? AppName = null,
    string? CountryCode = null,
    string? Isp = null);

/// <summary>One persisted threat score row as shown to operators.</summary>
/// <param name="IpAddress">IP key.</param>
/// <param name="Score">Accumulated score.</param>
/// <param name="FirstSeen">UTC time of the first scored event.</param>
/// <param name="LastHit">UTC time of the last scored event.</param>
/// <param name="IsBanned">Whether the IP currently has an active, unexpired ban.</param>
public sealed record ThreatScoreSnapshot(string IpAddress, int Score, DateTime FirstSeen, DateTime LastHit, bool IsBanned);

/// <summary>Last client identity seen from an IP in the audit log.</summary>
/// <param name="HardwareId">Hardware identifier, possibly empty.</param>
/// <param name="MaskedLicenseKey">Masked licence key, possibly empty.</param>
/// <param name="AppName">Audited application name.</param>
/// <param name="SeenAtUtc">UTC time of that audit row.</param>
public sealed record ThreatScoreKnownClient(string HardwareId, string MaskedLicenseKey, string AppName, DateTime SeenAtUtc);

/// <summary>Detailed view of one IP for the admin API and the MCP tools.</summary>
/// <param name="IpAddress">Canonical IP text.</param>
/// <param name="Scores">Persisted rows for every textual form of the IP (plain and IPv4-mapped).</param>
/// <param name="KnownClient">Last client identity seen from the IP in the last 30 days, if any.</param>
/// <param name="RecentResets">Up to ten most recent operator resets.</param>
public sealed record ThreatScoreDetails(
    string IpAddress,
    IReadOnlyList<ThreatScoreSnapshot> Scores,
    ThreatScoreKnownClient? KnownClient,
    IReadOnlyList<IpThreatScoreReset> RecentResets);

/// <summary>Outcome of an operator reset.</summary>
/// <param name="IpAddress">Canonical IP text.</param>
/// <param name="PreviousScore">Sum of the erased persisted scores.</param>
/// <param name="ResetId">Journal row identifier.</param>
public sealed record ThreatScoreResetResult(string IpAddress, int PreviousScore, Guid ResetId);

/// <summary>Raised when an operator reset request is invalid (bad IP, missing reason).</summary>
public sealed class ThreatScoreResetValidationException(string errorCode, string message) : Exception(message)
{
    /// <summary>Stable machine error code returned by the admin API.</summary>
    public string ErrorCode { get; } = errorCode;
}

public partial class SecurityService
{
    /// <summary>Scores at which one alert is sent when crossed upward (TKT-002685).</summary>
    public static readonly IReadOnlyList<int> ThreatAlertThresholds = [50, 100];

    /// <summary>Audit-log lookback used to name the client behind an IP in an alert.</summary>
    public static readonly TimeSpan KnownClientLookback = TimeSpan.FromDays(30);

    /// <summary>
    /// A score below the ban threshold with no event for this long is erased automatically and journaled
    /// (product decision, 25/10/2026, TKT-002685): a dormant score must not revive on a later event.
    /// </summary>
    public static readonly TimeSpan ThreatScoreInactivityLimit = TimeSpan.FromDays(30);

    /// <summary>Journal reason of an automatic inactivity reset.</summary>
    public const string InactivityResetReason = "inactif 30 j";

    /// <summary>Journal actor of an automatic inactivity reset.</summary>
    public const string InactivityResetActor = "system:decay";

    private static readonly ConditionalWeakTable<object, ThreatScoreLoadState> ThreatScoreLoads = new();

    /// <summary>Whether a score is erased by inactivity: below the ban threshold and idle for 30 days or more.</summary>
    /// <param name="score">Persisted score.</param>
    /// <param name="lastHitUtc">UTC time of its last event.</param>
    /// <param name="nowUtc">Current UTC time.</param>
    public static bool IsThreatScoreDecayed(int score, DateTime lastHitUtc, DateTime nowUtc) =>
        score < 200 && lastHitUtc <= nowUtc - ThreatScoreInactivityLimit;

    private sealed class ThreatScoreLoadState
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public volatile bool Loaded;
    }

    /// <summary>
    /// Loads every persisted score into memory once per database factory, so a score stored before a
    /// restart is visible to quarantine decisions and to the audit log instead of reading as zero until
    /// the next scored event. A failed load is retried on the next call.
    /// </summary>
    public async Task EnsureThreatScoresLoadedAsync()
    {
        var state = ThreatScoreLoads.GetValue(_dbFactory, _ => new ThreatScoreLoadState());
        if (state.Loaded) return;
        await state.Gate.WaitAsync();
        try
        {
            if (state.Loaded) return;
            await PurgeInactiveThreatScoresAsync(DateTime.UtcNow);
            await using var db = await _dbFactory.CreateDbContextAsync();
            var rows = await db.IpThreatScores.AsNoTracking()
                .Select(row => new { row.IpAddress, row.Score, row.LastHit })
                .ToListAsync();
            foreach (var row in rows)
            {
                // A live increment already mirrored the database total; keep it.
                _threatScores.TryAdd(row.IpAddress, (row.Score, row.LastHit));
            }
            state.Loaded = true;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Threat scores could not be loaded from the database; retrying on the next request.");
        }
        finally
        {
            state.Gate.Release();
        }
    }

    /// <summary>
    /// Adds points in the database and mirrors the returned total in memory. PostgreSQL uses one atomic
    /// upsert, so concurrent events and restarts can neither lose points nor fail on a duplicate key.
    /// If the database is unavailable the event is still counted in memory.
    /// </summary>
    /// <returns>The score before and after the event.</returns>
    private async Task<(int Previous, int Current)> IncrementThreatScoreAsync(string ip, int points, DateTime now)
    {
        try
        {
            // A dormant score is erased (and journaled) before the new event, so it cannot revive.
            await PurgeInactiveThreatScoresAsync(now, ip);
            int current;
            await using var db = await _dbFactory.CreateDbContextAsync();
            if (db.Database.IsNpgsql())
            {
                var totals = await db.Database.SqlQuery<int>($"""
                    INSERT INTO "IpThreatScores" ("IpAddress", "Score", "LastHit", "FirstSeen")
                    VALUES ({ip}, {points}, {now}, {now})
                    ON CONFLICT ("IpAddress") DO UPDATE
                    SET "Score" = "IpThreatScores"."Score" + EXCLUDED."Score",
                        "LastHit" = EXCLUDED."LastHit"
                    RETURNING "Score" AS "Value"
                    """).ToListAsync();
                current = totals.Single();
            }
            else
            {
                var row = await db.IpThreatScores.FindAsync(ip);
                if (row == null)
                {
                    row = new IpThreatScore { IpAddress = ip, Score = 0, FirstSeen = now };
                    db.IpThreatScores.Add(row);
                }
                row.Score += points;
                row.LastHit = now;
                await db.SaveChangesAsync();
                current = row.Score;
            }

            // Concurrent events may return out of order; between resets a score only grows, so keep the
            // highest database total instead of the last writer's.
            _threatScores.AddOrUpdate(ip, (current, now), (_, old) => old.Score >= current ? old : (current, now));
            return (current - points, current);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Threat score for {IP} could not be persisted; counted in memory only.", ip);
            var entry = _threatScores.AddOrUpdate(ip, (points, now), (_, old) =>
                IsThreatScoreDecayed(old.Score, old.LastHit, now) ? (points, now) : (old.Score + points, now));
            return (entry.Score - points, entry.Score);
        }
    }

    /// <summary>
    /// Sends one alert when the score crosses 50 or 100 upward, and also 200 when the IP serves an active
    /// licence, since no ban notification follows in that case (TKT-003189). An IP with no known client
    /// identity does not alert for scans and 404s, which are robot noise; its ban still alerts.
    /// </summary>
    /// <param name="ip">Scored IP key.</param>
    /// <param name="previousScore">Score before the event.</param>
    /// <param name="currentScore">Score after the event.</param>
    /// <param name="points">Points added by the event.</param>
    /// <param name="reason">Operator-readable reason of the event.</param>
    /// <param name="context">Optional request facts shown in the alert.</param>
    /// <param name="activeClient">
    /// Whether the IP serves an active licence; the alert then states that neither quarantine nor
    /// automatic ban applies. Only computed by the caller from 100 points on.
    /// </param>
    /// <remarks>Failures while building or sending the alert are logged and never reach the caller.</remarks>
    private async Task NotifyThreatThresholdCrossingAsync(
        string ip,
        int previousScore,
        int currentScore,
        int points,
        string reason,
        ThreatScoreContext? context,
        bool activeClient = false)
    {
        IEnumerable<int> thresholds = activeClient ? ThreatAlertThresholds.Append(200) : ThreatAlertThresholds;
        var crossed = thresholds.Where(threshold => previousScore < threshold && currentScore >= threshold)
            .DefaultIfEmpty(0).Max();
        if (crossed == 0) return;

        try
        {
            var knownClient = await FindKnownClientAsync(ip, context);
            var category = context?.Category ?? ThreatScoreCategory.Unspecified;
            if (knownClient == null && category is ThreatScoreCategory.Scan or ThreatScoreCategory.NotFound)
                return;

            var title = activeClient
                ? $"⚠️ Score de menace {currentScore} : client actif, ni quarantaine ni ban (IP {ip})"
                : crossed >= 100
                    ? $"⚠️ Score de menace {currentScore} : quarantaine (IP {ip})"
                    : $"⚠️ Score de menace {currentScore} (IP {ip})";
            var effect = activeClient
                ? "Effet : aucun. Cette IP a réussi une vérification de licence active depuis moins de 30 jours : " +
                  "ni ralentissement ni ban automatique. À vérifier ; ban manuel possible depuis la page Audit.\n"
                : currentScore >= 100
                    ? "Effet : chaque requête hors Runtime est ralentie de 5 s ou plus.\n" +
                      "Ban automatique à 200. "
                    : "Ban automatique à 200. ";
            var location = string.Join(", ", new[] { context?.CountryCode, context?.Isp }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
            var route = string.IsNullOrWhiteSpace(context?.Path)
                ? "inconnue"
                : $"{context!.Method} {context.Path}".Trim();
            var client = knownClient == null
                ? "aucune identité client connue pour cette IP"
                : $"HWID {Display(knownClient.HardwareId)}, licence {Display(knownClient.MaskedLicenseKey)}, " +
                  $"application {Display(knownClient.AppName)}, vu le {knownClient.SeenAtUtc:yyyy-MM-dd HH:mm} UTC";
            var message =
                $"IP : {ip}{(location.Length > 0 ? $" ({location})" : string.Empty)}\n" +
                $"Score : {previousScore} -> {currentScore} (+{points})\n" +
                $"Route : {route}\n" +
                $"Raison : {reason}\n" +
                $"Client : {client}\n" +
                effect +
                "Remise à zéro : page Audit ou outil MCP reset_ip_threat_score.";

            _logger.LogWarning(
                "Threat score threshold {Threshold} crossed for {IP}: {Previous} -> {Current}, route {Route}, reason {Reason}, known client {KnownClient}, active client {ActiveClient}.",
                crossed, ip, previousScore, currentScore, route, reason, knownClient != null, activeClient);
            _notifier.Notify(NotificationService.Triggers.SecurityThreatScoreRaised, title, message, new
            {
                ip,
                previousScore,
                currentScore,
                threshold = crossed,
                activeClient,
                points,
                reason,
                route,
                countryCode = context?.CountryCode,
                isp = context?.Isp,
                hardwareId = knownClient?.HardwareId,
                licenseKey = knownClient?.MaskedLicenseKey,
                appName = knownClient?.AppName
            });
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Threat score alert for {IP} could not be prepared.", ip);
        }

        static string Display(string value) => string.IsNullOrWhiteSpace(value) ? "inconnu(e)" : value;
    }

    /// <summary>
    /// Names the client behind an IP: the current request facts first, then the most recent audit row
    /// from the same IP in the last 30 days that carried a hardware identifier or a licence key.
    /// </summary>
    private async Task<ThreatScoreKnownClient?> FindKnownClientAsync(string ip, ThreatScoreContext? context)
    {
        if (IsKnownIdentity(context?.HardwareId) || IsKnownIdentity(context?.LicenseKey))
        {
            return new ThreatScoreKnownClient(
                IsKnownIdentity(context!.HardwareId) ? context.HardwareId! : string.Empty,
                MaskLicenseKey(context.LicenseKey),
                context.AppName ?? string.Empty,
                DateTime.UtcNow);
        }

        var since = DateTime.UtcNow - KnownClientLookback;
        await using var db = await _dbFactory.CreateDbContextAsync();
        var row = await db.AccessLogs.AsNoTracking()
            .Where(log => log.ClientIp == ip && log.Timestamp >= since
                && ((log.HardwareId != "" && log.HardwareId != "Unknown") || log.LicenseKey != ""))
            .OrderByDescending(log => log.Timestamp)
            .Select(log => new { log.HardwareId, log.LicenseKey, log.AppName, log.Timestamp })
            .FirstOrDefaultAsync();
        return row == null
            ? null
            : new ThreatScoreKnownClient(
                IsKnownIdentity(row.HardwareId) ? row.HardwareId : string.Empty,
                MaskLicenseKey(row.LicenseKey),
                row.AppName,
                row.Timestamp);
    }

    private static bool IsKnownIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && !string.Equals(value, "Unknown", StringComparison.Ordinal);

    /// <summary>Keeps the first and last four characters of a licence key; short keys are fully hidden.</summary>
    /// <param name="licenseKey">Raw licence key, possibly empty.</param>
    /// <returns>A masked key, or an empty string.</returns>
    public static string MaskLicenseKey(string? licenseKey)
    {
        if (string.IsNullOrWhiteSpace(licenseKey)) return string.Empty;
        var key = licenseKey.Trim();
        return key.Length <= 12 ? "***" : $"{key[..4]}...{key[^4..]}";
    }

    /// <summary>
    /// Parses an operator-supplied IP and returns its canonical text plus every key form the
    /// forwarded-headers middleware can persist for the same address (plain IPv4 and IPv4-mapped IPv6).
    /// </summary>
    /// <param name="input">Operator input.</param>
    /// <param name="canonical">Canonical text (IPv4-mapped addresses are shown as IPv4).</param>
    /// <param name="keys">Distinct persisted key candidates.</param>
    /// <returns><see langword="false"/> when the input is not an IP address.</returns>
    public static bool TryGetThreatScoreKeys(string? input, out string canonical, out IReadOnlyList<string> keys)
    {
        canonical = string.Empty;
        keys = [];
        if (string.IsNullOrWhiteSpace(input) || input.Trim().Length > 64
            || !IPAddress.TryParse(input.Trim(), out var parsed))
            return false;

        var plain = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        canonical = plain.ToString();
        var candidates = new List<string> { canonical };
        if (plain.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            candidates.Add(plain.MapToIPv6().ToString());
        keys = candidates.Distinct(StringComparer.Ordinal).ToList();
        return true;
    }

    /// <summary>Lists persisted scores at or above a minimum, highest first.</summary>
    /// <param name="minScore">Minimum score, clamped to 0 or more.</param>
    /// <param name="limit">Maximum rows, clamped to 1..500.</param>
    public async Task<IReadOnlyList<ThreatScoreSnapshot>> ListThreatScoresAsync(int minScore, int limit)
    {
        minScore = Math.Max(0, minScore);
        limit = Math.Clamp(limit, 1, 500);
        var now = DateTime.UtcNow;
        await using var db = await _dbFactory.CreateDbContextAsync();
        var rows = await db.IpThreatScores.AsNoTracking()
            .Where(row => row.Score >= minScore)
            .OrderByDescending(row => row.Score).ThenByDescending(row => row.LastHit)
            .Take(limit)
            .ToListAsync();
        var ips = rows.Select(row => row.IpAddress).ToList();
        var banned = await db.BannedIps.AsNoTracking()
            .Where(ban => ips.Contains(ban.IpAddress) && ban.IsActive && (ban.ExpiresAt == null || ban.ExpiresAt > now))
            .Select(ban => ban.IpAddress)
            .ToListAsync();
        var bannedSet = banned.ToHashSet(StringComparer.Ordinal);
        return rows.Select(row => new ThreatScoreSnapshot(
            row.IpAddress, row.Score, row.FirstSeen, row.LastHit, bannedSet.Contains(row.IpAddress))).ToList();
    }

    /// <summary>Returns the persisted score rows, last known client and recent resets of one IP.</summary>
    /// <param name="ipInput">Operator-supplied IP.</param>
    /// <exception cref="ThreatScoreResetValidationException">The input is not an IP address.</exception>
    public async Task<ThreatScoreDetails> GetThreatScoreDetailsAsync(string ipInput)
    {
        if (!TryGetThreatScoreKeys(ipInput, out var canonical, out var keys))
            throw new ThreatScoreResetValidationException("invalid_ip", "ip must be an IPv4 or IPv6 address.");

        var now = DateTime.UtcNow;
        await using var db = await _dbFactory.CreateDbContextAsync();
        var rows = await db.IpThreatScores.AsNoTracking().Where(row => keys.Contains(row.IpAddress)).ToListAsync();
        var banned = await db.BannedIps.AsNoTracking()
            .Where(ban => keys.Contains(ban.IpAddress) && ban.IsActive && (ban.ExpiresAt == null || ban.ExpiresAt > now))
            .Select(ban => ban.IpAddress)
            .ToListAsync();
        var resets = await db.IpThreatScoreResets.AsNoTracking()
            .Where(reset => keys.Contains(reset.IpAddress))
            .OrderByDescending(reset => reset.ResetAtUtc)
            .Take(10)
            .ToListAsync();
        ThreatScoreKnownClient? knownClient = null;
        foreach (var key in keys)
        {
            knownClient = await FindKnownClientAsync(key, null);
            if (knownClient != null) break;
        }
        return new ThreatScoreDetails(
            canonical,
            rows.Select(row => new ThreatScoreSnapshot(
                row.IpAddress, row.Score, row.FirstSeen, row.LastHit, banned.Contains(row.IpAddress))).ToList(),
            knownClient,
            resets);
    }

    /// <summary>
    /// Erases every score below 200 whose last event is 30 days old or more, in the database and in memory,
    /// and journals each one in <c>IpThreatScoreResets</c> with the reason <c>inactif 30 j</c>. On
    /// PostgreSQL the delete and the journal are one statement, and the delete re-checks the condition, so
    /// a score that received an event meanwhile is kept. Failures are logged and retried on the next call.
    /// </summary>
    /// <param name="nowUtc">Current UTC time.</param>
    /// <param name="ip">Optional exact persisted key to limit the purge to one IP.</param>
    /// <returns>The number of erased scores.</returns>
    public async Task<int> PurgeInactiveThreatScoresAsync(DateTime nowUtc, string? ip = null)
    {
        var cutoff = nowUtc - ThreatScoreInactivityLimit;
        try
        {
            List<string> purged;
            await using var db = await _dbFactory.CreateDbContextAsync();
            if (db.Database.IsNpgsql())
            {
                purged = ip == null
                    ? await db.Database.SqlQuery<string>($"""
                        WITH purged AS (
                            DELETE FROM "IpThreatScores"
                            WHERE "Score" < 200 AND "LastHit" <= {cutoff}
                            RETURNING "IpAddress", "Score")
                        INSERT INTO "IpThreatScoreResets" ("Id", "IpAddress", "PreviousScore", "ResetAtUtc", "ResetBy", "Reason")
                        SELECT gen_random_uuid(), "IpAddress", "Score", {nowUtc}, {InactivityResetActor}, {InactivityResetReason}
                        FROM purged
                        RETURNING "IpAddress" AS "Value"
                        """).ToListAsync()
                    : await db.Database.SqlQuery<string>($"""
                        WITH purged AS (
                            DELETE FROM "IpThreatScores"
                            WHERE "IpAddress" = {ip} AND "Score" < 200 AND "LastHit" <= {cutoff}
                            RETURNING "IpAddress", "Score")
                        INSERT INTO "IpThreatScoreResets" ("Id", "IpAddress", "PreviousScore", "ResetAtUtc", "ResetBy", "Reason")
                        SELECT gen_random_uuid(), "IpAddress", "Score", {nowUtc}, {InactivityResetActor}, {InactivityResetReason}
                        FROM purged
                        RETURNING "IpAddress" AS "Value"
                        """).ToListAsync();
            }
            else
            {
                var query = db.IpThreatScores.Where(row => row.Score < 200 && row.LastHit <= cutoff);
                if (ip != null) query = query.Where(row => row.IpAddress == ip);
                var rows = await query.ToListAsync();
                foreach (var row in rows)
                {
                    db.IpThreatScoreResets.Add(new IpThreatScoreReset
                    {
                        IpAddress = row.IpAddress,
                        PreviousScore = row.Score,
                        ResetAtUtc = nowUtc,
                        ResetBy = InactivityResetActor,
                        Reason = InactivityResetReason
                    });
                }
                db.IpThreatScores.RemoveRange(rows);
                await db.SaveChangesAsync();
                purged = rows.Select(row => row.IpAddress).ToList();
            }

            foreach (var key in purged)
            {
                // Remove only a mirror that is itself still dormant; a concurrent event keeps its entry.
                if (_threatScores.TryGetValue(key, out var entry) && IsThreatScoreDecayed(entry.Score, entry.LastHit, nowUtc))
                    _threatScores.TryRemove(new KeyValuePair<string, (int Score, DateTime LastHit)>(key, entry));
            }
            if (purged.Count > 0)
                _logger.LogInformation(
                    "Threat score inactivity reset: {Count} score(s) below 200 without event for {Days} days erased and journaled.",
                    purged.Count, ThreatScoreInactivityLimit.TotalDays);
            return purged.Count;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Inactive threat scores could not be purged; retrying later.");
            return 0;
        }
    }

    /// <summary>
    /// Erases the threat score of one IP in the database and in memory, without restart, and journals
    /// the reset in <c>IpThreatScoreResets</c> in the same transaction. Bans and the ban count used as
    /// repeat-offender multiplier are not changed: lifting a ban stays a separate decision.
    /// </summary>
    /// <param name="ipInput">Operator-supplied IP (plain or IPv4-mapped forms are both erased).</param>
    /// <param name="actor">Who asks for the reset.</param>
    /// <param name="reason">Mandatory operator reason.</param>
    /// <exception cref="ThreatScoreResetValidationException">Invalid IP, actor or reason.</exception>
    public async Task<ThreatScoreResetResult> ResetThreatScoreAsync(string ipInput, string actor, string reason)
    {
        if (!TryGetThreatScoreKeys(ipInput, out var canonical, out var keys))
            throw new ThreatScoreResetValidationException("invalid_ip", "ip must be an IPv4 or IPv6 address.");
        reason = reason?.Trim() ?? string.Empty;
        if (reason.Length is 0 or > 1000)
            throw new ThreatScoreResetValidationException("invalid_reason", "reason is required and must be at most 1000 characters.");
        actor = string.IsNullOrWhiteSpace(actor) ? "unknown" : actor.Trim();
        if (actor.Length > 200) actor = actor[..200];

        await using var db = await _dbFactory.CreateDbContextAsync();
        var rows = await db.IpThreatScores.Where(row => keys.Contains(row.IpAddress)).ToListAsync();
        var previous = rows.Sum(row => row.Score);
        db.IpThreatScores.RemoveRange(rows);
        var journal = new IpThreatScoreReset
        {
            IpAddress = canonical,
            PreviousScore = previous,
            ResetAtUtc = DateTime.UtcNow,
            ResetBy = actor,
            Reason = reason
        };
        db.IpThreatScoreResets.Add(journal);
        await db.SaveChangesAsync();

        foreach (var key in keys)
            _threatScores.TryRemove(key, out _);

        _logger.LogWarning(
            "THREAT SCORE RESET: {IP} score {PreviousScore} erased by {Actor}, reason {Reason}, journal {ResetId}.",
            canonical, previous, actor, reason, journal.Id);
        return new ThreatScoreResetResult(canonical, previous, journal.Id);
    }
}
