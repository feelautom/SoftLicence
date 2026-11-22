using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;

namespace SoftLicence.Server.Services;

/// <summary>
/// Active-client protection of the IP threat score (TKT-003189, product decision of 08/11/2026):
/// before an IP is throttled (quarantine) or banned automatically, the server checks whether that IP
/// currently serves a real customer. Such an IP is never throttled or banned automatically; its
/// threshold alerts say so and the ban decision stays with an operator.
/// </summary>
public partial class SecurityService
{
    /// <summary>Audit-log window in which a successful licence check proves an active client behind an IP.</summary>
    public static readonly TimeSpan ActiveClientLookback = TimeSpan.FromDays(30);

    /// <summary>
    /// How long one verdict is reused. The quarantine check runs on every request of a scored IP, so the
    /// database is read at most once per IP and per period; a licence revoked meanwhile is seen at expiry.
    /// </summary>
    public static readonly TimeSpan ActiveClientVerdictTtl = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Upper bound of distinct hardware identifiers read for one IP. A shared office or carrier NAT has a
    /// handful; the bound keeps the query small on an address that carries unusual volume.
    /// </summary>
    private const int ActiveClientHardwareIdLimit = 64;

    /// <summary>
    /// Last verdict per IP key text and its UTC time. Static like the score cache, so every request scope
    /// shares it; entries are only replaced, never removed, and the map stays as small as the set of IPs
    /// that reached 100 points.
    /// </summary>
    private static readonly ConcurrentDictionary<string, (bool IsActive, DateTime CheckedAtUtc)> _activeClientVerdicts = new();

    /// <summary>
    /// Tells whether an IP serves an active customer: in the last 30 days it carried at least one
    /// successful licence check or activation (audit endpoint <c>CHECK</c> or <c>ACTIVATE</c>, result
    /// <c>OK</c> or <c>CREATED</c>) from a canonical hardware identifier that is, or was, bound to a licence
    /// that is still active, not revoked and not expired. A seat unlinked since then still counts: the
    /// customer of the 08/11 case had moved his licence to a new PC and his old PC kept the same IP.
    /// </summary>
    /// <remarks>
    /// The proof is computed only from server records (audit rows written by the server after its own
    /// licence decision, seats and licences), never from what the current request declares, so a
    /// replayed hardware identifier or key does not grant the protection by itself. Both textual forms of
    /// an IPv4 address (plain and IPv4-mapped) are searched. A database failure returns
    /// <see langword="false"/>, which keeps the normal protection, and is not cached.
    /// </remarks>
    /// <param name="ip">Client IP as used for the threat score key.</param>
    /// <returns><see langword="true"/> when the IP serves an active customer.</returns>
    public async Task<bool> IsActiveClientIpAsync(string ip)
    {
        var now = DateTime.UtcNow;
        if (_activeClientVerdicts.TryGetValue(ip, out var cached) && now - cached.CheckedAtUtc < ActiveClientVerdictTtl)
            return cached.IsActive;

        if (!TryGetThreatScoreKeys(ip, out _, out var keys))
            return false;

        try
        {
            var isActive = await QueryActiveClientAsync(keys, now);
            _activeClientVerdicts[ip] = (isActive, now);
            return isActive;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Active-client check for {IP} failed; the normal threat protection applies.", ip);
            return false;
        }
    }

    /// <summary>Forgets the cached active-client verdicts, so the next check reads the database again.</summary>
    /// <remarks>Used by tests that change licences between two checks of the same IP.</remarks>
    internal static void ClearActiveClientVerdicts() => _activeClientVerdicts.Clear();

    /// <summary>
    /// Runs the two database reads of <see cref="IsActiveClientIpAsync"/>: the canonical hardware
    /// identifiers with a successful licence access from the IP keys, then whether one of them is the
    /// primary identifier or a seat (current or unlinked) of a currently valid licence.
    /// </summary>
    /// <param name="ipKeys">Every persisted textual form of the IP.</param>
    /// <param name="now">Current UTC time, used for the lookback and the expiration test.</param>
    private async Task<bool> QueryActiveClientAsync(IReadOnlyList<string> ipKeys, DateTime now)
    {
        var since = now - ActiveClientLookback;
        await using var db = await _dbFactory.CreateDbContextAsync();

        // Same success definition as the zombie detection (IsAuthoritativeSuccessfulLicenseAccess): only
        // rows written after the server accepted a licence check or activation prove a real client.
        var hardwareIds = await db.AccessLogs.AsNoTracking()
            .Where(log => ipKeys.Contains(log.ClientIp)
                && log.Timestamp >= since
                && (log.Endpoint == "CHECK" || log.Endpoint == "ACTIVATE")
                && (log.ResultStatus == "OK" || log.ResultStatus == "CREATED"))
            .Select(log => log.HardwareId)
            .Distinct()
            .Take(ActiveClientHardwareIdLimit)
            .ToListAsync();

        // Only the contractual 16-character upper-case hexadecimal form is a security identity; legacy
        // display values ("8A96631C...") and "Unknown" never prove anything.
        var canonical = hardwareIds.Where(IsCanonicalHardwareId).Distinct(StringComparer.Ordinal).ToList();
        if (canonical.Count == 0)
            return false;

        // Licence and seat identifiers are compared upper-cased, as the hardware ban checks do, because
        // historical rows may hold another casing. The query runs only for scored IPs, rarely.
        return await db.Licenses.AsNoTracking().AnyAsync(license =>
            license.IsActive
            && license.RevokedAt == null
            && (license.ExpirationDate == null || license.ExpirationDate > now)
            && ((license.HardwareId != null && canonical.Contains(license.HardwareId.ToUpper()))
                || license.Seats.Any(seat => canonical.Contains(seat.HardwareId.ToUpper()))));
    }
}
