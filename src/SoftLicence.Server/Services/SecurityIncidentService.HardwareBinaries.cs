using System.Data;
using System.Globalization;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Outcome of one per-hardware ApprovedBinaries mismatch observation (TKT-003674).
/// </summary>
/// <param name="IncidentId">Per-hardware incident that received the observation.</param>
/// <param name="HardwareIdPrefix">First 16 characters of the canonical hardware identifier, the only form logged.</param>
/// <param name="LicenseId">Licence attached to the hardware, or <see langword="null"/> when none is known.</param>
/// <param name="UnapprovedComponentCount">
/// Number of mismatched components whose fingerprint belongs to no approved build of the product. Zero means every
/// mismatched fingerprint is an approved build of another version (mixed or interrupted installation): recorded, never
/// counted toward the alert.
/// </param>
/// <param name="CountedStart">Whether the observation was counted as a new application start.</param>
/// <param name="StartsInWindow">Counted starts of the incident in the 24 hours ending at its latest known start (0 when the observation has no unapproved fingerprint).</param>
/// <param name="AlertSent">Whether this observation reserved and sent the single alert of the incident.</param>
public sealed record HardwareBinaryMismatchOutcome(
    Guid IncidentId,
    string HardwareIdPrefix,
    Guid? LicenseId,
    int UnapprovedComponentCount,
    bool CountedStart,
    int StartsInWindow,
    bool AlertSent);

/// <summary>
/// TKT-003674: per-hardware tracking of modified T-IA Connect binaries reported by public telemetry. Decision of
/// 12/11/2026: no ban and no automatic blocking, only an immediate alert on the phone naming the customer, licence,
/// hardware and IP, once per machine. Public telemetry is unauthenticated, so this evidence never drives a sanction.
/// </summary>
public partial class SecurityIncidentService
{
    /// <summary>Incident family of the per-hardware ApprovedBinaries mismatch incident (one incident per product and hardware).</summary>
    public const string ApprovedBinaryHardwareMismatchFamily = "ApprovedBinaryHardwareMismatch";

    /// <summary>Distinct starts with unapproved fingerprints needed inside <see cref="TamperedStartWindow"/> to alert.</summary>
    public const int TamperedStartThreshold = 3;

    /// <summary>Sliding window of the alert threshold.</summary>
    public static readonly TimeSpan TamperedStartWindow = TimeSpan.FromHours(24);

    /// <summary>
    /// Two observations of the same incident closer than this gap belong to the same application start: one start
    /// sends several fingerprint-bearing events (<c>Startup_AppStarted</c>, <c>Startup_PrereqSnapshot</c>) within
    /// seconds, and counting them separately would reach the threshold with a single launch.
    /// </summary>
    public static readonly TimeSpan SameStartupGap = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum distinct fingerprints kept per per-hardware incident. A patched machine observed in production produced
    /// 18 EXE and 8 DLL fingerprints in 8 days; the bound keeps an unauthenticated sender from growing the table.
    /// </summary>
    public const int MaxEvidencePerHardwareIncident = 32;

    /// <summary>
    /// Maximum modified-binary alerts per product within <see cref="TamperedStartWindow"/>. Bounds the phone alerts an
    /// unauthenticated sender can trigger by inventing hardware identifiers; the evidence is still recorded past it.
    /// </summary>
    public const int MaxTamperedAlertsPerProductPerWindow = 10;

    /// <summary>Number of hardware identifier characters allowed in logs (#1360: never the full identifier).</summary>
    public const int LoggedHardwareIdPrefixLength = 16;

    /// <summary>Number of fingerprint characters shown in logs and alerts: never a full fingerprint.</summary>
    public const int ShownFingerprintPrefixLength = 12;

    /// <summary>
    /// Validates and canonicalizes a telemetry hardware identifier for per-hardware incidents: trimmed, upper-case
    /// invariant, 8 to 64 characters of <c>[0-9A-Z_-]</c>. The canonical production form is 16 upper-case hexadecimal
    /// characters, which this keeps unchanged; the wider alphabet only avoids dropping the evidence of a client that
    /// alters its identifier format. Lookups against licences compare the same upper-case form.
    /// </summary>
    /// <param name="hardwareId">Untrusted identifier from telemetry.</param>
    /// <returns>The canonical identifier, or <see langword="null"/> when it cannot identify a machine.</returns>
    public static string? CanonicalizeTelemetryHardwareId(string? hardwareId)
    {
        var trimmed = hardwareId?.Trim();
        if (trimmed is null || trimmed.Length is < 8 or > 64)
            return null;
        var canonical = trimmed.ToUpperInvariant();
        return canonical.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'Z' or '_' or '-')
            ? canonical
            : null;
    }

    /// <summary>
    /// Records one telemetry start whose fingerprints differ from the authoritative baseline of the announced version
    /// into the incident of that machine, and sends the single <see cref="NotificationService.Triggers.SecurityBinaryTampered"/>
    /// alert of the incident once <see cref="TamperedStartThreshold"/> distinct starts carrying a fingerprint that
    /// belongs to no approved build of the product fall within <see cref="TamperedStartWindow"/>.
    /// </summary>
    /// <remarks>
    /// <para>Only mismatch verdicts reach this method: missing evidence (<c>required_key_missing</c>), invalid evidence,
    /// unavailable capture and versions without an authoritative baseline never do, so they can neither count nor alert.</para>
    /// <para>A mismatched fingerprint that is an approved build of another version of the same product and component
    /// (interrupted update, mixed installation) is kept as evidence but does not count. Approved builds exclude legacy
    /// <c>auto</c> rows, which are untrusted client-derived state.</para>
    /// <para>One incident per product and hardware, never reopened: after the alert the incident keeps counting starts
    /// but never notifies again (no daily repetition). Concurrent replicas are serialized by a PostgreSQL advisory
    /// transaction lock on the incident key inside a serializable transaction, retried on relational conflicts; the
    /// alert reservation (<see cref="SecurityIncident.InitialNotificationSentAtUtc"/>) is committed before the
    /// fire-and-forget notification, so a failed webhook loses that alert rather than repeating it. At most
    /// <see cref="MaxTamperedAlertsPerProductPerWindow"/> alerts are sent per product and 24 hours.</para>
    /// <para>The licence is resolved by the server (telemetry carries no licence key): the most recently checked-in
    /// seat of the product with this hardware, active seats first, else a licence whose primary hardware matches.</para>
    /// </remarks>
    /// <param name="productId">Product resolved from the telemetry application name.</param>
    /// <param name="hardwareId">Untrusted telemetry hardware identifier; see <see cref="CanonicalizeTelemetryHardwareId"/>.</param>
    /// <param name="version">Version announced by the client, already validated by the baseline lookup.</param>
    /// <param name="clientIp">Server-observed client IP, or <see langword="null"/>.</param>
    /// <param name="countryCode">GeoIP country code of the IP for the alert text, or <see langword="null"/>.</param>
    /// <param name="isp">GeoIP ISP of the IP for the alert text, or <see langword="null"/>.</param>
    /// <param name="mismatches">Mismatched fingerprints by component key (<c>FP_EXE</c>, <c>FP_DLL</c>, <c>FP_CORE</c>).</param>
    /// <param name="observedAtUtc">Observation time; now when omitted.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns>The outcome, or <see langword="null"/> when the hardware identifier is unusable (nothing persisted).</returns>
    /// <exception cref="ArgumentException">A component key or fingerprint is invalid; nothing is persisted.</exception>
    public virtual async Task<HardwareBinaryMismatchOutcome?> RecordHardwareBinaryMismatchAsync(
        Guid productId,
        string? hardwareId,
        string version,
        string? clientIp,
        string? countryCode,
        string? isp,
        IReadOnlyDictionary<string, string> mismatches,
        DateTime? observedAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        var canonicalHardwareId = CanonicalizeTelemetryHardwareId(hardwareId);
        if (canonicalHardwareId == null)
            return null;

        // Same validation as the public aggregate: exact component keys, 64 hexadecimal characters, upper-cased.
        var evidence = CanonicalizeEvidence(mismatches);
        var observedAt = DateTime.SpecifyKind(observedAtUtc ?? DateTime.UtcNow, DateTimeKind.Utc);
        var storedIp = clientIp is { Length: > 50 } ? clientIp[..50] : clientIp;
        var storedVersion = version.Length > 80 ? version[..80] : version;

        // Read-only lookups run before the serializable transaction to keep its predicate locks narrow.
        var unapproved = await FindUnapprovedFingerprintsAsync(productId, evidence, cancellationToken);
        var license = await FindLicenseForHardwareAsync(productId, canonicalHardwareId, cancellationToken);

        var incidentKey = string.Create(
            CultureInfo.InvariantCulture,
            $"{productId:D}:{canonicalHardwareId}:{ApprovedBinaryHardwareMismatchFamily}");
        var incidentLock = _incidentLocks.GetOrAdd(incidentKey, static _ => new SemaphoreSlim(1, 1));
        await incidentLock.WaitAsync(cancellationToken);
        try
        {
            PersistedHardwareMismatch persisted = null!;
            for (var attempt = 1; attempt <= MaxPersistenceAttempts; attempt++)
            {
                try
                {
                    persisted = await PersistHardwareMismatchOnceAsync(
                        productId, canonicalHardwareId, storedVersion, storedIp, license?.LicenseId, evidence,
                        unapproved.Count > 0, observedAt, incidentKey, cancellationToken);
                    break;
                }
                catch (Exception ex) when (attempt < MaxPersistenceAttempts && IsRetryablePersistenceConflict(ex))
                {
                    _logger.LogWarning(ex,
                        "Retrying per-hardware ApprovedBinaries incident persistence after relational conflict; attempt={Attempt}/{MaxAttempts}",
                        attempt,
                        MaxPersistenceAttempts);
                    await Task.Delay(TimeSpan.FromMilliseconds(10 * attempt), cancellationToken);
                }
            }

            if (persisted.ShouldAlert)
            {
                var (title, message) = BuildTamperedAlert(
                    persisted, canonicalHardwareId, storedVersion, storedIp, countryCode, isp, license, unapproved);
                _notifications.Notify(
                    NotificationService.Triggers.SecurityBinaryTampered,
                    title,
                    message,
                    new
                    {
                        incidentId = persisted.IncidentId,
                        productId,
                        hardwareId = canonicalHardwareId,
                        licenseId = license?.LicenseId,
                        version = storedVersion,
                        clientIp = storedIp,
                        startsInWindow = persisted.StartsInWindow
                    });
            }

            return new HardwareBinaryMismatchOutcome(
                persisted.IncidentId,
                canonicalHardwareId.Length <= LoggedHardwareIdPrefixLength
                    ? canonicalHardwareId
                    : canonicalHardwareId[..LoggedHardwareIdPrefixLength],
                license?.LicenseId,
                unapproved.Count,
                persisted.CountedStart,
                persisted.StartsInWindow,
                persisted.ShouldAlert);
        }
        finally
        {
            incidentLock.Release();
            if (incidentLock.CurrentCount == 1)
                _incidentLocks.TryRemove(new KeyValuePair<string, SemaphoreSlim>(incidentKey, incidentLock));
        }
    }

    /// <summary>
    /// Keeps the mismatched fingerprints that are not an approved build of any version of the product for the same
    /// component. Approved hashes are documented as lowercase but legacy admin rows may differ, so both sides are
    /// compared after <see cref="ApprovedBinaryService.NormalizeSha256"/> in memory; the product's rows are a few
    /// hundred and this runs only on mismatch evidence, which is rare.
    /// </summary>
    /// <param name="productId">Product whose approved builds are searched.</param>
    /// <param name="evidence">Canonical mismatched fingerprints (upper-case hexadecimal) by component key.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns>The unapproved subset, by component key.</returns>
    private async Task<IReadOnlyDictionary<string, string>> FindUnapprovedFingerprintsAsync(
        Guid productId,
        IReadOnlyDictionary<string, string> evidence,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var keys = evidence.Keys.ToList();
        var approvedRows = await db.ApprovedBinaries.AsNoTracking()
            .Where(binary => binary.ProductId == productId && keys.Contains(binary.Key) && binary.Source != "auto")
            .Select(binary => new { binary.Key, binary.Hash })
            .ToListAsync(cancellationToken);
        var approved = approvedRows
            .Select(row => (row.Key, Hash: ApprovedBinaryService.NormalizeSha256(row.Hash)))
            .Where(row => row.Hash != null)
            .Select(row => $"{row.Key}:{row.Hash}")
            .ToHashSet(StringComparer.Ordinal);
        return evidence
            .Where(item => !approved.Contains($"{item.Key}:{item.Value.ToLowerInvariant()}"))
            .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
    }

    /// <summary>Licence facts shown in the alert for the machine.</summary>
    private sealed record HardwareLicense(Guid LicenseId, string LicenseKey, string CustomerName, string CustomerEmail, string? MachineName);

    /// <summary>
    /// Finds the licence of the product the machine belongs to: the most recently checked-in seat with this hardware
    /// (active seats first), else a licence whose primary hardware matches (most recent first). Stored identifiers may
    /// carry historical casing, so the column is upper-cased in SQL like the hardware-ban lookups do; this scans the
    /// product's seats, acceptable because it runs only on mismatch evidence.
    /// </summary>
    /// <param name="productId">Product of the telemetry.</param>
    /// <param name="canonicalHardwareId">Upper-case canonical hardware identifier.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns>The licence facts, or <see langword="null"/> when no licence of the product knows the hardware.</returns>
    private async Task<HardwareLicense?> FindLicenseForHardwareAsync(
        Guid productId,
        string canonicalHardwareId,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .Where(candidate => candidate.HardwareId.ToUpper() == canonicalHardwareId
                && candidate.License != null && candidate.License.ProductId == productId)
            .OrderByDescending(candidate => candidate.IsActive)
            .ThenByDescending(candidate => candidate.LastCheckInAt)
            .Select(candidate => new HardwareLicense(
                candidate.LicenseId,
                candidate.License!.LicenseKey,
                candidate.License.CustomerName,
                candidate.License.CustomerEmail,
                candidate.MachineName))
            .FirstOrDefaultAsync(cancellationToken);
        if (seat != null)
            return seat;

        return await db.Licenses.AsNoTracking()
            .Where(candidate => candidate.ProductId == productId
                && candidate.HardwareId != null && candidate.HardwareId.ToUpper() == canonicalHardwareId)
            .OrderByDescending(candidate => candidate.CreationDate)
            .Select(candidate => new HardwareLicense(
                candidate.Id, candidate.LicenseKey, candidate.CustomerName, candidate.CustomerEmail, null))
            .FirstOrDefaultAsync(cancellationToken);
    }

    /// <summary>Result of one persistence attempt of a per-hardware observation.</summary>
    private sealed record PersistedHardwareMismatch(
        Guid IncidentId, DateTime FirstSeenUtc, bool CountedStart, int StartsInWindow, bool ShouldAlert);

    /// <summary>
    /// One serializable attempt: finds or creates the incident of the machine, refreshes its last facts and licence
    /// link, merges the bounded evidence, writes a start row when the observation is a new start with an unapproved
    /// fingerprint, counts the starts of the sliding window and reserves the single alert when the threshold is met.
    /// </summary>
    /// <remarks>
    /// The incident is looked up without its window column because there is exactly one per product and hardware;
    /// <see cref="SecurityIncident.WindowStartUtc"/> holds the first observation (unique index satisfied) and
    /// <see cref="SecurityIncident.WindowEndUtc"/> the last one. Throws relational conflicts for the caller to retry.
    /// </remarks>
    private async Task<PersistedHardwareMismatch> PersistHardwareMismatchOnceAsync(
        Guid productId,
        string canonicalHardwareId,
        string version,
        string? clientIp,
        Guid? licenseId,
        IReadOnlyDictionary<string, string> evidence,
        bool hasUnapprovedFingerprint,
        DateTime observedAt,
        string incidentKey,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : null;

        if (db.Database.IsNpgsql())
        {
            // Same scheme as the public aggregate: a 64-bit advisory key derived from the exact ordinal key text.
            // Collisions only over-serialize.
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({incidentKey}, 0))",
                cancellationToken);
        }

        var incident = await db.SecurityIncidents
            .Include(row => row.Evidence)
            .Where(row => row.ProductId == productId
                && row.HardwareId == canonicalHardwareId
                && row.Family == ApprovedBinaryHardwareMismatchFamily)
            .OrderBy(row => row.WindowStartUtc)
            .FirstOrDefaultAsync(cancellationToken);

        if (incident == null)
        {
            incident = new SecurityIncident
            {
                ProductId = productId,
                HardwareId = canonicalHardwareId,
                Family = ApprovedBinaryHardwareMismatchFamily,
                Severity = 3,
                WindowStartUtc = observedAt,
                WindowEndUtc = observedAt,
                FirstSeenUtc = observedAt,
                LastSeenUtc = observedAt,
                OccurrenceCount = 1,
                Version = version,
                ClientIp = clientIp,
                LicenseId = licenseId,
                IsHardwareBanned = false
            };
            db.SecurityIncidents.Add(incident);
        }
        else
        {
            incident.FirstSeenUtc = incident.FirstSeenUtc <= observedAt ? incident.FirstSeenUtc : observedAt;
            if (observedAt >= incident.LastSeenUtc)
            {
                // Latest facts win; an out-of-order older observation must not overwrite them.
                incident.LastSeenUtc = observedAt;
                incident.WindowEndUtc = observedAt;
                incident.Version = version;
                incident.ClientIp = clientIp;
            }
            incident.OccurrenceCount++;
            // Keep a known licence when a later lookup finds none (seat removed); never auto-link a different one silently.
            incident.LicenseId ??= licenseId;
        }

        foreach (var item in evidence)
        {
            var existing = incident.Evidence.SingleOrDefault(row =>
                row.ComponentType == item.Key && row.ComponentHash == item.Value);
            if (existing != null)
            {
                existing.FirstSeenUtc = existing.FirstSeenUtc <= observedAt ? existing.FirstSeenUtc : observedAt;
                existing.LastSeenUtc = existing.LastSeenUtc >= observedAt ? existing.LastSeenUtc : observedAt;
                existing.OccurrenceCount++;
                continue;
            }
            if (incident.Evidence.Count >= MaxEvidencePerHardwareIncident)
                continue;
            var row = new SecurityIncidentEvidence
            {
                SecurityIncident = incident,
                ComponentType = item.Key,
                ComponentHash = item.Value,
                FirstSeenUtc = observedAt,
                LastSeenUtc = observedAt,
                OccurrenceCount = 1
            };
            incident.Evidence.Add(row);
            // Explicit Added state: a client-generated Guid key reached only through the navigation would be
            // treated as an existing row (UPDATE of nothing) when the incident is already persisted.
            db.SecurityIncidentEvidence.Add(row);
        }

        var countedStart = false;
        var startsInWindow = 0;
        if (hasUnapprovedFingerprint)
        {
            var incidentId = incident.Id;
            var sameStartFrom = observedAt - SameStartupGap;
            var sameStartTo = observedAt + SameStartupGap;
            countedStart = !await db.SecurityIncidentObservations.AnyAsync(row =>
                row.SecurityIncidentId == incidentId
                && row.ObservedAtUtc > sameStartFrom && row.ObservedAtUtc < sameStartTo,
                cancellationToken);
            if (countedStart)
            {
                db.SecurityIncidentObservations.Add(new SecurityIncidentObservation
                {
                    SecurityIncident = incident,
                    ObservedAtUtc = observedAt,
                    ClientIp = clientIp,
                    Version = version
                });
            }

            // The window ends at the latest known start, not at this observation: concurrent replicas can commit
            // starts out of time order, and a window ending at an older observation could then never reach the
            // threshold although three starts lie within 24 hours.
            var latestStored = await db.SecurityIncidentObservations
                .Where(row => row.SecurityIncidentId == incidentId)
                .MaxAsync(row => (DateTime?)row.ObservedAtUtc, cancellationToken);
            var windowEnd = latestStored is { } latest && latest > observedAt ? latest : observedAt;
            var windowFrom = windowEnd - TamperedStartWindow;
            startsInWindow = await db.SecurityIncidentObservations.CountAsync(row =>
                row.SecurityIncidentId == incidentId && row.ObservedAtUtc > windowFrom,
                cancellationToken) + (countedStart && observedAt > windowFrom ? 1 : 0);
        }

        // One alert per incident: the reservation is never cleared, so later starts never notify again.
        var shouldAlert = hasUnapprovedFingerprint
            && startsInWindow >= TamperedStartThreshold
            && incident.InitialNotificationSentAtUtc == null;
        if (shouldAlert)
        {
            // Telemetry is unauthenticated: a sender inventing hardware identifiers could otherwise flood the phone.
            // Past the product's daily budget the alert is not reserved, so a later start of this machine can still
            // alert once the budget frees up. Different machines lock different keys, so concurrent alerts may
            // overshoot the budget by the number of racing machines; that bound is accepted.
            var budgetFrom = observedAt - TamperedStartWindow;
            var alertsInWindow = await db.SecurityIncidents.CountAsync(row =>
                row.ProductId == productId
                && row.Family == ApprovedBinaryHardwareMismatchFamily
                && row.InitialNotificationSentAtUtc > budgetFrom,
                cancellationToken);
            if (alertsInWindow >= MaxTamperedAlertsPerProductPerWindow)
            {
                shouldAlert = false;
                _logger.LogWarning(
                    "Modified-binary alert budget reached for product {ProductId}: incident {IncidentId} not notified ({Alerts} alerts in 24 h)",
                    productId,
                    incident.Id,
                    alertsInWindow);
            }
        }
        if (shouldAlert)
        {
            incident.InitialNotificationSentAtUtc = observedAt;
            incident.Severity = 5;
        }

        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);

        return new PersistedHardwareMismatch(incident.Id, incident.FirstSeenUtc, countedStart, startsInWindow, shouldAlert);
    }

    /// <summary>
    /// Builds the French phone alert: customer, masked licence, full hardware identifier and machine name, version, IP
    /// with country and ISP, number of starts, truncated unapproved fingerprints, incident identifier, and the reminder
    /// that nothing is blocked automatically. The ntfy topic is private (operator-owned server), like the lock dossiers that
    /// already carry customer name and e-mail; logs never receive this text.
    /// </summary>
    private static (string Title, string Message) BuildTamperedAlert(
        PersistedHardwareMismatch persisted,
        string canonicalHardwareId,
        string version,
        string? clientIp,
        string? countryCode,
        string? isp,
        HardwareLicense? license,
        IReadOnlyDictionary<string, string> unapproved)
    {
        var title = $"🚨 Binaire modifié : poste {canonicalHardwareId}";
        var location = string.Join(", ", new[] { countryCode, isp }.Where(value => !string.IsNullOrWhiteSpace(value)));
        var fingerprints = string.Join(", ", unapproved
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(item => $"{item.Key} {item.Value[..ShownFingerprintPrefixLength].ToLowerInvariant()}…"));
        var message = new StringBuilder()
            .Append("Client : ").AppendLine(license == null
                ? "aucune licence connue pour ce poste"
                : $"{license.CustomerName} <{license.CustomerEmail}>")
            .Append("Licence : ").AppendLine(license == null
                ? "inconnue"
                : $"{SecurityService.MaskLicenseKey(license.LicenseKey)} ({license.LicenseId:D})")
            .Append("Poste : HWID ").Append(canonicalHardwareId)
            .AppendLine(string.IsNullOrWhiteSpace(license?.MachineName) ? string.Empty : $" ({license.MachineName})")
            .Append("IP : ").Append(string.IsNullOrWhiteSpace(clientIp) ? "inconnue" : clientIp)
            .AppendLine(location.Length > 0 ? $" ({location})" : string.Empty)
            .Append("Version annoncée : ").AppendLine(version)
            .Append(CultureInfo.InvariantCulture,
                $"Démarrages avec binaire non approuvé en 24 h : {persisted.StartsInWindow} (premier écart vu le {persisted.FirstSeenUtc:yyyy-MM-dd HH:mm} UTC)")
            .AppendLine()
            .Append("Empreintes non approuvées : ").AppendLine(fingerprints)
            .Append("Incident : ").AppendLine(persisted.IncidentId.ToString("D"))
            .AppendLine("Preuve déclarée par la télémétrie publique (non authentifiée) : vérifier avant toute décision.")
            .Append("Aucune action automatique : ban manuel si confirmé (outil MCP create_security_hardware_ban).");
        return (title, message.ToString());
    }
}
