using System.Collections.Concurrent;
using System.Data;
using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public enum ApprovedBinaryObservationKind
{
    Mismatch,
    EvidenceMissing,
    EvidenceInvalid,
    CaptureUnavailable,
    BaselineMissing
}

public class SecurityIncidentService
{
    public const string PublicTelemetryAggregateIdentity = "PUBLIC-TELEMETRY-AGGREGATE";
    public const int MaxEvidencePerPublicAggregate = 16;
    public const string BinaryPatchedFamily = "BinaryPatched";
    public const string ApprovedBinaryMismatchFamily = "ApprovedBinaryMismatch";
    public const string ApprovedBinaryEvidenceMissingFamily = "ApprovedBinaryEvidenceMissing";
    public const string ApprovedBinaryEvidenceInvalidFamily = "ApprovedBinaryEvidenceInvalid";
    public const string ApprovedBinaryCaptureUnavailableFamily = "ApprovedBinaryCaptureUnavailable";
    public const string ApprovedBinaryBaselineMissingFamily = "ApprovedBinaryBaselineMissing";
    private const int DefaultWindowMinutes = 1440;
    private const int MinWindowMinutes = 5;
    private const int MaxWindowMinutes = 10080;
    private const int MaxPersistenceAttempts = 6;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _incidentLocks = new(StringComparer.Ordinal);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly NotificationService _notifications;
    private readonly ILogger<SecurityIncidentService> _logger;
    private readonly IConfiguration _configuration;

    public SecurityIncidentService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        NotificationService notifications,
        ILogger<SecurityIncidentService> logger,
        IConfiguration configuration)
    {
        _dbFactory = dbFactory;
        _notifications = notifications;
        _logger = logger;
        _configuration = configuration;
    }

    public virtual async Task RecordApprovedBinaryObservationAsync(
        Guid productId,
        ApprovedBinaryObservationKind kind,
        IReadOnlyDictionary<string, string>? observedBinaries = null,
        DateTime? observedAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        var family = GetFamily(kind);
        var evidence = CanonicalizeEvidence(observedBinaries);
        var observedAt = DateTime.SpecifyKind(observedAtUtc ?? DateTime.UtcNow, DateTimeKind.Utc);
        var windowMinutes = GetWindowMinutes();
        var windowStart = FloorToWindow(observedAt, windowMinutes);
        var windowEnd = windowStart.AddMinutes(windowMinutes);
        var incidentKey = string.Create(
            CultureInfo.InvariantCulture,
            $"{productId:D}:{family}:{windowStart:O}");
        var incidentLock = _incidentLocks.GetOrAdd(incidentKey, static _ => new SemaphoreSlim(1, 1));

        await incidentLock.WaitAsync(cancellationToken);
        try
        {
            var persisted = await PersistObservationWithRetryAsync(
                productId,
                family,
                evidence,
                observedAt,
                windowStart,
                windowEnd,
                incidentKey,
                cancellationToken);

            if (persisted.ShouldNotify)
            {
                _notifications.Notify(
                    NotificationService.Triggers.SecurityEvidenceObserved,
                    GetNotificationTitle(kind),
                    $"Produit: {productId:D}\nEmpreintes distinctes conservées: {persisted.EvidenceCount}/{MaxEvidencePerPublicAggregate}\nFenêtre UTC: {windowStart:O} — {windowEnd:O}\nObservation publique non autoritative: aucune sanction ApprovedBinaries automatique.",
                    new { incidentId = persisted.IncidentId, family, productId });
            }
        }
        finally
        {
            incidentLock.Release();
            if (incidentLock.CurrentCount == 1)
                _incidentLocks.TryRemove(new KeyValuePair<string, SemaphoreSlim>(incidentKey, incidentLock));
        }
    }

    private async Task<PersistedObservation> PersistObservationWithRetryAsync(
        Guid productId,
        string family,
        IReadOnlyDictionary<string, string> evidence,
        DateTime observedAt,
        DateTime windowStart,
        DateTime windowEnd,
        string incidentKey,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= MaxPersistenceAttempts; attempt++)
        {
            try
            {
                return await PersistObservationOnceAsync(
                    productId,
                    family,
                    evidence,
                    observedAt,
                    windowStart,
                    windowEnd,
                    incidentKey,
                    cancellationToken);
            }
            catch (Exception ex) when (attempt < MaxPersistenceAttempts && IsRetryablePersistenceConflict(ex))
            {
                _logger.LogWarning(ex,
                    "Retrying ApprovedBinaries public aggregate persistence after relational conflict; attempt={Attempt}/{MaxAttempts}",
                    attempt,
                    MaxPersistenceAttempts);
                await Task.Delay(TimeSpan.FromMilliseconds(10 * attempt), cancellationToken);
            }
        }

        throw new InvalidOperationException("ApprovedBinaries observation persistence retry loop exhausted unexpectedly.");
    }

    private async Task<PersistedObservation> PersistObservationOnceAsync(
        Guid productId,
        string family,
        IReadOnlyDictionary<string, string> evidence,
        DateTime observedAt,
        DateTime windowStart,
        DateTime windowEnd,
        string incidentKey,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : null;

        if (db.Database.IsNpgsql())
        {
            // PostgreSQL derives the signed 64-bit advisory key from the exact ordinal/UTC
            // aggregate text. Collisions only over-serialize; they cannot weaken correctness.
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({incidentKey}, 0))",
                cancellationToken);
        }

        var incident = await db.SecurityIncidents
            .Include(i => i.Evidence)
            .SingleOrDefaultAsync(i => i.ProductId == productId
                && i.HardwareId == PublicTelemetryAggregateIdentity
                && i.Family == family
                && i.WindowStartUtc == windowStart,
                cancellationToken);

        var isNew = incident == null;
        if (incident == null)
        {
            incident = new SecurityIncident
            {
                ProductId = productId,
                HardwareId = PublicTelemetryAggregateIdentity,
                Family = family,
                Severity = 3,
                WindowStartUtc = windowStart,
                WindowEndUtc = windowEnd,
                FirstSeenUtc = observedAt,
                LastSeenUtc = observedAt,
                OccurrenceCount = 1,
                Version = null,
                ClientIp = null,
                IsHardwareBanned = false
            };
            db.SecurityIncidents.Add(incident);
        }
        else
        {
            incident.FirstSeenUtc = incident.FirstSeenUtc <= observedAt ? incident.FirstSeenUtc : observedAt;
            incident.LastSeenUtc = incident.LastSeenUtc >= observedAt ? incident.LastSeenUtc : observedAt;
            incident.OccurrenceCount++;
            incident.Version = null;
            incident.ClientIp = null;
            incident.IsHardwareBanned = false;
        }

        foreach (var item in evidence)
        {
            var existing = incident.Evidence.SingleOrDefault(e =>
                e.ComponentType == item.Key && e.ComponentHash == item.Value);
            if (existing == null)
            {
                if (incident.Evidence.Count >= MaxEvidencePerPublicAggregate)
                    continue;

                var newEvidence = new SecurityIncidentEvidence
                {
                    ComponentType = item.Key,
                    ComponentHash = item.Value,
                    FirstSeenUtc = observedAt,
                    LastSeenUtc = observedAt,
                    OccurrenceCount = 1
                };
                incident.Evidence.Add(newEvidence);
                if (!isNew)
                    db.SecurityIncidentEvidence.Add(newEvidence);
            }
            else
            {
                existing.FirstSeenUtc = existing.FirstSeenUtc <= observedAt ? existing.FirstSeenUtc : observedAt;
                existing.LastSeenUtc = existing.LastSeenUtc >= observedAt ? existing.LastSeenUtc : observedAt;
                existing.OccurrenceCount++;
            }
        }

        var shouldNotify = isNew && incident.InitialNotificationSentAtUtc == null;
        if (shouldNotify)
            incident.InitialNotificationSentAtUtc = observedAt;

        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);

        return new PersistedObservation(incident.Id, incident.Evidence.Count, shouldNotify);
    }

    private static bool IsRetryablePersistenceConflict(Exception exception)
    {
        if (exception is PostgresException postgres)
            return postgres.SqlState is PostgresErrorCodes.SerializationFailure
                or PostgresErrorCodes.DeadlockDetected
                or PostgresErrorCodes.UniqueViolation;
        if (exception is SqliteException sqlite)
            return sqlite.SqliteErrorCode is 5 or 6 or 19;
        if (exception is DbUpdateConcurrencyException)
            return true;
        return exception.InnerException != null && IsRetryablePersistenceConflict(exception.InnerException);
    }

    private sealed record PersistedObservation(Guid IncidentId, int EvidenceCount, bool ShouldNotify);

    internal static Dictionary<string, string> CanonicalizeEvidence(IReadOnlyDictionary<string, string>? values)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (values == null)
            return result;

        foreach (var pair in values)
        {
            var type = pair.Key.Trim().ToUpperInvariant();
            var hash = pair.Value.Trim().ToUpperInvariant();
            if (type is not ("FP_EXE" or "FP_DLL" or "FP_CORE"))
                throw new ArgumentException("Component type is not an approved-binary key.", nameof(values));
            if (hash.Length != 64 || hash.Any(c => !Uri.IsHexDigit(c)))
                throw new ArgumentException("Component hashes must be 64 hexadecimal characters.", nameof(values));
            result[type] = hash;
        }
        return result;
    }

    private static string GetFamily(ApprovedBinaryObservationKind kind) => kind switch
    {
        ApprovedBinaryObservationKind.Mismatch => ApprovedBinaryMismatchFamily,
        ApprovedBinaryObservationKind.EvidenceMissing => ApprovedBinaryEvidenceMissingFamily,
        ApprovedBinaryObservationKind.EvidenceInvalid => ApprovedBinaryEvidenceInvalidFamily,
        ApprovedBinaryObservationKind.CaptureUnavailable => ApprovedBinaryCaptureUnavailableFamily,
        ApprovedBinaryObservationKind.BaselineMissing => ApprovedBinaryBaselineMissingFamily,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private static string GetNotificationTitle(ApprovedBinaryObservationKind kind) => kind switch
    {
        ApprovedBinaryObservationKind.Mismatch => "APPROVED BINARIES — ÉCART OBSERVÉ",
        ApprovedBinaryObservationKind.EvidenceMissing => "APPROVED BINARIES — EMPREINTE MANQUANTE",
        ApprovedBinaryObservationKind.EvidenceInvalid => "APPROVED BINARIES — EMPREINTE INVALIDE",
        ApprovedBinaryObservationKind.CaptureUnavailable => "APPROVED BINARIES — CAPTURE NATIVE INDISPONIBLE",
        ApprovedBinaryObservationKind.BaselineMissing => "APPROVED BINARIES — BASELINE NON AUTORITATIVE",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private int GetWindowMinutes()
    {
        var raw = _configuration["Security:BinaryPatchedIncidentWindowMinutes"];
        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? Math.Clamp(parsed, MinWindowMinutes, MaxWindowMinutes)
            : DefaultWindowMinutes;
    }

    private static DateTime FloorToWindow(DateTime utc, int windowMinutes)
    {
        var ticks = TimeSpan.FromMinutes(windowMinutes).Ticks;
        return new DateTime(utc.Ticks - utc.Ticks % ticks, DateTimeKind.Utc);
    }

}
