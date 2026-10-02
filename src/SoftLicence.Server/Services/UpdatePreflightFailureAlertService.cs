using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed record UpdatePreflightFailureObservation(
    string SupportCode,
    string CurrentVersion,
    string LatestVersion,
    string PresentationStage,
    string DecisionReason,
    string SelectedChannel,
    string ReconciliationOutcome,
    bool? UpdateAvailable,
    bool? Mandatory,
    bool? UpToDate,
    string SignatureSha256);

public sealed record UpdatePreflightFailureAlertClaim(
    Guid AggregateId,
    Guid? ClaimId,
    bool ShouldNotify,
    long OccurrenceCount,
    DateTime WindowStartUtc,
    DateTime WindowEndUtc);

/// <summary>
/// Validates the closed Desktop contract and durably groups identical UPD shell presentations into
/// 30-minute UTC notification windows. This service never treats public telemetry as licence authority.
/// </summary>
public sealed class UpdatePreflightFailureAlertService
{
    public const string EventName = "Update_PreflightFailureShown";
    private const int AdvisoryLockSalt = 27;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan NotificationClaimLease = TimeSpan.FromMinutes(5);
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<UpdatePreflightFailureAlertService> _logger;

    public UpdatePreflightFailureAlertService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<UpdatePreflightFailureAlertService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public static bool TryParse(
        TelemetryEventRequest request,
        out UpdatePreflightFailureObservation observation)
    {
        observation = null!;
        return string.Equals(request.EventName, EventName, StringComparison.Ordinal)
            && TryParseProperties(request.Properties, out observation);
    }

    public static bool TryParseProperties(
        IReadOnlyDictionary<string, string>? properties,
        out UpdatePreflightFailureObservation observation)
    {
        observation = null!;
        if (properties == null
            || !TryRequired(properties, "SupportCode", out var supportCode)
            || !IsSupportCode(supportCode)
            || !TryRequired(properties, "CurrentVersion", out var currentVersion)
            || !IsVersionOrUnknown(currentVersion)
            || !TryRequired(properties, "LatestVersion", out var latestVersion)
            || !IsVersionOrUnknown(latestVersion)
            || !TryRequired(properties, "PresentationStage", out var presentationStage)
            || !(presentationStage is "initial" or "retry")
            || !TryRequiredToken(properties, "DecisionReason", out var decisionReason)
            || !TryRequiredToken(properties, "SelectedChannel", out var selectedChannel)
            || !TryRequiredToken(properties, "ReconciliationOutcome", out var reconciliationOutcome)
            || !TryNullableBoolean(properties, "UpdateAvailable", out var updateAvailable)
            || !TryNullableBoolean(properties, "Mandatory", out var mandatory)
            || !TryNullableBoolean(properties, "UpToDate", out var upToDate))
        {
            return false;
        }

        // Public telemetry is informational and forgeable. Keep diagnostic fields for analytics,
        // but limit notification cardinality to the closed support-code vocabulary.
        var signature = ComputeSignature(supportCode);
        observation = new UpdatePreflightFailureObservation(
            supportCode,
            currentVersion,
            latestVersion,
            presentationStage,
            decisionReason,
            selectedChannel,
            reconciliationOutcome,
            updateAvailable,
            mandatory,
            upToDate,
            signature);
        return true;
    }

    public async Task<UpdatePreflightFailureAlertClaim> RecordAndClaimAsync(
        Guid productId,
        UpdatePreflightFailureObservation observation,
        DateTime observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (observedAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The observed timestamp must be UTC.", nameof(observedAtUtc));

        var windowStart = FloorToWindow(observedAtUtc);
        var windowEnd = windowStart.Add(Window);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (db.Database.IsNpgsql())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.ReadCommitted,
                cancellationToken);
            var lockKey = $"upd-preflight:{productId:D}:{observation.SignatureSha256}:{windowStart:O}";
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({lockKey}, {AdvisoryLockSalt}))",
                cancellationToken);
            var claim = await RecordAndClaimCoreAsync(
                db, productId, observation, observedAtUtc, windowStart, windowEnd, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return claim;
        }

        return await RecordAndClaimCoreAsync(
            db, productId, observation, observedAtUtc, windowStart, windowEnd, cancellationToken);
    }

    public async Task MarkNotificationSentAsync(
        Guid aggregateId,
        Guid claimId,
        DateTime sentAtUtc,
        CancellationToken cancellationToken = default)
    {
        if (sentAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The sent timestamp must be UTC.", nameof(sentAtUtc));
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.TelemetryUpdatePreflightAlerts
            .Where(item => item.Id == aggregateId && item.NotificationClaimId == claimId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(item => item.NotificationSentAtUtc, sentAtUtc)
                .SetProperty(item => item.NotificationClaimId, (Guid?)null)
                .SetProperty(item => item.NotificationClaimedAtUtc, (DateTime?)null),
                cancellationToken);
    }

    public async Task ReleaseNotificationClaimAsync(
        Guid aggregateId,
        Guid claimId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.TelemetryUpdatePreflightAlerts
            .Where(item => item.Id == aggregateId
                && item.NotificationClaimId == claimId
                && !item.NotificationSentAtUtc.HasValue)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(item => item.NotificationClaimId, (Guid?)null)
                .SetProperty(item => item.NotificationClaimedAtUtc, (DateTime?)null),
                cancellationToken);
    }

    private async Task<UpdatePreflightFailureAlertClaim> RecordAndClaimCoreAsync(
        LicenseDbContext db,
        Guid productId,
        UpdatePreflightFailureObservation observation,
        DateTime observedAtUtc,
        DateTime windowStart,
        DateTime windowEnd,
        CancellationToken cancellationToken)
    {
        var aggregate = await db.TelemetryUpdatePreflightAlerts.SingleOrDefaultAsync(item =>
            item.ProductId == productId
            && item.SignatureSha256 == observation.SignatureSha256
            && item.WindowStartUtc == windowStart,
            cancellationToken);
        if (aggregate == null)
        {
            aggregate = new TelemetryUpdatePreflightAlert
            {
                ProductId = productId,
                SignatureSha256 = observation.SignatureSha256,
                WindowStartUtc = windowStart,
                WindowEndUtc = windowEnd,
                OccurrenceCount = 1,
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc,
                SupportCode = observation.SupportCode,
                CurrentVersion = observation.CurrentVersion,
                LatestVersion = observation.LatestVersion,
                DecisionReason = observation.DecisionReason,
                SelectedChannel = observation.SelectedChannel,
                ReconciliationOutcome = observation.ReconciliationOutcome,
                LastPresentationStage = observation.PresentationStage
            };
            db.TelemetryUpdatePreflightAlerts.Add(aggregate);
        }
        else
        {
            aggregate.OccurrenceCount = SaturatingAdd(aggregate.OccurrenceCount, 1);
            aggregate.FirstSeenUtc = observedAtUtc < aggregate.FirstSeenUtc
                ? observedAtUtc
                : aggregate.FirstSeenUtc;
            if (observedAtUtc >= aggregate.LastSeenUtc)
            {
                aggregate.LastSeenUtc = observedAtUtc;
                aggregate.LastPresentationStage = observation.PresentationStage;
            }
        }

        var claimIsMissingOrExpired = !aggregate.NotificationClaimId.HasValue
            || !aggregate.NotificationClaimedAtUtc.HasValue
            || aggregate.NotificationClaimedAtUtc.Value <= observedAtUtc.Subtract(NotificationClaimLease);
        var shouldNotify = !aggregate.NotificationSentAtUtc.HasValue && claimIsMissingOrExpired;
        Guid? claimId = null;
        if (shouldNotify)
        {
            claimId = Guid.NewGuid();
            aggregate.NotificationClaimId = claimId;
            aggregate.NotificationClaimedAtUtc = observedAtUtc;
        }

        await db.SaveChangesAsync(cancellationToken);
        _logger.LogDebug(
            "Recorded UPD preflight aggregate {AggregateId}: occurrences={OccurrenceCount}, notify={ShouldNotify}",
            aggregate.Id,
            aggregate.OccurrenceCount,
            shouldNotify);
        return new UpdatePreflightFailureAlertClaim(
            aggregate.Id,
            claimId,
            shouldNotify,
            aggregate.OccurrenceCount,
            windowStart,
            windowEnd);
    }

    private static DateTime FloorToWindow(DateTime utc) =>
        new(utc.Ticks / Window.Ticks * Window.Ticks, DateTimeKind.Utc);

    private static bool TryRequired(
        IReadOnlyDictionary<string, string> values,
        string key,
        out string value) =>
        values.TryGetValue(key, out value!) && !string.IsNullOrEmpty(value);

    private static bool TryRequiredToken(
        IReadOnlyDictionary<string, string> values,
        string key,
        out string value) =>
        TryRequired(values, key, out value) && IsToken(value);

    private static bool TryNullableBoolean(
        IReadOnlyDictionary<string, string> values,
        string key,
        out bool? value)
    {
        value = null;
        if (!TryRequired(values, key, out var raw))
            return false;
        if (string.Equals(raw, "unknown", StringComparison.Ordinal))
            return true;
        if (string.Equals(raw, "True", StringComparison.Ordinal))
        {
            value = true;
            return true;
        }
        if (string.Equals(raw, "False", StringComparison.Ordinal))
        {
            value = false;
            return true;
        }
        return false;
    }

    private static bool IsSupportCode(string value) =>
        value is "UPD-1001" or "UPD-1002" or "UPD-1003" or "UPD-1004";

    private static bool IsVersionOrUnknown(string value) =>
        string.Equals(value, "unknown", StringComparison.Ordinal)
        || value.Length <= 64
            && Version.TryParse(value, out var parsed)
            && string.Equals(parsed.ToString(), value, StringComparison.Ordinal);

    private static bool IsToken(string value)
    {
        if (value.Length is < 1 or > 64)
            return false;
        foreach (var character in value)
        {
            if (!(character >= 'a' && character <= 'z')
                && !(character >= 'A' && character <= 'Z')
                && !(character >= '0' && character <= '9')
                && character != '_'
                && character != '-')
                return false;
        }
        return true;
    }

    private static string ComputeSignature(params string[] fields)
    {
        var canonical = string.Join("\n", fields.Select(field =>
            field.Length.ToString(CultureInfo.InvariantCulture) + ":" + field));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static long SaturatingAdd(long current, long increment) =>
        increment > 0 && current > long.MaxValue - increment ? long.MaxValue : current + increment;
}
