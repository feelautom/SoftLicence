using System.Data;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed record CertPinningDailyAlertClaim(
    Guid AggregateId,
    Guid? ClaimId,
    bool ShouldNotify,
    long OccurrenceCount,
    long ClientSuppressedCount);

public sealed class CertPinningDailyAlertService
{
    public const string AlertType = "CertPinningFailed";
    private const int AdvisoryLockSalt = 22;
    private const int MaxHostLength = 253;
    private const int MaxVersionLength = 64;
    private const int MaxFailureReasonLength = 128;
    private const int MaxCertificateIssuerLength = 512;

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<CertPinningDailyAlertService> _logger;

    public CertPinningDailyAlertService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<CertPinningDailyAlertService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<CertPinningDailyAlertClaim> RecordAndClaimAsync(
        Guid productId,
        string hardwareId,
        string? host,
        string? version,
        int clientSuppressedCount,
        DateTime observedAtUtc,
        string? failureReason = null,
        string? certificateIssuer = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(hardwareId);
        if (observedAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The observed timestamp must be UTC.", nameof(observedAtUtc));

        var parisDate = DateOnly.FromDateTime(TimeZoneService.ToParisDate(observedAtUtc));
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        if (db.Database.IsNpgsql())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.ReadCommitted,
                cancellationToken);
            var lockKey = BuildLockKey(productId, hardwareId, parisDate);
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({lockKey}, {AdvisoryLockSalt}))",
                cancellationToken);
            var decision = await RecordAndClaimCoreAsync(
                db,
                productId,
                hardwareId,
                host,
                version,
                failureReason,
                certificateIssuer,
                clientSuppressedCount,
                observedAtUtc,
                parisDate,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return decision;
        }

        return await RecordAndClaimCoreAsync(
            db,
            productId,
            hardwareId,
            host,
            version,
            failureReason,
            certificateIssuer,
            clientSuppressedCount,
            observedAtUtc,
            parisDate,
            cancellationToken);
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
        if (db.Database.IsRelational())
        {
            await db.TelemetryCertPinningDailyAlerts
                .Where(a => a.Id == aggregateId && a.NotificationClaimId == claimId)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(a => a.NotificationSentAtUtc, sentAtUtc)
                    .SetProperty(a => a.NotificationClaimId, (Guid?)null)
                    .SetProperty(a => a.NotificationClaimedAtUtc, (DateTime?)null), cancellationToken);
            return;
        }

        var aggregate = await db.TelemetryCertPinningDailyAlerts
            .SingleOrDefaultAsync(a => a.Id == aggregateId && a.NotificationClaimId == claimId, cancellationToken);
        if (aggregate == null)
            return;

        aggregate.NotificationSentAtUtc = sentAtUtc;
        aggregate.NotificationClaimId = null;
        aggregate.NotificationClaimedAtUtc = null;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<CertPinningDailyAlertClaim> RecordAndClaimCoreAsync(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string? host,
        string? version,
        string? failureReason,
        string? certificateIssuer,
        int clientSuppressedCount,
        DateTime observedAtUtc,
        DateOnly parisDate,
        CancellationToken cancellationToken)
    {
        var aggregate = await db.TelemetryCertPinningDailyAlerts.SingleOrDefaultAsync(a =>
            a.ProductId == productId
            && a.HardwareId == hardwareId
            && a.AlertType == AlertType
            && a.ParisDate == parisDate,
            cancellationToken);

        if (aggregate == null)
        {
            aggregate = new TelemetryCertPinningDailyAlert
            {
                ProductId = productId,
                HardwareId = hardwareId,
                AlertType = AlertType,
                ParisDate = parisDate,
                OccurrenceCount = 1,
                ClientSuppressedCount = Math.Max(0, clientSuppressedCount),
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc,
                FirstHost = Bound(host, MaxHostLength),
                LastHost = Bound(host, MaxHostLength),
                LastVersion = Bound(version, MaxVersionLength),
                LastFailureReason = Bound(failureReason, MaxFailureReasonLength),
                LastCertificateIssuer = Bound(certificateIssuer, MaxCertificateIssuerLength)
            };
            db.TelemetryCertPinningDailyAlerts.Add(aggregate);
        }
        else
        {
            aggregate.OccurrenceCount = SaturatingAdd(aggregate.OccurrenceCount, 1);
            aggregate.ClientSuppressedCount = SaturatingAdd(
                aggregate.ClientSuppressedCount,
                Math.Max(0, clientSuppressedCount));
            if (observedAtUtc < aggregate.FirstSeenUtc)
            {
                aggregate.FirstSeenUtc = observedAtUtc;
                aggregate.FirstHost = Bound(host, MaxHostLength);
            }

            if (observedAtUtc >= aggregate.LastSeenUtc)
            {
                aggregate.LastSeenUtc = observedAtUtc;
                aggregate.LastHost = Bound(host, MaxHostLength);
                aggregate.LastVersion = Bound(version, MaxVersionLength);
                aggregate.LastFailureReason = Bound(failureReason, MaxFailureReasonLength);
                aggregate.LastCertificateIssuer = Bound(certificateIssuer, MaxCertificateIssuerLength);
            }
        }

        var shouldNotify = !aggregate.NotificationSentAtUtc.HasValue
            && !aggregate.NotificationClaimId.HasValue;
        Guid? claimId = null;
        if (shouldNotify)
        {
            claimId = Guid.NewGuid();
            aggregate.NotificationClaimId = claimId;
            aggregate.NotificationClaimedAtUtc = observedAtUtc;
        }

        await db.SaveChangesAsync(cancellationToken);
        _logger.LogDebug(
            "Recorded CertPinningFailed daily aggregate {AggregateId}: occurrences={OccurrenceCount}, notify={ShouldNotify}",
            aggregate.Id,
            aggregate.OccurrenceCount,
            shouldNotify);

        return new CertPinningDailyAlertClaim(
            aggregate.Id,
            claimId,
            shouldNotify,
            aggregate.OccurrenceCount,
            aggregate.ClientSuppressedCount);
    }

    private static string BuildLockKey(Guid productId, string hardwareId, DateOnly parisDate) =>
        $"cert-pinning-daily:{productId:D}:{hardwareId.Length}:{hardwareId}:{parisDate:yyyy-MM-dd}:{AlertType}";

    private static string? Bound(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value;

        var length = maxLength;
        if (char.IsHighSurrogate(value[length - 1]) && char.IsLowSurrogate(value[length]))
            length--;

        return value[..length];
    }

    private static long SaturatingAdd(long current, long increment) =>
        increment > 0 && current > long.MaxValue - increment ? long.MaxValue : current + increment;
}
