using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Applies authenticated, idempotent portal deactivation to one exact provider seat.</summary>
public interface IPortalDeactivationService
{
    /// <summary>
    /// Applies or exactly replays a portal deactivation inside a provider-owned transaction.
    /// </summary>
    /// <param name="clientId">Exact authenticated S2S client identifier.</param>
    /// <param name="exactPayloadDigest">Lowercase SHA-256 of the exact signed body.</param>
    /// <param name="request">Closed and canonical portal-deactivation request.</param>
    /// <param name="cancellationToken">Cancels database work before commit.</param>
    /// <returns>The terminal response and whether it was replayed.</returns>
    /// <exception cref="DistributionOperationException">The request is invalid, conflicting, or cannot safely mutate the exact seat.</exception>
    /// <exception cref="PortalDeactivationQuotaException">
    /// A customer reason would exceed the live daily seat-change quota of <see cref="SeatChangeQuota"/>;
    /// nothing is written and the refusal carries the limit and the next UTC reset.
    /// </exception>
    Task<PortalDeactivationResult> DeactivateAsync(
        string clientId,
        string exactPayloadDigest,
        PortalDeactivationRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Implements portal deactivation with atomic seat and commercial-assignment termination.
/// Exact request replays return their original terminal without affecting a later activation.
/// </summary>
public sealed class PortalDeactivationService : IPortalDeactivationService
{
    /// <summary>Exact closed request schema accepted from Website.</summary>
    public const string RequestSchema = "portal-deactivation-v1";
    /// <summary>Exact bounded terminal response schema returned to Website.</summary>
    public const string ResponseSchema = "portal-deactivation-result-v1";
    /// <summary>Terminal outcome emitted after this request deactivates the exact active seat.</summary>
    public const string DeactivatedOutcome = "deactivated";
    /// <summary>Terminal outcome emitted when the exact seat is already inactive.</summary>
    public const string AlreadyInactiveOutcome = "already_inactive";
    private static readonly TimeSpan AnonymousGuardWindow = TimeSpan.FromMinutes(5);
    private static readonly Regex HardwareIdPattern = new(
        "^[A-Z0-9][A-Z0-9:_-]{4,199}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex LowerSha256Pattern = new(
        "^[0-9a-f]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex ClientIdPattern = new(
        "^[a-z0-9][a-z0-9._-]{2,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly HashSet<string> Reasons = new(
        ["settings_button", "subscription_termination", "uninstall"],
        StringComparer.Ordinal);
    private static readonly HashSet<string> GuardBypassReasons = new(
        ["settings_button", "uninstall"],
        StringComparer.Ordinal);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PortalDeactivationService> _logger;

    /// <summary>Initializes the provider service with isolated contexts and an injectable UTC clock.</summary>
    public PortalDeactivationService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        TimeProvider timeProvider,
        ILogger<PortalDeactivationService> logger)
    {
        _dbFactory = dbFactory;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<PortalDeactivationResult> DeactivateAsync(
        string clientId,
        string exactPayloadDigest,
        PortalDeactivationRequest request,
        CancellationToken cancellationToken = default)
    {
        var parsed = Validate(clientId, exactPayloadDigest, request);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db, cancellationToken);

        if (string.Equals(db.Database.ProviderName, "Npgsql.EntityFrameworkCore.PostgreSQL", StringComparison.Ordinal))
        {
            // Global and item2 authority are already held. The exact request lock now serializes
            // receipt classification without creating a row/barrier inversion.
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({request.RequestId!}, 798))",
                cancellationToken);
        }

        var existing = await db.PortalDeactivationOperations
            .SingleOrDefaultAsync(candidate => candidate.RequestId == parsed.RequestId, cancellationToken);
        if (existing != null)
        {
            EnsureExactReplay(existing, clientId, exactPayloadDigest, parsed, request);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new PortalDeactivationResult(
                new PortalDeactivationResponse(ResponseSchema, request.RequestId!, existing.Outcome),
                true);
        }

        var license = await db.Licenses
            .Include(candidate => candidate.Type)
            .Include(candidate => candidate.Seats)
            .SingleOrDefaultAsync(candidate =>
                candidate.Id == parsed.LicenseId && candidate.ProductId == parsed.ProductId,
                cancellationToken);
        if (license == null)
            throw new DistributionOperationException("target_not_found", StatusCodes.Status404NotFound);

        var activeSeat = license.Seats.SingleOrDefault(candidate =>
            candidate.IsActive && string.Equals(candidate.HardwareId, request.HardwareId, StringComparison.Ordinal));
        var now = db.Database.IsRelational()
            ? (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime
            : _timeProvider.GetUtcNow().UtcDateTime;
        SeatRuntimeReleaseAuthority.SeatReleaseScope? releaseScope = null;
        string outcome;
        if (activeSeat == null)
        {
            if (!license.Seats.Any(candidate =>
                    !candidate.IsActive && string.Equals(candidate.HardwareId, request.HardwareId, StringComparison.Ordinal)))
            {
                throw new DistributionOperationException("target_not_found", StatusCodes.Status404NotFound);
            }
            // This receipt certifies only the commercial seat state. Historical Runtime
            // leftovers require the separate authenticated migration reconciliation, never a replay.
            outcome = AlreadyInactiveOutcome;
        }
        else
        {
            releaseScope = await SeatRuntimeReleaseAuthority.PrepareAsync(
                db, license.ProductId, license, [activeSeat], now, cancellationToken);
            now = releaseScope.ObservedAtUtc;
            // The shared event-based seat-change quota (TKT-001206) replaces the former
            // inactive-seat count, which forgot a seat once it was reactivated. The limit is read
            // live from the licence type; non-positive limits are unlimited. Exact successful
            // replays above and already-inactive targets consume no additional quota.
            // Subscription termination is authenticated server-owned cleanup, not a user unlink.
            // Its existing caller revokes first and must release every seat even at quota.
            // The dashboard fixes settings_button server-side; this exception cannot be selected
            // through browser input. Other reasons and the five-minute guard remain unchanged.
            if (!string.Equals(request.Reason, SeatChangeQuota.SubscriptionTerminationReason, StringComparison.Ordinal))
            {
                var quota = await SeatChangeQuota.GetStatusAsync(db, license, now, cancellationToken);
                if (quota.IsExhausted)
                    throw new PortalDeactivationQuotaException(new PortalDeactivationQuotaRefusal(
                        "portal-deactivation-refusal-v1", request.RequestId!,
                        "deactivation_quota_exceeded", quota.Limit, quota.ResetAtUtc));
            }

            var seatAge = now - DateTime.SpecifyKind(activeSeat.FirstActivatedAt, DateTimeKind.Utc);
            if (seatAge < TimeSpan.Zero)
            {
                throw new DistributionOperationException(
                    "authority_inconsistent",
                    StatusCodes.Status409Conflict);
            }
            if (seatAge < AnonymousGuardWindow && !GuardBypassReasons.Contains(request.Reason!))
            {
                throw new DistributionOperationException(
                    "deactivation_guard_active",
                    StatusCodes.Status409Conflict);
            }

            activeSeat.IsActive = false;
            activeSeat.UnlinkedAt = now;
            SyncLegacyHardwareStateFromSeats(license);
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Timestamp = now,
                Action = HistoryActions.UnlinkedApi,
                Details = $"Portal S2S deactivation ({request.Reason}, request {request.RequestId})",
                PerformedBy = $"S2S:{clientId}"
            });
            outcome = DeactivatedOutcome;
        }

        db.PortalDeactivationOperations.Add(new PortalDeactivationOperation
        {
            RequestId = parsed.RequestId,
            ClientId = clientId,
            RequestFingerprintSha256 = exactPayloadDigest,
            ProductId = parsed.ProductId,
            LicenseId = parsed.LicenseId,
            HardwareId = request.HardwareId!,
            Reason = request.Reason!,
            Outcome = outcome,
            CreatedAtUtc = now
        });
        if (releaseScope != null)
            await SeatRuntimeReleaseAuthority.CompleteAsync(db, releaseScope, [activeSeat!], cancellationToken);
        else
            await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);

        _logger.LogInformation(
            "Portal deactivation {Outcome} for correlation {RequestId} and reason {Reason}.",
            outcome,
            request.RequestId,
            request.Reason);
        return new PortalDeactivationResult(
            new PortalDeactivationResponse(ResponseSchema, request.RequestId!, outcome),
            false);
    }

    private static (Guid RequestId, Guid ProductId, Guid LicenseId) Validate(
        string clientId,
        string exactPayloadDigest,
        PortalDeactivationRequest request)
    {
        if (!ClientIdPattern.IsMatch(clientId)
            || !LowerSha256Pattern.IsMatch(exactPayloadDigest)
            || !string.Equals(request.Schema, RequestSchema, StringComparison.Ordinal)
            || !TryParseCanonicalUuid(request.RequestId, out var requestId)
            || !TryParseCanonicalUuid(request.ProductId, out var productId)
            || !TryParseCanonicalUuid(request.LicenseId, out var licenseId)
            || request.HardwareId == null
            || !HardwareIdPattern.IsMatch(request.HardwareId)
            || request.Reason == null
            || !Reasons.Contains(request.Reason))
        {
            throw new DistributionOperationException("invalid_request", StatusCodes.Status400BadRequest);
        }
        return (requestId, productId, licenseId);
    }

    private static bool TryParseCanonicalUuid(string? value, out Guid parsed)
    {
        return Guid.TryParseExact(value, "D", out parsed)
            && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal)
            && value![14] is >= '1' and <= '5'
            && value[19] is '8' or '9' or 'a' or 'b';
    }

    private static void EnsureExactReplay(
        PortalDeactivationOperation existing,
        string clientId,
        string exactPayloadDigest,
        (Guid RequestId, Guid ProductId, Guid LicenseId) parsed,
        PortalDeactivationRequest request)
    {
        if (!string.Equals(existing.ClientId, clientId, StringComparison.Ordinal)
            || !string.Equals(existing.RequestFingerprintSha256, exactPayloadDigest, StringComparison.Ordinal)
            || existing.ProductId != parsed.ProductId
            || existing.LicenseId != parsed.LicenseId
            || !string.Equals(existing.HardwareId, request.HardwareId, StringComparison.Ordinal)
            || !string.Equals(existing.Reason, request.Reason, StringComparison.Ordinal))
        {
            throw new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict);
        }
    }

    private static void SyncLegacyHardwareStateFromSeats(License license)
    {
        var activeSeat = license.Seats
            .Where(candidate => candidate.IsActive)
            .OrderByDescending(candidate => candidate.LastCheckInAt)
            .ThenByDescending(candidate => candidate.FirstActivatedAt)
            .FirstOrDefault();
        license.HardwareId = activeSeat?.HardwareId;
        license.ActivationDate = activeSeat?.FirstActivatedAt;
        if (activeSeat == null)
            license.RecoveryCount = 0;
    }
}
