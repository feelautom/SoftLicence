using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Applies, lifts and lists authenticated, idempotent licence hardware exclusions.</summary>
public interface ILicenseHardwareExclusionService
{
    /// <summary>
    /// Applies or exactly replays one exclusion, optionally releasing the active seat with the
    /// provider-authority reason inside the same provider-owned transaction.
    /// </summary>
    Task<LicenseHardwareExclusionResult> AddAsync(
        string clientId,
        string exactPayloadDigest,
        LicenseHardwareExclusionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Lifts one active exclusion without reactivating anything.</summary>
    Task<LicenseHardwareExclusionLiftResponse> LiftAsync(
        string actor,
        string clientId,
        LicenseHardwareExclusionLiftRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Returns a bounded list of the exclusions of one licence.</summary>
    Task<LicenseHardwareExclusionListResponse> ListAsync(
        LicenseHardwareExclusionListRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Implements licence hardware exclusions with one shared admission refusal and atomic
/// release-plus-exclude. Exact request replays return their original terminal without any effect.
/// </summary>
public sealed class LicenseHardwareExclusionService : ILicenseHardwareExclusionService
{
    /// <summary>Exact closed add-request schema accepted from Website.</summary>
    public const string RequestSchema = "license-hardware-exclusion-v1";
    /// <summary>Exact closed lift-request schema accepted from Website and administration.</summary>
    public const string LiftRequestSchema = "license-hardware-exclusion-lift-v1";
    /// <summary>Exact closed list-request schema accepted from Website and administration.</summary>
    public const string ListRequestSchema = "license-hardware-exclusion-list-v1";
    /// <summary>Exact bounded add-response schema returned to Website.</summary>
    public const string ResponseSchema = "license-hardware-exclusion-result-v1";
    /// <summary>Exact bounded lift-response schema returned to callers.</summary>
    public const string LiftResponseSchema = "license-hardware-exclusion-lift-result-v1";
    /// <summary>Exact bounded list-response schema returned to callers.</summary>
    public const string ListResponseSchema = "license-hardware-exclusion-list-result-v1";
    /// <summary>Terminal outcome emitted after this request created the exclusion row.</summary>
    public const string ExcludedOutcome = "excluded";
    /// <summary>Terminal outcome emitted when an active exclusion already covers the machine.</summary>
    public const string AlreadyExcludedOutcome = "already_excluded";
    /// <summary>Terminal outcome emitted after this request lifted the active exclusion.</summary>
    public const string LiftedOutcome = "lifted";
    /// <summary>Terminal outcome emitted when no active exclusion covers the machine.</summary>
    public const string AlreadyLiftedOutcome = "already_lifted";
    /// <summary>Closed actor value for server-to-server callers.</summary>
    public const string S2SActor = "s2s";
    /// <summary>Closed actor value for the SoftLicence administration.</summary>
    public const string AdminActor = "admin";

    private const string ReleaseOutcomeNone = "none";
    private const int MaximumListEntries = 200;

    private static readonly Regex ClientIdPattern = new(
        "^[a-z0-9][a-z0-9._-]{2,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex LowerSha256Pattern = new(
        "^[0-9a-f]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly TimeProvider _timeProvider;
    private readonly IHardwareAuthorityAliasResolver _hardwareAuthorityAliases;
    private readonly ILogger<LicenseHardwareExclusionService> _logger;

    /// <summary>Initializes the provider service with isolated contexts, alias identity and a UTC clock.</summary>
    public LicenseHardwareExclusionService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        TimeProvider timeProvider,
        IHardwareAuthorityAliasResolver hardwareAuthorityAliases,
        ILogger<LicenseHardwareExclusionService> logger)
    {
        _dbFactory = dbFactory;
        _timeProvider = timeProvider;
        _hardwareAuthorityAliases = hardwareAuthorityAliases;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<LicenseHardwareExclusionResult> AddAsync(
        string clientId,
        string exactPayloadDigest,
        LicenseHardwareExclusionRequest request,
        CancellationToken cancellationToken = default)
    {
        var parsed = Validate(clientId, exactPayloadDigest, request.Schema, request.RequestId,
            request.ProductId, request.LicenseId, request.HardwareId);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db, cancellationToken);
        if (db.Database.IsNpgsql())
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({parsed.RequestId.ToString("D")}, 799))",
                cancellationToken);
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({BuildLicenseMachineLockKey(parsed.LicenseId, request.HardwareId!)}, 799))",
                cancellationToken);
        }

        var existing = await db.LicenseHardwareExclusions
            .SingleOrDefaultAsync(candidate => candidate.CreatedByRequestId == parsed.RequestId, cancellationToken);
        if (existing != null)
        {
            EnsureExactAddReplay(existing, clientId, exactPayloadDigest, parsed, request);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new LicenseHardwareExclusionResult(
                new LicenseHardwareExclusionResponse(ResponseSchema, request.RequestId!, ExcludedOutcome, existing.ReleaseOutcome),
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

        var now = db.Database.IsRelational()
            ? (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime
            : _timeProvider.GetUtcNow().UtcDateTime;
        var activeExclusion = await db.LicenseHardwareExclusions
            .SingleOrDefaultAsync(candidate =>
                candidate.LicenseId == license.Id
                && candidate.HardwareId == request.HardwareId
                && candidate.LiftedAtUtc == null,
                cancellationToken);
        var releaseOutcome = await ReleaseActiveSeatAsync(
            db, license, request.HardwareId!, clientId, parsed.RequestId,
            request.ReleaseActiveSeat == true, now, cancellationToken);
        string outcome;
        if (activeExclusion == null)
        {
            db.LicenseHardwareExclusions.Add(new LicenseHardwareExclusion
            {
                Id = Guid.NewGuid(),
                ProductId = license.ProductId,
                LicenseId = license.Id,
                HardwareId = request.HardwareId!,
                CreatedAtUtc = now,
                CreatedByRequestId = parsed.RequestId,
                CreatedByClientId = clientId,
                CreatedByRequestFingerprintSha256 = exactPayloadDigest,
                Actor = S2SActor,
                ReleaseActiveSeat = request.ReleaseActiveSeat == true,
                ReleaseOutcome = releaseOutcome
            });
            outcome = ExcludedOutcome;
        }
        else
        {
            outcome = AlreadyExcludedOutcome;
        }

        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);
        _logger.LogInformation(
            "Licence hardware exclusion {Outcome} for correlation {RequestId} with release outcome {ReleaseOutcome}.",
            outcome, request.RequestId, releaseOutcome);
        return new LicenseHardwareExclusionResult(
            new LicenseHardwareExclusionResponse(ResponseSchema, request.RequestId!, outcome, releaseOutcome),
            false);
    }

    /// <inheritdoc />
    public async Task<LicenseHardwareExclusionLiftResponse> LiftAsync(
        string actor,
        string clientId,
        LicenseHardwareExclusionLiftRequest request,
        CancellationToken cancellationToken = default)
    {
        var parsed = Validate(clientId, null, request.Schema, request.RequestId,
            request.ProductId, request.LicenseId, request.HardwareId);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db, cancellationToken);
        if (db.Database.IsNpgsql())
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({parsed.RequestId.ToString("D")}, 799))",
                cancellationToken);
        }

        var lifted = await db.LicenseHardwareExclusions
            .SingleOrDefaultAsync(candidate => candidate.LiftedByRequestId == parsed.RequestId, cancellationToken);
        if (lifted != null)
        {
            EnsureExactLiftReplay(lifted, actor, clientId, parsed);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new LicenseHardwareExclusionLiftResponse(LiftResponseSchema, request.RequestId!, LiftedOutcome);
        }

        var activeExclusion = await db.LicenseHardwareExclusions
            .SingleOrDefaultAsync(candidate =>
                candidate.LicenseId == parsed.LicenseId
                && candidate.HardwareId == request.HardwareId
                && candidate.LiftedAtUtc == null,
                cancellationToken);
        string outcome;
        if (activeExclusion != null)
        {
            var now = db.Database.IsRelational()
                ? (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime
                : _timeProvider.GetUtcNow().UtcDateTime;
            activeExclusion.LiftedAtUtc = now;
            activeExclusion.LiftedByRequestId = parsed.RequestId;
            activeExclusion.LiftedByClientId = clientId;
            activeExclusion.LiftedByActor = actor;
            outcome = LiftedOutcome;
        }
        else
        {
            outcome = AlreadyLiftedOutcome;
        }

        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);
        _logger.LogInformation(
            "Licence hardware exclusion lift {Outcome} for correlation {RequestId}.",
            outcome, request.RequestId);
        return new LicenseHardwareExclusionLiftResponse(LiftResponseSchema, request.RequestId!, outcome);
    }

    /// <inheritdoc />
    public async Task<LicenseHardwareExclusionListResponse> ListAsync(
        LicenseHardwareExclusionListRequest request,
        CancellationToken cancellationToken = default)
    {
        var parsed = Validate(string.Empty, null, request.Schema, request.RequestId,
            request.ProductId, request.LicenseId, null);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var activeEntries = await db.LicenseHardwareExclusions.AsNoTracking()
            .Where(candidate => candidate.LicenseId == parsed.LicenseId && candidate.LiftedAtUtc == null)
            .OrderBy(candidate => candidate.CreatedAtUtc)
            .ThenBy(candidate => candidate.HardwareId)
            .Take(MaximumListEntries)
            .ToListAsync(cancellationToken);
        var liftedEntries = request.IncludeLifted == true
            ? await db.LicenseHardwareExclusions.AsNoTracking()
                .Where(candidate => candidate.LicenseId == parsed.LicenseId && candidate.LiftedAtUtc != null)
                .OrderBy(candidate => candidate.LiftedAtUtc)
                .ThenBy(candidate => candidate.HardwareId)
                .Take(MaximumListEntries - activeEntries.Count)
                .ToListAsync(cancellationToken)
            : [];
        var entries = activeEntries.Concat(liftedEntries)
            .Select(candidate => new LicenseHardwareExclusionEntry(
                candidate.HardwareId,
                candidate.CreatedAtUtc,
                candidate.LiftedAtUtc,
                candidate.Actor,
                candidate.LiftedByActor))
            .ToArray();
        return new LicenseHardwareExclusionListResponse(ListResponseSchema, request.RequestId!, entries);
    }

    /// <summary>
    /// Releases the exact active seat with the generic provider-authority reason when requested.
    /// The release runs inside the caller transaction and is exempt from the seat-change quota and
    /// from the five-minute guard by construction, never through the public reasons.
    /// </summary>
    private async Task<string> ReleaseActiveSeatAsync(
        LicenseDbContext db,
        License license,
        string hardwareId,
        string clientId,
        Guid requestId,
        bool requested,
        DateTime now,
        CancellationToken cancellationToken)
    {
        if (!requested)
            return ReleaseOutcomeNone;
        var storedSeatHardwareIds = await _hardwareAuthorityAliases
            .ResolveStoredSeatHardwareIdsByCanonicalAsync(
                db, license.ProductId, license.Id, hardwareId, cancellationToken);
        var seatIdentities = new HashSet<string>(StringComparer.Ordinal) { hardwareId };
        foreach (var storedSeatHardwareId in storedSeatHardwareIds)
            seatIdentities.Add(storedSeatHardwareId);
        var activeSeat = license.Seats.SingleOrDefault(candidate =>
            candidate.IsActive && seatIdentities.Contains(candidate.HardwareId));
        if (activeSeat == null)
            return PortalDeactivationService.AlreadyInactiveOutcome;

        var releaseScope = await SeatRuntimeReleaseAuthority.PrepareAsync(
            db, license.ProductId, license, [activeSeat], now, cancellationToken);
        activeSeat.IsActive = false;
        activeSeat.UnlinkedAt = releaseScope.ObservedAtUtc;
        PortalDeactivationService.SyncLegacyHardwareStateFromSeats(license);
        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = license.Id,
            Timestamp = releaseScope.ObservedAtUtc,
            Action = HistoryActions.UnlinkedApi,
            Details = $"Portal S2S deactivation ({PortalDeactivationService.ProviderAuthorityReleaseReason}, request {DeriveReleaseRequestId(requestId):D})",
            PerformedBy = $"S2S:{clientId}"
        });
        await SeatRuntimeReleaseAuthority.CompleteAsync(db, releaseScope, [activeSeat], cancellationToken);
        return PortalDeactivationService.DeactivatedOutcome;
    }

    /// <summary>Builds the exact advisory key serializing concurrent operations for one machine.</summary>
    private static string BuildLicenseMachineLockKey(Guid licenseId, string hardwareId) =>
        $"license-hardware-exclusion:{licenseId:D}:{hardwareId}";

    /// <summary>Derives the deterministic release correlation UUID from the add-request UUID.</summary>
    internal static Guid DeriveReleaseRequestId(Guid addRequestId)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(
            "tkt-002041:provider-authority-release:" + addRequestId.ToString("D")));
        var bytes = digest.AsSpan(0, 16).ToArray();
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }

    private static ParsedExclusionRequest Validate(
        string clientId,
        string? exactPayloadDigest,
        string? schema,
        string? requestId,
        string? productId,
        string? licenseId,
        string? hardwareId)
    {
        if (!string.IsNullOrEmpty(clientId) && !ClientIdPattern.IsMatch(clientId)
            || exactPayloadDigest != null && !LowerSha256Pattern.IsMatch(exactPayloadDigest)
            || !string.Equals(schema, RequestSchema, StringComparison.Ordinal)
                && !string.Equals(schema, LiftRequestSchema, StringComparison.Ordinal)
                && !string.Equals(schema, ListRequestSchema, StringComparison.Ordinal)
            || !TryParseCanonicalUuid(requestId, out var parsedRequestId)
            || !TryParseCanonicalUuid(productId, out var parsedProductId)
            || !TryParseCanonicalUuid(licenseId, out var parsedLicenseId)
            || hardwareId != null && !HardwareAuthorityAliasResolver.IsCanonicalHardwareId(hardwareId))
        {
            throw new DistributionOperationException("invalid_request", StatusCodes.Status400BadRequest);
        }

        return new ParsedExclusionRequest(parsedRequestId, parsedProductId, parsedLicenseId);
    }

    private static bool TryParseCanonicalUuid(string? value, out Guid parsed)
    {
        parsed = default;
        return value != null
            && Guid.TryParseExact(value, "D", out parsed)
            && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal)
            && value[14] is >= '1' and <= '5'
            && value[19] is '8' or '9' or 'a' or 'b';
    }

    private static void EnsureExactAddReplay(
        LicenseHardwareExclusion existing,
        string clientId,
        string exactPayloadDigest,
        ParsedExclusionRequest parsed,
        LicenseHardwareExclusionRequest request)
    {
        if (!string.Equals(existing.CreatedByClientId, clientId, StringComparison.Ordinal)
            || !string.Equals(existing.CreatedByRequestFingerprintSha256, exactPayloadDigest, StringComparison.Ordinal)
            || existing.ProductId != parsed.ProductId
            || existing.LicenseId != parsed.LicenseId
            || !string.Equals(existing.HardwareId, request.HardwareId, StringComparison.Ordinal)
            || existing.ReleaseActiveSeat != (request.ReleaseActiveSeat == true))
        {
            throw new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict);
        }
    }

    private static void EnsureExactLiftReplay(
        LicenseHardwareExclusion existing,
        string actor,
        string clientId,
        ParsedExclusionRequest parsed)
    {
        if (!string.Equals(existing.LiftedByClientId, clientId, StringComparison.Ordinal)
            || !string.Equals(existing.LiftedByActor, actor, StringComparison.Ordinal)
            || existing.ProductId != parsed.ProductId
            || existing.LicenseId != parsed.LicenseId)
        {
            throw new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict);
        }
    }

    private sealed record ParsedExclusionRequest(
        Guid RequestId,
        Guid ProductId,
        Guid LicenseId);
}
