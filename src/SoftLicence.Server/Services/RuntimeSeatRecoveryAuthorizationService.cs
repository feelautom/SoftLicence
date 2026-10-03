using System.Buffers;
using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Returns one exact HTTP result whose bytes are safe to send without reserialization.</summary>
public sealed record RuntimeSeatRecoveryHttpResult(int StatusCode, string ContentType, byte[] ExactBodyUtf8);

/// <summary>Defines provider authorization, proof, activation, and immutable readback operations.</summary>
public interface IRuntimeSeatRecoveryAuthorizationService
{
    /// <summary>
    /// Authorizes or replays one canonical request inside its authenticated client namespace.
    /// Expected authorized-resource uniqueness races and the closed PostgreSQL transient SQLSTATE set
    /// are rolled back and retried at most three times; exhaustion returns a non-terminal 503, while
    /// explicit caller cancellation always propagates.
    /// </summary>
    Task<RuntimeSeatRecoveryHttpResult> AuthorizeAsync(
        string authenticatedClientId,
        RuntimeSeatRecoveryContractCodec.AuthorizationParseResult parsed,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads and classifies current provider state without extending TTL or mutating lifecycle. A successful
    /// read requires the grant's exact commercial-ownership version to remain ACTIVE; historical null bindings
    /// and later ownership versions fail closed even when their subject UUID or digest matches.
    /// </summary>
    /// <param name="authenticatedClientId">The exact authenticated S2S namespace; no normalization is applied.</param>
    /// <param name="request">The already shape-validated current-readback identity and digest fields.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through the read-only transaction.</param>
    /// <returns>An exact HTTP result containing either current classification bytes or a closed 403 refusal.</returns>
    Task<RuntimeSeatRecoveryHttpResult> ReadCurrentAsync(
        string authenticatedClientId,
        RuntimeSeatRecoveryCurrentReadbackRequest request,
        CancellationToken cancellationToken);

    /// <summary>Creates or exactly replays one W10 provider key preparation.</summary>
    Task<RuntimeSeatRecoveryHttpResult> PrepareKeyAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryContractCodec.KeyPreparationParseResult parsed,
        CancellationToken cancellationToken);

    /// <summary>Consumes one W10 challenge and freezes a PROVED receipt or closed refusal.</summary>
    Task<RuntimeSeatRecoveryHttpResult> ConfirmKeyAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryContractCodec.KeyConfirmationParseResult parsed,
        CancellationToken cancellationToken);

    /// <summary>Consumes one exact PROVED receipt and atomically freezes the recovery cutover.</summary>
    Task<RuntimeSeatRecoveryHttpResult> ActivateAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryContractCodec.ActivationParseResult parsed,
        CancellationToken cancellationToken);

    /// <summary>Returns one immutable activation terminal without reevaluating proof expiry or current state.</summary>
    Task<RuntimeSeatRecoveryHttpResult> ReadActivationAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryActivationReadbackRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Owns short ReadCommitted provider transactions that authorize one seat, prove the future key,
/// and later commit only the closed recovery cutover from one durable PROVED receipt. Row locks and
/// the item-2 advisory barrier serialize decisions while post-barrier statements receive snapshots
/// that include a commercial writer which committed during an earlier lock wait.
/// </summary>
public sealed class RuntimeSeatRecoveryAuthorizationService : IRuntimeSeatRecoveryAuthorizationService
{
    private const string ContentType = "application/json; charset=utf-8";
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";
    private const string ProofUtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";
    /// <summary>Closed terminal reason written when canonical recovery consumes its derived source assignment.</summary>
    private const string IdentityRecoveredAssignmentEndReason = "identity_recovered";
    /// <summary>Exact v1 proof audience retained for all canonical recovery key confirmations.</summary>
    private const string ConfirmationAudience = "softlicence:runtime-identity-recovery:confirm:v1";
    /// <summary>Names the only authorized-resource 23505 constraints eligible for bounded reread.</summary>
    private static readonly HashSet<string> ExpectedRecoveryUniqueConstraints = new(StringComparer.Ordinal)
    {
        "PK_RuntimeRecoveryGrantOwnerships",
        "IX_RuntimeRecoveryGrantOwnerships_RecoveryOperationRef",
        "IX_RuntimeSeatRecoveryReservations_RecoveryOperationRef"
    };
    private static readonly string[] RequiredBinaryKeys = ["FP_EXE", "FP_DLL", "FP_CORE"];
    private static readonly HashSet<string> RequiredBinaryKeySet = new(RequiredBinaryKeys, StringComparer.Ordinal);
    private static readonly byte[] OwnerDomain = "SOFTLICENCE\0RUNTIME-RECOVERY-OWNER\0V1"u8.ToArray();
    private static readonly JsonSerializerOptions AuthorityJson = RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions();
    private readonly IDbContextFactory<LicenseDbContext> dbFactory;
    private readonly RuntimeEnrollmentAuthorityService authorityPersistence;
    private readonly RuntimeSeatRecoverySeatClaimCryptography seatClaimCryptography;
    private readonly IRuntimeEnrollmentCryptoService crypto;
    private readonly RuntimeEnrollmentOptions options;
    private readonly TimeProvider clock;
    /// <summary>Protected sink for redacted recovery-generation integrity diagnostics.</summary>
    private readonly ILogger<RuntimeSeatRecoveryAuthorizationService> logger;

    /// <summary>
    /// Creates the scoped recovery authority with provider database, generic authority-generation signer, and the signing-policy
    /// clock; business decision timestamps are always read from PostgreSQL after decisive locks.
    /// </summary>
    /// <param name="dbFactory">Factory for isolated provider transactions.</param>
    /// <param name="authorityPersistence">Persistence boundary for immutable signed authority generations.</param>
    /// <param name="seatClaimCryptography">Cryptography boundary for optional historical seat claims.</param>
    /// <param name="crypto">Envelope cryptography for recovery key material.</param>
    /// <param name="options">Validated Runtime authority and timeout configuration.</param>
    /// <param name="clock">Signing-policy clock; never used for mutable commercial decisions.</param>
    /// <param name="logger">Protected diagnostic sink; payload, key, HWID, customer, and secret data are excluded.</param>
    public RuntimeSeatRecoveryAuthorizationService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        RuntimeEnrollmentAuthorityService authorityPersistence,
        RuntimeSeatRecoverySeatClaimCryptography seatClaimCryptography,
        IRuntimeEnrollmentCryptoService crypto,
        IOptions<RuntimeEnrollmentOptions> options,
        TimeProvider clock,
        ILogger<RuntimeSeatRecoveryAuthorizationService> logger)
    {
        this.dbFactory = dbFactory;
        this.authorityPersistence = authorityPersistence;
        this.seatClaimCryptography = seatClaimCryptography;
        this.crypto = crypto;
        this.options = options.Value;
        this.clock = clock;
        this.logger = logger;
    }

    /// <inheritdoc />
    public async Task<RuntimeSeatRecoveryHttpResult> AuthorizeAsync(
        string authenticatedClientId,
        RuntimeSeatRecoveryContractCodec.AuthorizationParseResult parsed,
        CancellationToken cancellationToken)
    {
        if (!parsed.IsSuccess || parsed.Request is null || parsed.RequestDigestSha256 is null)
            return Transport(StatusCodes.Status400BadRequest, "invalid_request");
        for (var attempt = 0; attempt < 3; attempt++)
        {
            await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
            try
            {
                await SetTransactionGuardsAsync(db, cancellationToken);
                await AcquireCommandLockAsync(db, authenticatedClientId, parsed.Request.RequestId, cancellationToken);
                var replay = await ReadTerminalForUpdateAsync(db, authenticatedClientId,
                    Guid.Parse(parsed.Request.RequestId), cancellationToken);
                if (replay is not null)
                {
                    if (!string.Equals(replay.RequestDigestSha256,
                            parsed.RequestDigestSha256, StringComparison.Ordinal))
                    {
                        var conflictCompletedAtUtc = await ReadDatabaseClockAsync(db, cancellationToken);
                        await transaction.RollbackAsync(cancellationToken);
                        return SemanticError(parsed.Request, parsed.RequestDigestSha256,
                            "idempotency_conflict", StatusCodes.Status409Conflict, conflictCompletedAtUtc);
                    }

                    // Frozen refusals are inert. A successful authorization still advances a live grant,
                    // so current source authority is rechecked before its original bytes are returned.
                    if (!string.Equals(replay.Decision, "AUTHORIZED", StringComparison.Ordinal))
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return new(replay.HttpStatusCode, replay.ContentType, [.. replay.ExactResponseUtf8]);
                    }

                    var replayAuthority = await RevalidateAuthorizedReplayAsync(
                        db, replay, parsed.Request, cancellationToken);
                    await transaction.RollbackAsync(cancellationToken);
                    return replayAuthority.Outcome switch
                    {
                        PreviousAuthorityOutcome.Eligible =>
                            new(replay.HttpStatusCode, replay.ContentType, [.. replay.ExactResponseUtf8]),
                        PreviousAuthorityOutcome.Denied =>
                            CommercialAuthorityDenial(),
                        PreviousAuthorityOutcome.Unavailable =>
                            Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable"),
                        _ => Transport(StatusCodes.Status409Conflict, "authority_state_conflict")
                    };
                }

                var result = await CreateTerminalAsync(db, authenticatedClientId, parsed, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
            catch (Exception exception) when (IsCallerCancellationDatabaseFailure(exception, cancellationToken))
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw new OperationCanceledException("Runtime recovery authorization was canceled by the caller.",
                    exception, cancellationToken);
            }
            catch (DbUpdateException exception) when (IsExpectedRecoveryUniqueViolation(exception))
            {
                // Only known resource-ownership races may retry; the next transaction rereads the
                // operation and grant bindings before any provider effect.
                await transaction.RollbackAsync(CancellationToken.None);
                if (attempt == 2)
                    return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
            }
            catch (Exception exception) when (IsRetryableTransientDatabaseFailure(exception, cancellationToken))
            {
                // A failed PostgreSQL attempt has no authoritative terminal result. Roll back the
                // whole transaction before retrying, and never expose bounded transient SQLSTATEs.
                await transaction.RollbackAsync(CancellationToken.None);
                if (attempt == 2)
                    return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
    }

    /// <inheritdoc />
    public async Task<RuntimeSeatRecoveryHttpResult> ReadCurrentAsync(
        string authenticatedClientId,
        RuntimeSeatRecoveryCurrentReadbackRequest request,
        CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        var requestId = Guid.Parse(request.RequestId);
        var reservationRef = Guid.Parse(request.ReservationRef);
        var recoveryRef = Guid.Parse(request.RecoveryOperationRef);
        var productId = Guid.Parse(request.ProductId);
        var ledger = await db.RuntimeSeatRecoveryAuthorizations.AsNoTracking().SingleOrDefaultAsync(item =>
            item.AuthenticatedClientId == authenticatedClientId && item.RequestId == requestId,
            cancellationToken);
        var reservation = await db.RuntimeSeatRecoveryReservations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ReservationRef == reservationRef, cancellationToken);
        var authority = await db.RuntimeSeatRecoveryAuthorities.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ReservationRef == reservationRef, cancellationToken);
        if (ledger is null || reservation is null || authority is null
            || ledger.ReservationRef != reservationRef || ledger.RecoveryOperationRef != recoveryRef
            || reservation.RecoveryOperationRef != recoveryRef || reservation.ProductId != productId
            || reservation.AuthenticatedClientId != authenticatedClientId || reservation.RequestId != requestId
            || !string.Equals(ledger.RequestDigestSha256, request.RequestDigestSha256, StringComparison.Ordinal))
        {
            await transaction.RollbackAsync(cancellationToken);
            return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
        }
        if (!await ValidateRecoveryGenerationAsync(db, authority, cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        }
        var previousResolution = await ResolvePreviousActiveAuthorityAsync(
            db, reservation.ProductId, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, authority.ArtifactSetDigestSha256, cancellationToken);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        }
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
        {
            await transaction.RollbackAsync(cancellationToken);
            return CommercialAuthorityDenial();
        }

        var grantDigest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(reservation.ProviderGrantRef)));
        var grant = await db.RuntimeRecoveryGrantOwnerships.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ProductId == productId
                && item.ProviderGrantRefDigestSha256 == grantDigest, cancellationToken);
        var owner = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ProductId == productId && item.LicenseId == reservation.LicenseId
                && item.State == "ACTIVE", cancellationToken);
        if (grant is null || owner is null
            || grant.AuthenticatedClientId != authenticatedClientId || grant.LicenseId != reservation.LicenseId
            || grant.CommercialOwnershipId != owner.Id || grant.OwnerSubjectId != owner.OwnerSubjectId
            || grant.RecoveryOperationRef != recoveryRef || grant.RecoveryDigestSha256 != ledger.RecoveryDigestSha256
            || grant.RequestId != requestId || authority.SubjectRefDigestSha256 != SubjectDigest(owner.OwnerSubjectId))
        {
            await transaction.RollbackAsync(cancellationToken);
            return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
        }

        var observed = await ReadDatabaseClockAsync(db, cancellationToken);
        previousResolution = await ReassessResolvedCommercialAuthorityAsync(
            db, previousResolution, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, observed, cancellationToken);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        }
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
        {
            await transaction.RollbackAsync(cancellationToken);
            return CommercialAuthorityDenial();
        }

        var previousAuthority = previousResolution.Authority;
        var previousAuthorityState = previousAuthority is not null
            && previousAuthority.HeadLineageId == authority.PreviousAuthorityLineageId
            && previousAuthority.HeadGenerationId == authority.PreviousAuthorityGenerationId
            ? authority.PreviousAuthorityState.ToLowerInvariant()
            : "conflict";
        var status = RuntimeSeatRecoveryContractCodec.ClassifyCurrentReadback(
            reservation.State.ToLowerInvariant(), authority.State.ToLowerInvariant(), authority.IsCurrentHead,
            previousAuthorityState, observed >= reservation.ExpiresAtUtc);
        var response = new RuntimeSeatRecoveryHttpResult(StatusCodes.Status200OK, ContentType,
            SerializeReadback(status, ledger, reservation, authority, observed, previousAuthorityState));
        await transaction.CommitAsync(cancellationToken);
        return response;
    }

    /// <inheritdoc />
    /// <remarks>
    /// A successful W10 response carries the positive security epoch from the exact persisted signed generation;
    /// missing, malformed, or out-of-range generation authority fails closed before preparation persistence.
    /// </remarks>
    public async Task<RuntimeSeatRecoveryHttpResult> PrepareKeyAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryContractCodec.KeyPreparationParseResult parsed,
        CancellationToken cancellationToken)
    {
        if (!parsed.IsSuccess || parsed.Request is null
            || !string.Equals(routeRequestId, parsed.Request.RequestId, StringComparison.Ordinal))
            return Transport(StatusCodes.Status400BadRequest, "invalid_request");

        var request = parsed.Request;
        if (!TryValidateRecoverySpki(request.PublicKeySpki, out var spki, out var spkiDigest, out var thumbprint))
            return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
        try
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
                await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
                try
                {
                    await SetTransactionGuardsAsync(db, cancellationToken);
                    await AcquireKeyProofLockAsync(db, authenticatedClientId, request.RequestId, cancellationToken);
                    var existing = await ReadPreparationForUpdateAsync(db, authenticatedClientId,
                        Guid.Parse(request.RequestId), cancellationToken);
                    if (existing is not null
                        && !CryptographicOperations.FixedTimeEquals(existing.CanonicalRequestUtf8, parsed.CanonicalUtf8))
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
                    }

                    var scope = await LockAndValidateKeyScopeAsync(db, authenticatedClientId, request.ProductId,
                        request.RequestId, request.RequestDigestSha256, request.RecoveryOperationRef,
                        request.ReservationRef, request.EnrollmentId, request.AuthorityGenerationId,
                        spkiDigest, thumbprint, cancellationToken);
                    if (scope is null)
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
                    }
                    if (existing is not null)
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return new(StatusCodes.Status200OK, ContentType, [.. existing.ExactResponseUtf8]);
                    }

                    var now = await ReadDatabaseClockAsync(db, cancellationToken);
                    var expiresAt = new[] { now.AddMinutes(5), scope.Reservation.ExpiresAtUtc }.Min();
                    if (now >= expiresAt)
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return Transport(StatusCodes.Status410Gone, "confirmation_expired");
                    }

                    var prepareRef = Guid.CreateVersion7(new DateTimeOffset(now, TimeSpan.Zero));
                    var challenge = RandomNumberGenerator.GetBytes(32);
                    try
                    {
                        var spkiEnvelope = await crypto.SealAsync(db, "recovery-key-spki", prepareRef, 1, spki,
                            PreparationFieldReference(prepareRef, "PublicKeySpkiCiphertext"), cancellationToken);
                        var challengeEnvelope = await crypto.SealAsync(db, "recovery-key-challenge", prepareRef, 1,
                            challenge, PreparationFieldReference(prepareRef, "ChallengeCiphertext"), cancellationToken);
                        var challengeText = EncodeBase64Url(challenge);
                        var response = SerializeKeyPreparationResponse(
                            request, prepareRef, scope.SecurityEpoch, challengeText, expiresAt);
                        db.RuntimeSeatRecoveryKeyPreparations.Add(new RuntimeSeatRecoveryKeyPreparation
                        {
                            PrepareRef = prepareRef,
                            AuthenticatedClientId = authenticatedClientId,
                            ProductId = Guid.Parse(request.ProductId),
                            RequestId = Guid.Parse(request.RequestId),
                            RequestDigestSha256 = request.RequestDigestSha256,
                            RecoveryOperationRef = Guid.Parse(request.RecoveryOperationRef),
                            ReservationRef = Guid.Parse(request.ReservationRef),
                            EnrollmentId = Guid.Parse(request.EnrollmentId),
                            AuthorityGenerationId = Guid.Parse(request.AuthorityGenerationId),
                            CanonicalRequestUtf8 = [.. parsed.CanonicalUtf8],
                            PublicKeySpkiSha256 = spkiDigest,
                            PublicKeySpkiCiphertext = spkiEnvelope.Ciphertext,
                            PublicKeySpkiKeyId = spkiEnvelope.KeyId,
                            ChallengeDigestSha256 = Convert.ToHexStringLower(SHA256.HashData(challenge)),
                            ChallengeCiphertext = challengeEnvelope.Ciphertext,
                            ChallengeKeyId = challengeEnvelope.KeyId,
                            ConfirmAudience = ConfirmationAudience,
                            ExactResponseUtf8 = response,
                            CreatedAtUtc = now,
                            ExpiresAtUtc = expiresAt
                        });
                        await db.SaveChangesAsync(cancellationToken);
                        await transaction.CommitAsync(cancellationToken);
                        return new(StatusCodes.Status200OK, ContentType, response);
                    }
                    finally { CryptographicOperations.ZeroMemory(challenge); }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    throw;
                }
                catch (Exception exception) when (IsCallerCancellationDatabaseFailure(exception, cancellationToken))
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    throw new OperationCanceledException("Runtime recovery key preparation was canceled by the caller.",
                        exception, cancellationToken);
                }
                catch (RuntimeEnrollmentException exception)
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    return Transport(exception.StatusCode, exception.ErrorCode);
                }
                catch (Exception exception) when (IsRetryableTransientDatabaseFailure(exception, cancellationToken)
                    || IsKeyProofUniqueViolation(exception))
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    if (attempt == 2) return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
                }
                catch
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    throw;
                }
            }
            return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        }
        finally { CryptographicOperations.ZeroMemory(spki); }
    }

    /// <inheritdoc />
    /// <remarks>
    /// A successful W10.2 response repeats the W10 epoch from the same signed generation and freezes the exact
    /// response bytes for idempotent replay; the proof does not derive an epoch from preparation state.
    /// </remarks>
    public async Task<RuntimeSeatRecoveryHttpResult> ConfirmKeyAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryContractCodec.KeyConfirmationParseResult parsed,
        CancellationToken cancellationToken)
    {
        if (!parsed.IsSuccess || parsed.Request is null || parsed.ConfirmationRequestSha256 is null
            || !string.Equals(routeRequestId, parsed.Request.RequestId, StringComparison.Ordinal))
            return Transport(StatusCodes.Status400BadRequest, "invalid_request");

        var request = parsed.Request;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
            try
            {
                await SetTransactionGuardsAsync(db, cancellationToken);
                await AcquireKeyProofLockAsync(db, authenticatedClientId, request.PrepareRef, cancellationToken);
                var existing = await ReadConfirmationForUpdateAsync(db, authenticatedClientId,
                    Guid.Parse(request.PrepareRef), cancellationToken);
                if (existing is not null)
                {
                    if (!string.Equals(existing.ConfirmationRequestSha256,
                            parsed.ConfirmationRequestSha256, StringComparison.Ordinal))
                    {
                        var conflictAt = await ReadDatabaseClockAsync(db, cancellationToken);
                        await transaction.RollbackAsync(cancellationToken);
                        return KeyConfirmationError(request, "idempotency_conflict",
                            StatusCodes.Status409Conflict, conflictAt);
                    }
                    if (!string.Equals(existing.State, "PROVED", StringComparison.Ordinal)
                        || existing.HttpStatusCode != StatusCodes.Status200OK)
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return new(existing.HttpStatusCode, existing.ContentType, [.. existing.ExactResponseUtf8]);
                    }
                }

                var preparation = await ReadPreparationByReferenceForUpdateAsync(db, authenticatedClientId,
                    Guid.Parse(request.PrepareRef), cancellationToken);
                if (preparation is null || !MatchesPreparationOuter(preparation, request))
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
                }

                var scope = await LockAndValidateKeyScopeAsync(db, authenticatedClientId, request.ProductId,
                    request.RequestId, request.RequestDigestSha256, request.RecoveryOperationRef,
                    request.ReservationRef, request.EnrollmentId, request.AuthorityGenerationId,
                    request.PublicKeySpkiSha256, null, cancellationToken);
                if (scope is null || preparation.ChallengeConsumedAtUtc is not null)
                {
                    if (existing is not null && scope is not null)
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return new(existing.HttpStatusCode, existing.ContentType, [.. existing.ExactResponseUtf8]);
                    }
                    await transaction.RollbackAsync(cancellationToken);
                    return Transport(StatusCodes.Status409Conflict, "confirmation_state_conflict");
                }

                if (existing is not null)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return new(existing.HttpStatusCode, existing.ContentType, [.. existing.ExactResponseUtf8]);
                }

                var now = await ReadDatabaseClockAsync(db, cancellationToken);
                var receiptExpiry = preparation.ExpiresAtUtc <= scope.Reservation.ExpiresAtUtc
                    ? preparation.ExpiresAtUtc : scope.Reservation.ExpiresAtUtc;
                if (now >= receiptExpiry)
                {
                    var expired = FreezeConfirmationRefusal(db, authenticatedClientId, preparation, request,
                        parsed, now, "confirmation_expired", StatusCodes.Status410Gone);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return expired;
                }

                var statement = request.ConfirmationStatement;
                if (!MatchesStatement(request, statement, preparation))
                {
                    var refused = FreezeConfirmationRefusal(db, authenticatedClientId, preparation, request,
                        parsed, now, "recovery_not_authorized", StatusCodes.Status403Forbidden);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return refused;
                }

                var challenge = RuntimeSeatRecoveryContractCodec.DecodeBase64Url(statement.Challenge)!;
                var signature = RuntimeSeatRecoveryContractCodec.DecodeBase64Url(request.ConfirmationSignature)!;
                var signatureInput = RuntimeSeatRecoveryContractCodec.BuildConfirmationSignatureInput(
                    parsed.ConfirmationStatementUtf8);
                byte[]? spki = null;
                byte[]? challengeDigest = null;
                byte[]? expectedChallengeDigest = null;
                try
                {
                    challengeDigest = SHA256.HashData(challenge);
                    expectedChallengeDigest = Convert.FromHexString(preparation.ChallengeDigestSha256);
                    if (!CryptographicOperations.FixedTimeEquals(
                            challengeDigest, expectedChallengeDigest))
                    {
                        var refused = FreezeConfirmationRefusal(db, authenticatedClientId, preparation, request,
                            parsed, now, "recovery_not_authorized", StatusCodes.Status403Forbidden);
                        await db.SaveChangesAsync(cancellationToken);
                        await transaction.CommitAsync(cancellationToken);
                        return refused;
                    }
                    spki = crypto.Open("recovery-key-spki", preparation.PrepareRef, 1,
                        preparation.PublicKeySpkiKeyId, preparation.PublicKeySpkiCiphertext,
                        PreparationFieldReference(preparation.PrepareRef, "PublicKeySpkiCiphertext"));
                    if (!VerifyConfirmationSignature(spki, signatureInput, signature))
                    {
                        var refused = FreezeConfirmationRefusal(db, authenticatedClientId, preparation, request,
                            parsed, now, "recovery_not_authorized", StatusCodes.Status403Forbidden);
                        await db.SaveChangesAsync(cancellationToken);
                        await transaction.CommitAsync(cancellationToken);
                        return refused;
                    }

                    var response = SerializeProofResponse(
                        request, scope.SecurityEpoch, parsed.ConfirmationRequestSha256, now, receiptExpiry);
                    preparation.ChallengeConsumedAtUtc = now;
                    db.RuntimeSeatRecoveryKeyConfirmations.Add(new RuntimeSeatRecoveryKeyConfirmation
                    {
                        AuthenticatedClientId = authenticatedClientId,
                        PrepareRef = preparation.PrepareRef,
                        ConfirmationRequestSha256 = parsed.ConfirmationRequestSha256,
                        CanonicalRequestUtf8 = [.. parsed.CanonicalUtf8],
                        State = "PROVED",
                        HttpStatusCode = StatusCodes.Status200OK,
                        ContentType = ContentType,
                        ExactResponseUtf8 = response,
                        CompletedAtUtc = now
                    });
                    db.RuntimeSeatRecoveryProofReceipts.Add(new RuntimeSeatRecoveryProofReceipt
                    {
                        AuthenticatedClientId = authenticatedClientId,
                        PrepareRef = preparation.PrepareRef,
                        ProductId = preparation.ProductId,
                        RequestId = preparation.RequestId,
                        RequestDigestSha256 = preparation.RequestDigestSha256,
                        RecoveryOperationRef = preparation.RecoveryOperationRef,
                        ReservationRef = preparation.ReservationRef,
                        EnrollmentId = preparation.EnrollmentId,
                        AuthorityGenerationId = preparation.AuthorityGenerationId,
                        PublicKeySpkiSha256 = preparation.PublicKeySpkiSha256,
                        ConfirmationRequestSha256 = parsed.ConfirmationRequestSha256,
                        State = "PROVED",
                        ProvedAtUtc = now,
                        PreparationExpiresAtUtc = preparation.ExpiresAtUtc,
                        ReservationExpiresAtUtc = scope.Reservation.ExpiresAtUtc,
                        ExpiresAtUtc = receiptExpiry
                    });
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return new(StatusCodes.Status200OK, ContentType, response);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(challenge);
                    CryptographicOperations.ZeroMemory(signature);
                    CryptographicOperations.ZeroMemory(signatureInput);
                    if (challengeDigest is not null) CryptographicOperations.ZeroMemory(challengeDigest);
                    if (expectedChallengeDigest is not null) CryptographicOperations.ZeroMemory(expectedChallengeDigest);
                    if (spki is not null) CryptographicOperations.ZeroMemory(spki);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
            catch (Exception exception) when (IsCallerCancellationDatabaseFailure(exception, cancellationToken))
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw new OperationCanceledException("Runtime recovery key confirmation was canceled by the caller.",
                    exception, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Transport(exception.StatusCode, exception.ErrorCode);
            }
            catch (Exception exception) when (IsRetryableTransientDatabaseFailure(exception, cancellationToken)
                || IsKeyProofUniqueViolation(exception))
            {
                await transaction.RollbackAsync(CancellationToken.None);
                if (attempt == 2) return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
    }

    /// <inheritdoc />
    public async Task<RuntimeSeatRecoveryHttpResult> ActivateAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryContractCodec.ActivationParseResult parsed,
        CancellationToken cancellationToken)
    {
        if (!parsed.IsSuccess || parsed.Request is null || parsed.ActivationRequestDigestSha256 is null
            || !string.Equals(routeRequestId, parsed.Request.RequestId, StringComparison.Ordinal))
            return Transport(StatusCodes.Status400BadRequest, "invalid_request");

        var request = parsed.Request;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
            try
            {
                await SetTransactionGuardsAsync(db, cancellationToken);
                await AcquireActivationLockAsync(db, authenticatedClientId, request.RequestId, cancellationToken);
                var existing = await ReadActivationReceiptForUpdateAsync(db, authenticatedClientId,
                    Guid.Parse(request.RequestId), cancellationToken);
                if (existing is not null)
                {
                    var exact = string.Equals(existing.ActivationRequestDigestSha256,
                            parsed.ActivationRequestDigestSha256, StringComparison.Ordinal)
                        && CryptographicOperations.FixedTimeEquals(existing.CanonicalRequestUtf8, parsed.CanonicalUtf8);
                    await transaction.RollbackAsync(cancellationToken);
                    return exact
                        ? new(existing.HttpStatusCode, existing.ContentType, [.. existing.ExactResponseUtf8])
                        : Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
                }

                var scope = await LockActivationScopeAsync(db, authenticatedClientId, request, cancellationToken);
                if (scope is null)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
                }

                var decisionNow = await ReadDatabaseClockAsync(db, cancellationToken);
                if (decisionNow >= scope.Proof.ExpiresAtUtc)
                {
                    var expired = FreezeActivationReceipt(db, authenticatedClientId, parsed, scope,
                        "activation_expired", StatusCodes.Status410Gone, decisionNow);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return expired;
                }
                if (!scope.ProviderCompatible)
                {
                    var conflict = FreezeActivationReceipt(db, authenticatedClientId, parsed, scope,
                        "activation_conflict", StatusCodes.Status409Conflict, decisionNow);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return conflict;
                }

                var sourceAssignmentCount = await db.EnrollmentLicenseAssignments
                    .Where(item => item.Id == scope.PreviousAuthority.SourceAssignmentId
                        && item.EnrollmentId == scope.PreviousAuthority.EnrollmentId
                        && item.LicenseId == scope.Reservation.LicenseId
                        && item.LicenseSeatId == scope.Reservation.LicenseSeatId
                        && item.State == "ACTIVE"
                        && item.EndedAtUtc == null
                        && item.EndReason == null)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(item => item.State, "ENDED")
                        .SetProperty(item => item.EndedAtUtc, decisionNow)
                        .SetProperty(item => item.EndReason, IdentityRecoveredAssignmentEndReason),
                        cancellationToken);
                var previousBindingCount = sourceAssignmentCount == 1
                    ? await db.DistributionInstallationBindings
                    .Where(item => item.Id == scope.PreviousAuthority.BindingId
                        && item.ProductId == scope.Reservation.ProductId
                        && item.LicenseId == scope.Reservation.LicenseId
                        && item.LicenseSeatId == scope.Reservation.LicenseSeatId
                        && item.State == "active"
                        && item.InvalidatedAtUtc == null
                        && item.InvalidationReason == null)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(item => item.State, "invalidated")
                        .SetProperty(item => item.InvalidatedAtUtc, decisionNow)
                        .SetProperty(item => item.InvalidationReason, "installation_superseded"),
                        cancellationToken)
                    : 0;
                var previousEnrollmentCount = previousBindingCount == 1
                    ? await db.RuntimeEnrollments
                        .Where(item => item.Id == scope.PreviousAuthority.EnrollmentId
                            && item.BindingId == scope.PreviousAuthority.BindingId
                            && item.ProductId == scope.Reservation.ProductId
                            && item.State == "ACTIVE"
                            && item.InvalidatedAtUtc == null
                            && item.InvalidationReason == null)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(item => item.State, "INVALIDATED")
                            .SetProperty(item => item.InvalidatedAtUtc, decisionNow)
                            .SetProperty(item => item.InvalidationReason, "binding_superseded"),
                            cancellationToken)
                    : 0;
                var authorityCount = previousEnrollmentCount == 1
                    ? await db.RuntimeSeatRecoveryAuthorities
                    .Where(item => item.ReservationRef == scope.Reservation.ReservationRef
                        && item.PreviousAuthorityLineageId == scope.Authority.PreviousAuthorityLineageId
                        && item.PreviousAuthorityGenerationId == scope.Authority.PreviousAuthorityGenerationId
                        && item.AuthorityLineageId == scope.Authority.AuthorityLineageId
                        && item.AuthorityGenerationId == scope.Authority.AuthorityGenerationId
                        && item.LicenseSeatId == scope.Reservation.LicenseSeatId
                        && item.PreviousAuthorityState == "ACTIVE" && item.State == "PREPARED"
                        && item.IsCurrentHead)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(item => item.PreviousAuthorityState, "SUPERSEDED")
                        .SetProperty(item => item.State, "ACTIVE"), cancellationToken)
                    : 0;
                var reservationCount = authorityCount == 1
                    ? await db.RuntimeSeatRecoveryReservations
                        .Where(item => item.ReservationRef == scope.Reservation.ReservationRef
                            && item.AuthenticatedClientId == authenticatedClientId
                            && item.RequestId == scope.Reservation.RequestId
                            && item.RecoveryOperationRef == scope.Reservation.RecoveryOperationRef
                            && item.State == "RESERVED")
                        .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.State, "COMMITTED"),
                            cancellationToken)
                    : 0;
                if (sourceAssignmentCount != 1 || previousBindingCount != 1 || previousEnrollmentCount != 1
                    || authorityCount != 1 || reservationCount != 1)
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
                }

                var response = SerializeActivationResponse(request, parsed.ActivationRequestDigestSha256,
                    scope, decisionNow);
                AddActivationReceipt(db, authenticatedClientId, parsed, scope, "COMMITTED",
                    StatusCodes.Status200OK, null, response, decisionNow);
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return new(StatusCodes.Status200OK, ContentType, response);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
            catch (Exception exception) when (IsCallerCancellationDatabaseFailure(exception, cancellationToken))
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw new OperationCanceledException("Runtime recovery activation was canceled by the caller.",
                    exception, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Transport(exception.StatusCode, exception.ErrorCode);
            }
            catch (Exception exception) when (IsRetryableTransientDatabaseFailure(exception, cancellationToken)
                || IsActivationUniqueViolation(exception))
            {
                await transaction.RollbackAsync(CancellationToken.None);
                if (attempt == 2) return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
    }

    /// <inheritdoc />
    public async Task<RuntimeSeatRecoveryHttpResult> ReadActivationAsync(
        string authenticatedClientId,
        string routeRequestId,
        RuntimeSeatRecoveryActivationReadbackRequest request,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(routeRequestId, request.RequestId, StringComparison.Ordinal))
            return Transport(StatusCodes.Status400BadRequest, "invalid_request");
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
        var receipt = await db.RuntimeSeatRecoveryActivationReceipts.AsNoTracking().SingleOrDefaultAsync(item =>
            item.AuthenticatedClientId == authenticatedClientId && item.RequestId == Guid.Parse(request.RequestId),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return receipt is not null && receipt.ProductId == Guid.Parse(request.ProductId)
            && string.Equals(receipt.ActivationRequestDigestSha256,
                request.ActivationRequestDigestSha256, StringComparison.Ordinal)
            ? new(receipt.HttpStatusCode, receipt.ContentType, [.. receipt.ExactResponseUtf8])
            : Transport(StatusCodes.Status403Forbidden, "recovery_not_authorized");
    }

    /// <summary>
    /// Creates exactly one terminal result after locking the source enrollment, taking the shared item 2
    /// barrier, and revalidating immutable proof plus the source's ACTIVE assignment. Commercial ownership
    /// remains request-lineage proof and never substitutes for assignment B. Success leaves lifecycle state
    /// strictly RESERVED/PREPARED; divergent or historical-null proof freezes a semantic refusal instead.
    /// </summary>
    /// <param name="db">The context enlisted in the caller's locked ReadCommitted provider transaction.</param>
    /// <param name="clientId">The exact authenticated client namespace used for locking and idempotency.</param>
    /// <param name="parsed">The canonical request and byte-derived digest validated before this decision.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through provider reads and persistence.</param>
    /// <returns>The exact authorized or frozen-refusal HTTP bytes produced inside the ambient transaction.</returns>
    private async Task<RuntimeSeatRecoveryHttpResult> CreateTerminalAsync(
        LicenseDbContext db,
        string clientId,
        RuntimeSeatRecoveryContractCodec.AuthorizationParseResult parsed,
        CancellationToken cancellationToken)
    {
        var request = parsed.Request!;
        var requestId = Guid.Parse(request.RequestId);
        var productId = Guid.Parse(request.ProductId);
        var licenseId = Guid.Parse(request.LicenseId);
        var recoveryRef = Guid.Parse(request.RecoveryOperationRef);
        var requestedExpiry = DateTime.ParseExact(request.ExpiresAtUtc, UtcFormat,
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

        // Select only a candidate seat identifier before taking business-row locks. The source enrollment
        // is then locked before the shared commercial barrier; every mutable seat and licence fact is
        // reread below while that barrier is held.
        RuntimeSeatRecoverySeatClaimPlaintext? claim = request.SeatClaim is null
            ? null : seatClaimCryptography.Open(request.SeatClaim);
        Guid? candidateSeatId = null;
        if (request.SeatClaim is null)
        {
            var candidateSeatIds = await db.LicenseSeats.AsNoTracking()
                .Where(row => row.LicenseId == licenseId && row.IsActive
                    && !db.RuntimeSeatRecoveryReservations.Any(reservation =>
                        reservation.LicenseSeatId == row.Id && reservation.State == "RESERVED"))
                .OrderBy(row => row.Id)
                .Select(row => row.Id)
                .Take(2)
                .ToListAsync(cancellationToken);
            if (candidateSeatIds.Count == 1)
                candidateSeatId = candidateSeatIds[0];
        }
        else if (claim is not null && Guid.TryParseExact(claim.SeatId, "D", out var claimedSeatId))
        {
            candidateSeatId = claimedSeatId;
        }

        var previousResolution = candidateSeatId is null
            ? PreviousAuthorityResolution.Invalid("previous_seat_unresolved")
            : await ResolvePreviousActiveAuthorityAsync(
                db, productId, licenseId, candidateSeatId.Value,
                request.Release.Version, request.Release.ArtifactSetDigestSha256, cancellationToken);

        var license = await db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses" WHERE "Id" = {licenseId} FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var invalidLicense = license is null || license.ProductId != productId
            || !license.IsActive || license.RevokedAt is not null;

        var owner = await ResolveOwnerAsync(db, productId, licenseId, cancellationToken);
        var grantDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(request.ProviderGrantRef)));
        var grantBindings = await db.RuntimeRecoveryGrantOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryGrantOwnerships"
            WHERE "RecoveryOperationRef" = {recoveryRef}
               OR ("ProductId" = {productId} AND "ProviderGrantRefDigestSha256" = {grantDigest})
            ORDER BY "ProductId", "ProviderGrantRefDigestSha256"
            FOR UPDATE
            """).ToListAsync(cancellationToken);
        var operationGrant = grantBindings.SingleOrDefault(item => item.RecoveryOperationRef == recoveryRef);
        var grant = grantBindings.SingleOrDefault(item => item.ProductId == productId
            && string.Equals(item.ProviderGrantRefDigestSha256, grantDigest, StringComparison.Ordinal));
        var invalidGrantBinding = owner is not null
            && (operationGrant is not null && !GrantBindingMatches(operationGrant, clientId, requestId,
                    productId, licenseId, owner.Id, owner.OwnerSubjectId, recoveryRef, grantDigest,
                    request.RecoveryDigestSha256)
                || grant is not null && !GrantBindingMatches(grant, clientId, requestId,
                    productId, licenseId, owner.Id, owner.OwnerSubjectId, recoveryRef, grantDigest,
                    request.RecoveryDigestSha256));

        var seats = await db.LicenseSeats.FromSqlInterpolated($"""
            SELECT * FROM public."LicenseSeats"
            WHERE "LicenseId" = {licenseId} AND "IsActive" = TRUE
              AND NOT EXISTS (
                  SELECT 1 FROM public."RuntimeSeatRecoveryReservations" reservation
                  WHERE reservation."LicenseSeatId" = public."LicenseSeats"."Id"
                    AND reservation."State" = 'RESERVED')
            ORDER BY "Id" FOR UPDATE
            """).ToListAsync(cancellationToken);
        LicenseSeat? seat;
        string? seatSelectionError = null;
        DateTime? claimIssuedAt = null;
        DateTime? claimExpiresAt = null;
        var claimRevoked = false;
        var invalidClaimShape = false;
        if (request.SeatClaim is null)
        {
            if (seats.Count != 1)
                seatSelectionError = seats.Count == 0 ? "seat_unavailable" : "seat_selection_required";
            seat = seats.Count == 1 ? seats[0] : null;
        }
        else
        {
            var claimedSeatId = claim is null || !Guid.TryParseExact(claim.SeatId, "D", out var parsedSeatId)
                ? Guid.Empty : parsedSeatId;
            seat = seats.SingleOrDefault(candidate => candidate.Id == claimedSeatId);
            claimIssuedAt = ParseClaimTimestamp(claim?.IssuedAtUtc);
            claimExpiresAt = ParseClaimTimestamp(claim?.ExpiresAtUtc);
            var claimNonce = claim is null || !Guid.TryParseExact(claim.Nonce, "D", out var parsedNonce)
                ? Guid.Empty : parsedNonce;
            claimRevoked = claimNonce != Guid.Empty && await db.RuntimeSeatRecoveryRevokedClaimNonces.AsNoTracking()
                .AnyAsync(item => item.Nonce == claimNonce, cancellationToken);
            invalidClaimShape = claim is null || seat is null || claimIssuedAt is null || claimExpiresAt is null
                || claim.Purpose != "runtime_identity_recovery_seat_selection"
                || owner is null || claim.OwnerSubjectRefDigestSha256 != SubjectDigest(owner.OwnerSubjectId)
                || claim.ProductId != request.ProductId || claim.LicenseId != request.LicenseId
                || claim.SeatRevision != SeatRevision(seat)
                || claimExpiresAt <= claimIssuedAt
                || claimExpiresAt.Value - claimIssuedAt.Value > TimeSpan.FromSeconds(300)
                || claimRevoked;
        }

        var providerStateInvalid = seat is null
            || !IsProviderKeyCommitmentValid(request.NewKeyCommitment)
            || license is null || !IsVersionAllowed(request.Release.Version, license.AllowedVersions)
            || !await HasAuthoritativeReleaseAsync(db, productId, request.Release.Version,
                request.Release.ArtifactSetDigestSha256, cancellationToken);

        // This is the only business-decision instant for the attempt. Every decisive provider row
        // lock and immutable authority read above precedes it, so lock waits cannot extend validity.
        var decisionNow = await ReadDatabaseClockAsync(db, cancellationToken);
        if (requestedExpiry <= decisionNow)
            return await FreezeRefusalAsync(db, clientId, parsed, "authorization_expired",
                StatusCodes.Status410Gone, decisionNow, cancellationToken);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
            return Transport(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
            return CommercialAuthorityDenial();
        if (invalidLicense || license!.ExpirationDate is { } licenseExpiry && licenseExpiry <= decisionNow
            || owner is null || invalidGrantBinding)
            return await FreezeRefusalAsync(db, clientId, parsed, "recovery_not_authorized",
                StatusCodes.Status403Forbidden, decisionNow, cancellationToken);
        if (seatSelectionError is not null)
            return await FreezeRefusalAsync(db, clientId, parsed, seatSelectionError,
                StatusCodes.Status409Conflict, decisionNow, cancellationToken);
        if (invalidClaimShape || claimIssuedAt > decisionNow || decisionNow >= claimExpiresAt)
            return await FreezeRefusalAsync(db, clientId, parsed, "recovery_not_authorized",
                StatusCodes.Status403Forbidden, decisionNow, cancellationToken);
        if (providerStateInvalid || await HasActiveSecurityBanAsync(db, productId, seat!.HardwareId,
                request.Release.Version, decisionNow, cancellationToken))
            return await FreezeRefusalAsync(db, clientId, parsed, "recovery_not_authorized",
                StatusCodes.Status403Forbidden, decisionNow, cancellationToken);
        if (previousResolution.Authority is null)
            return await FreezeRefusalAsync(db, clientId, parsed, "authority_state_conflict",
                StatusCodes.Status409Conflict, decisionNow, cancellationToken);
        var previousAuthority = previousResolution.Authority;

        var reservationRef = Guid.NewGuid();
        var lineageId = Guid.NewGuid();
        var generationId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var enrollmentId = Guid.NewGuid();
        var installationId = Guid.Parse(request.Installation.InstallationId);
        var providerExpiry = new[] { requestedExpiry, decisionNow.AddMinutes(10) }.Min();
        var subjectDigest = SubjectDigest(owner.OwnerSubjectId);
        var signed = SignGeneration(request, requestId, seat.Id, lineageId, generationId, bindingId,
            enrollmentId, decisionNow, providerExpiry);
        var response = SerializeAuthorized(request, parsed.RequestDigestSha256!, reservationRef, subjectDigest,
            seat.Id, bindingId, enrollmentId, decisionNow, providerExpiry, signed.StatementUtf8);
        var candidate = new RuntimeEnrollmentAuthorityPersistenceCandidate
        {
            AuthorityLineageId = lineageId,
            AuthorityGenerationId = generationId,
            RequestId = requestId,
            RequestDigest = parsed.RequestDigestSha256!,
            Provider = "softlicence",
            ProductId = productId,
            LicenseSeatId = seat.Id,
            ProviderGrantRef = request.ProviderGrantRef,
            ProviderGrantRefScalarCount = request.ProviderGrantRef.EnumerateRunes().Count(),
            LineageCreatedAtUtc = decisionNow,
            Sequence = 0,
            PreviousGenerationId = null,
            CanonicalPayloadUtf8 = signed.CanonicalPayloadUtf8,
            SignedStatementUtf8 = signed.StatementUtf8,
            AuthorityDigest = signed.AuthorityDigest,
            SignatureAlgorithm = "PS256",
            SignatureKeyId = signed.KeyId,
            SignatureValue = signed.Signature,
            OccurredAtUtc = decisionNow,
            CreatedAtUtc = decisionNow
        };
        var persistence = await authorityPersistence.PersistRecoveryGenesisInAmbientTransactionAsync(
            db, candidate, cancellationToken);
        if (persistence.Status == RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict)
            return await FreezeRefusalAsync(db, clientId, parsed, "authority_state_conflict",
                StatusCodes.Status409Conflict, decisionNow, cancellationToken);

        db.RuntimeSeatRecoveryAuthorizations.Add(new RuntimeSeatRecoveryAuthorization
        {
            AuthenticatedClientId = clientId,
            RequestId = requestId,
            RequestDigestSha256 = parsed.RequestDigestSha256!,
            RecoveryOperationRef = recoveryRef,
            RecoveryDigestSha256 = request.RecoveryDigestSha256,
            CanonicalRequestUtf8 = parsed.CanonicalUtf8,
            ReservationRef = reservationRef,
            Decision = "AUTHORIZED",
            HttpStatusCode = StatusCodes.Status200OK,
            ContentType = ContentType,
            ExactResponseUtf8 = response,
            CompletedAtUtc = decisionNow
        });
        db.RuntimeSeatRecoveryReservations.Add(new RuntimeSeatRecoveryReservation
        {
            ReservationRef = reservationRef,
            AuthenticatedClientId = clientId,
            RequestId = requestId,
            ProductId = productId,
            LicenseId = licenseId,
            LicenseSeatId = seat.Id,
            RecoveryOperationRef = recoveryRef,
            ProviderGrantRef = request.ProviderGrantRef,
            State = "RESERVED",
            CreatedAtUtc = decisionNow,
            ExpiresAtUtc = providerExpiry
        });
        db.RuntimeSeatRecoveryAuthorities.Add(new RuntimeSeatRecoveryAuthority
        {
            ReservationRef = reservationRef,
            AuthorityLineageId = lineageId,
            AuthorityGenerationId = generationId,
            PreviousAuthorityLineageId = previousAuthority.HeadLineageId,
            PreviousAuthorityGenerationId = previousAuthority.HeadGenerationId,
            BindingId = bindingId,
            EnrollmentId = enrollmentId,
            LicenseSeatId = seat.Id,
            InstallationId = installationId,
            HardwareIdDigestSha256 = request.Installation.HardwareIdDigestSha256,
            ReleaseVersion = request.Release.Version,
            ArtifactSetDigestSha256 = request.Release.ArtifactSetDigestSha256,
            PublicKeySpkiSha256 = request.NewKeyCommitment.PublicKeySpkiSha256,
            KeyThumbprint = request.NewKeyCommitment.KeyThumbprint,
            State = "PREPARED",
            IsCurrentHead = true,
            PreviousAuthorityState = "ACTIVE",
            SubjectRefDigestSha256 = subjectDigest,
            CreatedAtUtc = decisionNow
        });
        if (grant is null)
            db.RuntimeRecoveryGrantOwnerships.Add(new RuntimeRecoveryGrantOwnership
            {
                ProductId = productId,
                ProviderGrantRefDigestSha256 = grantDigest,
                AuthenticatedClientId = clientId,
                LicenseId = licenseId,
                CommercialOwnershipId = owner.Id,
                OwnerSubjectId = owner.OwnerSubjectId,
                RecoveryOperationRef = recoveryRef,
                RecoveryDigestSha256 = request.RecoveryDigestSha256,
                RequestId = requestId,
                CreatedAtUtc = decisionNow
            });
        await db.SaveChangesAsync(cancellationToken);
        return new(StatusCodes.Status200OK, ContentType, response);
    }

    /// <summary>
    /// Revalidates the exact release registration and its three provider-owned child artifacts inside
    /// the caller's locked transaction. Missing, ambiguous, cross-scope, or divergent state fails closed.
    /// </summary>
    private static async Task<bool> HasAuthoritativeReleaseAsync(
        LicenseDbContext db,
        Guid productId,
        string version,
        string expectedDigestSha256,
        CancellationToken cancellationToken)
    {
        var registrations = await db.ApprovedBinaryRegistrations.AsNoTracking()
            .Include(registration => registration.Artifacts)
            .Where(registration => registration.ProductId == productId
                && registration.Version == version
                && registration.Source == ApprovedBinaryService.ReleaseSource)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (registrations.Count != 1)
            return false;

        var registration = registrations[0];
        if (!string.Equals(registration.BaselineDigestSha256, expectedDigestSha256, StringComparison.Ordinal)
            || !ApprovedBinaryService.IsCanonicalSha256(registration.BaselineDigestSha256)
            || registration.Artifacts.Count != RequiredBinaryKeys.Length)
            return false;

        var exact = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var artifact in registration.Artifacts)
        {
            if (artifact.ApprovedBinaryRegistrationId != registration.Id
                || artifact.ProductId != productId
                || !string.Equals(artifact.Version, version, StringComparison.Ordinal)
                || !string.Equals(artifact.Source, ApprovedBinaryService.ReleaseSource, StringComparison.Ordinal)
                || !RequiredBinaryKeySet.Contains(artifact.Key)
                || !ApprovedBinaryService.IsCanonicalSha256(artifact.Hash)
                || !exact.TryAdd(artifact.Key, artifact.Hash))
                return false;
        }

        if (RequiredBinaryKeys.Any(key => !exact.ContainsKey(key)))
            return false;
        var artifacts = RequiredBinaryKeys
            .Select(key => new ApprovedBinaryArtifact(key, exact[key]))
            .ToList();
        return string.Equals(ApprovedBinaryService.ComputeBaselineDigestSha256(artifacts),
            expectedDigestSha256, StringComparison.Ordinal);
    }

    /// <summary>
    /// Rejects active, non-expired provider bans scoped globally or to the requested product. Component
    /// evidence comes only from the authoritative release registration revalidated immediately beforehand.
    /// </summary>
    private static async Task<bool> HasActiveSecurityBanAsync(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string version,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var hardwareBans = await db.BannedHardwareIds.AsNoTracking()
            .Where(ban => ban.IsActive
                && (ban.ProductId == null || ban.ProductId == productId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => ban.HardwareId)
            .ToListAsync(cancellationToken);
        if (hardwareBans.Any(candidate => string.Equals(candidate, hardwareId,
                StringComparison.OrdinalIgnoreCase)))
            return true;

        var componentBans = await db.BannedComponents.AsNoTracking()
            .Where(ban => ban.IsActive
                && (ban.ProductId == null || ban.ProductId == productId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        if (componentBans.Count == 0)
            return false;

        var artifacts = await db.ApprovedBinaries.AsNoTracking()
            .Where(artifact => artifact.ProductId == productId
                && artifact.Version == version
                && artifact.Source == ApprovedBinaryService.ReleaseSource
                && artifact.ApprovedBinaryRegistrationId != null)
            .Select(artifact => new { artifact.Key, artifact.Hash })
            .ToListAsync(cancellationToken);
        return componentBans.Any(ban => artifacts.Any(artifact =>
            string.Equals(artifact.Key, ban.ComponentType, StringComparison.OrdinalIgnoreCase)
            && string.Equals(artifact.Hash, ApprovedBinaryService.NormalizeSha256(ban.ComponentHash),
                StringComparison.Ordinal)));
    }

    /// <summary>Applies exact provider release-mask semantics without trimming or case normalization.</summary>
    private static bool IsVersionAllowed(string version, string? allowedMask)
    {
        if (string.IsNullOrEmpty(allowedMask) || allowedMask == "*")
            return true;
        if (allowedMask.EndsWith(".*", StringComparison.Ordinal))
            return version.StartsWith(allowedMask[..^1], StringComparison.Ordinal);
        return string.Equals(version, allowedMask, StringComparison.Ordinal);
    }

    /// <summary>
    /// Rechecks the two equivalent commitment encodings at the provider decision boundary so mutable
    /// transport objects cannot diverge from the PS256 key identity after canonical parsing.
    /// </summary>
    private static bool IsProviderKeyCommitmentValid(RuntimeSeatRecoveryKeyCommitment commitment)
    {
        if (!string.Equals(commitment.Algorithm, "PS256", StringComparison.Ordinal)
            || !ApprovedBinaryService.IsCanonicalSha256(commitment.PublicKeySpkiSha256))
            return false;

        byte[] digest;
        try
        {
            digest = Convert.FromHexString(commitment.PublicKeySpkiSha256);
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            var thumbprint = Convert.ToBase64String(digest)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return string.Equals(thumbprint, commitment.KeyThumbprint, StringComparison.Ordinal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>Hashes provider-owned literal text as UTF-8 without normalization or case folding.</summary>
    private static string Sha256Text(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Parses one already shape-validated UTC claim timestamp without accepting offsets or repair.</summary>
    private static DateTime? ParseClaimTimestamp(string? value) => DateTime.TryParseExact(value, UtcFormat,
        CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
        out var parsed) ? parsed : null;

    /// <summary>Derives the provider seat revision used by short-lived claims from the locked seat state.</summary>
    private static long SeatRevision(LicenseSeat seat) => seat.LastCheckInAt.ToUniversalTime().Ticks;

    /// <summary>
    /// Resolves the only previous authority that is still backed by the exact active commercial binding,
    /// active enrollment, immutable current lineage head, and canonical v2 payload. Activation requests
    /// write-capable locks so the exact binding/enrollment CAS cannot race a stale authority observation.
    /// Every comparison is ordinal and literal; recovery must not select a historical row by timestamp.
    /// </summary>
    /// <param name="db">Context enlisted in the caller's provider transaction.</param>
    /// <param name="productId">Exact recovery product.</param>
    /// <param name="licenseId">Historical source licence scope selected by the request.</param>
    /// <param name="seatId">Historical source seat scope selected by the request.</param>
    /// <param name="targetReleaseVersion">Target release checked against current commercial policy.</param>
    /// <param name="targetArtifactSetDigestSha256">Exact authoritative target release digest.</param>
    /// <param name="cancellationToken">Cancels provider reads and lock acquisition.</param>
    /// <param name="lockForCutover">Uses the exclusive commercial barrier and write-capable binding lock.</param>
    /// <returns>A bounded eligible, denied, invalid, or unavailable source-authority result.</returns>
    private async Task<PreviousAuthorityResolution> ResolvePreviousActiveAuthorityAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        Guid seatId,
        string targetReleaseVersion,
        string targetArtifactSetDigestSha256,
        CancellationToken cancellationToken,
        bool lockForCutover = false)
    {
        var bindings = lockForCutover
            ? await db.DistributionInstallationBindings.FromSqlInterpolated($"""
                SELECT * FROM public."DistributionInstallationBindings"
                WHERE "ProductId" = {productId} AND "LicenseId" = {licenseId}
                  AND "LicenseSeatId" = {seatId} AND "State" = 'active'
                FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.DistributionInstallationBindings.FromSqlInterpolated($"""
                SELECT * FROM public."DistributionInstallationBindings"
                WHERE "ProductId" = {productId} AND "LicenseId" = {licenseId}
                  AND "LicenseSeatId" = {seatId} AND "State" = 'active'
                FOR SHARE
                """).ToListAsync(cancellationToken);
        if (bindings.Count != 1)
            return PreviousAuthorityResolution.Invalid("previous_binding_missing_or_ambiguous");
        var binding = bindings[0];

        // Enrollment identity is locked before the commercial barrier. Item 2 writers update this
        // row before taking the exclusive counterpart, which keeps both paths in one lock order.
        var enrollments = await db.RuntimeEnrollments.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollments"
            WHERE "BindingId" = {binding.Id} AND "ProductId" = {productId}
            FOR UPDATE
            """).ToListAsync(cancellationToken);
        if (enrollments.Count != 1 || !string.Equals(enrollments[0].State, "ACTIVE", StringComparison.Ordinal))
            return PreviousAuthorityResolution.Invalid("previous_enrollment_missing_or_inactive");
        var enrollment = enrollments[0];

        if (lockForCutover)
        {
            await db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", cancellationToken);
        }
        else
        {
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
        }

        var lineages = lockForCutover
            ? await db.RuntimeEnrollmentAuthorityLineages.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollmentAuthorityLineages"
                WHERE "Provider" = 'softlicence' AND "ProductId" = {productId}
                  AND "LicenseSeatId" = {seatId} AND "ProviderGrantRef" = {binding.GrantRef}
                FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.RuntimeEnrollmentAuthorityLineages.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollmentAuthorityLineages"
                WHERE "Provider" = 'softlicence' AND "ProductId" = {productId}
                  AND "LicenseSeatId" = {seatId} AND "ProviderGrantRef" = {binding.GrantRef}
                FOR SHARE
                """).ToListAsync(cancellationToken);
        if (lineages.Count != 1
            || lineages[0].ProviderGrantRefScalarCount != binding.GrantRef.EnumerateRunes().Count())
            return PreviousAuthorityResolution.Invalid("previous_lineage_missing_or_ambiguous");
        var lineage = lineages[0];

        var generations = await db.RuntimeEnrollmentAuthorityGenerations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollmentAuthorityGenerations"
            WHERE "AuthorityGenerationId" = {lineage.HeadGenerationId}
              AND "AuthorityLineageId" = {lineage.AuthorityLineageId}
              AND "Sequence" = {lineage.HeadSequence}
            FOR SHARE
            """).AsNoTracking().ToListAsync(cancellationToken);
        if (generations.Count != 1)
            return PreviousAuthorityResolution.Invalid("previous_generation_missing_or_ambiguous");
        var generation = generations[0];

        RuntimeEnrollmentAuthorityGenerationPayloadV2? payload;
        try
        {
            payload = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                generation.CanonicalPayloadUtf8, AuthorityJson);
        }
        catch (JsonException exception)
        {
            LogInvalidRecoveryGenerationPayload(exception, generation);
            return PreviousAuthorityResolution.Unavailable("previous_generation_payload_invalid");
        }
        catch (NotSupportedException exception)
        {
            LogInvalidRecoveryGenerationPayload(exception, generation);
            return PreviousAuthorityResolution.Unavailable("previous_generation_payload_invalid");
        }
        if (payload is null || payload.Release is null || payload.Binding is null
            || payload.Enrollment is null || payload.Key is null || payload.Installation is null
            || payload.Transition is null)
            return PreviousAuthorityResolution.Invalid("previous_generation_payload_invalid");
        byte[] canonicalPayload;
        try
        {
            canonicalPayload = JsonSerializer.SerializeToUtf8Bytes(payload, AuthorityJson);
        }
        catch (NotSupportedException exception)
        {
            LogInvalidRecoveryGenerationPayload(exception, generation);
            return PreviousAuthorityResolution.Unavailable("previous_generation_payload_invalid");
        }
        if (!generation.CanonicalPayloadUtf8.AsSpan().SequenceEqual(canonicalPayload)
            || !MatchesPreviousActiveAuthorityPayload(payload, lineage, generation, binding, enrollment))
            return PreviousAuthorityResolution.Invalid("previous_generation_payload_divergent");
        if (!VerifyPersistedGenerationCryptography(generation, canonicalPayload))
            return PreviousAuthorityResolution.Unavailable("previous_generation_signature_invalid");

        try
        {
            _ = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", true, null, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status503ServiceUnavailable)
        {
            return PreviousAuthorityResolution.Unavailable(exception.DiagnosticCode ?? "source_identity_unavailable");
        }
        catch (RuntimeEnrollmentException exception)
        {
            return PreviousAuthorityResolution.Invalid(exception.DiagnosticCode ?? exception.ErrorCode);
        }

        if (!await HasAuthoritativeReleaseAsync(db, productId, targetReleaseVersion,
                targetArtifactSetDigestSha256, cancellationToken))
            return PreviousAuthorityResolution.Denied("target_release_unapproved");

        var now = await ReadDatabaseClockAsync(db, cancellationToken);
        var commercial = await AssessSourceCommercialAuthorityAsync(
            db, enrollment, licenseId, seatId, targetReleaseVersion, now,
            lockForCutover, expectedSourceAssignmentId: null, cancellationToken);
        if (commercial.Outcome != PreviousAuthorityOutcome.Eligible)
            return new(commercial.Outcome, null, commercial.DiagnosticCode);

        return PreviousAuthorityResolution.Eligible(new(
            lineage.AuthorityLineageId, lineage.HeadGenerationId, binding.Id, enrollment.Id,
            commercial.SourceAssignmentId!.Value));
    }

    /// <summary>
    /// Checks all provider-owned scalar links represented by an ACTIVE previous authority. The payload is
    /// accepted only when it is the exact canonical projection of the durable binding and enrollment head.
    /// </summary>
    /// <param name="payload">The canonical signed generation payload to compare.</param>
    /// <param name="lineage">The locked authority lineage that owns the generation.</param>
    /// <param name="generation">The persisted generation whose identifiers and epoch must match.</param>
    /// <param name="binding">The locked installation binding represented by the generation.</param>
    /// <param name="enrollment">The locked Runtime enrollment represented by the generation.</param>
    /// <returns><see langword="true"/> only when every signed scalar matches the locked durable authority graph.</returns>
    private static bool MatchesPreviousActiveAuthorityPayload(
        RuntimeEnrollmentAuthorityGenerationPayloadV2 payload,
        RuntimeEnrollmentAuthorityLineage lineage,
        RuntimeEnrollmentAuthorityGeneration generation,
        DistributionInstallationBinding binding,
        RuntimeEnrollment enrollment)
    {
        var expectedDigest = Convert.ToHexStringLower(SHA256.HashData(generation.CanonicalPayloadUtf8));
        return string.Equals(payload.Schema, "runtime-enrollment-authority-generation-v2", StringComparison.Ordinal)
            && payload.ContractVersion == 2
            && string.Equals(payload.AuthorityLineageId, lineage.AuthorityLineageId.ToString("D"), StringComparison.Ordinal)
            && string.Equals(payload.AuthorityGenerationId, generation.AuthorityGenerationId.ToString("D"), StringComparison.Ordinal)
            && string.Equals(payload.PreviousGenerationId, generation.PreviousGenerationId?.ToString("D"), StringComparison.Ordinal)
            && payload.Sequence == generation.Sequence
            && string.Equals(payload.Provider, lineage.Provider, StringComparison.Ordinal)
            && string.Equals(payload.ProductId, lineage.ProductId.ToString("D"), StringComparison.Ordinal)
            && string.Equals(payload.ProviderGrantRef, lineage.ProviderGrantRef, StringComparison.Ordinal)
            && string.Equals(payload.Binding.BindingId, binding.Id.ToString("D"), StringComparison.Ordinal)
            && ApprovedBinaryService.IsCanonicalSha256(payload.Binding.HardwareIdDigest)
            && string.Equals(payload.Enrollment.EnrollmentId, enrollment.Id.ToString("D"), StringComparison.Ordinal)
            && string.Equals(payload.Enrollment.State, "active", StringComparison.Ordinal)
            && string.Equals(payload.Key.AuthorityKeyId, generation.SignatureKeyId, StringComparison.Ordinal)
            && payload.Key.SecurityEpoch == enrollment.SecurityEpoch
            && string.Equals(payload.Installation.InstallationId, binding.InstallationId, StringComparison.Ordinal)
            && string.Equals(payload.Installation.SeatId, lineage.LicenseSeatId.ToString("D"), StringComparison.Ordinal)
            && string.Equals(payload.Release.Version, enrollment.ReleaseVersion, StringComparison.Ordinal)
            && string.Equals(enrollment.InstallationId, binding.InstallationId, StringComparison.Ordinal)
            && enrollment.BindingId == binding.Id
            && enrollment.ProductId == binding.ProductId
            && string.Equals(payload.Transition.RequestId, generation.RequestId.ToString("D"), StringComparison.Ordinal)
            && string.Equals(payload.Transition.OccurredAtUtc, Format(generation.OccurredAtUtc), StringComparison.Ordinal)
            && string.Equals(generation.SignatureAlgorithm, "PS256", StringComparison.Ordinal)
            && string.Equals(generation.AuthorityDigest, expectedDigest, StringComparison.Ordinal);
    }

    /// <summary>Identifies the lineage-qualified immutable head and current assignment that proved the source.</summary>
    /// <param name="HeadLineageId">The exact immutable source authority lineage.</param>
    /// <param name="HeadGenerationId">The exact immutable current source generation.</param>
    /// <param name="BindingId">The row-locked active source binding.</param>
    /// <param name="EnrollmentId">The row-locked active source enrollment.</param>
    /// <param name="SourceAssignmentId">The unique current assignment derived under the commercial barrier.</param>
    internal sealed record PreviousActiveAuthority(
        Guid HeadLineageId,
        Guid HeadGenerationId,
        Guid BindingId,
        Guid EnrollmentId,
        Guid SourceAssignmentId);

    /// <summary>Classifies source authority validation without converting database faults into denials.</summary>
    private enum PreviousAuthorityOutcome
    {
        /// <summary>A, signed proof and the current assignment policy all passed.</summary>
        Eligible,
        /// <summary>A known current commercial policy refused the source.</summary>
        Denied,
        /// <summary>Historical identity or signed proof no longer forms one exact authority.</summary>
        Invalid,
        /// <summary>Ambiguous, corrupt or unavailable provider state prevented a decision.</summary>
        Unavailable
    }

    /// <summary>Returns the exact previous authority together with a bounded failure classification.</summary>
    /// <param name="Outcome">Identity, proof and current commercial classification.</param>
    /// <param name="Authority">Exact previous authority only when every layer is eligible.</param>
    /// <param name="DiagnosticCode">Bounded internal reason without raw commercial identifiers.</param>
    private sealed record PreviousAuthorityResolution(
        PreviousAuthorityOutcome Outcome,
        PreviousActiveAuthority? Authority,
        string DiagnosticCode)
    {
        /// <summary>Creates an eligible result carrying the exact previous authority.</summary>
        internal static PreviousAuthorityResolution Eligible(PreviousActiveAuthority authority) =>
            new(PreviousAuthorityOutcome.Eligible, authority, "eligible");
        /// <summary>Creates a known current commercial denial.</summary>
        internal static PreviousAuthorityResolution Denied(string diagnosticCode) =>
            new(PreviousAuthorityOutcome.Denied, null, diagnosticCode);
        /// <summary>Creates a historical identity or proof rejection.</summary>
        internal static PreviousAuthorityResolution Invalid(string diagnosticCode) =>
            new(PreviousAuthorityOutcome.Invalid, null, diagnosticCode);
        /// <summary>Creates an ambiguous, corrupt, or unavailable provider-state result.</summary>
        internal static PreviousAuthorityResolution Unavailable(string diagnosticCode) =>
            new(PreviousAuthorityOutcome.Unavailable, null, diagnosticCode);
    }

    /// <summary>Holds one current commercial verdict and the server-derived assignment when eligible.</summary>
    /// <param name="Outcome">Eligible, denied, or unavailable current assignment policy.</param>
    /// <param name="DiagnosticCode">Bounded server-only reason without hardware or customer data.</param>
    /// <param name="SourceAssignmentId">Exact locked ACTIVE assignment, present only for an eligible verdict.</param>
    private sealed record CommercialAuthorityAssessment(
        PreviousAuthorityOutcome Outcome,
        string DiagnosticCode,
        Guid? SourceAssignmentId = null);

    /// <summary>
    /// Assesses the only current commercial grant for the already-proved source enrollment.
    /// Historical enrollment and binding licence, seat and hardware copies never grant authority.
    /// </summary>
    /// <param name="db">Context holding the caller's shared or exclusive commercial barrier.</param>
    /// <param name="sourceEnrollment">Cryptographically proved and row-locked source enrollment.</param>
    /// <param name="expectedLicenseId">Historical request scope that the current assignment must retain.</param>
    /// <param name="expectedSeatId">Historical request scope that the current assignment must retain.</param>
    /// <param name="targetReleaseVersion">Target release checked against licence and product policy.</param>
    /// <param name="now">Database time read after the commercial barrier.</param>
    /// <param name="lockForCutover">Takes an update lock when the caller is preparing the atomic cutover.</param>
    /// <param name="expectedSourceAssignmentId">Previously derived assignment that must remain uniquely ACTIVE.</param>
    /// <param name="cancellationToken">Cancels the assessment and lock acquisition.</param>
    /// <returns>A business denial or eligible result carrying the exact locked source assignment.</returns>
    private static async Task<CommercialAuthorityAssessment> AssessSourceCommercialAuthorityAsync(
        LicenseDbContext db,
        RuntimeEnrollment sourceEnrollment,
        Guid expectedLicenseId,
        Guid expectedSeatId,
        string targetReleaseVersion,
        DateTimeOffset now,
        bool lockForCutover,
        Guid? expectedSourceAssignmentId,
        CancellationToken cancellationToken)
    {
        var assignments = lockForCutover
            ? await db.EnrollmentLicenseAssignments.FromSqlInterpolated($"""
                SELECT * FROM public."EnrollmentLicenseAssignments"
                WHERE "EnrollmentId" = {sourceEnrollment.Id} AND "State" = 'ACTIVE'
                ORDER BY "Id" FOR UPDATE
                """).AsNoTracking().ToListAsync(cancellationToken)
            : await db.EnrollmentLicenseAssignments.FromSqlInterpolated($"""
                SELECT * FROM public."EnrollmentLicenseAssignments"
                WHERE "EnrollmentId" = {sourceEnrollment.Id} AND "State" = 'ACTIVE'
                ORDER BY "Id" FOR SHARE
                """).AsNoTracking().ToListAsync(cancellationToken);
        if (assignments.Count > 1)
            return new(PreviousAuthorityOutcome.Unavailable, "assignment_duplicate_active");
        if (assignments.Count == 0)
        {
            var quarantined = await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                .AnyAsync(row => row.EnrollmentId == sourceEnrollment.Id, cancellationToken);
            return new(PreviousAuthorityOutcome.Denied,
                quarantined ? "assignment_quarantined" : "assignment_missing");
        }

        var assignment = assignments[0];
        if (expectedSourceAssignmentId is { } expectedAssignmentId && assignment.Id != expectedAssignmentId
            || assignment.LicenseId != expectedLicenseId || assignment.LicenseSeatId != expectedSeatId)
            return new(PreviousAuthorityOutcome.Denied, "assignment_scope_mismatch");

        var license = await db.Licenses.AsNoTracking()
            .Include(row => row.Product)
            .SingleOrDefaultAsync(row => row.Id == assignment.LicenseId, cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == assignment.LicenseSeatId, cancellationToken);
        if (license is null || seat is null)
            return new(PreviousAuthorityOutcome.Unavailable, "assignment_relation_missing");

        if (license.ProductId != sourceEnrollment.ProductId || !license.IsActive
            || license.RevokedAt is not null
            || license.ExpirationDate is { } expiry && expiry <= now.UtcDateTime
            || license.MaxSeats < 1 || !seat.IsActive || seat.LicenseId != license.Id
            || string.IsNullOrWhiteSpace(seat.HardwareId))
            return new(PreviousAuthorityOutcome.Denied, "commercial_authority_ineligible");

        var activeSeatCount = await db.LicenseSeats.AsNoTracking()
            .CountAsync(row => row.LicenseId == license.Id && row.IsActive, cancellationToken);
        if (activeSeatCount > license.MaxSeats)
            return new(PreviousAuthorityOutcome.Denied, "seat_capacity_exceeded");
        if (!RuntimeEnrollmentService.IsVersionAllowed(targetReleaseVersion, license.AllowedVersions)
            || RuntimeEnrollmentService.IsVersionBelow(targetReleaseVersion, license.Product?.MinimumAllowedVersion))
            return new(PreviousAuthorityOutcome.Denied, "version_ineligible");
        if (await HasActiveSecurityBanAsync(
                db, sourceEnrollment.ProductId, seat.HardwareId,
                targetReleaseVersion, now, cancellationToken))
            return new(PreviousAuthorityOutcome.Denied, "security_policy_banned");

        return new(PreviousAuthorityOutcome.Eligible, "eligible", assignment.Id);
    }

    /// <summary>
    /// Reassesses only current commercial authority at a database instant sampled after every later
    /// mutable-row wait. The caller uses ReadCommitted so these reads also receive a statement snapshot
    /// created after the barrier wait. Historical identity and signed proof remain the previously resolved authority.
    /// </summary>
    /// <param name="db">Context holding the same commercial barrier and provider transaction.</param>
    /// <param name="resolution">Previously resolved A/P authority and initial commercial verdict.</param>
    /// <param name="expectedLicenseId">Exact historical licence scope retained by the assignment.</param>
    /// <param name="expectedSeatId">Exact historical seat scope retained by the assignment.</param>
    /// <param name="targetReleaseVersion">Target release checked against current commercial policy.</param>
    /// <param name="decisionNow">Fresh PostgreSQL wall clock read after all decisive lock waits.</param>
    /// <param name="cancellationToken">Cancels the final read-only assessment.</param>
    /// <returns>The preserved A/P authority with the final current commercial outcome.</returns>
    private static async Task<PreviousAuthorityResolution> ReassessResolvedCommercialAuthorityAsync(
        LicenseDbContext db,
        PreviousAuthorityResolution resolution,
        Guid expectedLicenseId,
        Guid expectedSeatId,
        string targetReleaseVersion,
        DateTime decisionNow,
        CancellationToken cancellationToken)
    {
        if (resolution.Outcome != PreviousAuthorityOutcome.Eligible || resolution.Authority is null)
            return resolution;

        var enrollments = await db.RuntimeEnrollments.AsNoTracking()
            .Where(row => row.Id == resolution.Authority.EnrollmentId)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (enrollments.Count != 1)
            return PreviousAuthorityResolution.Unavailable("source_enrollment_missing_or_ambiguous");

        var commercial = await AssessSourceCommercialAuthorityAsync(
            db, enrollments[0], expectedLicenseId, expectedSeatId, targetReleaseVersion,
            decisionNow, lockForCutover: false, resolution.Authority.SourceAssignmentId, cancellationToken);
        return commercial.Outcome == PreviousAuthorityOutcome.Eligible
            ? resolution
            : new(commercial.Outcome, null, commercial.DiagnosticCode);
    }

    /// <summary>Resolves exactly one pre-existing ACTIVE provider owner without inferring commercial authority.</summary>
    private static async Task<RuntimeRecoveryCommercialOwnership?> ResolveOwnerAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        CancellationToken cancellationToken)
    {
        var owners = await db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {productId} AND "LicenseId" = {licenseId} AND "State" = 'ACTIVE'
            FOR UPDATE
            """).ToListAsync(cancellationToken);
        return owners.Count == 1 ? owners[0] : null;
    }

    /// <summary>Creates and signs the exact sequence-zero RECOVERY_AUTHORIZED generation without predecessor proof.</summary>
    /// <param name="request">The validated recovery authorization request that supplies the immutable release scope.</param>
    /// <param name="requestId">The canonical request identifier bound into the generation payload.</param>
    /// <param name="seatId">The server-derived eligible seat identifier.</param>
    /// <param name="lineageId">The newly owned authority-lineage identifier.</param>
    /// <param name="generationId">The newly owned generation identifier.</param>
    /// <param name="bindingId">The locked installation-binding identifier.</param>
    /// <param name="enrollmentId">The locked Runtime-enrollment identifier.</param>
    /// <param name="issuedAtUtc">The database-clock issuance instant.</param>
    /// <param name="expiresAtUtc">The bounded generation expiry instant.</param>
    /// <returns>The canonical payload, digest, statement, signature, and exact configured operational key identity.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the configured authority signer cannot produce the required canonical signature.</exception>
    private RuntimeEnrollmentAuthorityCryptography.SignedGenerationResult SignGeneration(
        RuntimeSeatRecoveryAuthorizationRequest request,
        Guid requestId,
        Guid seatId,
        Guid lineageId,
        Guid generationId,
        Guid bindingId,
        Guid enrollmentId,
        DateTime issuedAtUtc,
        DateTime expiresAtUtc)
    {
        var payload = new RuntimeEnrollmentAuthorityGenerationPayloadV2
        {
            Schema = "runtime-enrollment-authority-generation-v2", ContractVersion = 2,
            AuthorityLineageId = lineageId.ToString("D"), AuthorityGenerationId = generationId.ToString("D"),
            PreviousGenerationId = null, Sequence = 0, Provider = "softlicence",
            ProductId = request.ProductId, ProviderGrantRef = request.ProviderGrantRef,
            Release = new() { Version = request.Release.Version, ArtifactSetDigest = request.Release.ArtifactSetDigestSha256 },
            Binding = new() { BindingId = bindingId.ToString("D"), HardwareIdDigest = request.Installation.HardwareIdDigestSha256 },
            Enrollment = new() { EnrollmentId = enrollmentId.ToString("D"), State = "pending",
                IssuedAtUtc = Format(issuedAtUtc), ExpiresAtUtc = Format(expiresAtUtc) },
            Key = new() { AuthorityKeyId = options.AuthorityGenerationSigning?.ActiveSigningKeyId ?? string.Empty, SecurityEpoch = 1 },
            Installation = new() { InstallationId = request.Installation.InstallationId, SeatId = seatId.ToString("D") },
            Transition = new() { Kind = "recovery", ReasonCode = "RECOVERY_AUTHORIZED",
                RequestId = requestId.ToString("D"), OccurredAtUtc = Format(issuedAtUtc) }
        };
        var serialized = JsonSerializer.SerializeToUtf8Bytes(payload, AuthorityJson);
        byte[] pin;
        try { pin = Convert.FromBase64String(options.AuthorityGenerationV2.RegistryAuthoritySpkiBase64); }
        catch (FormatException) { throw new InvalidOperationException("Runtime recovery signing registry is unavailable."); }
        try
        {
            var cryptography = new RuntimeEnrollmentAuthorityCryptography(clock, pin);
            var signed = cryptography.SignGeneration(options.AuthorityGenerationSigning, serialized);
            return signed.Error == RuntimeEnrollmentAuthorityCryptography.Failure.None
                ? signed.Value!
                : throw new InvalidOperationException("Runtime recovery signing failed closed.");
        }
        finally { CryptographicOperations.ZeroMemory(pin); }
    }

    /// <summary>Freezes one semantic refusal after canonical request identity has been established.</summary>
    private static async Task<RuntimeSeatRecoveryHttpResult> FreezeRefusalAsync(
        LicenseDbContext db,
        string clientId,
        RuntimeSeatRecoveryContractCodec.AuthorizationParseResult parsed,
        string errorCode,
        int statusCode,
        DateTime completedAtUtc,
        CancellationToken cancellationToken)
    {
        var request = parsed.Request!;
        var result = SemanticError(request, parsed.RequestDigestSha256!, errorCode, statusCode, completedAtUtc);
        db.RuntimeSeatRecoveryAuthorizations.Add(new RuntimeSeatRecoveryAuthorization
        {
            AuthenticatedClientId = clientId, RequestId = Guid.Parse(request.RequestId),
            RequestDigestSha256 = parsed.RequestDigestSha256!, RecoveryOperationRef = Guid.Parse(request.RecoveryOperationRef),
            RecoveryDigestSha256 = request.RecoveryDigestSha256, CanonicalRequestUtf8 = parsed.CanonicalUtf8,
            Decision = "REFUSED", HttpStatusCode = statusCode, ContentType = ContentType,
            ErrorCode = errorCode, ExactResponseUtf8 = result.ExactBodyUtf8, CompletedAtUtc = completedAtUtc
        });
        await db.SaveChangesAsync(cancellationToken);
        return result;
    }

    /// <summary>
    /// Requires an existing provider grant row to match every exact resource, ownership version, and command
    /// dimension. Historical null version bindings fail closed. Opaque client and digest strings use ordinal
    /// equality and are never normalized or repaired.
    /// </summary>
    /// <param name="grant">The immutable provider grant row being revalidated.</param>
    /// <param name="clientId">The exact authenticated client namespace.</param>
    /// <param name="requestId">The exact request UUID that first established the grant.</param>
    /// <param name="productId">The exact product scope.</param>
    /// <param name="licenseId">The exact license scope.</param>
    /// <param name="commercialOwnershipId">The currently resolved ACTIVE ownership-version UUID.</param>
    /// <param name="ownerSubjectId">The provider-private commercial-subject UUID.</param>
    /// <param name="recoveryOperationRef">The immutable recovery-operation UUID.</param>
    /// <param name="providerGrantRefDigestSha256">The lowercase digest of the exact grant reference bytes.</param>
    /// <param name="recoveryDigestSha256">The lowercase canonical recovery digest.</param>
    /// <returns>True only when every typed and ordinal binding dimension matches exactly.</returns>
    private static bool GrantBindingMatches(
        RuntimeRecoveryGrantOwnership grant,
        string clientId,
        Guid requestId,
        Guid productId,
        Guid licenseId,
        Guid commercialOwnershipId,
        Guid ownerSubjectId,
        Guid recoveryOperationRef,
        string providerGrantRefDigestSha256,
        string recoveryDigestSha256) =>
        string.Equals(grant.AuthenticatedClientId, clientId, StringComparison.Ordinal)
        && grant.RequestId == requestId
        && grant.ProductId == productId
        && grant.LicenseId == licenseId
        && grant.CommercialOwnershipId == commercialOwnershipId
        && grant.OwnerSubjectId == ownerSubjectId
        && grant.RecoveryOperationRef == recoveryOperationRef
        && string.Equals(grant.ProviderGrantRefDigestSha256, providerGrantRefDigestSha256,
            StringComparison.Ordinal)
        && string.Equals(grant.RecoveryDigestSha256, recoveryDigestSha256, StringComparison.Ordinal);

    /// <summary>
    /// Identifies only EF-wrapped PostgreSQL uniqueness races owned by recovery grants or operation
    /// reservations. Unknown 23505 constraints remain visible and are never converted into retries.
    /// </summary>
    private static bool IsExpectedRecoveryUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException
        {
            SqlState: PostgresErrorCodes.UniqueViolation,
            ConstraintName: { } constraintName
        }
        && ExpectedRecoveryUniqueConstraints.Contains(constraintName);

    /// <summary>
    /// Accepts only lock timeout, statement timeout, serialization failure, and deadlock SQLSTATEs
    /// as transient recovery attempts. Unique violations remain governed by their named F4 allowlist.
    /// </summary>
    private static bool IsRetryableTransientSqlState(string sqlState) => sqlState is
        PostgresErrorCodes.LockNotAvailable
        or PostgresErrorCodes.QueryCanceled
        or PostgresErrorCodes.SerializationFailure
        or PostgresErrorCodes.DeadlockDetected;

    /// <summary>
    /// Detects a caller-canceled 57014 anywhere in the exception chain. This predicate is evaluated
    /// before transient retry classification so EF wrapping cannot demote explicit cancellation to 503.
    /// </summary>
    private static bool IsCallerCancellationDatabaseFailure(
        Exception exception,
        CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested
        && ContainsPostgresSqlState(exception, PostgresErrorCodes.QueryCanceled);

    /// <summary>
    /// Extracts a direct or EF-wrapped PostgreSQL failure and applies the closed transient allowlist.
    /// A caller-canceled 57014 is explicitly excluded even if this method is evaluated independently.
    /// </summary>
    private static bool IsRetryableTransientDatabaseFailure(
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (IsCallerCancellationDatabaseFailure(exception, cancellationToken))
            return false;

        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is PostgresException postgres && IsRetryableTransientSqlState(postgres.SqlState))
                return true;
        }

        return false;
    }

    /// <summary>Finds one exact PostgreSQL SQLSTATE in a direct or arbitrarily EF-wrapped exception.</summary>
    private static bool ContainsPostgresSqlState(Exception exception, string sqlState)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is PostgresException postgres
                && string.Equals(postgres.SqlState, sqlState, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Reads PostgreSQL wall time inside the current transaction. clock_timestamp is intentionally
    /// used instead of transaction-start time so lock waits cannot preserve a stale authorization instant.
    /// </summary>
    private static async Task<DateTime> ReadDatabaseClockAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken)
    {
        var observed = await db.Database.SqlQueryRaw<DateTime>(
            "SELECT pg_catalog.clock_timestamp() AS \"Value\"")
            .SingleAsync(cancellationToken);
        return observed.ToUniversalTime();
    }

    /// <summary>Acquires global Runtime authority before every command, license, seat, and lineage lock.</summary>
    private async Task SetTransactionGuardsAsync(LicenseDbContext db, CancellationToken cancellationToken)
    {
        var lockTimeout = options.LockTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture) + "ms";
        var statementTimeout = options.StatementTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture) + "ms";
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT set_config('lock_timeout', {lockTimeout}, true),
                   set_config('statement_timeout', {statementTimeout}, true);
            """, cancellationToken);
        await db.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);", cancellationToken);
    }

    /// <summary>Serializes concurrent replicas by the exact authenticated-client plus request identity.</summary>
    private static async Task AcquireCommandLockAsync(
        LicenseDbContext db, string clientId, string requestId, CancellationToken cancellationToken)
    {
        var identity = "runtime-seat-recovery:command:" + clientId.Length.ToString(CultureInfo.InvariantCulture)
            + ":" + clientId + ":" + requestId;
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
                {identity}, 763));
            """, cancellationToken);
    }

    /// <summary>Reads one terminal under the command lock so exact replay never repeats provider work.</summary>
    private static Task<RuntimeSeatRecoveryAuthorization?> ReadTerminalForUpdateAsync(
        LicenseDbContext db, string clientId, Guid requestId, CancellationToken cancellationToken) =>
        db.RuntimeSeatRecoveryAuthorizations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryAuthorizations"
            WHERE "AuthenticatedClientId" = {clientId} AND "RequestId" = {requestId}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);

    /// <summary>
    /// Revalidates A, immutable proof and current assignment authority before replaying a successful
    /// recovery authorization. The newly generated enrollment identifier is never used as the source grant.
    /// </summary>
    /// <param name="db">The context enlisted in the caller's replay transaction.</param>
    /// <param name="ledger">The locked successful authorization terminal.</param>
    /// <param name="request">The exact canonical request whose digest matched the terminal.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through source and commercial locks.</param>
    /// <returns>The current eligible, denied, invalid, or unavailable source-authority classification.</returns>
    private async Task<PreviousAuthorityResolution> RevalidateAuthorizedReplayAsync(
        LicenseDbContext db,
        RuntimeSeatRecoveryAuthorization ledger,
        RuntimeSeatRecoveryAuthorizationRequest request,
        CancellationToken cancellationToken)
    {
        var reservation = await db.RuntimeSeatRecoveryReservations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryReservations"
            WHERE "ReservationRef" = {ledger.ReservationRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var authority = reservation is null ? null : await db.RuntimeSeatRecoveryAuthorities.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryAuthorities"
            WHERE "ReservationRef" = {reservation.ReservationRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        if (reservation is null || authority is null || reservation.State != "RESERVED"
            || authority.State != "PREPARED" || !authority.IsCurrentHead
            || reservation.RequestId != ledger.RequestId
            || reservation.RecoveryOperationRef != ledger.RecoveryOperationRef
            || reservation.ProductId != Guid.Parse(request.ProductId)
            || reservation.LicenseId != Guid.Parse(request.LicenseId)
            || authority.ReservationRef != reservation.ReservationRef
            || authority.LicenseSeatId != reservation.LicenseSeatId)
            return PreviousAuthorityResolution.Invalid("authorization_replay_scope_invalid");

        if (!await ValidateRecoveryGenerationAsync(db, authority, cancellationToken))
            return PreviousAuthorityResolution.Unavailable("authorization_generation_invalid");

        var resolution = await ResolvePreviousActiveAuthorityAsync(
            db, reservation.ProductId, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, authority.ArtifactSetDigestSha256, cancellationToken);
        if (resolution.Authority is not { } previous
            || previous.HeadLineageId != authority.PreviousAuthorityLineageId
            || previous.HeadGenerationId != authority.PreviousAuthorityGenerationId)
            return resolution.Outcome == PreviousAuthorityOutcome.Eligible
                ? PreviousAuthorityResolution.Invalid("authorization_replay_previous_authority_changed")
                : resolution;
        return resolution;
    }

    /// <summary>
    /// Loads and verifies the recovery authority's immutable generic generation before replay or readback.
    /// Missing, malformed, divergent, or signature-invalid provider evidence is classified as unavailable.
    /// </summary>
    /// <param name="db">The context enlisted in the caller's provider transaction.</param>
    /// <param name="authority">The recovery authority naming the exact generic generation.</param>
    /// <param name="cancellationToken">Cancels the bounded generation lookup.</param>
    /// <returns>True only when the exact persisted generic generation and PS256 signature remain valid.</returns>
    private async Task<bool> ValidateRecoveryGenerationAsync(
        LicenseDbContext db,
        RuntimeSeatRecoveryAuthority authority,
        CancellationToken cancellationToken)
    {
        var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AuthorityLineageId == authority.AuthorityLineageId
                && item.AuthorityGenerationId == authority.AuthorityGenerationId, cancellationToken);
        return generation is not null
            && TryReadVerifiedSignedSecurityEpoch(generation, out _);
    }

    /// <summary>Serializes preparation and confirmation replicas by exact client-scoped functional identity.</summary>
    private static async Task AcquireKeyProofLockAsync(
        LicenseDbContext db, string clientId, string identity, CancellationToken cancellationToken)
    {
        var value = "runtime-seat-recovery:key-proof:" + clientId.Length.ToString(CultureInfo.InvariantCulture)
            + ":" + clientId + ":" + identity;
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({value}, 773));
            """, cancellationToken);
    }

    private static Task<RuntimeSeatRecoveryKeyPreparation?> ReadPreparationForUpdateAsync(
        LicenseDbContext db, string clientId, Guid requestId, CancellationToken cancellationToken) =>
        db.RuntimeSeatRecoveryKeyPreparations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryKeyPreparations"
            WHERE "AuthenticatedClientId" = {clientId} AND "RequestId" = {requestId}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);

    private static Task<RuntimeSeatRecoveryKeyPreparation?> ReadPreparationByReferenceForUpdateAsync(
        LicenseDbContext db, string clientId, Guid prepareRef, CancellationToken cancellationToken) =>
        db.RuntimeSeatRecoveryKeyPreparations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryKeyPreparations"
            WHERE "AuthenticatedClientId" = {clientId} AND "PrepareRef" = {prepareRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);

    private static Task<RuntimeSeatRecoveryKeyConfirmation?> ReadConfirmationForUpdateAsync(
        LicenseDbContext db, string clientId, Guid prepareRef, CancellationToken cancellationToken) =>
        db.RuntimeSeatRecoveryKeyConfirmations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryKeyConfirmations"
            WHERE "AuthenticatedClientId" = {clientId} AND "PrepareRef" = {prepareRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);

    /// <summary>Serializes activation replicas by the existing client-scoped request identity.</summary>
    private static async Task AcquireActivationLockAsync(
        LicenseDbContext db, string clientId, string requestId, CancellationToken cancellationToken)
    {
        var value = "runtime-seat-recovery:activation:" + clientId.Length.ToString(CultureInfo.InvariantCulture)
            + ":" + clientId + ":" + requestId;
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({value}, 767));
            """, cancellationToken);
    }

    /// <summary>Reads the immutable activation terminal before any proof or lifecycle reevaluation.</summary>
    private static Task<RuntimeSeatRecoveryActivationReceipt?> ReadActivationReceiptForUpdateAsync(
        LicenseDbContext db, string clientId, Guid requestId, CancellationToken cancellationToken) =>
        db.RuntimeSeatRecoveryActivationReceipts.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryActivationReceipts"
            WHERE "AuthenticatedClientId" = {clientId} AND "RequestId" = {requestId}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);

    /// <summary>
    /// Locks and revalidates the exact PROVED receipt, W10.2 terminal, provider ledger, ownership UUID,
    /// signed heads including the positive generation epoch, and the three mutable recovery states without
    /// rerunning proof-of-possession. The caller owns the ambient transaction; this helper only takes locks and
    /// throws before persistence when current commercial authority is denied or unavailable.
    /// </summary>
    /// <param name="db">The context enlisted in the caller's activation transaction.</param>
    /// <param name="clientId">The exact authenticated client namespace.</param>
    /// <param name="request">The already parsed canonical activation request.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through every provider lock.</param>
    /// <returns>The complete locked scope, or null when historical proof identity is invalid.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// Thrown with 422 for a known current commercial denial or 503 for unavailable provider state; the caller
    /// rolls back and maps only the stable public error.
    /// </exception>
    private async Task<ActivationScope?> LockActivationScopeAsync(
        LicenseDbContext db,
        string clientId,
        RuntimeSeatRecoveryActivationRequest request,
        CancellationToken cancellationToken)
    {
        var productId = Guid.Parse(request.ProductId);
        var requestId = Guid.Parse(request.RequestId);
        var recoveryRef = Guid.Parse(request.RecoveryOperationRef);
        var reservationRef = Guid.Parse(request.ReservationRef);
        var prepareRef = Guid.Parse(request.PrepareRef);

        var proof = await db.RuntimeSeatRecoveryProofReceipts.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryProofReceipts"
            WHERE "AuthenticatedClientId" = {clientId} AND "PrepareRef" = {prepareRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var preparation = await ReadPreparationByReferenceForUpdateAsync(db, clientId, prepareRef, cancellationToken);
        var confirmation = await ReadConfirmationForUpdateAsync(db, clientId, prepareRef, cancellationToken);
        var ledger = await db.RuntimeSeatRecoveryAuthorizations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryAuthorizations"
            WHERE "AuthenticatedClientId" = {clientId} AND "RequestId" = {requestId}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var reservation = await db.RuntimeSeatRecoveryReservations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryReservations"
            WHERE "ReservationRef" = {reservationRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var authority = await db.RuntimeSeatRecoveryAuthorities.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryAuthorities"
            WHERE "ReservationRef" = {reservationRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var generation = authority is null ? null : await db.RuntimeEnrollmentAuthorityGenerations
            .AsNoTracking().SingleOrDefaultAsync(item =>
                item.AuthorityLineageId == authority.AuthorityLineageId
                && item.AuthorityGenerationId == authority.AuthorityGenerationId, cancellationToken);
        var securityEpoch = 0;
        if (generation is not null
            && !TryReadVerifiedSignedSecurityEpoch(generation, out securityEpoch))
            throw new RuntimeEnrollmentException(
                "provider_unavailable", StatusCodes.Status503ServiceUnavailable,
                "authorization_generation_invalid");
        var hasSignedSecurityEpoch = generation is not null;

        if (proof is null || preparation is null || confirmation is null || ledger is null
            || reservation is null || authority is null || !hasSignedSecurityEpoch || proof.State != "PROVED"
            || proof.ProductId != productId || proof.RequestId != requestId
            || proof.RequestDigestSha256 != request.RequestDigestSha256
            || proof.RecoveryOperationRef != recoveryRef || proof.ReservationRef != reservationRef
            || proof.PrepareRef != prepareRef
            || proof.ConfirmationRequestSha256 != request.ConfirmationRequestSha256)
            return null;

        var expectedProofResponse = SerializeProofReceiptResponse(proof, securityEpoch);
        var confirmationRequestDigest = Convert.ToHexStringLower(SHA256.HashData(confirmation.CanonicalRequestUtf8));
        var providerCompatible = confirmation.State == "PROVED" && confirmation.HttpStatusCode == StatusCodes.Status200OK
            && confirmation.ErrorCode is null && confirmation.ContentType == ContentType
            && confirmation.ConfirmationRequestSha256 == proof.ConfirmationRequestSha256
            && confirmationRequestDigest == proof.ConfirmationRequestSha256
            && CryptographicOperations.FixedTimeEquals(confirmation.ExactResponseUtf8, expectedProofResponse)
            && preparation.ProductId == productId && preparation.RequestId == requestId
            && preparation.RequestDigestSha256 == request.RequestDigestSha256
            && preparation.RecoveryOperationRef == recoveryRef && preparation.ReservationRef == reservationRef
            && preparation.PrepareRef == prepareRef && preparation.EnrollmentId == proof.EnrollmentId
            && preparation.AuthorityGenerationId == proof.AuthorityGenerationId
            && preparation.PublicKeySpkiSha256 == proof.PublicKeySpkiSha256
            && preparation.ChallengeConsumedAtUtc == proof.ProvedAtUtc
            && confirmation.CompletedAtUtc == proof.ProvedAtUtc
            && proof.PreparationExpiresAtUtc == preparation.ExpiresAtUtc
            && proof.ReservationExpiresAtUtc == reservation.ExpiresAtUtc
            && proof.ExpiresAtUtc == (preparation.ExpiresAtUtc <= reservation.ExpiresAtUtc
                ? preparation.ExpiresAtUtc : reservation.ExpiresAtUtc)
            && proof.ProvedAtUtc < proof.ExpiresAtUtc
            && ledger.Decision == "AUTHORIZED" && ledger.ReservationRef == reservationRef
            && ledger.RecoveryOperationRef == recoveryRef && ledger.RequestDigestSha256 == request.RequestDigestSha256
            && reservation.AuthenticatedClientId == clientId && reservation.RequestId == requestId
            && reservation.ProductId == productId && reservation.RecoveryOperationRef == recoveryRef
            && reservation.State == "RESERVED"
            && authority.ReservationRef == reservationRef && authority.State == "PREPARED"
            && authority.PreviousAuthorityState == "ACTIVE" && authority.IsCurrentHead
            && authority.EnrollmentId == proof.EnrollmentId
            && authority.AuthorityGenerationId == proof.AuthorityGenerationId
            && authority.PublicKeySpkiSha256 == proof.PublicKeySpkiSha256
            && authority.LicenseSeatId == reservation.LicenseSeatId;

        var previousResolution = await ResolvePreviousActiveAuthorityAsync(
            db, productId, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, authority.ArtifactSetDigestSha256,
            cancellationToken, lockForCutover: true);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
            throw new RuntimeEnrollmentException(
                "provider_unavailable", StatusCodes.Status503ServiceUnavailable,
                previousResolution.DiagnosticCode);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
            throw CommercialAuthorityDenialException(previousResolution.DiagnosticCode);

        // Commercial ownership rows are historical request proof. They are locked after the
        // source enrollment and exclusive item 2 barrier and never substitute for assignment B.
        var license = await db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses"
            WHERE "ProductId" = {productId} AND "Id" = {reservation.LicenseId}
            FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var owners = await db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {productId} AND "LicenseId" = {reservation.LicenseId} AND "State" = 'ACTIVE'
            ORDER BY "Id" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        var owner = owners.Count == 1 ? owners[0] : null;
        var grantDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(reservation.ProviderGrantRef)));
        var grant = await db.RuntimeRecoveryGrantOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryGrantOwnerships"
            WHERE "ProductId" = {productId} AND "ProviderGrantRefDigestSha256" = {grantDigest}
            FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var activeRecoveryAuthorities = await db.RuntimeSeatRecoveryAuthorities.FromSqlInterpolated($"""
            SELECT authority.* FROM public."RuntimeSeatRecoveryAuthorities" authority
            WHERE authority."LicenseSeatId" = {reservation.LicenseSeatId} AND authority."State" = 'ACTIVE'
            ORDER BY authority."ReservationRef" FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        var newLineage = await db.RuntimeEnrollmentAuthorityLineages.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeEnrollmentAuthorityLineages"
            WHERE "AuthorityLineageId" = {authority.AuthorityLineageId}
            FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var decisionNow = await ReadDatabaseClockAsync(db, cancellationToken);
        previousResolution = await ReassessResolvedCommercialAuthorityAsync(
            db, previousResolution, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, decisionNow, cancellationToken);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
            throw new RuntimeEnrollmentException(
                "provider_unavailable", StatusCodes.Status503ServiceUnavailable,
                previousResolution.DiagnosticCode);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
            throw CommercialAuthorityDenialException(previousResolution.DiagnosticCode);
        var previous = previousResolution.Authority;

        providerCompatible = providerCompatible && license is not null && license.IsActive && license.RevokedAt is null
            && previousResolution.Outcome == PreviousAuthorityOutcome.Eligible
            && owner is not null && grant is not null
            && grant.AuthenticatedClientId == clientId && grant.LicenseId == reservation.LicenseId
            && grant.CommercialOwnershipId == owner.Id && grant.OwnerSubjectId == owner.OwnerSubjectId
            && grant.RecoveryOperationRef == recoveryRef && grant.RecoveryDigestSha256 == ledger.RecoveryDigestSha256
            && grant.RequestId == requestId && authority.SubjectRefDigestSha256 == SubjectDigest(owner.OwnerSubjectId)
            && activeRecoveryAuthorities.Count == 0
            && newLineage is not null && generation is not null
            && newLineage.Provider == "softlicence" && newLineage.ProductId == productId
            && newLineage.LicenseSeatId == reservation.LicenseSeatId
            && newLineage.ProviderGrantRef == reservation.ProviderGrantRef
            && newLineage.HeadGenerationId == authority.AuthorityGenerationId && newLineage.HeadSequence == 0
            && generation.RequestId == requestId && generation.Sequence == 0
            && generation.PreviousGenerationId is null
            && previous is not null && previous.HeadLineageId == authority.PreviousAuthorityLineageId
            && previous.HeadGenerationId == authority.PreviousAuthorityGenerationId;
        var lockedPrevious = previous ?? new(
            authority.PreviousAuthorityLineageId,
            authority.PreviousAuthorityGenerationId,
            Guid.Empty,
            Guid.Empty,
            Guid.Empty);
        return new(proof, reservation, authority, lockedPrevious, providerCompatible);
    }

    /// <summary>
    /// Locks and revalidates the complete provider scope, including the exact positive signed-generation epoch,
    /// without advancing any lifecycle state or inferring authority from preparation data. The caller owns the
    /// transaction and rolls it back when the helper refuses or throws.
    /// </summary>
    /// <param name="db">The context enlisted in the caller's key-stage transaction.</param>
    /// <param name="clientId">The exact authenticated client namespace.</param>
    /// <param name="productIdText">The canonical lowercase-D product UUID.</param>
    /// <param name="requestIdText">The canonical lowercase-D authorization request UUID.</param>
    /// <param name="requestDigest">The exact lowercase authorization body digest.</param>
    /// <param name="recoveryOperationRefText">The canonical lowercase-D recovery operation UUID.</param>
    /// <param name="reservationRefText">The canonical lowercase-D provider reservation UUID.</param>
    /// <param name="enrollmentIdText">The canonical lowercase-D prepared enrollment UUID.</param>
    /// <param name="authorityGenerationIdText">The canonical lowercase-D signed generation UUID.</param>
    /// <param name="publicKeySpkiSha256">The exact lowercase target public-key digest.</param>
    /// <param name="keyThumbprint">The optional exact base64url key thumbprint checked during preparation.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through every provider lock.</param>
    /// <returns>The locked proof scope, or null when historical identity or proof is invalid.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// Thrown with 422 for a known current commercial denial or 503 for unavailable provider state, before
    /// challenge consumption or stage persistence.
    /// </exception>
    private async Task<KeyProofScope?> LockAndValidateKeyScopeAsync(
        LicenseDbContext db,
        string clientId,
        string productIdText,
        string requestIdText,
        string requestDigest,
        string recoveryOperationRefText,
        string reservationRefText,
        string enrollmentIdText,
        string authorityGenerationIdText,
        string publicKeySpkiSha256,
        string? keyThumbprint,
        CancellationToken cancellationToken)
    {
        var productId = Guid.Parse(productIdText);
        var requestId = Guid.Parse(requestIdText);
        var recoveryRef = Guid.Parse(recoveryOperationRefText);
        var reservationRef = Guid.Parse(reservationRefText);
        var enrollmentId = Guid.Parse(enrollmentIdText);
        var generationId = Guid.Parse(authorityGenerationIdText);
        var ledger = await db.RuntimeSeatRecoveryAuthorizations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryAuthorizations"
            WHERE "AuthenticatedClientId" = {clientId} AND "RequestId" = {requestId}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var reservation = await db.RuntimeSeatRecoveryReservations.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryReservations"
            WHERE "ReservationRef" = {reservationRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var authority = await db.RuntimeSeatRecoveryAuthorities.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeSeatRecoveryAuthorities"
            WHERE "ReservationRef" = {reservationRef}
            FOR UPDATE
            """).SingleOrDefaultAsync(cancellationToken);
        var generation = authority is null ? null : await db.RuntimeEnrollmentAuthorityGenerations
            .AsNoTracking().SingleOrDefaultAsync(item =>
                item.AuthorityLineageId == authority.AuthorityLineageId
                && item.AuthorityGenerationId == authority.AuthorityGenerationId, cancellationToken);
        if (ledger is null || reservation is null || authority is null
            || ledger.Decision != "AUTHORIZED" || ledger.ReservationRef != reservationRef
            || ledger.RecoveryOperationRef != recoveryRef || ledger.RequestDigestSha256 != requestDigest
            || reservation.AuthenticatedClientId != clientId || reservation.RequestId != requestId
            || reservation.ProductId != productId || reservation.RecoveryOperationRef != recoveryRef
            || reservation.State != "RESERVED" || authority.State != "PREPARED" || !authority.IsCurrentHead
            || authority.EnrollmentId != enrollmentId || authority.AuthorityGenerationId != generationId
            || authority.PublicKeySpkiSha256 != publicKeySpkiSha256
            || keyThumbprint is not null && authority.KeyThumbprint != keyThumbprint)
            return null;
        if (generation is null)
            return null;
        if (!TryReadVerifiedSignedSecurityEpoch(generation, out var securityEpoch))
            throw new RuntimeEnrollmentException(
                "provider_unavailable", StatusCodes.Status503ServiceUnavailable,
                "authorization_generation_invalid");

        var previousResolution = await ResolvePreviousActiveAuthorityAsync(
            db, productId, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, authority.ArtifactSetDigestSha256, cancellationToken);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
            throw new RuntimeEnrollmentException(
                "provider_unavailable", StatusCodes.Status503ServiceUnavailable,
                previousResolution.DiagnosticCode);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
            throw CommercialAuthorityDenialException(previousResolution.DiagnosticCode);
        if (previousResolution.Authority is not { } previous
            || previous.HeadLineageId != authority.PreviousAuthorityLineageId
            || previous.HeadGenerationId != authority.PreviousAuthorityGenerationId)
            return null;

        var grantDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(reservation.ProviderGrantRef)));

        // This shared lock order must remain compatible with the TKT-000782 writer:
        // license -> exact ACTIVE ownership -> exact provider grant. PostgreSQL retains every row lock
        // until commit, so a concurrent transfer/revoke either follows this proof or invalidates its retry.
        var license = await db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses"
            WHERE "ProductId" = {productId} AND "Id" = {reservation.LicenseId}
            FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var activeOwners = await db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "ProductId" = {productId} AND "LicenseId" = {reservation.LicenseId}
              AND "State" = 'ACTIVE'
            ORDER BY "Id"
            FOR UPDATE
            """).AsNoTracking().ToListAsync(cancellationToken);
        var owner = activeOwners.Count == 1 ? activeOwners[0] : null;
        var grant = await db.RuntimeRecoveryGrantOwnerships.FromSqlInterpolated($"""
            SELECT * FROM public."RuntimeRecoveryGrantOwnerships"
            WHERE "ProductId" = {productId} AND "ProviderGrantRefDigestSha256" = {grantDigest}
            FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var decisionNow = await ReadDatabaseClockAsync(db, cancellationToken);
        previousResolution = await ReassessResolvedCommercialAuthorityAsync(
            db, previousResolution, reservation.LicenseId, reservation.LicenseSeatId,
            authority.ReleaseVersion, decisionNow, cancellationToken);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Unavailable)
            throw new RuntimeEnrollmentException(
                "provider_unavailable", StatusCodes.Status503ServiceUnavailable,
                previousResolution.DiagnosticCode);
        if (previousResolution.Outcome == PreviousAuthorityOutcome.Denied)
            throw CommercialAuthorityDenialException(previousResolution.DiagnosticCode);
        if (license is null || !license.IsActive || license.RevokedAt is not null
            || grant is null || owner is null || grant.AuthenticatedClientId != clientId
            || grant.LicenseId != reservation.LicenseId || grant.CommercialOwnershipId != owner.Id
            || grant.OwnerSubjectId != owner.OwnerSubjectId || grant.RecoveryOperationRef != recoveryRef
            || grant.RecoveryDigestSha256 != ledger.RecoveryDigestSha256 || grant.RequestId != requestId
            || authority.SubjectRefDigestSha256 != SubjectDigest(owner.OwnerSubjectId)) return null;
        return new(reservation, authority, securityEpoch);
    }

    /// <summary>
    /// Reads the positive security epoch only from the immutable payload carried by the persisted signed generation.
    /// The generation metadata and canonical payload digest must still agree, so W10/W10.2 never infer an epoch from
    /// a reservation, an enrollment default, or a locally incremented value.
    /// </summary>
    /// <param name="generation">The immutable provider generation row that owns the signed canonical payload.</param>
    /// <param name="securityEpoch">Receives the exact positive epoch from the canonical payload on success.</param>
    /// <returns><see langword="true"/> only when the signed-generation record and payload remain coherent.</returns>
    internal static bool TryReadSignedSecurityEpoch(
        RuntimeEnrollmentAuthorityGeneration generation,
        out int securityEpoch) => TryReadSignedSecurityEpoch(
            generation, out securityEpoch, out _);

    /// <summary>
    /// Reads and cryptographically verifies the positive security epoch from one persisted generic generation.
    /// Parsing failures retain their original exception at the protected redacted logging boundary.
    /// </summary>
    /// <param name="generation">The immutable provider generation row being verified.</param>
    /// <param name="securityEpoch">Receives the exact positive signed epoch on success.</param>
    /// <returns>True only when payload, statement, digest, configured key, and PS256 signature all agree.</returns>
    private bool TryReadVerifiedSignedSecurityEpoch(
        RuntimeEnrollmentAuthorityGeneration generation,
        out int securityEpoch)
    {
        if (!TryReadSignedSecurityEpoch(generation, out securityEpoch, out var parsingException))
        {
            if (parsingException is not null)
                LogInvalidRecoveryGenerationPayload(parsingException, generation);
            return false;
        }
        return VerifyPersistedGenerationCryptography(generation, generation.CanonicalPayloadUtf8);
    }

    /// <summary>Parses coherent generic generation bytes while returning the original bounded parser exception.</summary>
    private static bool TryReadSignedSecurityEpoch(
        RuntimeEnrollmentAuthorityGeneration generation,
        out int securityEpoch,
        out Exception? parsingException)
    {
        securityEpoch = 0;
        parsingException = null;
        RuntimeEnrollmentAuthorityGenerationPayloadV2? payload;
        try
        {
            payload = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                generation.CanonicalPayloadUtf8, AuthorityJson);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            parsingException = exception;
            return false;
        }

        if (payload?.Key is null || payload.Transition is null || payload.Key.SecurityEpoch <= 0
            || !string.Equals(payload.Schema, "runtime-enrollment-authority-generation-v2", StringComparison.Ordinal)
            || payload.ContractVersion != 2 || !string.Equals(payload.Provider, "softlicence", StringComparison.Ordinal)
            || !Guid.TryParseExact(payload.AuthorityLineageId, "D", out var lineageId)
            || !Guid.TryParseExact(payload.AuthorityGenerationId, "D", out var generationId)
            || lineageId != generation.AuthorityLineageId || generationId != generation.AuthorityGenerationId
            || payload.Sequence != generation.Sequence
            || !string.Equals(payload.PreviousGenerationId,
                generation.PreviousGenerationId?.ToString("D"), StringComparison.Ordinal)
            || !string.Equals(payload.Transition.RequestId,
                generation.RequestId.ToString("D"), StringComparison.Ordinal)
            || !string.Equals(payload.Transition.OccurredAtUtc,
                Format(generation.OccurredAtUtc), StringComparison.Ordinal)
            || !string.Equals(payload.Key.AuthorityKeyId, generation.SignatureKeyId, StringComparison.Ordinal)
            || !string.Equals(generation.SignatureAlgorithm, "PS256", StringComparison.Ordinal)
            || generation.SignedStatementUtf8.Length == 0 || generation.SignatureValue.Length == 0)
            return false;

        byte[] canonicalPayload;
        try
        {
            canonicalPayload = JsonSerializer.SerializeToUtf8Bytes(payload, AuthorityJson);
        }
        catch (NotSupportedException exception)
        {
            parsingException = exception;
            return false;
        }
        var digest = Convert.ToHexStringLower(SHA256.HashData(canonicalPayload));
        var expectedStatement = Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-enrollment-signed-generation-v2\",\"payload\":{Encoding.UTF8.GetString(canonicalPayload)},\"authorityDigest\":\"{digest}\",\"signature\":{{\"algorithm\":\"PS256\",\"keyId\":\"{generation.SignatureKeyId}\",\"value\":\"{generation.SignatureValue}\"}}}}");
        if (!generation.CanonicalPayloadUtf8.AsSpan().SequenceEqual(canonicalPayload)
            || !string.Equals(generation.AuthorityDigest, digest, StringComparison.Ordinal)
            || !generation.SignedStatementUtf8.AsSpan().SequenceEqual(expectedStatement))
            return false;

        securityEpoch = payload.Key.SecurityEpoch;
        return true;
    }

    /// <summary>
    /// Verifies persisted generic generation bytes with the exact configured operational public key. Configuration,
    /// decoding, RSA-profile, and PS256 failures are closed without exposing key material or payload bytes.
    /// </summary>
    /// <param name="generation">The immutable generation metadata containing exact key and signature text.</param>
    /// <param name="canonicalPayload">The canonical payload bytes already matched to durable generation metadata.</param>
    /// <returns>True only for the configured exact operational key and valid generic generation signature.</returns>
    private bool VerifyPersistedGenerationCryptography(
        RuntimeEnrollmentAuthorityGeneration generation,
        ReadOnlySpan<byte> canonicalPayload)
    {
        if (!string.Equals(generation.SignatureAlgorithm, "PS256", StringComparison.Ordinal))
            return false;
        var digest = Convert.ToHexStringLower(SHA256.HashData(canonicalPayload));
        var expectedStatement = Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-enrollment-signed-generation-v2\",\"payload\":{Encoding.UTF8.GetString(canonicalPayload)},\"authorityDigest\":\"{digest}\",\"signature\":{{\"algorithm\":\"PS256\",\"keyId\":\"{generation.SignatureKeyId}\",\"value\":\"{generation.SignatureValue}\"}}}}");
        if (!string.Equals(generation.AuthorityDigest, digest, StringComparison.Ordinal)
            || !generation.SignedStatementUtf8.AsSpan().SequenceEqual(expectedStatement))
            return false;
        byte[] registryPin;
        try
        {
            registryPin = Convert.FromBase64String(options.AuthorityGenerationV2.RegistryAuthoritySpkiBase64);
        }
        catch (FormatException)
        {
            return false;
        }
        try
        {
            var cryptography = new RuntimeEnrollmentAuthorityCryptography(clock, registryPin);
            return cryptography.VerifyGenerationSignature(
                options.AuthorityGenerationSigning,
                canonicalPayload,
                generation.SignatureKeyId,
                generation.SignatureValue) == RuntimeEnrollmentAuthorityCryptography.Failure.None;
        }
        catch (ArgumentException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(registryPin);
        }
    }

    /// <summary>
    /// Retains the original generic-generation parser exception with safe provider UUIDs and one stable diagnostic.
    /// A failing sink is contained without recursion so it cannot replace the primary provider-unavailable result.
    /// </summary>
    /// <param name="exception">The original JSON contract exception, including its protected stack trace.</param>
    /// <param name="generation">The generation whose payload could not be decoded.</param>
    private void LogInvalidRecoveryGenerationPayload(
        Exception exception,
        RuntimeEnrollmentAuthorityGeneration generation)
    {
        try
        {
            logger.LogWarning(
                exception,
                "Runtime recovery authority generation payload is invalid. DiagnosticCode={DiagnosticCode} AuthorityLineageId={AuthorityLineageId} AuthorityGenerationId={AuthorityGenerationId}",
                "authorization_generation_invalid",
                generation.AuthorityLineageId,
                generation.AuthorityGenerationId);
        }
        catch (Exception)
        {
            // The protected sink is best-effort. Never recurse or replace the safe provider-unavailable path.
        }
    }

    /// <summary>Imports only the canonical RSA-3072/e65537 recovery SPKI and derives its public identifiers.</summary>
    private static bool TryValidateRecoverySpki(
        string value, out byte[] spki, out string digest, out string thumbprint)
    {
        spki = [];
        digest = string.Empty;
        thumbprint = string.Empty;
        try
        {
            spki = Convert.FromBase64String(value);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            var exponent = rsa.ExportParameters(false).Exponent;
            if (consumed != spki.Length || rsa.KeySize != 3072 || exponent is not [0x01, 0x00, 0x01]
                || !CryptographicOperations.FixedTimeEquals(spki, rsa.ExportSubjectPublicKeyInfo()))
                throw new CryptographicException("Recovery SPKI is not canonical RSA-3072/e65537.");
            var hash = SHA256.HashData(spki);
            try
            {
                digest = Convert.ToHexStringLower(hash);
                thumbprint = EncodeBase64Url(hash);
                return true;
            }
            finally { CryptographicOperations.ZeroMemory(hash); }
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            CryptographicOperations.ZeroMemory(spki);
            spki = [];
            return false;
        }
    }

    /// <summary>Verifies one PS256 confirmation only with the canonical RSA-3072 recovery public key.</summary>
    private static bool VerifyConfirmationSignature(
        ReadOnlySpan<byte> spki, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            return consumed == spki.Length && rsa.KeySize == 3072
                && rsa.VerifyData(input, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException) { return false; }
    }

    /// <summary>Compares a confirmation outer with the exact immutable identity frozen by its preparation.</summary>
    /// <param name="preparation">The locked key preparation that owns the challenge.</param>
    /// <param name="request">The validated confirmation request being authorized.</param>
    /// <returns><see langword="true"/> only when every preparation-owned outer field matches exactly.</returns>
    private static bool MatchesPreparationOuter(
        RuntimeSeatRecoveryKeyPreparation preparation, RuntimeSeatRecoveryKeyConfirmationRequest request) =>
        preparation.ProductId == Guid.Parse(request.ProductId)
        && preparation.RequestId == Guid.Parse(request.RequestId)
        && preparation.RequestDigestSha256 == request.RequestDigestSha256
        && preparation.RecoveryOperationRef == Guid.Parse(request.RecoveryOperationRef)
        && preparation.ReservationRef == Guid.Parse(request.ReservationRef)
        && preparation.PrepareRef == Guid.Parse(request.PrepareRef)
        && preparation.EnrollmentId == Guid.Parse(request.EnrollmentId)
        && preparation.AuthorityGenerationId == Guid.Parse(request.AuthorityGenerationId)
        && preparation.PublicKeySpkiSha256 == request.PublicKeySpkiSha256;

    /// <summary>Validates that the signed confirmation statement exactly repeats its outer and preparation identity.</summary>
    /// <param name="outer">The validated confirmation outer.</param>
    /// <param name="statement">The captured canonical statement embedded in the outer.</param>
    /// <param name="preparation">The locked preparation that owns the challenge and audience.</param>
    /// <returns><see langword="true"/> only when every statement field matches the outer and preparation without normalization.</returns>
    private static bool MatchesStatement(
        RuntimeSeatRecoveryKeyConfirmationRequest outer,
        RuntimeSeatRecoveryKeyConfirmationStatement statement,
        RuntimeSeatRecoveryKeyPreparation preparation) =>
        statement.PrepareRef == outer.PrepareRef && statement.RequestId == outer.RequestId
        && statement.RequestDigestSha256 == outer.RequestDigestSha256
        && statement.RecoveryOperationRef == outer.RecoveryOperationRef
        && statement.ReservationRef == outer.ReservationRef && statement.EnrollmentId == outer.EnrollmentId
        && statement.AuthorityGenerationId == outer.AuthorityGenerationId
        && statement.ConfirmAudience == preparation.ConfirmAudience;

    /// <summary>Serializes frozen W10 bytes with the positive epoch supplied by the matching signed generation.</summary>
    /// <param name="request">The canonical W10 request whose immutable identity is echoed.</param>
    /// <param name="prepareRef">The provider-created preparation identifier.</param>
    /// <param name="securityEpoch">The signed-generation epoch in the closed range 1 through Int32.MaxValue.</param>
    /// <param name="challenge">The canonical unpadded challenge text.</param>
    /// <param name="expiresAtUtc">The authoritative preparation expiry.</param>
    /// <returns>Newly allocated canonical UTF-8 response bytes ready for durable freezing.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The supplied epoch is zero or negative.</exception>
    internal static byte[] SerializeKeyPreparationResponse(
        RuntimeSeatRecoveryKeyPreparationRequest request, Guid prepareRef, int securityEpoch,
        string challenge, DateTime expiresAtUtc)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityEpoch);
        return Encoding.UTF8.GetBytes($"{{\"schema\":\"runtime-seat-recovery-key-prepare-response-v1\",\"contractVersion\":1,\"status\":\"prepared\",\"requestId\":\"{request.RequestId}\",\"requestDigestSha256\":\"{request.RequestDigestSha256}\",\"recoveryOperationRef\":\"{request.RecoveryOperationRef}\",\"reservationRef\":\"{request.ReservationRef}\",\"prepareRef\":\"{prepareRef:D}\",\"enrollmentId\":\"{request.EnrollmentId}\",\"authorityGenerationId\":\"{request.AuthorityGenerationId}\",\"securityEpoch\":{securityEpoch},\"challenge\":\"{challenge}\",\"confirmAudience\":\"{ConfirmationAudience}\",\"expiresAtUtc\":\"{Format(expiresAtUtc)}\"}}");
    }

    /// <summary>Serializes frozen W10.2 bytes with the positive epoch supplied by the matching signed generation.</summary>
    /// <param name="request">The canonical W10.2 request whose immutable identity is echoed.</param>
    /// <param name="securityEpoch">The signed-generation epoch in the closed range 1 through Int32.MaxValue.</param>
    /// <param name="confirmationRequestSha256">The lowercase SHA-256 digest of the exact confirmation request.</param>
    /// <param name="provedAtUtc">The provider database instant at which possession became durable.</param>
    /// <param name="expiresAtUtc">The minimum authoritative proof expiry.</param>
    /// <returns>Newly allocated canonical UTF-8 PROVED bytes ready for durable freezing.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The supplied epoch is zero or negative.</exception>
    internal static byte[] SerializeProofResponse(
        RuntimeSeatRecoveryKeyConfirmationRequest request,
        int securityEpoch,
        string confirmationRequestSha256,
        DateTime provedAtUtc,
        DateTime expiresAtUtc)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityEpoch);
        return Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-seat-recovery-key-confirmation-response-v1\",\"contractVersion\":1,\"status\":\"proved\",\"productId\":\"{request.ProductId}\",\"requestId\":\"{request.RequestId}\",\"requestDigestSha256\":\"{request.RequestDigestSha256}\",\"recoveryOperationRef\":\"{request.RecoveryOperationRef}\",\"reservationRef\":\"{request.ReservationRef}\",\"prepareRef\":\"{request.PrepareRef}\",\"enrollmentId\":\"{request.EnrollmentId}\",\"authorityGenerationId\":\"{request.AuthorityGenerationId}\",\"securityEpoch\":{securityEpoch},\"publicKeySpkiSha256\":\"{request.PublicKeySpkiSha256}\",\"confirmationRequestSha256\":\"{confirmationRequestSha256}\",\"provedAtUtc\":\"{FormatProof(provedAtUtc)}\",\"expiresAtUtc\":\"{FormatProof(expiresAtUtc)}\"}}");
    }

    /// <summary>Reconstructs W10.2 from its durable receipt and the matching immutable signed generation epoch.</summary>
    /// <param name="proof">The durable PROVED identity and timestamps.</param>
    /// <param name="securityEpoch">The revalidated signed-generation epoch in the closed positive Int32 range.</param>
    /// <returns>Canonical bytes that must equal the frozen confirmation response.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The supplied epoch is zero or negative.</exception>
    private static byte[] SerializeProofReceiptResponse(
        RuntimeSeatRecoveryProofReceipt proof, int securityEpoch)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityEpoch);
        return Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-seat-recovery-key-confirmation-response-v1\",\"contractVersion\":1,\"status\":\"proved\",\"productId\":\"{proof.ProductId:D}\",\"requestId\":\"{proof.RequestId:D}\",\"requestDigestSha256\":\"{proof.RequestDigestSha256}\",\"recoveryOperationRef\":\"{proof.RecoveryOperationRef:D}\",\"reservationRef\":\"{proof.ReservationRef:D}\",\"prepareRef\":\"{proof.PrepareRef:D}\",\"enrollmentId\":\"{proof.EnrollmentId:D}\",\"authorityGenerationId\":\"{proof.AuthorityGenerationId:D}\",\"securityEpoch\":{securityEpoch},\"publicKeySpkiSha256\":\"{proof.PublicKeySpkiSha256}\",\"confirmationRequestSha256\":\"{proof.ConfirmationRequestSha256}\",\"provedAtUtc\":\"{FormatProof(proof.ProvedAtUtc)}\",\"expiresAtUtc\":\"{FormatProof(proof.ExpiresAtUtc)}\"}}");
    }

    /// <summary>Serializes the immutable positive activation receipt in the contract's exact property order.</summary>
    /// <param name="request">The validated activation command whose identity is echoed.</param>
    /// <param name="activationRequestDigestSha256">The lowercase digest of the exact activation request bytes.</param>
    /// <param name="scope">The locked proof, authority, enrollment, binding, seat, and source-assignment scope.</param>
    /// <param name="activatedAtUtc">The database-clock instant at which the cutover completed.</param>
    /// <returns>The exact terminal success bytes to persist and replay byte-for-byte.</returns>
    internal static byte[] SerializeActivationResponse(
        RuntimeSeatRecoveryActivationRequest request,
        string activationRequestDigestSha256,
        ActivationScope scope,
        DateTime activatedAtUtc) => Encoding.UTF8.GetBytes(
        $"{{\"schema\":\"runtime-seat-recovery-activation-response-v1\",\"contractVersion\":1,\"status\":\"committed\",\"productId\":\"{request.ProductId}\",\"requestId\":\"{request.RequestId}\",\"activationRequestDigestSha256\":\"{activationRequestDigestSha256}\",\"requestDigestSha256\":\"{request.RequestDigestSha256}\",\"recoveryOperationRef\":\"{request.RecoveryOperationRef}\",\"reservationRef\":\"{request.ReservationRef}\",\"activatedAtUtc\":\"{FormatProof(activatedAtUtc)}\",\"proofReceipt\":{{\"state\":\"proved\",\"prepareRef\":\"{request.PrepareRef}\",\"confirmationRequestSha256\":\"{request.ConfirmationRequestSha256}\",\"expiresAtUtc\":\"{FormatProof(scope.Proof.ExpiresAtUtc)}\"}},\"previousAuthority\":{{\"authorityLineageId\":\"{scope.Authority.PreviousAuthorityLineageId:D}\",\"authorityGenerationId\":\"{scope.Authority.PreviousAuthorityGenerationId:D}\",\"state\":\"superseded\"}},\"newAuthority\":{{\"authorityLineageId\":\"{scope.Authority.AuthorityLineageId:D}\",\"authorityGenerationId\":\"{scope.Authority.AuthorityGenerationId:D}\",\"enrollmentId\":\"{scope.Authority.EnrollmentId:D}\",\"state\":\"active\",\"isCurrentHead\":true}},\"reservation\":{{\"state\":\"committed\"}}}}");

    /// <summary>Freezes one exact terminal conflict or expiry after the PROVED identity is established.</summary>
    /// <param name="db">The caller-owned context whose active transaction owns the receipt mutation.</param>
    /// <param name="clientId">The authenticated client identity that owns the recovery operation.</param>
    /// <param name="parsed">The canonical activation request and digest established before persistence.</param>
    /// <param name="scope">The locked recovery scope from which the terminal receipt identity is derived.</param>
    /// <param name="errorCode">The stable public terminal error code.</param>
    /// <param name="statusCode">The frozen HTTP status returned by every exact replay.</param>
    /// <param name="completedAtUtc">The database-clock completion instant.</param>
    /// <returns>The exact error response also added to the caller's transaction for byte-identical replay.</returns>
    /// <remarks>This helper neither saves nor commits; the caller owns rollback, persistence, and transaction completion.</remarks>
    private static RuntimeSeatRecoveryHttpResult FreezeActivationReceipt(
        LicenseDbContext db,
        string clientId,
        RuntimeSeatRecoveryContractCodec.ActivationParseResult parsed,
        ActivationScope scope,
        string errorCode,
        int statusCode,
        DateTime completedAtUtc)
    {
        var request = parsed.Request!;
        var response = SerializeActivationError(
            request, parsed.ActivationRequestDigestSha256!, errorCode, completedAtUtc);
        AddActivationReceipt(db, clientId, parsed, scope, "REFUSED", statusCode, errorCode,
            response, completedAtUtc);
        return new(statusCode, ContentType, response);
    }

    /// <summary>Serializes one closed activation refusal in its exact frozen property order.</summary>
    /// <param name="request">The validated activation request whose public identity is echoed.</param>
    /// <param name="activationRequestDigestSha256">The lowercase digest of the exact activation request bytes.</param>
    /// <param name="errorCode">The stable public refusal code; protected causes are never serialized.</param>
    /// <param name="completedAtUtc">The database-clock completion instant.</param>
    /// <returns>The exact terminal refusal bytes to persist and replay byte-for-byte.</returns>
    internal static byte[] SerializeActivationError(
        RuntimeSeatRecoveryActivationRequest request,
        string activationRequestDigestSha256,
        string errorCode,
        DateTime completedAtUtc) => Encoding.UTF8.GetBytes(
        $"{{\"schema\":\"runtime-seat-recovery-activation-error-v1\",\"contractVersion\":1,\"status\":\"refused\",\"productId\":\"{request.ProductId}\",\"requestId\":\"{request.RequestId}\",\"activationRequestDigestSha256\":\"{activationRequestDigestSha256}\",\"errorCode\":\"{errorCode}\",\"completedAtUtc\":\"{FormatProof(completedAtUtc)}\"}}");

    /// <summary>Adds one immutable activation terminal inside the caller's cutover transaction.</summary>
    /// <param name="db">The caller-owned context tracking the new receipt.</param>
    /// <param name="clientId">The authenticated client identity that owns the activation.</param>
    /// <param name="parsed">The canonical request bytes and digest frozen by the receipt.</param>
    /// <param name="scope">The locked recovery scope that owns the receipt identity.</param>
    /// <param name="state">The closed terminal receipt state.</param>
    /// <param name="statusCode">The terminal HTTP status replayed from the receipt.</param>
    /// <param name="errorCode">The stable public error code, or <see langword="null"/> for success.</param>
    /// <param name="response">The exact response bytes owned by the receipt.</param>
    /// <param name="completedAtUtc">The database-clock terminal instant.</param>
    /// <remarks>This helper only attaches the receipt; the caller owns saving, commit, and rollback of the enclosing cutover transaction.</remarks>
    private static void AddActivationReceipt(
        LicenseDbContext db,
        string clientId,
        RuntimeSeatRecoveryContractCodec.ActivationParseResult parsed,
        ActivationScope scope,
        string state,
        int statusCode,
        string? errorCode,
        byte[] response,
        DateTime completedAtUtc)
    {
        var request = parsed.Request!;
        db.RuntimeSeatRecoveryActivationReceipts.Add(new RuntimeSeatRecoveryActivationReceipt
        {
            AuthenticatedClientId = clientId,
            RequestId = Guid.Parse(request.RequestId),
            ActivationRequestDigestSha256 = parsed.ActivationRequestDigestSha256!,
            CanonicalRequestUtf8 = [.. parsed.CanonicalUtf8],
            ProductId = Guid.Parse(request.ProductId),
            RequestDigestSha256 = request.RequestDigestSha256,
            RecoveryOperationRef = Guid.Parse(request.RecoveryOperationRef),
            ReservationRef = Guid.Parse(request.ReservationRef),
            PrepareRef = Guid.Parse(request.PrepareRef),
            ConfirmationRequestSha256 = request.ConfirmationRequestSha256,
            PreviousAuthorityLineageId = scope.Authority.PreviousAuthorityLineageId,
            PreviousAuthorityGenerationId = scope.Authority.PreviousAuthorityGenerationId,
            NewAuthorityLineageId = scope.Authority.AuthorityLineageId,
            NewAuthorityGenerationId = scope.Authority.AuthorityGenerationId,
            EnrollmentId = scope.Authority.EnrollmentId,
            State = state,
            HttpStatusCode = statusCode,
            ContentType = ContentType,
            ErrorCode = errorCode,
            ExactResponseUtf8 = response,
            CompletedAtUtc = completedAtUtc
        });
    }

    /// <summary>Builds the public key-confirmation refusal without persisting protected diagnostic detail.</summary>
    /// <param name="request">The validated confirmation request whose public identity is echoed.</param>
    /// <param name="errorCode">The stable public refusal code.</param>
    /// <param name="statusCode">The HTTP status associated with the refusal.</param>
    /// <param name="completedAtUtc">The database-clock refusal instant.</param>
    /// <returns>The exact refusal envelope; this helper performs no persistence or transaction work.</returns>
    private static RuntimeSeatRecoveryHttpResult KeyConfirmationError(
        RuntimeSeatRecoveryKeyConfirmationRequest request, string errorCode, int statusCode, DateTime completedAtUtc) =>
        new(statusCode, ContentType, Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-seat-recovery-key-confirmation-error-v1\",\"contractVersion\":1,\"productId\":\"{request.ProductId}\",\"requestId\":\"{request.RequestId}\",\"requestDigestSha256\":\"{request.RequestDigestSha256}\",\"prepareRef\":\"{request.PrepareRef}\",\"errorCode\":\"{errorCode}\",\"completedAtUtc\":\"{Format(completedAtUtc)}\"}}"));

    /// <summary>Consumes one challenge and freezes its terminal confirmation refusal for exact replay.</summary>
    /// <param name="db">The caller-owned context whose active transaction owns the mutation.</param>
    /// <param name="authenticatedClientId">The authenticated client identity that owns the preparation.</param>
    /// <param name="preparation">The locked preparation whose challenge is consumed.</param>
    /// <param name="request">The validated confirmation request whose identity is frozen.</param>
    /// <param name="parsed">The exact canonical request bytes and digest.</param>
    /// <param name="completedAtUtc">The database-clock refusal instant.</param>
    /// <param name="errorCode">The stable public refusal code.</param>
    /// <param name="statusCode">The terminal HTTP status replayed for this confirmation.</param>
    /// <returns>The exact refusal response attached to the new immutable confirmation row.</returns>
    /// <remarks>This helper neither saves nor commits; the caller owns rollback, persistence, and transaction completion.</remarks>
    private static RuntimeSeatRecoveryHttpResult FreezeConfirmationRefusal(
        LicenseDbContext db,
        string authenticatedClientId,
        RuntimeSeatRecoveryKeyPreparation preparation,
        RuntimeSeatRecoveryKeyConfirmationRequest request,
        RuntimeSeatRecoveryContractCodec.KeyConfirmationParseResult parsed,
        DateTime completedAtUtc,
        string errorCode,
        int statusCode)
    {
        var response = KeyConfirmationError(request, errorCode, statusCode, completedAtUtc);
        preparation.ChallengeConsumedAtUtc = completedAtUtc;
        db.RuntimeSeatRecoveryKeyConfirmations.Add(new RuntimeSeatRecoveryKeyConfirmation
        {
            AuthenticatedClientId = authenticatedClientId,
            PrepareRef = preparation.PrepareRef,
            ConfirmationRequestSha256 = parsed.ConfirmationRequestSha256!,
            CanonicalRequestUtf8 = [.. parsed.CanonicalUtf8],
            State = "REFUSED",
            HttpStatusCode = statusCode,
            ContentType = ContentType,
            ErrorCode = errorCode,
            ExactResponseUtf8 = response.ExactBodyUtf8,
            CompletedAtUtc = completedAtUtc
        });
        return response;
    }

    /// <summary>Recognizes only the closed set of key-proof uniqueness races that permit a bounded reread.</summary>
    /// <param name="exception">The database exception chain to inspect without exposing its message.</param>
    /// <returns><see langword="true"/> only for a PostgreSQL unique violation on an allowlisted key-proof constraint.</returns>
    private static bool IsKeyProofUniqueViolation(Exception exception)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "PK_RuntimeSeatRecoveryKeyPreparations",
            "AK_RSRKP_Client_Request_Recovery",
            "IX_RuntimeSeatRecoveryKeyPreparations_ReservationRef",
            "IX_RuntimeSeatRecoveryKeyPreparations_EnrollmentId",
            "IX_RuntimeSeatRecoveryKeyPreparations_AuthorityGenerationId",
            "PK_RuntimeSeatRecoveryKeyConfirmations",
            "PK_RuntimeSeatRecoveryProofReceipts",
            "IX_RuntimeSeatRecoveryProofReceipts_ReservationRef",
            "IX_RuntimeSeatRecoveryProofReceipts_AuthorityGenerationId"
        };
        for (var current = exception; current is not null; current = current.InnerException)
            if (current is PostgresException postgres && postgres.SqlState == PostgresErrorCodes.UniqueViolation)
                return postgres.ConstraintName is not null && allowed.Contains(postgres.ConstraintName);
        return false;
    }

    /// <summary>Allows bounded reread only for activation receipt and active-seat uniqueness races.</summary>
    private static bool IsActivationUniqueViolation(Exception exception)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "PK_RuntimeSeatRecoveryActivationReceipts",
            "UX_RSRActivation_Client_PrepareRef",
            "IX_RuntimeSeatRecoveryActivationReceipts_ReservationRef",
            "UX_RSRAuthorities_OneActivePerSeat"
        };
        for (var current = exception; current is not null; current = current.InnerException)
            if (current is PostgresException postgres && postgres.SqlState == PostgresErrorCodes.UniqueViolation)
                return postgres.ConstraintName is not null && allowed.Contains(postgres.ConstraintName);
        return false;
    }

    /// <summary>Encodes exact bytes as unpadded canonical base64url without normalizing their content.</summary>
    /// <param name="value">The bytes to encode.</param>
    /// <returns>The canonical unpadded base64url representation.</returns>
    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Builds the stable envelope owner reference for one encrypted preparation field.</summary>
    /// <param name="prepareRef">The preparation identifier that owns the encrypted value.</param>
    /// <param name="field">The closed field name within the preparation row.</param>
    /// <returns>The deterministic owner reference used by envelope sealing and opening.</returns>
    private static string PreparationFieldReference(Guid prepareRef, string field) =>
        $"RuntimeSeatRecoveryKeyPreparations:{prepareRef:D}:{field}";

    /// <summary>Builds the public non-terminal commercial refusal without exposing its protected cause.</summary>
    /// <returns>The stable 422 transport envelope used at every recovery stage.</returns>
    private static RuntimeSeatRecoveryHttpResult CommercialAuthorityDenial() =>
        Transport(StatusCodes.Status422UnprocessableEntity, "commercial_authority_ineligible");

    /// <summary>Preserves a protected commercial cause while exposing only the stable non-terminal refusal.</summary>
    /// <param name="diagnosticCode">The bounded server-only commercial denial reason.</param>
    /// <returns>An exception mapped by the owning transaction to the public 422 transport envelope.</returns>
    private static RuntimeEnrollmentException CommercialAuthorityDenialException(string diagnosticCode) =>
        new("commercial_authority_ineligible", StatusCodes.Status422UnprocessableEntity, diagnosticCode);

    /// <summary>Holds the locked provider authority and its exact positive signed-generation epoch.</summary>
    /// <param name="Reservation">The locked RESERVED provider reservation.</param>
    /// <param name="Authority">The locked PREPARED recovery authority.</param>
    /// <param name="SecurityEpoch">The positive Int32 epoch read from the matching signed generation.</param>
    private sealed record KeyProofScope(
        RuntimeSeatRecoveryReservation Reservation,
        RuntimeSeatRecoveryAuthority Authority,
        int SecurityEpoch);

    /// <summary>Holds the locked activation aggregate and its closed non-commercial compatibility verdict.</summary>
    /// <param name="Proof">The exact durable proof-of-possession receipt.</param>
    /// <param name="Reservation">The row-locked recovery reservation.</param>
    /// <param name="Authority">The row-locked prepared recovery authority.</param>
    /// <param name="PreviousAuthority">The proved source authority and current assignment held for cutover.</param>
    /// <param name="ProviderCompatible">Whether all historical proof and ownership relations remain coherent.</param>
    internal sealed record ActivationScope(
        RuntimeSeatRecoveryProofReceipt Proof,
        RuntimeSeatRecoveryReservation Reservation,
        RuntimeSeatRecoveryAuthority Authority,
        PreviousActiveAuthority PreviousAuthority,
        bool ProviderCompatible)
    {
        /// <summary>Builds a serialization-only scope for pure contract vectors without provider mutation.</summary>
        internal ActivationScope(
            RuntimeSeatRecoveryProofReceipt proof,
            RuntimeSeatRecoveryReservation reservation,
            RuntimeSeatRecoveryAuthority authority,
            bool providerCompatible)
            : this(proof, reservation, authority, new(
                authority.PreviousAuthorityLineageId,
                authority.PreviousAuthorityGenerationId,
                Guid.Empty,
                Guid.Empty,
                Guid.Empty), providerCompatible)
        {
        }
    }

    /// <summary>Builds the non-terminal transport envelope without persisting or revealing business scope.</summary>
    private static RuntimeSeatRecoveryHttpResult Transport(int statusCode, string errorCode) =>
        new(statusCode, ContentType, Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-seat-recovery-transport-error-v1\",\"contractVersion\":1,\"errorCode\":\"{errorCode}\"}}"));

    /// <summary>Builds one exact semantic refusal without changing any previously frozen terminal.</summary>
    private static RuntimeSeatRecoveryHttpResult SemanticError(
        RuntimeSeatRecoveryAuthorizationRequest request,
        string requestDigest,
        string errorCode,
        int statusCode,
        DateTime completedAtUtc) => new(statusCode, ContentType, Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-seat-recovery-authorization-error-v1\",\"contractVersion\":1,\"decision\":\"refused\",\"requestId\":\"{request.RequestId}\",\"requestDigestSha256\":\"{requestDigest}\",\"errorCode\":\"{errorCode}\",\"completedAtUtc\":\"{Format(completedAtUtc)}\"}}"));

    /// <summary>
    /// Serializes the authorized outer once with the shared W5 opaque writer while embedding the
    /// already signed statement bytes verbatim.
    /// </summary>
    /// <param name="request">The validated authorization request whose opaque fields are preserved exactly.</param>
    /// <param name="requestDigest">The lowercase digest of the canonical request bytes.</param>
    /// <param name="reservationRef">The provider-owned reservation identifier.</param>
    /// <param name="subjectDigest">The lowercase provider subject digest.</param>
    /// <param name="seatId">The locked eligible seat identifier.</param>
    /// <param name="bindingId">The locked installation-binding identifier.</param>
    /// <param name="enrollmentId">The locked Runtime-enrollment identifier.</param>
    /// <param name="authorizedAtUtc">The database-clock authorization instant.</param>
    /// <param name="expiresAtUtc">The bounded reservation expiry instant.</param>
    /// <param name="signedStatement">The exact canonical signed statement bytes embedded without reparsing.</param>
    /// <returns>The canonical authorized response bytes suitable for immutable persistence and exact replay.</returns>
    private static byte[] SerializeAuthorized(
        RuntimeSeatRecoveryAuthorizationRequest request,
        string requestDigest,
        Guid reservationRef,
        string subjectDigest,
        Guid seatId,
        Guid bindingId,
        Guid enrollmentId,
        DateTime authorizedAtUtc,
        DateTime expiresAtUtc,
        byte[] signedStatement)
    {
        var output = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        writer.WriteStartObject();
        writer.WriteString("schema", "runtime-seat-recovery-authorization-response-v1"); writer.WriteNumber("contractVersion", 1);
        writer.WriteString("decision", "authorized"); writer.WriteString("requestId", request.RequestId);
        writer.WriteString("requestDigestSha256", requestDigest); writer.WriteString("recoveryOperationRef", request.RecoveryOperationRef);
        writer.WriteString("reservationRef", reservationRef); writer.WriteString("reservationState", "reserved");
        writer.WriteString("authorizedAtUtc", Format(authorizedAtUtc)); writer.WriteString("expiresAtUtc", Format(expiresAtUtc));
        writer.WriteString("provider", "softlicence");
        RuntimeSeatRecoveryContractCodec.WriteCanonicalOpaqueString(
            writer, "providerGrantRef", request.ProviderGrantRef);
        writer.WriteString("subjectRefDigestSha256", subjectDigest); writer.WriteString("productId", request.ProductId);
        writer.WriteString("licenseId", request.LicenseId); writer.WriteString("seatId", seatId);
        writer.WriteString("bindingId", bindingId); writer.WriteString("enrollmentId", enrollmentId);
        writer.WritePropertyName("installation"); JsonSerializer.Serialize(writer, request.Installation, AuthorityJson);
        writer.WritePropertyName("release"); JsonSerializer.Serialize(writer, request.Release, AuthorityJson);
        writer.WritePropertyName("newKeyCommitment"); JsonSerializer.Serialize(writer, request.NewKeyCommitment, AuthorityJson);
        writer.WriteString("authorityState", "prepared"); writer.WritePropertyName("signedGeneration");
        writer.WriteRawValue(signedStatement, skipInputValidation: false); writer.WriteEndObject(); writer.Flush();
        return output.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Serializes one complete six-branch snapshot with the shared W5 opaque writer and no optional
    /// HTTP-200 blocks.
    /// </summary>
    /// <param name="status">The already classified closed readback status.</param>
    /// <param name="ledger">The immutable authorization ledger that owns request identity and signed bytes.</param>
    /// <param name="reservation">The locked provider reservation represented in the snapshot.</param>
    /// <param name="authority">The locked recovery authority represented in the snapshot.</param>
    /// <param name="observedAtUtc">The database-clock observation instant.</param>
    /// <param name="revalidatedPreviousAuthorityState">An optional freshly revalidated previous-authority state; otherwise the frozen state is emitted.</param>
    /// <returns>The canonical readback bytes; opaque grant and signed-statement bytes are preserved without normalization.</returns>
    internal static byte[] SerializeReadback(
        string status,
        RuntimeSeatRecoveryAuthorization ledger,
        RuntimeSeatRecoveryReservation reservation,
        RuntimeSeatRecoveryAuthority authority,
        DateTime observedAtUtc,
        string? revalidatedPreviousAuthorityState = null)
    {
        var output = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        writer.WriteStartObject(); writer.WriteString("schema", "runtime-seat-recovery-current-readback-response-v1");
        writer.WriteNumber("contractVersion", 1); writer.WriteString("status", status); writer.WriteString("requestId", ledger.RequestId);
        writer.WriteString("requestDigestSha256", ledger.RequestDigestSha256); writer.WriteString("recoveryOperationRef", ledger.RecoveryOperationRef);
        writer.WriteString("reservationRef", reservation.ReservationRef); writer.WriteString("observedAtUtc", Format(observedAtUtc));
        writer.WriteStartObject("reservation"); writer.WriteString("state", reservation.State.ToLowerInvariant()); writer.WriteString("expiresAtUtc", Format(reservation.ExpiresAtUtc)); writer.WriteEndObject();
        writer.WriteStartObject("newAuthority"); writer.WriteString("authorityLineageId", authority.AuthorityLineageId); writer.WriteString("authorityGenerationId", authority.AuthorityGenerationId); writer.WriteString("state", authority.State.ToLowerInvariant()); writer.WriteBoolean("isCurrentHead", authority.IsCurrentHead); writer.WriteEndObject();
        writer.WriteStartObject("previousAuthority"); writer.WriteString("state",
            revalidatedPreviousAuthorityState ?? authority.PreviousAuthorityState.ToLowerInvariant()); writer.WriteEndObject();
        writer.WriteStartObject("scope"); writer.WriteString("provider", "softlicence");
        RuntimeSeatRecoveryContractCodec.WriteCanonicalOpaqueString(
            writer, "providerGrantRef", reservation.ProviderGrantRef);
        writer.WriteString("subjectRefDigestSha256", authority.SubjectRefDigestSha256); writer.WriteString("productId", reservation.ProductId);
        writer.WriteString("licenseId", reservation.LicenseId); writer.WriteString("seatId", reservation.LicenseSeatId);
        writer.WriteString("bindingId", authority.BindingId); writer.WriteString("enrollmentId", authority.EnrollmentId);
        writer.WriteString("installationId", authority.InstallationId); writer.WriteString("hardwareIdDigestSha256", authority.HardwareIdDigestSha256);
        writer.WriteString("releaseVersion", authority.ReleaseVersion); writer.WriteString("artifactSetDigestSha256", authority.ArtifactSetDigestSha256);
        writer.WriteString("publicKeySpkiSha256", authority.PublicKeySpkiSha256); writer.WriteString("keyThumbprint", authority.KeyThumbprint);
        writer.WriteEndObject(); writer.WriteEndObject(); writer.Flush(); return output.WrittenSpan.ToArray();
    }

    /// <summary>Derives the public owner digest from the provider-private canonical UUID bytes.</summary>
    private static string SubjectDigest(Guid ownerSubjectId)
    {
        var owner = Encoding.ASCII.GetBytes(ownerSubjectId.ToString("D"));
        var input = new byte[OwnerDomain.Length + 1 + owner.Length];
        OwnerDomain.CopyTo(input, 0); input[OwnerDomain.Length] = 0x0a; owner.CopyTo(input, OwnerDomain.Length + 1);
        var digest = Convert.ToHexStringLower(SHA256.HashData(input)); CryptographicOperations.ZeroMemory(input); return digest;
    }

    /// <summary>Formats exact six-digit UTC timestamps used by every W9 body.</summary>
    private static string Format(DateTime value) => value.ToUniversalTime().ToString(UtcFormat, CultureInfo.InvariantCulture);

    /// <summary>Formats the W10.2 proof wire with exactly seven fractional UTC digits.</summary>
    private static string FormatProof(DateTime value) =>
        value.ToUniversalTime().ToString(ProofUtcFormat, CultureInfo.InvariantCulture);
}
