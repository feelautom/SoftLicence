using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Applies authenticated, idempotent key-activation settings to one exact license.</summary>
public interface ILicenseKeyActivationSettingService
{
    /// <summary>Disables key-based activation for the exact license, or exactly replays the request.</summary>
    /// <param name="command">Validated pose command with its canonical request UUID and actor.</param>
    /// <param name="cancellationToken">Cancels database work before commit.</param>
    /// <returns>The terminal response and whether it was replayed.</returns>
    /// <exception cref="DistributionOperationException">The request is invalid, conflicting, or the target license is unknown.</exception>
    Task<LicenseKeyActivationResult> DisableAsync(
        LicenseKeyActivationCommand command,
        CancellationToken cancellationToken = default);

    /// <summary>Lifts the key-activation refusal of the exact license, or exactly replays the request.</summary>
    /// <param name="command">Validated lift command with its canonical request UUID and actor.</param>
    /// <param name="cancellationToken">Cancels database work before commit.</param>
    /// <returns>The terminal response and whether it was replayed.</returns>
    /// <exception cref="DistributionOperationException">The request is invalid, conflicting, or the target license is unknown.</exception>
    Task<LicenseKeyActivationResult> LiftAsync(
        LicenseKeyActivationCommand command,
        CancellationToken cancellationToken = default);
}

/// <summary>Validated provider or administrator mutation of one license key-activation setting.</summary>
/// <param name="RequestId">Canonical request UUID owning the idempotency terminal.</param>
/// <param name="ProductId">Exact product UUID of the target license.</param>
/// <param name="LicenseId">Exact license UUID.</param>
/// <param name="Actor">Closed actor: <c>s2s</c> or <c>admin</c>.</param>
/// <param name="ClientId">Exact authenticated S2S client identifier, or <c>admin</c>.</param>
public sealed record LicenseKeyActivationCommand(
    Guid RequestId,
    Guid ProductId,
    Guid LicenseId,
    string Actor,
    string ClientId);

/// <summary>
/// Implements the per-license key-activation setting with durable idempotency. Each request UUID freezes
/// one receipt (<see cref="LicenseKeyActivationOperation"/>); replays return that receipt's terminal without
/// writing anything, so an old replay never undoes a newer decision. No seat, distribution or enrollment
/// path is touched here.
/// </summary>
public sealed class LicenseKeyActivationSettingService : ILicenseKeyActivationSettingService
{
    /// <summary>Exact closed request schema accepted from the publisher for a pose.</summary>
    public const string RequestSchema = "license-key-activation-v1";
    /// <summary>Exact closed request schema accepted from the publisher for a lift.</summary>
    public const string RequestLiftSchema = "license-key-activation-lift-v1";
    /// <summary>Exact bounded terminal response schema returned for a pose.</summary>
    public const string ResponseSchema = "license-key-activation-result-v1";
    /// <summary>Exact bounded terminal response schema returned for a lift.</summary>
    public const string ResponseLiftSchema = "license-key-activation-lift-result-v1";
    /// <summary>Terminal outcome emitted when this request disabled key-based activation.</summary>
    public const string DisabledOutcome = "disabled";
    /// <summary>Terminal outcome emitted when key-based activation was already disabled.</summary>
    public const string AlreadyDisabledOutcome = "already_disabled";
    /// <summary>Terminal outcome emitted when this request lifted the refusal.</summary>
    public const string LiftedOutcome = "lifted";
    /// <summary>Terminal outcome emitted when the refusal was already lifted or never set.</summary>
    public const string AlreadyLiftedOutcome = "already_lifted";
    /// <summary>Closed administrator actor identifier used for both actor and client columns.</summary>
    public const string AdminActor = "admin";
    /// <summary>Closed server-to-server actor identifier.</summary>
    public const string S2SActor = "s2s";
    /// <summary>Closed receipt intent of a pose request.</summary>
    public const string DisableIntent = "disable";
    /// <summary>Closed receipt intent of a lift request.</summary>
    public const string LiftIntent = "lift";

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<LicenseKeyActivationSettingService> _logger;

    /// <summary>Initializes the provider service with isolated contexts and an injectable UTC clock.</summary>
    public LicenseKeyActivationSettingService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        TimeProvider timeProvider,
        ILogger<LicenseKeyActivationSettingService> logger)
    {
        _dbFactory = dbFactory;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task<LicenseKeyActivationResult> DisableAsync(
        LicenseKeyActivationCommand command,
        CancellationToken cancellationToken = default) =>
        ApplyAsync(command, isDisable: true, cancellationToken);

    /// <inheritdoc />
    public Task<LicenseKeyActivationResult> LiftAsync(
        LicenseKeyActivationCommand command,
        CancellationToken cancellationToken = default) =>
        ApplyAsync(command, isDisable: false, cancellationToken);

    /// <summary>
    /// Applies one pose or lift in a single transaction serialized with activations: an already-recorded request
    /// UUID is answered from its frozen receipt only; otherwise the setting is created or updated, one history
    /// entry is written when the state changes, and one receipt is frozen for every terminal outcome.
    /// </summary>
    /// <param name="command">Validated command carrying the request UUID, product, license and actor.</param>
    /// <param name="isDisable"><see langword="true"/> for a pose, <see langword="false"/> for a lift.</param>
    /// <param name="cancellationToken">Cancels database work before commit.</param>
    /// <returns>The terminal response, flagged idempotent when it comes from a stored receipt.</returns>
    /// <exception cref="DistributionOperationException">
    /// <c>invalid_request</c> (400), <c>target_not_found</c> (404) for an unknown product/license pair, or
    /// <c>idempotency_conflict</c> (409) when the request UUID was recorded with another intent, product or license.
    /// </exception>
    private async Task<LicenseKeyActivationResult> ApplyAsync(
        LicenseKeyActivationCommand command,
        bool isDisable,
        CancellationToken cancellationToken)
    {
        Validate(command);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db, cancellationToken);

        var requestKey = command.RequestId.ToString("D");
        var responseSchema = isDisable ? ResponseSchema : ResponseLiftSchema;
        if (db.Database.IsNpgsql())
        {
            // The authority barriers already serialize this mutation with activations and deactivations.
            // The exact request lock serializes receipt classification of concurrent same-request replays.
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({requestKey}, 2475))",
                cancellationToken);
        }

        // Replays are answered from the frozen receipt only: an old request never mutates the setting
        // again, so it cannot undo a more recent pose or lift decided by another request.
        var intent = isDisable ? DisableIntent : LiftIntent;
        var stored = await db.LicenseKeyActivationOperations.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.RequestId == command.RequestId, cancellationToken);
        if (stored != null)
        {
            if (stored.ProductId != command.ProductId
                || stored.LicenseId != command.LicenseId
                || !string.Equals(stored.Intent, intent, StringComparison.Ordinal))
            {
                throw new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict);
            }
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new LicenseKeyActivationResult(
                new LicenseKeyActivationResponse(responseSchema, requestKey, stored.Outcome),
                true);
        }

        var setting = await db.LicenseKeyActivationSettings
            .SingleOrDefaultAsync(candidate => candidate.LicenseId == command.LicenseId, cancellationToken);
        var now = db.Database.IsRelational()
            ? (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime
            : _timeProvider.GetUtcNow().UtcDateTime;
        var license = await db.Licenses
            .SingleOrDefaultAsync(candidate =>
                candidate.Id == command.LicenseId && candidate.ProductId == command.ProductId,
                cancellationToken);
        if (license == null)
            throw new DistributionOperationException("target_not_found", StatusCodes.Status404NotFound);

        string terminalOutcome;
        if (isDisable)
        {
            if (setting is { Disabled: true })
            {
                terminalOutcome = AlreadyDisabledOutcome;
            }
            else
            {
                if (setting == null)
                {
                    setting = new LicenseKeyActivationSetting
                    {
                        Id = Guid.NewGuid(),
                        ProductId = command.ProductId,
                        LicenseId = command.LicenseId,
                        CreatedAtUtc = now
                    };
                    db.LicenseKeyActivationSettings.Add(setting);
                }
                setting.Disabled = true;
                setting.DisabledAtUtc = now;
                setting.LiftedAtUtc = null;
                setting.DisabledByRequestId = command.RequestId;
                setting.LiftedByRequestId = null;
                setting.DisabledByActor = command.Actor;
                setting.LiftedByActor = null;
                setting.DisabledByClientId = command.ClientId;
                setting.LiftedByClientId = null;
                setting.UpdatedAtUtc = now;
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = command.LicenseId,
                    Timestamp = now,
                    Action = HistoryActions.KeyActivationDisabled,
                    Details = $"Key activation disabled (request {command.RequestId:D})",
                    PerformedBy = DescribePerformer(command)
                });
                terminalOutcome = DisabledOutcome;
            }
        }
        else
        {
            if (setting == null || !setting.Disabled)
            {
                terminalOutcome = AlreadyLiftedOutcome;
            }
            else
            {
                setting.Disabled = false;
                setting.LiftedAtUtc = now;
                setting.LiftedByRequestId = command.RequestId;
                setting.LiftedByActor = command.Actor;
                setting.LiftedByClientId = command.ClientId;
                setting.UpdatedAtUtc = now;
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = command.LicenseId,
                    Timestamp = now,
                    Action = HistoryActions.KeyActivationLifted,
                    Details = $"Key activation lifted (request {command.RequestId:D})",
                    PerformedBy = DescribePerformer(command)
                });
                terminalOutcome = LiftedOutcome;
            }
        }

        // Every first sight of a request, already_* terminals included, freezes one receipt.
        db.LicenseKeyActivationOperations.Add(new LicenseKeyActivationOperation
        {
            RequestId = command.RequestId,
            ProductId = command.ProductId,
            LicenseId = command.LicenseId,
            Intent = intent,
            Outcome = terminalOutcome,
            Actor = command.Actor,
            ClientId = command.ClientId,
            CreatedAtUtc = now
        });

        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);

        _logger.LogInformation(
            "Key activation setting {Outcome} for correlation {RequestId} and license {LicenseId}.",
            terminalOutcome,
            command.RequestId,
            command.LicenseId);
        return new LicenseKeyActivationResult(
            new LicenseKeyActivationResponse(responseSchema, requestKey, terminalOutcome),
            false);
    }

    private static string DescribePerformer(LicenseKeyActivationCommand command) =>
        string.Equals(command.Actor, AdminActor, StringComparison.Ordinal)
            ? AdminActor
            : $"S2S:{command.ClientId}";

    private static void Validate(LicenseKeyActivationCommand command)
    {
        if (command.RequestId == Guid.Empty
            || command.ProductId == Guid.Empty
            || command.LicenseId == Guid.Empty
            || !(string.Equals(command.Actor, S2SActor, StringComparison.Ordinal)
                || string.Equals(command.Actor, AdminActor, StringComparison.Ordinal))
            || command.ClientId is not { Length: >= 3 and <= 64 }
            || command.ClientId.Any(character =>
                character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-')))
        {
            throw new DistributionOperationException("invalid_request", StatusCodes.Status400BadRequest);
        }
    }
}
