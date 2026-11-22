using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Application side of the commercial-assignment open/closed switch (TKT-001277 lot 2d, product decision of
/// 29/09/2026). Every guarded control keeps its original blocking code; it asks <see cref="IsOpenAsync"/> first and,
/// when the switch is open, records "would have blocked" with <see cref="Record"/> and lets the operation through.
/// Since TKT-001428 the switch is closed unless <c>open</c> is configured explicitly: the observation period ended
/// and the controls block. The open position is kept only as a rollback lever until a follow-up ticket removes it.
/// </summary>
/// <remarks>
/// String contract: the environment value is trimmed and compared case-insensitively against <c>open</c> and
/// <c>closed</c> only (ASCII, invariant); the persisted value is always the lowercase canonical constant, which the
/// database check constraint also enforces. A missing, blank or invalid value means closed (fail closed).
/// </remarks>
internal static class AssignmentEnforcement
{
    /// <summary>Environment variable that sets the switch at application startup.</summary>
    internal const string EnvironmentVariable = "SOFTLICENCE_ASSIGNMENT_ENFORCEMENT";

    /// <summary>Control name recorded for the seat-release checks.</summary>
    internal const string SeatReleaseControl = "seat_release";

    /// <summary>
    /// Reads the switch from the database. Only a stored <c>open</c> opens it: a missing row or any other value means
    /// closed, so a lost or damaged setting can never silently disable the controls (TKT-001428). Database failures
    /// propagate like any other read of the caller's transaction.
    /// </summary>
    /// <remarks>
    /// The trigger's SQL helper <c>assignment_enforcement_is_open()</c> still treats a missing row as open. The row
    /// always exists in production (seeded by the migration, rewritten at startup, and the application role cannot
    /// delete it); aligning the SQL helper is left to the removal of the open mode (TKT-004056).
    /// </remarks>
    /// <param name="db">Context of the caller's transaction.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns><see langword="true"/> when controls must record instead of blocking.</returns>
    internal static async Task<bool> IsOpenAsync(LicenseDbContext db, CancellationToken cancellationToken)
    {
        var mode = await db.AssignmentEnforcementSettings.AsNoTracking()
            .Where(setting => setting.Id == 1)
            .Select(setting => setting.Mode)
            .SingleOrDefaultAsync(cancellationToken);
        return string.Equals(mode, AssignmentEnforcementSetting.Open, StringComparison.Ordinal);
    }

    /// <summary>
    /// Adds a "would have blocked" event to the caller's context; it is persisted with the caller's next save, so it
    /// commits together with the operation it let through.
    /// </summary>
    /// <param name="db">Context of the caller's transaction.</param>
    /// <param name="control">Control name, for example <see cref="SeatReleaseControl"/>.</param>
    /// <param name="reason">Exact reason the original code blocks with.</param>
    /// <param name="action">What is done instead of blocking.</param>
    /// <param name="licenseId">Licence concerned, when known.</param>
    /// <param name="seatId">Seat concerned, when known.</param>
    /// <param name="enrollmentId">Runtime enrollment concerned, when known.</param>
    /// <param name="detail">Bounded diagnostic detail without secrets.</param>
    internal static void Record(
        LicenseDbContext db, string control, string reason, string action,
        Guid? licenseId, Guid? seatId, Guid? enrollmentId, string detail)
    {
        db.AssignmentEnforcementEvents.Add(new AssignmentEnforcementEvent
        {
            Source = "application",
            Control = control,
            Reason = reason,
            Action = action,
            LicenseId = licenseId,
            LicenseSeatId = seatId,
            EnrollmentId = enrollmentId,
            Detail = detail.Length <= 512 ? detail : detail[..512],
            ObservedAtUtc = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Parses the environment value into the canonical persisted mode. Closed is the default since TKT-001428: only an
    /// explicit <c>open</c> (trimmed, ASCII case-insensitive) opens the switch, as a deliberate operator rollback.
    /// </summary>
    /// <param name="value">Raw value; <see langword="null"/> or blank means closed.</param>
    /// <param name="mode">The canonical mode (<c>closed</c> when the value is invalid, so a typo never opens it).</param>
    /// <returns><see langword="false"/> when the value is neither empty, <c>open</c> nor <c>closed</c>.</returns>
    internal static bool TryParseMode(string? value, out string mode)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        if (string.Equals(trimmed, AssignmentEnforcementSetting.Open, StringComparison.OrdinalIgnoreCase))
        {
            mode = AssignmentEnforcementSetting.Open;
            return true;
        }
        mode = AssignmentEnforcementSetting.Closed;
        return trimmed.Length == 0
            || string.Equals(trimmed, AssignmentEnforcementSetting.Closed, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Writes the switch from <c>SOFTLICENCE_ASSIGNMENT_ENFORCEMENT</c> into the database at startup, so the PostgreSQL
/// trigger and the application read the same value. Without the variable the switch is written closed (TKT-001428).
/// A failure is logged and never stops the server; the database then keeps its previous value.
/// </summary>
public sealed class AssignmentEnforcementModeSynchronizer : IHostedService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AssignmentEnforcementModeSynchronizer> _logger;

    /// <summary>Creates the synchronizer.</summary>
    public AssignmentEnforcementModeSynchronizer(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IConfiguration configuration,
        ILogger<AssignmentEnforcementModeSynchronizer> logger)
    {
        _dbFactory = dbFactory;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Writes the configured mode once at host startup: <c>open</c> only when the variable says so explicitly,
    /// otherwise <c>closed</c> (absent, blank or invalid value; an invalid value is also logged as an error). The
    /// row is created when missing and stamped <c>startup:env</c>. A database failure is logged and swallowed so the
    /// server still starts; the database then keeps its previous mode, which is why an operator must read the row
    /// back after changing the variable. Cancellation propagates.
    /// </summary>
    /// <param name="cancellationToken">Host startup cancellation.</param>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var raw = _configuration[AssignmentEnforcement.EnvironmentVariable];
        if (!AssignmentEnforcement.TryParseMode(raw, out var mode))
        {
            _logger.LogError(
                "ASSIGNMENT_ENFORCEMENT invalid value for {Variable}; expected 'open' or 'closed'. The switch is closed.",
                AssignmentEnforcement.EnvironmentVariable);
        }

        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var setting = await db.AssignmentEnforcementSettings.SingleOrDefaultAsync(row => row.Id == 1, cancellationToken);
            if (setting is null)
            {
                setting = new AssignmentEnforcementSetting { Id = 1 };
                db.AssignmentEnforcementSettings.Add(setting);
            }
            setting.Mode = mode;
            setting.UpdatedAtUtc = DateTime.UtcNow;
            setting.UpdatedBy = "startup:env";
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogError(exception, "ASSIGNMENT_ENFORCEMENT could not write the switch; the database keeps its current value.");
            return;
        }

        if (mode == AssignmentEnforcementSetting.Open)
            _logger.LogWarning("ASSIGNMENT_ENFORCEMENT switch OPEN: assignment controls record instead of blocking.");
        else
            _logger.LogInformation("ASSIGNMENT_ENFORCEMENT switch CLOSED: assignment controls block.");
    }

    /// <summary>Nothing to stop.</summary>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// Sends one grouped admin alert for new "would have blocked" events, at most every configured interval
/// (<c>AssignmentEnforcement:AlertIntervalMinutes</c>, 15 by default), and only when there is something new.
/// </summary>
public sealed class AssignmentEnforcementAlertWorker : BackgroundService
{
    private const int BatchSize = 1000;
    private const int ExampleCount = 5;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly NotificationService _notifier;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AssignmentEnforcementAlertWorker> _logger;

    /// <summary>Creates the worker.</summary>
    public AssignmentEnforcementAlertWorker(
        IDbContextFactory<LicenseDbContext> dbFactory,
        NotificationService notifier,
        IConfiguration configuration,
        ILogger<AssignmentEnforcementAlertWorker> logger)
    {
        _dbFactory = dbFactory;
        _notifier = notifier;
        _configuration = configuration;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Clamp(
            _configuration.GetValue("AssignmentEnforcement:AlertIntervalMinutes", 15), 1, 1440));
        // The first cycle waits one full interval: nothing is pending at startup, and no background database access
        // competes with the host's first requests.
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(interval, stoppingToken);
            try
            {
                await SendPendingAsync(stoppingToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                _logger.LogError(exception, "ASSIGNMENT_ENFORCEMENT alert cycle failed.");
            }
        }
    }

    /// <summary>Groups unalerted events into one message, sends it and marks them alerted.</summary>
    /// <param name="cancellationToken">Stops the cycle.</param>
    /// <returns>The number of events acknowledged; zero when nothing was pending or the alert was not delivered.</returns>
    internal async Task<int> SendPendingAsync(CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var pending = await db.AssignmentEnforcementEvents
            .Where(row => row.AlertedAtUtc == null)
            .OrderBy(row => row.Id)
            .Take(BatchSize)
            .ToListAsync(cancellationToken);
        if (pending.Count == 0)
            return 0;

        var lines = new List<string>
        {
            $"{pending.Count} blocage(s) évité(s) depuis la dernière alerte (interrupteur ouvert).",
            string.Empty,
            "Par type :"
        };
        lines.AddRange(pending
            .GroupBy(row => (row.Source, row.Control, row.Reason, row.Action))
            .OrderByDescending(group => group.Count())
            .Select(group => $"- {group.Count()} × {group.Key.Control} / {group.Key.Reason} → {group.Key.Action} ({group.Key.Source})"));
        lines.Add(string.Empty);
        lines.Add("Exemples :");
        lines.AddRange(pending.Take(ExampleCount).Select(row =>
            $"- {row.ObservedAtUtc:yyyy-MM-dd HH:mm:ss} UTC, cas {row.CaseNumber?.ToString() ?? "-"}, licence {row.LicenseId?.ToString() ?? "-"}, poste {row.LicenseSeatId?.ToString() ?? "-"}, installation {row.EnrollmentId?.ToString() ?? "-"}"));
        if (pending.Count == BatchSize)
            lines.Add("(lot plein : d'autres événements suivront au prochain cycle)");

        // The events are acknowledged only after at least one configured destination accepted the alert, so a
        // webhook outage or a missing configuration keeps them pending for the next cycle (TKT-001277 review I4).
        var delivery = await _notifier.NotifyAsync(
            NotificationService.Triggers.SecurityAssignmentEnforcement,
            $"Contrôles de droits : {pending.Count} blocage(s) évité(s)",
            string.Join('\n', lines));
        if (delivery.Delivered < 1)
        {
            _logger.LogWarning(
                "ASSIGNMENT_ENFORCEMENT alert not delivered ({Configured} destination(s), {Failed} failure(s)); {Count} event(s) stay pending.",
                delivery.Configured, delivery.Failed, pending.Count);
            return 0;
        }

        var now = DateTime.UtcNow;
        foreach (var row in pending)
            row.AlertedAtUtc = now;
        await db.SaveChangesAsync(cancellationToken);
        return pending.Count;
    }
}
