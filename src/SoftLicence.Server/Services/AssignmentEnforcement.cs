using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Application side of the commercial-assignment open/closed switch (TKT-001277 lot 2d, decided by Franck on
/// 29/09/2026). Every guarded control keeps its original blocking code; it asks <see cref="IsOpenAsync"/> first and,
/// when the switch is open, records "would have blocked" with <see cref="Record"/> and lets the operation through.
/// </summary>
/// <remarks>
/// String contract: the environment value is trimmed and compared case-insensitively against <c>open</c> and
/// <c>closed</c> only (ASCII, invariant); the persisted value is always the lowercase canonical constant, which the
/// database check constraint also enforces. Any other value is refused and the switch stays open.
/// </remarks>
internal static class AssignmentEnforcement
{
    /// <summary>Environment variable that sets the switch at application startup.</summary>
    internal const string EnvironmentVariable = "SOFTLICENCE_ASSIGNMENT_ENFORCEMENT";

    /// <summary>Control name recorded for the seat-release checks.</summary>
    internal const string SeatReleaseControl = "seat_release";

    // LEGACY-EXPIRY(TKT-001428, 2026-11-15): a missing row means open while the switch is observed. By 15/11/2026 production must run
    // closed and this default, TryParseMode's default and the startup default must become closed.
    /// <summary>
    /// Reads the switch from the database. A missing row means open, the decision in force; database failures
    /// propagate like any other read of the caller's transaction.
    /// </summary>
    /// <param name="db">Context of the caller's transaction.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns><see langword="true"/> when controls must record instead of blocking.</returns>
    internal static async Task<bool> IsOpenAsync(LicenseDbContext db, CancellationToken cancellationToken)
    {
        var mode = await db.AssignmentEnforcementSettings.AsNoTracking()
            .Where(setting => setting.Id == 1)
            .Select(setting => setting.Mode)
            .SingleOrDefaultAsync(cancellationToken);
        return !string.Equals(mode, AssignmentEnforcementSetting.Closed, StringComparison.Ordinal);
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

    // LEGACY-EXPIRY(TKT-001428, 2026-11-15): empty or invalid values default to open; by 15/11/2026 the default must become closed.
    /// <summary>Parses the environment value into the canonical persisted mode.</summary>
    /// <param name="value">Raw value; <see langword="null"/> or blank means open.</param>
    /// <param name="mode">The canonical mode (<c>open</c> when the value is invalid).</param>
    /// <returns><see langword="false"/> when the value is neither empty, <c>open</c> nor <c>closed</c>.</returns>
    internal static bool TryParseMode(string? value, out string mode)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        if (trimmed.Length == 0 || string.Equals(trimmed, AssignmentEnforcementSetting.Open, StringComparison.OrdinalIgnoreCase))
        {
            mode = AssignmentEnforcementSetting.Open;
            return true;
        }
        if (string.Equals(trimmed, AssignmentEnforcementSetting.Closed, StringComparison.OrdinalIgnoreCase))
        {
            mode = AssignmentEnforcementSetting.Closed;
            return true;
        }
        mode = AssignmentEnforcementSetting.Open;
        return false;
    }
}

/// <summary>
/// Writes the switch from <c>SOFTLICENCE_ASSIGNMENT_ENFORCEMENT</c> into the database at startup, so the PostgreSQL
/// trigger and the application read the same value. A failure is logged and never stops the server.
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

    /// <summary>Applies the configured mode once.</summary>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var raw = _configuration[AssignmentEnforcement.EnvironmentVariable];
        if (!AssignmentEnforcement.TryParseMode(raw, out var mode))
        {
            _logger.LogError(
                "ASSIGNMENT_ENFORCEMENT invalid value for {Variable}; expected 'open' or 'closed'. The switch stays open.",
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
