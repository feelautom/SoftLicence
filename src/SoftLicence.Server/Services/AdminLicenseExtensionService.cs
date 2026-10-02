using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Applies confirmed administrative durations atomically without changing billing receipts or revocation.</summary>
public sealed class AdminLicenseExtensionService(IDbContextFactory<LicenseDbContext> factory, TimeProvider clock)
{
    /// <summary>Maximum administrative duration, in exact 86,400-second UTC days.</summary>
    public const int MaximumDays = 3650;
    /// <summary>Versioned audit discriminator; the history primary key is the durable operation identity.</summary>
    public const string HistoryAction = "ADMIN_EXTENSION_V1";

    /// <summary>Frozen confirmation identity. Reusing it with different inputs is never a new grant.</summary>
    public sealed record Command(Guid OperationId, Guid LicenseId, Guid ExpectedAuthorityVersion, int Days);
    /// <summary>Explicit business outcome; unexpected infrastructure errors propagate to the caller for logging.</summary>
    public sealed record Result(string Code, DateTime? ExpirationUtc = null, bool Replayed = false);
    /// <summary>Immutable audit evidence, serialized inside the existing licence history row.</summary>
    public sealed record Receipt(int Version, Guid ExpectedAuthorityVersion, int Days, string ActorId,
        DateTime ConfirmedAtUtc, DateTime OldExpirationUtc, DateTime NewExpirationUtc);

    /// <summary>Accepts only one to four ASCII digits representing 1..3650; signs, whitespace and fractions are invalid.</summary>
    public static bool TryParseDays(string? text, out int days)
    {
        days = 0;
        return text is { Length: > 0 and <= 4 } && text.All(c => c is >= '0' and <= '9')
            && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out days)
            && days is >= 1 and <= MaximumDays;
    }

    /// <summary>
    /// Adds exact UTC days after the later of current expiry and confirmation, preserving all remaining rights.
    /// Returns null for invalid durations or an unrepresentable date; shared by preview and locked persistence.
    /// </summary>
    public static DateTime? CalculateExpirationUtc(DateTime currentExpiry, DateTime confirmedAt, int days)
    {
        if (days is < 1 or > MaximumDays) return null;
        var start = currentExpiry > confirmedAt ? currentExpiry : confirmedAt;
        return start > DateTime.MaxValue.AddDays(-days) ? null : start.AddDays(days);
    }

    /// <summary>
    /// Rechecks the existing admin licence permission, serializes with paid-period writers, and commits expiry,
    /// pass horizon and nominative evidence together. Exact retries return the frozen result before checking
    /// current authority. Changed authority requires a fresh preview; revoked and deferred licences stay untouched.
    /// </summary>
    public async Task<Result> ConfirmAsync(Command command, ClaimsPrincipal actor, CancellationToken cancellationToken = default)
    {
        var actorId = actor.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? actor.Identity?.Name;
        if (actor.Identity?.IsAuthenticated != true || string.IsNullOrWhiteSpace(actorId)
            || !(actor.IsInRole("CHANGE_ME_RANDOM_SECRET") || (actor.FindFirst("Permissions")?.Value.Split(',')
                .Any(p => p is "licenses.view" or "all") ?? false))) return new("Unauthorized");
        if (command.OperationId == Guid.Empty || command.LicenseId == Guid.Empty
            || command.ExpectedAuthorityVersion == Guid.Empty || command.Days is < 1 or > MaximumDays)
            return new("InvalidDays");

        // Capture the server confirmation instant once, before waiting on database locks. Millisecond
        // precision round-trips through PostgreSQL and the Website without lengthening a replay.
        var instant = clock.GetUtcNow().UtcDateTime;
        var confirmedAt = new DateTime(instant.Ticks - instant.Ticks % TimeSpan.TicksPerMillisecond, DateTimeKind.Utc);
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql()) throw new InvalidOperationException("Administrative extensions require PostgreSQL.");
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms'; SELECT pg_advisory_xact_lock(999831, 1);", cancellationToken);

        var previous = await db.LicenseHistories.AsNoTracking().SingleOrDefaultAsync(h => h.Id == command.OperationId, cancellationToken);
        if (previous is not null)
        {
            if (previous.LicenseId != command.LicenseId || previous.Action != HistoryAction || previous.Details is null)
                return new("Conflict");
            var receipt = JsonSerializer.Deserialize<Receipt>(previous.Details);
            if (receipt is null || receipt.Version != 1 || receipt.Days != command.Days
                || receipt.ExpectedAuthorityVersion != command.ExpectedAuthorityVersion
                || !string.Equals(receipt.ActorId, actorId, StringComparison.Ordinal)) return new("Conflict");
            return new("Applied", receipt.NewExpirationUtc, true);
        }

        var pass = await db.PersonalDayPasses.FromSqlInterpolated($"SELECT * FROM public.\"PersonalDayPasses\" WHERE \"LicenseId\" = {command.LicenseId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var license = await db.Licenses.FromSqlInterpolated($"SELECT * FROM public.\"Licenses\" WHERE \"Id\" = {command.LicenseId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (license is null) return new("NotFound");
        if (license.AuthorityVersion != command.ExpectedAuthorityVersion) return new("Conflict");
        if (!license.IsActive || license.RevokedAt.HasValue || !license.ExpirationDate.HasValue) return new("Ineligible");
        if (pass is not null && pass.PaidThroughUtc != license.ExpirationDate.Value) return new("InconsistentPass");
        // Use the fresh expiry under the authority lock, never a browser-provided base date.
        var calculated = CalculateExpirationUtc(license.ExpirationDate.Value, confirmedAt, command.Days);
        if (calculated is null) return new("ExpirationOutOfRange");
        var target = calculated.Value;

        var evidence = new Receipt(1, command.ExpectedAuthorityVersion, command.Days, actorId, confirmedAt,
            license.ExpirationDate.Value, target);
        license.ExpirationDate = target;
        if (pass is not null) pass.PaidThroughUtc = target;
        db.LicenseHistories.Add(new LicenseHistory
        {
            Id = command.OperationId, LicenseId = license.Id, Timestamp = confirmedAt, Action = HistoryAction,
            PerformedBy = actor.Identity?.Name ?? actorId, Details = JsonSerializer.Serialize(evidence)
        });
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new("Applied", target);
    }
}
