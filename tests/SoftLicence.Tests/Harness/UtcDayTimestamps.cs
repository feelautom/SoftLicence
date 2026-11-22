namespace SoftLicence.Tests.Harness;

/// <summary>
/// TKT-004196: builds test timestamps that are guaranteed to fall inside the current UTC day.
/// </summary>
/// <remarks>
/// The daily seat-change quota (<c>SeatChangeQuota</c>) counts activations from UTC midnight to the next UTC midnight.
/// Seeding "an activation two hours ago" with <c>DateTime.UtcNow.AddHours(-2)</c> puts it on the previous day between
/// 00:00 and 02:00 UTC, so a test expecting it to count fails every night (runs #775 and #776, 22/11/2026). This
/// helper places the timestamp at a fraction of the time elapsed since that day's UTC midnight instead: it is always
/// today, never after <c>nowUtc</c>, and a larger fraction gives a later instant, so the order of seeded events is kept.
/// The only remaining window is a test that itself runs across midnight, which no anchoring can remove while the code
/// under test reads the real clock.
/// </remarks>
internal static class UtcDayTimestamps
{
    /// <summary>
    /// Returns the instant at <paramref name="fraction"/> of the time elapsed between the UTC midnight of
    /// <paramref name="nowUtc"/> and <paramref name="nowUtc"/> itself (0 gives midnight, 1 gives <paramref name="nowUtc"/>).
    /// </summary>
    /// <param name="nowUtc">The reference instant; must be of kind <see cref="DateTimeKind.Utc"/>.</param>
    /// <param name="fraction">Position inside the elapsed part of the day, from 0 to 1 inclusive.</param>
    /// <returns>A UTC instant in the same UTC day as <paramref name="nowUtc"/> and not after it.</returns>
    /// <exception cref="ArgumentException"><paramref name="nowUtc"/> is not a UTC instant.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="fraction"/> is outside [0, 1] or not a number.</exception>
    internal static DateTime Today(DateTime nowUtc, double fraction)
    {
        if (nowUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("The reference instant must be UTC.", nameof(nowUtc));
        if (double.IsNaN(fraction) || fraction < 0 || fraction > 1)
            throw new ArgumentOutOfRangeException(nameof(fraction), fraction, "The fraction must be between 0 and 1.");

        var midnight = nowUtc.Date;
        var elapsedTicks = (nowUtc - midnight).Ticks;
        return DateTime.SpecifyKind(midnight.AddTicks((long)(elapsedTicks * fraction)), DateTimeKind.Utc);
    }
}
