using System.Globalization;

namespace SoftLicence.Server.Services;

public sealed record TelemetryAnalyticsPeriod(
    int Days,
    DateTime FromUtc,
    DateTime ToUtc,
    string Mode)
{
    private const int DefaultDays = 7;
    private const int MaxDays = 30;

    public static TelemetryAnalyticsPeriod Resolve(int days, string? date, string? fromUtc, string? toUtc)
    {
        if (!string.IsNullOrWhiteSpace(date))
        {
            if (!DateOnly.TryParseExact(date.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
                throw new ArgumentException("date must use YYYY-MM-DD format.");

            var from = day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
            var to = from.AddDays(1);
            return new TelemetryAnalyticsPeriod(1, from, to, "date");
        }

        if (!string.IsNullOrWhiteSpace(fromUtc) || !string.IsNullOrWhiteSpace(toUtc))
        {
            if (string.IsNullOrWhiteSpace(fromUtc) || string.IsNullOrWhiteSpace(toUtc))
                throw new ArgumentException("fromUtc and toUtc must be provided together.");

            var from = ParseUtc(fromUtc, nameof(fromUtc));
            var to = ParseUtc(toUtc, nameof(toUtc));
            if (to <= from)
                throw new ArgumentException("toUtc must be greater than fromUtc.");

            if (to - from > TimeSpan.FromDays(MaxDays))
                throw new ArgumentException($"Explicit telemetry windows are limited to {MaxDays} days.");

            return new TelemetryAnalyticsPeriod(Math.Max(1, (int)Math.Ceiling((to - from).TotalDays)), from, to, "range");
        }

        days = Math.Clamp(days <= 0 ? DefaultDays : days, 1, MaxDays);
        var now = DateTime.UtcNow;
        return new TelemetryAnalyticsPeriod(days, now.AddDays(-days), now, "rolling");
    }

    public string CacheKey => $"{Mode}:{FromUtc:O}:{ToUtc:O}";

    private static DateTime ParseUtc(string value, string parameterName)
    {
        if (!DateTime.TryParse(value.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            throw new ArgumentException($"{parameterName} must be a valid UTC date/time.");

        return parsed.Kind == DateTimeKind.Utc ? parsed : parsed.ToUniversalTime();
    }
}
