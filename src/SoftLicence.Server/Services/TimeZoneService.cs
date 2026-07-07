namespace SoftLicence.Server.Services;

public class TimeZoneService
{
    private static readonly TimeZoneInfo ParisZone = GetParisZone();

    private static TimeZoneInfo GetParisZone()
    {
        // "Romance Standard Time" on Windows, "Europe/Paris" on Linux (Docker)
        try { return TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time"); }
        catch { return TimeZoneInfo.FindSystemTimeZoneById("Europe/Paris"); }
    }

    public DateTime ToLocal(DateTime utcDateTime)
    {
        return TimeZoneInfo.ConvertTimeFromUtc(
            DateTime.SpecifyKind(utcDateTime, DateTimeKind.Utc), ParisZone);
    }

    /// <summary>Returns today's start (midnight) in Paris timezone, as UTC.</summary>
    public static DateTime TodayStartUtc()
    {
        var parisNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, ParisZone);
        var parisMidnight = parisNow.Date;
        return TimeZoneInfo.ConvertTimeToUtc(
            DateTime.SpecifyKind(parisMidnight, DateTimeKind.Unspecified), ParisZone);
    }

    /// <summary>Converts a UTC timestamp to its Paris date (for day grouping).</summary>
    public static DateTime ToParisDate(DateTime utcTimestamp)
    {
        return TimeZoneInfo.ConvertTimeFromUtc(
            DateTime.SpecifyKind(utcTimestamp, DateTimeKind.Utc), ParisZone).Date;
    }

    /// <summary>Returns the Paris date for "now minus N days", as a Paris-local date.</summary>
    public static DateTime ParisDateDaysAgo(int days)
    {
        var parisNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, ParisZone);
        return parisNow.Date.AddDays(-days);
    }

    /// <summary>Returns the UTC range covering a Paris-local date.</summary>
    public static (DateTime StartUtc, DateTime EndUtc) ParisDateToUtcRange(DateTime parisDate)
    {
        var startLocal = DateTime.SpecifyKind(parisDate.Date, DateTimeKind.Unspecified);
        var endLocal = DateTime.SpecifyKind(parisDate.Date.AddDays(1), DateTimeKind.Unspecified);
        return (
            TimeZoneInfo.ConvertTimeToUtc(startLocal, ParisZone),
            TimeZoneInfo.ConvertTimeToUtc(endLocal, ParisZone));
    }

    // Keep for backward compat — MainLayout calls this but it's no longer used
    public void SetOffset(int offsetMinutes) { }
}
