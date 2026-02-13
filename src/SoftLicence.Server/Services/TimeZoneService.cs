namespace SoftLicence.Server.Services;

public class TimeZoneService
{
    private int? _userOffsetMinutes;

    public void SetOffset(int offsetMinutes)
    {
        _userOffsetMinutes = offsetMinutes;
    }

    public DateTime ToLocal(DateTime utcDateTime)
    {
        if (!_userOffsetMinutes.HasValue) 
            return utcDateTime; // Fallback to UTC if not yet detected

        // Browser offset is usually UTC - Local (e.g., -60 for UTC+1)
        // We subtract the offset to get local time
        return utcDateTime.AddMinutes(-_userOffsetMinutes.Value);
    }
}
