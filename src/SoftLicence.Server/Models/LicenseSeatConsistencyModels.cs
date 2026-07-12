namespace SoftLicence.Server.Models;

public sealed class LicenseSeatConsistencyResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int LicensesChecked { get; set; }
    public int AnomaliesDetected { get; set; }
    public int AnomaliesReturned { get; set; }
    public List<TelemetryToolCount> AnomalyCounts { get; set; } = new();
    public List<LicenseSeatConsistencyAnomaly> Anomalies { get; set; } = new();
}

public sealed class LicenseSeatConsistencyAnomaly
{
    public Guid LicenseId { get; set; }
    public string? ProductName { get; set; }
    public string? LicenseTypeSlug { get; set; }
    public string CustomerEmailRedacted { get; set; } = "";
    public string LicenseKeyRedacted { get; set; } = "";
    public string AnomalyType { get; set; } = "";
    public string? LegacyHardwareId { get; set; }
    public string? ExpectedHardwareId { get; set; }
    public DateTime? LegacyActivationDateUtc { get; set; }
    public DateTime? ExpectedActivationDateUtc { get; set; }
    public int ActiveSeatCount { get; set; }
    public int TotalSeatCount { get; set; }
}
