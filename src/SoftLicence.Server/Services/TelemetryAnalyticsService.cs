using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Text.Json;

namespace SoftLicence.Server.Services;

public class TelemetryAnalyticsService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public TelemetryAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<TelemetryAnalyticsData> GetAnalyticsAsync(Guid? productId, int days)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var since = DateTime.UtcNow.AddDays(-days);
        var data = new TelemetryAnalyticsData();

        // Base query
        var query = db.TelemetryRecords.Where(r => r.Timestamp >= since);
        if (productId.HasValue)
            query = query.Where(r => r.ProductId == productId.Value);

        // Charger les records en mémoire pour agrégation
        var records = await query
            .Select(r => new
            {
                r.Id,
                r.Timestamp,
                r.Type,
                r.HardwareId,
                r.Version,
                r.EventName,
                ErrorType = r.ErrorData != null ? r.ErrorData.ErrorType : null,
                ErrorMessage = r.ErrorData != null ? r.ErrorData.Message : null,
                DiagnosticScore = r.DiagnosticData != null ? (int?)r.DiagnosticData.Score : null
            })
            .ToListAsync();

        // KPIs
        data.TotalRecords = records.Count;
        data.EventCount = records.Count(r => r.Type == TelemetryType.Event);
        data.DiagnosticCount = records.Count(r => r.Type == TelemetryType.Diagnostic);
        data.ErrorCount = records.Count(r => r.Type == TelemetryType.Error);
        data.UniqueDevices = records.Select(r => r.HardwareId).Distinct().Count();
        data.UniqueVersions = records.Where(r => r.Version != null).Select(r => r.Version).Distinct().Count();

        var diagScores = records.Where(r => r.DiagnosticScore.HasValue).Select(r => r.DiagnosticScore!.Value).ToList();
        data.AvgDiagnosticScore = diagScores.Count > 0 ? (int)Math.Round(diagScores.Average()) : 0;

        // Volume quotidien (stacked) — groupé par jour Europe/Paris
        for (int i = days - 1; i >= 0; i--)
        {
            var parisDate = TimeZoneService.ParisDateDaysAgo(i);
            var dayRecords = records.Where(r => TimeZoneService.ToParisDate(r.Timestamp) == parisDate).ToList();
            data.DailyVolume.Add(new DailyVolume
            {
                Date = parisDate,
                Events = dayRecords.Count(r => r.Type == TelemetryType.Event),
                Diagnostics = dayRecords.Count(r => r.Type == TelemetryType.Diagnostic),
                Errors = dayRecords.Count(r => r.Type == TelemetryType.Error)
            });
        }

        // Appareils uniques par jour — groupé par jour Europe/Paris
        for (int i = days - 1; i >= 0; i--)
        {
            var parisDate = TimeZoneService.ParisDateDaysAgo(i);
            var count = records.Where(r => TimeZoneService.ToParisDate(r.Timestamp) == parisDate).Select(r => r.HardwareId).Distinct().Count();
            data.DailyDevices.Add(new DailyDevices { Date = parisDate, Count = count });
        }

        // Distribution versions (top 8)
        data.VersionDistribution = records
            .Where(r => !string.IsNullOrEmpty(r.Version))
            .GroupBy(r => r.Version!)
            .Select(g => new VersionCount { Version = g.Key, Count = g.Count() })
            .OrderByDescending(v => v.Count)
            .Take(8)
            .ToList();

        // Top events (top 10)
        data.TopEvents = records
            .Where(r => r.Type == TelemetryType.Event)
            .GroupBy(r => r.EventName)
            .Select(g => new EventCount { Name = g.Key, Count = g.Count() })
            .OrderByDescending(e => e.Count)
            .Take(10)
            .ToList();

        // Top erreurs (top 10)
        data.TopErrors = records
            .Where(r => r.Type == TelemetryType.Error && r.ErrorType != null)
            .GroupBy(r => new { r.ErrorType, r.ErrorMessage })
            .Select(g => new ErrorSummary
            {
                ErrorType = g.Key.ErrorType ?? "Unknown",
                Message = g.Key.ErrorMessage ?? "",
                Count = g.Count()
            })
            .OrderByDescending(e => e.Count)
            .Take(10)
            .ToList();

        // Distribution scores diagnostic (5 buckets)
        data.DiagnosticScoreBuckets = new List<ScoreBucket>
        {
            new() { Label = "0-20", Count = diagScores.Count(s => s <= 20) },
            new() { Label = "21-40", Count = diagScores.Count(s => s > 20 && s <= 40) },
            new() { Label = "41-60", Count = diagScores.Count(s => s > 40 && s <= 60) },
            new() { Label = "61-80", Count = diagScores.Count(s => s > 60 && s <= 80) },
            new() { Label = "81-100", Count = diagScores.Count(s => s > 80) }
        };

        // Alertes de cohérence
        data.CoherenceAlerts = await BuildCoherenceAlertsAsync(db, productId, since);
        data.AlertCount = data.CoherenceAlerts.Count;

        return data;
    }

    private async Task<List<CoherenceAlert>> BuildCoherenceAlertsAsync(LicenseDbContext db, Guid? productId, DateTime since)
    {
        var alerts = new List<CoherenceAlert>();

        // Charger les licences actives avec HardwareId et CustomParams
        var licensesQuery = db.Licenses
            .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
            .Where(l => l.IsActive && l.HardwareId != null);

        if (productId.HasValue)
            licensesQuery = licensesQuery.Where(l => l.ProductId == productId.Value);

        var licenses = await licensesQuery
            .Where(l => l.Type != null && l.Type.CustomParams.Any())
            .Select(l => new
            {
                l.HardwareId,
                l.CustomerName,
                l.LicenseKey,
                l.ProductId,
                CustomParams = l.Type!.CustomParams.Select(p => new { p.Key, p.Value }).ToList()
            })
            .ToListAsync();

        if (licenses.Count == 0) return alerts;

        // Récupérer le dernier événement télémétrie par HardwareId
        var hwIds = licenses.Select(l => l.HardwareId!).Distinct().ToList();

        var latestEvents = await db.TelemetryRecords
            .Where(r => hwIds.Contains(r.HardwareId) && r.Type == TelemetryType.Event && r.Timestamp >= since)
            .Include(r => r.EventData)
            .GroupBy(r => r.HardwareId)
            .Select(g => g.OrderByDescending(r => r.Timestamp).First())
            .ToListAsync();

        var eventsByHw = latestEvents.ToDictionary(e => e.HardwareId, e => e);

        foreach (var lic in licenses)
        {
            if (lic.HardwareId == null || !eventsByHw.TryGetValue(lic.HardwareId, out var telemetry))
                continue;

            if (telemetry.EventData?.PropertiesJson == null)
                continue;

            Dictionary<string, JsonElement>? props;
            try
            {
                props = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(telemetry.EventData.PropertiesJson);
            }
            catch
            {
                continue;
            }

            if (props == null) continue;

            foreach (var param in lic.CustomParams)
            {
                if (!props.TryGetValue(param.Key, out var actualElement))
                    continue;

                var actualValue = actualElement.ToString();
                if (!string.Equals(actualValue, param.Value, StringComparison.OrdinalIgnoreCase))
                {
                    alerts.Add(new CoherenceAlert
                    {
                        HardwareId = lic.HardwareId,
                        Customer = lic.CustomerName,
                        LicenseKey = lic.LicenseKey,
                        ParamKey = param.Key,
                        ExpectedValue = param.Value,
                        ActualValue = actualValue,
                        DetectedAt = telemetry.Timestamp
                    });
                }
            }
        }

        return alerts;
    }
}

// DTOs

public class TelemetryAnalyticsData
{
    // KPIs
    public int TotalRecords { get; set; }
    public int EventCount { get; set; }
    public int DiagnosticCount { get; set; }
    public int ErrorCount { get; set; }
    public int UniqueDevices { get; set; }
    public int UniqueVersions { get; set; }
    public int AvgDiagnosticScore { get; set; }
    public int AlertCount { get; set; }

    // Charts
    public List<DailyVolume> DailyVolume { get; set; } = new();
    public List<DailyDevices> DailyDevices { get; set; } = new();
    public List<VersionCount> VersionDistribution { get; set; } = new();
    public List<EventCount> TopEvents { get; set; } = new();
    public List<ErrorSummary> TopErrors { get; set; } = new();
    public List<ScoreBucket> DiagnosticScoreBuckets { get; set; } = new();
    public List<CoherenceAlert> CoherenceAlerts { get; set; } = new();
}

public class DailyVolume
{
    public DateTime Date { get; set; }
    public int Events { get; set; }
    public int Diagnostics { get; set; }
    public int Errors { get; set; }
    public int Total => Events + Diagnostics + Errors;
}

public class DailyDevices
{
    public DateTime Date { get; set; }
    public int Count { get; set; }
}

public class VersionCount
{
    public string Version { get; set; } = "";
    public int Count { get; set; }
}

public class EventCount
{
    public string Name { get; set; } = "";
    public int Count { get; set; }
}

public class ErrorSummary
{
    public string ErrorType { get; set; } = "";
    public string Message { get; set; } = "";
    public int Count { get; set; }
}

public class ScoreBucket
{
    public string Label { get; set; } = "";
    public int Count { get; set; }
}

public class CoherenceAlert
{
    public string HardwareId { get; set; } = "";
    public string Customer { get; set; } = "";
    public string LicenseKey { get; set; } = "";
    public string ParamKey { get; set; } = "";
    public string ExpectedValue { get; set; } = "";
    public string ActualValue { get; set; } = "";
    public DateTime DetectedAt { get; set; }
}
