using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public class PiracyDetectionService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<PiracyDetectionService> _logger;
    private readonly NotificationService _notifier;
    private readonly SecurityService _security;

    // Events that do NOT indicate actual feature usage
    private static readonly string[] NonFeaturePrefixes = ["Startup_", "Update_"];
    private static readonly HashSet<string> NonFeatureEvents = [
        "API_AuthFailed", "API_Error", "API_LicenseRequired", "API_FeatureNotAvailable",
        "CertPinningFailed"
    ];

    public PiracyDetectionService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<PiracyDetectionService> logger,
        NotificationService notifier,
        SecurityService security)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _notifier = notifier;
        _security = security;
    }

    private static bool IsFeatureEvent(string eventName)
    {
        if (NonFeatureEvents.Contains(eventName)) return false;
        foreach (var prefix in NonFeaturePrefixes)
            if (eventName.StartsWith(prefix, StringComparison.Ordinal)) return false;
        return true;
    }

    /// <summary>
    /// Scans telemetry for a product and upserts PiracySuspect records.
    /// Returns the number of NEW suspects found.
    /// </summary>
    public async Task<int> RunScanAsync(Guid productId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();

        var product = await db.Products.FindAsync(productId);
        if (product == null) return 0;

        // 1. Get all licensed HWIDs for this product
        var licensedFromSeats = await db.LicenseSeats
            .Where(s => s.License!.ProductId == productId && s.IsActive && s.License.IsActive)
            .Select(s => s.HardwareId)
            .ToListAsync();

        var licensedDirect = await db.Licenses
            .Where(l => l.ProductId == productId && l.Seats.Count == 0 && l.HardwareId != null && l.IsActive)
            .Select(l => l.HardwareId!)
            .ToListAsync();

        var licensedHwids = licensedFromSeats.Union(licensedDirect).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // 2. Get all telemetry records grouped by HWID (only for this product)
        var telemetryRecords = await db.TelemetryRecords
            .Where(r => r.AppName.ToLower() == product.Name.ToLower())
            .GroupBy(r => r.HardwareId)
            .Select(g => new
            {
                HardwareId = g.Key,
                TotalEvents = g.Count(),
                FirstSeen = g.Min(r => r.Timestamp),
                LastSeen = g.Max(r => r.Timestamp),
                Events = g.Select(r => new { r.EventName, r.ClientIp, r.Version }).ToList()
            })
            .ToListAsync();

        // 3. Filter to unlicensed HWIDs with feature events
        var suspects = telemetryRecords
            .Where(t => !licensedHwids.Contains(t.HardwareId))
            .Select(t =>
            {
                var featureEvents = t.Events.Count(e => IsFeatureEvent(e.EventName));
                var topEvents = t.Events
                    .Where(e => IsFeatureEvent(e.EventName))
                    .GroupBy(e => e.EventName)
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .Select(g => new { name = g.Key, count = g.Count() })
                    .ToList();
                var ips = t.Events.Select(e => e.ClientIp).Where(ip => ip != null).Distinct().ToList();
                var versions = t.Events.Select(e => e.Version).Where(v => v != null).Distinct().OrderBy(v => v).ToList();

                return new
                {
                    t.HardwareId,
                    t.TotalEvents,
                    FeatureEvents = featureEvents,
                    FirstSeen = DateTime.SpecifyKind(t.FirstSeen, DateTimeKind.Utc),
                    LastSeen = DateTime.SpecifyKind(t.LastSeen, DateTimeKind.Utc),
                    Ips = ips,
                    IpCount = ips.Count,
                    Versions = string.Join(", ", versions!),
                    TopEvents = JsonSerializer.Serialize(topEvents)
                };
            })
            .Where(s => s.FeatureEvents > 0)
            .ToList();

        // 4. Enrich with culture/OS from latest Startup_AppStarted
        var suspectHwids = suspects.Select(s => s.HardwareId).ToHashSet();
        var startupProps = await db.TelemetryRecords
            .Where(r => r.AppName.ToLower() == product.Name.ToLower()
                        && r.EventName == "Startup_AppStarted"
                        && suspectHwids.Contains(r.HardwareId))
            .Include(r => r.EventData)
            .GroupBy(r => r.HardwareId)
            .Select(g => g.OrderByDescending(r => r.Timestamp).First())
            .ToListAsync();

        var propsMap = new Dictionary<string, (string? Culture, string? OS)>();
        foreach (var rec in startupProps)
        {
            if (rec.EventData?.PropertiesJson == null) continue;
            try
            {
                var props = JsonSerializer.Deserialize<Dictionary<string, string>>(rec.EventData.PropertiesJson);
                if (props != null)
                {
                    props.TryGetValue("Culture", out var culture);
                    props.TryGetValue("OS", out var os);
                    propsMap[rec.HardwareId] = (culture, os);
                }
            }
            catch { /* ignore parse errors */ }
        }

        // 5. Upsert PiracySuspect records
        var existing = await db.PiracySuspects
            .Where(p => p.ProductId == productId)
            .ToDictionaryAsync(p => p.HardwareId, StringComparer.OrdinalIgnoreCase);

        int newCount = 0;
        foreach (var s in suspects)
        {
            propsMap.TryGetValue(s.HardwareId, out var props);
            var ipList = string.Join(", ", s.Ips.Take(20)!);
            if (s.Ips.Count > 20) ipList += $" (+{s.Ips.Count - 20} more)";

            if (existing.TryGetValue(s.HardwareId, out var ex))
            {
                // Update stats (don't touch Status/AdminNotes)
                ex.TotalEvents = s.TotalEvents;
                ex.FeatureEvents = s.FeatureEvents;
                ex.FirstSeenAt = s.FirstSeen;
                ex.LastSeenAt = s.LastSeen;
                ex.Culture = props.Culture ?? ex.Culture;
                ex.OS = props.OS ?? ex.OS;
                ex.Versions = s.Versions;
                ex.IpAddresses = ipList;
                ex.DistinctIpCount = s.IpCount;
                ex.TopEvents = s.TopEvents;
                ex.LastScanAt = DateTime.UtcNow;
            }
            else
            {
                db.PiracySuspects.Add(new PiracySuspect
                {
                    HardwareId = s.HardwareId,
                    ProductId = productId,
                    TotalEvents = s.TotalEvents,
                    FeatureEvents = s.FeatureEvents,
                    FirstSeenAt = s.FirstSeen,
                    LastSeenAt = s.LastSeen,
                    Culture = props.Culture,
                    OS = props.OS,
                    Versions = s.Versions,
                    IpAddresses = ipList,
                    DistinctIpCount = s.IpCount,
                    TopEvents = s.TopEvents,
                    DetectedAt = DateTime.UtcNow,
                    LastScanAt = DateTime.UtcNow
                });
                newCount++;
            }
        }

        // 6. Remove suspects that now have a license (cleared)
        var cleared = existing.Values.Where(e => licensedHwids.Contains(e.HardwareId)).ToList();
        if (cleared.Count > 0)
        {
            db.PiracySuspects.RemoveRange(cleared);
            _logger.LogInformation("Piracy scan: {Count} suspects cleared (now licensed) for {Product}", cleared.Count, product.Name);
        }

        await db.SaveChangesAsync();

        if (newCount > 0)
        {
            _logger.LogWarning("Piracy scan: {New} new suspects detected for {Product} (total: {Total})", newCount, product.Name, suspects.Count);
            _notifier.Notify("Security.PiracyDetected",
                $"🏴‍☠️ {newCount} nouveaux pirates détectés",
                $"Produit: {product.Name}\nNouveaux: {newCount}\nTotal actifs: {suspects.Count}");
        }

        return newCount;
    }

    /// <summary>
    /// Returns all suspects for a product, optionally filtered by status.
    /// </summary>
    public async Task<List<PiracySuspect>> GetSuspectsAsync(Guid productId, string? statusFilter = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var query = db.PiracySuspects
            .Where(p => p.ProductId == productId)
            .AsQueryable();

        if (!string.IsNullOrEmpty(statusFilter))
            query = query.Where(p => p.Status == statusFilter);

        return await query.OrderByDescending(p => p.FeatureEvents).ToListAsync();
    }

    /// <summary>
    /// Returns all suspects across all products.
    /// </summary>
    public async Task<List<PiracySuspect>> GetAllSuspectsAsync(string? statusFilter = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var query = db.PiracySuspects.Include(p => p.Product).AsQueryable();

        if (!string.IsNullOrEmpty(statusFilter))
            query = query.Where(p => p.Status == statusFilter);

        return await query.OrderByDescending(p => p.FeatureEvents).ToListAsync();
    }

    /// <summary>
    /// Updates the status and optional notes for a suspect.
    /// </summary>
    public async Task UpdateStatusAsync(Guid suspectId, string newStatus, string? notes = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var suspect = await db.PiracySuspects.FindAsync(suspectId);
        if (suspect == null) return;

        suspect.Status = newStatus;
        if (notes != null) suspect.AdminNotes = notes;
        await db.SaveChangesAsync();

        // Auto-ban hardware ID when suspect is marked as Blocked
        if (newStatus == PiracyStatus.Blocked)
        {
            var reason = $"Piracy suspect blocked (HWID: {suspect.HardwareId}, events: {suspect.FeatureEvents})";
            await _security.BanHardwareIdAsync(suspect.HardwareId, reason, suspect.ProductId, piracySuspectId: suspect.Id, banCategory: Data.BannedHardwareId.Categories.Piracy);
        }
    }

    /// <summary>
    /// Returns detailed event breakdown for a single suspect.
    /// </summary>
    public async Task<SuspectDetail?> GetSuspectDetailAsync(Guid suspectId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var suspect = await db.PiracySuspects.Include(p => p.Product).FirstOrDefaultAsync(p => p.Id == suspectId);
        if (suspect == null) return null;

        var productName = suspect.Product?.Name ?? "";

        var events = await db.TelemetryRecords
            .Where(r => r.HardwareId == suspect.HardwareId && r.AppName.ToLower() == productName.ToLower())
            .Select(r => new { r.EventName, r.Timestamp, r.ClientIp, r.Version })
            .ToListAsync();

        var eventBreakdown = events
            .GroupBy(e => e.EventName)
            .Select(g => new EventStat { Name = g.Key, Count = g.Count(), IsFeature = IsFeatureEvent(g.Key) })
            .OrderByDescending(e => e.Count)
            .ToList();

        var dailyActivity = events
            .GroupBy(e => e.Timestamp.Date)
            .Select(g => new PiracyDailyActivity
            {
                Date = DateTime.SpecifyKind(g.Key, DateTimeKind.Utc),
                Total = g.Count(),
                Features = g.Count(e => IsFeatureEvent(e.EventName))
            })
            .OrderBy(d => d.Date)
            .ToList();

        var ips = events.Select(e => e.ClientIp).Where(ip => ip != null).Distinct().ToList();
        var versions = events.Select(e => e.Version).Where(v => v != null).Distinct().OrderBy(v => v).ToList();

        // Get PropertiesJson from latest Startup_AppStarted
        var startupEvent = await db.TelemetryRecords
            .Where(r => r.HardwareId == suspect.HardwareId
                        && r.AppName.ToLower() == productName.ToLower()
                        && r.EventName == "Startup_AppStarted")
            .Include(r => r.EventData)
            .OrderByDescending(r => r.Timestamp)
            .FirstOrDefaultAsync();

        Dictionary<string, string>? startupProps = null;
        if (startupEvent?.EventData?.PropertiesJson != null)
        {
            try { startupProps = JsonSerializer.Deserialize<Dictionary<string, string>>(startupEvent.EventData.PropertiesJson); }
            catch { /* ignore */ }
        }

        return new SuspectDetail
        {
            Suspect = suspect,
            EventBreakdown = eventBreakdown,
            PiracyDailyActivity = dailyActivity,
            AllIps = ips!,
            AllVersions = versions!,
            StartupProperties = startupProps
        };
    }

    /// <summary>
    /// Scans all products at once.
    /// </summary>
    public async Task<Dictionary<string, int>> RunFullScanAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var products = await db.Products.ToListAsync();
        var results = new Dictionary<string, int>();

        foreach (var product in products)
        {
            var newCount = await RunScanAsync(product.Id);
            results[product.Name] = newCount;
        }

        return results;
    }

    /// <summary>
    /// Summary stats across all products.
    /// </summary>
    public async Task<PiracyStats> GetStatsAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var suspects = await db.PiracySuspects.ToListAsync();
        var weekAgo = DateTime.UtcNow.AddDays(-7);

        return new PiracyStats
        {
            TotalSuspects = suspects.Count,
            NewThisWeek = suspects.Count(s => s.DetectedAt >= weekAgo),
            ByStatus = suspects.GroupBy(s => s.Status).ToDictionary(g => g.Key, g => g.Count()),
            TotalFeatureEvents = suspects.Sum(s => s.FeatureEvents),
            TopCultures = suspects.Where(s => s.Culture != null).GroupBy(s => s.Culture!)
                .OrderByDescending(g => g.Count()).Take(5)
                .ToDictionary(g => g.Key, g => g.Count())
        };
    }
}

public class SuspectDetail
{
    public PiracySuspect Suspect { get; set; } = null!;
    public List<EventStat> EventBreakdown { get; set; } = [];
    public List<PiracyDailyActivity> PiracyDailyActivity { get; set; } = [];
    public List<string> AllIps { get; set; } = [];
    public List<string> AllVersions { get; set; } = [];
    public Dictionary<string, string>? StartupProperties { get; set; }
}

public class EventStat
{
    public string Name { get; set; } = "";
    public int Count { get; set; }
    public bool IsFeature { get; set; }
}

public class PiracyDailyActivity
{
    public DateTime Date { get; set; }
    public int Total { get; set; }
    public int Features { get; set; }
}

public class PiracyStats
{
    public int TotalSuspects { get; set; }
    public int NewThisWeek { get; set; }
    public Dictionary<string, int> ByStatus { get; set; } = [];
    public int TotalFeatureEvents { get; set; }
    public Dictionary<string, int> TopCultures { get; set; } = [];
}
