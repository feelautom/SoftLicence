using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using System.Diagnostics;
namespace SoftLicence.Server.Services
{
    public class StatsService
    {
        private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
        private readonly ILogger<StatsService> _logger;

        public StatsService(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<StatsService>? logger = null)
        {
            _dbFactory = dbFactory;
            _logger = logger ?? NullLogger<StatsService>.Instance;
        }

        public async Task<DashboardStats> GetDashboardStatsAsync()
        {
            var totalSw = Stopwatch.StartNew();
            using var db = await _dbFactory.CreateDbContextAsync();
            if (db.Database.IsRelational())
            {
                db.Database.SetCommandTimeout(10); // timeout court pour éviter de bloquer le dashboard
            }

            var stats = new DashboardStats();
            var stepSw = Stopwatch.StartNew();

            // KPIs
            stats.TotalProducts = await db.Products.CountAsync();
            stats.TotalLicenses = await db.Licenses.CountAsync();
            var now = DateTime.UtcNow;
            stats.ActiveLicenses = await db.Licenses.CountAsync(l => l.IsActive && (!l.ExpirationDate.HasValue || l.ExpirationDate > now));
            stats.RevokedLicenses = await db.Licenses.CountAsync(l => !l.IsActive);
            LogStep("kpis", stepSw);

            // Audit Stats (Derniers 30 jours)
            stepSw.Restart();
            var since = now.AddDays(-30);
            var logsQuery = db.AccessLogs.AsNoTracking().Where(l => l.Timestamp >= since);

            stats.TotalRequests = await logsQuery.CountAsync();
            stats.FailedRequests = await logsQuery.CountAsync(l => !l.IsSuccess);
            stats.ActivationCount = await logsQuery.CountAsync(l => l.Endpoint == "ACTIVATE" && l.IsSuccess);
            stats.CheckInCount = await logsQuery.CountAsync(l => l.Endpoint == "CHECK" && l.IsSuccess);
            LogStep("audit-30d-counts", stepSw);

            // Graphique 7 jours - Activité (groupé par jour Europe/Paris)
            stepSw.Restart();
            for (int i = 6; i >= 0; i--)
            {
                var parisDate = TimeZoneService.ParisDateDaysAgo(i);
                var (startUtc, endUtc) = TimeZoneService.ParisDateToUtcRange(parisDate);
                var dayQuery = db.AccessLogs.AsNoTracking().Where(l => l.Timestamp >= startUtc && l.Timestamp < endUtc);
                var count = await dayQuery.CountAsync();
                var fail = await dayQuery.CountAsync(l => !l.IsSuccess);

                stats.ActivityChart.Add(new DailyActivity
                {
                    Date = parisDate,
                    Total = count,
                    Errors = fail
                });
            }
            LogStep("activity-chart-7d", stepSw);

            // Graphique 7 jours - Licences (groupé par jour Europe/Paris)
            stepSw.Restart();
            for (int i = 6; i >= 0; i--)
            {
                var parisDate = TimeZoneService.ParisDateDaysAgo(i);
                var (startUtc, endUtc) = TimeZoneService.ParisDateToUtcRange(parisDate);
                stats.LicenseChart.Add(new DailyLicenseActivity
                {
                    Date = parisDate,
                    Created = await db.Licenses.AsNoTracking().CountAsync(l => l.CreationDate >= startUtc && l.CreationDate < endUtc),
                    Activated = await db.Licenses.AsNoTracking().CountAsync(l => l.ActivationDate.HasValue && l.ActivationDate.Value >= startUtc && l.ActivationDate.Value < endUtc)
                });
            }
            LogStep("license-chart-7d", stepSw);

            _logger.LogInformation(
                "Dashboard stats loaded in {ElapsedMs}ms: products={Products}, licenses={Licenses}, requests30d={Requests30d}",
                totalSw.ElapsedMilliseconds,
                stats.TotalProducts,
                stats.TotalLicenses,
                stats.TotalRequests);

            return stats;
        }

        private void LogStep(string step, Stopwatch sw)
        {
            _logger.LogInformation("Dashboard stats step {Step} completed in {ElapsedMs}ms", step, sw.ElapsedMilliseconds);
        }
    }

    public class DashboardStats
    {
        public int TotalProducts { get; set; }
        public int TotalLicenses { get; set; }
        public int ActiveLicenses { get; set; }
        public int RevokedLicenses { get; set; }
        
        public int TotalRequests { get; set; }
        public int FailedRequests { get; set; }
        public int ActivationCount { get; set; }
        public int CheckInCount { get; set; }

        public List<DailyActivity> ActivityChart { get; set; } = new();
        public List<DailyLicenseActivity> LicenseChart { get; set; } = new();
    }

    public class DailyActivity
    {
        public DateTime Date { get; set; }
        public int Total { get; set; }
        public int Errors { get; set; }
    }

    public class DailyLicenseActivity
    {
        public DateTime Date { get; set; }
        public int Created { get; set; }
        public int Activated { get; set; }
    }
}
