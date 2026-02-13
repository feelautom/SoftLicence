using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services
{
    public class StatsService
    {
        private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

        public StatsService(IDbContextFactory<LicenseDbContext> dbFactory)
        {
            _dbFactory = dbFactory;
        }

        public async Task<DashboardStats> GetDashboardStatsAsync()
        {
            using var db = await _dbFactory.CreateDbContextAsync();

            var stats = new DashboardStats();

            // KPIs
            stats.TotalProducts = await db.Products.CountAsync();
            stats.TotalLicenses = await db.Licenses.CountAsync();
            stats.ActiveLicenses = await db.Licenses.CountAsync(l => l.IsActive);
            stats.RevokedLicenses = await db.Licenses.CountAsync(l => !l.IsActive);

            // Audit Stats (Derniers 30 jours)
            var since = DateTime.UtcNow.AddDays(-30);
            var logs = await db.AccessLogs
                .Where(l => l.Timestamp >= since)
                .Select(l => new { l.ResultStatus, l.Timestamp, l.AppName, l.Endpoint, l.IsSuccess })
                .ToListAsync();

            stats.TotalRequests = logs.Count;
            stats.FailedRequests = logs.Count(l => !l.IsSuccess);
            
            stats.ActivationCount = logs.Count(l => l.Endpoint == "ACTIVATE" && l.IsSuccess);
            stats.CheckInCount = logs.Count(l => l.Endpoint == "CHECK" && l.IsSuccess);

            // Graphique 7 jours - Activité
            for (int i = 6; i >= 0; i--)
            {
                var date = DateTime.UtcNow.Date.AddDays(-i);
                var count = logs.Count(l => l.Timestamp.Date == date);
                var fail = logs.Count(l => l.Timestamp.Date == date && !l.IsSuccess);

                stats.ActivityChart.Add(new DailyActivity
                {
                    Date = date,
                    Total = count,
                    Errors = fail
                });
            }

            // Graphique 7 jours - Licences
            var sinceLic = DateTime.UtcNow.Date.AddDays(-6);
            var recentLicenses = await db.Licenses
                .Where(l => l.CreationDate >= sinceLic)
                .Select(l => new { l.CreationDate, l.ActivationDate })
                .ToListAsync();

            for (int i = 6; i >= 0; i--)
            {
                var date = DateTime.UtcNow.Date.AddDays(-i);
                stats.LicenseChart.Add(new DailyLicenseActivity
                {
                    Date = date,
                    Created = recentLicenses.Count(l => l.CreationDate.Date == date),
                    Activated = recentLicenses.Count(l => l.ActivationDate?.Date == date)
                });
            }

            return stats;
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
